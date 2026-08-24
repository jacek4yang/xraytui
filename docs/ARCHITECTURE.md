# Architecture

This document describes how xraytui is put together and why. Rationale for
individual choices lives in `DECISIONS.md`; what is actually implemented today
lives in `STATUS.md`.

## Component split

```text
 user
  │
  │  terminal / argv
  v
xraytui  ──CBOR over $XDG_RUNTIME_DIR/xraytui/control.sock──>  xraytuid
 (TUI+CLI)                                                        │
                                                                  │ gRPC (loopback TCP or unix socket)
                                                                  v
                                                                xray  (child process, same UID)
                                                                  ^
                                                                  │ attaches to a pre-created TUN
 xraytuid ──CBOR over /run/xraytui/netd.sock (SO_PEERCRED)──> xraytui-netd  ──netlink/nft/D-Bus──> kernel
```

| Component | Privilege | Responsibility | Never does |
|---|---|---|---|
| `xraytui` | user | Render state, collect intent, format output (`dmenu`, JSON, `dwmblocks`). | Mutate networking; talk to Xray; hold the desired state. |
| `xraytuid` | user | Own the desired state, compile it, supervise the core, drive the gRPC API, serve the control socket, run health probes. | Anything requiring `CAP_NET_ADMIN`. |
| `xraytui-netd` | system service with `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE` | TUN devices, addresses, routes, policy rules, `table inet xraytui`, cgroup classification, DNS backends. | Parse subscriptions, perform network I/O, see node credentials, run a shell. |
| `xray` | user for supported SOCKS/HTTP operation | Carry traffic. | Configure host routes, firewall or DNS. Current official Linux TUN additionally performs privileged link setup itself; the packaged user service cannot yet launch that path. |

There is no setuid binary. The privilege boundary is the netd socket, and
everything crossing it is a typed, validated, allowlisted operation from a closed
enum (`crates/netd-protocol`).

## Desired state and observed state

The system is a reconciliation loop over two distinct values.

| | Desired state | Observed state |
|---|---|---|
| Type | `xraytui_domain::DesiredState` | `xraytui_domain::RuntimeState` |
| Source | User-edited TOML under `~/.config/xraytui` | The running core, the kernel, netd, and probe results |
| Contents | mode, default profile, nodes, unsupported nodes, groups, chains, profiles, application rules, routing rules, subscriptions | core lifecycle, TUN status, DNS status, per-profile runtime, node/group/chain health, counters, current generation, last known good |
| Durability | Persisted, versioned, hand-editable, diffable | Derived; serialised to `$XDG_RUNTIME_DIR/xraytui/runtime-state.json` for read-only clients and crash inspection |
| Ordering | `BTreeMap` throughout, so iteration and therefore compilation is deterministic | Sorted for display |

Desired state never contains anything the compiler cannot express, and it knows
nothing about Xray JSON. `DesiredState::validate()` returns a list of
`Diagnostic { severity, code, message, subject }`; every diagnostic carries a
stable machine-readable code such as `target.unknown-node`,
`listener.port-collision` or `group.manual-selection-not-member`, so the TUI can
focus the offending entity and the CLI can be scripted against the code rather
than the prose.

A **generation** (`GenerationId`) is one compiled snapshot of desired state. It is
the unit of rollback, the unit of ownership tagging in netd, and what
`RuntimeState.generation` and `RuntimeState.last_known_good` refer to.

## IPC boundaries

Both sockets use the same framing: a `u32` big-endian length prefix, a CBOR body,
request identifiers, typed errors, server-streamed events and cancellation
frames. The first exchange on any connection is `Hello`/`Welcome` carrying a
protocol version and feature flags, so a mismatched client fails immediately and
legibly instead of misparsing a later frame.

| Boundary | Path | Mode | Peer authentication | Frame cap |
|---|---|---|---|---|
| `xraytui` to `xraytuid` | `$XDG_RUNTIME_DIR/xraytui/control.sock` | socket inside a 0700 directory | same UID by filesystem permission | 8 MiB |
| `xraytuid` to `xraytui-netd` | `/run/xraytui/netd.sock` | 0660, group `xraytui` | `SO_PEERCRED` on accept; all resources derived from the credential UID | 256 KiB |
| `xraytuid` to `xray` | loopback TCP, or a Unix socket in the runtime directory | file mode, or none for TCP | not applicable |

The user socket is not a security boundary — both ends run as the same user — but
it is a correctness and availability boundary, and it is where request
concurrency limits, bounded event channels and idle timeouts live. The netd
socket is a real privilege boundary: the PID from `SO_PEERCRED` is used for
logging only, never for authorisation, because PIDs are reusable.

Netd protocol version 3 carries independent IPv4 and IPv6 blackhole decisions,
system-mode UID marking and an immediate `CoreFailed` transition. `CreateTun`
returns metadata only: netd drops its temporary creation descriptor so official
Xray can attach to the non-multiqueue persistent interface by name. The
authenticated connection and bounded lease provide liveness. A core failure
tears down the unusable device without closing that owner connection; an
unexpected final disconnect applies the recorded restore/block policy rather
than silently treating a daemon crash as an orderly release.
The helper records the configured TUN families in its credential-owned lease;
it never infers them from include prefixes. A plan that includes a prefix from a
disabled family is rejected during candidate validation, before live routes are
flushed. When reading a lease written before protocol v2, it recovers the
missing flags from the live interface's netlink address records.

For TUN topology changes the cross-component transaction is:

```text
stop old Xray (when attached)
 -> apply restore/block policy immediately
 -> netd prepares persistent TUN and core-bypass cgroup
 -> compile and run real `xray run -test`
 -> start and health-gate Xray
 -> classify the exact Xray pid
 -> install routes, nftables and DNS
 -> persist desired and observed state
```

The split between prepare and activate prevents both failure modes seen with the
opposite order: Xray cannot validate a missing interface, while host traffic must
not be routed into a core that has not passed its health gate. A structural
change relinquishes the old non-multiqueue attachment before validation and
retains blackhole policy during the handover when `failure_policy = "block"`.

## One core, many balancers

"Several proxies at once" can be built as N core processes or as one core with N
routing targets. xraytui uses one core (`DECISIONS.md` D-002).

| | One core, N balancers (chosen) | N cores |
|---|---|---|
| Switching a profile | one `OverrideBalancerTarget` RPC, no restart, existing connections on other profiles untouched | restart or reconfigure one core |
| Memory and file descriptors | one process, one geodata mapping | linear in profile count |
| Configuration surface | one generated document, reviewable as a whole | N documents that must stay consistent |
| Routing between profiles | expressible: a rule can dispatch to any balancer | requires chaining cores through local listeners |
| Failure domain | shared; one bad generation affects every profile | isolated |

The shared failure domain is the real cost, and it is what the health gate and the
last-known-good rollback below exist to contain. A separate core instance is only
introduced if a future documented isolation requirement demands it.

## Applying a generation

The controller applies a generation in a fixed order. Each step can fail, and the
failure of any step leaves the previous generation running.

```text
1. validate   DesiredState::validate(); any Severity::Error aborts before compiling.
              Warnings are collected and surfaced, not fatal.
2. compile    xraytui_xray_compiler::compile(&state, &options) -> Compiled
              { config, selector_overrides, listeners, owned_tags, warnings }.
              Pure function: no I/O, no environment, no consultation of the core.
3. pre-check  Write the document 0600 to $XDG_RUNTIME_DIR/xraytui/generated-xray.json
              and verify it with `xray run -test -config <file>`, so a document the
              core would reject never causes a live restart.
4. start      Spawn the pinned xray binary with a fixed argument vector. Secrets
              reach it only through that 0600 file, never through argv or the
              environment.
5. health     Connect with ApiClient::connect_ready, bounded by
              runtime.start_health_deadline_ms (default 15000 ms), then probe the
              commander with Capabilities::probe. Capabilities::is_sufficient()
              requires HandlerService, RoutingService and OverrideBalancerTarget.
              Configured listeners are probed on loopback.
6. overrides  Re-apply every entry of Compiled::selector_overrides, in the
              deterministic order the compiler produced, as
              OverrideBalancerTarget(balancer_tag, target_outbound_tag).
              Xray does not persist overrides, so this step is mandatory after
              every start, not only after a configuration change.
7. commit     Copy the document to last-good-xray.json and record the generation
              as RuntimeState.last_known_good.
```

Step 6 is the reason profile switching is cheap at runtime and yet survives a
crash: the balancer's `selector` still lists the *configured* target, so a core
that comes up before overrides are applied routes according to the saved
configuration rather than at random.

## Last-known-good rollback

`RuntimeState` carries both `generation` and `last_known_good`. A generation is
promoted to last known good only after step 7 above, meaning it started, passed
capability probing and accepted its overrides.

When a new generation fails at any step, the controller keeps the previous core
running if it is still alive, or restarts from `last-good-xray.json` if the new
core has already replaced it. Restarts are bounded by
`runtime.restart_backoff_min_ms`, `runtime.restart_backoff_max_ms` and
`runtime.max_consecutive_restarts` (defaults 500 ms, 60000 ms, 8); after the
limit the core enters `CoreStatus::Failed { reason }` and waits for the operator
rather than flapping.

`CoreStatus` distinguishes `Running` from `Degraded`: degraded means the process
is alive and carrying traffic but a health gate is unsatisfied, which is
information the dashboard shows rather than a reason to restart.

While TUN is active the failure story is different, because a dead daemon leaves
kernel state behind. That is handled by netd's lease, described in
`docs/NETWORKING.md`, and governed by `runtime.failure_policy` (`restore` or
`block`).

## Crate map

Workspace members under `crates/`:

| Crate | Purpose |
|---|---|
| `domain` | The vocabulary: identifiers, nodes, protocols, transports, groups, chains, profiles, rules, subscriptions, desired state, runtime state, validation. Knows nothing about Xray JSON, terminals, clap, tonic or Linux. |
| `secrets` | `Secret` wrapper with redacting `Debug` and zeroising `Drop`, plus the log/diagnostic redaction layer. |
| `config` | Versioned TOML (`schema_version`), the XDG layout, private directory creation, atomic 0600 writes, migrations with mandatory backup. |
| `import` | Standard/de-facto share-link parsing and fidelity-aware serialization, independent terminal/PNG QR handling, private atomic exports and Xray JSON import. Parses attacker-influenced bytes, so production code forbids `unsafe` and denies indexing/slicing/panic shortcuts. |
| `subscription` | Transactional subscription fetching, normalisation and diffing against the existing node set. |
| `xray-model` | Typed model of the Xray JSON document — inbounds, outbounds, routing rules, balancers, DNS, observatory, policy — with the exact upstream field names and omission rules. |
| `xray-compiler` | Pure `DesiredState` to `XrayConfig` compilation: the tag namespace, outbound construction, rule ordering, balancer construction, prefix-safety checking. |
| `xray-api` | The gRPC client generated from the vendored protobufs, the endpoint abstraction (TCP or Unix), and probe-based capability detection. |
| `state-store` | Transactional SQLite store for runtime history and cached metadata. Policy never lives here. |
| `daemon-ipc` | The length-prefixed CBOR protocol between `xraytui` and `xraytuid`, with version negotiation and typed errors. |
| `netd-protocol` | The closed operation set spoken to the privileged helper, versioned separately from the user protocol. |
| `linux-net` | Linux TUN, netlink, nftables, cgroup and DNS backends. The only crate permitted to use `unsafe`, and every block documents its invariants. |
| `controller` | The reconciliation loop: desired-state ownership, compilation, core supervision, health probing, override application, generation bookkeeping. |
| `tui` | The ratatui front end. |
| `cli` | The clap command surface, completions and man page generation. |
| `test-support` | Mock egress servers, an HTTP fixture server and shared fixtures for tests. |

Binaries under `bins/`:

| Binary | Purpose |
|---|---|
| `xraytui` | TUI and CLI front end; composes `cli` and `tui`. |
| `xraytuid` | Per-user desired-state daemon; composes `controller`, `config` and `daemon-ipc`. |
| `xraytui-netd` | Privileged network helper; composes `netd-protocol` and `linux-net`. |
| `linux-net` (in `xraytuid`) | The daemon links the same crate, but only for `transport::NetdClient` and the pure planner. It never calls the netlink, TUN, nftables, cgroup or DNS backends: those need privileges it does not have. |

`xtask/` holds build, install and maintenance tasks, invoked through the
`cargo xtask` alias defined in `.cargo/config.toml`.

## Sharing boundary

Sharing is not part of the Xray data plane and never crosses the privileged
helper boundary:

```text
DesiredState::Node
       |
       +-- connection-semantic canonical identity
       |
       +-- fidelity analysis -- refusal if meaningful fields do not fit
       |                              |
       |                              +-- explicit --allow-lossy only
       v
ecosystem serializer -> Secret(link/subscription/JSON)
       |
       +-- stdout (payload only)
       +-- explicit TUI secret overlay
       +-- clipboard helper stdin
       +-- atomic mode-0600 file
       +-- terminal or PNG QR
```

The link is never sent through daemon mutation IPC, netd, SQLite history, logs,
or diagnostics. The CLI requests the already-private desired state from the
per-user daemon and serializes locally after an explicit `node share`; the TUI
does the same only after the share menu action. `docs/SHARING.md` specifies the
dialects and fidelity rules.

## Dependency direction

```text
domain  <-  xray-compiler  <-  controller  ->  xray-api  ->  vendor/xray-proto
  ^              ^                 |    \
  |              |                 |     ->  linux-net  ->  netd-protocol
config ----------+                 |
  ^                                v
  |                          state-store
tui / cli  ->  daemon-ipc  ->  domain
```

`domain` is a leaf: it depends on serde, `thiserror` and `regex` and on nothing
that knows about presentation, transport or the operating system. That is what
makes the compiler testable without a core and the TUI testable without a daemon.
The layering rules are stated as requirements in `CONTRIBUTING.md`.
