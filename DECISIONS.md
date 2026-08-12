# Architecture decision record

Newest last. Each entry: context, decision, consequences.

---

## D-001 — Xray-core runs as an external supervised process

**Context.** Reimplementing VLESS/REALITY/XHTTP in Rust would be a permanent
compatibility treadmill and a security liability.

**Decision.** Run the official `xray` binary as a child process of `xraytuid`.
Never fork or embed it. Control it through its gRPC commander API.

**Consequences.** xraytui inherits Xray's protocol matrix for free and must track
Xray's JSON schema. Version and capability detection is mandatory
(`docs/UPSTREAM-COMPATIBILITY.md`). Managed downloads verify the official
`.dgst` SHA2-256 and never replace a binary while the core is running.

---

## D-002 — One core process, many egress profiles

**Context.** "Multiple proxies at once" can be implemented as N cores or as one
core with N routing targets.

**Decision.** One supervised core. Each egress profile compiles to an independent
**balancer** (`profile/<id>/selector`) whose target is changed at runtime with
`RoutingService.OverrideBalancerTarget`.

**Consequences.** Switching a profile costs one RPC and no restart; other profiles
are untouched; connection state is preserved. A single core is a single failure
domain — mitigated by last-known-good rollback and health gating. A separate core
instance is only used if a future documented isolation requirement demands it.

---

## D-003 — Profile selectors are balancers, not rewritten rules

**Context.** A profile's target could be changed by rewriting the routing rule
(`AddRule`/`RemoveRule`) or by overriding a balancer.

**Decision.** Every profile owns a one-element-per-target balancer.
`OverrideBalancerTarget` sets the concrete outbound tag.

**Consequences.** Rule ordering never changes at runtime, so the compiled routing
table stays deterministic and reviewable. Overrides are *not* persisted by Xray,
so `xraytuid` re-applies every override after each core start — this is an explicit
step in the startup sequence.

Balancer `selector` entries are **prefix** matches. Tags are therefore designed so
that no tag is a prefix of an unrelated tag: `node/<uuid>` never prefixes
`chain/...`, and the profile balancer's selector is seeded with the full set of
selectable terminal tags.

---

## D-004 — Groups compile through a loopback second stage

**Context.** Xray rules accept either `outboundTag` or `balancerTag`; a balancer
cannot be the target of another balancer.

**Decision.** `group/<id>/entry` is a `loopback` outbound whose `inboundTag` is
`group/<id>/entry`. A high-priority rule matches that inbound tag and dispatches to
`balancerTag: group/<id>/balancer`. Profile balancers can therefore select the
group entry as if it were an ordinary outbound.

**Consequences.** One extra routing pass per group-routed connection. Groups become
first-class selectable targets for profiles and chains' final hop.

---

## D-005 — Chains use `sockopt.dialerProxy`, with cloned outbounds

**Context.** A node used in two chains must not be mutated by either.

**Decision.** Each chain hop is compiled as a **clone** of the node outbound under
tag `chain/<id>/<index>`, and the terminal is `chain/<id>/terminal`. Hop *n*
carries `streamSettings.sockopt.dialerProxy = chain/<id>/<n-1>`. Routing points at
the terminal.

**Consequences.** `Local -> A -> B -> C -> Internet` is expressed as C dialling
through B dialling through A. Node definitions stay immutable. Chain validation
rejects self-reference, cycles, missing hops, and UDP-incapable intermediate hops.

---

## D-006 — TOML is the source of truth; Xray JSON is a build artifact

**Decision.** User-editable durable state is TOML with `schema_version`.
Generated Xray JSON lives in `$XDG_RUNTIME_DIR` and is regenerated deterministically.
Runtime history/metrics live in SQLite; policy never does.

**Consequences.** Users can hand-edit configuration and diff it in git. The
compiler must produce canonically ordered, byte-stable output — enforced by test.

---

## D-007 — Only `xraytui-netd` is privileged, and it takes typed operations only

**Decision.** A system service with `CapabilityBoundingSet=CAP_NET_ADMIN
CAP_NET_RAW CAP_NET_BIND_SERVICE` and no shell. Its IPC is a closed enum of
operations over a Unix socket, authenticated with `SO_PEERCRED`. No setuid binary
is installed.

**Consequences.** Everything the helper can do is enumerable by reading one Rust
enum. Resources are namespaced per UID (`xraytui-<uid>-...`) and tagged/commented so
ownership is provable. The helper never parses subscriptions, never performs
network I/O, and never sees node credentials.

---

## D-008 — Persistent TUN owned by the user's UID, not FD passing

**Context.** Upstream Xray's Linux TUN opens `/dev/net/tun` itself and cannot
consume an inherited FD (verified in `proxy/tun/tun_linux.go`).

**Decision.** `xraytui-netd` creates a **persistent** TUN device with
`TUNSETPERSIST`, assigns `TUNSETOWNER` to the requesting UID, configures
addresses/MTU/link over netlink, and returns the FD over `SCM_RIGHTS` for
`xraytuid` to hold as a liveness handle. Xray then attaches to the pre-existing
device unprivileged.

**Consequences.** Xray needs no `CAP_NET_ADMIN` for the common case *if* the kernel
permits an owner to attach and Xray's `LinkSetMTU`/`LinkSetUp` calls succeed
(they are no-ops on an already-configured link only if the kernel skips the
permission check — this is verified at runtime, not assumed). When the attach path
fails, `xraytui doctor` reports it and TUN mode is refused rather than silently
escalating privileges. The alternative — netd exec'ing the core with ambient
`CAP_NET_ADMIN` under the caller's UID — is specified in `docs/NETWORKING.md`
as `CoreLaunchTun` and is **opt-in**, because it widens netd's mandate.

---

## D-009 — Three per-application mechanisms, honestly labelled

**Decision.**
1. *Native process routing* — Xray's `process` matcher, used in TUN modes.
   Best-effort: matches the socket-owning process, which for browsers is a network
   helper process.
2. *Dedicated local listeners* — one SOCKS5 + one HTTP CONNECT per profile;
   `xraytui exec --profile P -- cmd` injects proxy environment variables.
   Exact and unprivileged, but only honoured by proxy-aware programs.
3. *cgroup v2 exact-instance* — `xraytui exec --transparent`, classifying a single
   process tree into a project cgroup matched by nftables `socket cgroupv2`,
   marked, and policy-routed into a per-profile transparent inbound.

The UI and CLI always state which mechanism produced a decision. Falling back from
(3) to (2) or (1) is reported, never silent.

---

## D-010 — IPC is length-prefixed CBOR with explicit version negotiation

**Decision.** `u32` big-endian length prefix, 8 MiB cap, CBOR body, request IDs,
typed errors, server-streamed events, cancellation frames. First frame is a
`Hello`/`Welcome` exchange carrying protocol version and feature flags.

**Consequences.** No schema compiler needed for the user-facing socket; the
privileged socket uses the same framing with a much smaller, separately versioned
message set. Bounded frames give backpressure and DoS resistance for free.

---

## D-011 — No telemetry, no crash upload, no auto-update of the helper

**Decision.** The application performs network I/O only to (a) user-configured
subscription URLs, (b) user-configured test URLs, (c) proxy endpoints the user
configured, and (d) `api.github.com` / `github.com` **only** when the user
explicitly runs a managed Xray install or `upstream-check`.

---

## D-012 — `panic = "abort"` in release, `unwrap` denied in daemon crates

**Decision.** Release builds abort on panic so a corrupted daemon cannot continue
with half-applied network state; the netd lease then triggers cleanup. Crates
`controller`, `daemon-ipc`, `linux-net`, `netd-protocol` and both daemon binaries
set `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`.
`unsafe` is forbidden everywhere except `linux-net`, where each block documents its
invariants.

---

## D-013 — Health probes traverse the actual outbound

**Decision.** A probe opens a connection *through the profile's own SOCKS listener*
(or a dedicated probe inbound bound to loopback) to the configured test URL, so it
measures the usable path — TCP connect, optional TLS handshake, optional small HTTP
request. ICMP is never used.

**Consequences.** Probing requires the core to be running. Concurrency is bounded,
results are cached with confidence decay, and only prioritised nodes are probed
(active targets, group candidates, chain hops, pinned, recently used).

---

## D-014 — Deterministic tags and an explicit terminal catch-all

**Decision.** The compiler emits a `control/block` blackhole **first** in the
outbound list, so a malformed or truncated routing table fails closed rather than
leaking directly. Routing always ends with an explicit catch-all rule; Xray's
implicit "first outbound" fallback is never relied on.
