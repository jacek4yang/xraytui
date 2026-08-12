# Status

**Not production ready**, but every mandatory component now exists. Ten of the
fourteen acceptance scenarios are implemented and passing against a real
Xray-core, a real kernel, a real HTTP server or a real terminal buffer; three
more pass in part; one is not implemented and is marked as such below rather
than claimed.

Read this file before trusting anything the README says.

Last updated: 2026-08-12. Everything below was produced by running the commands
shown, in this repository, in the environment described at the bottom.

---

## What actually works

The central claim of the project is implemented and proven by test:

* **Several egress profiles run concurrently through one supervised core.**
  Two profiles with their own SOCKS listeners reach two different proxies at the
  same time (scenario A).
* **One profile's target hot-switches through the gRPC API** with the other
  profile untouched, the same core PID, and the same generation (scenario B).
* **Two-hop chains** reach the exit through the transit hop, proven by observing
  a connection at the transit proxy (scenario E).
* **A runtime-only failure rolls back** to the previous generation, and the
  working profile keeps serving.
* **The core dying is noticed**, the listeners go with it, and a backoff restart
  is scheduled and succeeds (scenario I).
* **A system TUN comes up with its addresses, routes and policy rule**, and the
  kernel's own lookup confirms that marked traffic enters the tunnel while an
  excluded prefix and the proxy's own endpoint do not (scenario C).
* **A lapsed lease is reclaimed**: the interface, the routes and the rule all
  go, and under the `block` failure policy the table is left blackholed instead
  so traffic stops rather than silently leaving unprotected (scenario J).
* **Repeated enable and disable leaves nothing behind** — no interface, no
  route, no rule, no nftables chain, no lease — over three cycles (scenario K).
* **A process is placed in its profile's cgroup by `pidfd`**, and the nftables
  ruleset marks exactly that cgroup while exempting the core's own (scenario M,
  in part; see below).
* **State this project did not create is left alone.** A route and a rule put in
  the same table by something else survive a full teardown.
* **The interface runs at 80x24 and gives the terminal back.** Every documented
  key is pressed by a test; every pane is drawn into a buffer at sizes from
  80x24 down to 1x1 and asserted not to overflow; the restore sequence is
  asserted byte for byte (scenario L).
* **A subscription updates transactionally**, against a real HTTP server: a
  provider that adds, renames and drops nodes in one update produces exactly
  those three changes; a profile pointing at a renamed node keeps working; and
  an update that would break a profile, empty the node list or arrive as an
  error page is refused with nothing written (scenario G).
* The **CLI and daemon** talk to each other over a versioned CBOR socket, with
  the documented output formats and exit codes, proven by running the real
  binaries against each other.

## Quality gates

Run on 2026-08-12 with Rust 1.95.0 and Xray-core v26.3.27.

| Command | Result |
|---|---|
| `cargo fmt --all --check` | **pass** (no output) |
| `cargo check --workspace --all-targets` | **pass** |
| `cargo clippy --workspace --all-targets -- -D warnings` | **pass**, no warnings |
| `cargo test --workspace` | **pass**, 628 tests, 0 failures |
| `sudo ./scripts/netns-test.sh` | **pass**, 9 privileged tests, 0 failures |
| `cargo doc --workspace --no-deps` | **pass**, 0 warnings |
| `cargo build --release --workspace` | **pass** |
| `cargo xtask install --prefix /usr --destdir …` | **pass**, 53 files, no setuid |

`cargo nextest` was not available in this environment; the ordinary `cargo test`
path is the one that was exercised.

`cargo audit` and `cargo deny` were **not run** — neither tool is installed here
and installing them was out of scope for the session. No advisory has therefore
been reviewed or accepted; treat the dependency set as unaudited.

### Test breakdown

| Crate | Tests | Notes |
|---|---|---|
| `xraytui-linux-net` | 108 + 9 | the 9 are the privileged tests, run only in a namespace |
| `xraytui-import` | 67 | includes proptests asserting no panic on arbitrary input |
| `xraytui-subscription` | 49 + 8 | the 8 run the whole pipeline against a real HTTP server |
| `xraytui-domain` | 55 | includes proptests for the slug and bounded-regex code |
| `xraytui-xray-compiler` | 41 + 6 | the 6 are validated by a real `xray run -test` |
| `xraytui-tui` | 65 | every key pressed; every pane drawn into a buffer |
| `xraytui-config` | 34 | permissions, atomicity, schema rejection, migration ladder |
| `xraytui-cli` | 33 + 11 | the 11 run the real `xraytui`/`xraytuid` binaries |
| `xraytui-ipc` | 25 | framing limits, version negotiation, streaming, filters |
| `xraytui-controller` | 24 + 6 | the 6 are the acceptance scenarios against a real core |
| `xraytui-netd-protocol` | 17 | validation of the privileged operation set |
| `xraytuid` | 13 + 9 | includes the netd request builder and the helper server |
| `xtask` | 8 + 5 | the 5 are the no-shell and unsafe-confinement invariants |
| others | remainder | secrets, xray-model, xray-api, test-support |

## Acceptance scenarios

| ID | Scenario | State |
|----|---|---|
| **A** | two profiles, two SOCKS ports, two mock egresses, simultaneously | **passing** — `controller/tests/acceptance.rs` |
| **B** | hot-switch one profile via gRPC; other unchanged; no restart | **passing** — asserts identical PID and generation |
| **C** | shared TUN rule mode, per-app routing in a netns | **passing** — `linux-net/tests/netns.rs`; the kernel's own `ip route get` is the oracle |
| D | two apps concurrently plus DNS following policy | **partial** — the two-app half is scenario A; the DNS backends are implemented and unit-tested but no live resolver was driven |
| **E** | two-hop chain reaches the terminal through hop 1 | **passing** — proven by a connection count at the transit hop |
| **F** | import valid/malformed/unsupported node representations | **passing** — 67 unit tests including proptests, and exercised end to end through the subscription pipeline |
| **G** | subscription add/change/remove with diff and rollback | **passing** — `subscription/tests/transaction.rs`, against `HttpFixtureServer` |
| H | terminal and PNG QR round-trip decode | **passing at unit level** — `render_png` → `decode_png` reproduces the exact string |
| **I** | kill Xray in restore mode | **passing** — listener death observed, backoff restart scheduled and verified |
| **J** | kill the daemon while TUN is active; lease expiry cleanup | **passing** — both mechanisms: the connection closing releases immediately, and an expired lease is reclaimed by the reaper |
| **K** | repeated TUN enable/disable leaves no residue | **passing** — three cycles, four independent checks after each |
| **L** | TUI usable at 80x24, restores the terminal | **passing** — `crates/tui`; drawn into a `TestBackend`, restore sequence asserted |
| M | cgroup v2 exact-instance isolation | **partial** — classification by `pidfd` and per-cgroup marking are implemented and proven in a namespace; per-profile *transparent egress* is not (see below) |
| N | clean build and install; nothing runs as root | **partial** — build, install manifest and units are done and verified; a from-scratch install on a clean Arch host was not performed |

## What is not implemented

Stated plainly, because a half-built privileged component is worse than an
absent one:

1. **Per-profile transparent egress.** Scenario M asks that two instances of the
   same program, launched under different profiles, take different exits. What
   exists: each profile gets its own cgroup, a process is placed in one by
   `pidfd` with an ownership check, and nftables marks that cgroup's traffic —
   all proven in a namespace. What is missing is the last link: one user has one
   routing table and one tunnel, so the mark decides *whether* traffic enters
   the tunnel, not *which* exit it takes. Selecting an exit per profile needs a
   `tproxy` inbound per profile and a policy rule per mark. The tag namespace
   already reserves `inbound/profile/{id}/transparent` for it.

   Within the tunnel, per-application routing does work: application rules are
   compiled into Xray's `process` matchers and applied on the TUN inbound. The
   gap is specifically *two instances of the same executable* taking different
   exits.

2. **The state store is a stub.** Runtime history and health history live in
   memory and are lost when the daemon restarts. Policy is durable — it is TOML
   on disk — so nothing the user configured is at risk.

3. **`xraytui app assign` prints the TOML to add** rather than editing the file.
   Application rules are compiled and routed correctly once present; only the
   editing command is missing.

4. **No `cargo audit`/`cargo deny` run.** See above.

5. **Health probing is not scheduled.** `xraytui node test` probes on demand and
   works; the periodic sweep with prioritisation and backoff is not wired up.

6. **The DNS backends have not been driven against a live resolver.** The
   systemd-resolved client is written against the documented `resolve1`
   interface and its marshalling is tested byte for byte; `resolvconf` is tested
   against a stand-in that records its argv and stdin. Neither has talked to the
   real thing, because this environment has neither.

## Upstream findings

Eight things were discovered by testing against a real core and a real kernel
rather than by reading documentation. All eight are load-bearing.

Against Xray-core:

1. **A routing rule with no conditions is rejected** (`this rule has no effective
   fields`). The generated catch-all therefore carries `network: "tcp,udp"`,
   which is the broadest condition Xray accepts.
2. **`fallbackTag` on a balancer requires an observatory.** `RandomStrategy` and
   `RoundRobinStrategy` call `core.RequireFeatures(observatory)` whenever the tag
   is non-empty, and the core refuses to start with "not all dependencies are
   resolved" otherwise. The compiler now emits the two together or neither, which
   is why a default configuration has no active probing.
3. **mKCP `header` and `seed` were removed** in v26.3.27 and replaced by
   `streamSettings.finalmask`. Share links still carry the old fields, so the
   compiler translates them.
4. **The commander only listens on TCP.** `app/commander` calls
   `net.Listen("tcp", listen)` unconditionally, so `api.listen` cannot be a Unix
   socket. `[core] api_unix_socket` therefore defaults to false, and the
   local-multi-user risk in `docs/THREAT-MODEL.md` T1 is **real and unmitigated**
   on a shared machine.

Against the kernel and userland, all four found by `scripts/netns-test.sh`:

5. **nftables 1.0.9's JSON parser cannot express `socket cgroupv2`.** It emits
   the expression when dumping — lossily, dropping the `level` — and rejects it
   on input. The helper therefore generates nftables syntax behind a
   character-set gate (`DECISIONS.md` D-015).
6. **nftables resolves a cgroup path at parse time, against `/sys/fs/cgroup`.**
   The cgroup must exist before the rule is added, and a hierarchy mounted
   elsewhere is invisible to nftables.
7. **`Command::env_clear()` leaves no `PATH`,** and Rust resolves a relative
   program against the child's `PATH`, so clearing the environment makes a bare
   program name unresolvable on a machine where the program is installed
   (`DECISIONS.md` D-016).
8. **A kernel without IPv6 answers every `AF_INET6` route message with
   `EOPNOTSUPP`,** including blackhole routes. The helper installs the IPv4 half
   and reports what it left out.

Additionally, upstream's Linux TUN opens `/dev/net/tun` itself and cannot consume
an inherited file descriptor, which is why the design uses a persistent
owner-assigned device rather than `SCM_RIGHTS` for the data plane
(`DECISIONS.md` D-008).

## Defects found and fixed during development

Recorded because they are the kind of thing that would otherwise be silently
fixed and forgotten:

* **Stack overflow in log redaction.** `redact_url` fell back to `redact_text`,
  which routed URL-shaped tokens straight back into `redact_url`. Any log line
  containing a malformed URL — a subscription body is exactly that — exhausted
  the stack. Found by the import crate's property tests; regression tests added
  in `crates/secrets`.
* **The engine compiled the commander address from the wrong place**, so the core
  bound a random port while the client dialled a fixed one. Presented as a
  15-second start timeout. Found by the acceptance tests.
* **`url` splits userinfo at the first colon**, so `socks://user:pass@host` was
  silently losing its password on import. Found by a round-trip test.
* **The privileged helper could not run `nft` at all.** `env_clear()` removed the
  `PATH` that Rust uses to resolve a relative program name. Presented as "nft is
  not installed" on a machine where it was. Found by the namespace tests.

## Privileged tests

Nine of them, and they run **only inside a disposable namespace**.

`sudo ./scripts/netns-test.sh` builds the test binary outside the namespace —
building needs the network, and the namespace deliberately has none — then runs
it inside a fresh network, mount and PID namespace with a private cgroup v2
hierarchy. Two things stop it touching a real machine:

* the tests return immediately unless `XRAYTUI_NETNS_TESTS` is set, which only
  the script does;
* every fixture calls `assert_disposable_namespace()` first, which refuses to
  proceed if the namespace contains any interface other than loopback and the
  project's own.

**No test in this repository modifies host networking**, and none is claimed to.
Every route, rule, interface, nftables table and cgroup created by the suite
lives in a namespace that the kernel destroys when the last process in it exits.

The other commands worth knowing:

```sh
# Capability report, safe to run anywhere; performs no changes.
xraytui-netd --check-capabilities

# Dry run: prints every intended change without making one, and works whether or
# not a helper is installed.
xraytui tun plan

# Reconciliation: removes project-owned state whose owner is gone.
sudo xraytui-netd --recover --once
```

## Environment this was verified in

| | |
|---|---|
| Kernel | Linux 6.18.5 x86_64, **no IPv6 support** |
| Distribution | Ubuntu 24.04 (container) — **not** the tier-one Arch target |
| Rust | 1.95.0, edition 2024, MSRV declared 1.90 |
| Xray-core | v26.3.27, SHA2-256 verified against the official `.dgst` |
| nftables | 1.0.9 |
| cgroups | v1 hybrid on the host; the namespace tests mount their own v2 |
| protoc | 3.21.12 |
| Privileges | uid 0 in a container; no host networking was touched |

The tier-one target is current Arch Linux with systemd, nftables and cgroup v2.
Nothing here was tested on Arch. The IPv6 path in particular has been written
and unit-tested but never executed against a kernel that has IPv6.

## Editing from the interface

The interface can point a profile at a target, cycle the mode, start and stop the
core, and probe a node. It cannot yet create a node, edit a rule or add a
subscription — those are CLI-only. That is a deliberate order of work: switching
a profile is what people do many times a day, and creating a node is what they do
once.

## The next single most important thing

The scheduler. Health probes and subscription updates both work on demand and
neither runs on its own, so a long-running daemon's picture of the world goes
stale until somebody asks. Both need the same thing — a timer with
prioritisation, jitter and backoff — and building it once serves both.

After that, in order: per-profile `tproxy` inbounds to finish scenario M;
driving the DNS backends against a live systemd-resolved; a durable state store
so runtime history survives a restart; editing from the interface; and
`cargo audit`/`cargo deny`.
