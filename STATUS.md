# Status

**Not production ready**, but every mandatory component now exists. Eleven of
the fourteen acceptance scenarios pass end to end against a real Xray-core, a
real kernel, a real HTTP server or a real terminal buffer; one (H) passes at
unit level only; two (D, N) pass in part. What is unfinished is listed under
"What is not implemented" rather than described as nearly done.

Read this file before trusting anything the README says.

Last updated: 2026-08-13. Everything below was produced by running the commands
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
* **IPv4 is the tested path.** Every namespace test above ran IPv4 only. This
  kernel has no IPv6 at all (`/proc/net/if_inet6` is absent), so the helper
  logs `this kernel has no IPv6; leaving the IPv6 half of the plan out` and
  drops it. IPv6 is therefore **implemented but runtime-unverified**, and the
  release treats it as experimental and off by default.
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
* **Two instances of the same executable take two different exits at the same
  time.** `xraytui exec --transparent --profile a` and `… --profile b` run the
  same program, with the same arguments, to the same destination and port, with
  no proxy environment at all; each leaves by its own profile's exit, through one
  core. Then one profile is hot-switched through the gRPC API and its *new*
  connections move to a third exit while the other profile does not notice, with
  the core's PID and generation unchanged (scenario M).
* **State this project did not create is left alone.** A route and a rule put in
  the same table by something else survive a full teardown.
* **The interface runs at 80x24 and gives the terminal back.** Every documented
  key is pressed by a test; every pane is drawn into a buffer at sizes from
  80x24 down to 1x1 and asserted not to overflow; the restore sequence is
  asserted byte for byte (scenario L).
* **Probes and subscription updates run on their own**, prioritised so the node
  a profile is using is checked before one nobody has selected, backed off on
  failure, jittered from a hash of the entry's key so a restart does not re-roll
  into a stampede, and bounded per tick so a laptop waking from suspend queues
  rather than floods.
* **A subscription updates transactionally**, against a real HTTP server: a
  provider that adds, renames and drops nodes in one update produces exactly
  those three changes; a profile pointing at a renamed node keeps working; and
  an update that would break a profile, empty the node list or arrive as an
  error page is refused with nothing written (scenario G).
* The **CLI and daemon** talk to each other over a versioned CBOR socket, with
  the documented output formats and exit codes, proven by running the real
  binaries against each other.

## Quality gates

Re-measured on 2026-08-15 in a rebuilt environment, at commit `bde078f`.
Every number below was produced by running the command shown, in this
environment, today. Counts from earlier sessions were discarded rather than
carried forward: this project has lost its environment three times, and a
number nobody can reproduce is not evidence.

| Command | Result |
|---|---|
| `cargo fmt --all --check` | **pass** (no output) |
| `cargo check --workspace --all-targets` | **pass** |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **pass**, no warnings |
| `cargo test --workspace` | **pass**, 703 tests, 0 failures |
| `sudo ./scripts/netns-test.sh` | **pass**, 12 + 1 privileged tests, 0 failures |
| `cargo doc --workspace --no-deps` | not re-run at this commit |
| `cargo build --release --workspace` | not re-run at this commit |
| `cargo xtask install --prefix /usr --destdir …` | not re-run at this commit |
| `cargo audit` | **not run** — not installed here |
| `cargo deny check` | **not run** — not installed here |
| live systemd-resolved | **not run** — no D-Bus system bus |
| clean Arch package build | **not run** — no container runtime |
| IPv6 runtime | **not run** — this kernel has no IPv6 |

Toolchain actually used: `rustc 1.95.0 (59807616e 2026-04-14)`,
Xray-core `26.3.27` (`d2758a0`, go1.26.1), kernel `6.18.5-fc-v20`.

No advisory has been reviewed or accepted yet; treat the dependency set as
unaudited until `cargo audit` and `cargo deny` have been run and their results
recorded here.

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
| `xraytui-controller` | 49 + 6 | includes the scheduler; the 6 are the acceptance scenarios against a real core |
| `xraytui-netd-protocol` | 17 | validation of the privileged operation set |
| `xraytuid` | 30 + 9 | includes the netd request builder and the sweeper |
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
| H | terminal and PNG QR round-trip decode | **passing at unit level only** — `render_png` → `decode_png` reproduces the exact string. Nothing scans a QR *rendered in a terminal* with a real decoder, and no user-facing export path is asserted end to end, so this is not counted among the scenarios that pass |
| **I** | kill Xray in restore mode | **passing** — listener death observed, backoff restart scheduled and verified |
| **J** | kill the daemon while TUN is active; lease expiry cleanup | **passing** — both mechanisms: the connection closing releases immediately, and an expired lease is reclaimed by the reaper |
| **K** | repeated TUN enable/disable leaves no residue | **passing** — three cycles, four independent checks after each |
| **L** | TUI usable at 80x24, restores the terminal | **passing** — `crates/tui`; drawn into a `TestBackend`, restore sequence asserted |
| **M** | cgroup v2 exact-instance isolation | **passing** — `controller/tests/netns_transparent.rs`: two instances of one executable, launched through the real CLI against the real helper and a real core, reach two different mock exits; then a gRPC switch moves one and not the other. IPv4 only — this kernel has no IPv6 (see below) |
| N | clean build and install; nothing runs as root | **partial** — build, install manifest and units are done and verified; a from-scratch install on a clean Arch host was not performed |

## What is not implemented

Stated plainly, because a half-built privileged component is worse than an
absent one:

1. **The transparent path is IPv4 only, and its IPv6 half is unexecuted.** The
   redirect rule is `tproxy ip to 127.0.0.1:<port>`, and the transparent listener
   must bind IPv4 loopback — validation refuses anything else rather than
   starting a listener nothing can reach. IPv6 from a transparent profile is
   fail-closed, not leaked: the profile's mark still selects the local-delivery
   table, where there is no redirect, so the connection is refused rather than
   sent out unproxied. An IPv6 transparent path would need a second inbound on
   `[::1]` and a `tproxy ip6` rule. **The kernel in this environment has no IPv6
   at all** (`this kernel has no IPv6` appears in the helper's log during the
   namespace run), so no IPv6 runtime path in this project has been executed —
   including the tunnel's, which is exercised only by unit tests and by graceful
   degradation.

2. **The state store is a stub.** Runtime history and health history live in
   memory and are lost when the daemon restarts. Policy is durable — it is TOML
   on disk — so nothing the user configured is at risk.

3. **`xraytui app assign` prints the TOML to add** rather than editing the file.
   Application rules are compiled and routed correctly once present; only the
   editing command is missing.

4. **No `cargo audit`/`cargo deny` run.** See above.

5. **The DNS backends have not been driven against a live resolver.** The
   systemd-resolved client is written against the documented `resolve1`
   interface and its marshalling is tested byte for byte; `resolvconf` is tested
   against a stand-in that records its argv and stdin. Neither has talked to the
   real thing, because this environment has neither.

## Upstream findings

Eleven things were discovered by testing against a real core and a real kernel
rather than by reading documentation. All eleven are load-bearing.

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
9. **`tproxy` in an `inet` table refuses a named address without a family:**
   "specify `tproxy ip' or `tproxy ip6' in inet table to disambiguate". Leaving
   the address out avoids the error but then the socket lookup uses the packet's
   *original* destination, which forces the listener to bind every address on the
   machine. Naming `tproxy ip to 127.0.0.1:<port>` is what lets it bind loopback
   instead, so the redirect and the listener's address are one decision.
10. **A `tproxy` listener that does not set `IP_TRANSPARENT` never completes the
    handshake.** The accepted socket's local address is the original destination,
    and the kernel will not send from an address this machine does not own unless
    the listener is transparent. Tested both ways in a namespace: with the option
    the connection arrives with its destination intact, without it the client
    times out. This is why the compiler emits `sockopt.tproxy` and not merely a
    `dokodemo-door`.
11. **`geoip:private` is RFC 6890's special-purpose registry, not RFC 1918.** It
    includes the documentation ranges — `192.0.2.0/24`, `198.51.100.0/24`,
    `203.0.113.0/24` — which are exactly what a test uses for a stand-in
    destination. A private-network bypass therefore captures test traffic that
    looks public. Found when the transparent acceptance test started answering
    from `control/direct`.

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

Thirteen of them, in two suites, and they run **only inside a disposable
namespace**: twelve in `crates/linux-net/tests/netns.rs`, which prove the
kernel-side arrangement, and one in `crates/controller/tests/netns_transparent.rs`,
which proves acceptance scenario M through the real helper, the real command-line
client and a real core on top of it.

`sudo ./scripts/netns-test.sh` builds the test binaries and the project's own
binaries outside the namespace — building needs the network, and the namespace
deliberately has none — then runs them inside a fresh network, mount and PID
namespace with a private cgroup v2 hierarchy. Two things stop it touching a real machine:

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

Per-profile `tproxy` inbounds, to finish scenario M. It is the last acceptance
scenario with a genuine hole rather than a missing test environment: the cgroup
classification and the marking behind it are implemented and proven in a
namespace, and what is missing is a listener per profile and a policy rule per
mark so that the mark chooses an *exit* rather than only whether traffic enters
the tunnel.

After that, in order: driving the DNS backends against a live systemd-resolved;
a durable state store so runtime history survives a restart; editing from the
interface; and `cargo audit`/`cargo deny`.
