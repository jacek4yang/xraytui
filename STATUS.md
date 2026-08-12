# Status

**Not production ready.** Two of the fourteen mandatory acceptance scenarios are
implemented and passing end to end against a real Xray-core; four more pass in
part; the privileged-networking scenarios are **not implemented** and are marked
as such below rather than claimed.

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
| `cargo test --workspace` | **pass**, 342 tests, 0 failures |
| `cargo doc --workspace --no-deps` | **pass**, 0 warnings |
| `cargo build --release --workspace` | **pass** |
| `cargo xtask manifest --prefix /usr` | **pass**, 23 entries, no setuid |

`cargo nextest` was not available in this environment; the ordinary `cargo test`
path is the one that was exercised.

`cargo audit` and `cargo deny` were **not run** — neither tool is installed here
and installing them was out of scope for the session. No advisory has therefore
been reviewed or accepted; treat the dependency set as unaudited.

### Test breakdown

| Crate | Tests | Notes |
|---|---|---|
| `xraytui-domain` | 55 | includes proptests for the slug and bounded-regex code |
| `xraytui-import` | 67 | includes proptests asserting no panic on arbitrary input |
| `xraytui-config` | 34 | permissions, atomicity, schema rejection, migration ladder |
| `xraytui-xray-compiler` | 41 + 6 | the 6 are validated by a real `xray run -test` |
| `xraytui-ipc` | 25 | framing limits, version negotiation, streaming, filters |
| `xraytui-controller` | 24 + 6 | the 6 are the acceptance scenarios against a real core |
| `xraytui-cli` | 33 + 9 | the 9 run the real `xraytui`/`xraytuid` binaries |
| `xraytui-netd-protocol` | 17 | validation of the privileged operation set |
| others | remainder | secrets, xray-model, xray-api, test-support |

## Acceptance scenarios

| ID | Scenario | State |
|----|---|---|
| **A** | two profiles, two SOCKS ports, two mock egresses, simultaneously | **passing** — `controller/tests/acceptance.rs` |
| **B** | hot-switch one profile via gRPC; other unchanged; no restart | **passing** — asserts identical PID and generation |
| C | shared TUN rule mode, per-app routing in a netns | **not implemented** — needs `xraytui-netd` |
| D | two apps concurrently plus DNS following policy | **partial** — the two-app half is scenario A; DNS is unimplemented |
| **E** | two-hop chain reaches the terminal through hop 1 | **passing** — proven by a connection count at the transit hop |
| F | import valid/malformed/unsupported node representations | **passing at unit level** — 67 tests including proptests; not wired to a live subscription |
| G | subscription add/change/remove with diff and rollback | **not implemented** — the diff types and transactional model exist; the fetcher does not |
| H | terminal and PNG QR round-trip decode | **passing at unit level** — `render_png` → `decode_png` reproduces the exact string |
| **I** | kill Xray in restore mode | **passing** — listener death observed, backoff restart scheduled and verified |
| J | kill the daemon while TUN is active; lease expiry cleanup | **not implemented** — needs `xraytui-netd` |
| K | repeated TUN enable/disable leaves no residue | **not implemented** — needs `xraytui-netd` |
| L | TUI usable at 80x24, restores the terminal | **not implemented** — see below |
| M | cgroup v2 exact-instance isolation | **not implemented** — the operation set and validation exist; the backend does not |
| N | clean build and install; nothing runs as root | **partial** — build, install manifest and units are done and verified; a from-scratch install on a clean Arch host was not performed |

## What is not implemented

Stated plainly, because a half-built privileged component is worse than an absent
one:

1. **`xraytui-netd` and `xraytui-linux-net` are stubs.** The privileged
   *protocol* is complete, documented and tested (`crates/netd-protocol`, 17
   tests) — it defines exactly what root can be asked to do, validates every
   field, and derives all resource names from the `SO_PEERCRED` UID. The
   implementation behind it — TUN creation, netlink routes, nftables, DNS
   backends, cgroups, leases — is not written. Consequently:
   - system TUN modes (`direct`, `global`, `rule`) cannot come up;
   - `xraytui tun plan` reports that it needs the helper;
   - `xraytui exec --transparent` refuses with a typed reason rather than
     silently falling back;
   - scenarios C, D (DNS half), J, K and M are untestable.

   `mode set rule` currently *compiles and starts* a TUN inbound if asked, but
   without the helper nothing configures addresses or routes, so no traffic
   flows through it. That is a rough edge: the daemon should refuse the mode
   outright when the helper is absent.

2. **The TUI does not exist.** `xraytui` with no subcommand, and `xraytui tui`,
   print a message saying so and exit non-zero. Everything the TUI would show is
   available through the CLI, including `--format json` for scripting.

3. **Subscriptions cannot be fetched.** The domain model, diff types, transaction
   semantics, HTTP fixture server and size caps are all in place; the client that
   performs the fetch is not. `xraytui node import --file` and `--stdin` do work,
   so a subscription can be updated by hand with `curl | xraytui node import
   --stdin`.

4. **The state store is a stub.** Runtime history and health history live in
   memory and are lost when the daemon restarts. Policy is durable — it is TOML
   on disk — so nothing the user configured is at risk.

5. **`xraytui app assign` prints the TOML to add** rather than editing the file.
   Application rules are compiled and routed correctly once present; only the
   editing command is missing.

6. **No `cargo audit`/`cargo deny` run.** See above.

7. **Health probing is not scheduled.** `xraytui node test` probes on demand and
   works; the periodic sweep with prioritisation and backoff is not wired up.

## Upstream findings

Four things were discovered by testing against the real core rather than by
reading documentation. All four are load-bearing.

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

## Privileged tests

**None were run against real host networking, and none are claimed.**

This session ran in a disposable cloud container as uid 0. That is not the same
as the user's machine, and modifying real routing, DNS or nftables was out of
scope regardless. No test in this repository creates a TUN device, changes a
route, writes an nftables rule or touches a resolver.

The commands that *would* exercise the privileged paths, once `xraytui-netd` is
implemented, are:

```sh
# In a disposable network namespace, never on the host.
sudo unshare --net --mount --pid --fork -- \
    cargo test -p xraytui-linux-net --features netns-tests -- --test-threads=1

# Capability report, safe to run anywhere; performs no changes.
xraytui-netd --check-capabilities

# Dry run: prints every intended change without making one.
xraytui tun plan
```

## Environment this was verified in

| | |
|---|---|
| Kernel | Linux 6.18.5 x86_64 |
| Distribution | Ubuntu 24.04 (container) — **not** the tier-one Arch target |
| Rust | 1.95.0, edition 2024, MSRV declared 1.90 |
| Xray-core | v26.3.27, SHA2-256 verified against the official `.dgst` |
| protoc | 3.21.12 |
| Privileges | uid 0 in a container; no host networking was touched |

The tier-one target is current Arch Linux with systemd, nftables and cgroup v2.
Nothing here was tested on Arch.

## The next single most important thing

Implement `xraytui-linux-net` behind the existing `netd-protocol` operation set,
starting with `CreateTun` + `ApplyRouting` and the lease, and prove it in a
network namespace. That one piece unblocks acceptance scenarios C, D, J, K and M
— five of the six that are currently untestable — and is the only remaining
component that the rest of the system is already written to expect.
