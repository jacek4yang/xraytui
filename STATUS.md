# Status

Version 1.0.0 is ready for its supported deployment: one trusted interactive
user on a Linux `x86_64` workstation, with current Arch Linux as the tier-one
target. Thirteen of the fourteen acceptance scenarios pass. Scenario H has
unit and release-smoke coverage but remains partial because no test decodes a
QR code from an actual terminal capture.

IPv4 is the supported and fully exercised path. IPv6 is implemented,
fail-closed and disabled by default, but its runtime path has not received
equivalent coverage and remains experimental. Shared machines with mutually
untrusted local users are outside scope because Xray's loopback TCP commander
has no authentication.

Last verified: 2026-08-20. An unexecuted test is never recorded as passing.

## Release evidence

| Gate | Result |
|---|---|
| `cargo xtask ci` | **pass**: fmt, all-target/all-feature check, Clippy with `-D warnings`, workspace build, 761 tests, doctests and docs |
| `cargo build --release --workspace` | **pass** |
| `scripts/release-smoke.sh` with Xray-core 26.3.27 | **pass**: init, mutations, subscriptions, concurrent exits, hot switching, QR export, crash restart, persistence, install and uninstall |
| `sudo scripts/netns-test.sh` | **pass**: 12 kernel/network tests plus one full transparent-routing CLI/helper/core scenario |
| `cargo audit` | **pass**: 0 vulnerabilities; three reviewed transitive warnings documented in `SECURITY.md` |
| `cargo deny check` | **pass** |
| deterministic source archive | **pass**: two independent runs produced identical bytes and SHA-256 |
| `makepkg --verifysource` | **pass** |
| clean Arch `makepkg` | **pass** as an unprivileged builder: frozen release build, all 761 ordinary tests, typed installation and package creation |
| `namcap PKGBUILD` | **pass** with no findings |
| `namcap` package inspection | only expected runtime-tool dependency notices and dynamic-loader false positives |
| live `systemd-resolved` | **pass** against the real `org.freedesktop.resolve1`; `resolvectl` independently observed the link DNS and its removal |
| package installation | **pass**: versions 1.0.0, 77 files present, shared SQLite resolved, no setuid/setgid binary, private first-run state permissions |
| `systemd-analyze verify` | **pass** for both installed units, including their man-page references |

The clean package gate used the official `archlinux:base-devel` image
`20260816.0.574111`, Rust 1.97.1, protobuf 35.1, systemd 261.2, sqlite 3.53.4,
nftables 1.1.6 and iproute2 7.2.0. It found and fixed an Arch-specific release
problem before publication: makepkg's global GCC LTO produced native archives
that Rust's lld link step could not consume. The PKGBUILD now disables that
global LTO while retaining the workspace's Rust thin LTO, and links Arch's
maintained shared SQLite rather than bundling a duplicate copy.

The host integration gates used Debian 13, kernel 6.12.100, Rust 1.95.0,
protobuf 3.21.12 and the official Xray-core 26.3.27 binary. The Xray archive's
SHA-256 matched its official `.dgst` file before use.

## Acceptance scenarios

| ID | Scenario | State and evidence |
|---|---|---|
| A | two profiles, two SOCKS ports and two exits simultaneously | **passing** in controller acceptance tests and release smoke |
| B | hot-switch one profile; other profile and core PID unchanged | **passing** against real Xray gRPC |
| C | shared TUN rule mode and per-app routing | **passing** in the disposable network namespace; kernel route lookup is the oracle |
| D | concurrent applications and DNS following policy | **passing across integration boundaries**: A/M prove concurrent classification, compiler tests prove DNS interception, and the real resolve1 test proves apply/revert; there is no single monolithic test |
| E | two-hop chain reaches the terminal through hop one | **passing** with an observed transit connection |
| F | import valid, malformed and unsupported node representations | **passing**, including property tests over arbitrary input |
| G | subscription add/change/remove, diff and rollback | **passing** against a real local HTTP fixture |
| H | terminal and PNG QR round-trip decode | **partial**: PNG encode/decode round-trip passes and release smoke exports both forms; terminal pixels are not captured and decoded by an independent scanner |
| I | kill Xray in restore mode | **passing**: listener death, backoff and a new live PID are observed |
| J | daemon loss while TUN is active; lease cleanup | **passing** for disconnect and expired-lease recovery |
| K | repeated TUN enable/disable leaves no residue | **passing** over three cycles, checking links, routes, rules, nftables and leases |
| L | TUI usable at 80x24 and restores the terminal | **passing**; every documented key and byte-exact restoration are tested |
| M | cgroup v2 exact-instance isolation | **passing** through the real CLI, helper and Xray: two instances of one executable take different exits, then only one hot-switches |
| N | clean build/install and privilege boundary | **passing** in clean Arch: the user daemon is a user unit, only the optional helper is a system unit, and no installed file is setuid/setgid |

## What works

* Multiple independent SOCKS5/HTTP profiles share one supervised Xray-core.
  Runtime target switching does not restart the core or disturb other profiles.
* Nodes, profiles, groups, two-hop chains, subscriptions, listeners and routing
  rules are editable from the CLI and TUI through one validate/compile/apply/
  rollback path.
* `xraytui exec` supports proxy-environment and fail-closed transparent
  cgroup/pidfd backends. A command is not executed until its classification is
  verified.
* SQLite persists runtime state, health history, subscription metadata and
  interrupted operations. Policy remains human-readable TOML and is backed up
  before migration.
* The per-user daemon supervises Xray, restarts it after unexpected exit and
  restores the last known-good generation after failed changes.
* The narrowly privileged helper owns TUN, routes, rules, nftables, cgroups and
  DNS through a closed typed protocol. Production code never spawns a shell.
* The TUI fits 80x24, supports the complete daily editing surface, redacts
  secrets and restores the terminal after normal or interrupted exit.

## Remaining limitations

1. **IPv6 runtime coverage.** The code has IPv6 validation, routing and
   fail-closed behaviour, but the release's privileged scenarios intentionally
   use IPv4. IPv6 stays off by default and outside the 1.0 support promise.
2. **Untrusted local users.** Upstream Xray commander traffic uses
   unauthenticated loopback TCP. A random local port is not a security boundary.
3. **Architecture.** The package and binary archive are verified only for
   `x86_64`; no `aarch64` artifact is claimed.
4. **Terminal QR decoding.** The terminal renderer is tested structurally and
   in release smoke, but scenario H will not be called complete until an
   independent decoder reads an actual terminal capture.

## Security posture

There is no telemetry, crash upload, packet capture or TLS interception.
Credentials in share links, subscription URLs, QR codes and generated Xray JSON
are redacted from normal output and logs, but exported material must still be
handled as secret.

The final dependency audit found RUSTSEC-2026-0258 in `h2` 0.4.15, published
after rc1. `Cargo.lock` was updated to the fixed 0.4.16 and every quality,
package and integration gate above was run with that version. The remaining
three RustSec warnings are reviewed transitive risks, not known vulnerabilities;
their exact reachability and decisions are in `SECURITY.md` and `deny.toml`.

## Privileged-test containment

The 12+1 network tests run only in a new network, mount, PID and UTS namespace
with a private cgroup v2 hierarchy. They refuse to proceed unless only loopback
and project-created interfaces are visible. The live resolved test is separately
opt-in: it creates its own `xraytui-t0` link, applies DNS only to that link,
verifies through `resolvectl`, reverts twice and deletes the link. Post-test
checks confirmed the interface no longer existed.
