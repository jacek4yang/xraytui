# Status

Version 1.1.0 is the verified candidate for one trusted interactive user on a
Linux `x86_64` workstation, with current Arch Linux as the tier-one target. It
is not a published release until its clean package gate, PR merge, tag, public
artifacts, downloaded-checksum verification and clean artifact install all
complete. The historical 1.0.0 evidence remains below.

IPv4 is the supported and fully exercised path. IPv6 is implemented,
fail-closed and disabled by default, but its runtime path has not received
equivalent coverage and remains experimental. Shared machines with mutually
untrusted local users are outside scope because Xray's loopback TCP commander
has no authentication.

Last published-release verification: 2026-08-20. Candidate evidence updated:
2026-08-21. An unexecuted test is never recorded as passing.

## 1.1.0 candidate sharing evidence (pre-release)

| Capability | Current branch evidence |
|---|---|
| standard links | VLESS, VMess classic/authority, Trojan, Shadowsocks, SOCKS, HTTP proxy, WireGuard and Xray-native Hysteria unit round trips pass |
| modern VLESS | REALITY Vision, XHTTP `extra`, `finalmask`, ECH, pins/names, ALPN, fingerprint, `pqv`, SpiderX and IPv6 literals survive normalized round trips |
| cross-client corpus | eight sanitized current v2rayN/v2rayNG links import, export and re-import to the same canonical semantic set |
| terminal QR | captured Unicode half-block output independently decodes with `quircs` to the exact original link |
| PNG QR | mode-0600 PNG independently decodes with `quircs`, including a long REALITY/XHTTP/Unicode link |
| portable subscription | multi-node Base64 output independently decodes, imports again, and produces the same canonical node set |
| live REALITY | export → PNG QR decode → re-import → compile → real loopback connection passes separately with Xray v26.3.27 and v26.7.28 |
| chain semantics | `chain export` retains all hop outbounds and `dialerProxy` edges, validates against stable Xray and never emits a single-node link |
| secret handling | JSON node lists and opaque `node show` fields are redacted; output files replace atomically at 0600; relative and absolute destinations are tested; clipboard payload uses stdin |
| upstream review | live stable/preview releases and commits, 33 Xray source snapshots, eight vendored protobuf files, and current v2rayN/v2rayNG serializer paths are checked by `cargo xtask upstream-check` |

## 1.1.0 candidate gate evidence

| Gate | Candidate result |
|---|---|
| `cargo fmt --all --check` | **pass** |
| `cargo check --workspace --all-targets --all-features` | **pass** |
| strict all-target/all-feature Clippy | **pass**, zero warnings |
| stable v26.3.27 workspace | **pass**: Cargo reported 799 passed, 0 failed, 1 privilege-gated ignored across 45 result sets |
| preview v26.7.28 workspace | **pass**: Cargo reported 799 passed, 0 failed, 1 privilege-gated ignored across 45 result sets |
| ignored TUN/DNS Xray validation | **pass separately** with `CAP_NET_ADMIN` on both stable and preview; `xraytui0` absent afterward |
| privileged namespaces | **pass**: 12 kernel/network scenarios plus one real CLI/helper/core exact-instance scenario; no skip |
| `cargo xtask ci` | **pass**: fmt, check, strict Clippy, workspace build/test and rustdoc |
| `cargo xtask upstream-check` | **pass** against live GitHub release/tag/source state on 2026-08-21 |
| `cargo deny check` | **pass**: advisories, bans, licenses and sources |
| `cargo audit` | **pass** against fresh advisory-db commit `bf5c0d245a92671908518d7e765914d437954ed6`: 1,225 advisories, 436 locked dependencies, zero findings |
| release workspace build | **pass** with all features |
| `scripts/release-smoke.sh` | **pass** against stable Xray: sharing, supervision, persistence, staged install/permissions/uninstall |
| deterministic archive / clean Arch / `namcap` / package install-upgrade | **pending**; do not inherit 1.0.0's result |
| PR/CI/merge/tag/public artifact verification | **pending** |

## Published 1.0.0 release evidence

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
| H | terminal and PNG QR round-trip decode | **passing on the 1.1.0 candidate branch**: both a captured terminal module matrix and PNG are decoded by independent `quircs`; **published 1.0.0 remained partial** |
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
4. **1.1.0 publication.** Clean packaging, upgrade and retrieved-public-artifact
   verification remain pending and must not be inferred from the 1.0.0 table.
5. **Diagnostic bundles.** There is no automatic bundle exporter yet. Bug
   reports must use `doctor`, `status` and manually reviewed log excerpts; never
   attach generated JSON, policy files, share exports or QR images.

## Security posture

There is no telemetry, crash upload, packet capture or TLS interception.
Credentials in share links, subscription URLs, QR codes and generated Xray JSON
are redacted from normal output and logs, but exported material must still be
handled as secret.

The 1.0.0 audit found RUSTSEC-2026-0258 in `h2` 0.4.15 and upgraded it to
0.4.16. The 1.1.0 candidate additionally removed the advisory-affected
`rqrr`/`lru` QR path. Its release policy has no RustSec ignores, and the fresh
audit and `cargo deny check` results are recorded above and in `SECURITY.md`.

## Privileged-test containment

The 12+1 network tests run only in a new network, mount, PID and UTS namespace
with a private cgroup v2 hierarchy. They refuse to proceed unless only loopback
and project-created interfaces are visible. The live resolved test is separately
opt-in: it creates its own `xraytui-t0` link, applies DNS only to that link,
verifies through `resolvectl`, reverts twice and deletes the link. Post-test
checks confirmed the interface no longer existed.
