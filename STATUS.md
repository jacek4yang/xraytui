# Status

Version 1.1.0 is published and verified for one trusted interactive user on a
Linux `x86_64` workstation, with current Arch Linux as the tier-one target. The
release, tag and artifacts are at
<https://github.com/jacek4yang/xraytui/releases/tag/v1.1.0>. The historical
1.0.0 evidence remains below.

IPv4 is the supported and fully exercised path. IPv6 is implemented,
fail-closed and disabled by default, but its runtime path has not received
equivalent coverage and remains experimental. Shared machines with mutually
untrusted local users are outside scope because Xray's loopback TCP commander
has no authentication.

Last published-release verification: 2026-08-21. An unexecuted test is never
recorded as passing.

## Unreleased dual-stack candidate evidence

This section describes unreleased `main` after PRs #5 and #6, not the published
artifact. On 2026-08-22, `./scripts/netns-test.sh` executed 21 privileged kernel
scenarios plus the real CLI/helper/Xray exact-instance scenario with no skip, once with
`XRAYTUI_TEST_XRAY=/tmp/xray-bin-stable/xray` (v26.3.27) and again with
`XRAYTUI_TEST_XRAY=/tmp/xray-bin-preview/xray` (v26.7.28). The new scenarios
keep usable direct IPv4 and IPv6 defaults present while proving:

* dual-stack marked sockets select the TUN address in both families;
* IPv4-only and IPv6-only policies blackhole the disabled family instead of
  falling through to those direct defaults;
* explicit proxied-IPv4/direct-IPv6 and proxied-IPv6/direct-IPv4 policies select
  the intended source address;
* a contradictory family update is refused before changing the working route
  table;
* a lease written before the family flags existed recovers both families from
  the live TUN addresses during an in-place upgrade;
* a nested namespace with both IPv6 disable sysctls set refuses an IPv6 TUN
  before mutation, while IPv4 plus an IPv6 blackhole remains available;
* after deletion of a dual-stack TUN makes both marked kernel lookups resolve to
  the direct device, nftables rejects one real UDP packet per family and the
  project guard's counter advances from zero to two.

This closes the kernel routing and kill-switch coverage gap. The next candidate
increment also executes real Xray over an IPv6 proxy endpoint, concurrent IPv4
and IPv6 profiles, a two-hop IPv6 chain, and split AAAA DNS through a two-hop
IPv6 chain. Proxied-resolver failure attempts the configured profile but makes
zero connections to the available direct resolver. Compile-time and live
selector checks additionally refuse implicit resolvers or any supposedly
proxied DNS profile/group path that can select direct traffic. IPv6 is still not
promoted: IPv6 group selection, the combined TUN + DNS + systemd-resolved path,
bootstrap DNS-cycle detection and broader failure injection remain unexecuted.

| Candidate gate | 2026-08-22 result |
|---|---|
| stable v26.3.27 workspace | **pass**: 837 passed, 0 failed, 1 privilege-gated ignored across 45 result sets |
| preview v26.7.28 workspace | **pass**: 837 passed, 0 failed, 1 privilege-gated ignored across 45 result sets |
| ignored TUN/DNS Xray validator | **pass separately** with `CAP_NET_ADMIN` against stable and preview; `xraytui0` absent before and after |
| privileged namespaces | **pass twice**: 21 kernel/network scenarios plus one real CLI/helper/Xray exact-instance scenario with stable and preview; no skip |
| real-Xray controller acceptance | **pass twice**: 13/13 with stable and 13/13 with preview; includes IPv6 endpoint, concurrent dual-stack profiles, two-hop IPv6 data and DNS chains, split direct/proxy DNS, and fail-closed resolver failure |
| `cargo xtask ci` | **pass** after the final DNS hot-path/no-leak review: fmt, check, strict Clippy, workspace build/test and rustdoc |
| `cargo xtask upstream-check` | **pass** against live Xray release/tag/source state and reviewed v2rayN/v2rayNG serializer snapshots |
| `cargo deny check` | **pass**: advisories, bans, licenses and sources |
| `cargo audit --no-fetch` | **pass** after manually fast-forwarding the database to RustSec commit `bf5c0d245a92671908518d7e765914d437954ed6`: 1,225 advisories, 436 locked dependencies, zero findings |
| release workspace build | **pass** with all features after the final DNS policy hardening |
| `scripts/release-smoke.sh` | **pass** against stable Xray: first run, mutations, subscriptions, concurrent exits, hot switching, sharing, supervision, restart, persistence and staged install/uninstall |
| PR/CI/merge | PR [#6](https://github.com/jacek4yang/xraytui/pull/6) **passed and merged** as `cb8ba42628964795bfd7c9d0393ccd8ba07b9c05`; replacement CI run [32591713629](https://github.com/jacek4yang/xraytui/actions/runs/32591713629) passed Rust quality, dependency policy and clean Arch package jobs. Its first run exposed `ETXTBSY` while executing a generated fake-`resolvconf`; commit `a8edb020d693e9f3f56c8da19820c89b6dfa7844` removed deterministic path reuse and made the PR rerun green, but post-merge `main` run [32592576152](https://github.com/jacek4yang/xraytui/actions/runs/32592576152) reproduced the error on the unique inode. Follow-up PR [#7](https://github.com/jacek4yang/xraytui/pull/7) removes generated-file execution entirely: tests execute stable `/bin/sh` and pass the unique recorder as script input. The focused suite, no-production-shell policy, 1,000 repeated fixture executions and complete all-feature Rust gates pass locally; required CI run [32592971946](https://github.com/jacek4yang/xraytui/actions/runs/32592971946) passed Rust quality, dependency policy and clean Arch packaging. PR #7 is merged only after any later head change passes the same required gates. |

## Published 1.1.0 sharing evidence

| Capability | Release evidence |
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

## Published 1.1.0 gate evidence

| Gate | Release result |
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
| deterministic source archive | **pass**: independent builds under umask 0002 and 0022 produce identical bytes and SHA-256; CI enforces the comparison |
| clean Arch `makepkg` | **pass** as an unprivileged builder: frozen release build/tests and typed package installation |
| `namcap` | PKGBUILD has no findings; package has only reviewed runtime-tool dependency and dynamic-loader false positives |
| package install/uninstall | **pass**: all three versions report 1.1.0, `systemd-analyze verify` passes, no setuid/setgid binary, first-run files are 0600, uninstall retains user state |
| 1.0.0 → 1.1.0 upgrade | **pass** from the checksum-verified published 1.0.0 portable artifact to the 1.1.0 Arch package: daemon state reopened, its persisted node ID remained byte-for-byte identical, and the new share command exported it |
| PR/CI/merge | **pass**: PR [#3](https://github.com/jacek4yang/xraytui/pull/3) merged as `2eb98ba87093a1e2b88d16c50666c717d8e7890f`; Rust, dependency-policy and clean-Arch jobs all passed |
| tag and public artifacts | **pass**: annotated `v1.1.0` peels to the merged commit; all seven assets were downloaded again; source SHA-256 is `96cb495f885bffb106033b6b3684646e61b2e1d3a9512183368f5eea2f0c1f3b`, binary SHA-256 is `913cb58fe612b2f6487e61a681787493fee9f2d433cb7c1052ee1677f5d08ca9` |
| downloaded artifact verification | **pass**: both checksum files, byte-identical Arch metadata, complete release smoke and a separate clean Arch filesystem install/systemd verification |

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
| D | concurrent applications and DNS following policy | **passing across integration boundaries**: A/M prove concurrent classification; real stable/preview Xray sends split AAAA queries through the observed direct path or every hop of the selected IPv6 chain; the real resolve1 test proves apply/revert. The combined TUN + resolve1 + proxied-upstream scenario remains unexecuted |
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

1. **IPv6 end-to-end coverage.** The post-release candidate proves IPv4-only,
   IPv6-only, dual-stack and broken-route kernel behavior plus real Xray IPv6
   endpoints, chains and split/failing DNS. IPv6 group selection and the
   combined TUN + systemd-resolved + proxied-upstream path remain unexecuted, so
   IPv6 stays off by default and experimental.
2. **DNS bootstrap cycles and per-profile overrides.** Proxied upstream DNS
   requires the default profile and fails closed, but automatic detection of a
   hostname-based first hop depending on the same resolver is not implemented.
   Keep an independent bootstrap resolver or use an IP-literal first hop. The
   reserved per-profile `dns_policy` field is explicitly refused, not ignored.
3. **Untrusted local users.** Upstream Xray commander traffic uses
   unauthenticated loopback TCP. A random local port is not a security boundary.
4. **Architecture.** The package and binary archive are verified only for
   `x86_64`; no `aarch64` artifact is claimed.
5. **Diagnostic bundles.** There is no automatic bundle exporter yet. Bug
   reports must use `doctor`, `status` and manually reviewed log excerpts; never
   attach generated JSON, policy files, share exports or QR images.

## Security posture

There is no telemetry, crash upload, packet capture or TLS interception.
Credentials in share links, subscription URLs, QR codes and generated Xray JSON
are redacted from normal output and logs, but exported material must still be
handled as secret.

The 1.0.0 audit found RUSTSEC-2026-0258 in `h2` 0.4.15 and upgraded it to
0.4.16. The 1.1.0 release additionally removed the advisory-affected
`rqrr`/`lru` QR path. Its release policy has no RustSec ignores, and the fresh
audit and `cargo deny check` results are recorded above and in `SECURITY.md`.

## Privileged-test containment

The 12+1 network tests run only in a new network, mount, PID and UTS namespace
with a private cgroup v2 hierarchy. They refuse to proceed unless only loopback
and project-created interfaces are visible. The live resolved test is separately
opt-in: it creates its own `xraytui-t0` link, applies DNS only to that link,
verifies through `resolvectl`, reverts twice and deletes the link. Post-test
checks confirmed the interface no longer existed.
