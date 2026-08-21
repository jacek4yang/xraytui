# xraytui 1.0.0

The first daily-use release of a terminal client for Xray-core that runs several
independent egress profiles through one supervised core on Linux.

## Highlights

* Several profiles can expose their own loopback SOCKS5 and HTTP listeners at
  the same time. Switching one profile uses Xray's gRPC API and does not restart
  the core or disturb another profile.
* `xraytui exec` offers an unprivileged proxy-environment backend and an exact
  cgroup/pidfd transparent backend. Classification is verified before the
  requested program starts; failure is fail-closed.
* Nodes, groups, two-hop chains, subscriptions, application routing rules and
  listeners are editable from both the CLI and the 80x24-capable TUI.
* The per-user daemon persists desired and observed state in SQLite, supervises
  Xray-core, restarts it after unexpected exit, and rolls back failed runtime
  changes to the last known-good generation.
* The narrowly privileged `xraytui-netd` helper owns TUN, routes, policy rules,
  nftables, cgroups and DNS through a closed typed operation set. It never
  accepts a command line or shell fragment from the client.
* The Arch PKGBUILD verifies an immutable release asset, builds and tests with a
  frozen lockfile, and installs the binaries, hardened systemd units,
  completions, man pages and documentation through the same manifest exercised
  by the release smoke test.

## Important fixes since 1.0.0-rc1

* Corrected the release repository URL and replaced the PKGBUILD's unchecked
  local source with a versioned GitHub release asset and SHA-256 verification.
* Limited the Arch package to the actually verified `x86_64` architecture,
  completed its runtime/build dependency declarations, and made `check()` run
  the ordinary workspace integration tests as well as library tests.
* Fixed native dependency linking under Arch's makepkg flags by using the
  distribution SQLite and disabling incompatible global GCC LTO while keeping
  the project's Rust thin LTO.
* Removed an invalid cross-manager dependency: the per-user systemd service no
  longer tries to start the optional system-level network helper.
* Added repeatable GitHub quality, dependency-policy and clean Arch package
  checks for pull requests and the main branch.
* Updated installation and status documentation that still described already
  implemented TUN, state and editing features as scaffolding.
* Updated `h2` to 0.4.16 after the final audit detected the newly published
  RUSTSEC-2026-0258 advisory in rc1's lockfile.

The candidate itself fixed several more serious correctness gaps: a killed
Xray process had not been supervised by the shipping daemon; `app assign` had
printed TOML instead of mutating policy; narrow changes could bypass validation;
`init` could overwrite policy it could not parse; and a closed output pipe could
panic instead of ending normally.

## Support boundary

Linux `x86_64`; current Arch Linux is tier one. systemd, nftables, cgroup v2 and
an external Xray-core are required for the complete feature set. The intended
deployment is one trusted interactive user on a laptop or workstation.

IPv4 is the fully exercised path. IPv6 is implemented, disabled by default,
fail-closed and experimental until its runtime path receives equivalent
coverage. Shared machines with mutually untrusted local users are out of scope:
Xray's commander is loopback TCP without authentication, so a random local port
is not a security boundary.

## Security and privacy

There is no telemetry, crash upload, automatic issue submission, packet capture
or TLS interception. Share links, subscription URLs, QR codes and generated
Xray JSON contain credentials and should be handled as secrets. The release
installs no setuid files; only `xraytui-netd` runs as root, under a restricted
systemd unit and a closed protocol.

See `STATUS.md` for the evidence-backed test matrix, `SECURITY.md` for the
dependency review and residual risks, and `docs/INSTALLATION.md` for package and
first-run instructions.
