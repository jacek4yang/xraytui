# Continuation State

## Repository

* GitHub: `https://github.com/jacek4yang/xraytui`
* Release branch: `release/1.0.0`
* Base: `main` at the complete `v1.0.0-rc1` tree
* Target release: `v1.0.0`

The original history was recovered from the verified rc1 bundle and pushed in
full, including `recovery-baseline`, `v1.0.0-rc1`, `main` and `release/v1`.

## What rc1 already proved

* 761 workspace tests passed, plus 12 kernel namespace tests and one full
  transparent-routing acceptance test.
* The release smoke test exercised init, mutations, subscriptions, concurrent
  profiles, hot switching, QR export, crash supervision, persistence,
  installation and uninstall through the real binaries.
* `cargo audit` found no vulnerabilities; three transitive warnings were
  reviewed in `SECURITY.md`, and `cargo deny check` passed.
* The source snapshot and Git bundle were checksum-verified and restored to the
  same tagged tree.

## 1.0.0 release result

* Repository/version metadata and stale pre-implementation documentation were
  corrected.
* The rc1 PKGBUILD was replaced by an immutable, checksum-pinned release source,
  complete runtime/build dependencies, frozen full tests and the canonical
  installer. A clean current-Arch build, package install and `namcap` passed.
* `xraytui-netd` remains an explicitly enabled system service; the user manager
  no longer tries to start a unit from the wrong manager.
* GitHub quality, security-policy and clean Arch package checks run on PRs and
  `main`.
* Full quality, real-Xray smoke, audit, deny, 12+1 namespace, live
  systemd-resolved and package gates passed. `STATUS.md` records the evidence.
* The release PR is merged before `v1.0.0` is tagged; source/binary/checksum
  assets are attached to the public GitHub release and verified after upload.

## Support boundary

Version 1.0.0 supports Linux `x86_64`, with current Arch Linux as tier one, for
one trusted interactive user. IPv4 is the supported path. IPv6 remains
experimental, off by default and fail-closed. Shared machines with mutually
untrusted local users are outside scope because the upstream Xray commander is
unauthenticated loopback TCP.

Never record an unexecuted gate as passing. `STATUS.md` is authoritative test
evidence; update its environment and counts from the final release run.
