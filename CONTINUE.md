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

## 1.0.0 release work

* Correct the repository/version metadata and remove stale pre-implementation
  documentation.
* Replace the rc1 PKGBUILD's local unchecked source with a deterministic GitHub
  release asset, fixed checksum, complete dependency list and frozen full test
  build.
* Keep `xraytui-netd` as an explicitly enabled system service rather than asking
  the user service manager to start it.
* Add GitHub quality, security-policy and clean Arch package checks.
* Re-run the full quality, smoke, audit, package and live systemd-resolved gates.
* Merge the release PR, tag the merge commit, upload source/binary/checksum
  assets, and verify the public 1.0.0 release.

## Support boundary

Version 1.0.0 supports Linux `x86_64`, with current Arch Linux as tier one, for
one trusted interactive user. IPv4 is the supported path. IPv6 remains
experimental, off by default and fail-closed. Shared machines with mutually
untrusted local users are outside scope because the upstream Xray commander is
unauthenticated loopback TCP.

Never record an unexecuted gate as passing. `STATUS.md` is authoritative test
evidence; update its environment and counts from the final release run.
