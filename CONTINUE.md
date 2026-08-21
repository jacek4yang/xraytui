# Continuation state

## Repository and release target

* GitHub: `https://github.com/jacek4yang/xraytui`
* Base release: `v1.0.0`, commit `f9051059af1e331c0577e41dfa3c45d7b0907c33`
* Development branch: `feature/node-sharing-interoperability`
* Intended semantic version: `v1.1.0` (new backward-compatible CLI/TUI and
  interchange capability; do not create the tag before the verified PR merge)
* Official Xray stable under test: `v26.3.27`
* Explicit preview under test: `v26.7.28`

## Implemented on the branch

First-class standard link export now covers VLESS, both VMess dialects, Trojan,
Shadowsocks, SOCKS, HTTP proxy, WireGuard and Xray-native Hysteria v2. Export has
explicit fidelity and refuses silent omissions. CLI/TUI sharing, captured
terminal QR, private PNG/text/JSON output, portable multi-node subscriptions,
chain-safe Xray JSON, stable semantic fingerprints, current cross-client
fixtures, modern Xray fields and a real loopback VLESS REALITY connection test
are implemented. `docs/SHARING.md` is the behavioral specification.

`cargo xtask upstream-check` is no longer a placeholder. It checks live release
channels and tag commits, Xray source snapshots, the vendored protobuf closure,
and current v2rayN/v2rayNG serializer paths against `upstream-compat.toml`.

## Final pre-publication evidence executed

These are candidate-branch results, not claims about an unbuilt public artifact.

* Final fmt, all-target/all-feature check, strict Clippy and debug workspace build
  passed.
* Stable v26.3.27 and preview v26.7.28 each reported 799 passing workspace test
  instances, zero failures and one privilege-gated ignored test. The ignored
  TUN/DNS validation passed separately with `CAP_NET_ADMIN` on both binaries and
  left no `xraytui0` device.
* The disposable namespace script executed all 12 Linux-network scenarios and
  the one exact-instance CLI/helper/core scenario without a skip.
* `cargo xtask ci`, release workspace build and `scripts/release-smoke.sh`
  passed.
* Live `cargo xtask upstream-check` passed for stable/preview release tags, exact
  commits, 33 Xray paths, eight protobuf files and both ecosystem serializer
  sets.
* `cargo deny check` passed. A fresh RustSec clone at
  `bf5c0d245a92671908518d7e765914d437954ed6` loaded 1,225 advisories and found
  no issue in 436 locked dependencies.
* Independent terminal/PNG QR, cross-client round-trip, portable-subscription,
  chain and live loopback REALITY evidence all passed on the relevant channel.
* Three deterministic source-archive builds matched. An unprivileged clean Arch
  `makepkg` build, `namcap`, installed-unit verification, first-run permission,
  setuid absence and uninstall-retention checks passed. The recipe remaps Rust
  generated-source paths instead of embedding makepkg's temporary directory.
* A checksum-verified published 1.0.0 portable artifact created daemon state and
  node `upgrade-node-01a0242c370d`; the 1.1.0 Arch package reopened it with the
  same ID, exported it with the new share command and retained it on uninstall.

## Required next steps

1. Push the feature branch, open the PR with the evidence
   table, monitor every required CI job, and fix root causes.
2. Merge only after mandatory checks pass. Tag the verified merged `main` commit,
   build/publish using the established process, retrieve the public artifacts,
   verify checksums and tag ancestry independently, then run clean install and
   smoke tests from the downloaded artifact.

Never record an unexecuted gate as passing. `STATUS.md` remains the authoritative
published evidence matrix.
