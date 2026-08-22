# Continuation state

## Repository and release target

* GitHub: `https://github.com/jacek4yang/xraytui`
* Published release: `v1.1.0`, merged commit
  `2eb98ba87093a1e2b88d16c50666c717d8e7890f`
* Release PR: <https://github.com/jacek4yang/xraytui/pull/3>
* Release page: <https://github.com/jacek4yang/xraytui/releases/tag/v1.1.0>
* Merged dual-stack kernel branch: PR #5, commit
  `2f13f4144516b27f4a9745ee701eb91af24df84e`
* Merged real-Xray IPv6 and DNS branch: PR #6, commit
  `cb8ba42628964795bfd7c9d0393ccd8ba07b9c05`
* Current development branch: `feat/dns-bootstrap-safety`
* Official Xray stable under test: `v26.3.27`
* Explicit preview under test: `v26.7.28`

## Implemented in 1.1.0

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

## Unreleased hostname-bootstrap increment

`feat/dns-bootstrap-safety` adds explicit `dns.bootstrap_servers` and schema 3.
The compiler resolves every possible hostname-based first hop through exact,
direct, IP-hosted bootstrap resolvers and converts only that locally dialled
outbound copy to the matching Xray `ForceIP*` strategy. Nodes, chain hop 1,
group candidates, WireGuard peer endpoints, and permitted profile/group
fallbacks are covered; later `dialerProxy` hops retain remote DNS semantics.
Missing, hostname-valued, unsupported-scheme, self-listening, and unavailable
bootstrap routes fail closed.

Stable v26.3.27 and preview v26.7.28 each pass 852 ordinary workspace tests,
five doctests, 15 real-Xray controller cases, the isolated privileged TUN/DNS
validator, and 21+1 disposable-namespace scenarios. The real fixtures observe
direct bootstrap DNS followed by proxied DNS, then separately prove that failed
bootstrap makes zero ordinary-direct, proxy, and proxied-resolver connections.
`cargo xtask ci`, live 55-snapshot upstream checking, dependency policy,
RustSec audit, release build, and stable release smoke all pass.

## Final release evidence executed

These results include the merged commit and retrieved public artifact.

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
* Deterministic source-archive builds under umask 0002 and 0022 match. An
  unprivileged clean Arch
  `makepkg` build, `namcap`, installed-unit verification, first-run permission,
  setuid absence and uninstall-retention checks passed. The recipe remaps Rust
  generated-source paths instead of embedding makepkg's temporary directory.
* A checksum-verified published 1.0.0 portable artifact created daemon state and
  a node; the 1.1.0 Arch package reopened it with the byte-identical persisted
  ID, exported it with the new share command and retained it on uninstall.
* PR #3 passed all mandatory GitHub jobs and merged as
  `2eb98ba87093a1e2b88d16c50666c717d8e7890f`. The annotated `v1.1.0` tag peels
  to that commit.
* All seven public assets were downloaded into a fresh directory. Both checksum
  files passed independently; the source and binary SHA-256 values are recorded
  in `STATUS.md`, and the Arch metadata matched the tag byte-for-byte.
* The downloaded public binaries passed the complete release smoke workflow and
  a separate clean Arch filesystem install with systemd verification, version,
  mode-0600 first-run state and setuid/setgid checks.

## Required next steps

1. Keep IPv6 experimental until IPv6 group selection, combined TUN +
   systemd-resolved + proxied-upstream DNS, and broader failure injection execute
   deterministically. Hostname bootstrap dependency detection is implemented on
   `feat/dns-bootstrap-safety` with stable/preview real-Xray evidence.
2. Add an automatic redacted diagnostic-bundle exporter without including
   policy, generated Xray JSON, share links, QR images or subscription secrets.

Never record an unexecuted gate as passing. `STATUS.md` remains the authoritative
published evidence matrix.
