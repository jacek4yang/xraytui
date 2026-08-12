# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial implementation. Not production ready — see `STATUS.md` for the honest
per-scenario state.

### Added

* Typed domain model with validated identifiers, secret wrappers that redact in
  `Debug`/`Display`, and a bounded regex engine for group filters.
* Deterministic Xray configuration compiler: one balancer per egress profile
  switchable through `OverrideBalancerTarget`, groups compiled through a loopback
  second stage, chains linked with `sockopt.dialerProxy`, a blackhole outbound
  first, and an explicit terminal catch-all.
* gRPC client for Xray's Handler, Routing, Stats and Logger services, generated
  from protobuf files vendored at v26.3.27, with probe-based capability
  detection.
* `xraytuid`: desired-state controller, core supervision with health gating and
  last-known-good rollback, single-instance locking, versioned CBOR control
  socket with event streaming.
* `xraytui`: the documented command surface with plain, JSON, dmenu, dwmblocks
  and shell output; stable exit codes; `exec` with a `socks5h` proxy environment;
  share links and terminal/PNG QR codes; shell completions and man pages.
* Share-link import and export for VLESS, VMess, Trojan, Shadowsocks (SIP002 and
  legacy), SOCKS and HTTP, plus Xray JSON import. Unsupported protocols are
  preserved rather than dropped.
* The closed privileged operation set for `xraytui-netd`, validated and tested,
  with all resource names derived from the caller's `SO_PEERCRED` UID.
* Arch `PKGBUILD`, hardened systemd units, tmpfiles and sysusers fragments, and a
  typed `cargo xtask` installer with `--dry-run` and `DESTDIR` support.

### Known limitations

* `xraytui-netd` and `xraytui-linux-net` are stubs: no TUN, routing, nftables,
  DNS management or cgroup classification.
* No TUI.
* Subscriptions cannot be fetched; nodes can be imported by hand.
* Runtime history is in memory only.

### Upstream findings

* Xray rejects a routing rule with no conditions.
* A balancer `fallbackTag` requires an observatory, or the core will not start.
* mKCP `header`/`seed` were removed in v26.3.27 in favour of `finalmask`.
* The commander listens on TCP only; `api.listen` cannot be a Unix socket.
* Linux Xray cannot consume an inherited TUN file descriptor.
