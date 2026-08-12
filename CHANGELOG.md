# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial implementation. Not production ready — see `STATUS.md` for the honest
per-scenario state.

### Added

* Subscription fetching, as four stages of which only the last can change
  anything: fetch (streamed under a size cap, conditional on the recorded
  `ETag`), normalise (base64 or plain, bounded-regex filters, dedup), diff
  (identity by canonical fingerprint, so a rename keeps the node's identifier
  and the profiles pointing at it), and apply (on a clone, validated before it
  is returned). Refuses to remove a node something points at, and refuses an
  update that would empty the node list — a provider outage looks exactly like
  one. `xraytui subscription diff` and `update` share the code, so the preview
  cannot disagree with what it previews.

* The interactive interface (`xraytui`, or `xraytui tui`): six panes, an
  incremental filter, a target picker that switches a profile without restarting
  the core, and a key reference generated from the same table the tests press.
  Designed for 80x24; degrades by dropping panes rather than wrapping; restores
  the terminal on a clean exit, an error and a panic.

* `xraytui-linux-net` and `xraytui-netd`: the privileged network backend and the
  helper that speaks the operation set. A safe rtnetlink client, persistent TUN
  creation, the project's nftables table, cgroup v2 classification by `pidfd`,
  systemd-resolved over a minimal D-Bus client, `resolvconf`, leases, capability
  probing and dry-run planning. Nine tests prove it against a real kernel inside
  a disposable namespace (`sudo ./scripts/netns-test.sh`), covering acceptance
  scenarios C, J, K and part of M.
* `xraytui tun plan`: the exact list of intended changes, and the nftables
  ruleset verbatim, before anything is applied. Works with or without a helper
  installed, and says which.
* Every route and policy rule the helper installs carries routing protocol 114,
  so cleanup removes only what this project created. A route or rule put in the
  same table by anything else survives a full teardown, which is asserted by
  test.
* `xtask/tests/no_shell.rs`: the threat model's "no shell, one program resolver,
  unsafe in one module" claims asserted against the source rather than only
  written down.

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

### Fixed

* The privileged helper could not run `nft` at all: `Command::env_clear()` removes
  the `PATH` Rust uses to resolve a relative program name, so a bare name failed
  with `NotFound` on machines where the program was installed. Programs are now
  resolved to an absolute path against a fixed search list.
* A kernel without IPv6 answers every `AF_INET6` route message with `EOPNOTSUPP`,
  which turned an ordinary configuration into a rollback. The helper now installs
  the IPv4 half and reports what it left out.

### Known limitations

* Nothing runs on a schedule: health probes and subscription updates both work
  on demand only.

* The interface can switch profiles, cycle the mode and probe nodes, but cannot
  yet create a node, edit a rule or add a subscription; those stay CLI-only.
* Per-profile transparent egress: cgroup classification and marking work, but
  selecting a different exit per profile needs a `tproxy` inbound per profile.
* Runtime history is in memory only.
* The DNS backends have not been driven against a live resolver.

### Upstream findings

Against Xray-core:

* Xray rejects a routing rule with no conditions.
* A balancer `fallbackTag` requires an observatory, or the core will not start.
* mKCP `header`/`seed` were removed in v26.3.27 in favour of `finalmask`.
* The commander listens on TCP only; `api.listen` cannot be a Unix socket.
* Linux Xray cannot consume an inherited TUN file descriptor.

Against the kernel and userland:

* nftables 1.0.9's JSON parser cannot express `socket cgroupv2`; it emits the
  expression lossily and rejects it on input.
* nftables resolves a cgroup path at parse time, against `/sys/fs/cgroup` only.
* `Command::env_clear()` leaves the child with no `PATH`, which Rust uses to
  resolve a relative program name.
* A kernel without IPv6 rejects every `AF_INET6` route message, including
  blackhole routes.
