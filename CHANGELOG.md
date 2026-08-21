# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08-21

### Added

* First-class `node share` for one or many nodes: standard newline-separated
  links, conventional Base64 subscriptions, versioned normalized JSON and Xray
  outbound JSON. Selection accepts repeated node IDs, a subscription, or all
  nodes; stdout contains only the requested payload.
* Standard/de-facto serialization for VLESS, VMess (classic v2rayN JSON and
  modern authority form), Trojan, Shadowsocks SIP002, SOCKS, HTTP proxy,
  WireGuard and Xray-native Hysteria v2. Modern VLESS retains REALITY, Vision,
  XHTTP `extra`, `finalmask`, post-quantum verification, ECH, certificate pins,
  verified names, ALPN, fingerprints and every modeled transport field.
* Explicit `lossless`, `compatible`, `lossy` and `unsupported` export fidelity.
  Lossy standard output is refused until `--allow-lossy` is requested, with
  non-secret omitted field names reported on stderr.
* Terminal QR rendering with automatic H/Q/M/L correction selection and terminal
  fit checks; atomic mode-0600 PNG QR and text/JSON exports; clipboard transfer
  over stdin. Independent `quircs` acceptance tests decode captured half-block
  terminal output and PNG output, including long Unicode REALITY/XHTTP links.
* The Nodes TUI share menu (`Q`): show link, show QR, export PNG, export link, or
  export Xray JSON. Credential overlays are explicit, closable, and tested at
  80x24.
* Lossless `chain export` to Xray JSON. It retains every hop and
  `streamSettings.sockopt.dialerProxy` edge and refuses to masquerade as a
  portable single-node link.
* Sanitized current v2rayN/v2rayNG fixture corpus and import → export → re-import
  semantic equivalence tests. A loopback-only acceptance test additionally
  exports VLESS REALITY Vision, independently decodes its QR, re-imports it,
  compiles it, and carries a real connection through Xray stable and preview.
* A network-backed `cargo xtask upstream-check`: live stable/preview release and
  tag-commit checks, SHA-256 watches over 33 Xray connection/routing source
  paths, byte comparison of the eight vendored protobuf files, and watches over
  current v2rayN/v2rayNG share serializers. Reviewed snapshots live in
  `upstream-compat.toml`.

### Changed

* Node identity is now a SHA-256 canonical fingerprint of every modeled
  connection layer, including credential fingerprints, transport, TLS/REALITY,
  `finalmask`, mux, socket settings and unknown extension fields, while ignoring
  display name/source/tags. Rename/reorder no longer changes identity; endpoint,
  credential, protocol, transport or security changes do.
* Xray JSON import and compilation track modern mKCP `finalmask`, TLS ECH/pins/
  verified names/cipher fields, REALITY post-quantum verification, and Xray's
  native Hysteria protocol/transport split. WireGuard and Hysteria de-facto links
  are preserved as Xray nodes rather than mislabeled as foreign runtimes.
* mKCP share fields are compiled through a startup capability probe instead of a
  brittle version check. Stable v26.3.27 uses layered `header-*` and
  `mkcp-aes128gcm` masks; preview v26.7.28 uses repeated `mkcp-legacy` masks.
  Runtime, node export and chain export all use the selected binary's proven
  dialect.

### Fixed

* Export no longer emits an apparently valid link while silently dropping mux,
  socket options, custom WebSocket headers, VMess `alterId`, WireGuard routing,
  Hysteria-only fields, or dialect-specific extensions.
* `node list --format json` no longer serializes UUIDs or passwords; it emits a
  redacted summary and canonical fingerprint.
* A bare relative output such as `--output node.txt` no longer writes the file
  and then reports a false failure while trying to fsync an empty parent path.
* Hysteria port ranges using the older colon spelling are normalized before
  identity calculation, so export/re-import cannot rotate the node fingerprint.
* Hostile QR imports no longer traverse the advisory-affected `rqrr`/`lru`
  dependency path. The independent decoder is now `quircs`; input dimensions and
  decode allocation are bounded, ratatui is 0.30.2, `lru` is fixed at 0.18.2,
  and the release policy carries no RustSec ignores.
* Stable Xray's post-2026-06 removal of `allowInsecure` is enforced rather than
  silently ignored. Links requiring it remain preserved and explain why the
  installed core cannot execute them.
* TLS-only extension keys found on a REALITY link are retained for ecosystem
  round trips and mark the node degraded instead of being silently consumed as
  if current Xray REALITY used them.
* `node show` now redacts opaque `finalmask` values and preserved future query
  values as well as typed credentials. This closes a leak where an imported
  extension token or mask password could appear in ordinary inspection output.
* Cross-package CLI tests now stop the daemon gracefully, allowing it to reap
  the supervised Xray child rather than leaving orphan test processes behind.

## [1.0.0] - 2026-08-20

First daily-use release. See `STATUS.md` for the measured acceptance matrix and
`RELEASE-NOTES.md` for the supported deployment boundary.

### Added

* **Per-profile transparent egress — acceptance scenario M.** Two instances of
  the same executable, launched under two profiles, take two different exits at
  the same time, through one supervised core, with no proxy environment and no
  dependence on the program's name. Each profile gets a `dokodemo-door` inbound
  with `followRedirect` and `sockopt.tproxy`, tagged
  `inbound/profile/<id>/transparent`, routed into that profile's existing
  selector; the privileged helper marks each profile's cgroup with a mark derived
  from the credential and redirects it to that profile's listener with
  `tproxy ip to 127.0.0.1:<port>`. Proven end to end in a disposable namespace by
  `crates/controller/tests/netns_transparent.rs`, which also switches one
  profile's target through the gRPC API and asserts the other profile, the core's
  PID and the generation are all unchanged, then asserts that teardown leaves no
  chain, rule, route, cgroup, lease or interface behind and does not touch state
  the test itself created.

* `xraytui exec --transparent --profile P -- CMD`, which classifies **its own
  process** into P's cgroup, confirms the classification against
  `/proc/self/cgroup`, and only then `execve`s CMD — so there is no window in
  which the application runs unclassified. A refusal, or an acknowledgement the
  kernel does not agree with, means the command is not started at all.

* `EgressProfile.transparent`, a loopback listener spec. Validation refuses a
  non-loopback address, an IPv6 address, or credentials, rather than starting a
  listener nothing can reach or silently ignoring a field.


* A scheduler, shared by health probes and subscription updates: intervals with
  a floor, doubling backoff to a cap, jitter derived from a hash of the entry's
  key rather than a random number so deadlines are reproducible and stable
  across restarts, a bounded number of jobs per tick, and prioritisation that
  probes what a profile is using before what nobody has selected.

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

* The shipping daemon now notices and restarts an unexpectedly dead Xray-core;
  it no longer reports a dead PID as healthy indefinitely.
* `app assign` and `app unassign` mutate policy transactionally instead of
  printing a TOML snippet and exiting with failure.
* All CLI and TUI mutations use one validate, compile, reconcile and rollback
  path; narrow changes can no longer bypass model validation.
* `xraytui init` refuses to overwrite policy files it cannot parse.
* Closed stdout pipes terminate normally instead of panicking with a backtrace.
* The Arch package now uses the real repository and immutable release asset,
  verifies its checksum, declares complete dependencies, and installs through
  the canonical manifest.
* Clean Arch builds now link the distribution's SQLite and disable makepkg's
  incompatible global GCC LTO for native Rust dependency archives; the
  workspace's own Rust thin LTO remains enabled.
* The user systemd unit no longer tries to start the system-level network helper
  from the wrong service manager.
* `h2` was upgraded from 0.4.15 to 0.4.16 to fix RUSTSEC-2026-0258 before the
  final release.
* The privileged helper could not run `nft` at all: `Command::env_clear()` removes
  the `PATH` Rust uses to resolve a relative program name, so a bare name failed
  with `NotFound` on machines where the program was installed. Programs are now
  resolved to an absolute path against a fixed search list.
* A kernel without IPv6 answers every `AF_INET6` route message with `EOPNOTSUPP`,
  which turned an ordinary configuration into a rollback. The helper now installs
  the IPv4 half and reports what it left out.

### Known limitations

* IPv6 is experimental, disabled by default and fail-closed. IPv4 is the
  supported and fully exercised path for 1.0.0.
* Shared machines with mutually untrusted local users are out of scope because
  Xray's loopback TCP commander has no authentication.
* The Arch package is verified and published for `x86_64` only.

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
