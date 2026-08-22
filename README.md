# xraytui

`xraytui` is a Linux-only, keyboard-first terminal client for
[Xray-core](https://github.com/XTLS/Xray-core). Its distinguishing feature is
**several independent egress profiles running concurrently through one supervised
core**: a browser can leave through a Hong Kong node while a shell leaves
directly and a backup job leaves through a two-hop chain, all at the same time,
each profile addressable by its own loopback SOCKS5/HTTP listener. Every profile
compiles to its own Xray balancer, so retargeting one profile is a single
`RoutingService.OverrideBalancerTarget` call — no core restart, no configuration
reload, and no disturbance to the connections belonging to the other profiles.

## Components

| Component      | Runs as              | Owns                                                                 |
|----------------|----------------------|----------------------------------------------------------------------|
| `xraytui`      | your user            | TUI and CLI. Performs no network mutation; talks to `xraytuid` over a Unix socket. |
| `xraytuid`     | your user            | Desired state, the Xray configuration compiler, core supervision, the gRPC client, the control socket. |
| `xraytui-netd` | system, capabilities | TUN device, routes, policy rules, nftables, DNS backends, cgroups. Accepts a closed set of typed operations only. |
| `xray`         | your user            | Data plane. The official upstream binary, supervised as a child process — never forked, never embedded. |

`xraytui-netd` is only needed for system-wide TUN mode, per-application
transparent routing and system DNS management. Per-profile SOCKS/HTTP listeners
and `xraytui exec` work without it.

## Install on Arch Linux

Xray-core is deliberately external. Install either AUR provider first, then
build the release package definition shipped in this repository:

```sh
paru -S xray-bin                       # or another package that provides xray
git clone https://github.com/jacek4yang/xraytui.git
cd xraytui/packaging/arch
makepkg -si
xraytui init
systemctl --user enable --now xraytuid.service
xraytui doctor
```

The PKGBUILD downloads the immutable `v1.1.0` source asset, verifies its SHA-256
checksum, builds with `Cargo.lock` frozen, runs the unprivileged test suite, and
installs the three binaries, hardened systemd units, completions, man pages and
documentation. See [docs/INSTALLATION.md](docs/INSTALLATION.md) for TUN setup,
upgrades and removal.

## Quick start

```sh
cargo build --release                          # needs protoc; see CONTRIBUTING.md
cargo xtask install --dry-run                  # print exactly what would be installed, where
xraytui init                                   # create private XDG configuration and state
xraytui doctor                                 # check xray binary, gRPC capabilities, permissions
xraytui node import --file ~/nodes.txt         # share links, one per line; use --qr for a QR image
xraytui node share hk-01                       # clean standard link on stdout
xraytui node share hk-01 --qr                  # terminal QR; --output node.png for private PNG
xraytui node share hk-01 jp-02 --as base64     # portable curated subscription
xraytui                                        # TUI: define profiles, pick targets, write rules
xraytui exec --profile work -- curl https://example.com   # exact, unprivileged per-process routing
xraytui mode cycle                             # off -> rule -> global -> direct (needs netd for TUN)
xraytui tun plan                               # show every intended kernel change before applying it
```

Share links and QR codes grant proxy access. Import reads from a file or stdin so
credentials need not land in shell history; export is an explicit reveal, keeps
stdout machine-clean, and writes files atomically with mode 0600. Standard VLESS,
VMess, Trojan, Shadowsocks, SOCKS, HTTP-proxy, WireGuard and Xray-native Hysteria
representations round-trip through the typed model. Lossy links are refused unless
the user explicitly opts in. See [docs/SHARING.md](docs/SHARING.md).

## What this is not

- **Linux only.** There is no Windows or macOS support and none is planned. The
  design depends on netlink, nftables, cgroup v2, `/dev/net/tun` semantics and
  `SO_PEERCRED`.
- **Not an Xray reimplementation.** xraytui does not embed, fork or vendor
  Xray-core. It generates JSON for, and drives, the official binary. Protocol
  support is whatever the installed core supports.
- **No telemetry.** No usage reporting, no crash upload, no automatic issue
  submission. Network access is limited to the endpoints you configured, plus
  GitHub when you explicitly ask for a managed core install or an upstream check.
- **No packet capture and no TLS interception.** Only routing metadata
  (inbound/outbound tag, network, address, port, matched rule) is ever read, via
  the core's own statistics API. No CA is generated or installed.
- **Not a sandbox.** Per-application routing is a routing convenience. An
  uncooperative local process can defeat it; see `docs/NETWORKING.md`.

## Status

Version 1.1.0 adds first-class interoperable sharing for a trusted single-user
Linux workstation. Post-release development now exercises deterministic
IPv4-only, IPv6-only, dual-stack and no-leak kernel paths plus real-Xray IPv6
endpoints, chains and split/failing DNS on stable and preview. `STATUS.md` keeps
published evidence separate from candidate evidence. IPv6 remains experimental
and disabled by default until group selection, the combined TUN/system resolver
path and broader failure injection receive equivalent coverage. Shared machines
with mutually untrusted local users are outside
the support boundary because Xray's loopback commander has no authentication.

`STATUS.md` is the authoritative, evidence-backed feature and test matrix;
`SECURITY.md` records the residual risks and dependency review.

## Documentation

| Document | Contents |
|---|---|
| `docs/ARCHITECTURE.md` | Component split, desired vs observed state, IPC boundaries, startup sequence, crate map. |
| `docs/XRAY-INTEGRATION.md` | Generated tag namespace, rule order, profile switching, group loopback, chains, upstream constraints. |
| `docs/CONFIGURATION.md` | XDG layout, permissions, every `config.toml` field, target/action token syntax. |
| `docs/SHARING.md` | Share-link fidelity, CLI/TUI workflows, QR behavior, portable subscriptions and secret handling. |
| `docs/NETWORKING.md` | TUN privilege separation, routes, marks, nftables, failure policies, per-application routing. |
| `docs/DNS.md` | DNS managers, Xray DNS module, split DNS, loop prevention, leak diagnostics. |
| `docs/TROUBLESHOOTING.md` | Symptom to cause to fix. |
| `docs/RECOVERY.md` | Manual removal of project-owned network state after a crash. |
| `docs/UPSTREAM-COMPATIBILITY.md` | Pinned Xray release, verified API surface, fallback implementations. |
| `docs/THREAT-MODEL.md` | Assets, trust boundaries, threats and mitigations. |
| `DECISIONS.md` | Architecture decision record. |
| `CONTRIBUTING.md` | Build prerequisites, quality gates, crate layering rules. |
| `SECURITY.md` | Reporting a vulnerability, trust boundaries, scope. |

## Licence

GPL-3.0-or-later, as declared by `license` in the workspace manifest.
