# Installation

Linux only. The tier-one target is current Arch Linux with systemd, nftables and
cgroup v2; Debian stable, Ubuntu LTS and current Fedora are secondary targets.

Read `STATUS.md` first: several components are not implemented yet, and the
system TUN is one of them.

## Prerequisites

| | |
|---|---|
| Rust | the toolchain in `rust-toolchain.toml`; MSRV 1.90 |
| protoc | `protobuf` (Arch) / `protobuf-compiler` (Debian) |
| Xray-core | a hard runtime dependency; xraytui supervises it, it does not embed it |
| geodata | optional; needed only for `geoip:`/`geosite:` rules |

## From source

```sh
cargo build --release --workspace
sudo cargo xtask install --prefix /usr
systemctl --user enable --now xraytuid.service
xraytui doctor
```

`cargo xtask install --dry-run` prints every file it would place, and
`DESTDIR=/tmp/stage cargo xtask install --prefix /usr` stages an install for
packaging. Nothing is ever installed setuid.

Only if you want the system TUN, which is **not implemented yet**:

```sh
sudo systemctl enable --now xraytui-netd.service
sudo usermod -aG xraytui "$USER"     # log out and back in
```

## Arch

```sh
cd packaging/arch
makepkg -si
```

The `PKGBUILD` runs `cargo test --lib` during `check()` — the privileged and
network-namespace tests are deliberately excluded, because a package build must
not need `CAP_NET_ADMIN` and must not touch host networking.

## What gets installed where

| Path | What |
|---|---|
| `/usr/bin/xraytui` | TUI and CLI, unprivileged |
| `/usr/bin/xraytuid` | per-user daemon, unprivileged |
| `/usr/bin/xraytui-netd` | privileged helper, capabilities from systemd |
| `/usr/lib/systemd/user/xraytuid.service` | user service |
| `/usr/lib/systemd/system/xraytui-netd.service` | system service |
| `/usr/lib/tmpfiles.d/xraytui.conf` | `/run/xraytui` |
| `/usr/lib/sysusers.d/xraytui.conf` | the `xraytui` group |
| `/usr/share/man/man1/xraytui*.1` | man pages |
| `~/.config/xraytui/` | your configuration, created on first run |

## First run

The daemon writes a starter configuration on first start: one `direct` profile
with loopback SOCKS and HTTP listeners, mode `off`. Nothing is proxied until you
add a node.

```sh
xraytui node import 'vless://…'
xraytui profile set-target direct node:<id>
xraytui up
xraytui exec --profile direct -- curl -s https://example.com
```

## Upgrading

```sh
cargo build --release --workspace
sudo cargo xtask install --prefix /usr
systemctl --user restart xraytuid.service
xraytui doctor
```

Configuration is migrated automatically, after a timestamped backup of the whole
configuration directory beside it. A file written by a *newer* xraytui is a hard
error rather than a best-effort parse, so a downgrade cannot silently mangle
policy.

## Uninstalling

```sh
systemctl --user disable --now xraytuid.service
sudo systemctl disable --now xraytui-netd.service
sudo cargo xtask uninstall --prefix /usr
```

Your configuration is left alone. Remove it deliberately:

```sh
rm -rf ~/.config/xraytui ~/.local/state/xraytui ~/.cache/xraytui
```

If networking was left modified by a crash, see `docs/RECOVERY.md`.
