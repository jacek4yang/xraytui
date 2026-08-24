# Installation

Linux only. The tier-one target is current Arch Linux with systemd, nftables and
cgroup v2; Debian stable, Ubuntu LTS and current Fedora are secondary targets.

Read `STATUS.md` for the tested feature matrix. IPv4 is the supported path in
1.1.0; IPv6 is experimental, disabled by default and fail-closed.

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
xraytui init
systemctl --user enable --now xraytuid.service
xraytui doctor
```

`cargo xtask install --dry-run` prints every file it would place, and
`DESTDIR=/tmp/stage cargo xtask install --prefix /usr` stages an install for
packaging. Nothing is ever installed setuid.

Only if you want the system TUN or transparent per-process routing:

```sh
sudo systemctl enable --now xraytui-netd.service
sudo usermod -aG xraytui "$USER"     # log out and back in
```

The helper setup alone does not currently make official Xray's Linux TUN usable
from the packaged user service. Upstream Xray itself performs
`LinkSetMTU`/`LinkSetUp`, and a systemd-resolved-facing listener binds port 53;
the hardened user unit intentionally has neither required capability. Run
`xraytui doctor` and treat `xray-tun-privilege` or
`xray-dns-listen-privilege` as blocking findings. Do not grant broad capabilities
manually; per-profile SOCKS/HTTP listeners are the supported installed path.

## Arch

Xray-core is available from the AUR. Install one package that provides `xray`
before using plain `makepkg`; an AUR helper can resolve that provider for you:

```sh
paru -S xray-bin                       # or xray / xray-git
git clone https://github.com/jacek4yang/xraytui.git
cd xraytui/packaging/arch
makepkg --verifysource                 # verify the release asset before building
makepkg -si
```

The PKGBUILD follows Arch's Rust packaging guidance: it fetches the exact locked
dependency graph in `prepare()`, builds and tests with `--frozen`, and supports
only the verified `x86_64` architecture. Privileged and live-host tests are
explicitly opt-in and skip during `check()`; all ordinary workspace unit and
integration tests run. Installation goes through the same typed manifest used
by the release smoke test, so binaries, systemd units, completions, man pages and
documentation cannot silently drift between install methods.

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

Run `xraytui init` once. It creates private XDG directories, a starter policy
with one `direct` profile and loopback SOCKS/HTTP listeners, and the versioned
state database. It is idempotent and refuses to overwrite policy it cannot
parse. Nothing is proxied until you add a node.

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

For an Arch package upgrade, rebuild from the updated PKGBUILD and use
`makepkg -si`; its install hook reminds you to restart the user daemon.

Configuration is migrated automatically, after a timestamped backup of the whole
configuration directory beside it. A file written by a *newer* xraytui is a hard
error rather than a best-effort parse, so a downgrade cannot silently mangle
policy.

Share-link, QR and chain JSON exports are intentionally outside the configuration
tree. They are credential-bearing transfer artifacts, not backups, and are not
migrated during an upgrade. Remove or protect old exports yourself after the
recipient imports them.

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
