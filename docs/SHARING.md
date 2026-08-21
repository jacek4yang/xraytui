# Node sharing and interoperable export

Sharing is an explicit credential-reveal operation. xraytui uses established
V2Ray/Xray ecosystem formats; it does not invent an `xraytui://` replacement and
does not run another proxy core.

## One node

```sh
xraytui node share hk-01                         # one link on stdout
xraytui node share hk-01 --qr                    # terminal QR on stdout
xraytui node share hk-01 --qr --output hk.png    # private PNG
xraytui node share hk-01 --png hk.png            # equivalent PNG form
xraytui node share hk-01 --output hk.txt          # private link file
xraytui node share hk-01 --as xray-json           # lossless Xray outbound
xraytui node share hk-01 --format json            # link + fidelity metadata
```

Serialized data is the only content written to stdout. Warnings, fidelity notes,
and file status go to stderr, so `xraytui node share hk-01 >node.txt` and shell
pipelines remain clean. `--clipboard` writes the credential to `wl-copy` or
`xclip` over standard input; it never puts the link in a child process argument.

In the TUI, select a row in **Nodes**, press `Q`, and choose **Show QR**,
**Show share link**, **Export PNG QR**, **Export share link**, or **Export Xray
JSON**. A complete credential appears only after this explicit action. The share
menu and overlays fit 80x24; a QR that does not fit is refused with its required
dimensions and a suggestion to export PNG.

## Several nodes and portable subscriptions

Repeat node identifiers, select a subscription, or select the complete node set:

```sh
xraytui node share hk-01 jp-02 us-03
xraytui node share --subscription provider-a
xraytui node share --all

xraytui node share hk-01 jp-02 --as links       # one link per line
xraytui node share hk-01 jp-02 --as base64      # conventional Base64 subscription
xraytui node share hk-01 jp-02 --as json        # versioned normalized nodes
xraytui node share hk-01 jp-02 --as xray-json   # Xray outbound collection
```

`links` and `base64` are the portable ecosystem forms. Normalized JSON is an
optional lossless xraytui representation, and Xray JSON is for Xray-aware tools;
neither replaces standard links. QR output deliberately requires exactly one
node—one QR is never made to imply a set.

## Formats and fidelity

| Node kind | Standard/de-facto output | Notes |
|---|---|---|
| VLESS | `vless://` authority/query | encryption, flow, raw, WS, HTTPUpgrade, gRPC, XHTTP, mKCP, TLS, REALITY, ECH, certificate pins/names, ALPN, fingerprint, `fm`, `pqv`, SpiderX |
| VMess | classic v2rayN Base64 JSON or authority/query `vmess://` | `auto` chooses classic for broad compatibility and authority form when modern fields need it |
| Trojan | `trojan://` authority/query | flow, transports, TLS/REALITY fields where representable |
| Shadowsocks | SIP002 `ss://` | modern Xray cipher and password form; SIP003 plugins are preserved but never executed |
| SOCKS | `socks://` | credentials are portable; Xray-specific stream settings are not |
| HTTP proxy | `http-proxy://` | avoids confusing a proxy node with an HTTP subscription URL |
| WireGuard | `wireguard://` v2rayN/v2rayNG dialect | one peer, key material, address, reserved bytes and MTU |
| Xray Hysteria v2 | `hysteria2://` / `hy2://` dialect | auth, TLS, SNI, ALPN, pins, ECH, salamander and port hopping |

Every link export has one of four fidelity states:

| State | Meaning |
|---|---|
| `lossless` | all modeled connection-critical settings are represented |
| `compatible` | a different ecosystem spelling is expected to make an equivalent connection |
| `lossy` | meaningful settings were omitted after explicit authorization |
| `unsupported` | no safe standard representation exists; use normalized or Xray JSON where possible |

Lossy standard output is refused by default. The error names only the unrepresented
field classes and recommends lossless Xray JSON. `--allow-lossy` is an explicit
override and prints every omission to stderr; there is no silent fallback.
Examples that require this decision include mux/socket options, custom WebSocket
headers, VMess `alterId`, multi-peer or policy-rich WireGuard, and Hysteria fields
with no common URI key. Unknown imported query parameters are retained and
re-emitted when the selected dialect can carry them.

`--vmess-format auto|classic|standard` controls the VMess dialect. Forcing a
dialect that cannot carry the node is subject to the same lossy refusal.

## QR behavior

The encoder starts at QR error correction H, then tries Q, M, and L only when the
payload needs more capacity. A four-module quiet zone is always included. The
terminal renderer packs two module rows into Unicode half blocks; `--invert`
swaps modules for a dark default terminal background. PNG uses a monochrome
module grid and defaults to eight pixels per module.

The TUI uses the inverted form because its normal palette is dark. Both the
ordinary light-background capture and inverted dark-background capture are
rasterized with their real foreground/background meaning and decoded by the
independent scanner in tests.

QR byte capacity is 2,953 bytes (version 40-L). A larger share link can still be
exported as text or Xray JSON, but it cannot honestly be represented by a single
QR and is refused. Both terminal block captures and PNG files are decoded in
tests by `quircs`, an implementation independent of the `qrcode` encoder. The
long-link case contains REALITY, XHTTP `extra`, `finalmask`, Unicode, and enough
query data to force a large symbol.

## Secrets and files

A link, Base64 subscription, normalized export, Xray JSON file, and QR all grant
proxy access. They are not logged, stored in SQLite history, included in normal
node lists, or placed in diagnostic bundles. Complete values appear only on an
explicit share command or TUI action.

File exports use a sibling created with `O_CREAT|O_EXCL` and mode 0600, write and
fsync it, force mode 0600, atomically rename it, then fsync the parent directory.
An existing world-readable destination is replaced rather than retaining its
mode. Temporary files are removed on failure. The destination path—not its
contents—is safe to include in an error.

## Chains

An arbitrary chain is not a node and is never flattened into a misleading
`vless://`, `trojan://`, or other single-node link. Share individual members with
`node share`. Export the complete composition with:

```sh
xraytui chain export hk-jp-us
xraytui chain export hk-jp-us --output hk-jp-us.json
```

This emits credential-bearing Xray JSON containing every cloned hop and every
`streamSettings.sockopt.dialerProxy` edge. stdout carries only JSON; stderr says
that the result is not a portable single-node link. File output is mode 0600.

## Evidence and maintenance

The relevant executable evidence is:

```sh
cargo test -p xraytui-import
XRAYTUI_TEST_XRAY=/path/to/stable/xray \
  cargo test -p xraytui-controller --test acceptance \
  exported_vless_reality_vision_reimports_and_carries_a_real_connection
XRAYTUI_TEST_XRAY=/path/to/preview/xray \
  cargo test -p xraytui-xray-compiler --test xray_validates_output \
  cross_client_share_links_recompile_for_real_xray
cargo xtask upstream-check
```

The fixture corpus under `crates/import/tests/fixtures/` represents current
v2rayN and v2rayNG serializers with synthetic credentials. `upstream-compat.toml`
pins the official Xray stable/preview source paths and the active v2rayN/v2rayNG
serializer paths by SHA-256. A change makes `upstream-check` require review of
the typed model, parser, serializer, compiler, and round-trip corpus together.
