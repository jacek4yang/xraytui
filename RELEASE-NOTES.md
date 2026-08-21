# xraytui 1.1.0

xraytui 1.1 makes node sharing a first-class terminal workflow while preserving
the project's Linux-only, terminal-only and official-Xray-only runtime boundary.

## Highlights

* `xraytui node share NODE` writes one clean standard share link to stdout.
  Repeated node IDs, `--subscription` and `--all` export newline-separated links,
  conventional Base64 subscriptions, normalized JSON or Xray outbound JSON.
* VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP proxy, WireGuard and Xray-native
  Hysteria representations round-trip through the typed model. Modern VLESS
  carries Vision, REALITY, XHTTP, gRPC, WS, HTTPUpgrade, raw and mKCP semantics,
  including ECH, pins, verified names, `finalmask`, `pqv` and SpiderX where the
  ecosystem link format defines them.
* Link fidelity is explicit. Lossless and compatible output proceeds; lossy
  output is refused unless `--allow-lossy` is an explicit user decision. Xray
  JSON remains available when a common single-node URI is not faithful.
* `--qr` renders a terminal QR; `--qr --output FILE` and `--png FILE` create a
  private PNG. Both light-terminal and dark-TUI block captures, plus PNG files,
  are decoded by the independent `quircs` scanner in acceptance tests.
* The Nodes TUI has one `Q` share menu for QR, complete link, private PNG/link
  files and Xray JSON. Secret overlays are explicit and zeroized on close.
* `chain export` writes the complete Xray composition, retaining every hop and
  `dialerProxy` edge. A chain is never flattened into a misleading node link.

## Interoperability and Xray compatibility

The sanitized corpus comes from the current v2rayN and v2rayNG serializer
families. Import → export → re-import compares canonical connection semantics,
and exported configurations are checked by real stable v26.3.27 and preview
v26.7.28 binaries. A loopback VLESS REALITY Vision case additionally carries an
actual connection after link export, independent QR decode and re-import.

Preview Xray changed the JSON representation of legacy mKCP share fields. The
daemon now capability-probes the selected binary: stable uses layered masks and
preview uses repeated `mkcp-legacy` masks. Runtime config, node Xray JSON and
chain JSON therefore follow observed core behavior instead of version guesses.

`cargo xtask upstream-check` now verifies the live stable/preview releases and
tag commits, 33 reviewed Xray source/schema snapshots, the eight vendored
protobuf files and the current v2rayN/v2rayNG serializer paths.

## Security and privacy

Share links, portable subscriptions, normalized/Xray JSON and QR codes are
credentials. Ordinary lists and inspection redact typed and opaque fields;
clipboard helpers receive data over stdin; file exports are atomic siblings
created and forced to mode 0600. No generated link is logged or placed in
SQLite history.

QR import no longer uses the advisory-affected `rqrr`/`lru` path. The release
uses `quircs`, bounds image dimensions and decoder allocation, upgrades ratatui
and `lru`, and carries no RustSec advisory ignore. The final candidate audit
used a fresh 1,225-advisory database and found no vulnerability in 436 locked
dependencies.

## Support boundary

Linux `x86_64`; current Arch Linux is tier one. The complete data plane remains
the official external Xray-core—no Clash, Mihomo, sing-box or other core is
executed. IPv4 is the fully exercised path. IPv6 remains implemented,
fail-closed, disabled by default and experimental pending equivalent runtime
coverage. Shared machines with mutually untrusted local users remain outside
scope because Xray's commander is unauthenticated loopback TCP. Automatic
diagnostic-bundle export is not implemented; use `doctor`, `status` and manually
reviewed log excerpts.

See `docs/SHARING.md` for interchange behavior, `STATUS.md` for exact evidence,
and `SECURITY.md` for the threat model and dependency record.
