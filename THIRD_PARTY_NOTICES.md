# Third-party notices

xraytui is GPL-3.0-or-later. This file records what it depends on and under what
terms. Generate the authoritative, version-exact inventory with:

```sh
cargo install cargo-about && cargo about generate about.hbs
# or
cargo tree --format '{p} {l}' --prefix none | sort -u
```

That has **not** been run for this revision; see `STATUS.md`.

## Xray-core

xraytui does not link, embed, fork or reimplement Xray-core. It runs the official
`xray` binary as a supervised external process and speaks to it over its gRPC
API. Xray-core is licensed under the **Mozilla Public License 2.0**
(<https://github.com/XTLS/Xray-core/blob/main/LICENSE>) and is a separate work,
obtained and installed independently by the user or their distribution.

The protobuf definitions under `vendor/xray-proto/` are copied verbatim from
XTLS/Xray-core at tag `v26.3.27`, commit
`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`, and remain under the MPL-2.0. They
are vendored so that an ordinary build never fetches code from a moving branch.
Modifying those files would trigger MPL-2.0's file-level copyleft; they are not
modified.

## Rust dependencies

Direct dependencies and their usual licences. Verify with `cargo about` before a
release rather than trusting this table.

| Crate | Purpose | Licence |
|---|---|---|
| tokio, tokio-util, tokio-stream | async runtime | MIT |
| tonic, tonic-prost, prost, prost-types | gRPC and protobuf | MIT / Apache-2.0 |
| hyper-util, tower, http | transport for tonic | MIT |
| serde, serde_json, toml, ciborium | serialisation | MIT / Apache-2.0 |
| clap, clap_complete, clap_mangen | command line, completions, man pages | MIT / Apache-2.0 |
| ratatui, crossterm, unicode-width | terminal interface | MIT |
| rustix, libc, nix, socket2 | Linux syscalls | Apache-2.0 WITH LLVM-exception / MIT / BSD-3 |
| reqwest | HTTP client, rustls only, no OpenSSL | MIT / Apache-2.0 |
| qrcode, image, rqrr | QR generation and decoding | MIT / Apache-2.0 |
| secrecy, zeroize | secret handling | MIT / Apache-2.0 |
| rusqlite | embedded state store | MIT |
| uuid, ipnet, base64, hex, url, percent-encoding | small utilities | MIT / Apache-2.0 |
| tracing, tracing-subscriber | structured logging | MIT |
| thiserror, anyhow | error types | MIT / Apache-2.0 |
| proptest, tempfile, insta, assert_cmd, predicates | testing | MIT / Apache-2.0 |

`rustls` is used in preference to OpenSSL throughout, so xraytui carries no
dependency on a system TLS library.

## Data files

`geoip.dat` and `geosite.dat` are **not** distributed with xraytui. They are
provided by the user's distribution (`xray-geoip`, `xray-geosite` on Arch) under
their own terms, and are only read, never modified.
