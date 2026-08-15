# Third-party notices

xraytui is GPL-3.0-or-later. It links the Rust crates below; the table is
generated from `Cargo.lock` by `cargo deny list`, so it cannot drift from what
is actually built.

| Licence | Crates |
|---|---|
| `Apache-2.0` | 232 |
| `Apache-2.0 WITH LLVM-exception` | 7 |
| `BSD-2-Clause` | 2 |
| `BSD-3-Clause` | 4 |
| `BSL-1.0` | 1 |
| `GPL-3.0-or-later` | 20 |
| `ISC` | 7 |
| `LGPL-2.1-or-later` | 2 |
| `MIT` | 282 |
| `MPL-2.0` | 2 |
| `Unicode-3.0` | 19 |
| `Unlicense` | 3 |
| `Zlib` | 3 |

Two crates offer a licence not in the allow-list as one option of a dual
licence — `ryu` (Apache-2.0 OR BSL-1.0) and `r-efi` (MIT OR Apache-2.0 OR
LGPL-2.1-or-later). Both are taken under their permissive option, which is what
`cargo deny check` resolves and accepts.

## Xray-core

Xray-core is **not** linked, vendored or redistributed here. xraytui supervises
it as an external process, the way a service manager does. It is MPL-2.0 and is
obtained from its own official releases or from the distribution's `xray`
package. The protobuf definitions under `vendor/xray-proto/` are copied from
Xray-core to generate the gRPC client, and carry Xray-core's licence.

Full licence texts ship with each crate in the Cargo registry and with
Xray-core's own distribution.
