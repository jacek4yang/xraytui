# Contributing

## Prerequisites

* The Rust toolchain pinned in `rust-toolchain.toml` (currently 1.95.0). The
  declared MSRV is lower, so distribution packagers can build with an older
  stable.
* `protoc` — `protobuf-compiler` on Debian/Ubuntu, `protobuf` on Arch. The
  vendored `.proto` files are committed; a build never downloads them.
* Xray-core, for the integration tests. Without it those tests print
  `SKIPPED …` and pass; they never silently do nothing.

```sh
cargo build --workspace
cargo test --workspace
```

Point the tests at a specific core with `XRAYTUI_TEST_XRAY=/path/to/xray`, and
at geodata with `XRAY_LOCATION_ASSET=/usr/share/xray`.

## Quality gates

`cargo xtask ci` runs all of these; CI runs the same list.

```sh
cargo fmt --all --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

## Layering rules

These are not style preferences; breaking them breaks testability.

| Rule | Why |
|---|---|
| `xraytui-domain` depends on nothing from this project except `xraytui-secrets` | so the model can be tested without a core, a terminal or a socket |
| No crate outside `crates/tui` mentions `ratatui`; none outside `crates/cli` mentions `clap`; none outside `crates/xray-api` mentions `tonic` | keeps front ends replaceable |
| `unsafe` is forbidden everywhere except `crates/linux-net` | and there, every block documents its invariants |
| `unwrap`/`expect`/`panic` are denied in non-test code in `controller`, `daemon-ipc`, `netd-protocol` and both daemons | a panicking daemon leaves the host in an unknown state |
| The compiler performs no I/O | so its output is a pure function of the model, and diffable |

## Tests

Write the test that would have caught the bug, not the test that exercises the
code. Prefer a test that asserts an externally observable property — "traffic
left through egress B" — over one that asserts an internal call happened.

* Unit and property tests live beside the code.
* Tests needing a real core live in `tests/` and skip loudly without one.
* Tests needing privileges live behind a feature flag and run only in a network
  namespace. **Never write a test that modifies host networking.**

```sh
# Privileged tests, in a disposable namespace.
sudo unshare --net --mount --pid --fork -- \
    cargo test -p xraytui-linux-net --features netns-tests -- --test-threads=1
```

## Re-checking upstream

```sh
cargo xtask upstream-check
```

Fetches official stable and preview release metadata, resolves both tag commits,
and byte-compares watched Xray source/protobuf files and mature-client serializer
sources against `upstream-compat.toml`. It requires network access and fails
closed on drift. Inspect every reported change, update the manifest and
`docs/UPSTREAM-COMPATIBILITY.md` **with the date you checked**, then rerun real
stable/preview compiler and share-link tests. Hash equality detects change; real
Xray proves behavior.

## Commits

Explain why, not what. If you discovered something about upstream, put it in
`docs/UPSTREAM-COMPATIBILITY.md`; if you made a decision someone might reverse
later, put it in `DECISIONS.md`.
