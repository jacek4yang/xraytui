# Testing

## The pyramid

| Layer | Where | Needs |
|---|---|---|
| unit and property | beside the code | nothing |
| compiler-versus-core | `crates/xray-compiler/tests/` | an Xray binary |
| acceptance | `crates/controller/tests/acceptance.rs` | an Xray binary |
| end-to-end | `crates/cli/tests/end_to_end.rs` | an Xray binary; runs the real daemon and CLI |
| privileged | `crates/linux-net` behind a feature | a network namespace, **never the host** |

Tests that need a core skip with a printed `SKIPPED …` rather than passing
silently. Nothing in this repository requires internet access, a public proxy or
a public resolver.

```sh
cargo test --workspace
XRAYTUI_TEST_XRAY=/usr/bin/xray XRAY_LOCATION_ASSET=/usr/share/xray cargo test --workspace
```

## How "which proxy did this traffic take?" is proven

The central difficulty in testing a proxy client is that success looks the same
whichever route the packet took. `crates/test-support` solves it with
`MockEgress`: a SOCKS5 front end that **ignores the requested destination** and
splices the client to its own identity service, which answers `EGRESS <name>`.

A test can therefore assert the egress by reading it back, rather than inferring
it from timing or logs:

```rust
let egress = MockEgress::start("web").await?;
// … point a profile at egress.socks_addr() and start the core …
let answer = probe_through_socks5(profile_listener, "anything.invalid", 80).await?;
assert!(answer.contains("EGRESS web"));
```

Chains need the opposite behaviour from the transit hop, so
`MockEgress::start_forwarding` connects to the destination that was actually
requested. A chain test then asserts both that the exit identified itself *and*
that the transit hop saw exactly one connection — which is what distinguishes
"went through the chain" from "went straight to the exit".

## Property tests

`xraytui-import` and `xraytui-domain` assert that arbitrary input never panics,
never allocates without bound and always terminates. This is not decorative: it
is how the stack overflow in log redaction described in `STATUS.md` was found.

## Privileged tests

**Never run these against host networking.** Everything privileged belongs in a
disposable namespace:

```sh
sudo unshare --net --mount --pid --fork -- \
    cargo test -p xraytui-linux-net --features netns-tests -- --test-threads=1
```

The lab creates veth pairs, a local resolver and locally distinguishable egress
endpoints, so per-application routing can be proven without leaving the machine.
As of this writing the privileged backend is not implemented, so these tests do
not exist yet; see `STATUS.md`.

## Quality gates

```sh
cargo xtask ci
```

runs fmt, check, clippy with `-D warnings`, test and doc. CI runs the same list.

## Adding a test

Assert an externally observable property, not an internal call. "Profile B still
reaches egress B after profile A was switched" is a test; "the override method
was invoked once" is not.
