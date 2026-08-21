# Testing

## The pyramid

| Layer | Where | Needs |
|---|---|---|
| unit and property | beside the code | nothing |
| compiler-versus-core | `crates/xray-compiler/tests/` | an Xray binary |
| acceptance | `crates/controller/tests/acceptance.rs` | an Xray binary |
| end-to-end | `crates/cli/tests/end_to_end.rs` | an Xray binary; runs the real daemon and CLI |
| privileged | `crates/linux-net/tests/netns.rs` | a network namespace, **never the host** |
| invariants | `xtask/tests/no_shell.rs` | nothing; greps the shipping code |

Tests that need a core skip with a printed `SKIPPED …` rather than passing
silently. Nothing in this repository requires internet access, a public proxy or
a public resolver.

```sh
cargo build --workspace
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

## The privileged suite

```sh
sudo ./scripts/netns-test.sh
```

Twelve linux-net tests plus one full controller/CLI scenario exercise TUN
creation, addressing, routing, policy rules, nftables, cgroup classification,
lease expiry and per-profile transparent egress against a real kernel. They
cover acceptance scenarios C, J, K and M.

Three separate things keep them off a real machine:

1. **The script builds outside and runs inside.** Building may need the network;
   the namespace deliberately has none. `unshare --net --mount --pid --fork
   --mount-proc --propagation private` then gives the test binary a network
   stack with nothing in it but loopback, a mount namespace where a private
   cgroup v2 hierarchy is mounted over `/sys/fs/cgroup`, and a PID namespace
   whose `/proc` matches it.
2. **The tests are inert without a variable.** Every one returns immediately
   unless `XRAYTUI_NETNS_TESTS` is set, so `cargo test --workspace` on a
   developer's laptop runs them as no-ops.
3. **The fixture checks where it is.** `assert_disposable_namespace()` lists the
   interfaces and refuses to continue if it finds anything other than loopback
   and the project's own devices. Setting the variable by hand on a real machine
   stops the suite rather than reconfiguring the machine.

`--mount-proc` in particular is not optional: without it `/proc` still belongs to
the host's PID namespace, a `pidfd`'s `Pid:` field and a child's own pid
disagree, and cgroup classification writes a pid that does not exist. That was a
real failure, and it is why the flag is there.

An independent oracle is used wherever one exists. The routing tests assert with
`ip route get`, so a disagreement between this project's netlink code and
iproute2 fails the test rather than being invisible; the nftables tests read the
ruleset back with `nft list table`.

## Invariants asserted as tests

Some claims in `docs/THREAT-MODEL.md` are the kind that quietly stop being true.
`xtask/tests/no_shell.rs` asserts them against the source:

* no shipping code constructs a `Command` for a shell, or contains the literal
  `sh -c`;
* every external program the privileged backend runs goes through
  `program::command`, which clears the environment and resolves against a fixed
  search path;
* `unsafe` appears in exactly one module, `crates/linux-net/src/tun.rs`;
* the privileged binary forbids `unsafe` outright.

Test code is exempt — the suite legitimately writes a shell script to stand in
for `resolvconf` — and a fifth test asserts that the `#[cfg(test)]` boundary the
exemption relies on is where the other four believe it is.

## Property tests

`xraytui-import` and `xraytui-domain` assert that arbitrary input never panics,
never allocates without bound and always terminates. This is not decorative: it
is how the stack overflow in log redaction described in `STATUS.md` was found.

## Quality gates

```sh
cargo xtask ci
```

runs fmt, check, clippy with `-D warnings`, builds the real cross-package
binaries, then runs tests and docs. CI runs the same list.

## Adding a test

Assert an externally observable property, not an internal call. "Profile B still
reaches egress B after profile A was switched" is a test; "the override method
was invoked once" is not.
