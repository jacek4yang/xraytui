# Working agreement

Read this first. The durable, changing state is in `CONTINUE.md`.

## What this project is

`xraytui` supervises the user's own Xray-core process and manages project-owned
listeners, TUN devices, routes, nftables rules, cgroups, DNS and subscriptions
on a single-user Linux machine. It is a network-administration tool for a
machine you own.

It does not, and must not, gain: vulnerability scanning or exploitation,
credential interception, TLS interception, payload inspection, unauthorized
capture, arbitrary scanning, denial of service, open-proxy defaults, stealth or
anti-forensics, remote control, arbitrary command execution through the
privileged helper, or telemetry.

## Resuming — read this before anything else

When the instruction is only `continue` (or `继续`), that is authorisation to
resume without asking. In order:

1. Look for the newest `xraytui-checkpoint-*.tar.gz` — first among the
   conversation's attachments, then in the delivery directory named by
   `DELIVERY-LOCATION.txt`, then beside the workspace.
2. If a workspace still exists, compare its `HEAD` with the checkpoint's
   `CHECKPOINT-MANIFEST.json`. Prefer whichever is **newer and valid**; never
   discard uncommitted work without inspecting it first.
3. Extract the outer archive, `sha256sum -c SHA256SUMS`, then
   `git clone xraytui-history.bundle` into a fresh directory and check out the
   branch and commit the manifest records.
4. Read `CLAUDE.md`, `CONTINUE.md`, `RELEASE-1.0.md`, `STATUS.md` and the
   manifest.
5. Run the manifest's `first_resume_command`.
6. Keep implementing. Do not restate the plan.

If no checkpoint is available anywhere, ask for the newest checkpoint archive
and nothing else. Never ask the user to restate the requirements.

## The rule this project was built by, the hard way

**This environment has destroyed committed work three times.** A local commit is
not durable here. The only thing that survives is a file the user has
downloaded.

So: a slice is not finished when it compiles, and not when it is committed. It
is finished when

```sh
cargo xtask checkpoint --label <slice>
```

has produced an archive **and that archive has been sent to the user**. Never
leave more than one coherent slice unexported. Before any long or risky
operation, checkpoint first.

Nothing is ever pushed to a remote. The user has forbidden it. The Git bundle
inside each checkpoint is the only copy of the history.

## Architecture, frozen

* `xraytui` — unprivileged TUI and CLI.
* `xraytuid` — unprivileged per-user daemon; owns desired state, supervises one
  Xray-core.
* `xraytui-netd` — narrowly privileged helper: TUN, routes, nftables, cgroups,
  DNS. A closed typed operation set, no shell, no arbitrary paths.
* TOML is the durable user-editable policy. SQLite is observed runtime state.
* Typed CBOR over Unix sockets between components; Xray gRPC for runtime
  selector, routing and statistics operations.

Do not rewrite the controller or the core supervisor, add a second core, add a
GUI or web UI, add a plugin system, add remote administration, change the
configuration format, or run more than one Xray process. Extend what is there.

## How work is done here

* **One mutation path.** CLI and TUI share the same typed mutation functions.
  Two implementations of "add a profile" is two behaviours.
* **Never claim an unexecuted test passed.** `STATUS.md` records what actually
  ran, with numbers. "Not verified" is an acceptable entry; a hopeful one is
  not.
* **Privileged tests run only inside the disposable namespace harness**
  (`scripts/netns-test.sh`). Nothing may touch the real host's routes, DNS,
  nftables, cgroups, services or interfaces.
* **Comments explain why**, not what. If a line encodes something learned from a
  kernel or from upstream, say so.
* Focused tests while implementing; full gates at checkpoint boundaries only.

## The gates

```sh
cargo xtask checkpoint --label <slice>   # the durable unit
cargo test --workspace
sudo ./scripts/netns-test.sh             # privileged, namespace-only
./scripts/release-smoke.sh               # the whole user workflow
```
