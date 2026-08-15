# Continuation State

## Repository
- Current branch: `release/v1`
- Current HEAD: see the manifest; 001 was exported from the verified baseline
- Last exported checkpoint: 003
- Latest local tag: `recovery-baseline`
- Expected worktree state: clean

## Completed in the Latest Slice (slice 2)
- `crates/domain/src/draft.rs`: one shared `NodeDraft` that both the CLI and the
  interface build nodes through. Every field is an `Option`, so an edit can tell
  "leave this alone" from "set this to empty" — `--flow ''` clears a flow. A
  field belonging to another protocol is refused, never dropped. Security is
  inferred (`--public-key` implies REALITY), and `allow_insecure` is never set
  from a form. 18 tests.
- CLI: `node add`, `node edit`, `group add/remove`, `chain add/remove`,
  `rule enable/disable/remove`, `profile add/remove/listeners`, all through one
  `set_desired` helper that reports a rolled-back change as a failure.
- **`app assign` and `app unassign` printed a TOML snippet and exited 1.** They
  now mutate. This is the exact anti-pattern the brief names.
- Removal refuses to strand a reference: a group or chain a profile still points
  at cannot be removed, and removing a profile takes its application rules with
  it and says so.

## Previously (slice 1)
- Real SQLite state store: mode, tunnel state, per-profile targets, last-known-good
  generation, subscription fetch metadata, bounded per-subject health history,
  and a transaction log whose unfinished rows are what `recover()` reports as an
  interrupted operation. 0600 database in a 0700 directory, WAL, `user_version`
  migration ladder, refuses a database written by a newer build. 15 tests.
- Daemon wiring: opens the store, prunes history older than 30 days, seeds node
  health back into the engine (`or_insert`, so restoring never moves health
  backwards), records mode/targets/last-known-good after every apply, and
  persists every probe.
- `xraytui init`: XDG-only, idempotent, 0700/0600, writes the starter policy,
  creates the database, prints the next commands. It refuses to overwrite policy
  files it cannot parse — writing the starter configuration there would delete
  every node the user owns because one file has a typo.
- Fixed: piping any command into `head` or `dmenu` panicked with a backtrace,
  because Rust ignores SIGPIPE. Both are documented workflows.

## Previously
- Recovered the project after a third environment reset. The uploaded bundle
  and source snapshot were **not present** in this session; the workspace at
  `9a69375` plus its uncommitted scenario-M tree had survived, and that tree is
  content-identical to the lost `b6248b8`. Re-committed as `369be5b`.
- Commit: `369be5b`, 11 commits total, branch `release/v1`, tag
  `recovery-baseline`.
- Implemented `cargo xtask checkpoint --label L`: git bundle of all refs,
  `git archive HEAD | gzip -n` source snapshot, manifest, README, recovery
  document, SHA256SUMS, one deterministic outer tarball. It verifies its own
  bundle by cloning it and comparing HEAD, and refuses to run on a dirty tree.
- Test evidence: none yet. Everything is UNEXECUTED at this commit.

## Current Incomplete Slice
- Slice 3: the daily-use TUI. Nothing started.
- Missing behaviour: the interface can list and select but cannot create or
  edit. It needs node add/edit forms built on `NodeDraft`, a subscription
  workflow, profile listener editing, application assignment, rule
  enable/disable, and a QR view.
- Current failing test: none. 738 workspace tests pass.

## Exact Next Action
- Add the pure editing state machine the interface will drive.
- First command: `cargo test -p xraytui-tui`
- First file: `crates/tui/src/app.rs` — read how `Action` and the existing
  overlays work before adding a form; the reducer is pure and must stay so.

## Remaining v1.0 Gates
- [x] Slice 0a — recovery, branch, checkpoint tooling, checkpoint 000
- [x] Slice 0b — baseline verified here: 703 workspace tests, 12 + 1 privileged,
      scenario M re-run and passing, STATUS.md re-measured
- [x] Slice 1 — durable SQLite state, migrations, `xraytui init`, SIGPIPE fix
- [x] Slice 2 — typed configuration surface, one mutation path, `app assign` fixed
- [ ] Slice 3 — daily-use TUI
- [ ] Slice 4 — DNS, recovery and reliability
- [ ] Slice 5 — release smoke test, dist, packaging, RC tag
- [ ] Slice 6 — final hardening, audit, deny, upgrade tests, v1.0.0

## Environment Blockers
Demonstrated in this session, not assumed:
- No D-Bus system bus (`/run/dbus/system_bus_socket` absent) → live
  systemd-resolved cannot be tested here.
- No IPv6 (`/proc/net/if_inet6` absent) → the IPv6 runtime path cannot run.
- No container runtime answering → no clean Arch package build.
- Disk is tight: `target/` reached 26 GB and had to be pruned to free space.

## Last Commands and Results
```
cargo test --workspace                              # 703 passed, 0 failed
cargo clippy --workspace --all-targets --all-features  # 0 warnings
sudo -E env "PATH=$PATH" ./scripts/netns-test.sh    # 12 + 1 passed, scenario M ok
```

## Safety State
- No project-owned TUN, route, nftables rule, cgroup or DNS state was created in
  this session: nothing privileged has been run yet.
- If a later run is interrupted while a daemon is up:
  `pkill -f 'xraytuid --root /tmp' ; pkill -f smoke-fixtures.py`
