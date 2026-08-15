# Continuation State

## Repository
- Current branch: `release/v1`
- Current HEAD: see the manifest; 001 was exported from the verified baseline
- Last exported checkpoint: 002
- Latest local tag: `recovery-baseline`
- Expected worktree state: clean

## Completed in the Latest Slice (slice 1)
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
- Slice 2: the typed configuration surface. Nothing started.
- Missing behaviour: nodes can be imported but not typed in; groups, chains and
  rules can only be created by editing TOML by hand. `NodeCommand` has no
  `Add`/`Edit`; `GroupCommand`/`ChainCommand` have no `Add`/`Remove`.
- Current failing test: none. 718 workspace tests pass.

## Exact Next Action
- Build the shared typed node builder used by both the CLI and the TUI.
- First command: `cargo test -p xraytui-domain draft`
- First file: `crates/domain/src/draft.rs` (new).

## Remaining v1.0 Gates
- [x] Slice 0a — recovery, branch, checkpoint tooling, checkpoint 000
- [x] Slice 0b — baseline verified here: 703 workspace tests, 12 + 1 privileged,
      scenario M re-run and passing, STATUS.md re-measured
- [x] Slice 1 — durable SQLite state, migrations, `xraytui init`, SIGPIPE fix
- [ ] Slice 2 — typed configuration surface shared by CLI and TUI
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
