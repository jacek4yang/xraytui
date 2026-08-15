# Continuation State

## Repository
- Current branch: `release/v1`
- Current HEAD: see the manifest; 001 was exported from the verified baseline
- Last exported checkpoint: 001
- Latest local tag: `recovery-baseline`
- Expected worktree state: clean

## Completed in the Latest Slice
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
- Slice 1: durable state. Nothing started.
- Missing behaviour: `crates/state-store/src/lib.rs` is a one-line stub, so the
  daemon forgets mode, profile targets and health across a restart.
- Current failing test: none. 703 workspace + 13 privileged tests pass.

## Exact Next Action
- Implement the SQLite state store.
- First command: `cargo test -p xraytui-state-store`
- First file: `crates/state-store/src/lib.rs` (currently one line).

## Remaining v1.0 Gates
- [x] Slice 0a — recovery, branch, checkpoint tooling, checkpoint 000
- [x] Slice 0b — baseline verified here: 703 workspace tests, 12 + 1 privileged,
      scenario M re-run and passing, STATUS.md re-measured
- [ ] Slice 1 — durable SQLite state, migrations, `xraytui init`, doctor
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
