# Continuation State

## Repository
- Current branch: `release/v1`
- Current HEAD: `369be5b`
- Last exported checkpoint: 000 (this one)
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
- Slice 0 is finished except for baseline verification.
- Missing behaviour: nothing implemented yet beyond the checkpoint tool.
- Current failing test: unknown — no test has been run in this environment.

## Exact Next Action
- Verify the baseline, then correct `STATUS.md` from the real results.
- First command:
  `cargo fmt --all --check && cargo check --workspace --all-targets`
- First file: `STATUS.md` — every count in it comes from a destroyed
  environment and must be treated as unverified until re-measured.

## Remaining v1.0 Gates
- [x] Slice 0a — recovery, branch, checkpoint tooling, checkpoint 000
- [ ] Slice 0b — baseline verification, scenario M re-run, STATUS.md corrected
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
git rev-parse HEAD          # 369be5b…, 11 commits
git switch -c release/v1    # created
cargo build -p xtask        # clean
```

## Safety State
- No project-owned TUN, route, nftables rule, cgroup or DNS state was created in
  this session: nothing privileged has been run yet.
- If a later run is interrupted while a daemon is up:
  `pkill -f 'xraytuid --root /tmp' ; pkill -f smoke-fixtures.py`
