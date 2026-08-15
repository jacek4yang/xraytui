# Road to v1.0.0

The support boundary v1.0 claims, and nothing wider:

* Linux only; current Arch Linux is tier one.
* systemd, nftables, cgroup v2, Xray-core as an external process.
* Single-user laptops and workstations, one trusted interactive user.
* dwm, st, tmux, dmenu, shell and Neovim workflows.
* IPv4 fully supported and tested. IPv6 supported only if runtime tests pass;
  otherwise experimental, disabled by default, fail-closed, and visibly
  runtime-unverified.
* **Shared servers with mutually untrusted local users are out of scope**,
  because Xray's commander is loopback TCP without authentication. A random
  port is not authentication.

"Daily-use release" means a user can install, configure, operate, recover,
upgrade and uninstall without editing generated Xray JSON and without repairing
ordinary failures by hand.

## Gates

| Gate | What it means | State |
|---|---|---|
| G0 | Recovery, checkpoint tooling, verified baseline | in progress |
| G1 | Durable SQLite state, migrations, `init`, doctor | pending |
| G2 | Typed configuration surface, one mutation path | pending |
| G3 | Daily-use TUI | pending |
| G4 | DNS, recovery, reliability | pending |
| G5 | Smoke test, dist, packaging, RC tag | pending |
| G6 | audit, deny, upgrade tests, clean Arch, IPv6, v1.0.0 | pending |

"Blocked here" means the environment cannot run it, not that it is optional:
the harness is written, guarded and runnable where the environment exists. What
was never executed is recorded as never executed, in `STATUS.md`.

## Every mutation

Lock, load, validate, apply the typed change, validate the model, compile a
candidate Xray configuration, write atomically preserving mode, reconcile
through the daemon, roll back if reconciliation fails, and return a structured
actionable error. One implementation, used by both the CLI and the TUI.

## What an advisory means for the release

A critical or high advisory reachable from a production path blocks the tag. A
lower-severity or unreachable one may be accepted with a written rationale, the
affected path, the mitigation and a follow-up reference in `SECURITY.md`.

## Tagging rule

`v1.0.0` is tagged only when no mandatory gate is failing **or unexecuted**. If
implementation is complete but an environment-only gate cannot run here, the
release is tagged `v1.0.0-rcN` instead, with the missing gate named in
`CONTINUE.md` and its harness left ready to run.
