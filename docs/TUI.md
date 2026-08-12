# Interactive interface

`xraytui` with no subcommand opens it; so does `xraytui tui`. Everything it shows
is also available from the CLI with `--format json`, so nothing is only reachable
through the interface — see `docs/CLI.md` and `docs/DWM-INTEGRATION.md`.

## What it is designed around

The specification names dwm, `st` and `tmux` users, and that shapes three
decisions:

* **Every action has a key.** Nothing requires a mouse. Mouse reporting is
  enabled only so that a stray click does not paste escape codes into the
  terminal.
* **The sixteen ANSI colours, and no more.** Terminal users have their own
  palettes; a hard-coded theme fights them. There are no Nerd Font glyphs and no
  characters outside the box-drawing set.
* **80x24 is the design size**, not the minimum tolerated one. Below it the
  layout degrades by dropping panes — footer first, then the tab bar — rather
  than by wrapping or overlapping. It draws without panicking down to 1x1.

## Panes

| Key | Pane | What it lists |
|---|---|---|
| `1` | Profiles | every egress profile, its target, the outbound it currently resolves to, and its health |
| `2` | Nodes | every node, its endpoint, its protocol and its health |
| `3` | Groups | groups with their strategy and member count, and chains with their hop count |
| `4` | Rules | application rules and routing rules, with their action and priority |
| `5` | Subs | subscriptions. **The URL is never shown** — it usually carries a reusable token |
| `6` | Logs | core log lines as they arrive, newest first, capped at 500 |

## Keys

| Key | Action |
|---|---|
| `q`, `Ctrl-C` | quit |
| `?` | key reference; any key closes it |
| `Tab` / `Shift-Tab` | next / previous pane |
| `1`..`6` | jump to a pane |
| `j` / `k`, arrows | move the cursor |
| `g` / `G` | first / last row |
| `PgUp` / `PgDn` | move ten rows |
| `/` | filter; `Enter` applies, `Esc` cancels |
| `Esc` | clear an applied filter |
| `Enter` | point the selected profile at a target |
| `m` | cycle the system mode |
| `u` / `d` | start / stop the core |
| `t` | probe the selected node |
| `r` | refresh from the daemon |

The table above is generated from the same constant the help overlay is, and a
test presses every key in it and fails if one is documented but does nothing.

An overlay takes every key while it is up. `q` with the help overlay open closes
the overlay rather than quitting, and `q` while typing a filter types a `q`.
An interface where a key sometimes means one thing and sometimes another is one
people stop trusting.

## Why the fast path is a profile switch

The thing people do most often is point one profile somewhere else while
everything else keeps running. That is `Enter`: it opens a list of every node,
group and chain, positioned on the profile's current target, and choosing one
sends a single `OverrideBalancerTarget` through the daemon. The core is not
restarted, other profiles are untouched, and connections through them are not
interrupted.

## What happens when things are not working

* **No daemon at all**: the interface refuses to start and says how to start one.
  It does not open a blank screen.
* **The daemon goes away while it is running**: the last known state stays on
  screen, the header says `[daemon unreachable]` in red, and the next successful
  refresh clears it. The user's place in the list is not lost.
* **The log stream is unavailable**: the Logs pane says so. Everything else keeps
  working, because logs arrive on a second connection.
* **The terminal is too small**: panes are dropped rather than overlapped, and
  the list always keeps at least one row.

## Giving the terminal back

Acceptance scenario L asks that the terminal be left usable however the program
ends. Three mechanisms cover the three ways out:

* `Drop` on the terminal guard covers a normal return and an error return;
* a panic hook restores the terminal **before** the default hook runs, so a
  backtrace is printed to a terminal that is already cooked and readable;
* the key reader is joined before the guard is dropped, so nothing reads a
  keystroke after the terminal has been handed back.

The restore sequence is written through a `Write`, so a test asserts exactly what
would be sent — cursor shown, mouse reporting off, alternate screen left last —
without needing a terminal to run in.

## How it is tested

The interesting parts are pure, which is what makes them testable at all:

| Module | Tested by |
|---|---|
| `app` | pressing keys and asserting on the resulting state and action |
| `render` | drawing into ratatui's `TestBackend` at sizes from 80x24 down to 1x1 |
| `terminal` | asserting the escape sequences written on restore |
| `run` | the end-to-end suite, which asserts it refuses a pipe and says why |

Sixty-five tests, including: every documented key does something; an
undocumented key does nothing; no line ever exceeds the terminal width, counted
in display columns so CJK names do not overflow; overlays stay inside a terminal
too small to hold them; and a subscription's URL never reaches the screen.
