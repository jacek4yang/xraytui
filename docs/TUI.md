# Interactive interface

**The TUI is not implemented.** `xraytui` with no subcommand and `xraytui tui`
both print a message saying so and exit non-zero. This document records the
design so the work is specified rather than guessed at, and so the CLI equivalents
are discoverable now.

Everything the TUI would show is available from the CLI, with `--format json` for
scripting. See `docs/CLI.md` and `docs/DWM-INTEGRATION.md`.

## Intended design

Keyboard-first, no mouse required, correct at 80x24, no Nerd Fonts, 16-colour
default with a monochrome fallback. Pages: Dashboard, Profiles, Nodes, Groups,
Chains, Applications, Rules, Subscriptions, Runtime, Logs, Settings.

The Dashboard shows every simultaneously active profile:

```
Profiles
----------------------------------------------------------------
web          auto-hk           HK-01        42 ms    up
development  jp-fixed          JP-02        61 ms    up
chat         hk-us-chain       HK -> US     96 ms    up
direct       direct            direct        --      up
----------------------------------------------------------------
TUN: on   Mode: rule   DNS: healthy   Xray API: healthy
Upload: 1.2 MiB/s   Download: 8.4 MiB/s
```

That rendering already exists and is tested — `xraytui status` prints it, from
`crates/cli/src/output.rs`.

## Intended keys

| Key | Action | CLI equivalent today |
|---|---|---|
| `j`/`k`, arrows | move | |
| `h`/`l` | switch pane or tab | |
| `gg`/`G` | first/last | |
| `Ctrl-u`/`Ctrl-d` | page | |
| `/` | fuzzy filter | `node list --filter` |
| `Enter` | open or activate | |
| `Space` | toggle or mark | |
| `a` | add or import | `node import` |
| `e` | edit | edit the TOML |
| `d` | delete, with confirmation | `node remove` |
| `t` | test current item | `node test` |
| `T` | test marked items | `group test` |
| `m` | select system mode | `mode set` |
| `p` | profiles page | `profile list` |
| `n` | nodes page | `node list` |
| `u`/`U` | update subscription(s) | not implemented |
| `y` | copy share link | `node share` |
| `Q` | show QR code | `node share --qr` |
| `:` | command palette | |
| `?` | contextual help | `--help` |
| `Esc` | close modal | |
| `q` | back or quit | |

## Why the fast path is a profile switch

The operation worth optimising is repointing one profile: select it, press
`Enter`, fuzzy-pick a node, group, chain, `direct` or `block`. That is one gRPC
call, leaves other profiles running and does not restart the core. The dmenu
recipe in `docs/DWM-INTEGRATION.md` already does exactly this today.

## Constraints the implementation must respect

* Terminal state restored on normal exit, panic, `SIGINT` and daemon disconnect.
* Unicode width correctness, including Chinese node names.
* Event-driven refresh from the daemon's event stream, not polling.
* Non-blocking background operations, all cancellable.
* Bounded log view.
* The reducer must be testable without a terminal; rendering goes through
  ratatui's `TestBackend`.
