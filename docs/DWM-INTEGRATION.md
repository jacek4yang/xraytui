# dwm, dmenu and shell integration

xraytui is built to be driven from key bindings and pipes rather than from a
mouse. Every read-only command takes `--format`, and every state-changing command
is one verb with a stable exit code.

## Output formats

| Format | Shape | Use |
|---|---|---|
| `plain` | aligned columns | reading in a terminal |
| `json` | pretty JSON | scripts, `jq` |
| `dmenu` | `id<TAB>human label` | piping into `dmenu` |
| `dwmblocks` | one short line | a status bar |
| `shell` | `KEY=value` lines | `eval "$(…)"` |

The dmenu contract matters: dmenu shows the whole line, and
`profile select-from-stdin` and `profile set-target --stdin` read back the first
tab-separated field. The identifier therefore survives a round trip through a
menu a human can read. A hand-typed bare identifier is also accepted.

## dwm key bindings

Add to `config.h`, adapting the modifier to taste:

```c
static const char *xraytui[]      = { "st", "-e", "xraytui", NULL };
static const char *xraytuimode[]  = { "xraytui", "mode", "cycle", NULL };
static const char *xraytuiprof[]  = { "/usr/local/bin/xraytui-pick-profile", NULL };
static const char *xraytuitarget[]= { "/usr/local/bin/xraytui-pick-target", NULL };

static const Key keys[] = {
    { MODKEY|ShiftMask, XK_x, spawn, {.v = xraytui } },
    { MODKEY|ShiftMask, XK_m, spawn, {.v = xraytuimode } },
    { MODKEY|ShiftMask, XK_p, spawn, {.v = xraytuiprof } },
    { MODKEY|ShiftMask, XK_t, spawn, {.v = xraytuitarget } },
};
```

## The two pickers

`xraytui-pick-profile` — choose a profile to inspect:

```sh
#!/bin/sh
set -eu
xraytui profile list --format dmenu \
  | dmenu -i -l 10 -p "Proxy profile" \
  | xraytui profile select-from-stdin
```

`xraytui-pick-target` — repoint one profile, which is the operation worth binding
a key to, because it is the one that happens several times a day:

```sh
#!/bin/sh
set -eu
profile=$(xraytui profile list --format dmenu \
  | dmenu -i -l 10 -p "Which profile?" \
  | cut -f1)
[ -n "$profile" ] || exit 0

xraytui target list --profile "$profile" --format dmenu \
  | dmenu -i -l 20 -p "Egress for $profile" \
  | xraytui profile set-target "$profile" --stdin
```

Switching a target this way is a single gRPC call: other profiles keep running
and the core is not restarted.

## Status bar

```sh
xraytui status --format dwmblocks
# rule tun ↑1.2 MiB/s ↓8.4 MiB/s
```

For dwmblocks, prefer a long interval and a signal over polling every second:

```c
/* blocks.h */
{"", "xraytui status --format dwmblocks", 30, 12},
```

and have something nudge it when state changes rather than polling:

```sh
# Refresh the block whenever the daemon reports a change.
xraytui logs --follow >/dev/null &
while xraytui status --format shell >/tmp/xraytui.env; do
    pkill -RTMIN+12 dwmblocks
    sleep 5
done
```

A one-process-per-second poll is exactly what the event stream exists to avoid;
`xraytui runtime connections --follow` and `xraytui logs --follow` both stream
from the daemon rather than polling it.

## Shell integration

```sh
eval "$(xraytui status --format shell)"
echo "$XRAYTUI_MODE $XRAYTUI_PROFILE_WEB"
```

Every value is shell-safe: no spaces, semicolons, backticks or dollar signs. That
is asserted by a test.

## Per-command proxying

```sh
xraytui exec --profile development -- cargo build
xraytui exec --profile web -- curl -s https://example.com
xraytui exec --profile chat --no-proxy 'localhost,.internal' -- telegram-desktop
```

`exec` replaces itself with the command, so signals, the terminal and the exit
status all behave normally. `ALL_PROXY` uses `socks5h://`, which asks the client
to let the proxy resolve the hostname rather than resolving it locally and
leaking the destination to the local resolver.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the operation failed |
| 2 | usage error |
| 3 | the daemon is not reachable |
| 4 | the named entity does not exist |
| 5 | the core is not running |

```sh
if ! xraytui status >/dev/null 2>&1; then
    case $? in
        3) notify-send "xraytui" "daemon is not running" ;;
        5) notify-send "xraytui" "core is down" ;;
    esac
fi
```

## Completions

```sh
xraytui completion bash > ~/.local/share/bash-completion/completions/xraytui
xraytui completion zsh  > ~/.local/share/zsh/site-functions/_xraytui
xraytui completion fish > ~/.config/fish/completions/xraytui.fish
```

Packages install these already.
