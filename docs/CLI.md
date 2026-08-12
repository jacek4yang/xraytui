# Command line

Every read-only command takes `--format`; every state-changing command is a single
verb. Exit codes are stable so shell conditionals work. Commands that change state
go through the daemon; `completion` and `manpages` work without one.

See `docs/DWM-INTEGRATION.md` for dmenu recipes and status-bar integration.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the operation failed |
| 2 | usage error |
| 3 | the daemon is not reachable |
| 4 | the named entity does not exist |
| 5 | the core is not running |

## Global options

| Option | Meaning |
|---|---|
| `--root DIR` | use this directory instead of the XDG locations; for testing |
| `--format`, `-f` | `plain`, `json`, `dmenu`, `dwmblocks`, `shell` |
| `--quiet`, `-q` | suppress informational output; errors still go to stderr |
| `--verbose`, `-v` | more logging; repeatable |

## Lifecycle

```sh
xraytui status                 # profile table, TUN, mode, DNS, throughput
xraytui up                     # start the core
xraytui down                   # stop the core
xraytui restart
xraytui doctor                 # environment report; non-zero if a check failed
xraytui show-config            # the generated Xray JSON (contains credentials)
```

## Modes

Mode and profile target are different operations: the mode decides what happens
to *system* traffic, a profile target decides where *that profile's* traffic goes.

```sh
xraytui mode get
xraytui mode set off|direct|global|rule
xraytui mode cycle             # off -> rule -> global -> direct -> off
```

## Profiles

The core operation. Switching a target is one gRPC call: other profiles keep
running, existing connections drain naturally, the core is not restarted.

```sh
xraytui profile list
xraytui profile list --format dmenu
xraytui profile show web
xraytui profile set-target web node:hk-01
xraytui profile set-target web group:auto-hk
xraytui profile set-target web chain:hk-us
xraytui profile set-target web direct
xraytui profile set-target web block
xraytui profile set-target web --stdin       # read the target from a pipe
xraytui profile select-from-stdin            # read an id back from dmenu
```

Target tokens: `node:ID`, `group:ID`, `chain:ID`, `direct`, `block`.
Rule actions additionally accept `profile:ID` and `default`.

```sh
xraytui target list                          # every selectable target
xraytui target list --profile development --format dmenu
```

## Nodes

```sh
xraytui node list
xraytui node list --filter HK --format json
xraytui node show hk-01                      # credentials shown as <redacted>
xraytui node import 'vless://…'
xraytui node import --stdin
xraytui node import --file links.txt
xraytui node import --xray-json config.json
xraytui node import --qr code.png
xraytui node remove hk-01
xraytui node test hk-01                      # probe through a profile listener
xraytui node share hk-01                     # prints a share link
xraytui node share hk-01 --qr                # terminal QR
xraytui node share hk-01 --qr --invert       # for dark terminals
xraytui node share hk-01 --png node.png      # PNG, written 0600
```

A share link and a QR code are credentials. `node share` prints a warning to
stderr, so piping the link still works.

## Groups and chains

```sh
xraytui group list
xraytui group select auto-hk node:hk-02      # manual groups only; one RPC
xraytui group test auto-hk
xraytui chain list                           # Local -> HK -> US -> Internet
xraytui chain test hk-us
```

Chains are printed in traffic order: the first hop is the one the local machine
talks to, the last is the exit.

## Applications and exec

```sh
xraytui app list
xraytui exec --profile development -- cargo build
xraytui exec --profile web -- curl -s https://example.com
xraytui exec --profile chat --no-proxy 'localhost,.internal' -- telegram-desktop
xraytui exec --transparent --profile web -- curl -s https://example.com
```

The default backend sets `ALL_PROXY` (as `socks5h://`, so the proxy resolves the
hostname), `HTTP_PROXY`, `HTTPS_PROXY`, their lowercase spellings and `NO_PROXY`,
then replaces itself with the command. The command is never passed through a
shell.

`--transparent` uses the cgroup v2 backend. It is not implemented yet and refuses
with a typed reason naming the alternative, rather than silently doing something
weaker.

## Rules

```sh
xraytui rule list                            # in evaluation order
xraytui rule explain example.com             # asks the core, via TestRoute
xraytui rule explain 1.2.3.4:443 --network udp
xraytui rule validate
```

## Subscriptions

Not implemented; see `STATUS.md`. Until then:

```sh
curl -s "$SUBSCRIPTION_URL" | xraytui node import --stdin
```

## Runtime and logs

```sh
xraytui runtime stats
xraytui runtime connections --follow         # streamed, not polled
xraytui logs --follow
```

## Shell integration

```sh
xraytui completion bash|zsh|fish
xraytui manpages /usr/share/man/man1
xraytui status --format shell                # KEY=value for eval
xraytui status --format dwmblocks            # one line for a status bar
```
