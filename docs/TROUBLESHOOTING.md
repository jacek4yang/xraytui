# Troubleshooting

Start with `xraytui doctor`. It reports the core binary and its version, the
commander capabilities actually probed, directory permissions, listener
exposure, TUN and DNS state, and conflicts with existing host configuration.
Most entries below are things `doctor` names directly.

If networking is already broken and xraytui is not running, go straight to
`docs/RECOVERY.md`.

## Quick reference

| Symptom | Likely cause | First action |
|---|---|---|
| `xraytui` cannot reach the daemon | `xraytuid` not running, stale socket, or a different `XDG_RUNTIME_DIR` | Check the daemon is running for **this** user and session |
| Core will not start | Generated document rejected, binary missing, port taken | `xray run -test -config <generated>` |
| `this rule has no effective fields` | A rule reached the core with no conditions | Give the rule a condition, or let it be the catch-all |
| `not all dependencies are resolved` | A `fallbackTag` without an observatory block | Remove the fallback, or use a strategy that supplies liveness |
| Profile switch has no effect | Traffic is not entering that profile, or overrides were not re-applied | `GetBalancerInfo` via `doctor`; check which inbound the traffic uses |
| Application rule does not match | The socket is owned by a helper process | Use `xraytui exec --profile` |
| TUN refuses to come up | netd unreachable, group membership, table/mark conflict, unprivileged attach not permitted | `xraytui tun plan`, then `doctor` |
| DNS not restored | Backend failed, or the daemon died before teardown | `resolvectl status`, then `doctor --repair` |
| Stale nftables or routes after a crash | Lease expired with `failure_policy = "block"`, or netd was also killed | `xraytui-netd --recover` |
| `address already in use` | Another process, or a previous run, holds the listener port | Find the holder before changing the port |
| Node share says `lossy` or `unsupported` | A standard single-node link cannot preserve required semantics | Export Xray JSON, or inspect with `--allow-lossy` before explicitly accepting loss |
| QR does not fit the terminal | The encoded link is long or the terminal is narrow | Enlarge the terminal or use `--qr --output node.png` |
| QR image is rejected | No readable QR, unsupported image, or dimension/allocation limit | Re-export as PNG; input images are intentionally capped at 8192×8192 and 128 MiB decode allocation |

---

## The daemon is not reachable

**Symptom.** `xraytui` exits with a connection error naming
`$XDG_RUNTIME_DIR/xraytui/control.sock`, or hangs briefly and then reports the
socket is absent.

**Causes and fixes.**

| Cause | How to tell | Fix |
|---|---|---|
| `xraytuid` is not running | No process; the socket file is absent | Start the daemon for your user |
| Daemon running as a different user | The socket exists but connecting is refused | The control socket is per-user by design; run both as the same uid |
| `XDG_RUNTIME_DIR` differs between the two | `echo $XDG_RUNTIME_DIR` in both shells | Common under `sudo`, `su`, cron and detached terminal multiplexers. The runtime directory falls back to `/run/user/<uid>` and then to a temporary directory, so two shells can legitimately disagree |
| Stale socket after an unclean exit | The socket file exists but nothing accepts | Remove the stale socket and restart the daemon; `daemon.lock` prevents two daemons for one user |
| A directory in the path is not private | The daemon refuses to start with `refusing to use <path>` | The runtime and config directories must be directories, not symlinks, owned by you. Fix ownership rather than loosening the check |

The control socket is not a security boundary — both ends run as the same user —
but it lives inside a 0700 directory, so anything that changes those permissions
breaks the connection rather than silently widening access.

---

## The core will not start

**Symptom.** `CoreStatus` cycles through `starting` and `restarting`, then
settles at `failed` with a bounded reason after `max_consecutive_restarts`
(default 8) attempts.

**First check.** The generated document is written before the core is spawned,
so it can be tested independently:

```sh
xray run -test -config "$XDG_RUNTIME_DIR/xraytui/generated-xray.json"
```

| Cause | Signal | Fix |
|---|---|---|
| Binary not found | `doctor` reports no `xray` on `PATH` and `[core] binary` empty | Set `[core] binary` to an absolute path, or install the core |
| Version too old | `doctor` refuses versions below 1.8.0 | Below 1.8.0 there is no `ruleTag`, `RemoveRule` or `ListRule`, so rule management is impossible. Upgrade |
| Document rejected | `xray run -test` prints the offending field | See the two dedicated sections below for the two errors that are xraytui's own responsibility |
| Listener port taken | `address already in use` naming a profile port | See "Port already in use" |
| Missing geodata | Rules using `geoip:` or `geosite:` fail to load | Set `[core] asset_dir` to the directory holding `geoip.dat` and `geosite.dat` |
| Capabilities insufficient | `doctor` lists what is missing | `HandlerService`, `RoutingService` and `OverrideBalancerTarget` are the minimum; without the last one profile switching cannot work at all |

A failed start does not take down a working core: the previous generation keeps
running, and `last-good-xray.json` is what a rollback restores.

---

## `this rule has no effective fields`

**Meaning.** Xray rejects a routing rule that carries no conditions
(`app/router/config.go`). Such a rule would match everything, and upstream
refuses it rather than guessing.

**Cause.** A rule reached the core with an empty matcher. The compiler's final
pass sets `network = "tcp,udp"` on every condition-free rule precisely to avoid
this, so seeing it means either a rule bypassed that pass, or a rule was added to
a live core through the API rather than by compilation.

**Fix.**

1. Find the offending rule by `ruleTag`:
   ```sh
   jq '[.routing.rules[] | select((.domain//[]) == [] and (.ip//[]) == []
        and .port == null and .network == null and (.inboundTag//[]) == []
        and (.process//[]) == [] and (.protocol//[]) == []) | .ruleTag]' \
      "$XDG_RUNTIME_DIR/xraytui/generated-xray.json"
   ```
2. If it is one of your own rules (`rule/user/<id>`), give it a condition. A rule
   that is genuinely meant to match everything belongs at the end and is better
   expressed by setting the system mode's default profile than by an empty rule.
3. If it is `rule/system/mode-fallback`, the catch-all pass did not run; that is
   a compiler defect worth reporting with `xraytui doctor`, `xraytui status` and
   a manually reviewed excerpt that contains no generated JSON or policy files.

Validation also warns before this ever reaches the core: a catch-all rule that is
not last produces `routing-rule.shadowing`, naming every later rule it hides.

---

## `not all dependencies are resolved`

**Meaning.** A balancer carries a `fallbackTag` but the configuration has no
`observatory` or `burstObservatory` block to supply liveness data. Upstream's
`RandomStrategy::InjectContext` and `RoundRobinStrategy::InjectContext` call
`core.RequireFeatures(observatory)` whenever the fallback tag is non-empty, and
`leastPing`/`leastLoad` require it unconditionally.

**Cause.** The two must be emitted in lockstep, and the compiler does that: any
tag that acquires a fallback is added to the observatory subject selector.
Encountering this error means the document was hand-edited, or was produced by a
different tool, or a group or profile acquired a fallback after the observatory
selector was computed.

**Fix.**

```sh
jq '{observatory, burstObservatory,
     fallbacks: [.routing.balancers[] | select(.fallbackTag != null)
                 | {tag, fallbackTag, strategy: .strategy.type}]}' \
   "$XDG_RUNTIME_DIR/xraytui/generated-xray.json"
```

Every balancer listed under `fallbacks` needs its candidates present in one of
the two selectors: `leastLoad` in `burstObservatory`, everything else in
`observatory`. Practical resolutions:

- Remove the group or profile `fallback` if you did not need it. With
  `kill_switch = "off"` and no fallback the configuration is entirely probe-free.
- Prefer the daemon's own health probing over the in-core observatory. It
  measures the usable path through the profile's real listener, and it does not
  require the core to carry a fallback tag at all.

---

## Switching a profile has no effect

**Symptom.** The target changes in the UI, no error is reported, and traffic
keeps taking the old path.

Work through these in order.

| Check | How | Meaning |
|---|---|---|
| Did the override land? | `doctor` reports each balancer's `override_target` from `GetBalancerInfo` | If the override is absent, the RPC failed or was re-applied over. If it is present and traffic still differs, the traffic is not using that profile |
| Which inbound is the traffic using? | The routing event stream shows the inbound tag per connection | A connection arriving on `inbound/profile/web/socks` is dispatched to `profile/web/selector` by rule 3, **whatever the application rules say**. If it arrives on the TUN inbound instead, an application rule or the mode fallback decided its fate |
| Is the connection old? | Compare connection age with the switch time | The override affects **new** connections. Existing connections keep their outbound; that is the point of switching without a restart |
| Did the core restart? | `CoreStatus` uptime | Overrides are process state and Xray does not persist them. `xraytuid` re-applies them after every start; if the core restarted and the re-apply step failed, the balancer falls back to its selector, which names the *configured* target |
| Is the profile enabled? | Profile list | A disabled profile is not compiled at all: no balancer, no listeners, no rule |
| Is a group involved? | `effective_outbound` in the profile's runtime record | Switching a profile to `group:x` points it at `group/x/entry`; which **member** is used is then the group balancer's decision, and for a manual group that is a second override on `group/x/balancer` |

`TestRoute` answers "where would a connection like this go" without dialling
anything, which is the fastest way to separate "the override did not apply" from
"this traffic never belonged to that profile".

---

## An application rule does not match

**Symptom.** A rule for `firefox` exists and is enabled, but the browser's
traffic takes the fallback route.

**Cause, almost always.** Xray's `process` matcher matches **the process that owns
the socket**. Modern browsers do not open sockets from the binary you launched;
they use a network or socket helper process, often at a different path such as
`/usr/lib/firefox/firefox`. Flatpak, Snap and wrapper scripts move the path
further still.

**Diagnosis.** The Applications page resolves and displays the *actual*
executable paths of running processes matching your literal matcher, and marks
matchers that currently match nothing. That marking is the answer: a matcher that
matches nothing is not a routing problem, it is a wrong matcher.

**Fixes, best first.**

1. `xraytui exec --profile web -- firefox` — exact, unprivileged, and immune to
   the helper-process problem, because it is the launched tree that carries the
   proxy environment.
2. `xraytui exec --transparent` — exact per **instance**, so two copies of the
   same executable can take different profiles. Requires netd and cgroup v2.
3. Widen the matcher to a directory prefix, for example `/usr/lib/firefox/`. This
   matches by executable path prefix and catches helper processes, at the cost of
   matching anything else under that directory.

Other reasons a matcher fails:

| Cause | Detail |
|---|---|
| Matcher shape is not what you think | No `/` means process **name**; containing `/` means absolute **path**; trailing `/` means **directory prefix**. `usr/bin/curl` is invalid — a path matcher must be absolute |
| The rule is disabled, or shadowed | An earlier rule matched first. Rule order is: system rules, profile inbounds, group stage, private bypass, user `block` rules, application rules, remaining user rules, catch-all |
| Two rules share a priority | Validation warns with `app-rule.duplicate-priority`; ties break by identifier, which is stable but probably not what you intended |
| Not in a TUN mode | The `process` matcher is only consulted for traffic that reaches the core through the TUN inbound. Traffic sent to a profile's SOCKS listener is dispatched by inbound tag before application rules are ever evaluated |
| The peer is not local | The matcher returns "no match" rather than an error when it cannot resolve the owning process |

Process matching is a routing convenience, not a sandbox. An uncooperative local
process can defeat it.

---

## TUN refuses to come up

**Symptom.** `TunStatus` is `failed` with a bounded reason, and the system mode
stays at whatever it was.

Run `xraytui tun plan` first. It prints every intended change without making any
of them, which usually identifies the conflict immediately.

| Cause | Signal | Fix |
|---|---|---|
| netd not running or not reachable | Connection error naming `/run/xraytui/netd.sock` | Start the system service |
| Not in the `xraytui` group | Permission denied on the socket (mode 0660, group `xraytui`) | Have the administrator add you, then start a new login session so the new group takes effect |
| Routing table already in use | `plan` reports the conflict on `tun.route_table` | Table id 29281 (`0x7261`) is the default and is probed before use. If something else owns it, setup fails rather than overwriting. Pick a free id |
| Policy rule priority taken | `plan` reports the conflict on `tun.rule_priority` | Same reasoning; default is 17000 |
| nftables table conflict | `plan` reports `table inet xraytui` already present and not owned by this generation | A previous run left it. `xraytui-netd --recover`, or see `docs/RECOVERY.md` |
| Interface name rejected | Configuration error naming `^xraytui[0-9a-z]{0,8}$` | The helper derives ownership from the name, so the pattern is mandatory. `xraytui0` is the default |
| Unprivileged attach not permitted | `doctor` reports the core cannot attach to the persistent device | The device is created persistent and owned by your uid, but the kernel must permit the owner to attach and Xray's link calls must succeed. When they do not, TUN mode is **refused** rather than escalating privileges silently. The documented alternative is the opt-in `CoreLaunchTun` path |
| MTU or address family invalid | Configuration error | MTU must be within `576..=9000`; at least one of `tun.ipv4`, `tun.ipv6` must be enabled |

---

## DNS was not restored

**Symptom.** After stopping xraytui, name resolution is broken, or `resolvectl
status` still shows xraytui's resolver on a link.

```sh
resolvectl status                 # which resolver is on which link
xraytui doctor                    # what xraytui believes the DNS state is
xraytui doctor --repair           # reconcile through the running helper
xraytui-netd --recover            # reconcile when the daemon is gone
```

| Cause | Fix |
|---|---|
| The daemon died before teardown | The netd lease expires after `runtime.netd_lease_ttl_secs` (default 30 s) and restoration runs then. Wait that long before intervening |
| netd was also killed | Restoration runs at netd start-up reconciliation. Restart the service, or run `xraytui-netd --recover` |
| The link no longer exists | Per-link settings vanish with the link; nothing to restore. Confirm with `resolvectl status` that no stale link remains |
| `manual` backend was used | `/etc/resolv.conf` is a global file with no per-link scope, and whatever else manages it may have rewritten it in the meantime. Restore from the captured copy; see `docs/RECOVERY.md` |
| `resolvconf` backend | Restoration goes through the same interface that applied the change; if that tool is missing or has changed, restoration fails and is reported as `unhealthy` |

Restoration is idempotent, so running the repair paths more than once is safe.
Manual `resolvectl revert` commands are in `docs/RECOVERY.md`.

---

## IPv6 TUN routing is unavailable

**Symptom.** Enabling a dual-stack or IPv6-only TUN is refused with:

```text
IPv6 TUN routing is unavailable because the host kernel has IPv6 disabled.
IPv4 remains available.
```

Check the same evidence used by `xraytui doctor`:

```sh
cat /proc/net/if_inet6
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
cat /proc/sys/net/ipv6/conf/default/disable_ipv6
```

Both sysctl values must be `0` before a newly created interface can receive an
IPv6 address. The helper refuses before creating the TUN; it does not silently
downgrade the request. Either enable IPv6 at the host/network-namespace level,
or keep `tun.ipv6 = false`. With the default
`tun.disabled_family_policy = "block"`, the latter still installs an IPv6
blackhole so an available host route cannot leak traffic. Set the policy to
`"direct"` only when direct IPv6 is intentional.

---

## Stale nftables rules or routes after a crash

**Symptom.** Traffic is blackholed, or routed into a device that no longer
exists, and xraytui is not running.

**Expected behaviour first.** If `runtime.failure_policy = "block"`, a kill
switch surviving a crash is **working as configured**: it keeps a minimal chain
that drops non-loopback, non-bypass traffic until an authenticated client clears
it. That is a deliberate denial of service against your own machine, and it is
the reason the setting is explicit.

```sh
xraytui-netd --recover            # reconcile recorded generations against the kernel
```

netd records minimal recovery state — never credentials — under
`/run/xraytui/state/` with atomic rename, so a restart reconciles rather than
forgets. If `/run` was cleared by a reboot, there is nothing to reconcile and
kernel state from before the reboot is gone too.

For removal by hand, `docs/RECOVERY.md` gives the exact ordered commands. Two
rules apply throughout:

- Only objects carrying the project's name, mark, table id or
  `xraytui:<uid>:<gen>` comment are ever touched. `table inet xraytui` is the
  only nftables table xraytui creates or flushes.
- Remove the **nftables table first**, then the policy rule, then the routes and
  the device. Clearing the firewall stops any kill-switch drop and stops packets
  being marked, so ordinary egress resumes immediately; the reverse order leaves
  you offline for longer than necessary.

---

## Port already in use

**Symptom.** The core fails to start with `address already in use`, naming a
profile's SOCKS or HTTP port.

```sh
ss -ltnp 'sport = :1080'          # who holds it
```

| Cause | Fix |
|---|---|
| Another proxy client | Choose a different port for the profile, or stop the other client |
| A previous core has not exited | Check for a leftover `xray` process; the daemon lock prevents two daemons but not an orphaned core |
| Two profiles configured on the same address | Validation catches this as `listener.port-collision`, naming both profiles. Change one |
| Port 0 requested | Validation rejects it as `listener.zero-port`: an ephemeral port cannot be addressed by clients |

Listeners bind `127.0.0.1` unless `lan_access` is enabled **and**
acknowledged **and** credentials are set; `listener.lan-without-auth` is an error
and `listener.lan-exposed` a warning, both reported by `doctor`.

---

## Reading validation diagnostics

Every diagnostic carries a stable machine-readable code, so scripts can match on
the code rather than the prose. Errors block compilation; warnings do not.

| Code | Meaning |
|---|---|
| `target.unknown-node`, `target.unknown-group`, `target.unknown-chain` | A profile, rule or group points at something that does not exist |
| `target.unsupported-node` | The node exists but cannot be compiled for the configured Xray release |
| `target.disabled-node`, `target.empty-group` | Warnings: the target exists but currently carries nothing |
| `chain.invalid` | Chain too short, missing hop, repeated hop, UDP-incapable intermediate hop, or an unusable hop |
| `group.manual-selection-not-member` | A manual group selects something outside its own membership |
| `group.no-criteria`, `group.empty` | The group will always be empty; its traffic is blocked until a member matches |
| `action.unknown-profile`, `action.no-default-profile` | A rule action names a profile that does not exist, or uses `default` with none configured |
| `state.global-without-default` | Global mode requires a default profile |
| `listener.port-collision`, `listener.zero-port`, `listener.lan-without-auth` | Listener configuration errors |
| `routing-rule.shadowing` | A catch-all rule appears before other rules and hides them |
| `app-rule.no-matchers`, `app-rule.bad-matcher`, `routing-rule.bad-matcher` | A rule has no matchers, or a matcher that is syntactically unusable |

## Share/export failures

`xraytui node share` writes only the serialized payload to stdout. Secret
warnings and status go to stderr, so redirecting stdout cannot contaminate a
subscription. If more than one node is selected, QR output is refused because a
QR represents one credential payload; choose `--as links`, `--as base64` or
`--as json` instead.

Lossy output is never implicit. The diagnostic names the fields a standard link
cannot carry and recommends normalized Xray JSON. `--allow-lossy` is an explicit
acknowledgement for interoperability testing, not a repair. A chain has no honest
single-node URI: share members individually or use `chain export` for complete
Xray JSON. Export files are written atomically with mode 0600; if the containing
directory is not writable, the error names the temporary-create, flush or rename
operation that failed.

## Collecting information for a bug report

There is not yet an automatic diagnostic-bundle exporter. Capture `xraytui
doctor`, `xraytui status` and only the minimum manually reviewed runtime-log
excerpt. Do **not** attach `generated-xray.json`, `last-good-xray.json`,
`secrets.toml` or `subscriptions.toml`, any share-link export, or any QR image:
all can contain node credentials, and subscription URLs usually embed a bearer
token.
