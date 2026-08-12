# Configuration

TOML is the source of truth. Generated Xray JSON is a build artifact and is never
read back as configuration, so a file under `~/.config/xraytui` can be hand
edited, diffed and kept in version control.

Every file carries a `schema_version`. A file written by a **newer** xraytui is a
hard error, not a best-effort parse, so a downgrade cannot silently mangle
policy. The current schema version is `1`.

## File layout

Locations follow the XDG base directory specification. `XDG_CONFIG_HOME`,
`XDG_STATE_HOME` and `XDG_CACHE_HOME` are honoured only when set to an absolute
path; otherwise the standard fallbacks apply.

| Directory | Default | Mode | Contents |
|---|---|---|---|
| Config | `$XDG_CONFIG_HOME/xraytui`, else `~/.config/xraytui` | 0700 | `config.toml`, `secrets.toml`, policy files, `nodes.d/`, `routes.d/` |
| State | `$XDG_STATE_HOME/xraytui`, else `~/.local/state/xraytui` | 0700 | `state.sqlite3`, `history/`, `logs/` |
| Cache | `$XDG_CACHE_HOME/xraytui`, else `~/.cache/xraytui` | 0700 | `subscriptions/`, `geodata/`, `downloads/` |
| Runtime | `$XDG_RUNTIME_DIR/xraytui` | 0700 | sockets, generated JSON, runtime state |

`XDG_RUNTIME_DIR` has no portable fallback that is both private and tmpfs-backed.
When it is unset, `/run/user/<uid>` is used if it exists, and failing that a 0700
directory named `xraytui-<uid>` under the system temporary directory, in which
case the caller is expected to warn.

### Files

| Path | Mode | Purpose |
|---|---|---|
| `<config>/config.toml` | 0600 | Everything documented below. |
| `<config>/secrets.toml` | 0600 | Node credentials, kept out of the display configuration. |
| `<config>/subscriptions.toml` | 0600 | Subscription definitions, including URLs that usually embed a bearer token. |
| `<config>/<entity>.toml` | 0600 | Policy entities: nodes, groups, chains, profiles and rules, one file per kind. |
| `<config>/nodes.d/`, `<config>/routes.d/` | 0700 | Drop-in directories for split policy files. |
| `<state>/state.sqlite3` | 0600 | Runtime history and cached metadata. Policy never lives here. |
| `<state>/logs/xraytuid.log`, `<state>/logs/xray.log` | 0600 | Daemon and core logs. |
| `<runtime>/control.sock` | inside a 0700 directory | Daemon control socket. |
| `<runtime>/daemon.lock` | 0600 | Prevents two daemons for one user. |
| `<runtime>/xray-api.json` | 0600 | The recorded commander endpoint. |
| `<runtime>/xray-api.sock` | 0600 | Commander socket when the Unix transport is used. |
| `<runtime>/generated-xray.json` | 0600 | The generation currently applied. Contains credentials in cleartext. |
| `<runtime>/last-good-xray.json` | 0600 | Last generation that started, probed and accepted its overrides. |
| `<runtime>/runtime-state.json` | 0600 | Serialised observed state, for read-only clients and crash inspection. |

### How permissions are enforced

Directories are created with `mkdir(0700)`. An existing directory is verified
before use and is **refused** if it is a symlink, is not a directory, or is owned
by another uid; if it merely has loose permissions (any group or other bits set)
they are tightened back to 0700 rather than refused.

Files are written by a single helper that creates a sibling temporary file
`.<name>.tmp.<pid>` with mode 0600, writes it, `fsync`s it, `rename(2)`s it into
place and then `fsync`s the directory. A crash therefore leaves either the old
contents or the new ones, never a truncated file, and no temporary files are left
behind.

## `config.toml`

Only settings that are not part of the routing model live here. Nodes, groups,
chains, profiles, rules and subscriptions are policy entities and live in their
own files.

Every section may be omitted; every field within a section may be omitted. An
empty `config.toml` is exactly equivalent to the defaults below.

### Top level

| Field | Type | Default | Meaning |
|---|---|---|---|
| `schema_version` | integer | `1` | Schema version of this file. A higher value than the build understands is a hard error. |

### `[core]`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `binary` | string | `""` | Absolute path to the `xray` binary. Empty means "look it up on `PATH`". |
| `asset_dir` | path | unset | Directory containing `geoip.dat` and `geosite.dat`. |
| `release_channel` | `"stable"` \| `"preview"` | `"stable"` | Which upstream releases a managed install considers. `preview` includes GitHub prereleases and is never selected implicitly. |
| `pinned_version` | string | unset | Pin a specific release, for example `"v26.3.27"`. |
| `log_level` | string | `"warning"` | Xray log level, written into the generated document. |
| `api_unix_socket` | boolean | `true` | Prefer a Unix-domain commander socket over loopback TCP. Loopback TCP has no per-user access control on Linux. |
| `stats` | boolean | `true` | Emit the `stats` and `policy` blocks so traffic counters are collected. |
| `sniffing` | boolean | `false` | Enable traffic sniffing for routing. Off by default because it inspects the first bytes of a connection. |
| `lan_access` | boolean | `false` | Permit listeners on non-loopback addresses. |
| `lan_access_acknowledged` | boolean | `false` | Explicit confirmation. `lan_access = true` without it is a validation error. |

### `[runtime]`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `start_core_on_launch` | boolean | `true` | Bring the core up as soon as the daemon starts. |
| `failure_policy` | `"restore"` \| `"block"` | `"restore"` | What happens to networking when the core or daemon dies while TUN is active. See `docs/NETWORKING.md`. |
| `restart_backoff_min_ms` | integer | `500` | Restart backoff floor. |
| `restart_backoff_max_ms` | integer | `60000` | Restart backoff ceiling. |
| `max_consecutive_restarts` | integer | `8` | Give up after this many consecutive failed starts and wait for the operator. |
| `start_health_deadline_ms` | integer | `15000` | How long to wait for a freshly started core to become reachable and healthy. |
| `netd_lease_ttl_secs` | integer | `30` | Seconds a netd lease survives without a heartbeat before the failure policy is applied. |

### `[tun]`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"off"` \| `"direct"` \| `"global"` \| `"rule"` | `"off"` | Desired system mode at startup. Anything other than `off` requires a TUN device. |
| `name` | string | `"xraytui0"` | Interface name. Must match `^xraytui[0-9a-z]{0,8}$` so the helper can prove ownership from the name alone. |
| `mtu` | integer | `1500` | Device MTU. Must be within `576..=9000`. |
| `ipv4` | boolean | `true` | Carry IPv4 inside the tunnel. |
| `ipv6` | boolean | `false` | Carry IPv6 inside the tunnel. When false, IPv6 is explicitly blackholed rather than left to leak. |
| `ipv4_address` | string | `"198.18.0.1/15"` | Address assigned to the device, CIDR form. |
| `ipv6_address` | string | `"fdfe:dcba:9876::1/126"` | IPv6 address assigned to the device, CIDR form. |
| `bypass_private_networks` | boolean | `true` | Send RFC1918 and link-local traffic straight out; compiles to a `geoip:private` direct rule. |
| `include_cidrs` | array of string | `[]` | Extra destination prefixes routed into the tunnel. |
| `exclude_cidrs` | array of string | `[]` | Destination prefixes never routed into the tunnel. |
| `route_table` | integer | `29281` (`0x7261`) | Routing table id. Probed for conflicts before use. |
| `fwmark` | integer | `29281` (`0x7261`) | Firewall mark. Probed for conflicts before use. |
| `rule_priority` | integer | `17000` | Priority of the policy-routing rule. |

At least one of `ipv4` and `ipv6` must be enabled.

### `[dns]`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `manager` | `"none"` \| `"systemd-resolved"` \| `"resolvconf"` \| `"manual"` | `"none"` | Which Linux component owns the system resolver configuration. `none` means system DNS is not touched. |
| `manual_acknowledged` | boolean | `false` | Required alongside `manager = "manual"`; the manual backend rewrites `/etc/resolv.conf` and refuses to act without it. |
| `enabled` | boolean | `false` | Configure Xray's own DNS module. Independent of `manager`. |
| `listen` | socket address | unset | Local address the DNS listener binds, when one is needed, for example `"127.0.0.53:5353"`. |
| `direct_servers` | array of string | `["localhost"]` | Resolvers reached without a proxy. |
| `proxy_servers` | array of string | `[]` | Resolvers reached through the default profile. |
| `direct_domains` | array of string | `["geosite:private"]` | Domains always resolved by `direct_servers`, regardless of order. |
| `query_strategy` | `"UseIP"` \| `"UseIPv4"` \| `"UseIPv6"` | `"UseIP"` | Address families the DNS module will return. |
| `non_ip_query` | `"drop"` \| `"skip"` \| `"reject"` | `"drop"` | Deterministic handling of non-A/AAAA queries. |

### `[health]`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | `true` | Run probes automatically. |
| `test_url` | string | `"http://cp.cloudflare.com/generate_204"` | URL fetched through the outbound under test. Must be an `http` or `https` URL. |
| `timeout_ms` | integer | `5000` | Per-probe deadline. Must be at least `200`. |
| `concurrency` | integer | `8` | Maximum probes in flight. Must be within `1..=64`. |
| `interval_secs` | integer | `300` | Seconds between automatic sweeps. Omit the field to disable automatic sweeps. |
| `probe_idle_nodes` | boolean | `false` | Also probe nodes that are not active targets, group candidates or chain hops. |
| `history_len` | integer | `32` | How many probe results to keep per entity. |

Probes always traverse the real outbound — TCP connect, optional TLS handshake,
optional small HTTP request. ICMP is never used, because Xray's TUN has no ICMP
support and reports connect success optimistically.

### `[subscription]`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `max_response_bytes` | integer | `8388608` (8 MiB) | Hard cap on a response body, counted while streaming rather than trusting `Content-Length`. Must be non-zero. |
| `max_nodes` | integer | `10000` | Hard cap on nodes produced by one subscription. Must be non-zero. |
| `max_redirects` | integer | `5` | Redirect limit. Must be at most `10`. |
| `timeout_ms` | integer | `30000` | Total request deadline. |
| `user_agent` | string | `"xraytui/<version>"` | `User-Agent` sent with subscription requests. |
| `update_on_start` | boolean | `false` | Update every enabled subscription when the daemon starts. |

TLS validation is always on for subscription fetches and there is no switch to
disable it. Downgrades to plain HTTP across a redirect, and non-HTTP(S) schemes,
are refused.

### `[ui]`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `mouse` | boolean | `false` | Capture mouse events. Off by default so terminal text selection keeps working. |
| `colour` | `"auto"` \| `"16"` \| `"256"` \| `"truecolor"` \| `"mono"` | `"auto"` | Colour depth. |
| `start_page` | string | `"dashboard"` | Page opened at startup. |
| `idle_refresh_ms` | integer | `1000` | Milliseconds between dashboard refreshes when nothing has changed. |
| `log_buffer_lines` | integer | `2000` | Lines kept in the log view. |
| `keymap` | table of string to string | `{}` | Key overrides, written as `"action" = "key"`. |

### Validation

Values that serde cannot express are checked when the file is loaded, and **every
problem is reported together** rather than one at a time:

| Check | Message fragment |
|---|---|
| `tun.mtu` within `576..=9000` | `[tun] mtu … is outside the usable range` |
| at least one of `tun.ipv4`, `tun.ipv6` | `[tun] at least one of ipv4 or ipv6` |
| `tun.name` matches the interface pattern | `[tun] name … must match ^xraytui[0-9a-z]{0,8}$` |
| `health.concurrency` within `1..=64` | `[health] concurrency … must be between 1 and 64` |
| `health.timeout_ms` at least 200 | `[health] timeout_ms must be at least 200` |
| `health.test_url` is `http`/`https` | `[health] test_url must be an http or https URL` |
| `subscription.max_response_bytes` non-zero | `[subscription] max_response_bytes must be non-zero` |
| `subscription.max_nodes` non-zero | `[subscription] max_nodes must be non-zero` |
| `subscription.max_redirects` at most 10 | `[subscription] max_redirects must be at most 10` |
| `core.lan_access` requires acknowledgement | `set lan_access_acknowledged = true` |

## Identifiers

Nodes, groups, chains, profiles and rules are addressed by slugs: lowercase ASCII
alphanumerics plus `-` and `_`, 1 to 64 bytes, never starting or ending with a
separator.

The restriction is not cosmetic. Identifiers end up inside generated Xray tags,
nftables comments, cgroup directory names and systemd unit arguments, so they must
be free of `/`, whitespace, quotes and shell metacharacters by construction
rather than by escaping at each use site. Uppercase input is rejected rather than
silently lowercased, so two configurations differing only in case cannot compile
to the same tag.

When importing, the display name keeps the original text and the identifier gets
a machine-safe derivative: a node named `香港 01 | IEPL` becomes id `01-iepl`
with the name preserved for display.

## Target and action tokens

A **target** is anything traffic can be pointed at. It is what a profile selects,
what a chain hop resolves to, and what the CLI and `dmenu` output print.

| Token | Meaning |
|---|---|
| `node:<node-id>` | A concrete node, for example `node:hk-01`. |
| `group:<group-id>` | A group; its balancer picks a member. |
| `chain:<chain-id>` | A multi-hop chain; traffic reaches the chain's terminal hop. |
| `direct` | Leave the machine without a proxy. |
| `block` | Drop the connection. |

A **rule action** is what a routing or application rule does with matching
traffic. Every target token is also a valid action, plus two more:

| Token | Meaning |
|---|---|
| `profile:<profile-id>` | Send to a named egress profile, which resolves through that profile's selector. |
| `default` | Use whichever profile the current system mode designates as default. |

Parsing is strict and round-trips: `"node:hk-01"` parses to a node target and
prints back as `node:hk-01`. Unknown prefixes are rejected with the list of
accepted kinds; an invalid identifier is reported as an identifier error rather
than as an unknown kind, so `node:UPPER` says what is actually wrong.

## Worked example

```toml
schema_version = 1

[core]
binary = "/usr/bin/xray"
asset_dir = "/usr/share/xray"
release_channel = "stable"
pinned_version = "v26.3.27"
log_level = "warning"
api_unix_socket = true
stats = true
sniffing = false
lan_access = false
lan_access_acknowledged = false

[runtime]
start_core_on_launch = true
failure_policy = "block"          # do not let traffic fall back to direct
restart_backoff_min_ms = 500
restart_backoff_max_ms = 60000
max_consecutive_restarts = 8
start_health_deadline_ms = 15000
netd_lease_ttl_secs = 30

[tun]
mode = "rule"                     # evaluate the ordered rule set for TUN traffic
name = "xraytui0"
mtu = 1500
ipv4 = true
ipv6 = false
ipv4_address = "198.18.0.1/15"
ipv6_address = "fdfe:dcba:9876::1/126"
bypass_private_networks = true
include_cidrs = []
exclude_cidrs = ["192.0.2.0/24"]  # a lab network that must stay off the tunnel
route_table = 29281
fwmark = 29281
rule_priority = 17000

[dns]
manager = "systemd-resolved"
manual_acknowledged = false
enabled = true
listen = "127.0.0.53:5353"
direct_servers = ["localhost"]
proxy_servers = ["1.1.1.1", "8.8.8.8"]
direct_domains = ["geosite:private", "geosite:cn"]
query_strategy = "UseIPv4"
non_ip_query = "drop"

[health]
enabled = true
test_url = "http://cp.cloudflare.com/generate_204"
timeout_ms = 5000
concurrency = 8
interval_secs = 300
probe_idle_nodes = false
history_len = 32

[subscription]
max_response_bytes = 8388608
max_nodes = 10000
max_redirects = 5
timeout_ms = 30000
user_agent = "xraytui/0.1.0"
update_on_start = false

[ui]
mouse = false
colour = "auto"
start_page = "dashboard"
idle_refresh_ms = 1000
log_buffer_lines = 2000

[ui.keymap]
switch-profile = "p"
cycle-mode = "m"
```

That configuration describes the host settings only. The profiles it implies —
for instance a `web` profile targeting `chain:hk-us` with a SOCKS listener on
`127.0.0.1:1080`, and a `bulk` profile targeting `group:auto-hk` with
`kill_switch = "block"` — are policy entities and live in the policy files, where
their targets are written using exactly the token syntax above.

## Migration and backup

Migrations are versioned functions from schema `n` to `n + 1`, applied in a
contiguous ladder that a test asserts has no gaps and reaches the current
version. At schema version 1 the ladder is deliberately empty: the machinery
exists so that the first real migration is a data change rather than an
infrastructure change.

| Property | Behaviour |
|---|---|
| Dry run | Planning reads every `*.toml` in the configuration directory and reports `path: schema n -> m (description)` per file, plus the backup location, without touching the filesystem. |
| Backup | A timestamped sibling directory `<config>.backup.<unix-seconds>` is created **before** anything is written, containing a copy of every `*.toml`. |
| Atomicity per file | Each file is fully transformed in memory and only then written atomically at 0600. A failing migration leaves that file untouched. |
| Newer schema | Refused outright with `SchemaTooNew { found, supported }`. A newer file is never downgraded. |
| Symlinks | A symlink inside the configuration directory aborts the migration rather than being followed, so a migration write cannot be redirected outside the tree. |
| Unknown fields | Preserved verbatim rather than dropped, so a field added by a newer build survives a round trip through an older one. |

Because the backup directory is a sibling of the configuration directory, it
inherits the same private-directory guarantees: created with mode 0700, contents
written at 0600.
