# Upstream compatibility

All statements in this file were checked against primary sources — the
`XTLS/Xray-core` git tree at the pinned tag and the shipped release artifacts —
not from memory.

| Field | Value |
|---|---|
| Date upstream behaviour was checked | **2026-08-12** |
| Default supported Xray stable release | **v26.3.27** (published 2026-03-27, `prerelease: false`) |
| Commit the release was built from | `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0` |
| Protobuf source tag | `v26.3.27` (same commit) |
| Optional preview channel | none selected; `release_channel = "preview"` opts in to GitHub prereleases and is never used implicitly |
| Verified release artifact | `Xray-linux-64.zip`, SHA2-256 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`, matching the official `.dgst` file |
| Minimum Xray version accepted | `1.8.0` (below this the routing `ruleTag` / `RemoveRule` API surface is missing) |

Release selection rule: the managed installer reads
`https://api.github.com/repos/XTLS/Xray-core/releases` and **filters out entries
with `prerelease: true` or `draft: true`** unless the user selected the preview
channel. Version comparison is semantic, not lexical, so `v26.3.27` sorts above
`v26.3.9`; the highest numeric tag is never chosen without the stable filter.

## Verified API surface (`vendor/xray-proto`, tag v26.3.27)

The vendored `.proto` files are the exact dependency closure of the four command
services. They are committed to the repository, so an ordinary build never
downloads protobufs from a moving branch.

```
app/log/command/config.proto          -> LoggerService
app/proxyman/command/command.proto    -> HandlerService
app/router/command/command.proto      -> RoutingService
app/stats/command/command.proto       -> StatsService
common/net/network.proto
common/protocol/user.proto
common/serial/typed_message.proto
core/config.proto
```

Confirmed RPCs at this tag:

* `HandlerService`: `AddInbound`, `RemoveInbound`, `AlterInbound`, `ListInbounds`,
  `GetInboundUsers`, `GetInboundUsersCount`, `AddOutbound`, `RemoveOutbound`,
  `AlterOutbound`, `ListOutbounds`.
* `RoutingService`: `SubscribeRoutingStats` (server stream), `TestRoute`,
  `GetBalancerInfo`, `OverrideBalancerTarget`, `AddRule`, `RemoveRule`, `ListRule`.
* `StatsService`: `GetStats`, `GetStatsOnline`, `QueryStats`, `GetSysStats`,
  `GetStatsOnlineIpList`, `GetAllOnlineUsers`.
* `LoggerService`: `RestartLogger`.

`RoutingService.OverrideBalancerTarget(balancerTag, target)` is the mechanism
xraytui uses for hot profile switching. `target` is matched against the balancer's
`selector` prefixes, so **the selector list is a prefix match, not an exact tag
list** — this drove the tag-namespacing scheme in `docs/XRAY-INTEGRATION.md`.

`gRPC server reflection` is *not* served by Xray's commander. Capability discovery
is therefore done by (a) parsing `xray version`, and (b) probing each service with
a cheap read-only RPC and recording `Unimplemented` as "absent". This is recorded
as a fallback implementation below.

## Verified configuration semantics

### Routing rule fields (`infra/conf/router.go`, `parseFieldRule`)

`domain`, `domains`, `ip`, `port`, `network`, `sourceIP`/`source`, `sourcePort`,
`user`, `vlessRoute`, `inboundTag`, `protocol`, `attrs`, `localIP`, `localPort`,
`process`, `webhook`, plus `ruleTag`, and exactly one of `outboundTag` /
`balancerTag`. A rule with neither target is rejected by Xray at load time.

### Process matcher (`app/router/condition.go`, `NewProcessNameMatcher`)

The single `process` string list is demultiplexed by shape:

| Input shape | Matched against |
|---|---|
| `firefox` (no `/`) | process **name**; a trailing `.exe` is stripped |
| `/usr/lib/firefox/firefox` (contains `/`) | absolute **executable path** |
| `/usr/bin/` (trailing `/`) | **directory prefix** of the executable path |
| `self/` | the Xray process itself (by PID) — loop prevention |
| `xray/` | replaced at load time with Xray's own `os.Executable()` |

Matching requires a local source address; Xray resolves the owning process via
`net.FindProcess` on the connection 4-tuple. It returns `false` (no match) rather
than erroring when the peer is not local.

### Balancers (`infra/conf/router.go`, `BalancingRule`)

`tag`, `selector` (prefix list), `strategy.type`, `strategy.settings`,
`fallbackTag`. Accepted strategies: `random` (default), `roundrobin`, `leastload`,
`leastping`. `leastping` and `fallbackTag`-aware round-robin require an
`observatory` / `burstObservatory` block to supply liveness; without it every
candidate is treated as alive.

**A balancer cannot be used as an outbound target.** `outboundTag` and
`balancerTag` are mutually exclusive fields of a *rule*. This is why groups are
compiled through a second routing stage (see below).

### Loopback outbound (`proxy/loopback`)

`{"protocol":"loopback","settings":{"inboundTag":"<tag>"}}` re-injects the
connection into routing with the given inbound tag. This is the supported
mechanism for the two-stage group compilation:

```
profile/<p>/selector  --(balancer override)-->  group/<g>/entry   (loopback)
group/<g>/entry       --(inboundTag rule)---->  balancerTag: group/<g>/balancer
group/<g>/balancer    --(selector prefix)---->  node/<n>
```

### Chains (`infra/conf/transport_internet.go`)

`streamSettings.sockopt.dialerProxy = "<outbound tag>"` makes an outbound dial
through another outbound while keeping its own transport and TLS/REALITY settings
intact. For `Local -> A -> B -> C -> Internet`, C carries
`dialerProxy = B`, B carries `dialerProxy = A`, and the chain terminal that
routing points at is **C**. (The deprecated `proxySettings.tag` form is not used.)

### TUN inbound (`proxy/tun`, `infra/conf/tun.go`)

Settings are only `{name, MTU, userLevel}`. `port`/`listen` are ignored. Verified
in `proxy/tun/README.md` and `infra/conf/xray.go`:

> *"Current implementation does not contain options to configure network level
> addresses, routing or rules. Enabling the feature will result only tun interface
> up, and that's it."*

Consequences that shaped this project:

1. **Addresses, routes, policy rules and DNS are entirely xraytui's job.** That is
   the whole reason `xraytui-netd` exists.
2. **Linux TUN does not accept an inherited file descriptor.** `proxy/tun/tun_linux.go`
   calls `unix.Open("/dev/net/tun")` + `TUNSETIFF` itself. The `xray.tun.fd`
   environment flag (`common/platform.TunFdKey`) is only consumed by
   `tun_android.go` and `tun_darwin.go`. See *Fallback implementations* below.
3. Xray's TUN has **no ICMP support** and reports connect success optimistically,
   so health checks must be L4/L7 through an outbound, never ICMP ping.

### DNS

`dns.servers[]` accepts `address`, `port`, `domains`, `expectedIPs`,
`unexpectedIPs`, `skipFallback`, `queryStrategy`, `tag`, `timeoutMs`,
`disableCache`, `finalQuery`, `clientIp`. The `dokodemo`-style DNS inbound is
`protocol: "dns"` with `{network, address, port, nonIPQuery, blockTypes}`;
`nonIPQuery` accepts `drop` / `skip` / `reject`, which is how non-A/AAAA queries
are handled deterministically.

## Features detected dynamically at runtime

| Capability | Detection |
|---|---|
| gRPC service availability | probe RPC; `Unimplemented`/`Unavailable` ⇒ absent |
| `RoutingService.RemoveRule` / `ruleTag` | version ≥ 1.8.0 **and** successful `ListRule` |
| `GetStatsOnlineIpList`, `GetAllOnlineUsers` | probe; optional, only used by Runtime page |
| `tun` inbound | `xray run -test` against a probe config containing a TUN inbound |
| `observatory` / `burstObservatory` | `xray run -test` probe config |
| VLESS `encryption` / post-quantum fields | `xray run -test` probe config |
| geodata files | existence of `geoip.dat` / `geosite.dat` in `XRAY_LOCATION_ASSET` |

Probing uses `xray run -test -config <tmpfile>` in a temporary directory, never a
live core, and the results are cached per Xray binary hash in the state store.

## Fallback implementations required by upstream behaviour

1. **TUN file descriptor passing.** The task specification asks for `SCM_RIGHTS`
   FD passing to Xray. Upstream Linux Xray cannot consume a passed FD. xraytui
   instead has `xraytui-netd` create a **persistent** TUN device
   (`TUNSETPERSIST`) owned by the requesting UID (`TUNSETOWNER`/`TUNSETGROUP`),
   configure addresses/MTU/link state over netlink, and *then* let the
   unprivileged Xray process attach to the existing device. The netd protocol
   still returns the tun FD over `SCM_RIGHTS` — `xraytuid` holds it as a liveness
   handle and as proof of ownership — but the data plane FD is opened by Xray.
   See `docs/NETWORKING.md` for the capability consequences and the
   `CoreLaunchTun` fallback used when the kernel/`/dev/net/tun` permissions do not
   allow unprivileged attach.
2. **gRPC reflection.** Not served; replaced by probe-based capability detection.
3. **Balancer-of-balancer.** Not supported upstream; replaced by the loopback
   two-stage compilation described above.
4. **Per-rule `continue` action.** Xray routing rules are terminal. The controller
   implements `continue` only where it can be flattened deterministically at
   compile time, and rejects it otherwise with a diagnostic.

## Known incompatible or unstable upstream releases

| Range | Problem | xraytui behaviour |
|---|---|---|
| `< 1.8.0` | no `ruleTag`, no `RemoveRule`, no `ListRule` | refuse to start, explain in `xraytui doctor` |
| `< 1.8.6` | `dialerProxy` did not reliably preserve terminal TLS settings for all transports | chains disabled, warning surfaced |
| any release marked `prerelease` | may change JSON fields between builds | requires explicit `release_channel = "preview"` |

## Re-checking procedure

`cargo xtask upstream-check` re-runs the checks that produced this file: it fetches
the release list, filters prereleases, compares the pinned tag, verifies the
vendored protobuf closure hash against the upstream tag, and prints a diff of the
routing/tun/balancer JSON schema field lists. It never writes to the system.
