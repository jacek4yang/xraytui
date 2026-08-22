# Upstream compatibility

All statements in this file were checked against primary sources — the
`XTLS/Xray-core` git tree at the pinned tag and the shipped release artifacts —
not from memory.

| Field | Value |
|---|---|
| Date upstream behaviour was checked | **2026-08-22** |
| Default supported Xray stable release | **v26.3.27** (published 2026-03-27, `prerelease: false`) |
| Commit the release was built from | `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0` |
| Protobuf source tag | `v26.3.27` (same commit) |
| Latest explicit preview tested | **v26.7.28**, commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`; never selected implicitly |
| Verified release artifact | `Xray-linux-64.zip`, SHA2-256 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`, matching the official `.dgst` file |
| Verified preview artifact | `Xray-linux-64.zip`, SHA2-256 `8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40`, matching the official `.dgst` file |
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

### Endpoint DNS and bootstrap failure (`transport/internet/dialer.go`)

Stable v26.3.27 and preview v26.7.28 have the same ordering in `DialSystem`:

1. when `sockopt.domainStrategy` has an IP strategy and the destination is a
   domain, call the process-wide Xray DNS client;
2. replace the destination when lookup succeeds;
3. on lookup failure, return only for a `ForceIP*` strategy — `UseIP*` continues
   with the unresolved hostname;
4. only then apply `sockopt.dialerProxy`, if present; otherwise call the system
   dialer.

That ordering is why xraytui forces only the locally dialled first-hop outbound
copy and never later chain hops. A later hostname with `dialerProxy` and `AsIs`
is handed to the preceding proxy; forcing it locally would change chain DNS
semantics and disclose the hop name. WireGuard is separate: its client calls the
same Xray DNS feature for peer hostnames, and its JSON loader accepts only
`ForceIP*` strategies (default `ForceIP`).

The DNS client sources establish the other half of the guarantee. A
nameserver's `tag` becomes a synthetic inbound tag for routing; priority-domain
matches are ordered; `disableFallbackIfMatch` omits generic fallback clients;
and `finalQuery` stops the priority set at that client. `LookupIP` removes one
trailing root dot but does not lowercase its input, while the `full` matcher is
an exact string-key lookup; bootstrap rules must therefore preserve the endpoint
hostname's case. xraytui consequently
emits exact `full:` first-hop rules on explicit direct bootstrap resolvers, sets
`skipFallback` on each, `finalQuery` on the last resolver, and
`disableFallbackIfMatch` globally. This was checked in `app/dns/dns.go`,
`app/dns/nameserver.go`, `infra/conf/dns.go`, the normal transport dialer and the
WireGuard client/loader at both tested commits.

### Share/export-relevant connection fields

The official Xray share-link proposal (XTLS/Xray-core discussion 716) and the
actual v2rayN/v2rayNG serializers were checked together. The reviewed client
snapshots are v2rayN commit `af0eb9ed14638fa877d11c235e491442ec7ba215`
and v2rayNG commit `63f557242bdd071214c4037c76c912b66da925c8`.
`upstream-compat.toml` watches the exact serializer files on their active master
branches, so a relevant change fails the compatibility review even when Xray's
own tag did not move.

The v2rayN snapshot was reviewed again on 2026-08-22. Its only watched-path
change since `ebb4bd5daa45478e337a68f0be768fb7045520dc` removes an unused
`System.Collections.Specialized` import from `BaseFmt.cs`; query parsing and
serialization behavior are byte-for-byte unchanged after that line. No typed
model, importer, serializer or fixture change is required.

Verified modern mappings include:

* raw transport is written as `type=tcp`; IPv6 authorities are bracketed;
* VLESS carries `encryption`, `flow`, transport parameters and `fm`;
* XHTTP carries `host`, `path`, `mode` and JSON `extra`;
* TLS uses `sni`, `alpn`, `fp`, `ech`, `pcs` and `vcn` where ecosystem clients
  implement them;
* REALITY uses `pbk`, `sid`, `spx` and `pqv` in addition to SNI/fingerprint;
* current v2rayN/v2rayNG implement de-facto `wireguard://` and
  `hysteria2://` forms, including Hysteria `pinSHA256`, ECH, salamander and
  `mport`.

The URI proposal is not assumed to be an infallible standard. Serializer output
is gated by explicit fidelity, and fields absent from the mature-client dialect
cause refusal or explicit lossy output. `docs/SHARING.md` records the exact
contract.

### Xray-native Hysteria v2

The outbound is split across two layers in current Xray source:

* protocol `settings`: `{ "version": 2, "address": ..., "port": ... }`;
* stream: `network: "hysteria"`, TLS, and `hysteriaSettings` containing
  version/auth (plus deprecated bandwidth hints when supplied).

Salamander obfuscation is a `finalmask.udp` mask. Port hopping is
`finalmask.quicParams.udpHop.ports`. Putting address/auth wholly inside protocol
settings or treating Hysteria as a foreign standalone core is incorrect. The
generated shape has been accepted by real stable and preview binaries.

### mKCP legacy fields and final-mask dialects

Stable v26.3.27 translates de-facto share-link `headerType` and `seed` fields to
separate `header-*`, `mkcp-original`, and `mkcp-aes128gcm` UDP masks. Preview
v26.7.28 removes those JSON registry names and replaces them with repeated
`mkcp-legacy` masks whose settings carry `header` or `value`. The underlying
header and AES mask implementations remain present; only their configuration
registry changed.

xraytui probes the selected binary with synthetic, credential-free
configurations and supplies the accepted dialect explicitly to its pure
compiler. It does not infer this capability from a channel label or silently
drop either the header or seed. `upstream-compat.toml` watches preview's split
`infra/conf/transport_finalmask.go` as well as both channels' stream-settings
sources so a later registry change becomes a mandatory review failure.

### Time-based TLS removal

The stable v26.3.27 source contains a scheduled removal that became active after
2026-06-01: `allowInsecure` now makes `xray run -test` fail. xraytui preserves
links that request it, classifies them unavailable for the installed core, and
does not silently turn verification back on or discard the field. Lossless Xray
execution requires certificate pins and/or verified certificate names supported
by current core semantics.

### Preview private-destination default

Preview v26.7.28 adds a default Freedom final rule for traffic arriving through
VLESS, VMess, Trojan, Hysteria, WireGuard and Shadowsocks server inbounds: private
IP targets are blackholed unless an earlier explicit `finalRules` allow matches.
This was first observed as a live REALITY test that completed its handshake but
carried no payload, then confirmed in `proxy/freedom/freedom.go`. The loopback
acceptance server has a fixture-only allow rule; xraytui does not weaken the
upstream default in generated client configurations.

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

`xray run -test` is not side-effect-free for this inbound. In both tested
channels, `main/run.go` calls `startXray()` before it checks the `-test` flag;
constructing `proxy/tun` immediately opens `/dev/net/tun`, issues `TUNSETIFF`,
and configures the link. Consequently the real TUN configuration acceptance
test is explicitly ignored in the unprivileged Rust suite and is executed
separately with `CAP_NET_ADMIN`. An unprivileged `operation not permitted` is
not treated as evidence that the generated JSON is invalid.

### DNS

`dns.servers[]` accepts `address`, `port`, `domains`, `expectedIPs`,
`unexpectedIPs`, `skipFallback`, `queryStrategy`, `tag`, `timeoutMs`,
`disableCache`, `finalQuery`, `clientIp`. Xray's `dns` proxy handler accepts
`{network, address, port, nonIPQuery, blockTypes}`; xraytui feeds that handler
from a local `dokodemo-door` and the `control/dns` outbound. `nonIPQuery` accepts
`drop` / `skip` / `reject`, which is how non-A/AAAA queries are handled
deterministically.

The stable and preview source were re-audited on 2026-08-22. `app/dns/dns.go`
selects each `NameServer.Tag` over the global `Config.Tag`, and
`app/dns/nameserver.go` installs that value as `session.Inbound.Tag` before the
resolver dispatches its socket. A normal routing `inboundTag` rule can therefore
send different nameservers to direct and profile/chain outbounds. This is proven
against both real binaries by a loopback DNS-over-TCP fixture: an AAAA query
traverses both members of an IPv6 chain, while a `full:` direct-domain query
reaches only the direct fixture.

Two fallback fields have different semantics in upstream source. Per-server
`skipFallback` excludes that server from the generic fallback set; it does not
mean “a matched-domain failure stops here.” Global `disableFallbackIfMatch`
provides the latter guarantee. xraytui emits both for direct-domain servers and
omits generic direct servers whenever proxied DNS is configured with the default
`proxy_failure_policy = "block"`. A real-core failure test points the proxied
resolver at a closed IPv6 TCP port, observes the configured proxy connection,
and observes zero connections at the available direct resolver.

The compiler additionally refuses implicit empty resolver policy and rejects a
`proxy_servers` route whose default profile or group/profile fallback can select
direct traffic. Controller hot-selector changes compile the candidate before
calling `OverrideBalancerTarget`, closing the runtime mutation path around that
check.

## Verified userland semantics

These are not Xray; they are the userland the privileged helper drives. Each was
found by running the code against a real kernel in a namespace
(`scripts/netns-test.sh`), not by reading documentation, and each changed a
design decision.

### nftables JSON cannot express `socket cgroupv2` (nftables 1.0.9)

`nft -j list` emits the expression as `{"socket": {"key": "cgroupv2"}}` —
**without the `level`**, so the dump is lossy — and the JSON *parser* rejects
the same object on input:

```
internal:0:0-0: Error: Invalid socket key value.
```

Adding the `level` field does not help; removing it does not help. The native
syntax works:

```
add rule inet xraytui u1000-mark socket cgroupv2 level 3 "xraytui.slice/u1000/work" \
    meta mark set 0x72610001
```

Matching a cgroup is the mechanism behind per-application routing, so the helper
generates nftables syntax rather than JSON, behind the character-set gate
described in `DECISIONS.md` D-015.

### nftables resolves a cgroup path at parse time, against `/sys/fs/cgroup`

`socket cgroupv2 "<path>"` is converted to a cgroup id when the rule is parsed,
by stating `/sys/fs/cgroup/<path>`. Two consequences: the cgroup must exist
*before* the rule is added — the helper creates every group a ruleset names
first — and a cgroup v2 hierarchy mounted anywhere else is invisible to
nftables. On a machine running cgroup v1 in hybrid mode, with cgroup2 at
`/sys/fs/cgroup/unified`, `socket cgroupv2` cannot be used at all;
`--check-capabilities` reports `nft socket cgroupv2  no`.

### `Command::env_clear()` removes the PATH used to resolve the program

Rust resolves a relative program name against the *child's* `PATH`. Clearing the
environment therefore makes `Command::new("nft").env_clear()` fail with
`NotFound` on a machine where `nft` is installed. See `DECISIONS.md` D-016.

### IPv6 route support and IPv6 interface enablement are different capabilities

`ipv6.disable=1`, or a kernel built without IPv6, answers `RTM_NEWROUTE` for an
IPv6 destination with `EOPNOTSUPP` — including a blackhole route, and including
`ip -6 route add`. The helper checks for `/proc/net/if_inet6` once and installs
the IPv4 half of the plan, reporting what it left out, rather than treating an
unusable family as a failure.

By contrast, setting `net.ipv6.conf.{all,default}.disable_ipv6=1` inside a live
network namespace leaves `/proc/net/if_inet6` present and still permits IPv6
policy rules and blackhole routes, but rejects assigning an IPv6 address to the
new TUN. This was reproduced on Linux 6.12.100 and is now a nested namespace
acceptance test. TUN capability probing therefore reads both sysctls; an IPv6
TUN request is refused before mutation with the proc/sysctl checks named, while
an IPv4-only request may still install an IPv6 blackhole and remain fail-closed.

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
| stable/preview after 2026-06-01 | `allowInsecure` is removed at validation time | preserve but mark unavailable; require pins/verified names rather than silently changing security |
| preview v26.7.28 | legacy mKCP mask JSON names consolidated as `mkcp-legacy` | capability-probe the selected binary and compile both header and seed in its accepted dialect |
| preview v26.7.28 | protocol-server Freedom defaults block private destinations | retain upstream fail-closed behavior; local server fixtures use an explicit allow |
| any release marked `prerelease` | may change JSON fields between builds | requires explicit `release_channel = "preview"` |

## Re-checking procedure

`cargo xtask upstream-check` performs live, read-only primary-source checks:

1. fetch the GitHub release list, separate draft/stable/preview, compare numeric
   latest tags and resolve each tag to its exact commit;
2. compare SHA-256 for 55 reviewed stable/preview source snapshots (27 stable,
   28 preview) covering stream settings, endpoint/DNS dial ordering, protocols,
   REALITY, XHTTP, Hysteria, WireGuard and Freedom routing;
3. byte-compare all eight vendored command-API protobuf files with the stable
   commit;
4. resolve the active v2rayN/v2rayNG branches and hash the sixteen watched
   importer/serializer files.

The expected values and commits are reviewable in `upstream-compat.toml`. Any
mismatch fails with the exact path and expected/observed hash and instructs the
maintainer to update the typed model, import/export, compiler, fixtures and this
document together. It downloads source text only, writes no system state, and
never promotes preview to stable.
