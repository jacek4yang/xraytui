# DNS

DNS is two independent concerns and xraytui keeps them separate:

| Concern | Setting | Owner |
|---|---|---|
| Where the **system** sends its queries | `[dns] manager` | `xraytui-netd`, through a DNS manager backend |
| How **Xray** resolves names it is asked to reach | `[dns] enabled` and the server lists | the compiler, through Xray's DNS module |

Either can be used without the other. `manager = "none"` with `enabled = true`
gives a resolver inside the core without touching the host. `manager =
"systemd-resolved"` with `enabled = false` points the host at a resolver that is
not xraytui's own. Both are legitimate, and both are off by default.

## DNS manager abstraction

The system resolver is mutated only through a backend chosen explicitly by the
operator. Nothing is auto-detected and then acted on.

| `manager` | Mechanism | Notes |
|---|---|---|
| `none` (default) | none | System DNS is never touched. |
| `systemd-resolved` | `org.freedesktop.resolve1` over **D-Bus** | The primary backend. Per-link settings, so only the interfaces xraytui manages are affected. `resolvectl(8)` is not invoked; the D-Bus API is used directly. |
| `resolvconf` | the `resolvconf` interface | Optional, for hosts that use it. |
| `manual` | rewrite `/etc/resolv.conf` | Requires `manual_acknowledged = true`. Without that confirmation the backend refuses to act. `/etc/resolv.conf` is never written by any other backend. |

The manual backend is last because a global `/etc/resolv.conf` rewrite affects
every process on the machine, cannot be scoped to a link, and races with whatever
else manages that file. It exists for hosts that have no resolver manager at all.

When the `systemd-resolved` link is applied or re-applied, netd calls the
documented `ResetServerFeatures` and `FlushCaches` manager methods after setting
the link DNS, route-only domains and default-route flag. This matters after a
core outage: resolved remembers an unreachable server and may otherwise keep it
downgraded while trying fallback servers even though Xray has recovered.

Observed DNS state is reported as one of four values, visible in the TUI and in
`xraytui doctor`:

| `DnsStatus` | Meaning |
|---|---|
| `unmanaged` | No DNS management requested. |
| `healthy` | Managed and answering; carries the backend in use and the resolver the system was pointed at. |
| `unhealthy` | Managed but not answering; carries a bounded explanation. |
| `restored` | Previous state has been put back after teardown. |

## Xray's DNS module

Setting `[dns] enabled = true` makes the compiler emit a `dns` block, a `dns`
outbound and the routing rules that feed them.

Objects emitted:

| Object | Tag | Shape |
|---|---|---|
| DNS outbound | `control/dns` | `{"protocol":"dns","settings":{"nonIPQuery":"<drop\|skip\|reject>"}}` |
| Local listener inbound | `inbound/system/dns` | `dokodemo-door` bound to `[dns] listen`, forwarding to `127.0.0.1:53` over `tcp,udp`. Emitted only when `listen` is set. |
| Direct resolver tag | `inbound/system/dns-query/direct` | Per-nameserver `tag` (and the global `dns.tag`); routes that resolver's sockets to `control/direct`. |
| Proxied resolver tag | `inbound/system/dns-query/proxy` | Per-nameserver `tag`; routes that resolver's sockets to the default profile selector. |

Server list construction, in the order the compiler emits it:

1. When the proxied-DNS profile can start through a hostname, one **detailed**
   server per entry of `bootstrap_servers`. These entries match only the exact
   first-hop names, carry the direct tag and `skipFallback: true`, and the last
   carries `finalQuery: true`. Global `disableFallbackIfMatch: true` provides a
   second guard against unrelated resolvers joining the lookup.
2. If `direct_domains` is non-empty, one **detailed** server per entry of
   `direct_servers`, each carrying `domains: direct_domains` and
   `skipFallback: true`, the direct tag, and global
   `disableFallbackIfMatch: true`.
3. Every entry of `proxy_servers`, as a detailed server carrying the proxied
   tag.
4. Every entry of `direct_servers`, carrying the direct tag, only when no
   proxied resolver exists or `proxy_failure_policy = "direct"` explicitly
   permits direct fallback.

The compiler refuses to synthesize a resolver. Enabling DNS with both server
lists empty is an actionable error. It also refuses `direct_domains` without a
`direct_servers` entry and refuses `proxy_failure_policy = "direct"` when there
is no explicit direct resolver to receive that fallback.

`queryStrategy` comes from `[dns] query_strategy` (`UseIP`, `UseIPv4`,
`UseIPv6`). `hosts` is emitted empty and cache remains at Xray's default;
fallback is governed explicitly as described below.

Three routing rules complete the picture (see `docs/XRAY-INTEGRATION.md`):

```text
rule/system/dns-upstream-direct
                            inboundTag: [inbound/system/dns-query/direct]
                                                               -> control/direct
rule/system/dns-upstream-proxy
                            inboundTag: [inbound/system/dns-query/proxy]
                                                               -> profile/<default>/selector
rule/system/dns-intercept   inboundTag: [inbound/system/tun, inbound/system/dns]
                            port: "53", network: "tcp,udp"      -> control/dns
```

The two exact upstream rules are placed before the broad `self/` direct bypass;
otherwise Xray's own resolver sockets would all go direct. The intercept rule is
placed before ordinary traffic rules can claim port 53.

## Split DNS

The split is expressed by the two server lists plus `direct_domains`:

| List | Reached | Typical use |
|---|---|---|
| `direct_servers` | without a proxy | the host's own resolver, or a LAN resolver that knows internal names |
| `proxy_servers` | through the default profile | a public resolver you want queried from the proxy's vantage point, so the answer matches where the connection will come from |
| `bootstrap_servers` | directly, but only for exact hostname-based first hops needed to establish `proxy_servers` | independent IP-literal resolvers; empty is valid only when every possible first hop is already an IP literal |
| `proxy_failure_policy` | `block` returns failure; `direct` permits the generic direct resolver list | keep `block` unless exposing a failed proxied query directly is an intentional availability tradeoff |
| `direct_domains` | forced onto `direct_servers` regardless of list order, with `skipFallback` and `disableFallbackIfMatch` | `geosite:private` by default; add internal zones and any `geosite:` set that must resolve locally |

The two fallback controls are intentionally paired. In Xray,
`skipFallback: true` means that a server is excluded when constructing the
generic fallback set; it does **not** stop fallback after that server matched a
domain. `disableFallbackIfMatch: true` supplies that second guarantee. A domain
in `direct_domains` is therefore answered by a matching direct server or not at
all, rather than quietly crossing to the proxied resolver. Conversely, an
ordinary proxied query cannot reach a generic direct resolver unless the user
selected `proxy_failure_policy = "direct"`.

Configuring `proxy_servers` requires an enabled default profile whose target and
effective profile/group fallbacks cannot select `direct`. Compilation refuses a
missing, disabled or direct-capable profile with an actionable DNS policy error;
it does not reinterpret the resolver as direct. The check also runs before a
live profile/group selector override, not only when Xray restarts. Since a
profile target can be a chain, proxied DNS can use the same multi-hop composition
as ordinary traffic.

Resolving through the proxy matters when a destination is geographically
load-balanced. Resolving directly matters when a name only exists on your LAN, or
when the answer must be a local address. Getting this wrong does not usually
break connectivity, so it will not announce itself — it shows up as unexpectedly
distant CDN endpoints or as internal names that stop resolving.

The persisted profile model reserves a future `dns_policy` field, but the
current compiler refuses any value instead of silently ignoring it. Today,
proxied upstream DNS uses the default profile; a client using a profile's SOCKS
listener may still request remote hostname resolution using ordinary SOCKS5
domain-address semantics. Per-profile direct/proxied resolver selection remains
a tracked limitation.

## Loop prevention

A DNS loop is the characteristic failure of this design: the core asks the system
resolver, the system resolver is xraytui's listener, the listener asks the core.
Three separate mechanisms prevent it.

| Mechanism | Where | Prevents |
|---|---|---|
| Exact direct/proxied DNS upstream rules, emitted before the self bypass | generated rule table | Resolver sockets taking a broader route than the selected per-server policy. |
| `rule/system/core-bypass` with `process: ["self/"]`, emitted immediately afterward | generated rule table | Other core traffic — especially its uplink — being captured by its own TUN. Without this the core dials through itself. |
| `nonIPQuery` set to a deterministic value (`drop` by default) | `control/dns` outbound | Non-A/AAAA queries taking an undefined path. |

One loop still requires an explicit configuration choice: setting `direct_servers =
["localhost"]` **while** the system resolver has been pointed at xraytui's own
listener. `localhost` means "ask the system resolver", and the system resolver is
now the core. Symptom: every name times out and the DNS listener shows continuous
traffic. When `[dns] manager` points the host at `[dns] listen`, set
`direct_servers` to a concrete address — the upstream resolver the host used
before, or a public one — never `localhost`.

The compiler now closes the second bootstrap cycle automatically. It expands the
default profile's target, permitted profile fallback, every group candidate and
group fallback. For a chain, only hop 1 is a local bootstrap dependency; later
hostname hops remain unresolved until `dialerProxy` hands them to the preceding
proxy. Every hostname-based dependency must have at least one
`bootstrap_servers` entry whose own host is an IP literal. `localhost`, a
hostname resolver, the xraytui DNS listener itself, and schemes Xray does not
implement are refused. Accepted URL schemes are `tcp`, `tcp+local`, `https`,
`https+local`, `h2c`, `h2c+local`, and `quic+local`; a bare IP uses classic UDP
DNS.

For those exact first-hop outbound copies, the compiler converts the effective
family preference into `ForceIP`, `ForceIPv4`, `ForceIPv6`, `ForceIPv4v6`, or
`ForceIPv6v4`. This distinction is deliberate: upstream `UseIP*` logs an
internal-resolution failure and continues with the unresolved hostname, while
`ForceIP*` returns the failure. An unavailable bootstrap resolver therefore
blocks the connection rather than invoking the system resolver. The generated
warning and Xray JSON make this direct control-plane query visible.

## Leak diagnostics

A DNS leak here means a query that left the machine by a path you did not intend:
plaintext to the ISP's resolver while everything else is proxied, or resolved
locally when the answer needed to come from the exit.

Generating a share link or QR performs no DNS query at all. Endpoint hostnames
remain hostnames in the portable representation; an IPv6 literal is bracketed
according to URI syntax. Consequently sharing cannot bypass the configured DNS
route, and a share operation cannot be used as a reachability or leak test. Use
the profile/node health and exit-IP operations for those questions.

What to check, in order:

```sh
xraytui doctor                       # reports the DNS backend, the resolver in force,
                                     # and whether the managed link matches expectations
resolvectl status                    # per-link resolvers; the xraytui link should show
                                     # exactly what doctor reported
resolvectl query example.com         # which link and which resolver answered
```

Then confirm the path xraytui believes in:

- `xraytui show-config` shows the effective per-nameserver tags and the exact
  `dns-upstream-direct` / `dns-upstream-proxy` routing targets. The latter must
  name the default profile selector. Per-profile DNS overrides and a dedicated
  `dns-resolve` health probe are not implemented; the compiler refuses an
  override instead of displaying or silently ignoring it.
- With TUN active, port 53 arriving on `inbound/system/tun` is intercepted by
  `rule/system/dns-intercept`. If queries are still reaching an external resolver
  directly, the traffic is not entering the TUN at all — that is a routing
  problem, not a DNS one, and `docs/NETWORKING.md` is the right document.
- Under `failure_policy = "block"`, the host nftables route chain marks
  non-loopback TCP/UDP destination ports 53 and 853 even when the socket belongs
  to the systemd-resolved service UID. The core's exact bypass cgroup is accepted
  first so explicitly configured Xray direct/bootstrap resolvers retain their
  intended route. On core loss the same marking remains while both policy-table
  defaults are blackholed, preventing resolved fallback from becoming direct.
- `direct_domains` entries are answered by direct servers **by design**. A name
  in `geosite:private` resolving locally is correct behaviour, not a leak.
- With proxied DNS configured, a failure should not increment a direct-resolver
  connection counter under the default `block` policy. The real-Xray acceptance
  test exercises that exact failure. If `proxy_failure_policy = "direct"`, the
  direct query is intentional and should be reported as such.
- A hostname-based first hop appears as an exact `full:<host>` rule on the
  bootstrap resolvers. A bootstrap failure must not query an overlapping
  `direct_domains` resolver or reach the proxied resolver; the real-Xray
  acceptance fixture asserts all three connection counters.
- Application-level DNS bypasses xraytui entirely. A browser with DNS-over-HTTPS
  enabled resolves inside the browser over port 443; it will not appear as port
  53 traffic and no DNS setting in xraytui affects it. Disable it in the browser
  if you need those queries to follow policy.

## Restoration

Prior state is captured **before** any mutation and stored in the generation
record, so restoration does not depend on inferring what the previous
configuration was.

| Trigger | What happens |
|---|---|
| Normal teardown | Restore the captured per-link state; `DnsStatus` becomes `restored`. |
| Lease expiry after a crash | netd applies the generation's `failure_policy`; both `restore` and `block` restore DNS, because leaving the machine pointed at a resolver that no longer exists is not a useful kill switch. |
| netd start-up reconciliation | Any generation recorded in `/run/xraytui/state/` that has no live lease is restored. |
| Manual | `xraytui doctor --repair`, or `xraytui-netd --recover` when the daemon is gone. |

Restoration is idempotent: running it twice, or running it when nothing was
changed, is not an error. That is what makes it safe to run from three different
triggers.

The combined acceptance captures a postrouting counter on an otherwise usable
direct interface. A real query goes through `127.0.0.53` → systemd-resolved →
the Xray TUN listener → Xray DNS → an IPv6 DNS-over-TCP fixture through the
selected SOCKS outbound. It then kills Xray, exercises the restart backoff and
recovery, performs orderly down/up, kills the daemon, and requires the direct
DNS counter and configured direct-resolver fixture to remain at zero while the
recorded block policy survives the final helper disconnect on both official
stable and preview cores.

If restoration has failed and you need to intervene by hand, `docs/RECOVERY.md`
gives the exact commands, including `resolvectl revert` for the managed link and
the caveats for the `resolvconf` and `manual` backends.
