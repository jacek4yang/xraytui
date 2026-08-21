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
| DNS module tag | `inbound/system/dns-query` | `dns.tag`; Xray stamps it on queries the module itself emits, so they can be routed explicitly. |

Server list construction, in the order the compiler emits it:

1. If `direct_domains` is non-empty, one **detailed** server per entry of
   `direct_servers`, each carrying `domains: direct_domains` and
   `skipFallback: true`.
2. Every entry of `proxy_servers`, as a plain address.
3. Every entry of `direct_servers`, as a plain address.
4. If that produced nothing at all, a single `localhost` server, so the block is
   never empty.

`queryStrategy` comes from `[dns] query_strategy` (`UseIP`, `UseIPv4`,
`UseIPv6`). `hosts` is emitted empty; cache and fallback are left at Xray's
defaults.

Two routing rules complete the picture, at positions 2a and 2b of the generated
rule table (see `docs/XRAY-INTEGRATION.md`):

```text
rule/system/dns-intercept   inboundTag: [inbound/system/tun, inbound/system/dns]
                            port: "53", network: "tcp,udp"      -> control/dns
rule/system/dns-direct      inboundTag: [inbound/system/dns-query] -> control/direct
```

The intercept rule is placed before anything else can claim port 53, so a later,
broader rule cannot capture DNS by accident.

## Split DNS

The split is expressed by the two server lists plus `direct_domains`:

| List | Reached | Typical use |
|---|---|---|
| `direct_servers` | without a proxy | the host's own resolver, or a LAN resolver that knows internal names |
| `proxy_servers` | through the default profile | a public resolver you want queried from the proxy's vantage point, so the answer matches where the connection will come from |
| `direct_domains` | forced onto `direct_servers` regardless of list order, with `skipFallback: true` | `geosite:private` by default; add internal zones and any `geosite:` set that must resolve locally |

`skipFallback: true` on the detailed entries is what makes the split
deterministic: a domain in `direct_domains` is answered by a direct server or not
at all, rather than quietly falling through to a proxied resolver and leaking the
name.

Resolving through the proxy matters when a destination is geographically
load-balanced. Resolving directly matters when a name only exists on your LAN, or
when the answer must be a local address. Getting this wrong does not usually
break connectivity, so it will not announce itself — it shows up as unexpectedly
distant CDN endpoints or as internal names that stop resolving.

Per-profile overrides exist for the same reason. A profile's `dns_policy` may be
`proxied` (resolve through that profile's own egress), `direct` (use the direct
resolvers) or `remote` (let the SOCKS client send the hostname, `socks5h`
semantics, so the exit resolves it). Leaving it unset inherits the global policy.

## Loop prevention

A DNS loop is the characteristic failure of this design: the core asks the system
resolver, the system resolver is xraytui's listener, the listener asks the core.
Three separate mechanisms prevent it.

| Mechanism | Where | Prevents |
|---|---|---|
| `rule/system/core-bypass` with `process: ["self/"]`, emitted **first** | generated rule table | The core's own traffic — including its resolver queries and its uplink — being captured by its own TUN. Without this the core dials through itself. |
| `rule/system/dns-direct` matching `inboundTag: [inbound/system/dns-query]` | generated rule table | Queries the DNS module itself emits from re-entering routing and being proxied, which would recurse. |
| `nonIPQuery` set to a deterministic value (`drop` by default) | `control/dns` outbound | Non-A/AAAA queries taking an undefined path. |

One loop the software cannot prevent for you: setting `direct_servers =
["localhost"]` **while** the system resolver has been pointed at xraytui's own
listener. `localhost` means "ask the system resolver", and the system resolver is
now the core. Symptom: every name times out and the DNS listener shows continuous
traffic. When `[dns] manager` points the host at `[dns] listen`, set
`direct_servers` to a concrete address — the upstream resolver the host used
before, or a public one — never `localhost`.

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

- The TUI's per-profile view shows the profile's DNS policy and the result of
  the `dns-resolve` probe kind, which resolves *through* the profile rather than
  through the host stack.
- With TUN active, port 53 arriving on `inbound/system/tun` is intercepted by
  `rule/system/dns-intercept`. If queries are still reaching an external resolver
  directly, the traffic is not entering the TUN at all — that is a routing
  problem, not a DNS one, and `docs/NETWORKING.md` is the right document.
- `direct_domains` entries are answered by direct servers **by design**. A name
  in `geosite:private` resolving locally is correct behaviour, not a leak.
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

If restoration has failed and you need to intervene by hand, `docs/RECOVERY.md`
gives the exact commands, including `resolvectl revert` for the managed link and
the caveats for the `resolvconf` and `manual` backends.
