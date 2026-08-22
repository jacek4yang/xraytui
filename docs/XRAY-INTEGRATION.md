# Xray integration

How xraytui turns desired state into an Xray configuration, and how it drives a
running core. The pinned upstream release, the verified gRPC surface and the
re-check procedure are in `docs/UPSTREAM-COMPATIBILITY.md`; the rationale behind
each choice is in `DECISIONS.md`.

The compiler (`crates/xray-compiler`) is a pure function. It performs no I/O,
reads no environment and never consults the running core, which is what makes
generation diffing, snapshot testing and last-known-good rollback work.

## Tag namespace

Every object the compiler emits carries a namespaced tag, so ownership against a
live core is provable: `Compiled::owned_tags` is the complete set for a
generation. First path segments are reserved
(`crates/xray-compiler/src/tags.rs`, `RESERVED_ROOTS`): `control`, `node`,
`chain`, `group`, `profile`, `inbound`, `rule`.

### Constants

| Tag | Kind | Meaning |
|---|---|---|
| `control/block` | outbound | Blackhole with `{"response":{"type":"none"}}`. Emitted **first** so a truncated or malformed outbound list fails closed rather than leaking. |
| `control/direct` | outbound | `freedom` with `domainStrategy: UseIP`. |
| `control/dns` | outbound | `dns` outbound carrying `nonIPQuery`. Emitted only when the DNS module is enabled. |
| `control/self` | outbound | Reserved for the core's own traffic. Defined in `tags.rs`; the current compiler routes core traffic to `control/direct` instead and does not emit this tag. |
| `inbound/system/api` | inbound | The gRPC commander (`api.tag`). |
| `inbound/system/dns` | inbound | Local DNS listener, when one is configured. |
| `inbound/system/tun` | inbound | The shared system TUN inbound. |
| `inbound/system/dns-query/direct` | per-nameserver `tag` / `dns.tag` | Applied by Xray to direct nameserver traffic. |
| `inbound/system/dns-query/proxy` | per-nameserver `tag` | Applied by Xray to proxied nameserver traffic. |

### Generated tags

| Constructor | Shape | Kind | Selectable |
|---|---|---|---|
| `tags::node` | `node/<node-id>/out` | outbound | yes |
| `tags::chain_hop` | `chain/<chain-id>/hop<n>` | outbound | no |
| `tags::chain_terminal` | `chain/<chain-id>/terminal` | outbound (the last hop, under an alias) | yes |
| `tags::group_entry` | `group/<group-id>/entry` | `loopback` outbound | yes |
| `tags::group_balancer` | `group/<group-id>/balancer` | balancer | not an outbound |
| `tags::profile_selector` | `profile/<profile-id>/selector` | balancer | not an outbound |
| `tags::profile_socks_inbound` | `inbound/profile/<profile-id>/socks` | inbound | — |
| `tags::profile_http_inbound` | `inbound/profile/<profile-id>/http` | inbound | — |
| `tags::profile_transparent_inbound` | `inbound/profile/<profile-id>/transparent` | inbound | — |
| `tags::group_stage_rule` | `rule/group/<group-id>/stage2` | `ruleTag` | — |
| `tags::app_rule` | `rule/app/<app-rule-id>` | `ruleTag` | — |
| `tags::user_rule` | `rule/user/<routing-rule-id>` | `ruleTag` | — |
| `tags::system_rule` | `rule/system/<name>` | `ruleTag` | — |

`tags::profile_entry` (`profile/<id>/entry`) and `tags::profile_stage_rule`
(`rule/profile/<id>/stage2`) also exist in `tags.rs` but are not emitted by the
current compiler: a profile's listeners dispatch straight to its balancer through
a rule tagged `rule/profile/<id>/inbound`, so no loopback stage is needed for
profiles. Groups do need one; see below.

### Why every selectable tag ends in a fixed segment

Balancer `selector` entries are **prefix** matches. Node identifiers may
legitimately be prefixes of one another — `hk` and `hk-01` are both valid slugs —
so a selector naming `node/hk` would also capture `node/hk-01`. Ending every
selectable tag with a fixed final segment after a `/` (`/out`, `/terminal`,
`/entry`) makes the selectable tag set prefix-free.

This is not left to convention. `compile()` calls `tags::assert_prefix_safety`
over the selectable tag set on every build and returns
`CompileError::TagCollision` if a future naming change ever reintroduces the
hazard, because the consequence would be a balancer silently selecting the wrong
outbound.

## Outbound order

```text
outbounds[0] = control/block               blackhole, first, fails closed
outbounds[1] = control/direct              freedom
outbounds[2] = control/dns                 dns          (only when DNS is enabled)
             + node/<id>/out               one per compilable node, BTreeMap order
             + chain/<id>/hop0 …           one per hop, linked by dialerProxy
             + chain/<id>/terminal         the exit hop, under its alias
             + group/<id>/entry            loopback into stage two
```

Determinism comes from `BTreeMap` iteration in `DesiredState`, not from insertion
order, so the same policy always produces byte-identical JSON.

## Routing rule order

`Builder::build_rules` emits rules in exactly this order. Xray evaluates rules
top to bottom and the first match wins, so this ordering is the routing
semantics.

| # | `ruleTag` | Conditions | Target | Emitted when |
|---|---|---|---|---|
| 1a | `rule/system/dns-upstream-direct` | `inboundTag: [inbound/system/dns-query/direct]` | `outboundTag: control/direct` | DNS module enabled |
| 1b | `rule/system/dns-upstream-proxy` | `inboundTag: [inbound/system/dns-query/proxy]` | `balancerTag: profile/<default>/selector` | proxied resolvers configured |
| 2 | `rule/system/core-bypass` | `process: ["self/"]` | `outboundTag: control/direct` | always |
| 3 | `rule/system/dns-intercept` | `inboundTag: [inbound/system/tun, inbound/system/dns]`, `port: "53"`, `network: "tcp,udp"` | `outboundTag: control/dns` | DNS module enabled and at least one of those inbounds exists |
| 4 | `rule/profile/<id>/inbound` | `inboundTag:` that profile's socks/http/transparent inbounds | `balancerTag: profile/<id>/selector` | per enabled profile that has at least one listener |
| 5 | `rule/group/<id>/stage2` | `inboundTag: [group/<id>/entry]` | `balancerTag: group/<id>/balancer` | per group |
| 6 | `rule/system/private-direct` | `ip: ["geoip:private"]` | `outboundTag: control/direct` | `bypass_private_networks` and a TUN inbound exists |
| 7 | `rule/user/<id>` | the rule's own matcher | `outboundTag: control/block` | user routing rules whose action is `block`, sorted by `(priority, id)` |
| 8 | `rule/app/<id>` | `process:` the rule's matchers | per the rule's action | application rules, sorted by `(priority, id)` |
| 9 | `rule/user/<id>` | the rule's own matcher | per the rule's action | remaining user routing rules, sorted by `(priority, id)` |
| 10 | `rule/system/mode-fallback` | none, so `network: "tcp,udp"` | see below | always |

Four properties of that order are deliberate:

- **DNS upstream tags precede the self bypass.** Xray's DNS client carries no
  ordinary application inbound, so its exact per-nameserver route must win
  before the broad direct rule for the Xray process.
- **The self bypass precedes ordinary traffic.** Without it the core dials its
  own uplink through its own TUN and loops. `process: ["self/"]` is matched by
  PID against the Xray process itself.
- **Rule 7 before rule 9.** A user `block` is never overtaken by a later, broader
  proxy rule, regardless of the priority numbers the user chose.
- **Rule 10 always present.** Xray's implicit "first outbound" fallback is never
  relied on. Since `control/block` is the first outbound, relying on it would
  drop everything, and an explicit terminal rule is reviewable.

Rule 10's target depends on the system mode:

| `mode` | Rule 10 target |
|---|---|
| `off`, `direct` | `outboundTag: control/direct` |
| `global`, `rule` | `balancerTag: profile/<default>/selector`, or `outboundTag: control/direct` when no default profile is set |

An action of `default` with no default profile configured compiles to
`outboundTag: control/block` — validation rejects that combination first
(`action.no-default-profile`), and failing closed is the right answer if it ever
gets through.

Note that an action naming a group directly (`group:media` on a rule) compiles to
`balancerTag: group/media/balancer`, skipping the loopback entry; only a profile
selecting a group goes through `group/<id>/entry`.

## Profile switching

Each enabled profile compiles to a balancer:

```json
{
  "tag": "profile/web/selector",
  "selector": ["node/hk-01/out"],
  "strategy": { "type": "random" }
}
```

The selector lists the *configured* target only. Switching the profile at runtime
is one RPC:

```text
RoutingService.OverrideBalancerTarget {
  balancerTag: "profile/web/selector",
  target:      "chain/hk-us/terminal"
}
```

Properties that follow:

- **No restart.** The compiled rule table never changes at runtime, so rule order
  stays deterministic and reviewable, and connections belonging to other profiles
  are untouched.
- **Overrides are process state.** Xray does not persist them. `xraytuid`
  therefore re-applies every entry of `Compiled::selector_overrides` after each
  core start; this is an explicit step in the startup sequence, not an
  optimisation (see `docs/ARCHITECTURE.md`).
- **A core that starts before overrides are applied still routes correctly**,
  because the selector already names the saved target rather than an arbitrary
  candidate.
- **The override vocabulary is bounded.** `selectable_tags(&state)` returns every
  tag a target may resolve to, and the daemon validates a requested target
  against it before issuing the RPC. `tag_for_target` and `target_for_tag`
  convert in both directions, which is also how routing events are rendered back
  as `node:hk-01` rather than `node/hk-01/out`.
- **Read back with `GetBalancerInfo`**, which returns the override in force
  (`override_target`) and the candidates the strategy would otherwise choose
  between (`principle_targets`).

`DECISIONS.md` D-003 and `docs/UPSTREAM-COMPATIBILITY.md` describe the upstream
validation of `target` against `selector` slightly differently. xraytui does not
depend on which reading is correct: the tag set is prefix-free, the selector
names the configured target, and the daemon validates the target itself before
sending it. `cargo xtask upstream-check` is the procedure for re-confirming the
upstream behaviour.

Manual groups reuse the same mechanism. `GroupStrategy::Manual` compiles to
`strategy.type = "random"` and adds an override pinning
`group/<id>/balancer` to the selected member, so changing a group's member is a
runtime operation rather than a recompile.

Profile balancers also carry a `fallbackTag` derived from the kill switch:

| `kill_switch` | `fallback` | emitted `fallbackTag` |
|---|---|---|
| `off` | absent | none |
| `off` | present | the fallback's outbound tag |
| `fallback-only` | present | the fallback's outbound tag |
| `fallback-only` | absent | `control/block` |
| `block` | any | `control/block` |

## Groups: the loopback second stage

A balancer cannot be the target of another balancer — `outboundTag` and
`balancerTag` are mutually exclusive fields of a *rule*, and neither accepts a
balancer as an outbound. A profile therefore cannot select a group directly.

The compiler resolves this with a `loopback` outbound and a second routing pass:

```json
{
  "tag": "group/auto-hk/entry",
  "protocol": "loopback",
  "settings": { "inboundTag": "group/auto-hk/entry" }
}
```

```text
profile/web/selector   --(balancer override)-->  group/auto-hk/entry     (loopback outbound)
group/auto-hk/entry    --(rule/group/auto-hk/stage2, inboundTag)-->  balancerTag: group/auto-hk/balancer
group/auto-hk/balancer --(selector prefix)-->    node/hk-03/out
```

The loopback outbound re-injects the connection into routing carrying the given
inbound tag; the stage-two rule (position 4 in the rule table) matches that tag
and dispatches to the group's balancer. Groups thus become ordinary selectable
targets for profiles and for a chain's final hop, at the cost of one extra
routing pass per group-routed connection.

Group balancer construction:

- `selector` is the set of member target tags, sorted and deduplicated.
- An **empty** selector is rejected by Xray at load time. Rather than fail the
  whole generation and take every other profile down, the compiler seeds the
  selector with `control/block` and emits a `[group.empty]` warning, so the
  failure surfaces as "this group is blocked" instead of "the core will not
  start".
- `strategy.type` comes from `GroupStrategy::xray_strategy()`: `manual` and
  `random` both map to `random`, plus `roundRobin`, `leastPing`, `leastLoad`.
- `fallbackTag` is emitted only when the user configured one. A synthesised
  fallback would silently switch on active probing.

## Chains: `sockopt.dialerProxy`

A chain hop is compiled as a **clone** of the node's outbound under a chain-owned
tag, so a node used in two chains is never mutated by either and node definitions
stay immutable.

For a chain `hk-us` with hops `[a, b, c]` in traffic order, expressing
`Local -> A -> B -> C -> Internet`:

| Outbound tag | Built from | `streamSettings.sockopt.dialerProxy` |
|---|---|---|
| `chain/hk-us/hop0` | node `a` | absent |
| `chain/hk-us/hop1` | node `b` | `chain/hk-us/hop0` |
| `chain/hk-us/terminal` | node `c` | `chain/hk-us/hop1` |

Routing points at `chain/hk-us/terminal`. Read outwards, it says: C dials through
B, which dials through A. The terminal is an alias for the last hop rather than
an extra outbound, so a chain costs exactly as many outbounds as it has hops.
Each hop keeps its own transport and TLS/REALITY settings intact; the deprecated
`proxySettings.tag` form is not used.

Chain validation (`DesiredState::validate_chain`) rejects, before compilation:

| Error | Condition |
|---|---|
| `TooShort` | fewer than two hops |
| `MissingHop` | a hop references a node that does not exist |
| `RepeatedHop` | the same node appears twice, which loops traffic |
| `UdpBreak` | a non-terminal hop cannot carry UDP, so UDP breaks for later hops |
| `UnusableHop` | a hop is disabled, or its protocol cannot be compiled |

Separately, `outbound::build` refuses to attach a `dialerProxy` to a protocol
that does not accept stream settings. WireGuard carries all transport state in
its protocol settings and has nowhere to hang one, so it cannot be used where a
chain edge would be discarded. Xray-native Hysteria is different: the current
core represents it as protocol settings (`version`, address, port) plus
`streamSettings.network = "hysteria"`, `hysteriaSettings` and TLS; its sockopt
therefore carries `dialerProxy`. The generated Hysteria shape is validated on
stable and preview Xray. A real multi-hop Hysteria network-path test has not yet
been executed, so documentation does not promote that combination beyond
config-compatibility evidence.

## Share-link fields and compiled Xray fields

The normalized node model is shared by import, export, identity and compilation;
there is no second reduced "share model." Important mappings include:

| Ecosystem field | Typed model | Xray JSON |
|---|---|---|
| `type=xhttp`, `host`, `path`, `mode`, `extra` | `Transport::Xhttp` | `streamSettings.xhttpSettings` |
| `security=reality`, `sni`, `fp`, `pbk`, `sid`, `spx`, `pqv` | `RealitySettings` | `realitySettings.serverName`, `fingerprint`, `publicKey`, `shortId`, `spiderX`, `mldsa65Verify` |
| `ech`, `pcs`, `vcn`, ALPN | `TlsSettings` | `echConfigList`, `pinnedPeerCertSha256`, `verifyPeerCertByName`, `alpn` |
| `fm` | `Node.finalmask` | `streamSettings.finalmask` |
| mKCP `headerType`, `seed`, `mtu`, `tti` | `MkcpTransport` | current `finalmask.udp` masks plus `kcpSettings.mtu/tti` |
| Hysteria `obfs-password`, `mport` | `HysteriaSettings` | salamander UDP mask and `finalmask.quicParams.udpHop` |

Export is permitted only if every connection-critical modeled field has a common
dialect representation, unless the user explicitly chooses a lossy export.
Compiler support alone is not treated as evidence that a URI field exists. See
`docs/SHARING.md` for the full matrix.

The `exported_vless_reality_vision_reimports_and_carries_a_real_connection`
acceptance test starts a synthetic TLS camouflage target, a VLESS REALITY server,
and the compiled client as separate official Xray processes. It uses the
QR-decoded re-imported node and observes a loopback egress banner. This has been
run with stable v26.3.27 and preview v26.7.28; it is stronger than JSON
validation alone.

## Upstream constraints the compiler works around

### 1. A rule must have at least one condition

Xray rejects a rule with no effective fields at load time
(`app/router/config.go`, "this rule has no effective fields"). A genuine
catch-all therefore cannot be expressed as an empty rule.

After building the rule list, the compiler makes a final pass and sets
`network: "tcp,udp"` on every rule that is still condition-free — the broadest
condition Xray accepts. This applies to `rule/system/mode-fallback` and to any
user rule written with an empty matcher.

### 2. `fallbackTag` requires a liveness feature

`RandomStrategy::InjectContext` and `RoundRobinStrategy::InjectContext` call
`core.RequireFeatures(observatory)` whenever the fallback tag is non-empty, and
`leastPing`/`leastLoad` require it unconditionally. Emitting a `fallbackTag`
without an `observatory` or `burstObservatory` block makes the core refuse to
start with **"not all dependencies are resolved"**.

The compiler therefore keeps the two in lockstep:

| Trigger | Subject added to |
|---|---|
| group strategy `leastPing` | `observatory.subjectSelector` |
| group strategy `leastLoad` | `burstObservatory.subjectSelector` |
| a group has a user-configured `fallback` | `observatory.subjectSelector` |
| a profile acquires a `fallbackTag` from its kill switch or fallback | `observatory.subjectSelector` |

Neither block is emitted when its subject set is empty, so the common case —
`kill_switch = "off"` with no fallback — stays entirely probe-free. `control/`
and `group/` tags are filtered out of both selectors, because a blackhole, a
freedom outbound and a loopback are not meaningful probe subjects. Probe URL and
interval come from `CompileOptions` (defaults
`https://www.gstatic.com/generate_204`, `5m`).

The daemon's own health probing is separate and is preferred where possible: it
measures the usable path through the profile's real listener, which is both
cheaper and more accurate than the in-core observatory (`DECISIONS.md` D-013).

### 3. mKCP `header` and `seed` were replaced by `finalmask`

The pinned release removed `kcpSettings.header` and `kcpSettings.seed` and
refuses any configuration that still sets them. Share links, however, still carry
`headerType` and `seed`, so the compiler translates them into the replacement
mask list: an empty `kcpSettings` object plus `streamSettings.finalmask` with UDP
masks.

| Share-link `headerType` | Emitted mask |
|---|---|
| `srtp` | `header-srtp` |
| `utp` | `header-utp` |
| `wechat-video`, `wechat` | `header-wechat` |
| `dtls` | `header-dtls` |
| `wireguard` | `header-wireguard` |
| `dns` | `header-dns` |
| `none`, or anything the pinned release does not register | no header mask |

Exactly one trailing mask is always appended: `mkcp-aes128gcm` with
`{"password": "<seed>"}` when the link carried a seed, otherwise
`mkcp-original`.

## Inspecting the generated JSON

The compiled document is a build artifact, not configuration. TOML is the source
of truth; nothing reads the generated JSON back as policy.

| File | Contents |
|---|---|
| `$XDG_RUNTIME_DIR/xraytui/generated-xray.json` | The generation currently applied, mode 0600. |
| `$XDG_RUNTIME_DIR/xraytui/last-good-xray.json` | The last generation that started, probed and accepted its overrides. |

Both contain node credentials in cleartext. Never attach either to a bug report.
There is not yet an automatic diagnostic-bundle exporter; use `xraytui doctor`,
`xraytui status` and only manually reviewed runtime-log excerpts.

```sh
CFG="$XDG_RUNTIME_DIR/xraytui/generated-xray.json"

jq '[.outbounds[] | {tag, protocol}]' "$CFG"                  # what exists, in emission order
jq '[.routing.rules[] | {ruleTag, outboundTag, balancerTag}]' "$CFG"   # the rule table, in order
jq '.routing.balancers' "$CFG"                                # selectors, strategies, fallbacks
jq '.observatory, .burstObservatory' "$CFG"                   # who is being probed by the core
xray run -test -config "$CFG"                                 # what the core thinks of it
```

Against a running core, `xraytui doctor` reports the commander capabilities and
compares the core's live outbound and rule tags with the generation's
`owned_tags`, which is how a stale or foreign object is detected. Rule-level
"why did this connection go there" questions are answered by `TestRoute`, which
simulates a routing decision without dialling anything and without publishing the
result to the routing event stream.
