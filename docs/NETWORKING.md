# Networking

Everything in this document concerns state that lives in the kernel rather than
in a configuration file: TUN devices, addresses, routes, policy rules, firewall
marks, nftables and cgroups. All of it is applied by `xraytui-netd`, the only
privileged component, and all of it is namespaced and tagged so that ownership is
provable.

If xraytui has already died and left something behind, go to `docs/RECOVERY.md`,
which lists the exact inspection and removal commands.

## Why a privileged helper exists at all

Upstream Xray's TUN inbound accepts only `{name, MTU, userLevel}`; `port` and
`listen` are ignored, and upstream states plainly that enabling the feature
brings the interface up and does nothing else. Addresses, routes, policy rules
and DNS are therefore entirely xraytui's responsibility. That work needs
`CAP_NET_ADMIN`, and giving it to a terminal application, a daemon that parses
subscriptions, or the core itself would be indefensible.

`xraytui-netd` runs as a system service with
`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE`, no shell,
and an IPC surface that is a closed enum of typed operations. There is no setuid
binary. Everything the helper can do is enumerable by reading one Rust enum in
`crates/netd-protocol`.

| Property | Value |
|---|---|
| Socket | `/run/xraytui/netd.sock`, mode 0660, group `xraytui` |
| Authentication | `SO_PEERCRED` on accept; the credential uid is the only identity used |
| Frame cap | 256 KiB, checked before allocation |
| Recovery state | `/run/xraytui/state/`, mode 0700, owned by root, written by atomic rename |
| Never does | parse subscriptions, perform network I/O, see node credentials, invoke a shell |

Membership of the `xraytui` group is the administrator's explicit grant. A user
in that group can create TUN devices and project-owned routes **for their own
uid**; that is the intended authority and it is equivalent to what the
administrator authorised.

The PID returned by `SO_PEERCRED` is used only for logging, never for
authorisation, because PIDs are reusable.

## TUN privilege separation

The task specification originally called for passing a TUN file descriptor to
Xray over `SCM_RIGHTS`. **Upstream Linux Xray cannot consume a passed
descriptor.** `proxy/tun/tun_linux.go` opens `/dev/net/tun` and issues `TUNSETIFF`
itself; the `xray.tun.fd` environment flag (`common/platform.TunFdKey`) is
consumed only by the Android and Darwin implementations. This is recorded as
`DECISIONS.md` D-008 and as fallback implementation 1 in
`docs/UPSTREAM-COMPATIBILITY.md`.

The design that replaces it:

```text
1. xraytuid asks netd for a TUN, by name, addresses, MTU and generation.
2. netd opens /dev/net/tun, TUNSETIFF, then:
     TUNSETPERSIST  — the device survives the creating process exiting
     TUNSETOWNER    — ownership is assigned to the *credential* uid of the caller
3. netd configures addresses, MTU and link state over netlink.
4. netd returns the tun fd over SCM_RIGHTS.
5. xraytuid holds that fd. It is a liveness handle and proof of ownership,
   not the data path.
6. The unprivileged xray process attaches to the already-existing, already-
   configured device by name.
```

Two consequences follow, and neither is assumed:

- Xray needs no `CAP_NET_ADMIN` in the common case **if** the kernel permits the
  device's owner to attach and Xray's `LinkSetMTU`/`LinkSetUp` calls succeed on an
  already-configured link. Whether that holds is **verified at runtime**, not
  taken on faith.
- When the attach path fails, `xraytui doctor` reports it and TUN mode is
  **refused**. Privileges are never escalated silently to make it work.

The documented alternative is `CoreLaunchTun`: netd executes the core itself with
ambient `CAP_NET_ADMIN` under the caller's uid. It is **opt-in**, because it
widens netd's mandate from "configure the network" to "start a process", and it
must be requested explicitly rather than reached by fallback.

Xray's TUN has no ICMP support and reports connect success optimistically, which
is why health checks are always L4 or L7 through an outbound and never a ping.

## Routes, policy rules, marks and table reservation

Some of these are configured and some are **derived from the credential uid**.
The distinction matters: anything derived cannot be influenced by what a user
writes in their own configuration file, which is what stops one user from
addressing another's resources.

| Resource | Default | Where it comes from |
|---|---|---|
| Interface name | `xraytui<uid>` | **derived**; `tun.name` is advisory and the daemon says so once if they differ |
| IPv4 address | `198.18.0.1/15` | `tun.ipv4_address` |
| IPv6 address | `fdfe:dcba:9876::1/126` | `tun.ipv6_address` |
| MTU | `1500` | `tun.mtu` |
| Routing table id | `0x7261 + (uid mod 64)` | **derived**; `tun.route_table` is advisory |
| Firewall mark | `0x72610000 + (uid mod 4096)` | **derived**; `tun.fwmark` is advisory |
| Policy rule priority | `17000 + (uid mod 64)` | **derived**; `tun.rule_priority` is advisory |

The interface-name pattern is a security control, not a style rule: the helper
derives ownership decisions from the name, so it must be impossible for a name to
contain a shell metacharacter, a `/`, or an unexpected prefix. Ownership itself is
established by `TUNSETOWNER` against the credential uid, so the unprivileged core
can open the device and nobody else can.

### Ownership marking

Cleanup is only safe if "this is ours" is decidable without a state file, because
the state file is exactly what is missing after a crash. Every object therefore
carries a marker the kernel itself maintains:

| Object | Marker |
|---|---|
| Routes | `rtm_protocol = 114`, a value unassigned in `rtnetlink.h` and in iproute2's `rt_protos` |
| Policy rules | the same protocol number, in `FRA_PROTOCOL` |
| Interfaces | the `xraytui` name prefix |
| nftables table | `table inet xraytui` — the only table ever created, flushed or deleted |
| nftables chains | `u<uid>-mark` and `u<uid>-guard` |
| cgroups | under `/sys/fs/cgroup/xraytui.slice/u<uid>/` |

**Only objects carrying a marker are ever removed.** A route added to the same
table by an administrator, a VPN client or a routing daemon has a different
protocol number and is invisible to every cleanup path here. That is asserted by
a test — `state_this_project_did_not_create_is_left_alone` in
`crates/linux-net/tests/netns.rs` puts a `proto static` route and a foreign
policy rule in place, runs a full teardown, and checks that both survive.

The helper does **not** refuse to start when it finds a table already in use,
because with per-uid table ids the only thing it would be refusing is its own
previous run. It reconciles instead: it removes what it owns and leaves the rest.

`xraytui tun plan` prints the exact set of intended changes — device, addresses,
routes, rules, marks, the nftables ruleset verbatim, DNS changes — before any of
them are made. It works whether or not a helper is installed: with one, the plan
is the helper's own account of what it would do; without one, the daemon renders
it from the same functions and says so. Reading that output is the cheapest way
to find a conflict.

### What is inside the table

One table per user holds the tunnel's routes, and traffic reaches it through a
single policy rule matching the user's firewall mark. Inside:

* the `include` prefixes — or the default route, when none are given — point at
  the tunnel;
* the `exclude` prefixes, the configured proxy endpoints, and (when
  `bypass_private_networks` is set) RFC 1918, RFC 4193, link-local, loopback and
  multicast space become **`throw`** routes, which abandon the table and let the
  next rule take over, i.e. the machine's ordinary routing.

`throw` is used rather than copying the main table's routes because a copy goes
stale the moment the physical link changes. The proxy endpoints matter most:
without those host routes the core's own connection to its proxy would be routed
into the tunnel the core is providing — a loop that presents as "the tunnel comes
up and nothing works".

### nftables

The ruleset is applied as one transaction: checked with `nft -c -f -`, then
committed with `nft -f -`. Both read the ruleset from standard input with a fixed
argument vector, and both run a program resolved against a fixed search path
rather than the ambient `PATH`. There is no shell anywhere in the privileged
path, which `xtask/tests/no_shell.rs` asserts against the source.

The ruleset is nftables' own syntax rather than libnftables JSON, because the
JSON parser cannot express `socket cgroupv2` — see `DECISIONS.md` D-015. Every
value that becomes part of the text passes a gate accepting only `[a-z0-9._/-]`;
a value outside that set is refused and no ruleset is produced at all.

Routes, rules, links and addresses are programmed over **netlink**, not by
shelling out to `ip(8)`.

## Failure policy: restore or block

`runtime.failure_policy` decides what the machine does when the daemon or core
dies while TUN is active. There is no correct default for every operator, so the
choice is explicit.

| Policy | Behaviour on failure | Suits |
|---|---|---|
| `restore` (default) | Remove project routes, rules and the `inet xraytui` table; restore the previous DNS state; delete the TUN device. The machine returns to unproxied connectivity. | Workstations where losing connectivity is worse than losing proxying. |
| `block` | Keep a minimal kill-switch nft chain that drops non-loopback, non-bypass traffic, and keep it until an authenticated client clears it. | Hosts where traffic must never leave unproxied, even briefly. |

`block` is a deliberate denial of service against your own machine. It is the
right answer when unproxied egress is unacceptable, and the wrong answer if you
might be locked out of a remote host. `docs/RECOVERY.md` explains how to clear it
by hand.

Note the separate, per-profile `kill_switch` setting, which is a routing-level
control compiled into the core's balancer `fallbackTag`. The two are independent:
`kill_switch` decides where a profile's traffic goes when its target is
unhealthy; `failure_policy` decides what happens to the host when xraytui itself
is gone.

## Lease-based crash cleanup

netd never trusts a client to tell it when to clean up, because a SIGKILLed
client cannot.

```text
xraytuid  --RequestTun(gen)-->  netd   creates a lease for that generation
xraytuid  --Heartbeat-------->  netd   refreshes the lease
   (xraytuid dies)
                                netd   lease expires after runtime.netd_lease_ttl_secs
                                netd   applies the generation's recorded failure_policy
```

| Property | Value |
|---|---|
| Lease scope | one generation |
| Default TTL | 30 seconds (`runtime.netd_lease_ttl_secs`) |
| Refresh | heartbeat from `xraytuid` |
| On expiry | apply the recorded `failure_policy` for that generation |
| Durable record | `/run/xraytui/state/`, 0700 root, atomic rename, never credentials |

Because the recovery record is durable, a netd restart reconciles rather than
forgets: on start-up it compares the recorded generations against what is
actually in the kernel and removes or completes as required. The same
reconciliation is available on demand through `xraytui doctor --repair` and
`xraytui-netd --recover`.

Release builds use `panic = "abort"`, so a corrupted daemon cannot continue with
half-applied network state; it dies, and the lease then does its job.

## Per-application routing

There are three mechanisms with genuinely different guarantees. The UI and CLI
always state which one produced a decision, and a fall back from a stronger
mechanism to a weaker one is reported, never silent.

### 1. Native process routing (Xray's `process` matcher)

Used in TUN modes. Compiles the user's matchers into a routing rule's `process`
list, which Xray demultiplexes by shape:

| Matcher shape | Matched against |
|---|---|
| `firefox` — no `/` | process **name**; a trailing `.exe` is stripped |
| `/usr/lib/firefox/firefox` — contains `/` | absolute **executable path** |
| `/usr/bin/` — trailing `/` | **directory prefix** of the executable path |
| `self/` | the Xray process itself, by PID — this is what rule 1 of the generated table uses for loop prevention |
| `xray/` | replaced at load time with Xray's own `os.Executable()` |

Limitations, stated plainly:

- It matches **the process that owns the socket**. For a browser that is usually
  a network or content helper process, not the binary you launched, so a matcher
  for `firefox` may match nothing while traffic silently takes the fallback
  route. The Applications page resolves and displays the *actual* executable
  paths of running processes matching your literal matcher, and marks matchers
  that currently match nothing.
- Flatpak, Snap and wrapper scripts change the executable path from what you
  would expect.
- Matching requires a local source address. When the peer is not local the
  matcher returns "no match" rather than an error.
- It is a routing convenience, **not a sandbox**. An uncooperative local process
  can defeat it.

### 2. Dedicated local listeners

Each profile can own one SOCKS5 and one HTTP CONNECT listener, bound to loopback.
`xraytui exec --profile P -- cmd` runs a program with the corresponding proxy
environment variables injected.

- **Exact**: the process you launched, and nothing else, uses that profile.
- **Unprivileged**: no netd, no TUN, no capabilities, works on any machine.
- **Limited**: honoured only by programs that read proxy environment variables or
  are configured to use a proxy. A statically configured program that ignores
  them is unaffected.

Listeners bind `127.0.0.1` by default. `lan_access = true` requires
`lan_access_acknowledged = true` and forces authentication credentials to be set;
while any non-loopback listener is bound the TUI shows a banner and
`xraytui doctor` reports it as a finding. Traffic arriving on a profile's own
listener is dispatched to that profile by rule 3 of the generated table,
**whatever the application rules say**.

### 3. cgroup v2 exact-instance routing — **partly implemented**

`xraytui exec --transparent` is intended to classify a single process tree into a
project cgroup, which nftables matches with `socket cgroupv2`, marks with the
profile's fwmark, and policy-routes into that profile's transparent inbound.

What is implemented and proven in a namespace:

- the cgroup is created under `/sys/fs/cgroup/xraytui.slice/u<uid>/<profile>`;
- a process is placed in it by `pidfd`, never by pid. The launcher opens a
  `pidfd` and passes it over `SCM_RIGHTS`; the helper resolves identity from the
  descriptor alone, checks the owner against the peer credential, and writes the
  pid into `cgroup.procs`. Holding the descriptor pins the identity, so a
  recycled pid cannot be reached through a stale one;
- nftables marks exactly that cgroup's traffic, and accepts the core's own
  cgroup unmarked first so the core's uplink never enters its own tunnel.

What is **not** implemented: the last link. One user has one routing table and
one tunnel, so today the mark decides *whether* an application's traffic enters
the tunnel, not *which exit* it takes. Selecting an exit per profile needs a
`tproxy` inbound per profile and a policy rule per mark; the tag namespace
reserves `inbound/profile/{id}/transparent` for it. Until then
`exec --transparent` refuses with a typed reason rather than silently behaving
like `exec --profile`. See `STATUS.md`.

### Choosing between them

| Requirement | Mechanism |
|---|---|
| One specific command, right now, no privileges | 2 (`exec --profile`) |
| Two instances of the same program on different profiles | 3 (`exec --transparent`) — **not yet available**; see above |
| Everything a named program does, system-wide, including children you did not launch | 1 (process matcher, with the caveats above) |
| A program that ignores proxy environment variables | 1 or 3 |

## What is never done

- No packet capture. The routing event stream subscribes to metadata field
  selectors only — inbound tag, network, ip, port, domain, protocol, outbound tag
  — and no payload is ever read.
- No TLS interception, no CA generation, no CA installation.
- Traffic sniffing for routing is **disabled by default** (`core.sniffing =
  false`), because it inspects the first bytes of a connection to recover a
  destination name. When enabled it can be restricted to route-only, so a sniffed
  name informs routing but never rewrites the destination.
- No `sh -c` anywhere in the codebase; a test enforces this.

## Manual recovery, in short

Full commands are in `docs/RECOVERY.md`. The short version, in order:

1. `xraytui doctor --repair` — reconcile through the running helper.
2. `xraytui-netd --recover` — reconcile when the daemon is gone but the helper is
   present.
3. By hand: delete the `xraytui*` link, delete the policy rule at priority
   `17000`, flush and delete `table inet xraytui`, then restore DNS. Only ever
   touch objects carrying the project's name, mark, table id or
   `xraytui:<uid>:<gen>` comment.
