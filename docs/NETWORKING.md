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

Defaults come from `[tun]` in `config.toml`:

| Resource | Default | Configured by |
|---|---|---|
| Interface name | `xraytui0` | `tun.name`, constrained to `^xraytui[0-9a-z]{0,8}$` |
| IPv4 address | `198.18.0.1/15` | `tun.ipv4_address` |
| IPv6 address | `fdfe:dcba:9876::1/126` | `tun.ipv6_address` |
| MTU | `1500` | `tun.mtu` |
| Routing table id | `29281` (`0x7261`) | `tun.route_table` |
| Firewall mark | `29281` (`0x7261`) | `tun.fwmark` |
| Policy rule priority | `17000` | `tun.rule_priority` |

The interface-name pattern is a security control, not a style rule: netd derives
ownership decisions from the name, so it must be impossible for a name to contain
a shell metacharacter, a `/`, or an unexpected prefix. Ownership itself is
established by `TUNSETOWNER` against the credential uid — netd will not adopt a
device it does not own.

### Conflict detection

Routing table ids and firewall marks come from a documented reserved range and
are **probed for conflict before use**. If the table already contains routes, or
a policy rule at the chosen priority exists and was not created by xraytui, setup
**fails with a clear error rather than overwriting**. The same applies to the
nftables table. An administrator's routing policy is never silently replaced.

`xraytui tun plan` prints the exact set of intended changes — device, addresses,
routes, rules, marks, nft objects, DNS changes — before any of them are made.
Reading that output is the cheapest way to find a conflict.

### Ownership marking

| Object | Naming or marking |
|---|---|
| nftables table | `table inet xraytui` — the only table ever created or flushed |
| nftables chains | `xraytui-u<uid>` |
| nftables and routing rules | comment `xraytui:<uid>:<gen>` |
| Routing table id | allocated from the reserved range as `base + uid_slot` |
| cgroup | under `/sys/fs/cgroup/xraytui.slice` |

Other nftables tables are never read into a generated ruleset and never flushed.
The generated ruleset is applied atomically through `nft -f -` on stdin, with
`--check` first; that is the only external binary in the privileged path, invoked
by absolute path with a fixed argument vector and a ruleset built exclusively
from validated typed values. Routes, rules, links and addresses are programmed
over **netlink**, not by shelling out to `ip(8)`.

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

### 3. cgroup v2 exact-instance routing

`xraytui exec --transparent` classifies a single process tree into a project
cgroup, which nftables matches with `socket cgroupv2`, marks with the project
fwmark, and policy-routes into that profile's transparent inbound.

- **Exact per instance**: two processes running the same executable can take
  different profiles, which neither of the other mechanisms can express.
- Requires netd and cgroup v2.
- PID reuse is handled without a race: the launcher creates the child **stopped**
  and opens a `pidfd` for it, then passes the `pidfd` over `SCM_RIGHTS`. netd
  resolves identity from the pidfd alone, verifies the uid against the peer
  credential, writes the pid into `cgroup.procs`, and only then does the launcher
  let the child continue. A recycled PID cannot be reached through a stale
  pidfd.

### Choosing between them

| Requirement | Mechanism |
|---|---|
| One specific command, right now, no privileges | 2 (`exec --profile`) |
| Two instances of the same program on different profiles | 3 (`exec --transparent`) |
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
