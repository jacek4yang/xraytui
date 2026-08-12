# Manual recovery

What to do if xraytui dies leaving the host's networking modified.

**As of this writing xraytui does not modify host networking at all** — the
privileged helper is not implemented, so nothing below can currently have
happened. This document describes the recovery procedure for the state the helper
*will* create, and is the contract that implementation has to satisfy: every
resource must be identifiable and removable by hand.

## Everything xraytui may own

Nothing outside this list is ever created, and nothing outside it should ever be
removed in xraytui's name.

| Resource | Name | Default |
|---|---|---|
| TUN interface | `xraytui<uid-derived>` | `xraytui0` |
| routing table | reserved id | `0x7261` (29281) + uid slot |
| policy rule priority | reserved | from 17000 |
| firewall mark | reserved | `0x72610000` + uid slot |
| nftables table | `inet xraytui` | one table, never another |
| cgroup | `/sys/fs/cgroup/xraytui.slice/u<uid>/<profile>` | |
| recovery state | `/run/xraytui/state/` | root-only, no credentials |

Every rule the helper installs carries a comment of the form
`xraytui:<uid>:<generation>`.

## The supported way

```sh
sudo xraytui-netd --recover --once
```

Removes project-owned state whose lease has expired, and nothing else. Safe to
run at any time.

## By hand, in order

Work top-down; each step is independent and idempotent.

### 1. See what is there

```sh
ip -details link show type tun | grep -A3 xraytui
ip rule show | grep -E 'lookup (29281|2928[2-9]|293[0-9][0-9])'
ip route show table 29281
ip -6 route show table 29281
sudo nft list table inet xraytui
ls /sys/fs/cgroup/xraytui.slice 2>/dev/null
resolvectl status | sed -n '/xraytui/,+6p'
```

### 2. Remove the policy rules

Do this **first**: while the rules exist, traffic is directed at a table whose
routes you are about to delete.

```sh
sudo ip rule del priority 17000 2>/dev/null || true
sudo ip -6 rule del priority 17000 2>/dev/null || true
```

Check `ip rule show` again; repeat for any remaining priority in the 17000 range
that names an xraytui table.

### 3. Flush the routing table

```sh
sudo ip route flush table 29281
sudo ip -6 route flush table 29281
```

Substitute your own table id if `[tun] route_table` was changed.

### 4. Remove the firewall table

```sh
sudo nft delete table inet xraytui
```

This removes **only** xraytui's table. Never `nft flush ruleset` — that would
destroy your firewall, and xraytui never does it.

### 5. Remove the TUN device

```sh
sudo ip link set xraytui0 down
sudo ip link delete xraytui0
```

A persistent device survives the process that created it, which is exactly why it
has to be deleted explicitly.

### 6. Restore DNS

```sh
# systemd-resolved
sudo resolvectl revert xraytui0                 # if the link still exists
resolvectl status                               # confirm your real link is back

# resolvconf
sudo resolvconf -d xraytui0
```

If `/etc/resolv.conf` was edited by the `manual` backend — which requires an
explicit confirmation to enable — restore it from
`/run/xraytui/state/resolv.conf.saved`.

### 7. Remove the cgroups

```sh
sudo find /sys/fs/cgroup/xraytui.slice -depth -type d -exec rmdir {} + 2>/dev/null
```

`rmdir` fails on a non-empty cgroup, which is the desired behaviour: a live
process is still classified there.

### 8. Clear the recovery state

```sh
sudo rm -rf /run/xraytui/state
```

### 9. Verify

```sh
ip rule show | grep -c xraytui        # expect 0
ip link show | grep -c xraytui        # expect 0
sudo nft list tables | grep -c xraytui # expect 0
ping -c1 1.1.1.1                       # expect normal connectivity
resolvectl query example.com           # expect normal resolution
```

## If you are locked out of the network

`failure_policy = "block"` keeps a kill switch in place deliberately, so that
traffic cannot silently fall back to unproxied. Steps 2 and 4 above remove it.
The one-liner:

```sh
sudo nft delete table inet xraytui && sudo ip rule del priority 17000
```

## Preventing it

* `failure_policy = "restore"` is the default and is what you want on a laptop.
* `xraytui tun plan` prints every intended change before any is made.
* The helper's lease means an unclean daemon exit is cleaned up automatically
  once the TTL expires; `[runtime] netd_lease_ttl_secs` controls how long that
  takes.
