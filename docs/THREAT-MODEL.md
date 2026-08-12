# Threat model

Written before `xraytui-netd` was implemented; updated as the helper's operation
set changed. Scope: a single Linux workstation or server administered by the person
running xraytui.

## What xraytui is

A local network-administration client. It manages the operator's own outbound
traffic, supervises an Xray-core process, exposes loopback proxy listeners,
optionally creates a project-owned TUN device with policy routing, and measures
connectivity through endpoints the operator configured.

## What xraytui is deliberately not

No vulnerability exploitation, credential theft, phishing, malware delivery,
evasive persistence, unauthorised interception, brute forcing, denial of service,
or host scanning. No TLS interception, no CA installation, no payload capture, no
anti-forensics, no hiding from the machine's administrator. Subscription payloads
are passive configuration and are never executed. No telemetry leaves the machine.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Node credentials (UUIDs, passwords, PSKs, REALITY private material) | `~/.config/xraytui/secrets.toml` (0600), compiled Xray JSON in `$XDG_RUNTIME_DIR` (0600) | grants proxy access, often reusable |
| Subscription URLs | `subscriptions.toml` (0600) | usually contain a bearer token in the path or query |
| Xray gRPC API endpoint | loopback port recorded in `$XDG_RUNTIME_DIR/xraytui/xray-api.json` (0600) | full control of the data plane |
| Daemon control socket | `$XDG_RUNTIME_DIR/xraytui/control.sock` inside a 0700 directory | full control of the user's proxy state |
| netd socket | `/run/xraytui/netd.sock` (0660, group `xraytui`) | privileged network operations |
| Host routing/DNS/nftables state | kernel | breaking it takes the machine off the network |

## Trust boundaries

```
 remote subscription server ─┐          (untrusted bytes)
 proxy endpoints ────────────┤
                             v
 user ──> xraytui (TUI/CLI) ──IPC──> xraytuid ──gRPC──> xray  (same UID)
                                        │
                                        └──IPC(SO_PEERCRED)──> xraytui-netd (root, caps)
```

* **user ↔ xraytuid**: same UID. Not a security boundary; it is an availability and
  correctness boundary. Socket lives in a 0700 directory in `XDG_RUNTIME_DIR`.
* **xraytuid ↔ xraytui-netd**: a real privilege boundary. Everything crossing it is
  a typed, validated, allowlisted operation.
* **xraytuid ↔ xray**: same UID, loopback gRPC. Not a privilege boundary, but the
  API port is an asset (see *local multi-user*).
* **network ↔ parsers**: the hostile boundary. Subscription bodies, share links,
  QR payloads and Xray JSON imports are attacker-influenced.

## Threats and mitigations

### T1 — Local multi-user: another account controls the data plane

*Risk.* Any local user who can reach the Xray gRPC port gets full outbound control
and can read the traffic statistics of the xraytui user.

*Mitigations.* API bound to `127.0.0.1` on an ephemeral port chosen by binding
port 0 and reading back the assignment; the port file is 0600; the control socket
directory is 0700; `xraytui doctor` warns that **loopback TCP has no per-user
access control on Linux** and documents the residual risk. On systems with other
untrusted local users, the recommended configuration is `[core] api_transport =
"unix"` which places the commander on a 0600 Unix socket instead
(`listen: "/run/user/<uid>/xraytui/xray-api.sock"`). This is the default whenever
the running Xray version accepts a Unix-domain `api.listen` value.

### T2 — Unix socket spoofing / confused deputy at the privilege boundary

*Risk.* A hostile local process connects to `netd.sock` and asks for routes or a
TUN for another user.

*Mitigations.* `SO_PEERCRED` on accept yields `(pid, uid, gid)`. All resources are
derived from the **credential UID**, never from a UID field in the message. Names
are generated (`xraytui<uid>` links, `xraytui-u<uid>` nft chains, table id
`base + uid_slot`) so one user cannot name another user's objects. The socket is
`0660 root:xraytui`; membership in `xraytui` is the administrator's explicit grant.
PID from `SO_PEERCRED` is used only for logging, never for authorisation, because
PIDs are reusable.

### T3 — PID reuse in the cgroup exec path

*Risk.* `exec --transparent` asks netd to move "pid N" into a cgroup; N exits and
is recycled into a privileged process before netd acts.

*Mitigations.* The user-side launcher creates the child **stopped** and opens a
`pidfd` for it, then passes the `pidfd` over `SCM_RIGHTS`. netd resolves identity
from the pidfd only (`/proc/self/fdinfo` → `Pid:`, then
`/proc/<pid>` opened via that same pidfd's procfd where available), verifies
`Uid:` matches the peer credential, writes the pid into
`cgroup.procs`, and only then does the launcher continue the child. A recycled PID
cannot be reached through a stale pidfd — the pidfd refers to the original task and
`pidfd_send_signal`/`pidfd_getfd` fail with `ESRCH`.

### T4 — Command injection through the helper

*Risk.* Node names, interface names, domains or rule text reach a shell.

*Mitigations.* No `sh -c` anywhere in shipping code, enforced by
`xtask/tests/no_shell.rs`, which also asserts that every external program the
privileged backend runs goes through one resolver and that `unsafe` stays in the
single module that needs it. Routes, rules, links and addresses are programmed
over **netlink**, not `ip(8)`. nftables changes are applied as one ruleset,
checked with `nft -c -f -` and then committed with `nft -f -` — both with a fixed
argument vector, both reading the ruleset from stdin, and both invoked at an
absolute path resolved against a fixed search directory list rather than the
ambient `PATH` (`DECISIONS.md` D-016).

The ruleset is nftables syntax rather than libnftables JSON, because the JSON
parser cannot express `socket cgroupv2` — see `DECISIONS.md` D-015 and
`docs/UPSTREAM-COMPATIBILITY.md`. What replaces "no syntax anywhere" is a checked
property rather than an assumed one: every value that becomes part of the text
passes a gate accepting only `[a-z0-9._/-]`, which contains no quote, brace,
semicolon, backslash, newline or space. A value outside the set is refused and
**no ruleset is produced at all**. The values themselves are already
constrained upstream of the gate: interface names by `^xraytui[0-9a-z]{0,8}$`,
profile names by the protocol's slug validator, marks and table ids by reserved
integer ranges, and prefixes by `ipnet` types.

DNS uses D-Bus (`org.freedesktop.resolve1`) through a client written for the four
calls it makes, not `resolvectl(8)`, and not a general-purpose D-Bus crate that
would enlarge the privileged dependency set.

### T5 — Malicious subscription content

*Risk.* Multi-gigabyte body, decompression bomb, billion-laughs base64, 10^6 nodes,
crafted URI that panics a parser, redirect to `file://` or to a LAN address.

*Mitigations.* Response body capped (`max_response_bytes`, default 8 MiB) with a
streaming counter, not `Content-Length` trust. Node count capped
(`max_nodes`, default 10 000). Redirects capped at 5, downgrade to plain HTTP
refused, non-HTTP(S) schemes refused. Request timeout and total-deadline. TLS
validation is always on; there is no "insecure" switch for subscription fetches.
Every parser returns `Result` with a bounded error; `#![forbid(unsafe_code)]` plus
`deny(clippy::indexing_slicing)` in `import`; proptest and fuzz targets assert
no panic, no unbounded allocation, and termination on arbitrary bytes.
Subscription content is **never executed** and never becomes a file path.

### T6 — Path traversal and symlink attacks

*Risk.* `--file`, `--png`, geodata paths, or a node name used in a filename escapes
its directory or follows a symlink into something privileged.

*Mitigations.* All project directories are created with `mkdir(0700)` and verified
to be owned by the caller and not a symlink before use. Privileged file access in
netd uses `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)` against a directory FD
for `/run/xraytui` and `/sys/fs/cgroup/xraytui.slice`. Node-derived filenames are
never used; exports go to a caller-specified path opened with `O_NOFOLLOW` in the
*caller's* process, not in netd.

### T7 — Secret leakage

*Risk.* Credentials appear in logs, `ps` output, environment, crash dumps, QR codes,
diagnostics, or a bug report.

*Mitigations.* `Secret<T>` wrapper with a `Debug` that prints `Secret(<redacted>)`
and `Drop` that zeroizes. Secrets are never passed as argv and never placed in
long-lived environment variables — the core receives them only in a 0600 config
file. `tracing` fields go through a redaction layer that rewrites userinfo, known
query parameters (`token`, `key`, `password`, `sub`, `auth`), and any path segment
longer than 24 characters in a subscription URL. `xraytui diag export` produces a
redacted bundle and diff-tests it against a secret corpus. Share links and QR codes
are treated as secrets: displaying one prints a one-line warning that it grants
proxy access. No crash upload, no automatic issue submission.

### T8 — Supply chain: the Xray binary

*Risk.* A tampered core binary, or a downgrade to a version with known routing bugs.

*Mitigations.* Managed installs download only from
`github.com/XTLS/Xray-core/releases`, verify the SHA2-256 from the release's
`.dgst` asset, and refuse a version lower than the recorded installed version
unless `--allow-downgrade` is passed. The binary is written to a temp file in the
same directory and `rename(2)`d into place, never over a running process's path,
and never while the core is running. System-installed binaries are used as-is and
their `xray version` output plus file hash is recorded so a silent change is
visible in `xraytui doctor`.

### T9 — Unclean shutdown leaves the host broken or leaking

*Risk.* `xraytuid` is SIGKILLed or panics while TUN is active. Traffic either
blackholes forever or silently leaves the machine unproxied.

*Mitigations.* netd holds a **lease** per generation, refreshed by a heartbeat.
On lease expiry, netd applies the generation's recorded `failure_policy`:
`restore` (remove project routes/rules/nft table, restore DNS, delete TUN) or
`block` (keep a minimal kill-switch nft chain that drops non-loopback,
non-bypass traffic, and keep it until an authenticated client clears it).
Minimal recovery state — never credentials — is written to `/run/xraytui/state/`
(0700, root) with atomic rename, so a netd restart can reconcile. `xraytui doctor
--repair` and `xraytui-netd --recover` do the same reconciliation manually.

### T10 — Routing/DNS ownership collisions with the administrator

*Risk.* xraytui overwrites an nftables table, routing table id, fwmark or DNS
setting that belongs to the system administrator.

*Mitigations.* Only `table inet xraytui` is ever created or flushed; other tables
are never read into a generated ruleset and never flushed. Routing table ids and
fwmarks come from a documented reserved range and are **probed for conflict before
use** — if occupied by a rule xraytui did not create, setup fails with a clear
error instead of overwriting. Every rule carries a `comment "xraytui:<uid>:<gen>"`.
`xraytui tun plan` prints the exact set of intended changes before any are made.

### T11 — DNS restoration failure

*Risk.* systemd-resolved per-link settings are not restored, leaving the machine
pointing at a dead resolver.

*Mitigations.* Prior per-link state is captured before mutation and stored in the
generation record; restoration is idempotent and runs on teardown, on lease expiry,
and on netd start-up reconciliation. `/etc/resolv.conf` is never written unless the
user explicitly selected the `manual` backend and confirmed it; the default
backends are `systemd-resolved` (D-Bus) and `resolvconf`.

### T12 — LAN exposure of proxy listeners

*Risk.* An open SOCKS listener on `0.0.0.0` becomes an open relay.

*Mitigations.* Listeners bind `127.0.0.1` by default. `lan_access = true` requires
an explicit acknowledgement field in the config and forces authentication
credentials to be set; the TUI shows a red banner while any non-loopback listener
is active; `xraytui doctor` reports it as a finding.

### T13 — Browser / helper process ambiguity

*Risk.* A rule for `firefox` does not match because the socket is owned by
`/usr/lib/firefox/firefox` running as a content or socket process, or by a Flatpak
wrapper, so traffic silently takes the fallback route.

*Mitigations.* The Applications page resolves and shows the *actual* executable
paths of running processes matching the user's literal matcher, marks matchers that
currently match nothing, and documents the limitation. Users are steered towards
`exec --profile` for exactness.

### T14 — Parser denial of service in the IPC layer

*Risk.* A local process floods the control socket or sends a 4 GiB frame.

*Mitigations.* Frame length cap (8 MiB user socket, 256 KiB netd socket) checked
*before* allocation; per-connection concurrent-request cap; bounded event channels
with drop-oldest and a `lagged` notification; accept-rate limiting; idle timeout.

### T15 — Update rollback / downgrade of xraytui's own state

*Risk.* A newer xraytui writes a schema the older one silently mis-parses.

*Mitigations.* `schema_version` in every TOML file; unknown newer versions are a
hard error, not a best-effort parse. Migrations are versioned functions with a
mandatory timestamped backup and a `--dry-run`. Unknown fields are preserved
verbatim rather than dropped.

## Residual risks accepted

1. Loopback TCP for the Xray API has no per-user ACL. Mitigated by preferring a
   Unix-domain commander; documented where TCP must be used.
2. Xray's process matcher can be defeated by an uncooperative local process
   (it is a routing convenience, not a sandbox). Documented in `docs/TUI.md`.
3. A user in the `xraytui` group can create TUN devices and project-owned routes
   for their own UID. That is the intended grant; it is equivalent to what the
   administrator authorised.
4. xraytui cannot protect against a compromised proxy endpoint. Endpoint choice is
   the operator's trust decision.

## Reporting

See `SECURITY.md`. No automatic submission of any kind exists in the codebase.
