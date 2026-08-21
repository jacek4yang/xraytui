# xraytui — implementation plan

Short, actionable plan. Status of each item is tracked in `STATUS.md`.
Architectural rationale lives in `DECISIONS.md` and `docs/ARCHITECTURE.md`.

## Product in one paragraph

`xraytui` is a Linux-only, keyboard-first terminal client that drives an external
Xray-core process. Its distinguishing feature is **several independent egress
profiles running concurrently through a single supervised core**: different local
applications reach the internet through different proxies, chains, or directly, at
the same time, and each profile's target can be hot-switched through the Xray gRPC
API without restarting the core.

## Component split

| Component        | Privilege     | Owns                                                   |
|------------------|---------------|--------------------------------------------------------|
| `xraytui`        | user          | TUI + CLI. No network mutation. Talks to `xraytuid`.   |
| `xraytuid`       | user          | Desired state, compiler, Xray supervision, gRPC, IPC.  |
| `xraytui-netd`   | system, caps  | TUN device, routes, rules, nftables, DNS, cgroups.     |
| `xray`           | user          | Data plane. External official binary.                  |

## Phase list

- **P0 Discovery** — verify upstream Xray release, protobufs, routing/process/TUN
  semantics from source; write `PLAN.md`, `DECISIONS.md`,
  `docs/UPSTREAM-COMPATIBILITY.md`, `docs/THREAT-MODEL.md`.
- **P1 Foundation** — workspace, typed domain model, secrets, versioned TOML config,
  share-link parsers/serializers, subscription decoding, property tests.
- **P2 Xray layer** — vendored protobufs, Xray JSON model, deterministic compiler,
  tonic gRPC client, capability detection, config validation, core supervisor.
- **P3 Daemon** — `xraytuid`, CBOR IPC, concurrent egress profiles, per-profile
  SOCKS/HTTP listeners, hot switching, stats/events, SQLite state store.
- **P4 Front ends** — full CLI surface, ratatui TUI with all pages, dmenu/JSON/
  dwmblocks output, completions, man pages.
- **P5 Privileged networking** — `xraytui-netd` allowlist protocol, TUN, netlink,
  nftables, DNS managers, lease-based crash cleanup, restore/block policies.
- **P6 Per-application routing & chains** — process matcher compilation, `exec`
  environment backend, cgroup v2 exact-instance backend, chain compilation.
- **P7 Subscriptions, groups, health, sharing** — transactional updates, balancer
  strategies, probes through outbounds, share links and QR.
- **P8 Hardening & packaging** — acceptance scenarios, quality gates, Arch PKGBUILD,
  systemd units, docs, release-readiness report.

## Acceptance matrix

Scenario IDs match `<mandatory_acceptance_scenarios>` in the task specification.
Every row is either *automated*, *manual-privileged*, or *blocked* with a reason.

| ID | Scenario                                                 | Harness                                   |
|----|----------------------------------------------------------|-------------------------------------------|
| A  | Two profiles, two SOCKS ports, two mock egresses         | `tests/integration/` + mock egress server |
| B  | Hot-switch one profile via gRPC, other unchanged, no restart | same                                  |
| C  | Shared TUN rule mode: per-app routing in a netns          | `tests/netns/`                            |
| D  | Two apps concurrently + DNS following policy              | `tests/netns/`                            |
| E  | Two-hop chain reaches terminal exit through hop 1         | `tests/integration/`                      |
| F  | Import valid/malformed/unsupported node representations   | unit + proptest                           |
| G  | Subscription add/change/remove with diff and rollback     | integration, local HTTP fixture server    |
| H  | Terminal + PNG QR round-trip decode                       | unit (`quircs`, independent from encoder) |
| I  | Kill Xray in restore mode                                 | integration                               |
| J  | Kill `xraytuid` while TUN active, lease expiry cleanup    | `tests/netns/`                            |
| K  | Repeated TUN enable/disable leaves no residue             | `tests/netns/`                            |
| L  | TUI usable at 80x24, restores terminal, shows profiles    | ratatui `TestBackend`                     |
| M  | cgroup v2 exact-instance isolation of two same-exe procs  | `tests/netns/` (capability gated)         |
| N  | Clean build + install, nothing runs as root               | `cargo xtask install --dry-run` + docs    |

## Non-negotiable engineering rules

1. No `sh -c`. Fixed absolute executables with argument vectors only.
2. No secrets in argv or long-lived environment variables.
3. Loopback-only listeners unless the user explicitly opts into LAN exposure.
4. Privileged helper accepts a closed set of typed operations. No paths, commands,
   or rule text pass through from user input unvalidated.
5. Generated Xray JSON is a build artifact; TOML is the source of truth.
6. Every generated Xray object carries a namespaced tag so ownership is provable.
7. `unwrap`/`expect` are denied by lint in daemon and helper crates.
