# xraytui 1.0.0-rc1

A terminal client for Xray-core that runs several egress profiles at once
through one supervised core, on Linux, for a machine you own.

**This is a release candidate, not 1.0.0.** Two mandatory gates cannot run in
the environment it was built in, and the project's own rule is that a gate
which was never executed is not a gate that passed. Both are named below, both
have a harness that is written and ready, and neither was quietly skipped.

## What it does

* Several egress profiles at the same time through one Xray process, each with
  its own loopback SOCKS5 and HTTP listeners and its own selector.
* Switching one profile's target through the gRPC API: new connections move,
  the other profiles do not notice, and the core is not restarted.
* Per-instance transparent routing: two instances of the *same* executable,
  same arguments, same destination, leaving by two different exits, with no
  proxy environment variables — classified by cgroup and pidfd before the
  program can open a connection.
* Nodes typed in or imported, groups, chains, application rules, routing rules
  and subscriptions — all from the command line or the interface, never by
  editing generated JSON.
* A TUN mode with policy routing, nftables and DNS, owned entirely by a
  narrowly privileged helper that has a closed operation set and no shell.

## Fixed in this candidate

Each of these was the program quietly claiming something untrue:

* **The core was not supervised.** `note_core_exit` and `has_exited` existed,
  were unit-tested, and had no callers. A core killed by the OOM killer was
  reported as `running` with a dead pid, indefinitely, while every listener was
  dead. The end-to-end test was confirmed to fail without the fix.
* **`app assign` printed a TOML snippet and exited 1** instead of changing
  anything — a feature that looked implemented in `--help` and was not.
* **Narrow mutations skipped validation.** `profile set-target work
  node:does-not-exist` was accepted and restarted the core onto a profile
  pointing at nothing.
* **`xraytui init` overwrote policy it could not parse**, so one typo in
  `groups.toml` deleted every node a user owned.
* **The plain-HTTP subscription refusal named a setting that did not exist.**
  `allow_plaintext` is now a real field with a real flag.
* **Piping any command into `head` or `dmenu` panicked** with a backtrace,
  because Rust ignores `SIGPIPE`. Both are documented workflows.

## What is not verified

* **Live `systemd-resolved`.** No D-Bus system bus here.
  `crates/linux-net/tests/resolved.rs` drives the real
  `org.freedesktop.resolve1`, checks the result with `resolvectl` rather than
  with the code under test, and reverts. It needs `XRAYTUI_TEST_RESOLVED=1`
  because resolved is a host service that cannot be namespaced.
* **A clean Arch package build.** No container runtime here.
* **IPv6 at runtime.** This kernel has no IPv6 at all. IPv6 is implemented,
  disabled by default, and fail-closed: unwanted IPv6 gets a `::/0` blackhole
  in the project's own routing table rather than a path around the tunnel.
* **aarch64.** No aarch64 archive is published, because a renamed x86_64 binary
  is not a port.

## Support boundary

Linux only; current Arch Linux is tier one. systemd, nftables, cgroup v2,
Xray-core as an external process. One trusted interactive user on a laptop or
workstation. IPv4 fully supported.

**Shared servers with mutually untrusted local users are out of scope.** Xray's
commander is a loopback TCP socket with no authentication. A random port is not
authentication and this project does not pretend otherwise.
