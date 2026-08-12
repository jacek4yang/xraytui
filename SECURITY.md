# Security

## Reporting

Report suspected vulnerabilities privately by email to the maintainers listed in
`Cargo.toml`, or through the repository host's private advisory mechanism. Please
do not open a public issue for a vulnerability.

Include: what you did, what happened, what you expected, the output of
`xraytui doctor`, and the versions of xraytui and Xray-core. **Do not include a
share link, a subscription URL, a QR code or a generated Xray configuration** —
all four contain credentials. `xraytui node show` and the logs are already
redacted and are safe to attach.

## Supported versions

Only the latest release is supported. `docs/UPSTREAM-COMPATIBILITY.md` records
which Xray-core releases each version is tested against.

## What this project does not do

* No telemetry, of any kind, ever.
* No crash upload, no automatic issue submission, no phone-home version check.
* No setuid binary is installed. The privileged helper receives capabilities
  from systemd, not from the filesystem.
* No arbitrary command execution behind a privilege boundary, and no `sh -c`
  anywhere in the codebase.
* No plugin loading, no scripting engine, no unsigned native modules.
* No TLS interception, no CA installation, no packet capture, no payload
  inspection. Runtime observability uses Xray statistics, routing metadata and
  local process state only.
* No proxy listener is bound to a non-loopback address unless the user sets both
  `lan_access` and `lan_access_acknowledged`.

## Trust boundaries

1. **Network → parsers.** Subscription bodies, share links, QR payloads and Xray
   JSON are attacker-influenced. Every parser is bounded and panic-free, and is
   covered by property tests asserting termination on arbitrary input.
2. **`xraytuid` → `xraytui-netd`.** The only privilege boundary. Everything
   crossing it is one variant of a closed operation enum, validated before any
   action, with all resource names derived from the `SO_PEERCRED` UID.
3. **Other local users → the control socket and the Xray API.** The control
   socket is 0600 in a 0700 directory and additionally checks the peer UID. The
   Xray commander is loopback TCP, which has no per-user access control on
   Linux; see the residual risks below.

`docs/THREAT-MODEL.md` has the full analysis.

## Known residual risks

* **The Xray commander is reachable by any local user.** Xray-core listens for
  its gRPC API on TCP only (`app/commander` calls `net.Listen("tcp", …)`), so on
  a machine with other untrusted local accounts, those accounts can drive the
  data plane. There is no mitigation available today; `[core] api_unix_socket`
  exists for the day upstream gains one.
* **Xray's process matcher is a routing convenience, not a sandbox.** An
  uncooperative local process can avoid it. Use `xraytui exec` when exactness
  matters.
* **A member of the `xraytui` group can create project-owned TUN devices and
  routes for their own UID.** That is the grant the administrator made by adding
  them to the group.
* **The dependency set has not been audited.** `cargo audit` and `cargo deny`
  have not been run; see `STATUS.md`.

## Out of scope

A compromised proxy endpoint, a malicious Xray-core binary installed by the
administrator, and an attacker who already has the user's UID.
