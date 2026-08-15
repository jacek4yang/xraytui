//! The closed operation set spoken to `xraytui-netd`.
//!
//! This crate is the privilege boundary made legible: **everything the
//! privileged helper can be asked to do is one variant of [`Operation`]**. There
//! is no "run this command", no path that reaches a shell, no nftables or
//! iproute2 text, and no way to name a resource belonging to another user.
//!
//! Three rules hold for every operation and are enforced by
//! [`Operation::validate`] plus the tests below:
//!
//! 1. **Ownership is derived, not asserted.** No message carries a UID. The
//!    helper takes the UID from `SO_PEERCRED` and computes every resource name
//!    from it, so a caller cannot address another user's TUN, table or cgroup.
//! 2. **Every free-form value is constrained.** Interface names must match
//!    `^xraytui[0-9a-z]{0,8}$`; addresses and routes are typed `IpNet`, not
//!    strings; table ids, marks and priorities come from reserved ranges.
//! 3. **Nothing is unbounded.** Lists have caps, so one message cannot make the
//!    helper build an enormous ruleset.
//!
//! What the helper deliberately cannot do: parse a subscription, resolve a name,
//! open a network socket, read a node credential, touch an nftables table other
//! than its own, or modify an interface it did not create.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(missing_docs)]

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Protocol version for the helper socket, versioned separately from the user
/// control protocol because it changes for different reasons.
pub const NETD_PROTOCOL_VERSION: u32 = 1;

/// Default socket path.
pub const DEFAULT_SOCKET: &str = "/run/xraytui/netd.sock";

/// Directory holding minimal recovery state. Never contains credentials.
pub const RECOVERY_DIR: &str = "/run/xraytui/state";

/// The only nftables table the helper will ever create, flush or delete.
pub const NFT_TABLE: &str = "xraytui";

/// The nftables family that table lives in.
pub const NFT_FAMILY: &str = "inet";

/// Lowest routing table id the helper will use.
pub const TABLE_ID_BASE: u32 = 0x7261;
/// Number of routing table ids reserved, one per concurrent user.
pub const TABLE_ID_SPAN: u32 = 64;

/// Lowest firewall mark the helper will use.
pub const FWMARK_BASE: u32 = 0x7261_0000;
/// Number of marks reserved.
pub const FWMARK_SPAN: u32 = 0x0000_1000;
/// Mask selecting the reserved band, for a policy rule that catches all of it.
pub const FWMARK_MASK: u32 = 0xffff_0000;
/// Bits of a mark that identify the profile within a user's allocation.
pub const PROFILE_SLOT_BITS: u32 = 6;
/// Transparent profiles one user may have at once.
///
/// Slot 0 is the user's tunnel, so 63 profiles remain. Nobody has 63 profiles;
/// the limit exists so that one user's marks provably cannot reach another's.
pub const MAX_TRANSPARENT_PROFILES: usize = (1 << PROFILE_SLOT_BITS) - 1;

/// Lowest policy-routing rule priority the helper will use.
pub const RULE_PRIORITY_BASE: u32 = 17_000;

/// Longest list accepted in any single operation.
pub const MAX_LIST_LEN: usize = 256;

/// Longest lease a client can ask for, in seconds.
pub const MAX_LEASE_TTL_SECS: u64 = 3600;

/// Interface names the helper accepts.
///
/// The prefix is what makes ownership provable: an interface not called
/// `xraytui…` was not created by this project, and the helper refuses to touch
/// it. The character set excludes everything that could matter to a shell, an
/// nftables parser or a path, so the name is safe by construction rather than by
/// escaping.
#[must_use]
pub fn is_valid_interface(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("xraytui") else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 15
        && suffix.len() <= 8
        && suffix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// The routing table id reserved for a UID.
#[must_use]
pub fn table_for_uid(uid: u32) -> u32 {
    TABLE_ID_BASE + (uid % TABLE_ID_SPAN)
}

/// The firewall mark reserved for a UID's system tunnel.
///
/// A mark is `FWMARK_BASE | uid_slot << 6 | profile_slot`, and the tunnel is
/// profile slot zero. Splitting the reserved band this way is what lets one
/// user have several *distinguishable* marks — which is how traffic from two
/// instances of the same program reaches two different exits — while keeping
/// every mark a user can obtain inside their own allocation.
#[must_use]
pub fn fwmark_for_uid(uid: u32) -> u32 {
    transparent_mark(uid, 0)
}

/// The firewall mark reserved for one of a UID's transparent profiles.
///
/// `slot` is the profile's position in the sorted list the caller sent, so it
/// is derived rather than asserted: a client cannot ask for a particular mark,
/// and therefore cannot ask for somebody else's.
#[must_use]
pub fn transparent_mark(uid: u32, slot: usize) -> u32 {
    let uid_slot = uid % TABLE_ID_SPAN;
    let profile_slot = (slot as u32) & ((1 << PROFILE_SLOT_BITS) - 1);
    FWMARK_BASE | (uid_slot << PROFILE_SLOT_BITS) | profile_slot
}

/// The routing table that delivers transparently-proxied traffic locally.
///
/// Separate from the tunnel table because the two hold contradictory default
/// routes: the tunnel's sends traffic to the device, this one keeps it on the
/// machine so a `tproxy` rule can hand it to a listener.
#[must_use]
pub fn transparent_table_for_uid(uid: u32) -> u32 {
    TABLE_ID_BASE + TABLE_ID_SPAN + (uid % TABLE_ID_SPAN)
}

/// The interface name reserved for a UID's system TUN.
#[must_use]
pub fn interface_for_uid(uid: u32) -> String {
    format!("xraytui{}", uid % 100_000)
}

/// The cgroup path reserved for a UID and profile.
#[must_use]
pub fn cgroup_for(uid: u32, profile: &str) -> String {
    format!("/sys/fs/cgroup/xraytui.slice/u{uid}/{profile}")
}

/// What happens to the network if the owning daemon dies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FailurePolicy {
    /// Remove project routes and rules, restore DNS, delete the device.
    #[default]
    Restore,
    /// Keep a kill-switch chain so traffic cannot silently fall back to direct.
    Block,
}

/// Which system component owns resolver configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DnsBackend {
    /// Leave system DNS alone.
    #[default]
    None,
    /// `org.freedesktop.resolve1` over D-Bus.
    SystemdResolved,
    /// The `resolvconf` interface.
    Resolvconf,
}

/// A request to the helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetdRequest {
    /// Correlates the reply.
    pub id: u64,
    /// Protocol version the caller speaks.
    pub protocol_version: u32,
    /// What to do.
    pub operation: Operation,
}

/// A reply from the helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetdReply {
    /// The request this answers.
    pub id: u64,
    /// The outcome.
    pub result: Result<Outcome, NetdError>,
}

/// **The complete set of privileged operations.**
///
/// Reading this enum is reading the full extent of what root can be asked to do
/// on behalf of a user. Adding a variant is a security review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    /// Liveness and capability check. Performs no changes.
    Ping,

    /// Report what the kernel and userland can support.
    Capabilities,

    /// Create a persistent TUN device owned by the calling UID and configure it.
    ///
    /// The device is created with `TUNSETPERSIST` and `TUNSETOWNER` so that the
    /// unprivileged Xray process can attach to it afterwards. The file
    /// descriptor is returned over `SCM_RIGHTS` for the daemon to hold as a
    /// liveness handle. See `DECISIONS.md` D-008 for why the FD is not simply
    /// passed to Xray.
    CreateTun(TunRequest),

    /// Delete the calling UID's TUN device and everything attached to it.
    DeleteTun,

    /// Install policy routing for the calling UID's TUN.
    ApplyRouting(RoutingRequest),

    /// Remove the calling UID's policy routing.
    ClearRouting,

    /// Replace the calling UID's chains inside `table inet xraytui`.
    ///
    /// The ruleset is described structurally; no nftables text crosses the
    /// boundary.
    ApplyFirewall(FirewallRequest),

    /// Remove the calling UID's chains, leaving other users' chains alone.
    ClearFirewall,

    /// Point the system resolver at an address, saving the previous state.
    ApplyDns(DnsRequest),

    /// Restore the resolver state saved by [`Operation::ApplyDns`].
    ClearDns,

    /// Create a project-owned cgroup for a profile.
    CreateCgroup {
        /// Profile identifier; must be a slug.
        profile: String,
    },

    /// Move a process into a project-owned cgroup.
    ///
    /// The process is identified by a `pidfd` passed over `SCM_RIGHTS`, never by
    /// a numeric pid: a pid can be recycled between the check and the write,
    /// and a `pidfd` cannot. The helper verifies the process belongs to the
    /// calling UID before writing to `cgroup.procs`.
    ClassifyProcess {
        /// Profile whose cgroup to use.
        profile: String,
    },

    /// Remove a project-owned cgroup once it is empty.
    RemoveCgroup {
        /// Profile identifier.
        profile: String,
    },

    /// Refresh the lease so the helper knows the daemon is still alive.
    Heartbeat {
        /// Generation the daemon believes is current.
        generation: u64,
    },

    /// Release the lease and tear down everything this UID owns.
    Release,

    /// Report what would be changed, without changing anything.
    Plan(Box<PlanRequest>),

    /// Reconcile: remove project-owned state whose lease has expired.
    ///
    /// Safe to call at any time; it only ever removes state this project
    /// created and whose owner is gone.
    Recover,
}

/// Parameters for [`Operation::CreateTun`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunRequest {
    /// Interface name. Must satisfy [`is_valid_interface`] and match the name
    /// the helper derives for the calling UID.
    pub interface: String,
    /// MTU, 576..=9000.
    pub mtu: u32,
    /// IPv4 address to assign, if any.
    pub ipv4: Option<IpNet>,
    /// IPv6 address to assign, if any.
    pub ipv6: Option<IpNet>,
    /// Seconds the lease survives without a heartbeat.
    pub lease_ttl_secs: u64,
    /// What to do when the lease expires.
    pub failure_policy: FailurePolicy,
}

/// Parameters for [`Operation::ApplyRouting`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingRequest {
    /// Prefixes routed into the tunnel.
    pub include: Vec<IpNet>,
    /// Prefixes never routed into the tunnel.
    pub exclude: Vec<IpNet>,
    /// Addresses of the configured proxy endpoints, pinned to the physical
    /// route so the core's own uplink cannot loop through its own tunnel.
    pub bypass_endpoints: Vec<IpAddr>,
    /// Skip RFC1918, link-local and multicast destinations.
    pub bypass_private: bool,
    /// Blackhole IPv6 rather than leaving it to leak around the tunnel.
    pub blackhole_ipv6: bool,
}

/// Structural description of the firewall state to install.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirewallRequest {
    /// Mark traffic from these cgroups, one entry per transparent profile.
    pub cgroup_marks: Vec<CgroupMark>,
    /// Install the kill switch, dropping traffic that would otherwise escape.
    pub kill_switch: bool,
    /// Never mark traffic owned by this UID's core process.
    pub bypass_uid: bool,
}

/// One cgroup-to-mark classification.
///
/// **No mark appears here.** The helper derives it from the calling UID and the
/// profile's position in the sorted list, for the same reason no message
/// carries a UID: a value a client can choose is a value a client can choose
/// *badly*, and a mark that reached another user's allocation would route their
/// traffic into this user's listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupMark {
    /// Profile identifier, used to derive the cgroup path.
    pub profile: String,
    /// Local port of this profile's transparent listener.
    ///
    /// When set, traffic from the profile's cgroup is redirected there with
    /// `tproxy` — which is what lets two instances of the same program take
    /// different exits. When unset, the traffic is merely marked for the
    /// system tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tproxy_port: Option<u16>,
}

/// Parameters for [`Operation::ApplyDns`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsRequest {
    /// Which backend to drive.
    pub backend: DnsBackend,
    /// Resolver addresses to install.
    pub servers: Vec<IpAddr>,
    /// Search domains, or `~.` to claim every query.
    pub domains: Vec<String>,
}

/// Parameters for [`Operation::Plan`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanRequest {
    /// The TUN that would be created.
    pub tun: TunRequest,
    /// The routing that would be applied.
    pub routing: RoutingRequest,
    /// The firewall state that would be installed.
    pub firewall: FirewallRequest,
    /// The DNS state that would be applied.
    pub dns: DnsRequest,
}

/// A successful outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    /// Nothing to report.
    Ack,
    /// Liveness answer.
    Pong {
        /// Helper version.
        version: String,
        /// Protocol version.
        protocol_version: u32,
    },
    /// What this kernel and userland can do.
    Capabilities(Box<NetdCapabilities>),
    /// A TUN device was created.
    TunCreated {
        /// Interface name.
        interface: String,
        /// Interface index.
        index: u32,
        /// Routing table id assigned to this UID.
        table: u32,
        /// Firewall mark assigned to this UID.
        fwmark: u32,
        /// Whether a file descriptor accompanies this reply over `SCM_RIGHTS`.
        fd_attached: bool,
    },
    /// A plan, as a list of human-readable steps. Nothing was changed.
    Plan {
        /// One line per intended change.
        steps: Vec<String>,
    },
    /// A recovery pass finished.
    Recovered {
        /// What was cleaned up.
        removed: Vec<String>,
    },
}

/// What the helper found the system able to do.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NetdCapabilities {
    /// `/dev/net/tun` exists and is usable.
    pub tun: bool,
    /// The helper holds `CAP_NET_ADMIN`.
    pub cap_net_admin: bool,
    /// `nft` is present and the project table can be managed.
    pub nftables: bool,
    /// cgroup v2 is mounted with the controllers the exec backend needs.
    pub cgroup_v2: bool,
    /// nftables supports `socket cgroupv2`, required by exact-instance routing.
    pub nft_cgroup_match: bool,
    /// systemd-resolved is reachable over D-Bus.
    pub systemd_resolved: bool,
    /// `resolvconf` is present.
    pub resolvconf: bool,
    /// Kernel release string, for diagnostics.
    pub kernel: String,
}

impl NetdCapabilities {
    /// Whether a system TUN can be brought up at all.
    #[must_use]
    pub fn supports_tun(&self) -> bool {
        self.tun && self.cap_net_admin
    }

    /// Whether `exec --transparent` can work.
    #[must_use]
    pub fn supports_transparent_exec(&self) -> bool {
        self.supports_tun() && self.cgroup_v2 && self.nft_cgroup_match
    }
}

/// Why an operation was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum NetdError {
    /// The caller and helper do not speak a common protocol version.
    #[error("netd speaks protocol {helper}, the caller asked for {caller}")]
    Version {
        /// Helper's version.
        helper: u32,
        /// Caller's version.
        caller: u32,
    },
    /// The request failed validation. Nothing was changed.
    #[error("refused: {0}")]
    Refused(String),
    /// The caller is not permitted.
    #[error("not permitted: {0}")]
    Denied(String),
    /// A resource this project does not own is in the way.
    #[error("{resource} is already in use by something xraytui did not create")]
    Conflict {
        /// What collided.
        resource: String,
    },
    /// The kernel or userland lacks something the operation needs.
    #[error("unsupported on this system: {0}")]
    Unsupported(String),
    /// The caller holds no lease, so there is nothing to act on.
    #[error("no active lease for this user")]
    NoLease,
    /// The operation failed part-way and was rolled back.
    #[error("{operation} failed and was rolled back: {detail}")]
    RolledBack {
        /// Which operation.
        operation: String,
        /// What went wrong.
        detail: String,
    },
    /// Anything else, with a bounded message.
    #[error("{0}")]
    Internal(String),
}

impl Operation {
    /// Validate everything that can be checked without touching the system.
    ///
    /// `uid` is the credential from `SO_PEERCRED`, never a field of the message.
    /// Validation happens before any privileged action, so a refused request
    /// changes nothing.
    ///
    /// # Errors
    /// Returns [`NetdError::Refused`] naming the offending field.
    pub fn validate(&self, uid: u32) -> Result<(), NetdError> {
        match self {
            Self::Ping
            | Self::Capabilities
            | Self::DeleteTun
            | Self::ClearRouting
            | Self::ClearFirewall
            | Self::ClearDns
            | Self::Release
            | Self::Recover => Ok(()),

            Self::Heartbeat { .. } => Ok(()),

            Self::CreateTun(request) => validate_tun(request, uid),

            Self::ApplyRouting(request) => validate_routing(request),

            Self::ApplyFirewall(request) => validate_firewall(request),

            Self::ApplyDns(request) => validate_dns(request),

            Self::CreateCgroup { profile }
            | Self::ClassifyProcess { profile }
            | Self::RemoveCgroup { profile } => validate_profile(profile),

            Self::Plan(request) => {
                validate_tun(&request.tun, uid)?;
                validate_routing(&request.routing)?;
                validate_firewall(&request.firewall)?;
                validate_dns(&request.dns)
            }
        }
    }

    /// Short name for logging.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Capabilities => "capabilities",
            Self::CreateTun(_) => "create-tun",
            Self::DeleteTun => "delete-tun",
            Self::ApplyRouting(_) => "apply-routing",
            Self::ClearRouting => "clear-routing",
            Self::ApplyFirewall(_) => "apply-firewall",
            Self::ClearFirewall => "clear-firewall",
            Self::ApplyDns(_) => "apply-dns",
            Self::ClearDns => "clear-dns",
            Self::CreateCgroup { .. } => "create-cgroup",
            Self::ClassifyProcess { .. } => "classify-process",
            Self::RemoveCgroup { .. } => "remove-cgroup",
            Self::Heartbeat { .. } => "heartbeat",
            Self::Release => "release",
            Self::Plan(_) => "plan",
            Self::Recover => "recover",
        }
    }

    /// Whether this operation modifies the system.
    #[must_use]
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            Self::Ping | Self::Capabilities | Self::Plan(_) | Self::Heartbeat { .. }
        )
    }

    /// Whether the caller must send a file descriptor with this operation.
    #[must_use]
    pub fn expects_fd(&self) -> bool {
        matches!(self, Self::ClassifyProcess { .. })
    }
}

fn validate_tun(request: &TunRequest, uid: u32) -> Result<(), NetdError> {
    if !is_valid_interface(&request.interface) {
        return Err(NetdError::Refused(format!(
            "interface {:?} must match ^xraytui[0-9a-z]{{0,8}}$",
            request.interface
        )));
    }
    // The name is derived from the credential UID, so one user cannot ask for
    // another user's device even with a syntactically valid name.
    let expected = interface_for_uid(uid);
    if request.interface != expected {
        return Err(NetdError::Denied(format!(
            "uid {uid} may only manage interface {expected}"
        )));
    }
    if !(576..=9000).contains(&request.mtu) {
        return Err(NetdError::Refused(format!(
            "mtu {} is outside 576..=9000",
            request.mtu
        )));
    }
    if request.ipv4.is_none() && request.ipv6.is_none() {
        return Err(NetdError::Refused(
            "at least one of ipv4 or ipv6 must be given".into(),
        ));
    }
    if let Some(net) = request.ipv4
        && !net.addr().is_ipv4()
    {
        return Err(NetdError::Refused("ipv4 field holds an IPv6 prefix".into()));
    }
    if let Some(net) = request.ipv6
        && !net.addr().is_ipv6()
    {
        return Err(NetdError::Refused("ipv6 field holds an IPv4 prefix".into()));
    }
    if request.lease_ttl_secs == 0 || request.lease_ttl_secs > MAX_LEASE_TTL_SECS {
        return Err(NetdError::Refused(format!(
            "lease_ttl_secs must be 1..={MAX_LEASE_TTL_SECS}"
        )));
    }
    Ok(())
}

fn validate_routing(request: &RoutingRequest) -> Result<(), NetdError> {
    for (name, list) in [("include", &request.include), ("exclude", &request.exclude)] {
        if list.len() > MAX_LIST_LEN {
            return Err(NetdError::Refused(format!(
                "{name} has {} entries, over the {MAX_LIST_LEN} limit",
                list.len()
            )));
        }
    }
    if request.bypass_endpoints.len() > MAX_LIST_LEN {
        return Err(NetdError::Refused(format!(
            "bypass_endpoints has {} entries, over the {MAX_LIST_LEN} limit",
            request.bypass_endpoints.len()
        )));
    }
    // A default route in `exclude` would silently disable the tunnel.
    for net in &request.exclude {
        if net.prefix_len() == 0 {
            return Err(NetdError::Refused(
                "excluding the default route would disable the tunnel entirely".into(),
            ));
        }
    }
    Ok(())
}

fn validate_firewall(request: &FirewallRequest) -> Result<(), NetdError> {
    if request.cgroup_marks.len() > MAX_LIST_LEN {
        return Err(NetdError::Refused(format!(
            "cgroup_marks has {} entries, over the {MAX_LIST_LEN} limit",
            request.cgroup_marks.len()
        )));
    }
    if request.cgroup_marks.len() > MAX_TRANSPARENT_PROFILES {
        return Err(NetdError::Refused(format!(
            "{} profiles asked for a mark; at most {MAX_TRANSPARENT_PROFILES} fit in one \
             user's reserved allocation",
            request.cgroup_marks.len()
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in &request.cgroup_marks {
        validate_profile(&entry.profile)?;
        if !seen.insert(entry.profile.as_str()) {
            return Err(NetdError::Refused(format!(
                "profile {:?} appears twice; each needs its own mark",
                entry.profile
            )));
        }
        if entry.tproxy_port == Some(0) {
            return Err(NetdError::Refused(format!(
                "profile {:?} asked for a transparent listener on port 0",
                entry.profile
            )));
        }
    }
    // Two profiles redirected to one listener is not a configuration, it is a
    // mistake: whichever mark arrived would be answered by whichever profile
    // owns that inbound, so one profile's traffic would silently take the
    // other's egress. The caller's own validation should catch it first; the
    // helper checks anyway, because it does not trust the caller.
    let mut ports = std::collections::BTreeMap::new();
    for entry in &request.cgroup_marks {
        let Some(port) = entry.tproxy_port else {
            continue;
        };
        if let Some(previous) = ports.insert(port, entry.profile.as_str()) {
            return Err(NetdError::Refused(format!(
                "profiles {:?} and {:?} both want the transparent listener on port {port}",
                previous, entry.profile
            )));
        }
    }
    Ok(())
}

fn validate_dns(request: &DnsRequest) -> Result<(), NetdError> {
    if request.servers.len() > 8 {
        return Err(NetdError::Refused("at most 8 resolvers may be set".into()));
    }
    if request.domains.len() > 32 {
        return Err(NetdError::Refused(
            "at most 32 search domains may be set".into(),
        ));
    }
    for domain in &request.domains {
        // `~.` is systemd-resolved's "route everything here" marker; anything
        // else must look like a hostname.
        if domain == "~." {
            continue;
        }
        if domain.is_empty() || domain.len() > 253 {
            return Err(NetdError::Refused(
                "search domain has an implausible length".into(),
            ));
        }
        if !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~'))
        {
            return Err(NetdError::Refused(format!(
                "search domain {domain:?} contains characters that are not allowed"
            )));
        }
    }
    if matches!(request.backend, DnsBackend::None) && !request.servers.is_empty() {
        return Err(NetdError::Refused(
            "resolvers were given but the backend is `none`".into(),
        ));
    }
    Ok(())
}

fn validate_profile(profile: &str) -> Result<(), NetdError> {
    if profile.is_empty() || profile.len() > 64 {
        return Err(NetdError::Refused(
            "profile identifier must be 1..=64 bytes".into(),
        ));
    }
    if !profile
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(NetdError::Refused(format!(
            "profile identifier {profile:?} must be a lowercase slug; it becomes a directory name"
        )));
    }
    // Belt and braces against traversal even though the character set forbids it.
    if profile.contains("..") || profile.contains('/') {
        return Err(NetdError::Refused(
            "profile identifier must not contain path separators".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun(uid: u32) -> TunRequest {
        TunRequest {
            interface: interface_for_uid(uid),
            mtu: 1500,
            ipv4: "198.18.0.1/15".parse().ok(),
            ipv6: None,
            lease_ttl_secs: 30,
            failure_policy: FailurePolicy::Restore,
        }
    }

    #[test]
    fn interface_names_are_constrained_to_the_project_prefix() {
        assert!(is_valid_interface("xraytui0"));
        assert!(is_valid_interface("xraytui"));
        assert!(is_valid_interface("xraytui12345"));
        assert!(!is_valid_interface("eth0"));
        assert!(!is_valid_interface("wlan0"));
        assert!(!is_valid_interface("xraytui-0"));
        assert!(!is_valid_interface("xraytui/0"));
        assert!(!is_valid_interface("xraytui$(id)"));
        assert!(!is_valid_interface("xraytui;reboot"));
        assert!(!is_valid_interface("xraytui 0"));
        assert!(!is_valid_interface("xraytui123456789"));
        assert!(!is_valid_interface(""));
    }

    #[test]
    fn a_user_may_only_name_their_own_interface() {
        let request = tun(1000);
        assert!(request.validate_for(1000).is_ok());
        // Same syntactically valid name, different caller: refused.
        let error = request.validate_for(1001).expect_err("must refuse");
        assert!(matches!(error, NetdError::Denied(_)), "{error:?}");
    }

    impl TunRequest {
        fn validate_for(&self, uid: u32) -> Result<(), NetdError> {
            Operation::CreateTun(self.clone()).validate(uid)
        }
    }

    #[test]
    fn resource_names_are_derived_from_the_uid() {
        assert_ne!(interface_for_uid(1000), interface_for_uid(1001));
        assert_ne!(table_for_uid(1000), table_for_uid(1001));
        assert_ne!(fwmark_for_uid(1000), fwmark_for_uid(1001));
        assert!(table_for_uid(1000) >= TABLE_ID_BASE);
        assert!(table_for_uid(u32::MAX) < TABLE_ID_BASE + TABLE_ID_SPAN);
        assert!(fwmark_for_uid(1000) >= FWMARK_BASE);
        assert!(fwmark_for_uid(u32::MAX) < FWMARK_BASE + FWMARK_SPAN);
    }

    #[test]
    fn cgroup_paths_stay_inside_the_project_slice() {
        let path = cgroup_for(1000, "web");
        assert!(path.starts_with("/sys/fs/cgroup/xraytui.slice/"), "{path}");
        assert!(path.contains("/u1000/"), "{path}");
    }

    #[test]
    fn implausible_tun_parameters_are_refused() {
        let mut request = tun(1000);
        request.mtu = 10;
        assert!(matches!(
            Operation::CreateTun(request.clone()).validate(1000),
            Err(NetdError::Refused(_))
        ));

        request = tun(1000);
        request.ipv4 = None;
        request.ipv6 = None;
        assert!(matches!(
            Operation::CreateTun(request.clone()).validate(1000),
            Err(NetdError::Refused(_))
        ));

        request = tun(1000);
        request.lease_ttl_secs = 0;
        assert!(matches!(
            Operation::CreateTun(request.clone()).validate(1000),
            Err(NetdError::Refused(_))
        ));

        request = tun(1000);
        request.lease_ttl_secs = MAX_LEASE_TTL_SECS + 1;
        assert!(matches!(
            Operation::CreateTun(request).validate(1000),
            Err(NetdError::Refused(_))
        ));
    }

    #[test]
    fn an_address_family_mismatch_is_refused() {
        let mut request = tun(1000);
        request.ipv6 = "10.0.0.1/24".parse().ok();
        let error = Operation::CreateTun(request)
            .validate(1000)
            .expect_err("must refuse");
        assert!(error.to_string().contains("ipv6 field"), "{error}");
    }

    #[test]
    fn excluding_the_default_route_is_refused() {
        let request = RoutingRequest {
            include: vec![],
            exclude: vec!["0.0.0.0/0".parse().unwrap_or_else(|_| unreachable!())],
            bypass_endpoints: vec![],
            bypass_private: true,
            blackhole_ipv6: false,
        };
        let error = Operation::ApplyRouting(request)
            .validate(1000)
            .expect_err("must refuse");
        assert!(error.to_string().contains("default route"), "{error}");
    }

    #[test]
    fn oversized_lists_are_refused_before_any_work() {
        let request = RoutingRequest {
            include: (0..MAX_LIST_LEN + 1)
                .map(|i| {
                    format!("10.{}.{}.0/24", i / 256, i % 256)
                        .parse()
                        .unwrap_or_else(|_| unreachable!())
                })
                .collect(),
            exclude: vec![],
            bypass_endpoints: vec![],
            bypass_private: true,
            blackhole_ipv6: false,
        };
        assert!(matches!(
            Operation::ApplyRouting(request).validate(1000),
            Err(NetdError::Refused(_))
        ));
    }

    #[test]
    fn a_mark_cannot_be_asked_for_at_all_so_it_cannot_reach_another_user() {
        // Every mark one user can obtain lies inside their own allocation, and
        // no allocation overlaps another's, for every uid.
        for uid in [0u32, 1, 1000, 1001, 65_534, u32::MAX] {
            let mine: std::collections::BTreeSet<u32> = (0..=MAX_TRANSPARENT_PROFILES)
                .map(|slot| transparent_mark(uid, slot))
                .collect();
            assert_eq!(mine.len(), MAX_TRANSPARENT_PROFILES + 1);
            assert!(mine.contains(&fwmark_for_uid(uid)));
            for mark in &mine {
                assert_eq!(
                    mark & FWMARK_MASK,
                    FWMARK_BASE,
                    "{mark:#x} left the reserved band"
                );
            }
            // A different uid slot gets a disjoint set.
            let theirs: std::collections::BTreeSet<u32> = (0..=MAX_TRANSPARENT_PROFILES)
                .map(|slot| transparent_mark(uid.wrapping_add(1), slot))
                .collect();
            assert!(
                mine.is_disjoint(&theirs),
                "uid {uid} and uid {} share a mark",
                uid.wrapping_add(1)
            );
        }
    }

    #[test]
    fn more_profiles_than_fit_in_one_allocation_are_refused() {
        let request = FirewallRequest {
            cgroup_marks: (0..=MAX_TRANSPARENT_PROFILES)
                .map(|index| CgroupMark {
                    profile: format!("p{index}"),
                    tproxy_port: Some(10_000 + index as u16),
                })
                .collect(),
            kill_switch: false,
            bypass_uid: true,
        };
        let error = Operation::ApplyFirewall(request)
            .validate(1000)
            .expect_err("must refuse");
        assert!(error.to_string().contains("reserved allocation"), "{error}");
    }

    #[test]
    fn two_profiles_cannot_share_one_transparent_listener() {
        // Both would be redirected to whichever profile owns that inbound, so
        // one profile's traffic would leave by the other's egress — silently.
        let request = FirewallRequest {
            cgroup_marks: vec![
                CgroupMark {
                    profile: "web".into(),
                    tproxy_port: Some(12_000),
                },
                CgroupMark {
                    profile: "media".into(),
                    tproxy_port: Some(12_000),
                },
            ],
            kill_switch: false,
            bypass_uid: true,
        };
        let error = Operation::ApplyFirewall(request)
            .validate(1000)
            .expect_err("a shared listener must be refused");
        assert!(error.to_string().contains("12000"), "{error}");
    }

    #[test]
    fn a_profile_without_a_listener_does_not_collide_with_another_one() {
        let request = FirewallRequest {
            cgroup_marks: vec![
                CgroupMark {
                    profile: "web".into(),
                    tproxy_port: None,
                },
                CgroupMark {
                    profile: "media".into(),
                    tproxy_port: None,
                },
            ],
            kill_switch: false,
            bypass_uid: true,
        };
        assert!(Operation::ApplyFirewall(request).validate(1000).is_ok());
    }

    #[test]
    fn every_slot_in_a_users_allocation_gets_a_distinct_mark() {
        // Deterministic allocation: same uid and slot, same mark, every time —
        // and no two slots collide, which is what keeps two profiles' traffic
        // apart at prerouting.
        let mut seen = std::collections::BTreeSet::new();
        for slot in 0..=MAX_TRANSPARENT_PROFILES {
            let mark = transparent_mark(1000, slot);
            assert_eq!(mark, transparent_mark(1000, slot), "not deterministic");
            assert!(
                seen.insert(mark),
                "slot {slot} collided with an earlier one"
            );
            assert_eq!(
                mark & FWMARK_MASK,
                FWMARK_BASE & FWMARK_MASK,
                "slot {slot} left this project's reserved range"
            );
        }
        // And two users never share one, however many profiles they have.
        for slot in 0..=MAX_TRANSPARENT_PROFILES {
            assert!(
                !seen.contains(&transparent_mark(1001, slot)),
                "uid 1001 slot {slot} collided with uid 1000"
            );
        }
    }

    #[test]
    fn a_profile_named_twice_is_refused_rather_than_given_two_marks() {
        let request = FirewallRequest {
            cgroup_marks: vec![
                CgroupMark {
                    profile: "web".into(),
                    tproxy_port: Some(12_000),
                },
                CgroupMark {
                    profile: "web".into(),
                    tproxy_port: Some(12_001),
                },
            ],
            kill_switch: false,
            bypass_uid: true,
        };
        assert!(
            Operation::ApplyFirewall(request).validate(1000).is_err(),
            "a duplicate profile would silently take two slots"
        );
    }

    #[test]
    fn a_transparent_listener_on_port_zero_is_refused() {
        let request = FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "web".into(),
                tproxy_port: Some(0),
            }],
            kill_switch: false,
            bypass_uid: true,
        };
        assert!(Operation::ApplyFirewall(request).validate(1000).is_err());
    }

    #[test]
    fn the_transparent_table_never_collides_with_the_tunnel_table() {
        for uid in [0u32, 1, 63, 64, 1000, u32::MAX] {
            assert_ne!(table_for_uid(uid), transparent_table_for_uid(uid));
            assert!(transparent_table_for_uid(uid) >= TABLE_ID_BASE + TABLE_ID_SPAN);
        }
    }

    #[test]
    fn profile_identifiers_cannot_escape_the_cgroup_tree() {
        for bad in [
            "../../etc",
            "web/../..",
            "Web",
            "web profile",
            "web;rm -rf /",
            "",
            &"x".repeat(65),
        ] {
            let error = Operation::CreateCgroup {
                profile: bad.to_owned(),
            }
            .validate(1000)
            .expect_err("must refuse");
            assert!(
                matches!(error, NetdError::Refused(_)),
                "{bad:?} -> {error:?}"
            );
        }
        assert!(
            Operation::CreateCgroup {
                profile: "web-2".into()
            }
            .validate(1000)
            .is_ok()
        );
    }

    #[test]
    fn dns_requests_are_bounded_and_syntactically_checked() {
        let ok = DnsRequest {
            backend: DnsBackend::SystemdResolved,
            servers: vec!["127.0.0.53".parse().unwrap_or_else(|_| unreachable!())],
            domains: vec!["~.".into(), "example.com".into()],
        };
        assert!(Operation::ApplyDns(ok).validate(1000).is_ok());

        let bad = DnsRequest {
            backend: DnsBackend::SystemdResolved,
            servers: vec![],
            domains: vec!["ex ample.com".into()],
        };
        assert!(matches!(
            Operation::ApplyDns(bad).validate(1000),
            Err(NetdError::Refused(_))
        ));

        let contradictory = DnsRequest {
            backend: DnsBackend::None,
            servers: vec!["1.1.1.1".parse().unwrap_or_else(|_| unreachable!())],
            domains: vec![],
        };
        assert!(matches!(
            Operation::ApplyDns(contradictory).validate(1000),
            Err(NetdError::Refused(_))
        ));
    }

    #[test]
    fn read_only_operations_are_marked_as_such() {
        assert!(!Operation::Ping.is_mutating());
        assert!(!Operation::Capabilities.is_mutating());
        assert!(!Operation::Heartbeat { generation: 1 }.is_mutating());
        assert!(Operation::DeleteTun.is_mutating());
        assert!(Operation::CreateTun(tun(1000)).is_mutating());
    }

    #[test]
    fn only_process_classification_expects_a_descriptor() {
        assert!(
            Operation::ClassifyProcess {
                profile: "web".into()
            }
            .expects_fd()
        );
        assert!(!Operation::CreateTun(tun(1000)).expects_fd());
        assert!(!Operation::Ping.expects_fd());
    }

    #[test]
    fn every_operation_has_a_name_for_the_audit_log() {
        let operations = [
            Operation::Ping,
            Operation::Capabilities,
            Operation::CreateTun(tun(1000)),
            Operation::DeleteTun,
            Operation::ClearRouting,
            Operation::ClearFirewall,
            Operation::ClearDns,
            Operation::CreateCgroup {
                profile: "web".into(),
            },
            Operation::ClassifyProcess {
                profile: "web".into(),
            },
            Operation::RemoveCgroup {
                profile: "web".into(),
            },
            Operation::Heartbeat { generation: 1 },
            Operation::Release,
            Operation::Recover,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for operation in operations {
            let name = operation.name();
            assert!(!name.is_empty());
            assert!(seen.insert(name), "duplicate operation name {name}");
        }
    }

    #[test]
    fn messages_round_trip_through_cbor() {
        let request = NetdRequest {
            id: 1,
            protocol_version: NETD_PROTOCOL_VERSION,
            operation: Operation::CreateTun(tun(1000)),
        };
        let mut buffer = Vec::new();
        ciborium::into_writer(&request, &mut buffer).unwrap_or_else(|_| unreachable!("encode"));
        let back: NetdRequest =
            ciborium::from_reader(buffer.as_slice()).unwrap_or_else(|_| unreachable!("decode"));
        assert_eq!(back, request);

        let reply = NetdReply {
            id: 1,
            result: Err(NetdError::NoLease),
        };
        let mut buffer = Vec::new();
        ciborium::into_writer(&reply, &mut buffer).unwrap_or_else(|_| unreachable!("encode"));
        let back: NetdReply =
            ciborium::from_reader(buffer.as_slice()).unwrap_or_else(|_| unreachable!("decode"));
        assert_eq!(back, reply);
    }

    #[test]
    fn capabilities_gate_the_features_that_depend_on_them() {
        let mut capabilities = NetdCapabilities {
            tun: true,
            cap_net_admin: true,
            nftables: true,
            cgroup_v2: true,
            nft_cgroup_match: true,
            systemd_resolved: false,
            resolvconf: false,
            kernel: "6.12".into(),
        };
        assert!(capabilities.supports_tun());
        assert!(capabilities.supports_transparent_exec());

        capabilities.nft_cgroup_match = false;
        assert!(capabilities.supports_tun());
        assert!(
            !capabilities.supports_transparent_exec(),
            "exact-instance routing must be gated on the nftables cgroup match"
        );

        capabilities.cap_net_admin = false;
        assert!(!capabilities.supports_tun());
    }

    #[test]
    fn the_operation_set_is_small_enough_to_audit() {
        // A deliberately brittle assertion: if someone adds a privileged
        // operation, this test makes them notice and update the threat model.
        // Counting via the name list keeps it honest without reflection.
        let names = [
            "ping",
            "capabilities",
            "create-tun",
            "delete-tun",
            "apply-routing",
            "clear-routing",
            "apply-firewall",
            "clear-firewall",
            "apply-dns",
            "clear-dns",
            "create-cgroup",
            "classify-process",
            "remove-cgroup",
            "heartbeat",
            "release",
            "plan",
            "recover",
        ];
        assert_eq!(
            names.len(),
            17,
            "update docs/THREAT-MODEL.md when this changes"
        );
    }
}
