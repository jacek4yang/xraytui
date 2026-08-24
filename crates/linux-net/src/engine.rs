//! Applying one [`Operation`], and undoing it.
//!
//! # The three rules this module keeps
//!
//! 1. **The uid is a parameter, never a field.** Every function here takes the
//!    credential the server read from `SO_PEERCRED`. Nothing in a message can
//!    influence which interface, table, mark or cgroup is touched.
//! 2. **A failed operation leaves nothing behind.** `CreateTun` either produces
//!    a working device or removes what it made and reports
//!    [`NetdError::RolledBack`]. Partial state is the failure mode that turns a
//!    proxy tool into a machine that cannot reach the network.
//! 3. **Teardown only removes what this project created.** Routes and rules are
//!    matched on the project's routing protocol number, chains on their name,
//!    cgroups on their slice. A machine with its own VPN, its own firewall and
//!    its own resolver keeps all three.

use std::path::PathBuf;
use std::sync::Mutex;

use xraytui_netd_protocol::{
    DnsBackend, DnsRequest, FailurePolicy, FirewallRequest, NetdError, Operation, Outcome,
    RoutingRequest, TunRequest,
};

use crate::cgroup::CgroupTree;
use crate::dns::DnsManager;
use crate::lease::{Lease, LeaseStore};
use crate::netlink::message::RTN_THROW;
use crate::netlink::{Netlink, families, ipv6_supported};
use crate::nft::Nft;
use crate::routing::{self, RouteAction};
use crate::{internal, plan, refuse, tun, unsupported};

/// Where the backend looks for the things it drives.
///
/// Every path is injectable so the integration tests can run against a private
/// cgroup mount and a stand-in `nft` without touching the machine they run on.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Root of the cgroup v2 hierarchy.
    pub cgroup_root: PathBuf,
    /// Directory holding lease files.
    pub state_dir: PathBuf,
    /// The `nft` program.
    pub nft: Nft,
    /// The D-Bus system bus socket.
    pub dbus_socket: PathBuf,
    /// The `resolvconf` program.
    pub resolvconf: PathBuf,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            cgroup_root: CgroupTree::detect().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup")),
            state_dir: PathBuf::from(xraytui_netd_protocol::RECOVERY_DIR),
            nft: Nft::default(),
            dbus_socket: crate::dbus::system_bus_path(),
            resolvconf: PathBuf::from("resolvconf"),
        }
    }
}

impl EngineOptions {
    /// Options that touch nothing outside a temporary directory.
    ///
    /// Used by unit tests, which must be runnable by an unprivileged user on a
    /// developer's own machine without changing anything on it.
    #[must_use]
    pub fn for_test() -> Self {
        let base = std::env::temp_dir().join(format!("xraytui-netd-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&base);
        Self {
            cgroup_root: CgroupTree::detect().unwrap_or_else(|| base.join("cgroup")),
            state_dir: base.join("state"),
            nft: Nft::default(),
            dbus_socket: base.join("no-bus"),
            resolvconf: base.join("no-resolvconf"),
        }
    }
}

/// What one operation produced.
#[derive(Debug)]
pub struct Response {
    /// The protocol-level outcome.
    pub outcome: Outcome,
    /// A descriptor to hand back over `SCM_RIGHTS`, if the operation makes one.
    pub descriptor: Option<std::os::fd::OwnedFd>,
}

impl Response {
    /// A response carrying no descriptor.
    #[must_use]
    pub fn plain(outcome: Outcome) -> Self {
        Self {
            outcome,
            descriptor: None,
        }
    }
}

/// The privileged backend.
#[derive(Debug)]
pub struct Engine {
    options: EngineOptions,
    leases: LeaseStore,
    /// Serialises mutation. Netlink, nftables and cgroups are all shared state;
    /// two users' operations interleaving could leave a half-built ruleset.
    guard: Mutex<()>,
}

impl Engine {
    /// Open the backend and its lease store.
    ///
    /// # Errors
    /// [`NetdError::Internal`] if the state directory is unusable.
    pub fn new(options: EngineOptions) -> Result<Self, NetdError> {
        let leases = LeaseStore::open(&options.state_dir).map_err(internal)?;
        Ok(Self {
            options,
            leases,
            guard: Mutex::new(()),
        })
    }

    /// The options this engine was built with.
    #[must_use]
    pub fn options(&self) -> &EngineOptions {
        &self.options
    }

    /// The lease store, for the reaper and for diagnostics.
    #[must_use]
    pub fn leases(&self) -> &LeaseStore {
        &self.leases
    }

    fn cgroups(&self) -> CgroupTree {
        CgroupTree::new(self.options.cgroup_root.clone())
    }

    fn dns(&self) -> DnsManager {
        DnsManager::new(
            self.options.dbus_socket.clone(),
            self.options.resolvconf.clone(),
        )
    }

    fn lease_for(&self, uid: u32) -> Result<Lease, NetdError> {
        self.leases.get(uid).ok_or(NetdError::NoLease)
    }

    /// Apply one operation on behalf of `uid`.
    ///
    /// `descriptor` is whatever arrived over `SCM_RIGHTS`; it is required by
    /// [`Operation::ClassifyProcess`] and ignored otherwise.
    ///
    /// # Errors
    /// See [`NetdError`]. Validation happens first, so a refused request has
    /// changed nothing.
    pub fn handle(
        &self,
        uid: u32,
        operation: &Operation,
        descriptor: Option<std::os::fd::OwnedFd>,
    ) -> Result<Response, NetdError> {
        operation.validate(uid)?;

        // Read-only operations do not contend for the lock.
        match operation {
            Operation::Ping => {
                return Ok(Response::plain(Outcome::Pong {
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    protocol_version: xraytui_netd_protocol::NETD_PROTOCOL_VERSION,
                }));
            }
            Operation::Capabilities => {
                return Ok(Response::plain(Outcome::Capabilities(Box::new(
                    crate::capabilities::probe(&self.options),
                ))));
            }
            Operation::Plan(request) => {
                return Ok(Response::plain(Outcome::Plan {
                    steps: plan::render(uid, request),
                }));
            }
            _ => {}
        }

        let _held = self.guard.lock().map_err(|_| {
            internal("the helper's internal lock was poisoned; restart xraytui-netd")
        })?;

        match operation {
            Operation::Ping | Operation::Capabilities | Operation::Plan(_) => unreachable_handled(),
            Operation::CreateTun(request) => self.create_tun(uid, request),
            Operation::DeleteTun => {
                let removed = self.teardown(uid, TeardownReason::Requested)?;
                Ok(Response::plain(Outcome::Recovered { removed }))
            }
            Operation::ApplyRouting(request) => self.apply_routing(uid, request),
            Operation::ClearRouting => {
                self.clear_routing(uid)?;
                Ok(Response::plain(Outcome::Ack))
            }
            Operation::ApplyFirewall(request) => self.apply_firewall(uid, request),
            Operation::ClearFirewall => {
                self.clear_firewall(uid)?;
                Ok(Response::plain(Outcome::Ack))
            }
            Operation::ApplyDns(request) => self.apply_dns(uid, request),
            Operation::ClearDns => {
                self.clear_dns(uid)?;
                Ok(Response::plain(Outcome::Ack))
            }
            Operation::CreateCgroup { profile } => {
                self.cgroups().create(uid, profile).map_err(internal)?;
                if let Some(mut lease) = self.leases.get(uid) {
                    lease.cgroups.insert(profile.clone());
                    self.leases.put(&lease).map_err(internal)?;
                }
                Ok(Response::plain(Outcome::Ack))
            }
            Operation::ClassifyProcess { profile } => {
                let descriptor = descriptor.ok_or_else(|| {
                    refuse("classify-process needs a pidfd over SCM_RIGHTS; none arrived")
                })?;
                self.cgroups()
                    .classify(uid, profile, std::os::fd::AsFd::as_fd(&descriptor))
                    .map_err(|error| match error {
                        crate::cgroup::CgroupError::NotYours { .. } => {
                            NetdError::Denied(error.to_string())
                        }
                        other => internal(other),
                    })?;
                Ok(Response::plain(Outcome::Ack))
            }
            Operation::RemoveCgroup { profile } => {
                self.cgroups().remove(uid, profile).map_err(internal)?;
                if let Some(mut lease) = self.leases.get(uid) {
                    lease.cgroups.remove(profile);
                    self.leases.put(&lease).map_err(internal)?;
                }
                Ok(Response::plain(Outcome::Ack))
            }
            Operation::Heartbeat { generation } => {
                let mut lease = self.lease_for(uid)?;
                lease.renew(crate::lease::now());
                lease.generation = *generation;
                self.leases.put(&lease).map_err(internal)?;
                Ok(Response::plain(Outcome::Ack))
            }
            Operation::Release => {
                let removed = self.teardown(uid, TeardownReason::Requested)?;
                Ok(Response::plain(Outcome::Recovered { removed }))
            }
            Operation::CoreFailed => {
                let removed = self.teardown(uid, TeardownReason::Failed)?;
                Ok(Response::plain(Outcome::Recovered { removed }))
            }
            Operation::Recover => {
                let removed = self.recover_locked(crate::lease::now());
                Ok(Response::plain(Outcome::Recovered { removed }))
            }
        }
    }

    // --- tun -------------------------------------------------------------

    fn create_tun(&self, uid: u32, request: &TunRequest) -> Result<Response, NetdError> {
        if !tun::device_usable() {
            return Err(unsupported(
                "/dev/net/tun cannot be opened; load the tun module",
            ));
        }
        if !crate::capabilities::has_net_admin() {
            return Err(NetdError::Denied(
                "xraytui-netd is running without CAP_NET_ADMIN".into(),
            ));
        }
        if request.ipv6.is_some() && !crate::capabilities::ipv6_tun_available() {
            return Err(unsupported(
                "IPv6 TUN routing is unavailable because the host kernel has IPv6 disabled. \
                 IPv4 remains available. Check /proc/net/if_inet6 and \
                 /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6",
            ));
        }

        let device = tun::create(&request.interface, uid).map_err(|error| match error {
            tun::TunError::Conflict(resource) => NetdError::Conflict { resource },
            other => internal(other),
        })?;

        // From here on, any failure must undo the device.
        let outcome = (|| -> Result<(u32, u32, u32), NetdError> {
            let netlink = Netlink::open().map_err(internal)?;
            let index = netlink.link_index(&request.interface).map_err(internal)?;
            if let Some(prefix) = request.ipv4 {
                add_address_idempotently(&netlink, index, prefix)?;
            }
            if let Some(prefix) = request.ipv6 {
                add_address_idempotently(&netlink, index, prefix)?;
            }
            netlink.link_up(index, request.mtu).map_err(internal)?;
            Ok((
                index,
                xraytui_netd_protocol::table_for_uid(uid),
                xraytui_netd_protocol::fwmark_for_uid(uid),
            ))
        })();

        let (index, table, fwmark) = match outcome {
            Ok(values) => values,
            Err(error) => {
                self.remove_device(&request.interface);
                return Err(NetdError::RolledBack {
                    operation: "create-tun".into(),
                    detail: error.to_string(),
                });
            }
        };

        let mut lease = Lease::new(
            uid,
            request.interface.clone(),
            request.lease_ttl_secs,
            request.failure_policy,
            crate::lease::now(),
        );
        lease.ipv4 = Some(request.ipv4.is_some());
        lease.ipv6 = Some(request.ipv6.is_some());
        // Preserve anything an earlier lease knew about, so a re-created device
        // does not orphan the cgroups the user already has.
        if let Some(previous) = self.leases.get(uid) {
            lease.cgroups = previous.cgroups;
        }
        if let Err(error) = self.leases.put(&lease) {
            self.remove_device(&request.interface);
            return Err(NetdError::RolledBack {
                operation: "create-tun".into(),
                detail: error.to_string(),
            });
        }

        // A non-multiqueue TUN accepts only one attached descriptor. Xray opens
        // this persistent interface by name, so release the helper's creation
        // descriptor before replying and before the daemon starts Xray.
        drop(device);
        Ok(Response::plain(Outcome::TunCreated {
            interface: request.interface.clone(),
            index,
            table,
            fwmark,
        }))
    }

    fn remove_device(&self, interface: &str) {
        if let Ok(netlink) = Netlink::open()
            && let Ok(index) = netlink.link_index(interface)
        {
            let _ = netlink.link_delete(index);
        }
        // Clearing the persist flag covers the case where the link delete did
        // not take: the device then disappears when the descriptor closes.
        let _ = tun::clear_persist(interface);
    }

    // --- routing ---------------------------------------------------------

    fn apply_routing(&self, uid: u32, request: &RoutingRequest) -> Result<Response, NetdError> {
        let mut lease = self.lease_for(uid)?;
        let netlink = Netlink::open().map_err(internal)?;
        let index = netlink
            .link_index(&lease.interface)
            .map_err(|error| refuse(format!("the tunnel is not up: {error}")))?;

        // v1 lease files predate the explicit family flags. Recover their
        // meaning from the live device instead of interpreting a missing field
        // as `false`, which would break an active tunnel during an upgrade.
        let detected_addresses = if lease.ipv4.is_none() || lease.ipv6.is_none() {
            netlink.addresses_on_link(index).map_err(internal)?
        } else {
            Vec::new()
        };
        let has_v4 = lease.ipv4.unwrap_or_else(|| {
            detected_addresses
                .iter()
                .any(|prefix| prefix.addr().is_ipv4())
        });
        // A kernel with no IPv6 rejects every AF_INET6 message; asking it
        // anyway would turn an ordinary configuration into a rollback.
        let has_v6 = ipv6_supported()
            && lease.ipv6.unwrap_or_else(|| {
                detected_addresses.iter().any(|prefix| {
                    matches!(prefix.addr(), std::net::IpAddr::V6(address) if !address.is_unicast_link_local())
                })
            });

        if let Some(prefix) = request.include.iter().find(|prefix| {
            (prefix.addr().is_ipv4() && !has_v4) || (prefix.addr().is_ipv6() && !has_v6)
        }) {
            return Err(refuse(format!(
                "cannot route included prefix {prefix}: the TUN was not configured for {}",
                if prefix.addr().is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                }
            )));
        }

        // Validate and compute the entire candidate before touching the live
        // table. A contradictory family include must not erase the working
        // routes merely because it was discovered during an update.
        let mut computed = routing::compute(request, has_v4, has_v6);
        if !ipv6_supported() {
            let before = computed.routes.len();
            computed
                .routes
                .retain(|action| action.prefix().addr().is_ipv4());
            if computed.routes.len() != before {
                tracing::info!(
                    dropped = before - computed.routes.len(),
                    "this kernel has no IPv6; leaving the IPv6 half of the plan out"
                );
            }
        }

        // Recompute from scratch every time: the table is ours alone, so
        // emptying it and rebuilding is both simpler and more predictable than
        // diffing, and it makes repeated application idempotent.
        netlink.flush_owned_routes(lease.table).map_err(internal)?;
        for action in &computed.routes {
            let result = match action {
                RouteAction::Tunnel(prefix) => netlink.route_add(lease.table, *prefix, index, true),
                RouteAction::Throw(prefix) => {
                    netlink.route_add_special(lease.table, *prefix, RTN_THROW, true)
                }
                RouteAction::Blackhole(prefix) => {
                    netlink.route_add_blackhole(lease.table, *prefix, true)
                }
            };
            if let Err(error) = result {
                // Undo the partial table rather than leaving a half-routed
                // machine behind.
                let _ = netlink.flush_owned_routes(lease.table);
                return Err(NetdError::RolledBack {
                    operation: "apply-routing".into(),
                    detail: error.to_string(),
                });
            }
        }

        let priority = routing::rule_priority(uid);
        let _ = netlink.flush_rules(&[priority]);
        for family in families() {
            if let Err(error) = netlink.rule_add_fwmark(family, priority, lease.fwmark, lease.table)
                && !error.is_exists()
            {
                let _ = netlink.flush_rules(&[priority]);
                let _ = netlink.flush_owned_routes(lease.table);
                return Err(NetdError::RolledBack {
                    operation: "apply-routing".into(),
                    detail: error.to_string(),
                });
            }
        }

        lease.routing = true;
        self.leases.put(&lease).map_err(internal)?;
        Ok(Response::plain(Outcome::Ack))
    }

    fn clear_routing(&self, uid: u32) -> Result<(), NetdError> {
        let table = xraytui_netd_protocol::table_for_uid(uid);
        let priority = routing::rule_priority(uid);
        let netlink = Netlink::open().map_err(internal)?;
        let _ = netlink.flush_rules(&[priority]);
        let _ = netlink.flush_owned_routes(table);
        if let Some(mut lease) = self.leases.get(uid) {
            lease.routing = false;
            self.leases.put(&lease).map_err(internal)?;
        }
        Ok(())
    }

    // --- firewall --------------------------------------------------------

    fn apply_firewall(&self, uid: u32, request: &FirewallRequest) -> Result<Response, NetdError> {
        let mut lease = self.lease_for(uid)?;
        if !self.options.nft.available() {
            return Err(unsupported("nft is not installed"));
        }
        // Every cgroup the ruleset names must exist before nftables can resolve
        // it to a cgroup id, so create them first.
        let tree = self.cgroups();
        if request.bypass_uid {
            tree.create(uid, crate::cgroup::CORE_PROFILE)
                .map_err(internal)?;
            lease.cgroups.insert(crate::cgroup::CORE_PROFILE.to_owned());
        }
        for entry in &request.cgroup_marks {
            tree.create(uid, &entry.profile).map_err(internal)?;
            lease.cgroups.insert(entry.profile.clone());
        }

        // Rendering can refuse — see `nft::Script` — and when it does, nothing
        // has been asked of the system.
        let script = crate::nft::user_ruleset(uid, &lease.interface, lease.fwmark, request)
            .map_err(|error| refuse(error.to_string()))?;
        self.options
            .nft
            .apply(&script)
            .map_err(|error| NetdError::RolledBack {
                operation: "apply-firewall".into(),
                detail: error.to_string(),
            })?;

        // Traffic redirected to a profile's own listener has to be delivered
        // locally rather than sent anywhere, so each transparent profile gets a
        // policy rule into a table whose only route says "this is for us".
        // Without it the marked packet leaves the machine and the listener
        // never sees it.
        self.apply_transparent_routing(uid, request)?;

        lease.firewall = true;
        self.leases.put(&lease).map_err(internal)?;
        Ok(Response::plain(Outcome::Ack))
    }

    /// Install the local-delivery table and one rule per transparent profile.
    fn apply_transparent_routing(
        &self,
        uid: u32,
        request: &FirewallRequest,
    ) -> Result<(), NetdError> {
        let priority = routing::transparent_rule_priority(uid);
        let table = xraytui_netd_protocol::transparent_table_for_uid(uid);
        let netlink = Netlink::open().map_err(internal)?;

        // Rebuild from scratch so that removing a profile removes its rule.
        let _ = netlink.flush_rules(&[priority]);
        let _ = netlink.flush_owned_routes(table);

        let redirecting: Vec<usize> = request
            .cgroup_marks
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.tproxy_port.is_some())
            .map(|(index, _)| index)
            .collect();
        if redirecting.is_empty() {
            return Ok(());
        }

        // Loopback is index 1 in every namespace, but asking is cheaper than
        // assuming and fails loudly if it is not there.
        let loopback = netlink.link_index("lo").map_err(internal)?;
        netlink
            .route_add_local(table, routing::default_v4(), loopback, true)
            .map_err(internal)?;
        if ipv6_supported() {
            let _ = netlink.route_add_local(table, routing::default_v6(), loopback, true);
        }

        for index in redirecting {
            let mark = xraytui_netd_protocol::transparent_mark(uid, index + 1);
            for family in families() {
                if let Err(error) = netlink.rule_add_fwmark(family, priority, mark, table)
                    && !error.is_exists()
                {
                    let _ = netlink.flush_rules(&[priority]);
                    let _ = netlink.flush_owned_routes(table);
                    return Err(NetdError::RolledBack {
                        operation: "apply-firewall".into(),
                        detail: error.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    fn clear_firewall(&self, uid: u32) -> Result<(), NetdError> {
        if let Ok(netlink) = Netlink::open() {
            let _ = netlink.flush_rules(&[routing::transparent_rule_priority(uid)]);
            let _ =
                netlink.flush_owned_routes(xraytui_netd_protocol::transparent_table_for_uid(uid));
        }
        if self.options.nft.available() {
            let existing = self.options.nft.chains().map_err(internal)?;
            let script = crate::nft::clear_user(uid, &existing).map_err(internal)?;
            self.options.nft.apply(&script).map_err(internal)?;
        }
        if let Some(mut lease) = self.leases.get(uid) {
            lease.firewall = false;
            self.leases.put(&lease).map_err(internal)?;
        }
        Ok(())
    }

    // --- dns -------------------------------------------------------------

    fn apply_dns(&self, uid: u32, request: &DnsRequest) -> Result<Response, NetdError> {
        let mut lease = self.lease_for(uid)?;
        let netlink = Netlink::open().map_err(internal)?;
        let index = netlink
            .link_index(&lease.interface)
            .map_err(|error| refuse(format!("the tunnel is not up: {error}")))?;
        self.dns()
            .apply(&lease.interface, index, request)
            .map_err(|error| NetdError::RolledBack {
                operation: "apply-dns".into(),
                detail: error.to_string(),
            })?;
        lease.dns = request.backend;
        self.leases.put(&lease).map_err(internal)?;
        Ok(Response::plain(Outcome::Ack))
    }

    fn clear_dns(&self, uid: u32) -> Result<(), NetdError> {
        let Some(mut lease) = self.leases.get(uid) else {
            return Ok(());
        };
        if lease.dns != DnsBackend::None {
            let index = Netlink::open()
                .ok()
                .and_then(|netlink| netlink.link_index(&lease.interface).ok())
                .unwrap_or(0);
            self.dns()
                .revert(&lease.interface, index, lease.dns)
                .map_err(internal)?;
        }
        lease.dns = DnsBackend::None;
        self.leases.put(&lease).map_err(internal)?;
        Ok(())
    }

    // --- teardown and recovery -------------------------------------------

    /// Remove everything a uid owns.
    ///
    /// Returns a description of each thing removed, which the CLI prints and
    /// the tests assert on.
    ///
    /// # Errors
    /// [`NetdError::Internal`] only for failures that leave state behind;
    /// anything that was already absent is success.
    pub fn release(&self, uid: u32) -> Result<Vec<String>, NetdError> {
        let _held = self
            .guard
            .lock()
            .map_err(|_| internal("the helper's internal lock was poisoned"))?;
        self.teardown(uid, TeardownReason::Requested)
    }

    /// Apply the configured failure policy when the daemon's authenticated
    /// helper connection disappears without an explicit release.
    ///
    /// # Errors
    /// See [`Self::release`].
    pub fn connection_lost(&self, uid: u32) -> Result<Vec<String>, NetdError> {
        let _held = self
            .guard
            .lock()
            .map_err(|_| internal("the helper's internal lock was poisoned"))?;
        self.teardown(uid, TeardownReason::Failed)
    }

    fn teardown(&self, uid: u32, reason: TeardownReason) -> Result<Vec<String>, NetdError> {
        let mut removed = Vec::new();
        let mut safety_failures = Vec::new();
        let lease = self.leases.get(uid);
        let policy = lease
            .as_ref()
            .map_or(FailurePolicy::Restore, |lease| lease.failure_policy);
        let interface = lease.as_ref().map_or_else(
            || xraytui_netd_protocol::interface_for_uid(uid),
            |lease| lease.interface.clone(),
        );
        let table = xraytui_netd_protocol::table_for_uid(uid);
        let priority = routing::rule_priority(uid);
        let keep_blocking =
            !matches!(reason, TeardownReason::Requested) && policy == FailurePolicy::Block;

        // DNS first: it is the only change that is visible to programs that are
        // not routed through us at all.
        let _ = self.clear_dns(uid);
        if lease
            .as_ref()
            .is_some_and(|lease| lease.dns != DnsBackend::None)
        {
            removed.push(format!("dns configuration for {interface}"));
        }

        if keep_blocking {
            if self.options.nft.available() {
                let blocking = FirewallRequest {
                    mark_all: true,
                    cgroup_marks: Vec::new(),
                    kill_switch: true,
                    bypass_uid: false,
                };
                match crate::nft::user_ruleset(
                    uid,
                    &interface,
                    xraytui_netd_protocol::fwmark_for_uid(uid),
                    &blocking,
                ) {
                    Ok(script) => match self.options.nft.apply(&script) {
                        Ok(()) => removed.push(format!(
                            "nftables reduced to a fail-closed uid guard for uid {uid}"
                        )),
                        Err(error) => safety_failures
                            .push(format!("cannot retain the nftables uid guard: {error}")),
                    },
                    Err(error) => safety_failures.push(format!(
                        "cannot build the fail-closed nftables guard: {error}"
                    )),
                }
            } else {
                safety_failures.push("nftables is unavailable for the retained uid guard".into());
            }
        } else if self.options.nft.available()
            && let Ok(existing) = self.options.nft.chains()
            && let Ok(script) = crate::nft::clear_user(uid, &existing)
            && !script.is_empty()
            && self.options.nft.apply(&script).is_ok()
        {
            removed.push(format!("nftables chains for uid {uid}"));
        }

        match Netlink::open() {
            Ok(netlink) => {
                if let Ok(count) = netlink.flush_owned_routes(table)
                    && count > 0
                {
                    removed.push(format!("{count} routes in table {table}"));
                }

                // The transparent table and its rules go whatever the failure
                // policy is: a local-delivery route with no listener behind it
                // would black-hole traffic in a way nobody could diagnose.
                let transparent_table = xraytui_netd_protocol::transparent_table_for_uid(uid);
                let transparent_priority = routing::transparent_rule_priority(uid);
                if let Ok(count) = netlink.flush_owned_routes(transparent_table)
                    && count > 0
                {
                    removed.push(format!("{count} routes in table {transparent_table}"));
                }
                if let Ok(count) = netlink.flush_rules(&[transparent_priority])
                    && count > 0
                {
                    removed.push(format!(
                        "{count} transparent policy rules at priority {transparent_priority}"
                    ));
                }

                if keep_blocking {
                    // The user asked not to fall back to direct. Leave the rule in
                    // place and make the table discard everything, so traffic stops
                    // rather than silently leaving unprotected.
                    if let Err(error) =
                        netlink.route_add_blackhole(table, routing::default_v4(), true)
                    {
                        safety_failures.push(format!(
                            "cannot install the retained IPv4 blackhole in table {table}: {error}"
                        ));
                    }
                    if ipv6_supported()
                        && let Err(error) =
                            netlink.route_add_blackhole(table, routing::default_v6(), true)
                    {
                        safety_failures.push(format!(
                            "cannot install the retained IPv6 blackhole in table {table}: {error}"
                        ));
                    }
                    if safety_failures.is_empty() {
                        removed.push(format!(
                            "table {table} left blackholed by the kill-switch policy"
                        ));
                    }
                } else if let Ok(count) = netlink.flush_rules(&[priority])
                    && count > 0
                {
                    removed.push(format!("{count} policy rules at priority {priority}"));
                }

                if let Ok(index) = netlink.link_index(&interface) {
                    let _ = netlink.link_down(index);
                    if netlink.link_delete(index).is_ok() {
                        removed.push(format!("interface {interface}"));
                    }
                }
            }
            Err(error) if keep_blocking => safety_failures.push(format!(
                "cannot open netlink to retain the policy-table blackholes: {error}"
            )),
            Err(_) => {}
        }
        let _ = tun::clear_persist(&interface);

        if let Ok(groups) = self.cgroups().remove_user(uid) {
            removed.extend(groups.into_iter().map(|path| format!("cgroup {path}")));
        }

        if keep_blocking {
            // Retain the policy after the device is gone. This lets a live
            // daemon re-create the TUN on the same authenticated connection,
            // and lets a later connection-loss event preserve block policy
            // instead of defaulting to restore because the record vanished.
            // Once an expired owner has been handled, park the record so the
            // periodic reaper does not repeat the same teardown forever.
            if let Some(mut blocked) = lease {
                blocked.routing = true;
                blocked.firewall = true;
                blocked.dns = DnsBackend::None;
                if reason == TeardownReason::LeaseExpired {
                    blocked.expires_at = u64::MAX;
                }
                self.leases.put(&blocked).map_err(internal)?;
            }
        } else {
            self.leases.remove(uid).map_err(internal)?;
        }
        if !safety_failures.is_empty() {
            return Err(internal(format!(
                "failure policy could not be made fail-closed: {}",
                safety_failures.join("; ")
            )));
        }
        Ok(removed)
    }

    /// Remove state whose owner is gone.
    ///
    /// Two kinds of orphan are collected: leases past their deadline, and
    /// interfaces carrying the project prefix that no lease claims — the
    /// residue of a helper that was killed before it could tidy up.
    #[must_use]
    pub fn recover(&self, now: u64) -> Vec<String> {
        let Ok(_held) = self.guard.lock() else {
            return vec![
                "recovery skipped because the helper mutation lock is poisoned".to_owned(),
            ];
        };
        self.recover_locked(now)
    }

    /// Recovery while the caller holds `guard` (as every typed operation does).
    fn recover_locked(&self, now: u64) -> Vec<String> {
        let mut removed = Vec::new();
        for lease in self.leases.expired(now) {
            if let Ok(mut cleaned) = self.teardown(lease.uid, TeardownReason::LeaseExpired) {
                removed.push(format!("expired lease for uid {}", lease.uid));
                removed.append(&mut cleaned);
            }
        }

        let claimed: std::collections::BTreeSet<String> = self
            .leases
            .all()
            .into_iter()
            .map(|lease| lease.interface)
            .collect();
        if let Ok(netlink) = Netlink::open()
            && let Ok(links) = netlink.links_with_prefix("xraytui")
        {
            for (name, index) in links {
                if claimed.contains(&name) {
                    continue;
                }
                if netlink.link_delete(index).is_ok() {
                    removed.push(format!("orphaned interface {name}"));
                }
                let _ = tun::clear_persist(&name);
            }
        }
        if let Ok(groups) = self.cgroups().remove_empty_owned() {
            removed.extend(
                groups
                    .into_iter()
                    .map(|path| format!("empty cgroup {path}")),
            );
        }
        removed
    }
}

/// Why teardown is happening, which decides whether the kill switch stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TeardownReason {
    /// The owner asked.
    Requested,
    /// The owner stopped answering.
    LeaseExpired,
    /// The live owner reported that its core or activation path failed.
    Failed,
}

fn add_address_idempotently(
    netlink: &Netlink,
    index: u32,
    prefix: ipnet::IpNet,
) -> Result<(), NetdError> {
    match netlink.address_add(index, prefix) {
        Ok(()) => Ok(()),
        // A device adopted from a previous run already has its address.
        Err(error) if error.is_exists() => Ok(()),
        Err(error) => Err(internal(error)),
    }
}

fn unreachable_handled() -> Result<Response, NetdError> {
    Err(internal(
        "a read-only operation reached the mutating path; this is a bug",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut options = EngineOptions::for_test();
        options.state_dir = dir.path().join("state");
        options.cgroup_root = dir.path().join("cgroup");
        options.nft = Nft::new(dir.path().join("no-nft"));
        let engine = Engine::new(options).expect("engine");
        (dir, engine)
    }

    fn tun_request(uid: u32) -> TunRequest {
        TunRequest {
            interface: xraytui_netd_protocol::interface_for_uid(uid),
            mtu: 1500,
            ipv4: "198.18.0.1/15".parse().ok(),
            ipv6: None,
            lease_ttl_secs: 30,
            failure_policy: FailurePolicy::Restore,
        }
    }

    #[test]
    fn ping_reports_the_helper_version_and_protocol() {
        let (_guard, engine) = engine();
        let response = engine.handle(1000, &Operation::Ping, None).expect("ping");
        match response.outcome {
            Outcome::Pong {
                version,
                protocol_version,
            } => {
                assert_eq!(version, env!("CARGO_PKG_VERSION"));
                assert_eq!(
                    protocol_version,
                    xraytui_netd_protocol::NETD_PROTOCOL_VERSION
                );
            }
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[test]
    fn a_request_naming_another_users_interface_is_denied_before_anything_happens() {
        let (_guard, engine) = engine();
        let mut request = tun_request(1000);
        request.interface = xraytui_netd_protocol::interface_for_uid(1001);
        let error = engine
            .handle(1000, &Operation::CreateTun(request), None)
            .expect_err("must be denied");
        assert!(matches!(error, NetdError::Denied(_)), "{error:?}");
        assert!(engine.leases().get(1000).is_none());
    }

    #[test]
    fn operations_that_need_a_lease_say_so_rather_than_guessing() {
        let (_guard, engine) = engine();
        for operation in [
            Operation::ApplyRouting(RoutingRequest {
                include: Vec::new(),
                exclude: Vec::new(),
                bypass_endpoints: Vec::new(),
                bypass_private: false,
                blackhole_ipv4: false,
                blackhole_ipv6: false,
            }),
            Operation::ApplyFirewall(FirewallRequest {
                mark_all: false,
                cgroup_marks: Vec::new(),
                kill_switch: false,
                bypass_uid: false,
            }),
            Operation::ApplyDns(DnsRequest {
                backend: DnsBackend::Resolvconf,
                servers: Vec::new(),
                domains: Vec::new(),
            }),
            Operation::Heartbeat { generation: 1 },
        ] {
            let error = engine
                .handle(1000, &operation, None)
                .expect_err("no lease yet");
            assert!(
                matches!(error, NetdError::NoLease),
                "{} gave {error:?}",
                operation.name()
            );
        }
    }

    #[test]
    fn planning_produces_steps_without_a_lease_or_a_device() {
        let (_guard, engine) = engine();
        let request = xraytui_netd_protocol::PlanRequest {
            tun: tun_request(1000),
            routing: RoutingRequest {
                include: Vec::new(),
                exclude: Vec::new(),
                bypass_endpoints: Vec::new(),
                bypass_private: true,
                blackhole_ipv4: false,
                blackhole_ipv6: false,
            },
            firewall: FirewallRequest {
                mark_all: false,
                cgroup_marks: Vec::new(),
                kill_switch: false,
                bypass_uid: true,
            },
            dns: DnsRequest {
                backend: DnsBackend::None,
                servers: Vec::new(),
                domains: Vec::new(),
            },
        };
        let response = engine
            .handle(1000, &Operation::Plan(Box::new(request)), None)
            .expect("plan");
        match response.outcome {
            Outcome::Plan { steps } => assert!(!steps.is_empty()),
            other => panic!("unexpected outcome {other:?}"),
        }
        assert!(engine.leases().get(1000).is_none());
    }

    #[test]
    fn classify_without_a_descriptor_is_refused() {
        let (_guard, engine) = engine();
        let error = engine
            .handle(
                1000,
                &Operation::ClassifyProcess {
                    profile: "work".into(),
                },
                None,
            )
            .expect_err("needs a pidfd");
        assert!(matches!(error, NetdError::Refused(_)), "{error:?}");
    }

    #[test]
    fn a_capability_report_never_fails() {
        let (_guard, engine) = engine();
        let response = engine
            .handle(1000, &Operation::Capabilities, None)
            .expect("capabilities");
        assert!(matches!(response.outcome, Outcome::Capabilities(_)));
    }

    #[test]
    fn clearing_state_that_was_never_created_is_not_an_error() {
        let (_guard, engine) = engine();
        for operation in [
            Operation::ClearRouting,
            Operation::ClearFirewall,
            Operation::ClearDns,
        ] {
            // Netlink may be unavailable to an unprivileged test runner; either
            // way, the operation must not report a failure the user can do
            // nothing about.
            let result = engine.handle(1000, &operation, None);
            assert!(
                result.is_ok() || matches!(result, Err(NetdError::Internal(_))),
                "{} gave {result:?}",
                operation.name()
            );
        }
    }

    #[test]
    fn a_release_with_nothing_to_release_removes_nothing_and_succeeds() {
        let (_guard, engine) = engine();
        let removed = engine.release(31_337).expect("release");
        assert!(
            removed
                .iter()
                .all(|item| !item.contains("interface xraytui31337")),
            "{removed:?}"
        );
    }
}
