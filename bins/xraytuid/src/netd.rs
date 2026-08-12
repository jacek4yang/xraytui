//! The daemon's side of the privilege boundary.
//!
//! Everything privileged happens in `xraytui-netd`. This module builds the
//! request that describes what the user asked for, sends it, holds the
//! resulting lease alive, and gives it back when the mode goes off or the
//! daemon stops.
//!
//! # Two things it deliberately does not do
//!
//! * **It does not decide resource names.** The interface, routing table and
//!   firewall mark are derived by the helper from the connecting credential.
//!   `[tun] name`, `route_table`, `fwmark` and `rule_priority` in the
//!   configuration are advisory; when they disagree with what the helper
//!   derives, the helper wins and the daemon says so once. That is what stops
//!   one user from writing another user's identifiers into their own config.
//! * **It does not fall back.** If the helper is absent, a mode that needs a
//!   system tunnel is refused with a reason. Starting a core whose TUN inbound
//!   nothing routes to would look like it worked and carry no traffic.

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::Mutex;
use xraytui_config::{ConfigFile, DnsManager};
use xraytui_domain::DesiredState;
use xraytui_linux_net::transport::{NetdClient, TransportError};
use xraytui_netd_protocol::{
    CgroupMark, DnsBackend, DnsRequest, FirewallRequest, Operation, Outcome, PlanRequest,
    RoutingRequest, TunRequest,
};

/// Why the system tunnel cannot be brought up.
#[derive(Debug, thiserror::Error)]
pub enum NetdError {
    /// The helper is not running.
    #[error(
        "the privileged helper is not available at {socket}: {detail}. \
         Install and start it with `sudo systemctl enable --now xraytui-netd.service`, \
         or use SOCKS and HTTP listeners, which need no privileges."
    )]
    Unavailable {
        /// Where the daemon looked.
        socket: String,
        /// The underlying reason.
        detail: String,
    },
    /// The helper refused or failed.
    #[error("the privileged helper refused: {0}")]
    Refused(String),
    /// The configuration cannot be turned into a request.
    #[error("{0}")]
    Invalid(String),
}

/// A live claim on the machine's networking.
#[derive(Debug)]
struct Session {
    client: NetdClient,
    /// The TUN descriptor. Never read from or written to: holding it is what
    /// makes this daemon's death visible to the helper immediately, rather than
    /// only when the lease lapses.
    _liveness: Option<OwnedFd>,
    interface: String,
}

/// The daemon's connection to the privileged helper.
#[derive(Debug)]
pub struct Netd {
    socket: PathBuf,
    session: Mutex<Option<Session>>,
}

impl Netd {
    /// Point the daemon at a helper socket. Connects nothing yet.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            session: Mutex::new(None),
        }
    }

    /// The socket this daemon would use.
    #[must_use]
    pub fn socket(&self) -> &std::path::Path {
        &self.socket
    }

    /// Whether a helper answers. Performs no change.
    pub async fn available(&self) -> bool {
        match NetdClient::connect(&self.socket).await {
            Ok(mut client) => client.call(Operation::Ping).await.is_ok(),
            Err(_) => false,
        }
    }

    /// Whether a tunnel is currently held.
    pub async fn is_active(&self) -> bool {
        self.session.lock().await.is_some()
    }

    /// The interface currently held, if any.
    pub async fn interface(&self) -> Option<String> {
        self.session
            .lock()
            .await
            .as_ref()
            .map(|session| session.interface.clone())
    }

    /// Describe what enabling the tunnel would do, without doing any of it.
    ///
    /// Asks the helper when one is reachable, so the answer is the helper's own
    /// account of what it would do. When no helper is present the same pure
    /// planner is used locally and the caller is told, because a user deciding
    /// *whether* to install a privileged helper deserves to read its plan first.
    pub async fn plan(&self, request: &PlanRequest) -> (Vec<String>, String, bool) {
        let uid = rustix::process::getuid().as_raw();
        let script = xraytui_linux_net::plan::firewall_script(uid, request);
        if let Ok(mut client) = NetdClient::connect(&self.socket).await
            && let Ok(Outcome::Plan { steps }) = client
                .call(Operation::Plan(Box::new(request.clone())))
                .await
        {
            return (steps, script, true);
        }
        (xraytui_linux_net::plan::render(uid, request), script, false)
    }

    /// Bring the tunnel up, or explain why it cannot come up.
    ///
    /// Idempotent: establishing while a session is held releases the old one
    /// first, so a configuration change re-applies cleanly.
    ///
    /// # Errors
    /// See [`NetdError`]. Nothing partial is left behind: the helper rolls its
    /// own operations back, and this function releases the lease if a later
    /// step fails.
    pub async fn establish(&self, request: &PlanRequest) -> Result<String, NetdError> {
        self.release().await;

        let mut client =
            NetdClient::connect(&self.socket)
                .await
                .map_err(|error| NetdError::Unavailable {
                    socket: self.socket.display().to_string(),
                    detail: error.to_string(),
                })?;

        let (outcome, descriptors) = client
            .call_with(Operation::CreateTun(request.tun.clone()), &[])
            .await
            .map_err(refused)?;
        let Outcome::TunCreated { interface, .. } = outcome else {
            return Err(NetdError::Refused(
                "the helper answered create-tun with something else".into(),
            ));
        };

        let established = async {
            client
                .call(Operation::ApplyRouting(request.routing.clone()))
                .await?;
            if !request.firewall.cgroup_marks.is_empty() || request.firewall.kill_switch {
                client
                    .call(Operation::ApplyFirewall(request.firewall.clone()))
                    .await?;
            }
            if request.dns.backend != DnsBackend::None {
                client
                    .call(Operation::ApplyDns(request.dns.clone()))
                    .await?;
            }
            Ok::<(), TransportError>(())
        }
        .await;

        if let Err(error) = established {
            // The device exists but the rest does not; giving it back is better
            // than leaving a tunnel nothing routes to.
            let _ = client.call(Operation::Release).await;
            return Err(refused(error));
        }

        tracing::info!(interface, "the privileged helper granted a system tunnel");
        *self.session.lock().await = Some(Session {
            client,
            _liveness: descriptors.into_iter().next(),
            interface: interface.clone(),
        });
        Ok(interface)
    }

    /// Renew the lease. Called on a timer while a tunnel is held.
    pub async fn heartbeat(&self, generation: u64) {
        let mut guard = self.session.lock().await;
        let Some(session) = guard.as_mut() else {
            return;
        };
        if let Err(error) = session
            .client
            .call(Operation::Heartbeat { generation })
            .await
        {
            tracing::warn!(%error, "the helper stopped answering; releasing the tunnel");
            *guard = None;
        }
    }

    /// Give the tunnel back. Safe to call when nothing is held.
    pub async fn release(&self) {
        let Some(mut session) = self.session.lock().await.take() else {
            return;
        };
        match session.client.call(Operation::Release).await {
            Ok(Outcome::Recovered { removed }) => {
                for item in removed {
                    tracing::info!(item, "released");
                }
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "release was not acknowledged"),
        }
        // Dropping the client closes the connection, which is the helper's
        // primary teardown signal even if the message above never arrived.
    }
}

fn refused(error: TransportError) -> NetdError {
    match error {
        TransportError::Refused(reason) => NetdError::Refused(reason.to_string()),
        other => NetdError::Refused(other.to_string()),
    }
}

/// Turn the configuration and desired state into a request for the helper.
///
/// # Errors
/// [`NetdError::Invalid`] if a prefix in the configuration cannot be parsed.
/// Nothing is sent in that case.
pub fn plan_request(
    config: &ConfigFile,
    state: &DesiredState,
    endpoints: Vec<std::net::IpAddr>,
) -> Result<PlanRequest, NetdError> {
    let uid = rustix::process::getuid().as_raw();
    let interface = xraytui_netd_protocol::interface_for_uid(uid);
    if config.tun.name != interface {
        tracing::info!(
            configured = config.tun.name,
            derived = interface,
            "the helper derives the interface name from your credential; \
             [tun] name is advisory"
        );
    }

    let ipv4 = config
        .tun
        .ipv4
        .then(|| parse_prefix("tun.ipv4_address", &config.tun.ipv4_address))
        .transpose()?;
    let ipv6 = config
        .tun
        .ipv6
        .then(|| parse_prefix("tun.ipv6_address", &config.tun.ipv6_address))
        .transpose()?;

    let mut include = Vec::with_capacity(config.tun.include_cidrs.len());
    for text in &config.tun.include_cidrs {
        include.push(parse_prefix("tun.include_cidrs", text)?);
    }
    let mut exclude = Vec::with_capacity(config.tun.exclude_cidrs.len());
    for text in &config.tun.exclude_cidrs {
        exclude.push(parse_prefix("tun.exclude_cidrs", text)?);
    }

    // A cgroup and a mark for each profile an enabled application rule names.
    //
    // The mark is the same for all of them, because one user has one routing
    // table and one tunnel: what the marking decides is *whether* an
    // application's traffic enters the tunnel at all. Which egress it then
    // takes is decided inside Xray, by the same application rules, on the TUN
    // inbound. Per-profile transparent egress — a separate listener per
    // profile, selected by mark — would need a tproxy inbound per profile and
    // is not implemented; see STATUS.md.
    //
    // The mark is derived from the credential, never configured, so two users
    // cannot collide however they write their files.
    let fwmark = xraytui_netd_protocol::fwmark_for_uid(uid);
    let cgroup_marks: Vec<CgroupMark> = state
        .app_rules
        .values()
        .filter(|rule| rule.enabled)
        .filter_map(|rule| match &rule.action {
            xraytui_domain::RuleAction::Profile { id } => Some(id),
            _ => None,
        })
        .filter(|id| state.profiles.contains_key(*id))
        .map(|id| id.as_str().to_owned())
        .collect::<std::collections::BTreeSet<String>>()
        .into_iter()
        .map(|profile| CgroupMark {
            profile,
            mark: fwmark,
        })
        .collect();

    Ok(PlanRequest {
        tun: TunRequest {
            interface,
            mtu: config.tun.mtu,
            ipv4,
            ipv6,
            lease_ttl_secs: config.runtime.netd_lease_ttl_secs,
            failure_policy: failure_policy(config.runtime.failure_policy),
        },
        routing: RoutingRequest {
            include,
            exclude,
            bypass_endpoints: endpoints,
            bypass_private: config.tun.bypass_private_networks,
            // IPv6 that the tunnel does not carry must be discarded rather than
            // left to find its own way out; that is a leak nobody notices until
            // it matters.
            blackhole_ipv6: !config.tun.ipv6,
        },
        firewall: FirewallRequest {
            cgroup_marks,
            kill_switch: failure_policy(config.runtime.failure_policy)
                == xraytui_netd_protocol::FailurePolicy::Block,
            bypass_uid: true,
        },
        dns: DnsRequest {
            backend: match config.dns.manager {
                DnsManager::None | DnsManager::Manual => DnsBackend::None,
                DnsManager::SystemdResolved => DnsBackend::SystemdResolved,
                DnsManager::Resolvconf => DnsBackend::Resolvconf,
            },
            servers: dns_servers(config),
            domains: if matches!(config.dns.manager, DnsManager::None | DnsManager::Manual) {
                Vec::new()
            } else {
                vec!["~.".to_owned()]
            },
        },
    })
}

/// The resolver the system should be pointed at while the tunnel is up.
///
/// When Xray's own DNS module has a listener, that is the answer: queries then
/// follow the same routing rules as everything else. Otherwise nothing is
/// installed, because pointing the system at a resolver that is not listening
/// would break name resolution outright.
fn dns_servers(config: &ConfigFile) -> Vec<std::net::IpAddr> {
    if matches!(config.dns.manager, DnsManager::None | DnsManager::Manual) {
        return Vec::new();
    }
    config
        .dns
        .listen
        .map(|address| vec![address.ip()])
        .unwrap_or_default()
}

/// Translate the user-facing policy into the wire one.
///
/// The two enums are deliberately separate types: one is a word in a TOML file
/// that a person edits, the other is a field in a privileged protocol. The
/// exhaustive match is what keeps them from drifting — adding a policy on
/// either side stops the build here rather than silently mapping to the wrong
/// behaviour.
fn failure_policy(policy: xraytui_config::FailurePolicy) -> xraytui_netd_protocol::FailurePolicy {
    match policy {
        xraytui_config::FailurePolicy::Restore => xraytui_netd_protocol::FailurePolicy::Restore,
        xraytui_config::FailurePolicy::Block => xraytui_netd_protocol::FailurePolicy::Block,
    }
}

fn parse_prefix(field: &str, text: &str) -> Result<ipnet::IpNet, NetdError> {
    text.parse()
        .map_err(|_| NetdError::Invalid(format!("[{field}] is not a valid CIDR prefix: {text:?}")))
}

/// How often to renew a lease of `ttl` seconds.
///
/// A third of the lease: two heartbeats can be lost — to a busy machine, a
/// suspended laptop, a slow disk — before the helper concludes the daemon is
/// gone.
#[must_use]
pub fn heartbeat_interval(ttl_secs: u64) -> Duration {
    Duration::from_secs(ttl_secs.max(3) / 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ConfigFile {
        ConfigFile::default()
    }

    #[test]
    fn resource_names_come_from_the_credential_not_the_configuration() {
        let mut settings = config();
        settings.tun.name = "xraytui9999".into();
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        let uid = rustix::process::getuid().as_raw();
        assert_eq!(
            request.tun.interface,
            xraytui_netd_protocol::interface_for_uid(uid),
            "a configured name must not override the derived one"
        );
    }

    #[test]
    fn a_request_built_from_the_defaults_is_one_the_protocol_accepts() {
        let request =
            plan_request(&config(), &DesiredState::default(), Vec::new()).expect("request");
        let uid = rustix::process::getuid().as_raw();
        Operation::Plan(Box::new(request.clone()))
            .validate(uid)
            .expect("the defaults must produce a valid request");
        Operation::CreateTun(request.tun)
            .validate(uid)
            .expect("the defaults must produce a valid tun request");
    }

    #[test]
    fn ipv6_is_blackholed_exactly_when_the_tunnel_does_not_carry_it() {
        let mut settings = config();
        settings.tun.ipv6 = false;
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        assert!(request.routing.blackhole_ipv6);
        assert!(request.tun.ipv6.is_none());

        settings.tun.ipv6 = true;
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        assert!(!request.routing.blackhole_ipv6);
        assert!(request.tun.ipv6.is_some());
    }

    #[test]
    fn a_malformed_prefix_is_reported_before_anything_is_sent() {
        let mut settings = config();
        settings.tun.include_cidrs = vec!["not-a-prefix".into()];
        let error = plan_request(&settings, &DesiredState::default(), Vec::new())
            .expect_err("must be refused");
        assert!(matches!(error, NetdError::Invalid(_)), "{error:?}");
    }

    #[test]
    fn the_proxy_endpoints_reach_the_request_so_the_core_can_still_dial_out() {
        let endpoint: std::net::IpAddr = "203.0.113.7".parse().expect("address");
        let request =
            plan_request(&config(), &DesiredState::default(), vec![endpoint]).expect("request");
        assert_eq!(request.routing.bypass_endpoints, vec![endpoint]);
    }

    #[test]
    fn the_resolver_is_left_alone_unless_a_backend_and_a_listener_are_both_present() {
        let mut settings = config();
        settings.dns.manager = DnsManager::SystemdResolved;
        settings.dns.listen = None;
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        assert!(
            request.dns.servers.is_empty(),
            "without a listener there is nothing to point the system at"
        );

        settings.dns.listen = Some("127.0.0.1:5353".parse().expect("address"));
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        assert_eq!(
            request.dns.servers,
            vec!["127.0.0.1".parse::<std::net::IpAddr>().expect("address")]
        );
        assert_eq!(request.dns.domains, vec!["~.".to_owned()]);
    }

    #[test]
    fn manual_dns_is_treated_as_none_because_the_helper_will_not_write_resolv_conf() {
        let mut settings = config();
        settings.dns.manager = DnsManager::Manual;
        settings.dns.listen = Some("127.0.0.1:5353".parse().expect("address"));
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        assert_eq!(request.dns.backend, DnsBackend::None);
        assert!(request.dns.servers.is_empty());
    }

    #[test]
    fn the_kill_switch_follows_the_failure_policy() {
        let mut settings = config();
        settings.runtime.failure_policy = xraytui_config::FailurePolicy::Block;
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        assert!(request.firewall.kill_switch);

        settings.runtime.failure_policy = xraytui_config::FailurePolicy::Restore;
        let request =
            plan_request(&settings, &DesiredState::default(), Vec::new()).expect("request");
        assert!(!request.firewall.kill_switch);
    }

    #[test]
    fn the_core_is_always_exempted_from_marking() {
        let request =
            plan_request(&config(), &DesiredState::default(), Vec::new()).expect("request");
        assert!(
            request.firewall.bypass_uid,
            "without this the core would route its own uplink into its own tunnel"
        );
    }

    #[test]
    fn the_two_failure_policies_mean_the_same_thing() {
        assert_eq!(
            failure_policy(xraytui_config::FailurePolicy::Restore),
            xraytui_netd_protocol::FailurePolicy::Restore
        );
        assert_eq!(
            failure_policy(xraytui_config::FailurePolicy::Block),
            xraytui_netd_protocol::FailurePolicy::Block
        );
    }

    #[test]
    fn heartbeats_are_frequent_enough_to_survive_two_losses() {
        assert_eq!(heartbeat_interval(30), Duration::from_secs(10));
        assert_eq!(heartbeat_interval(3), Duration::from_secs(1));
        // A nonsensical TTL must still produce a usable interval.
        assert_eq!(heartbeat_interval(0), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_missing_helper_is_reported_with_something_to_do_about_it() {
        let netd = Netd::new("/nonexistent/netd.sock");
        assert!(!netd.available().await);
        assert!(!netd.is_active().await);
        let request =
            plan_request(&config(), &DesiredState::default(), Vec::new()).expect("request");
        let error = netd.establish(&request).await.expect_err("must fail");
        let text = error.to_string();
        assert!(text.contains("systemctl enable"), "{text}");
        assert!(text.contains("SOCKS"), "{text}");
    }

    #[tokio::test]
    async fn a_plan_is_available_even_without_a_helper_and_says_so() {
        let netd = Netd::new("/nonexistent/netd.sock");
        let request =
            plan_request(&config(), &DesiredState::default(), Vec::new()).expect("request");
        let (steps, script, from_helper) = netd.plan(&request).await;
        assert!(!steps.is_empty());
        assert!(!script.is_empty());
        assert!(!from_helper);
    }

    #[tokio::test]
    async fn releasing_when_nothing_is_held_is_not_an_error() {
        let netd = Netd::new("/nonexistent/netd.sock");
        netd.release().await;
        netd.heartbeat(1).await;
    }
}
