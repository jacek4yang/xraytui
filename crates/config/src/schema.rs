//! The shape of `config.toml`.
//!
//! Policy entities (nodes, groups, chains, profiles, rules, subscriptions) live
//! in the domain crate and are serialised into their own files; this module
//! covers only the settings that are not part of the routing model.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use xraytui_domain::SystemMode;

use crate::SCHEMA_VERSION;

/// Which upstream release channel a managed Xray install follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseChannel {
    /// Official stable releases only. Prereleases are filtered out.
    #[default]
    Stable,
    /// Includes GitHub prereleases. Never selected implicitly.
    Preview,
}

/// The whole of `config.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigFile {
    /// Schema version; a newer value is refused at load time.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Xray-core settings.
    #[serde(default)]
    pub core: CoreSection,
    /// Daemon runtime behaviour.
    #[serde(default)]
    pub runtime: RuntimeSection,
    /// System TUN settings.
    #[serde(default)]
    pub tun: TunSection,
    /// DNS management.
    #[serde(default)]
    pub dns: DnsSection,
    /// Health probing.
    #[serde(default)]
    pub health: HealthSection,
    /// Subscription fetching limits.
    #[serde(default)]
    pub subscription: SubscriptionSection,
    /// Front-end preferences.
    #[serde(default)]
    pub ui: UiSection,
}

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            core: CoreSection::default(),
            runtime: RuntimeSection::default(),
            tun: TunSection::default(),
            dns: DnsSection::default(),
            health: HealthSection::default(),
            subscription: SubscriptionSection::default(),
            ui: UiSection::default(),
        }
    }
}

impl ConfigFile {
    /// Check values that serde cannot express.
    ///
    /// # Errors
    /// Returns [`crate::ConfigError::Invalid`] with every problem joined.
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        let mut problems = Vec::new();

        if self.tun.mtu < 576 || self.tun.mtu > 9000 {
            problems.push(format!(
                "[tun] mtu {} is outside the usable range 576..=9000",
                self.tun.mtu
            ));
        }
        if !self.tun.ipv4 && !self.tun.ipv6 {
            problems.push("[tun] at least one of ipv4 or ipv6 must be enabled".to_owned());
        }
        if !is_valid_interface_name(&self.tun.name) {
            problems.push(format!(
                "[tun] name {:?} must match ^xraytui[0-9a-z]{{0,8}}$ so the helper can prove ownership",
                self.tun.name
            ));
        }
        if self.health.concurrency == 0 || self.health.concurrency > 64 {
            problems.push(format!(
                "[health] concurrency {} must be between 1 and 64",
                self.health.concurrency
            ));
        }
        if self.health.timeout_ms < 200 {
            problems.push("[health] timeout_ms must be at least 200".to_owned());
        }
        if !self.health.test_url.starts_with("http://")
            && !self.health.test_url.starts_with("https://")
        {
            problems.push("[health] test_url must be an http or https URL".to_owned());
        }
        if self.subscription.max_response_bytes == 0 {
            problems.push("[subscription] max_response_bytes must be non-zero".to_owned());
        }
        if self.subscription.max_nodes == 0 {
            problems.push("[subscription] max_nodes must be non-zero".to_owned());
        }
        if self.subscription.max_redirects > 10 {
            problems.push("[subscription] max_redirects must be at most 10".to_owned());
        }
        if self.core.lan_access && !self.core.lan_access_acknowledged {
            problems.push(
                "[core] lan_access exposes proxy listeners to the network; set \
                 lan_access_acknowledged = true to confirm you understand the risk"
                    .to_owned(),
            );
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(crate::ConfigError::Invalid(problems.join("\n")))
        }
    }
}

/// `^xraytui[0-9a-z]{0,8}$`, checked without pulling in a regex engine.
///
/// The privileged helper derives ownership from the interface name, so it must
/// be impossible for a name to contain a shell metacharacter, a `/`, or an
/// unexpected prefix.
#[must_use]
pub fn is_valid_interface_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("xraytui") else {
        return false;
    };
    // Linux caps interface names at IFNAMSIZ-1 = 15 bytes.
    suffix.len() <= 8
        && name.len() <= 15
        && suffix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// `[core]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreSection {
    /// Path to the Xray binary. Empty means "look it up on PATH".
    #[serde(default)]
    pub binary: String,
    /// Directory containing `geoip.dat`/`geosite.dat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_dir: Option<PathBuf>,
    /// Release channel for managed installs.
    #[serde(default)]
    pub release_channel: ReleaseChannel,
    /// Pin a specific version, e.g. `v26.3.27`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<String>,
    /// Xray log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Ask for a Unix-domain commander socket instead of loopback TCP.
    ///
    /// **Not supported by any released Xray-core to date.** `app/commander`
    /// calls `net.Listen("tcp", listen)` unconditionally, so a filesystem path
    /// makes the core fail to start with "missing port in address". The option
    /// exists so the safer transport can be switched on the day upstream gains
    /// it; until then leave it false and read the residual risk in
    /// `docs/THREAT-MODEL.md`, T1.
    #[serde(default)]
    pub api_unix_socket: bool,
    /// Collect traffic statistics.
    #[serde(default = "crate::schema::default_true")]
    pub stats: bool,
    /// Enable traffic sniffing for routing.
    #[serde(default)]
    pub sniffing: bool,
    /// Allow listeners on non-loopback addresses.
    #[serde(default)]
    pub lan_access: bool,
    /// Explicit acknowledgement required alongside `lan_access`.
    #[serde(default)]
    pub lan_access_acknowledged: bool,
}

fn default_log_level() -> String {
    "warning".to_owned()
}

pub(crate) const fn default_true() -> bool {
    true
}

impl Default for CoreSection {
    fn default() -> Self {
        Self {
            binary: String::new(),
            asset_dir: None,
            release_channel: ReleaseChannel::default(),
            pinned_version: None,
            log_level: default_log_level(),
            api_unix_socket: false,
            stats: true,
            sniffing: false,
            lan_access: false,
            lan_access_acknowledged: false,
        }
    }
}

/// What happens to networking when the core or daemon dies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailurePolicy {
    /// Remove project routes and restore the previous DNS state.
    #[default]
    Restore,
    /// Keep a kill switch in place so traffic cannot fall back to direct.
    Block,
}

/// `[runtime]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSection {
    /// Bring the core up as soon as the daemon starts.
    #[serde(default = "crate::schema::default_true")]
    pub start_core_on_launch: bool,
    /// What to do when the core or daemon dies while TUN is active.
    #[serde(default)]
    pub failure_policy: FailurePolicy,
    /// Restart backoff floor, milliseconds.
    #[serde(default = "default_backoff_min")]
    pub restart_backoff_min_ms: u64,
    /// Restart backoff ceiling, milliseconds.
    #[serde(default = "default_backoff_max")]
    pub restart_backoff_max_ms: u64,
    /// Give up after this many consecutive failed starts.
    #[serde(default = "default_max_restarts")]
    pub max_consecutive_restarts: u32,
    /// How long to wait for the core to become healthy after a start.
    #[serde(default = "default_health_deadline")]
    pub start_health_deadline_ms: u64,
    /// Seconds a netd lease survives without a heartbeat.
    #[serde(default = "default_lease_ttl")]
    pub netd_lease_ttl_secs: u64,
}

const fn default_backoff_min() -> u64 {
    500
}
const fn default_backoff_max() -> u64 {
    60_000
}
const fn default_max_restarts() -> u32 {
    8
}
const fn default_health_deadline() -> u64 {
    15_000
}
const fn default_lease_ttl() -> u64 {
    30
}

impl Default for RuntimeSection {
    fn default() -> Self {
        Self {
            start_core_on_launch: true,
            failure_policy: FailurePolicy::default(),
            restart_backoff_min_ms: default_backoff_min(),
            restart_backoff_max_ms: default_backoff_max(),
            max_consecutive_restarts: default_max_restarts(),
            start_health_deadline_ms: default_health_deadline(),
            netd_lease_ttl_secs: default_lease_ttl(),
        }
    }
}

/// `[tun]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunSection {
    /// Desired system mode at startup.
    #[serde(default)]
    pub mode: SystemMode,
    /// Interface name. Must start with `xraytui`.
    #[serde(default = "default_tun_name")]
    pub name: String,
    /// MTU.
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// Enable IPv4 inside the tunnel.
    #[serde(default = "crate::schema::default_true")]
    pub ipv4: bool,
    /// Enable IPv6 inside the tunnel.
    ///
    /// When false, IPv6 is explicitly blackholed rather than left to leak.
    #[serde(default)]
    pub ipv6: bool,
    /// IPv4 address assigned to the device, CIDR form.
    #[serde(default = "default_tun_ipv4")]
    pub ipv4_address: String,
    /// IPv6 address assigned to the device, CIDR form.
    #[serde(default = "default_tun_ipv6")]
    pub ipv6_address: String,
    /// Send RFC1918 and link-local traffic straight out.
    #[serde(default = "crate::schema::default_true")]
    pub bypass_private_networks: bool,
    /// Extra destination prefixes routed into the tunnel.
    #[serde(default)]
    pub include_cidrs: Vec<String>,
    /// Destination prefixes never routed into the tunnel.
    #[serde(default)]
    pub exclude_cidrs: Vec<String>,
    /// Routing table id. Probed for conflicts before use.
    #[serde(default = "default_table")]
    pub route_table: u32,
    /// Firewall mark. Probed for conflicts before use.
    #[serde(default = "default_fwmark")]
    pub fwmark: u32,
    /// Rule priority for the policy-routing rule.
    #[serde(default = "default_rule_priority")]
    pub rule_priority: u32,
}

fn default_tun_name() -> String {
    "xraytui0".to_owned()
}
const fn default_mtu() -> u32 {
    1500
}
fn default_tun_ipv4() -> String {
    "198.18.0.1/15".to_owned()
}
fn default_tun_ipv6() -> String {
    "fdfe:dcba:9876::1/126".to_owned()
}
const fn default_table() -> u32 {
    0x7261
}
const fn default_fwmark() -> u32 {
    0x7261
}
const fn default_rule_priority() -> u32 {
    17_000
}

impl Default for TunSection {
    fn default() -> Self {
        Self {
            mode: SystemMode::Off,
            name: default_tun_name(),
            mtu: default_mtu(),
            ipv4: true,
            ipv6: false,
            ipv4_address: default_tun_ipv4(),
            ipv6_address: default_tun_ipv6(),
            bypass_private_networks: true,
            include_cidrs: Vec::new(),
            exclude_cidrs: Vec::new(),
            route_table: default_table(),
            fwmark: default_fwmark(),
            rule_priority: default_rule_priority(),
        }
    }
}

/// Which Linux component owns the system resolver configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsManager {
    /// Do not touch system DNS.
    #[default]
    None,
    /// `org.freedesktop.resolve1` over D-Bus.
    SystemdResolved,
    /// The `resolvconf` interface.
    Resolvconf,
    /// Rewrite `/etc/resolv.conf` directly. Requires explicit confirmation.
    Manual,
}

/// `[dns]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsSection {
    /// Which system DNS backend to drive.
    #[serde(default)]
    pub manager: DnsManager,
    /// Required alongside `manager = "manual"`.
    #[serde(default)]
    pub manual_acknowledged: bool,
    /// Configure Xray's DNS module.
    #[serde(default)]
    pub enabled: bool,
    /// Local address the DNS listener binds, when one is needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<SocketAddr>,
    /// Resolvers reached without a proxy.
    #[serde(default = "default_direct_servers")]
    pub direct_servers: Vec<String>,
    /// Resolvers reached through the default profile.
    #[serde(default)]
    pub proxy_servers: Vec<String>,
    /// Domains always resolved by `direct_servers`.
    #[serde(default = "default_direct_domains")]
    pub direct_domains: Vec<String>,
    /// `UseIP`, `UseIPv4` or `UseIPv6`.
    #[serde(default = "default_query_strategy")]
    pub query_strategy: String,
    /// `drop`, `skip` or `reject` for non-A/AAAA queries.
    #[serde(default = "default_non_ip_query")]
    pub non_ip_query: String,
}

fn default_direct_servers() -> Vec<String> {
    vec!["localhost".to_owned()]
}
fn default_direct_domains() -> Vec<String> {
    vec!["geosite:private".to_owned()]
}
fn default_query_strategy() -> String {
    "UseIP".to_owned()
}
fn default_non_ip_query() -> String {
    "drop".to_owned()
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            manager: DnsManager::default(),
            manual_acknowledged: false,
            enabled: false,
            listen: None,
            direct_servers: default_direct_servers(),
            proxy_servers: Vec::new(),
            direct_domains: default_direct_domains(),
            query_strategy: default_query_strategy(),
            non_ip_query: default_non_ip_query(),
        }
    }
}

/// `[health]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthSection {
    /// Run probes automatically.
    #[serde(default = "crate::schema::default_true")]
    pub enabled: bool,
    /// URL fetched through the outbound under test.
    #[serde(default = "default_test_url")]
    pub test_url: String,
    /// Per-probe deadline.
    #[serde(default = "default_health_timeout")]
    pub timeout_ms: u64,
    /// Maximum probes in flight.
    #[serde(default = "default_health_concurrency")]
    pub concurrency: usize,
    /// Seconds between automatic sweeps; `None` disables them.
    #[serde(
        default = "default_health_interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub interval_secs: Option<u64>,
    /// Probe nodes that are not active targets, group candidates or chain hops.
    #[serde(default)]
    pub probe_idle_nodes: bool,
    /// How many results to keep per entity.
    #[serde(default = "default_history")]
    pub history_len: usize,
}

fn default_test_url() -> String {
    "http://cp.cloudflare.com/generate_204".to_owned()
}
const fn default_health_timeout() -> u64 {
    5_000
}
const fn default_health_concurrency() -> usize {
    8
}
const fn default_health_interval() -> Option<u64> {
    Some(300)
}
const fn default_history() -> usize {
    32
}

impl Default for HealthSection {
    fn default() -> Self {
        Self {
            enabled: true,
            test_url: default_test_url(),
            timeout_ms: default_health_timeout(),
            concurrency: default_health_concurrency(),
            interval_secs: default_health_interval(),
            probe_idle_nodes: false,
            history_len: default_history(),
        }
    }
}

/// `[subscription]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionSection {
    /// Hard cap on a response body.
    #[serde(default = "default_max_response")]
    pub max_response_bytes: u64,
    /// Hard cap on nodes produced by one subscription.
    #[serde(default = "default_max_nodes")]
    pub max_nodes: usize,
    /// Redirect limit.
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
    /// Total request deadline.
    #[serde(default = "default_fetch_timeout")]
    pub timeout_ms: u64,
    /// `User-Agent` sent with subscription requests.
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    /// Update every enabled subscription when the daemon starts.
    #[serde(default)]
    pub update_on_start: bool,
}

const fn default_max_response() -> u64 {
    8 * 1024 * 1024
}
const fn default_max_nodes() -> usize {
    10_000
}
const fn default_max_redirects() -> usize {
    5
}
const fn default_fetch_timeout() -> u64 {
    30_000
}
fn default_user_agent() -> String {
    concat!("xraytui/", env!("CARGO_PKG_VERSION")).to_owned()
}

impl Default for SubscriptionSection {
    fn default() -> Self {
        Self {
            max_response_bytes: default_max_response(),
            max_nodes: default_max_nodes(),
            max_redirects: default_max_redirects(),
            timeout_ms: default_fetch_timeout(),
            user_agent: default_user_agent(),
            update_on_start: false,
        }
    }
}

/// `[ui]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UiSection {
    /// Enable mouse capture. Off by default so terminal selection keeps working.
    #[serde(default)]
    pub mouse: bool,
    /// `auto`, `16`, `256`, `truecolor` or `mono`.
    #[serde(default = "default_colour")]
    pub colour: String,
    /// Page opened at startup.
    #[serde(default = "default_start_page")]
    pub start_page: String,
    /// Milliseconds between dashboard refreshes when nothing changes.
    #[serde(default = "default_refresh")]
    pub idle_refresh_ms: u64,
    /// Lines kept in the log view.
    #[serde(default = "default_log_lines")]
    pub log_buffer_lines: usize,
    /// Key overrides, `"action" = "key"`.
    #[serde(default)]
    pub keymap: std::collections::BTreeMap<String, String>,
}

fn default_colour() -> String {
    "auto".to_owned()
}
fn default_start_page() -> String {
    "dashboard".to_owned()
}
const fn default_refresh() -> u64 {
    1_000
}
const fn default_log_lines() -> usize {
    2_000
}

impl Default for UiSection {
    fn default() -> Self {
        Self {
            mouse: false,
            colour: default_colour(),
            start_page: default_start_page(),
            idle_refresh_ms: default_refresh(),
            log_buffer_lines: default_log_lines(),
            keymap: std::collections::BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        ConfigFile::default()
            .validate()
            .expect("defaults must be valid");
    }

    #[test]
    fn defaults_round_trip_through_toml() {
        let config = ConfigFile::default();
        let text = toml::to_string_pretty(&config).expect("serialise");
        let back: ConfigFile = toml::from_str(&text).expect("deserialise");
        assert_eq!(config, back);
    }

    #[test]
    fn an_empty_file_yields_defaults() {
        let config: ConfigFile = toml::from_str("").expect("deserialise");
        assert_eq!(config, ConfigFile::default());
    }

    #[test]
    fn lan_access_requires_acknowledgement() {
        let mut config = ConfigFile::default();
        config.core.lan_access = true;
        let error = config.validate().expect_err("must refuse");
        assert!(
            error.to_string().contains("lan_access_acknowledged"),
            "{error}"
        );
        config.core.lan_access_acknowledged = true;
        config.validate().expect("acknowledged");
    }

    #[test]
    fn interface_names_are_constrained() {
        assert!(is_valid_interface_name("xraytui0"));
        assert!(is_valid_interface_name("xraytui"));
        assert!(is_valid_interface_name("xraytuiabc123"));
        assert!(!is_valid_interface_name("eth0"));
        assert!(!is_valid_interface_name("xraytui-0"));
        assert!(!is_valid_interface_name("xraytui/0"));
        assert!(!is_valid_interface_name("xraytui0123456789"));
        assert!(!is_valid_interface_name("xraytui$(id)"));
    }

    #[test]
    fn bad_mtu_and_empty_address_family_are_rejected() {
        let mut config = ConfigFile::default();
        config.tun.mtu = 100;
        assert!(config.validate().is_err());

        let mut config = ConfigFile::default();
        config.tun.ipv4 = false;
        config.tun.ipv6 = false;
        let error = config.validate().expect_err("must refuse");
        assert!(error.to_string().contains("ipv4 or ipv6"), "{error}");
    }

    #[test]
    fn health_limits_are_bounded() {
        let mut config = ConfigFile::default();
        config.health.concurrency = 0;
        assert!(config.validate().is_err());
        config.health.concurrency = 1000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn all_validation_problems_are_reported_together() {
        let mut config = ConfigFile::default();
        config.tun.mtu = 1;
        config.health.concurrency = 0;
        config.subscription.max_nodes = 0;
        let error = config.validate().expect_err("must refuse").to_string();
        assert!(error.contains("[tun] mtu"), "{error}");
        assert!(error.contains("[health] concurrency"), "{error}");
        assert!(error.contains("[subscription] max_nodes"), "{error}");
    }

    #[test]
    fn defaults_do_not_expose_anything() {
        let config = ConfigFile::default();
        assert!(!config.core.lan_access);
        assert_eq!(config.tun.mode, SystemMode::Off);
        assert_eq!(config.dns.manager, DnsManager::None);
        assert!(!config.ui.mouse);
        // Loopback TCP, because the pinned Xray release cannot serve the
        // commander on a Unix socket.
        assert!(!config.core.api_unix_socket);
    }
}
