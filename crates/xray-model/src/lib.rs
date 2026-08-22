//! Typed model of the Xray-core JSON configuration.
//!
//! Field names and shapes were taken from `infra/conf` in the pinned Xray tag
//! (see `docs/UPSTREAM-COMPATIBILITY.md`), not from memory. Everything Xray
//! treats as optional is `Option`/`Vec` here and is skipped when empty, so the
//! generated document contains only fields that were deliberately set — that is
//! what makes the output reviewable and byte-stable.
//!
//! Serialisation uses `BTreeMap` and explicit field order rather than
//! `serde_json::Value` maps, so two compilations of the same state produce
//! identical bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Root of an Xray configuration document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct XrayConfig {
    /// Logging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogConfig>,
    /// gRPC commander.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
    /// Statistics collector. Present as an empty object when enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<StatsConfig>,
    /// Buffer and statistics policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
    /// DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// Routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,
    /// Liveness observation for `leastPing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observatory: Option<ObservatoryConfig>,
    /// Concurrent liveness observation for `leastLoad`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "burstObservatory"
    )]
    pub burst_observatory: Option<BurstObservatoryConfig>,
    /// Inbound handlers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Inbound>,
    /// Outbound handlers. Order matters: Xray falls back to the first entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
}

/// Logging configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogConfig {
    /// `debug`, `info`, `warning`, `error` or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loglevel: Option<String>,
    /// Access log path, or `none` to disable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// Error log path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Include DNS query results in the log.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dnsLog")]
    pub dns_log: Option<bool>,
}

/// gRPC commander configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Inbound tag the commander is reachable on.
    pub tag: String,
    /// `host:port` or an absolute path for a Unix socket.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub listen: String,
    /// Enabled services.
    pub services: Vec<String>,
}

/// Statistics collector. Xray expects an empty object.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StatsConfig {}

/// Policy configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Per-user-level policy.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub levels: BTreeMap<String, LevelPolicy>,
    /// System-wide statistics switches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPolicy>,
}

/// Per-level policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LevelPolicy {
    /// Handshake timeout, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<u32>,
    /// Idle timeout, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "connIdle")]
    pub conn_idle: Option<u32>,
    /// Uplink-only timeout, seconds.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "uplinkOnly"
    )]
    pub uplink_only: Option<u32>,
    /// Downlink-only timeout, seconds.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "downlinkOnly"
    )]
    pub downlink_only: Option<u32>,
    /// Per-connection buffer size in KiB.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "bufferSize"
    )]
    pub buffer_size: Option<i32>,
}

/// System statistics switches.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemPolicy {
    /// Count inbound uplink bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "statsInboundUplink"
    )]
    pub stats_inbound_uplink: Option<bool>,
    /// Count inbound downlink bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "statsInboundDownlink"
    )]
    pub stats_inbound_downlink: Option<bool>,
    /// Count outbound uplink bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "statsOutboundUplink"
    )]
    pub stats_outbound_uplink: Option<bool>,
    /// Count outbound downlink bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "statsOutboundDownlink"
    )]
    pub stats_outbound_downlink: Option<bool>,
}

/// DNS configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Servers, in priority order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,
    /// Static hosts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hosts: BTreeMap<String, serde_json::Value>,
    /// Inbound tag used to route DNS queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// `UseIP`, `UseIPv4`, `UseIPv6`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "queryStrategy"
    )]
    pub query_strategy: Option<String>,
    /// Disable the DNS cache.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "disableCache"
    )]
    pub disable_cache: Option<bool>,
    /// Disable falling back to later servers.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "disableFallback"
    )]
    pub disable_fallback: Option<bool>,
    /// Once a domain matched a server-specific rule, do not query unrelated
    /// fallback servers if that resolver fails.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "disableFallbackIfMatch"
    )]
    pub disable_fallback_if_match: Option<bool>,
}

/// A DNS server entry. Serialised as a bare string when only `address` is set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DnsServer {
    /// `"1.1.1.1"` or `"https://dns.example/dns-query"`.
    Simple(String),
    /// Object form with domain scoping.
    Detailed(Box<DnsServerDetail>),
}

/// Object form of a DNS server.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsServerDetail {
    /// Resolver address.
    pub address: String,
    /// Resolver port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Domains this resolver is authoritative for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// Accept only these IP ranges in the answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "expectedIPs")]
    pub expected_ips: Vec<String>,
    /// Reject these IP ranges in the answer.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        rename = "unexpectedIPs"
    )]
    pub unexpected_ips: Vec<String>,
    /// Do not fall through to later servers.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "skipFallback"
    )]
    pub skip_fallback: Option<bool>,
    /// Stop priority matching after this server. Used on the last resolver in
    /// an isolated resolver set so unrelated matching servers cannot join it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "finalQuery"
    )]
    pub final_query: Option<bool>,
    /// Routing tag applied to this resolver's own traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Per-server query strategy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "queryStrategy"
    )]
    pub query_strategy: Option<String>,
    /// Per-server timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeoutMs")]
    pub timeout_ms: Option<u64>,
}

/// Routing configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// `AsIs`, `IPIfNonMatch` or `IPOnDemand`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "domainStrategy"
    )]
    pub domain_strategy: Option<String>,
    /// Ordered rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RoutingRule>,
    /// Balancers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub balancers: Vec<Balancer>,
}

/// A routing rule. Exactly one of `outbound_tag` / `balancer_tag` must be set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Stable identifier used by `RemoveRule` and reported in routing events.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ruleTag")]
    pub rule_tag: Option<String>,
    /// Xray requires this to be `"field"`.
    #[serde(rename = "type")]
    pub rule_type: String,
    /// Destination domains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    /// Destination IPs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
    /// Destination ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Source ports.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "sourcePort"
    )]
    pub source_port: Option<String>,
    /// Source IPs.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "sourceIP")]
    pub source_ip: Vec<String>,
    /// `tcp`, `udp` or `tcp,udp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Sniffed protocols.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    /// Inbound tags this rule applies to.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "inboundTag")]
    pub inbound_tag: Vec<String>,
    /// Local process matchers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process: Vec<String>,
    /// Header attribute matchers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
    /// Outbound to dispatch to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "outboundTag"
    )]
    pub outbound_tag: Option<String>,
    /// Balancer to dispatch to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "balancerTag"
    )]
    pub balancer_tag: Option<String>,
}

impl RoutingRule {
    /// Start a `field` rule with a tag.
    pub fn field(rule_tag: impl Into<String>) -> Self {
        Self {
            rule_tag: Some(rule_tag.into()),
            rule_type: "field".to_owned(),
            ..Default::default()
        }
    }

    /// Set the outbound target.
    #[must_use]
    pub fn to_outbound(mut self, tag: impl Into<String>) -> Self {
        self.outbound_tag = Some(tag.into());
        self.balancer_tag = None;
        self
    }

    /// Set the balancer target.
    #[must_use]
    pub fn to_balancer(mut self, tag: impl Into<String>) -> Self {
        self.balancer_tag = Some(tag.into());
        self.outbound_tag = None;
        self
    }

    /// Whether the rule has a dispatch target, which Xray requires.
    #[must_use]
    pub fn has_target(&self) -> bool {
        self.outbound_tag.is_some() != self.balancer_tag.is_some()
    }

    /// Whether the rule carries no conditions and therefore matches everything.
    #[must_use]
    pub fn is_catch_all(&self) -> bool {
        self.domain.is_empty()
            && self.ip.is_empty()
            && self.port.is_none()
            && self.source_port.is_none()
            && self.source_ip.is_empty()
            && self.network.is_none()
            && self.protocol.is_empty()
            && self.inbound_tag.is_empty()
            && self.process.is_empty()
            && self.attrs.is_empty()
    }
}

/// A balancer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Balancer {
    /// Balancer tag referenced by rules and by `OverrideBalancerTarget`.
    pub tag: String,
    /// Outbound tag **prefixes** that define the candidate set.
    pub selector: Vec<String>,
    /// Strategy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<BalancerStrategy>,
    /// Outbound used when no candidate is alive.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "fallbackTag"
    )]
    pub fallback_tag: Option<String>,
}

/// Balancer strategy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BalancerStrategy {
    /// `random`, `roundRobin`, `leastPing` or `leastLoad`.
    #[serde(rename = "type")]
    pub strategy_type: String,
    /// Strategy-specific settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

/// Observatory for `leastPing`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObservatoryConfig {
    /// Outbound tag prefixes to observe.
    #[serde(rename = "subjectSelector")]
    pub subject_selector: Vec<String>,
    /// URL probed through each subject.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "probeURL")]
    pub probe_url: Option<String>,
    /// Interval such as `"5m"`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "probeInterval"
    )]
    pub probe_interval: Option<String>,
    /// Probe subjects concurrently.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "enableConcurrency"
    )]
    pub enable_concurrency: Option<bool>,
}

/// Burst observatory for `leastLoad`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BurstObservatoryConfig {
    /// Outbound tag prefixes to observe.
    #[serde(rename = "subjectSelector")]
    pub subject_selector: Vec<String>,
    /// Health check settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "pingConfig"
    )]
    pub ping_config: Option<serde_json::Value>,
}

/// An inbound handler.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inbound {
    /// Handler tag.
    pub tag: String,
    /// Listen address. Omitted for TUN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Listen port. Xray ignores it for TUN but requires the key to be absent or 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Protocol name.
    pub protocol: String,
    /// Protocol settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    /// Stream settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "streamSettings"
    )]
    pub stream_settings: Option<StreamSettings>,
    /// Traffic sniffing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<Sniffing>,
}

/// Sniffing configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sniffing {
    /// Whether sniffing runs.
    pub enabled: bool,
    /// Which sniffers to apply.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        rename = "destOverride"
    )]
    pub dest_override: Vec<String>,
    /// Domains excluded from sniffing.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        rename = "domainsExcluded"
    )]
    pub domains_excluded: Vec<String>,
    /// Use the sniffed domain for routing only, not for dialling.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "routeOnly")]
    pub route_only: Option<bool>,
    /// Do not rewrite the destination.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "metadataOnly"
    )]
    pub metadata_only: Option<bool>,
}

/// An outbound handler.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Outbound {
    /// Handler tag. Referenced by rules, balancers and `dialerProxy`.
    pub tag: String,
    /// Protocol name.
    pub protocol: String,
    /// Protocol settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    /// Stream settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "streamSettings"
    )]
    pub stream_settings: Option<StreamSettings>,
    /// Multiplexing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<MuxConfig>,
    /// Source address to send from.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "sendThrough"
    )]
    pub send_through: Option<String>,
}

/// Multiplexing settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MuxConfig {
    /// Whether mux is on.
    pub enabled: bool,
    /// Concurrency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<i16>,
    /// XUDP concurrency.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "xudpConcurrency"
    )]
    pub xudp_concurrency: Option<i16>,
    /// UDP/443 handling.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "xudpProxyUDP443"
    )]
    pub xudp_proxy_udp_443: Option<String>,
}

/// Stream settings shared by inbounds and outbounds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StreamSettings {
    /// Transport name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Security name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// TLS settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "tlsSettings"
    )]
    pub tls_settings: Option<serde_json::Value>,
    /// REALITY settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "realitySettings"
    )]
    pub reality_settings: Option<serde_json::Value>,
    /// RAW transport settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "rawSettings"
    )]
    pub raw_settings: Option<serde_json::Value>,
    /// XHTTP transport settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "xhttpSettings"
    )]
    pub xhttp_settings: Option<serde_json::Value>,
    /// gRPC transport settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "grpcSettings"
    )]
    pub grpc_settings: Option<serde_json::Value>,
    /// WebSocket transport settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "wsSettings"
    )]
    pub ws_settings: Option<serde_json::Value>,
    /// HTTPUpgrade transport settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "httpupgradeSettings"
    )]
    pub httpupgrade_settings: Option<serde_json::Value>,
    /// mKCP transport settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "kcpSettings"
    )]
    pub kcp_settings: Option<serde_json::Value>,
    /// Xray-native Hysteria2 transport settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hysteriaSettings"
    )]
    pub hysteria_settings: Option<serde_json::Value>,
    /// Post-transport obfuscation masks.
    ///
    /// Replaces the mKCP `header`/`seed` fields, which the pinned Xray release
    /// removed outright (`infra/conf/transport_internet.go`:
    /// `PrintRemovedFeatureError("mkcp header & seed", ...)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalmask: Option<serde_json::Value>,
    /// Socket options, including `dialerProxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sockopt: Option<SockOpt>,
}

/// Obfuscation masks applied under the transport.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FinalMask {
    /// Masks applied to TCP transports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp: Vec<Mask>,
    /// Masks applied to UDP transports such as mKCP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp: Vec<Mask>,
}

/// One obfuscation mask.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Mask {
    /// Registered mask identifier, e.g. `header-dtls`, `mkcp-aes128gcm`.
    #[serde(rename = "type")]
    pub mask_type: String,
    /// Mask-specific settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

/// Socket options.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SockOpt {
    /// SO_MARK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<u32>,
    /// TCP fast open.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "tcpFastOpen"
    )]
    pub tcp_fast_open: Option<bool>,
    /// Keep-alive interval in seconds.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "tcpKeepAliveInterval"
    )]
    pub tcp_keep_alive_interval: Option<i32>,
    /// Bind to this interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Address family preference.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "domainStrategy"
    )]
    pub domain_strategy: Option<String>,
    /// Dial this outbound's connection through another outbound.
    ///
    /// This is the chaining primitive; see `docs/XRAY-INTEGRATION.md`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "dialerProxy"
    )]
    pub dialer_proxy: Option<String>,
    /// Transparent-proxy mode for a *listening* socket.
    ///
    /// `"tproxy"` sets `IP_TRANSPARENT`, which is what lets a `dokodemo-door`
    /// inbound accept a connection addressed somewhere else and read the
    /// original destination back off it. Without it the kernel will not complete
    /// the handshake at all, because the accepted socket's local address is an
    /// address this machine does not own — established by experiment, not
    /// assumed; see `docs/UPSTREAM-COMPATIBILITY.md`. `"redirect"` is the
    /// `nat`-based variant and `"off"` disables both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tproxy: Option<String>,
}

/// Serialise a configuration deterministically.
///
/// `serde_json::to_string_pretty` already writes struct fields in declaration
/// order and `BTreeMap` keys in sorted order, so determinism follows from the
/// model definition rather than from a post-processing pass. This function exists
/// so every caller goes through the same formatting.
///
/// # Errors
/// Returns the underlying `serde_json` error if a value cannot be serialised.
pub fn to_pretty_json(config: &XrayConfig) -> Result<String, serde_json::Error> {
    let mut out = serde_json::to_string_pretty(config)?;
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_serialises_to_an_empty_object() {
        let json = to_pretty_json(&XrayConfig::default()).expect("serialise");
        assert_eq!(json.trim(), "{}");
    }

    #[test]
    fn rule_target_is_exclusive() {
        let rule = RoutingRule::field("r").to_outbound("a");
        assert!(rule.has_target());
        let rule = rule.to_balancer("b");
        assert!(rule.has_target());
        assert_eq!(rule.outbound_tag, None);
        let bad = RoutingRule::field("r");
        assert!(!bad.has_target());
    }

    #[test]
    fn optional_fields_are_omitted() {
        let outbound = Outbound {
            tag: "control/direct".into(),
            protocol: "freedom".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&outbound).expect("serialise");
        assert_eq!(json, r#"{"tag":"control/direct","protocol":"freedom"}"#);
    }

    #[test]
    fn serialisation_is_byte_stable() {
        let mut config = XrayConfig::default();
        config.outbounds.push(Outbound {
            tag: "node/a".into(),
            protocol: "vless".into(),
            settings: Some(serde_json::json!({"vnext": []})),
            ..Default::default()
        });
        config.routing = Some(RoutingConfig {
            domain_strategy: Some("AsIs".into()),
            rules: vec![RoutingRule::field("r1").to_outbound("node/a")],
            balancers: vec![],
        });
        let a = to_pretty_json(&config).expect("serialise");
        let b = to_pretty_json(&config).expect("serialise");
        assert_eq!(a, b);
    }

    #[test]
    fn config_round_trips() {
        let config = XrayConfig {
            api: Some(ApiConfig {
                tag: "control/api".into(),
                listen: "127.0.0.1:0".into(),
                services: vec!["HandlerService".into()],
            }),
            ..Default::default()
        };
        let json = to_pretty_json(&config).expect("serialise");
        let back: XrayConfig = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(config, back);
    }

    #[test]
    fn dialer_proxy_is_spelled_the_way_xray_expects() {
        let sockopt = SockOpt {
            dialer_proxy: Some("chain/x/0".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&sockopt).expect("serialise");
        assert_eq!(json, r#"{"dialerProxy":"chain/x/0"}"#);
    }

    #[test]
    fn dns_server_accepts_both_shapes() {
        let simple: DnsServer = serde_json::from_str(r#""1.1.1.1""#).expect("parse");
        assert!(matches!(simple, DnsServer::Simple(_)));
        let detailed: DnsServer =
            serde_json::from_str(r#"{"address":"1.1.1.1","domains":["geosite:cn"]}"#)
                .expect("parse");
        assert!(matches!(detailed, DnsServer::Detailed(_)));
    }

    #[test]
    fn dns_match_fallback_guard_uses_the_upstream_field_name() {
        let dns = DnsConfig {
            disable_fallback_if_match: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_value(&dns).expect("serialise");
        assert_eq!(json["disableFallbackIfMatch"], true);
        assert!(json.get("disable_fallback_if_match").is_none());
    }

    #[test]
    fn dns_priority_terminator_uses_the_upstream_field_name() {
        let server = DnsServerDetail {
            address: "9.9.9.9".into(),
            final_query: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_value(&server).expect("serialise");
        assert_eq!(json["finalQuery"], true);
        assert!(json.get("final_query").is_none());
    }
}
