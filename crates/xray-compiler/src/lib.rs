//! Deterministic compilation of [`DesiredState`] into an Xray configuration.
//!
//! The compiler is a pure function: same input, same bytes out. It performs no
//! I/O, reads no environment, and never consults the running core. That is what
//! makes generation diffing, last-known-good rollback and snapshot testing work.
//!
//! # The shape of the output
//!
//! ```text
//! outbounds[0] = control/block      (blackhole — first, so truncation fails closed)
//! outbounds[1] = control/direct     (freedom)
//! outbounds[2] = control/dns        (dns)
//!              + node/<id>/out                  one per compilable node
//!              + chain/<id>/hop<n>              one per hop, linked by dialerProxy
//!              + chain/<id>/terminal            alias for the exit hop
//!              + group/<id>/entry               loopback into stage two
//!
//! balancers    = group/<id>/balancer            candidate set = group members
//!              + profile/<id>/selector          candidate set = the configured
//!                                               target; runtime overrides move it
//! ```
//!
//! # Why profiles are balancers
//!
//! `RoutingService.OverrideBalancerTarget` sets a balancer's target directly and
//! **is not validated against the selector** (verified in
//! `app/router/balancing_override.go`: `PickOutbound` returns the override before
//! consulting the strategy). So one RPC repoints a profile at any outbound with
//! no restart and no effect on other profiles. The selector still lists the
//! *configured* target so that a core which starts before overrides are re-applied
//! routes according to the saved configuration rather than randomly.
//!
//! # Prefix safety
//!
//! Balancer selectors are prefix matches. `node/hk` would therefore also select
//! `node/hk-01`. Every selectable tag consequently ends in a fixed final segment
//! (`/out`, `/terminal`, `/entry`), which makes the tag set prefix-free. This is
//! a deliberate deviation from the tag names suggested in the specification and is
//! recorded in `DECISIONS.md` (D-014).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod outbound;
pub mod tags;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use xraytui_domain::{
    AppMatcher, ChainId, DesiredState, GroupId, GroupStrategy, KillSwitch, ListenerSpec, NodeId,
    ProfileId, RuleAction, Severity, SystemMode, Target,
};
use xraytui_xray_model::{
    ApiConfig, Balancer, BalancerStrategy, BurstObservatoryConfig, DnsConfig, DnsServer,
    DnsServerDetail, Inbound,
    LevelPolicy, LogConfig, ObservatoryConfig, Outbound, PolicyConfig, RoutingConfig, RoutingRule,
    Sniffing, StatsConfig, SystemPolicy, XrayConfig,
};

/// Why compilation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// The desired state did not validate.
    #[error("configuration is not valid: {0}")]
    Invalid(String),
    /// A node could not be represented as an Xray outbound.
    #[error("node '{node}' cannot be compiled: {reason}")]
    UnsupportedNode {
        /// Node identifier.
        node: String,
        /// Explanation.
        reason: String,
    },
    /// A chain could not be linked.
    #[error("chain '{chain}' cannot be compiled: {reason}")]
    UnsupportedChain {
        /// Chain identifier.
        chain: String,
        /// Explanation.
        reason: String,
    },
    /// The generated tag set was not prefix-free.
    ///
    /// This is an internal invariant violation, reported rather than ignored
    /// because the consequence would be a balancer silently selecting the wrong
    /// outbound.
    #[error("internal tag collision: {0}")]
    TagCollision(String),
    /// Serialising the configuration failed.
    #[error("failed to serialise configuration: {0}")]
    Serialize(String),
}

/// Knobs the daemon supplies that are not part of the user's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileOptions {
    /// Where the gRPC commander listens. `host:port` or an absolute socket path.
    pub api_listen: String,
    /// Xray log level.
    pub log_level: String,
    /// Access log path, or `None` for "none".
    pub access_log: Option<String>,
    /// Error log path.
    pub error_log: Option<String>,
    /// TUN interface name, when a TUN inbound should be emitted.
    pub tun: Option<TunOptions>,
    /// DNS settings.
    pub dns: DnsOptions,
    /// Skip private-network traffic in TUN modes.
    pub bypass_private_networks: bool,
    /// Enable traffic statistics collection.
    pub stats: bool,
    /// Probe URL used by the observatory when a group needs liveness data.
    pub observatory_probe_url: String,
    /// Observatory probe interval, e.g. `"5m"`.
    pub observatory_probe_interval: String,
    /// Sniff destination for routing. Disabled by default because it inspects
    /// the first bytes of a connection; see `docs/NETWORKING.md`.
    pub sniffing: SniffingOptions,
}

/// TUN inbound options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunOptions {
    /// Interface name; must already exist and be owned by this user.
    pub name: String,
    /// MTU.
    pub mtu: u32,
}

/// Sniffing options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SniffingOptions {
    /// Whether sniffing runs at all.
    pub enabled: bool,
    /// Which sniffers to apply.
    pub dest_override: Vec<String>,
    /// Use the sniffed name for routing only, never to rewrite the destination.
    pub route_only: bool,
}

/// DNS compilation options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOptions {
    /// Whether Xray's DNS module is configured at all.
    pub enabled: bool,
    /// Resolvers reached without a proxy.
    pub direct_servers: Vec<String>,
    /// Resolvers reached through the default profile.
    pub proxy_servers: Vec<String>,
    /// Domains resolved by the direct servers regardless of order.
    pub direct_domains: Vec<String>,
    /// `UseIP`, `UseIPv4` or `UseIPv6`.
    pub query_strategy: String,
    /// Local listener for the system resolver, when one is needed.
    pub listen: Option<std::net::SocketAddr>,
    /// Behaviour for non-A/AAAA queries: `drop`, `skip` or `reject`.
    pub non_ip_query: String,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            direct_servers: vec!["localhost".into()],
            proxy_servers: Vec::new(),
            direct_domains: Vec::new(),
            query_strategy: "UseIP".into(),
            listen: None,
            non_ip_query: "drop".into(),
        }
    }
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            api_listen: "127.0.0.1:0".into(),
            log_level: "warning".into(),
            access_log: None,
            error_log: None,
            tun: None,
            dns: DnsOptions::default(),
            bypass_private_networks: true,
            stats: true,
            observatory_probe_url: "https://www.gstatic.com/generate_204".into(),
            observatory_probe_interval: "5m".into(),
            sniffing: SniffingOptions::default(),
        }
    }
}

/// The result of a successful compilation.
#[derive(Debug, Clone, PartialEq)]
pub struct Compiled {
    /// The configuration document.
    pub config: XrayConfig,
    /// Selector overrides the daemon must apply after every core start, in
    /// deterministic order: `(balancer tag, target outbound tag)`.
    pub selector_overrides: Vec<(String, String)>,
    /// Listener addresses per profile, for health checks and for the UI.
    pub listeners: BTreeMap<ProfileId, ProfileListeners>,
    /// Every tag the generation owns, for ownership checks against a live core.
    pub owned_tags: BTreeSet<String>,
    /// Non-fatal notes produced while compiling.
    pub warnings: Vec<String>,
}

/// Bound addresses for one profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileListeners {
    /// SOCKS5 listener address.
    pub socks: Option<std::net::SocketAddr>,
    /// HTTP CONNECT listener address.
    pub http: Option<std::net::SocketAddr>,
    /// Transparent listener address, when the profile opted into one.
    pub transparent: Option<std::net::SocketAddr>,
}

impl Compiled {
    /// Render the configuration as pretty JSON with a trailing newline.
    ///
    /// # Errors
    /// Returns [`CompileError::Serialize`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, CompileError> {
        xraytui_xray_model::to_pretty_json(&self.config)
            .map_err(|e| CompileError::Serialize(e.to_string()))
    }
}

/// Compile desired state into an Xray configuration.
///
/// # Errors
/// Returns [`CompileError::Invalid`] when validation produced errors, or a more
/// specific variant when a particular entity could not be represented.
pub fn compile(state: &DesiredState, options: &CompileOptions) -> Result<Compiled, CompileError> {
    let diagnostics = state.validate();
    let errors: Vec<String> = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| format!("[{}] {}", d.code, d.message))
        .collect();
    if !errors.is_empty() {
        return Err(CompileError::Invalid(errors.join("; ")));
    }
    let mut warnings: Vec<String> = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| format!("[{}] {}", d.code, d.message))
        .collect();

    let mut builder = Builder::new(state, options);
    builder.build_outbounds()?;
    builder.build_balancers();
    builder.build_inbounds();
    builder.build_rules();
    builder.check_prefix_safety()?;
    warnings.append(&mut builder.warnings);

    let config = XrayConfig {
        log: Some(LogConfig {
            loglevel: Some(options.log_level.clone()),
            access: Some(options.access_log.clone().unwrap_or_else(|| "none".into())),
            error: options.error_log.clone(),
            dns_log: None,
        }),
        api: Some(ApiConfig {
            tag: tags::INBOUND_API.to_owned(),
            listen: options.api_listen.clone(),
            services: vec![
                "HandlerService".into(),
                "LoggerService".into(),
                "RoutingService".into(),
                "StatsService".into(),
            ],
        }),
        stats: options.stats.then(StatsConfig::default),
        policy: options.stats.then(stats_policy),
        dns: builder.dns,
        routing: Some(RoutingConfig {
            domain_strategy: Some("IPIfNonMatch".into()),
            rules: builder.rules,
            balancers: builder.balancers,
        }),
        observatory: builder.observatory,
        burst_observatory: builder.burst_observatory,
        inbounds: builder.inbounds,
        outbounds: builder.outbounds,
    };

    Ok(Compiled {
        config,
        selector_overrides: builder.selector_overrides,
        listeners: builder.listeners,
        owned_tags: builder.owned_tags,
        warnings,
    })
}

fn stats_policy() -> PolicyConfig {
    let mut levels = BTreeMap::new();
    levels.insert(
        "0".to_owned(),
        LevelPolicy { handshake: Some(4), conn_idle: Some(300), ..Default::default() },
    );
    PolicyConfig {
        levels,
        system: Some(SystemPolicy {
            stats_inbound_uplink: Some(true),
            stats_inbound_downlink: Some(true),
            stats_outbound_uplink: Some(true),
            stats_outbound_downlink: Some(true),
        }),
    }
}

struct Builder<'a> {
    state: &'a DesiredState,
    options: &'a CompileOptions,
    outbounds: Vec<Outbound>,
    balancers: Vec<Balancer>,
    inbounds: Vec<Inbound>,
    rules: Vec<RoutingRule>,
    dns: Option<DnsConfig>,
    observatory: Option<ObservatoryConfig>,
    burst_observatory: Option<BurstObservatoryConfig>,
    selector_overrides: Vec<(String, String)>,
    listeners: BTreeMap<ProfileId, ProfileListeners>,
    owned_tags: BTreeSet<String>,
    selectable_tags: BTreeSet<String>,
    warnings: Vec<String>,
}

impl<'a> Builder<'a> {
    fn new(state: &'a DesiredState, options: &'a CompileOptions) -> Self {
        Self {
            state,
            options,
            outbounds: Vec::new(),
            balancers: Vec::new(),
            inbounds: Vec::new(),
            rules: Vec::new(),
            dns: None,
            observatory: None,
            burst_observatory: None,
            selector_overrides: Vec::new(),
            listeners: BTreeMap::new(),
            owned_tags: BTreeSet::new(),
            selectable_tags: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    fn own(&mut self, tag: &str) {
        self.owned_tags.insert(tag.to_owned());
    }

    // ---------------------------------------------------------------- outbounds

    fn build_outbounds(&mut self) -> Result<(), CompileError> {
        // Blackhole first: if Xray ever falls back to "the first outbound", the
        // safe answer is to drop, never to leak.
        self.outbounds.push(Outbound {
            tag: tags::CONTROL_BLOCK.into(),
            protocol: "blackhole".into(),
            settings: Some(json!({ "response": { "type": "none" } })),
            ..Default::default()
        });
        self.own(tags::CONTROL_BLOCK);

        self.outbounds.push(Outbound {
            tag: tags::CONTROL_DIRECT.into(),
            protocol: "freedom".into(),
            settings: Some(json!({ "domainStrategy": "UseIP" })),
            ..Default::default()
        });
        self.own(tags::CONTROL_DIRECT);
        self.selectable_tags.insert(tags::CONTROL_DIRECT.to_owned());
        self.selectable_tags.insert(tags::CONTROL_BLOCK.to_owned());

        if self.options.dns.enabled {
            self.outbounds.push(Outbound {
                tag: tags::CONTROL_DNS.into(),
                protocol: "dns".into(),
                settings: Some(json!({ "nonIPQuery": self.options.dns.non_ip_query })),
                ..Default::default()
            });
            self.own(tags::CONTROL_DNS);
        }

        // Nodes. BTreeMap iteration keeps this deterministic.
        for (id, node) in &self.state.nodes {
            if !node.is_compilable() {
                continue;
            }
            let tag = tags::node(id);
            let built = outbound::build(node, &tag, None)?;
            self.own(&tag);
            self.selectable_tags.insert(tag);
            self.outbounds.push(built);
        }

        // Chains: hop n dials through hop n-1, terminal is the last hop.
        for (id, chain) in &self.state.chains {
            if !chain.enabled {
                continue;
            }
            let chain_errors = self.state.validate_chain(id);
            if !chain_errors.is_empty() {
                return Err(CompileError::UnsupportedChain {
                    chain: id.to_string(),
                    reason: chain_errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; "),
                });
            }
            let mut previous: Option<String> = None;
            for (index, hop) in chain.hops.iter().enumerate() {
                let node = self.state.nodes.get(hop).ok_or_else(|| {
                    CompileError::UnsupportedChain {
                        chain: id.to_string(),
                        reason: format!("hop '{hop}' disappeared during compilation"),
                    }
                })?;
                let is_terminal = Some(index) == chain.terminal_index();
                let tag = if is_terminal {
                    tags::chain_terminal(id)
                } else {
                    tags::chain_hop(id, index)
                };
                let built = outbound::build(node, &tag, previous.as_deref())?;
                self.own(&tag);
                if is_terminal {
                    self.selectable_tags.insert(tag.clone());
                }
                self.outbounds.push(built);
                previous = Some(tag);
            }
        }

        // Group entries: a loopback outbound that re-enters routing.
        for id in self.state.groups.keys() {
            let tag = tags::group_entry(id);
            self.outbounds.push(Outbound {
                tag: tag.clone(),
                protocol: "loopback".into(),
                settings: Some(json!({ "inboundTag": tag })),
                ..Default::default()
            });
            self.own(&tag);
            self.selectable_tags.insert(tag);
        }

        Ok(())
    }

    /// The concrete outbound tag a target resolves to.
    fn target_tag(&self, target: &Target) -> String {
        match target {
            Target::Node { id } => tags::node(id),
            Target::Chain { id } => tags::chain_terminal(id),
            Target::Group { id } => tags::group_entry(id),
            Target::Direct => tags::CONTROL_DIRECT.to_owned(),
            Target::Block => tags::CONTROL_BLOCK.to_owned(),
        }
    }

    // ---------------------------------------------------------------- balancers

    fn build_balancers(&mut self) {
        // Upstream requires a liveness feature whenever a balancer carries a
        // `fallbackTag` — `RandomStrategy::InjectContext` and
        // `RoundRobinStrategy::InjectContext` both call
        // `core.RequireFeatures(observatory)` when the tag is non-empty, and
        // `leastPing`/`leastLoad` require it unconditionally. Emitting a
        // fallbackTag without an observatory makes the core refuse to start with
        // "not all dependencies are resolved", so the two are kept in lockstep.
        let mut observed: BTreeSet<String> = BTreeSet::new();
        let mut burst_observed: BTreeSet<String> = BTreeSet::new();

        for (id, group) in &self.state.groups {
            let members = self.state.group_members(id);
            let mut selector: Vec<String> =
                members.iter().map(|m| self.target_tag(m)).collect();
            if selector.is_empty() {
                // An empty selector is rejected by Xray at load time. Point the
                // balancer at the blackhole so the configuration still loads and
                // the failure is visible as "blocked" rather than as a start
                // failure that takes every other profile down with it.
                selector.push(tags::CONTROL_BLOCK.to_owned());
                self.warnings.push(format!(
                    "[group.empty] group '{id}' has no members; its traffic is blocked until one matches"
                ));
            }
            selector.sort();
            selector.dedup();

            match group.strategy {
                GroupStrategy::LeastLoad => burst_observed.extend(selector.iter().cloned()),
                GroupStrategy::LeastPing => observed.extend(selector.iter().cloned()),
                _ => {}
            }

            // Only a user-configured fallback is honoured; a synthesised one would
            // silently switch on active probing.
            let fallback = group.fallback.as_ref().map(|t| self.target_tag(t));
            if fallback.is_some() {
                observed.extend(selector.iter().cloned());
            }

            let tag = tags::group_balancer(id);
            self.balancers.push(Balancer {
                tag: tag.clone(),
                selector,
                strategy: Some(BalancerStrategy {
                    strategy_type: group.strategy.xray_strategy().to_owned(),
                    settings: None,
                }),
                fallback_tag: fallback,
            });
            self.own(&tag);

            // A manual group is a balancer pinned by an override, exactly like a
            // profile selector. That keeps "switch a group's member" a runtime
            // operation rather than a recompile.
            if group.strategy == GroupStrategy::Manual {
                if let Some(selection) = &group.manual_selection {
                    self.selector_overrides.push((tag, self.target_tag(selection)));
                }
            }
        }

        for (id, profile) in &self.state.profiles {
            if !profile.enabled {
                continue;
            }
            let target_tag = self.target_tag(&profile.target);
            // An in-core fallback needs liveness observation. Only emit one when
            // the user asked for behaviour that cannot be expressed without it;
            // `KillSwitch::Off` with no fallback is the common case and stays
            // probe-free. When the daemon is running it enforces the kill switch
            // itself by overriding the selector, which is both cheaper and more
            // accurate than Xray's observatory. See DECISIONS.md D-013.
            let fallback_tag = match (profile.kill_switch, profile.fallback.as_ref()) {
                (KillSwitch::Off, None) => None,
                (KillSwitch::Block, _) => Some(tags::CONTROL_BLOCK.to_owned()),
                (_, Some(target)) => Some(self.target_tag(target)),
                (KillSwitch::FallbackOnly, None) => Some(tags::CONTROL_BLOCK.to_owned()),
                (KillSwitch::Off, Some(target)) => Some(self.target_tag(target)),
            };
            if fallback_tag.is_some() {
                observed.insert(target_tag.clone());
            }
            let tag = tags::profile_selector(id);
            self.balancers.push(Balancer {
                tag: tag.clone(),
                // The configured target is the candidate set, so a core that
                // starts before overrides are re-applied still routes correctly.
                selector: vec![target_tag.clone()],
                strategy: Some(BalancerStrategy {
                    strategy_type: "random".into(),
                    settings: None,
                }),
                fallback_tag,
            });
            self.own(&tag);
            self.selector_overrides.push((tag, target_tag));
        }

        // Loopback and control outbounds are not meaningful probe subjects.
        observed.retain(|tag| !tag.starts_with("control/") && !tag.starts_with("group/"));
        burst_observed.retain(|tag| !tag.starts_with("control/") && !tag.starts_with("group/"));

        if !observed.is_empty() {
            self.observatory = Some(ObservatoryConfig {
                subject_selector: observed.into_iter().collect(),
                probe_url: Some(self.options.observatory_probe_url.clone()),
                probe_interval: Some(self.options.observatory_probe_interval.clone()),
                enable_concurrency: Some(true),
            });
        }
        if !burst_observed.is_empty() {
            self.burst_observatory = Some(BurstObservatoryConfig {
                subject_selector: burst_observed.into_iter().collect(),
                ping_config: Some(json!({
                    "destination": self.options.observatory_probe_url,
                    "interval": self.options.observatory_probe_interval,
                    "connectivity": "",
                    "timeout": "3s",
                    "sampling": 5,
                })),
            });
        }
    }

    // ----------------------------------------------------------------- inbounds

    fn build_inbounds(&mut self) {
        let sniffing = self.sniffing();

        for (id, profile) in &self.state.profiles {
            if !profile.enabled {
                continue;
            }
            let mut bound = ProfileListeners::default();

            if let Some(spec) = &profile.socks {
                let tag = tags::profile_socks_inbound(id);
                self.inbounds.push(Inbound {
                    tag: tag.clone(),
                    listen: Some(spec.listen.ip().to_string()),
                    port: Some(spec.listen.port()),
                    protocol: "socks".into(),
                    settings: Some(socks_inbound_settings(spec)),
                    stream_settings: None,
                    sniffing: sniffing.clone(),
                });
                self.owned_tags.insert(tag);
                bound.socks = Some(spec.listen);
            }

            if let Some(spec) = &profile.http {
                let tag = tags::profile_http_inbound(id);
                self.inbounds.push(Inbound {
                    tag: tag.clone(),
                    listen: Some(spec.listen.ip().to_string()),
                    port: Some(spec.listen.port()),
                    protocol: "http".into(),
                    settings: Some(http_inbound_settings(spec)),
                    stream_settings: None,
                    sniffing: sniffing.clone(),
                });
                self.owned_tags.insert(tag);
                bound.http = Some(spec.listen);
            }

            self.listeners.insert(id.clone(), bound);
        }

        if let Some(tun) = &self.options.tun {
            let tag = tags::INBOUND_TUN.to_owned();
            self.inbounds.push(Inbound {
                tag: tag.clone(),
                listen: None,
                // Verified against `infra/conf/xray.go`: the TUN inbound skips
                // port validation entirely and never binds a socket.
                port: None,
                protocol: "tun".into(),
                settings: Some(json!({ "name": tun.name, "MTU": tun.mtu })),
                stream_settings: None,
                sniffing: sniffing.clone(),
            });
            self.owned_tags.insert(tag);
        }

        if let Some(listen) = self.options.dns.listen.filter(|_| self.options.dns.enabled) {
            let tag = tags::INBOUND_DNS.to_owned();
            self.inbounds.push(Inbound {
                tag: tag.clone(),
                listen: Some(listen.ip().to_string()),
                port: Some(listen.port()),
                protocol: "dokodemo-door".into(),
                settings: Some(json!({
                    "address": "127.0.0.1",
                    "port": 53,
                    "network": "tcp,udp"
                })),
                stream_settings: None,
                sniffing: None,
            });
            self.owned_tags.insert(tag);
        }
    }

    fn sniffing(&self) -> Option<Sniffing> {
        self.options.sniffing.enabled.then(|| Sniffing {
            enabled: true,
            dest_override: self.options.sniffing.dest_override.clone(),
            domains_excluded: Vec::new(),
            route_only: Some(self.options.sniffing.route_only),
            metadata_only: None,
        })
    }

    // -------------------------------------------------------------------- rules

    fn build_rules(&mut self) {
        self.build_dns_config();

        // 1. Xray's own traffic must never be captured by this ruleset. Without
        //    this the core dials its uplink through its own TUN and loops.
        self.rules.push(
            RoutingRule {
                process: vec!["self/".into()],
                ..RoutingRule::field(tags::system_rule("core-bypass"))
            }
            .to_outbound(tags::CONTROL_DIRECT),
        );

        // 2. DNS interception, before anything else can claim port 53.
        if self.options.dns.enabled {
            let mut inbound_tags = vec![];
            if self.options.tun.is_some() {
                inbound_tags.push(tags::INBOUND_TUN.to_owned());
            }
            if self.options.dns.listen.is_some() {
                inbound_tags.push(tags::INBOUND_DNS.to_owned());
            }
            if !inbound_tags.is_empty() {
                self.rules.push(
                    RoutingRule {
                        inbound_tag: inbound_tags,
                        port: Some("53".into()),
                        network: Some("tcp,udp".into()),
                        ..RoutingRule::field(tags::system_rule("dns-intercept"))
                    }
                    .to_outbound(tags::CONTROL_DNS),
                );
            }
            // Queries the DNS module itself emits are tagged and routed here.
            self.rules.push(
                RoutingRule {
                    inbound_tag: vec![dns_query_tag()],
                    ..RoutingRule::field(tags::system_rule("dns-direct"))
                }
                .to_outbound(tags::CONTROL_DIRECT),
            );
        }

        // 3. Traffic arriving on a profile's own listeners belongs to that
        //    profile, whatever the application rules say.
        for (id, profile) in &self.state.profiles {
            if !profile.enabled {
                continue;
            }
            let mut inbound_tags = Vec::new();
            if profile.socks.is_some() {
                inbound_tags.push(tags::profile_socks_inbound(id));
            }
            if profile.http.is_some() {
                inbound_tags.push(tags::profile_http_inbound(id));
            }
            if profile.transparent_inbound {
                inbound_tags.push(tags::profile_transparent_inbound(id));
            }
            if inbound_tags.is_empty() {
                continue;
            }
            self.rules.push(
                RoutingRule {
                    inbound_tag: inbound_tags,
                    ..RoutingRule::field(format!("rule/profile/{id}/inbound"))
                }
                .to_balancer(tags::profile_selector(id)),
            );
        }

        // 4. Group second stage: loopback traffic re-enters here.
        for id in self.state.groups.keys() {
            self.rules.push(
                RoutingRule {
                    inbound_tag: vec![tags::group_entry(id)],
                    ..RoutingRule::field(tags::group_stage_rule(id))
                }
                .to_balancer(tags::group_balancer(id)),
            );
        }

        // 5. Private and local networks bypass the tunnel.
        if self.options.bypass_private_networks && self.options.tun.is_some() {
            self.rules.push(
                RoutingRule {
                    ip: vec!["geoip:private".into()],
                    ..RoutingRule::field(tags::system_rule("private-direct"))
                }
                .to_outbound(tags::CONTROL_DIRECT),
            );
        }

        // 6. Explicit user block rules, so a block is never overtaken by a
        //    later, broader proxy rule.
        let mut block_rules: Vec<_> = self
            .state
            .routing_rules
            .values()
            .filter(|r| r.enabled && matches!(&r.action, RuleAction::Target { target: Target::Block }))
            .collect();
        block_rules.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        for rule in block_rules {
            let compiled = self.compile_user_rule(rule);
            self.rules.push(compiled);
        }

        // 7. Application rules.
        let mut app_rules: Vec<_> = self.state.app_rules.values().filter(|r| r.enabled).collect();
        app_rules.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        for rule in app_rules {
            let processes: Vec<String> = rule.process.iter().map(|m| m.0.clone()).collect();
            let base = RoutingRule {
                process: processes,
                ..RoutingRule::field(tags::app_rule(&rule.id))
            };
            self.rules.push(self.apply_action(base, &rule.action));
        }

        // 8. Remaining user routing rules.
        let mut user_rules: Vec<_> = self
            .state
            .routing_rules
            .values()
            .filter(|r| {
                r.enabled && !matches!(&r.action, RuleAction::Target { target: Target::Block })
            })
            .collect();
        user_rules.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        for rule in user_rules {
            let compiled = self.compile_user_rule(rule);
            self.rules.push(compiled);
        }

        // 9. Explicit terminal catch-all. Xray's implicit "first outbound"
        //    fallback is never relied on.
        let fallback = self.mode_fallback();
        self.rules.push(fallback);

        // Upstream rejects a rule with no conditions ("this rule has no effective
        // fields", `app/router/config.go`). A genuine catch-all is expressed as
        // "every network", which is the broadest condition Xray accepts.
        for rule in &mut self.rules {
            if rule.is_catch_all() {
                rule.network = Some("tcp,udp".to_owned());
            }
        }
    }

    fn compile_user_rule(&self, rule: &xraytui_domain::RoutingRule) -> RoutingRule {
        let m = &rule.matcher;
        let base = RoutingRule {
            domain: m.domain.clone(),
            ip: m.ip.clone(),
            port: m.port.clone(),
            source_port: m.source_port.clone(),
            source_ip: m.source_ip.clone(),
            network: m.network.clone(),
            protocol: m.protocol.clone(),
            inbound_tag: m.inbound_tag.clone(),
            process: m.process.iter().map(|p: &AppMatcher| p.0.clone()).collect(),
            attrs: m.attrs.clone(),
            ..RoutingRule::field(tags::user_rule(&rule.id))
        };
        self.apply_action(base, &rule.action)
    }

    fn apply_action(&self, rule: RoutingRule, action: &RuleAction) -> RoutingRule {
        match action {
            RuleAction::Profile { id } => rule.to_balancer(tags::profile_selector(id)),
            RuleAction::DefaultProfile => match &self.state.default_profile {
                Some(id) => rule.to_balancer(tags::profile_selector(id)),
                // Validation guarantees this cannot happen; failing closed is
                // still the right answer if it somehow does.
                None => rule.to_outbound(tags::CONTROL_BLOCK),
            },
            RuleAction::Target { target } => match target {
                Target::Group { id } => rule.to_balancer(tags::group_balancer(id)),
                other => rule.to_outbound(self.target_tag(other)),
            },
        }
    }

    fn mode_fallback(&self) -> RoutingRule {
        let base = RoutingRule::field(tags::system_rule("mode-fallback"));
        match self.state.mode {
            SystemMode::Direct | SystemMode::Off => base.to_outbound(tags::CONTROL_DIRECT),
            SystemMode::Global | SystemMode::Rule => match &self.state.default_profile {
                Some(id) => base.to_balancer(tags::profile_selector(id)),
                None => base.to_outbound(tags::CONTROL_DIRECT),
            },
        }
    }

    fn build_dns_config(&mut self) {
        if !self.options.dns.enabled {
            return;
        }
        let mut servers: Vec<DnsServer> = Vec::new();
        if !self.options.dns.direct_domains.is_empty() {
            for address in &self.options.dns.direct_servers {
                servers.push(DnsServer::Detailed(Box::new(DnsServerDetail {
                    address: address.clone(),
                    domains: self.options.dns.direct_domains.clone(),
                    skip_fallback: Some(true),
                    ..Default::default()
                })));
            }
        }
        for address in &self.options.dns.proxy_servers {
            servers.push(DnsServer::Simple(address.clone()));
        }
        for address in &self.options.dns.direct_servers {
            servers.push(DnsServer::Simple(address.clone()));
        }
        if servers.is_empty() {
            servers.push(DnsServer::Simple("localhost".into()));
        }
        self.dns = Some(DnsConfig {
            servers,
            hosts: BTreeMap::new(),
            tag: Some(dns_query_tag()),
            query_strategy: Some(self.options.dns.query_strategy.clone()),
            disable_cache: None,
            disable_fallback: None,
        });
    }

    fn check_prefix_safety(&self) -> Result<(), CompileError> {
        tags::assert_prefix_safety(&self.selectable_tags).map_err(CompileError::TagCollision)
    }
}

/// Inbound tag applied to queries the DNS module itself emits.
#[must_use]
fn dns_query_tag() -> String {
    "inbound/system/dns-query".to_owned()
}

fn socks_inbound_settings(spec: &ListenerSpec) -> serde_json::Value {
    let mut settings = serde_json::Map::new();
    // `udp: true` gives SOCKS5 UDP ASSOCIATE, which is what `socks5h`-style
    // clients need for remote DNS.
    settings.insert("udp".into(), json!(true));
    match (&spec.username, &spec.password) {
        (Some(user), Some(pass)) => {
            settings.insert("auth".into(), json!("password"));
            settings.insert(
                "accounts".into(),
                json!([{ "user": user, "pass": pass.expose() }]),
            );
        }
        _ => {
            settings.insert("auth".into(), json!("noauth"));
        }
    }
    serde_json::Value::Object(settings)
}

fn http_inbound_settings(spec: &ListenerSpec) -> serde_json::Value {
    let mut settings = serde_json::Map::new();
    settings.insert("allowTransparent".into(), json!(false));
    if let (Some(user), Some(pass)) = (&spec.username, &spec.password) {
        settings.insert(
            "accounts".into(),
            json!([{ "user": user, "pass": pass.expose() }]),
        );
    }
    serde_json::Value::Object(settings)
}

/// Convenience: every node, group and chain a target can resolve to, as tags.
///
/// Used by the daemon when it needs the complete override vocabulary, for
/// example to validate a `set-target` request before sending it to the core.
#[must_use]
pub fn selectable_tags(state: &DesiredState) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    out.insert(tags::CONTROL_DIRECT.to_owned());
    out.insert(tags::CONTROL_BLOCK.to_owned());
    for (id, node) in &state.nodes {
        if node.is_compilable() {
            out.insert(tags::node(id));
        }
    }
    for (id, chain) in &state.chains {
        if chain.enabled {
            out.insert(tags::chain_terminal(id));
        }
    }
    for id in state.groups.keys() {
        out.insert(tags::group_entry(id));
    }
    out
}

/// The outbound tag a target compiles to, for callers outside the compiler.
#[must_use]
pub fn tag_for_target(target: &Target) -> String {
    match target {
        Target::Node { id } => tags::node(id),
        Target::Chain { id } => tags::chain_terminal(id),
        Target::Group { id } => tags::group_entry(id),
        Target::Direct => tags::CONTROL_DIRECT.to_owned(),
        Target::Block => tags::CONTROL_BLOCK.to_owned(),
    }
}

/// Reverse of [`tag_for_target`], for rendering routing events.
#[must_use]
pub fn target_for_tag(tag: &str) -> Option<Target> {
    if tag == tags::CONTROL_DIRECT {
        return Some(Target::Direct);
    }
    if tag == tags::CONTROL_BLOCK {
        return Some(Target::Block);
    }
    let mut parts = tag.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("node"), Some(id), Some("out")) => NodeId::new(id).ok().map(|id| Target::Node { id }),
        (Some("chain"), Some(id), Some("terminal")) => {
            ChainId::new(id).ok().map(|id| Target::Chain { id })
        }
        (Some("group"), Some(id), Some("entry")) => {
            GroupId::new(id).ok().map(|id| Target::Group { id })
        }
        _ => None,
    }
}

/// The profile a selector tag belongs to.
#[must_use]
pub fn profile_of_selector(tag: &str) -> Option<ProfileId> {
    let mut parts = tag.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("profile"), Some(id), Some("selector")) => ProfileId::new(id).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
