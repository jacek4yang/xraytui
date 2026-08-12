//! Groups, chains, egress profiles and the two rule kinds.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ids::{AppRuleId, ChainId, GroupId, NodeId, ProfileId, RoutingRuleId, SubscriptionId};

/// Anything traffic can be pointed at.
///
/// This is the value a profile selects, a rule dispatches to, and a chain hop
/// resolves to. It is deliberately closed: adding a new kind of target requires
/// touching the compiler, which is where the safety-relevant decisions live.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Target {
    /// A concrete node.
    Node {
        /// Node identifier.
        id: NodeId,
    },
    /// A group; the balancer picks a member.
    Group {
        /// Group identifier.
        id: GroupId,
    },
    /// A multi-hop chain; traffic reaches the chain terminal.
    Chain {
        /// Chain identifier.
        id: ChainId,
    },
    /// Leave the machine without a proxy.
    Direct,
    /// Drop the connection.
    Block,
}

impl Target {
    /// Compact textual form used in TOML, the CLI and dmenu output.
    ///
    /// `node:hk-01`, `group:auto-hk`, `chain:hk-us`, `direct`, `block`.
    #[must_use]
    pub fn to_token(&self) -> String {
        match self {
            Self::Node { id } => format!("node:{id}"),
            Self::Group { id } => format!("group:{id}"),
            Self::Chain { id } => format!("chain:{id}"),
            Self::Direct => "direct".to_owned(),
            Self::Block => "block".to_owned(),
        }
    }

    /// Short label for narrow terminal columns.
    #[must_use]
    pub fn short_label(&self) -> String {
        match self {
            Self::Node { id } => id.to_string(),
            Self::Group { id } => id.to_string(),
            Self::Chain { id } => id.to_string(),
            Self::Direct => "direct".to_owned(),
            Self::Block => "block".to_owned(),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_token())
    }
}

/// Failure to parse a [`Target`] token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetParseError {
    /// The prefix before `:` was not recognised.
    #[error("unknown target kind '{0}'; expected node:, group:, chain:, direct or block")]
    UnknownKind(String),
    /// The identifier part failed slug validation.
    #[error("invalid {kind} identifier: {source}")]
    BadId {
        /// Which kind was being parsed.
        kind: &'static str,
        /// Underlying identifier error.
        #[source]
        source: crate::ids::IdError,
    },
}

impl FromStr for Target {
    type Err = TargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        match trimmed {
            "direct" => return Ok(Self::Direct),
            "block" => return Ok(Self::Block),
            _ => {}
        }
        let (kind, rest) = trimmed
            .split_once(':')
            .ok_or_else(|| TargetParseError::UnknownKind(trimmed.to_owned()))?;
        match kind {
            "node" => NodeId::new(rest)
                .map(|id| Self::Node { id })
                .map_err(|source| TargetParseError::BadId {
                    kind: "node",
                    source,
                }),
            "group" => GroupId::new(rest)
                .map(|id| Self::Group { id })
                .map_err(|source| TargetParseError::BadId {
                    kind: "group",
                    source,
                }),
            "chain" => ChainId::new(rest)
                .map(|id| Self::Chain { id })
                .map_err(|source| TargetParseError::BadId {
                    kind: "chain",
                    source,
                }),
            other => Err(TargetParseError::UnknownKind(other.to_owned())),
        }
    }
}

/// Balancer strategy, mapped onto what the pinned Xray release implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupStrategy {
    /// The user picks a member explicitly; the balancer is overridden to it.
    #[default]
    Manual,
    /// Xray `random`.
    Random,
    /// Xray `roundRobin`.
    RoundRobin,
    /// Xray `leastPing`; requires an observatory block.
    LeastPing,
    /// Xray `leastLoad`; requires a burst observatory block.
    LeastLoad,
}

impl GroupStrategy {
    /// Strategy name as Xray's `balancers[].strategy.type` spells it.
    ///
    /// `Manual` has no Xray equivalent: it compiles to `random` over a
    /// single-member candidate set fixed by an override.
    #[must_use]
    pub fn xray_strategy(self) -> &'static str {
        match self {
            Self::Manual | Self::Random => "random",
            Self::RoundRobin => "roundRobin",
            Self::LeastPing => "leastPing",
            Self::LeastLoad => "leastLoad",
        }
    }

    /// Whether the strategy needs Xray liveness observation to behave correctly.
    #[must_use]
    pub fn needs_observatory(self) -> bool {
        matches!(self, Self::LeastPing | Self::LeastLoad)
    }
}

/// How a group's membership is computed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GroupMembership {
    /// Explicitly listed nodes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<NodeId>,
    /// Explicitly listed chains, usable as group members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chains: Vec<ChainId>,
    /// Include every node belonging to these subscriptions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subscriptions: Vec<SubscriptionId>,
    /// Regular expressions matched against the node display name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_regex: Vec<String>,
    /// Regular expressions that remove a node after inclusion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_regex: Vec<String>,
    /// Node tags that must all be present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Protocol names to keep, e.g. `vless`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
    /// Region labels to keep.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
}

impl GroupMembership {
    /// True when no criterion was supplied at all, which would select nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
            && self.chains.is_empty()
            && self.subscriptions.is_empty()
            && self.include_regex.is_empty()
            && self.tags.is_empty()
            && self.protocols.is_empty()
            && self.regions.is_empty()
    }
}

/// A logical collection of nodes or chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// Stable identifier.
    pub id: GroupId,
    /// Display name.
    pub name: String,
    /// Selection strategy.
    #[serde(default)]
    pub strategy: GroupStrategy,
    /// Membership criteria.
    #[serde(default)]
    pub membership: GroupMembership,
    /// Member chosen when `strategy == Manual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_selection: Option<Target>,
    /// Target used when every member is down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Target>,
}

/// An ordered path from this machine towards a final exit.
///
/// `hops` is written in traffic order: `hops[0]` is the first server the local
/// machine talks to. The UI shows exactly this order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    /// Stable identifier.
    pub id: ChainId,
    /// Display name.
    pub name: String,
    /// Hops in traffic order, at least two entries for a meaningful chain.
    pub hops: Vec<NodeId>,
    /// Whether the chain is selectable.
    #[serde(default = "crate::node::default_true")]
    pub enabled: bool,
}

impl Chain {
    /// Render the hop order for display: `HK -> US`.
    #[must_use]
    pub fn describe(&self) -> String {
        self.hops
            .iter()
            .map(NodeId::to_string)
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Index of the terminal hop, i.e. the exit node.
    #[must_use]
    pub fn terminal_index(&self) -> Option<usize> {
        self.hops.len().checked_sub(1)
    }
}

/// Chain validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// Fewer than two hops.
    #[error("chain '{0}' needs at least two hops")]
    TooShort(ChainId),
    /// A hop referenced a node that does not exist.
    #[error("chain '{chain}' references unknown node '{node}'")]
    MissingHop {
        /// Chain being validated.
        chain: ChainId,
        /// Node that was not found.
        node: NodeId,
    },
    /// The same node appears more than once.
    #[error("chain '{chain}' uses node '{node}' more than once, which loops traffic")]
    RepeatedHop {
        /// Chain being validated.
        chain: ChainId,
        /// Node that repeats.
        node: NodeId,
    },
    /// A hop cannot carry UDP but a later hop needs it.
    #[error("chain '{chain}': hop '{node}' cannot carry UDP, so UDP breaks for later hops")]
    UdpBreak {
        /// Chain being validated.
        chain: ChainId,
        /// Offending hop.
        node: NodeId,
    },
    /// A hop is disabled or unsupported.
    #[error("chain '{chain}': hop '{node}' is not usable ({reason})")]
    UnusableHop {
        /// Chain being validated.
        chain: ChainId,
        /// Offending hop.
        node: NodeId,
        /// Why.
        reason: String,
    },
}

/// What happens to a profile's traffic when its target is unhealthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KillSwitch {
    /// Fall through to the profile's `fallback`, then to direct.
    #[default]
    Off,
    /// Fall through to the profile's `fallback` only; never direct.
    FallbackOnly,
    /// Drop traffic rather than let it leave unproxied.
    Block,
}

/// A listener bound by the compiled configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerSpec {
    /// Address to bind. Must be loopback unless `lan_access` is acknowledged.
    pub listen: SocketAddr,
    /// Optional credentials, required when the address is not loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password paired with `username`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<xraytui_secrets::Secret>,
}

impl ListenerSpec {
    /// Bind on loopback with no authentication.
    #[must_use]
    pub fn loopback(port: u16) -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], port)),
            username: None,
            password: None,
        }
    }

    /// True when the listener is reachable from outside this machine.
    #[must_use]
    pub fn is_exposed(&self) -> bool {
        !self.listen.ip().is_loopback()
    }
}

/// An independently selectable egress slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressProfile {
    /// Stable identifier; appears in every generated tag for this profile.
    pub id: ProfileId,
    /// Display name.
    pub name: String,
    /// Currently selected target.
    pub target: Target,
    /// Used when `target` is unreachable and the kill switch permits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Target>,
    /// Dedicated SOCKS5 listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks: Option<ListenerSpec>,
    /// Dedicated HTTP CONNECT listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<ListenerSpec>,
    /// Per-profile DNS override; `None` inherits the global policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_policy: Option<ProfileDnsPolicy>,
    /// Behaviour when the target is unhealthy.
    #[serde(default)]
    pub kill_switch: KillSwitch,
    /// Whether the profile is compiled at all.
    #[serde(default = "crate::node::default_true")]
    pub enabled: bool,
    /// Whether a transparent inbound is pre-created for `exec --transparent`.
    #[serde(default)]
    pub transparent_inbound: bool,
}

impl EgressProfile {
    /// Construct a profile with only a target.
    pub fn new(id: ProfileId, name: impl Into<String>, target: Target) -> Self {
        Self {
            id,
            name: name.into(),
            target,
            fallback: None,
            socks: None,
            http: None,
            dns_policy: None,
            kill_switch: KillSwitch::default(),
            enabled: true,
            transparent_inbound: false,
        }
    }

    /// Every listener the profile owns.
    #[must_use]
    pub fn listeners(&self) -> Vec<&ListenerSpec> {
        self.socks.iter().chain(self.http.iter()).collect()
    }
}

/// Per-profile DNS routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileDnsPolicy {
    /// Resolve through the profile's own egress.
    Proxied,
    /// Resolve using the direct resolvers.
    Direct,
    /// Let the SOCKS client send the hostname (`socks5h` semantics).
    Remote,
}

/// How an application matcher is written by the user.
///
/// The literal string is preserved so the UI can show exactly what was typed;
/// [`AppMatcher::shape`] classifies it the same way Xray's process matcher does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppMatcher(pub String);

/// The three shapes Xray's `process` list understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherShape {
    /// Bare executable name, e.g. `firefox`.
    ProcessName,
    /// Absolute executable path, e.g. `/usr/lib/firefox/firefox`.
    AbsolutePath,
    /// Directory prefix, e.g. `/opt/tools/`.
    Directory,
    /// The Xray process itself (`self/`).
    XraySelf,
}

impl AppMatcher {
    /// Classify the matcher exactly as `NewProcessNameMatcher` does upstream.
    #[must_use]
    pub fn shape(&self) -> MatcherShape {
        let raw = self.0.as_str();
        if raw == "self/" || raw == "xray/" {
            MatcherShape::XraySelf
        } else if raw.ends_with('/') {
            MatcherShape::Directory
        } else if raw.contains('/') {
            MatcherShape::AbsolutePath
        } else {
            MatcherShape::ProcessName
        }
    }

    /// Whether the matcher is syntactically usable.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let raw = self.0.as_str();
        if raw.is_empty() || raw.len() > 4096 {
            return false;
        }
        if raw.contains('\0') || raw.contains('\n') {
            return false;
        }
        match self.shape() {
            MatcherShape::XraySelf | MatcherShape::ProcessName => true,
            MatcherShape::AbsolutePath | MatcherShape::Directory => raw.starts_with('/'),
        }
    }
}

/// What an application rule does with matching traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RuleAction {
    /// Send to a named egress profile.
    Profile {
        /// Profile identifier.
        id: ProfileId,
    },
    /// Send to a target directly, bypassing profile indirection.
    Target {
        /// Selected target.
        target: Target,
    },
    /// Use whichever profile the current system mode designates as default.
    DefaultProfile,
}

impl RuleAction {
    /// Compact textual form: `profile:web`, `node:hk-01`, `direct`, `default`.
    #[must_use]
    pub fn to_token(&self) -> String {
        match self {
            Self::Profile { id } => format!("profile:{id}"),
            Self::Target { target } => target.to_token(),
            Self::DefaultProfile => "default".to_owned(),
        }
    }
}

impl FromStr for RuleAction {
    type Err = TargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed == "default" {
            return Ok(Self::DefaultProfile);
        }
        if let Some(rest) = trimmed.strip_prefix("profile:") {
            return ProfileId::new(rest)
                .map(|id| Self::Profile { id })
                .map_err(|source| TargetParseError::BadId {
                    kind: "profile",
                    source,
                });
        }
        Target::from_str(trimmed).map(|target| Self::Target { target })
    }
}

/// An ordered rule assigning local programs to an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationRule {
    /// Stable identifier.
    pub id: AppRuleId,
    /// Lower numbers are evaluated first.
    pub priority: i32,
    /// Matchers; any one matching selects the rule.
    pub process: Vec<AppMatcher>,
    /// What to do with matching traffic.
    pub action: RuleAction,
    /// Whether the rule is compiled.
    #[serde(default = "crate::node::default_true")]
    pub enabled: bool,
    /// Optional user note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Destination and metadata conditions for a routing rule.
///
/// Every field is optional; a rule with no conditions matches everything and is
/// only legal as the final catch-all.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RoutingMatch {
    /// Destination domain patterns (`example.com`, `domain:x`, `geosite:cn`, `regexp:`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    /// Destination IP/CIDR or `geoip:` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
    /// Destination ports, Xray port-list syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Source ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<String>,
    /// Source IP/CIDR.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ip: Vec<String>,
    /// `tcp`, `udp` or both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Sniffed protocols, e.g. `tls`, `http`, `bittorrent`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    /// Inbound tags this rule applies to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound_tag: Vec<String>,
    /// Process matchers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process: Vec<AppMatcher>,
    /// Header attribute matchers.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attrs: std::collections::BTreeMap<String, String>,
}

impl RoutingMatch {
    /// True when the rule has no conditions and therefore matches everything.
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

    /// Condition kinds present, used for shadowing analysis.
    #[must_use]
    pub fn condition_kinds(&self) -> BTreeSet<&'static str> {
        let mut kinds = BTreeSet::new();
        if !self.domain.is_empty() {
            kinds.insert("domain");
        }
        if !self.ip.is_empty() {
            kinds.insert("ip");
        }
        if self.port.is_some() {
            kinds.insert("port");
        }
        if self.source_port.is_some() {
            kinds.insert("sourcePort");
        }
        if !self.source_ip.is_empty() {
            kinds.insert("sourceIP");
        }
        if self.network.is_some() {
            kinds.insert("network");
        }
        if !self.protocol.is_empty() {
            kinds.insert("protocol");
        }
        if !self.inbound_tag.is_empty() {
            kinds.insert("inboundTag");
        }
        if !self.process.is_empty() {
            kinds.insert("process");
        }
        if !self.attrs.is_empty() {
            kinds.insert("attrs");
        }
        kinds
    }
}

/// An ordered destination or metadata rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Stable identifier; also becomes the Xray `ruleTag`.
    pub id: RoutingRuleId,
    /// Lower numbers are evaluated first.
    pub priority: i32,
    /// Conditions.
    #[serde(default, flatten)]
    pub matcher: RoutingMatch,
    /// Action.
    pub action: RuleAction,
    /// Whether the rule is compiled.
    #[serde(default = "crate::node::default_true")]
    pub enabled: bool,
    /// Optional user note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// System-wide TUN behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemMode {
    /// TUN and system DNS management disabled; per-profile listeners still work.
    #[default]
    Off,
    /// TUN traffic goes out directly after safety rules.
    Direct,
    /// TUN traffic goes through the default egress profile.
    Global,
    /// TUN traffic is evaluated through the ordered rule set.
    Rule,
}

impl SystemMode {
    /// Cycle order used by `xraytui mode cycle` and the `m` key.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Off => Self::Rule,
            Self::Rule => Self::Global,
            Self::Global => Self::Direct,
            Self::Direct => Self::Off,
        }
    }

    /// Whether this mode requires a TUN device.
    #[must_use]
    pub fn needs_tun(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Direct => "direct",
            Self::Global => "global",
            Self::Rule => "rule",
        }
    }
}

impl fmt::Display for SystemMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SystemMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "direct" => Ok(Self::Direct),
            "global" => Ok(Self::Global),
            "rule" => Ok(Self::Rule),
            other => Err(format!(
                "unknown mode '{other}'; expected off, direct, global or rule"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_tokens_round_trip() {
        for token in [
            "node:hk-01",
            "group:auto-hk",
            "chain:hk-us",
            "direct",
            "block",
        ] {
            let parsed: Target = token.parse().expect("parse");
            assert_eq!(parsed.to_token(), token);
        }
    }

    #[test]
    fn target_rejects_nonsense() {
        assert!("nope:x".parse::<Target>().is_err());
        assert!("node:UPPER".parse::<Target>().is_err());
        assert!("".parse::<Target>().is_err());
        assert!("node:".parse::<Target>().is_err());
    }

    #[test]
    fn rule_action_tokens_round_trip() {
        for token in ["profile:web", "node:hk-01", "direct", "block", "default"] {
            let parsed: RuleAction = token.parse().expect("parse");
            assert_eq!(parsed.to_token(), token);
        }
    }

    #[test]
    fn matcher_shapes_match_upstream_rules() {
        assert_eq!(
            AppMatcher("firefox".into()).shape(),
            MatcherShape::ProcessName
        );
        assert_eq!(
            AppMatcher("/usr/lib/firefox/firefox".into()).shape(),
            MatcherShape::AbsolutePath
        );
        assert_eq!(
            AppMatcher("/usr/bin/".into()).shape(),
            MatcherShape::Directory
        );
        assert_eq!(AppMatcher("self/".into()).shape(), MatcherShape::XraySelf);
        assert_eq!(AppMatcher("xray/".into()).shape(), MatcherShape::XraySelf);
    }

    #[test]
    fn matcher_validation_rejects_relative_paths_and_control_chars() {
        assert!(AppMatcher("firefox".into()).is_valid());
        assert!(AppMatcher("/usr/bin/curl".into()).is_valid());
        assert!(!AppMatcher("usr/bin/curl".into()).is_valid());
        assert!(!AppMatcher("".into()).is_valid());
        assert!(!AppMatcher("a\nb".into()).is_valid());
        assert!(!AppMatcher("a\0b".into()).is_valid());
    }

    #[test]
    fn mode_cycle_visits_every_state() {
        let mut mode = SystemMode::Off;
        let mut seen = vec![mode];
        for _ in 0..3 {
            mode = mode.next();
            seen.push(mode);
        }
        assert_eq!(
            seen,
            vec![
                SystemMode::Off,
                SystemMode::Rule,
                SystemMode::Global,
                SystemMode::Direct
            ]
        );
        assert_eq!(mode.next(), SystemMode::Off);
    }

    #[test]
    fn manual_strategy_maps_to_random_with_single_candidate() {
        assert_eq!(GroupStrategy::Manual.xray_strategy(), "random");
        assert!(!GroupStrategy::Manual.needs_observatory());
        assert!(GroupStrategy::LeastPing.needs_observatory());
    }

    #[test]
    fn loopback_listener_is_not_exposed() {
        assert!(!ListenerSpec::loopback(1080).is_exposed());
        let lan = ListenerSpec {
            listen: "0.0.0.0:1080".parse().expect("addr"),
            username: None,
            password: None,
        };
        assert!(lan.is_exposed());
    }

    #[test]
    fn empty_matcher_is_catch_all() {
        assert!(RoutingMatch::default().is_catch_all());
        let m = RoutingMatch {
            domain: vec!["x".into()],
            ..Default::default()
        };
        assert!(!m.is_catch_all());
        assert!(m.condition_kinds().contains("domain"));
    }

    #[test]
    fn chain_describes_traffic_order() {
        let chain = Chain {
            id: ChainId::new("hk-us").expect("valid"),
            name: "HK to US".into(),
            hops: vec![
                NodeId::new("hk-transit").expect("valid"),
                NodeId::new("us-exit").expect("valid"),
            ],
            enabled: true,
        };
        assert_eq!(chain.describe(), "hk-transit -> us-exit");
        assert_eq!(chain.terminal_index(), Some(1));
    }
}
