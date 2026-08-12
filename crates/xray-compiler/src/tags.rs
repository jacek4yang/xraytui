//! The generated tag namespace.
//!
//! Every Xray object xraytui creates carries a tag from this module. Two
//! properties matter and are enforced by test:
//!
//! 1. **Determinism.** The same domain state always produces the same tags.
//! 2. **Prefix safety.** Xray balancer `selector` entries are *prefix* matches
//!    (verified in `app/router/balancing.go`). A selector for one profile must
//!    never accidentally capture another profile's outbounds, so no tag in one
//!    namespace may be a prefix of a tag in another. The `/` separator plus a
//!    fixed set of first segments gives that for free, and
//!    [`assert_prefix_safety`] proves it for a concrete tag set.

use std::collections::BTreeSet;

use xraytui_domain::{ChainId, GroupId, NodeId, ProfileId};

/// Blackhole outbound. Emitted **first** so a truncated or malformed outbound
/// list fails closed instead of leaking to a proxy or to direct.
pub const CONTROL_BLOCK: &str = "control/block";
/// Freedom outbound used by direct routing.
pub const CONTROL_DIRECT: &str = "control/direct";
/// Freedom outbound reserved for the core's own traffic (API, observatory).
pub const CONTROL_SELF: &str = "control/self";
/// DNS outbound.
pub const CONTROL_DNS: &str = "control/dns";
/// Inbound tag of the gRPC commander.
pub const INBOUND_API: &str = "inbound/system/api";
/// Inbound tag of the local DNS listener.
pub const INBOUND_DNS: &str = "inbound/system/dns";
/// Inbound tag of the shared system TUN.
pub const INBOUND_TUN: &str = "inbound/system/tun";

/// First path segments that are reserved by the generator.
pub const RESERVED_ROOTS: &[&str] = &[
    "control", "node", "chain", "group", "profile", "inbound", "rule",
];

/// Outbound tag for a node.
///
/// The trailing `/out` segment is not decoration. Balancer selectors are prefix
/// matches, and node identifiers may legitimately be prefixes of one another
/// (`hk` and `hk-01`). Ending every selectable tag with a fixed segment after a
/// `/` makes the selectable tag set prefix-free, so a selector naming one node
/// can never also capture another.
#[must_use]
pub fn node(id: &NodeId) -> String {
    format!("node/{id}/out")
}

/// Outbound tag for hop `index` of a chain, counted in traffic order from 0.
#[must_use]
pub fn chain_hop(id: &ChainId, index: usize) -> String {
    format!("chain/{id}/hop{index}")
}

/// Outbound tag for the terminal (exit) hop of a chain.
///
/// This is the tag routing points at; it is an alias for the last hop rather than
/// an extra outbound, so a chain costs exactly as many outbounds as it has hops.
#[must_use]
pub fn chain_terminal(id: &ChainId) -> String {
    format!("chain/{id}/terminal")
}

/// Loopback outbound that re-enters routing so a group can be selected.
#[must_use]
pub fn group_entry(id: &GroupId) -> String {
    format!("group/{id}/entry")
}

/// Balancer tag for a group.
#[must_use]
pub fn group_balancer(id: &GroupId) -> String {
    format!("group/{id}/balancer")
}

/// Rule tag of the second-stage rule that dispatches a group's loopback traffic.
#[must_use]
pub fn group_stage_rule(id: &GroupId) -> String {
    format!("rule/group/{id}/stage2")
}

/// Balancer tag whose override selects a profile's current target.
///
/// This is the tag passed to `RoutingService.OverrideBalancerTarget`.
#[must_use]
pub fn profile_selector(id: &ProfileId) -> String {
    format!("profile/{id}/selector")
}

/// Loopback outbound that sends traffic into a profile's routing stage.
#[must_use]
pub fn profile_entry(id: &ProfileId) -> String {
    format!("profile/{id}/entry")
}

/// Rule tag of the rule that dispatches a profile's entry traffic to its selector.
#[must_use]
pub fn profile_stage_rule(id: &ProfileId) -> String {
    format!("rule/profile/{id}/stage2")
}

/// Inbound tag of a profile's dedicated SOCKS5 listener.
#[must_use]
pub fn profile_socks_inbound(id: &ProfileId) -> String {
    format!("inbound/profile/{id}/socks")
}

/// Inbound tag of a profile's dedicated HTTP CONNECT listener.
#[must_use]
pub fn profile_http_inbound(id: &ProfileId) -> String {
    format!("inbound/profile/{id}/http")
}

/// Inbound tag of a profile's transparent (cgroup-routed) listener.
#[must_use]
pub fn profile_transparent_inbound(id: &ProfileId) -> String {
    format!("inbound/profile/{id}/transparent")
}

/// Rule tag for an application rule.
#[must_use]
pub fn app_rule(id: &xraytui_domain::AppRuleId) -> String {
    format!("rule/app/{id}")
}

/// Rule tag for a user routing rule.
#[must_use]
pub fn user_rule(id: &xraytui_domain::RoutingRuleId) -> String {
    format!("rule/user/{id}")
}

/// Rule tag for one of the generated infrastructure rules.
#[must_use]
pub fn system_rule(name: &str) -> String {
    format!("rule/system/{name}")
}

/// Check that no tag in `tags` is a strict prefix of another.
///
/// Returns the offending pair. Called by the compiler on every build, so a future
/// change to the naming scheme cannot silently create a balancer that captures
/// unrelated outbounds.
#[must_use]
pub fn find_prefix_collision(tags: &BTreeSet<String>) -> Option<(String, String)> {
    let ordered: Vec<&String> = tags.iter().collect();
    for window in ordered.windows(2) {
        let (a, b) = (window[0], window[1]);
        if b.starts_with(a.as_str()) && a.len() < b.len() {
            return Some((a.clone(), b.clone()));
        }
    }
    None
}

/// Panic-free assertion helper used in tests and debug builds.
///
/// # Errors
/// Returns a human-readable description of the first collision found.
pub fn assert_prefix_safety(tags: &BTreeSet<String>) -> Result<(), String> {
    match find_prefix_collision(tags) {
        None => Ok(()),
        Some((a, b)) => Err(format!(
            "tag '{a}' is a prefix of '{b}'; a balancer selector for the former would also match the latter"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn node_id(s: &str) -> NodeId {
        NodeId::from_str(s).expect("valid")
    }

    #[test]
    fn tags_are_namespaced_and_deterministic() {
        let id = node_id("hk-01");
        assert_eq!(node(&id), "node/hk-01/out");
        assert_eq!(node(&id), node(&node_id("hk-01")));
    }

    #[test]
    fn chain_tags_carry_hop_order() {
        let id = ChainId::from_str("hk-us").expect("valid");
        assert_eq!(chain_hop(&id, 0), "chain/hk-us/hop0");
        assert_eq!(chain_hop(&id, 1), "chain/hk-us/hop1");
        assert_eq!(chain_terminal(&id), "chain/hk-us/terminal");
    }

    #[test]
    fn profile_selector_is_the_override_handle() {
        let id = ProfileId::from_str("web").expect("valid");
        assert_eq!(profile_selector(&id), "profile/web/selector");
    }

    #[test]
    fn no_generated_tag_is_a_prefix_of_another() {
        // `hk` and `hk-01` are legal identifiers where one *is* a prefix of the
        // other; the `/` separator is what keeps the full tags distinct.
        let mut tags = BTreeSet::new();
        for id in ["hk", "hk-01", "hk-01-b"] {
            tags.insert(node(&node_id(id)));
        }
        tags.insert(CONTROL_BLOCK.to_owned());
        tags.insert(CONTROL_DIRECT.to_owned());
        tags.insert(chain_terminal(&ChainId::from_str("hk").expect("valid")));
        assert_eq!(assert_prefix_safety(&tags), Ok(()));
    }

    #[test]
    fn prefix_collision_is_detected_when_it_exists() {
        // Without the trailing `/out` segment these two tags collide: a balancer
        // selector naming `node/hk` would also select `node/hk-01`. The detector
        // has to catch that, which is what justifies the tag shape.
        let mut tags = BTreeSet::new();
        tags.insert("node/hk".to_owned());
        tags.insert("node/hk-01".to_owned());
        let collision = find_prefix_collision(&tags);
        assert_eq!(collision, Some(("node/hk".into(), "node/hk-01".into())));
    }

    #[test]
    fn node_tag_shape_removes_the_collision() {
        let mut tags = BTreeSet::new();
        for id in ["hk", "hk-01", "hk-01-b", "hk-0"] {
            tags.insert(node(&node_id(id)));
        }
        assert_eq!(assert_prefix_safety(&tags), Ok(()));
    }

    #[test]
    fn reserved_roots_cover_every_generator() {
        let samples = [
            CONTROL_BLOCK.to_owned(),
            node(&node_id("a")),
            chain_terminal(&ChainId::from_str("a").expect("valid")),
            group_entry(&GroupId::from_str("a").expect("valid")),
            profile_selector(&ProfileId::from_str("a").expect("valid")),
            INBOUND_TUN.to_owned(),
            system_rule("dns"),
        ];
        for tag in samples {
            let root = tag.split('/').next().unwrap_or_default();
            assert!(RESERVED_ROOTS.contains(&root), "unexpected root in {tag}");
        }
    }
}
