//! Turning a [`RoutingRequest`] into a list of routes and rules.
//!
//! This module is pure: it computes what *should* exist and never touches the
//! system. That is what lets `xraytui tun plan` show the exact set of changes
//! before any of them happen, and what lets the interesting decisions — which
//! prefixes escape the tunnel, and in what order — be tested without root.
//!
//! # The shape of the answer
//!
//! One routing table per user holds the tunnel's routes. Traffic reaches it
//! through a single policy rule matching the user's firewall mark. Inside the
//! table:
//!
//! * `include` prefixes (or the default route, if none were given) point at the
//!   tunnel;
//! * `exclude` prefixes, the configured proxy endpoints, and — when asked —
//!   the private address space become **`throw`** routes, which abandon this
//!   table and continue with the next rule, i.e. the machine's ordinary
//!   routing. `throw` is used rather than copying the main table's routes
//!   because a copy goes stale the moment the physical link changes.
//!
//! The proxy endpoints matter most: without them the core's own connection to
//! the proxy would be routed into the tunnel the core is providing, which is a
//! loop that presents as "the tunnel comes up and nothing works".

use std::net::IpAddr;

use ipnet::IpNet;
use xraytui_netd_protocol::RoutingRequest;

/// Prefixes that should not normally traverse a tunnel.
///
/// RFC 1918 and RFC 4193 space, link-local addresses including the cloud
/// metadata address, loopback, and multicast. Excluding these keeps printers,
/// NAS boxes, `.local` discovery and the local network working while the
/// default route belongs to the tunnel.
const PRIVATE_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

/// The IPv6 equivalents.
const PRIVATE_V6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];

/// What to do with one prefix inside the user's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    /// Send it into the tunnel.
    Tunnel(IpNet),
    /// Abandon this table and continue with ordinary routing.
    Throw(IpNet),
    /// Discard it. Used for the IPv6 kill switch and for a lapsed lease under
    /// [`xraytui_netd_protocol::FailurePolicy::Block`].
    Blackhole(IpNet),
}

impl RouteAction {
    /// The prefix this action applies to.
    #[must_use]
    pub fn prefix(&self) -> IpNet {
        match self {
            Self::Tunnel(net) | Self::Throw(net) | Self::Blackhole(net) => *net,
        }
    }

    /// Short verb for the plan output.
    #[must_use]
    pub fn verb(&self) -> &'static str {
        match self {
            Self::Tunnel(_) => "tunnel",
            Self::Throw(_) => "bypass",
            Self::Blackhole(_) => "blackhole",
        }
    }
}

/// The complete set of changes one [`RoutingRequest`] implies.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoutingPlan {
    /// Routes to install in the user's table, in the order they are added.
    pub routes: Vec<RouteAction>,
}

impl RoutingPlan {
    /// Whether the plan would install nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Prefixes that end up in the tunnel.
    #[must_use]
    pub fn tunnelled(&self) -> Vec<IpNet> {
        self.routes
            .iter()
            .filter_map(|action| match action {
                RouteAction::Tunnel(net) => Some(*net),
                _ => None,
            })
            .collect()
    }

    /// Prefixes that leave the table for ordinary routing.
    #[must_use]
    pub fn bypassed(&self) -> Vec<IpNet> {
        self.routes
            .iter()
            .filter_map(|action| match action {
                RouteAction::Throw(net) => Some(*net),
                _ => None,
            })
            .collect()
    }
}

/// Compute the routes for a request.
///
/// `has_v4` and `has_v6` say which families the tunnel actually carries — a
/// device with no IPv6 address cannot be the target of an IPv6 route.
#[must_use]
pub fn compute(request: &RoutingRequest, has_v4: bool, has_v6: bool) -> RoutingPlan {
    let mut routes = Vec::new();

    // The tunnel's own destinations first, so that the throw routes below are
    // strictly more specific and therefore win.
    if request.include.is_empty() {
        if has_v4 && !request.blackhole_ipv4 {
            routes.push(RouteAction::Tunnel(default_v4()));
        }
        if has_v6 && !request.blackhole_ipv6 {
            routes.push(RouteAction::Tunnel(default_v6()));
        }
    } else {
        for prefix in &request.include {
            if (prefix.addr().is_ipv4() && has_v4 && !request.blackhole_ipv4)
                || (prefix.addr().is_ipv6() && has_v6 && !request.blackhole_ipv6)
            {
                routes.push(RouteAction::Tunnel(*prefix));
            }
        }
    }

    // A family that policy says the tunnel does not carry must be discarded
    // rather than left to find its own way out, which would be a leak that is
    // invisible until it matters.
    if request.blackhole_ipv4 && !routes.iter().any(|route| route.prefix().addr().is_ipv4()) {
        routes.push(RouteAction::Blackhole(default_v4()));
    }
    if request.blackhole_ipv6 && !routes.iter().any(|route| route.prefix().addr().is_ipv6()) {
        routes.push(RouteAction::Blackhole(default_v6()));
    }

    if request.bypass_private {
        for text in PRIVATE_V4 {
            if let Ok(prefix) = text.parse::<IpNet>() {
                routes.push(RouteAction::Throw(prefix));
            }
        }
        if has_v6 || request.blackhole_ipv6 {
            for text in PRIVATE_V6 {
                if let Ok(prefix) = text.parse::<IpNet>() {
                    routes.push(RouteAction::Throw(prefix));
                }
            }
        }
    }

    for prefix in &request.exclude {
        routes.push(RouteAction::Throw(*prefix));
    }

    // Host routes for the proxies come last so nothing can shadow them: if
    // these are wrong, the tunnel cannot come up at all.
    for address in &request.bypass_endpoints {
        routes.push(RouteAction::Throw(host_prefix(*address)));
    }

    // A later, more specific route replaces an earlier identical one, so
    // duplicates are removed keeping the last occurrence.
    let mut seen = std::collections::HashSet::new();
    let mut deduplicated = Vec::with_capacity(routes.len());
    for action in routes.iter().rev() {
        if seen.insert(action.prefix()) {
            deduplicated.push(*action);
        }
    }
    deduplicated.reverse();

    RoutingPlan {
        routes: deduplicated,
    }
}

/// The policy-rule priority reserved for a uid's tunnel.
#[must_use]
pub fn rule_priority(uid: u32) -> u32 {
    xraytui_netd_protocol::RULE_PRIORITY_BASE + (uid % xraytui_netd_protocol::TABLE_ID_SPAN)
}

/// The policy-rule priority reserved for a uid's transparent profiles.
///
/// Deliberately *higher* — evaluated later — than the tunnel's, so that a
/// profile with its own listener takes precedence over the tunnel only when its
/// own mark is set, and the tunnel keeps everything else.
#[must_use]
pub fn transparent_rule_priority(uid: u32) -> u32 {
    xraytui_netd_protocol::RULE_PRIORITY_BASE
        + xraytui_netd_protocol::TABLE_ID_SPAN
        + (uid % xraytui_netd_protocol::TABLE_ID_SPAN)
}

/// `0.0.0.0/0`
#[must_use]
pub fn default_v4() -> IpNet {
    IpNet::new(IpAddr::from([0u8; 4]), 0).unwrap_or_else(|_| unreachable_prefix())
}

/// `::/0`
#[must_use]
pub fn default_v6() -> IpNet {
    IpNet::new(IpAddr::from([0u8; 16]), 0).unwrap_or_else(|_| unreachable_prefix())
}

/// A single-address prefix.
#[must_use]
pub fn host_prefix(address: IpAddr) -> IpNet {
    let bits = if address.is_ipv4() { 32 } else { 128 };
    IpNet::new(address, bits).unwrap_or_else(|_| unreachable_prefix())
}

/// A prefix length is only invalid if it exceeds the address width, which none
/// of the constructors above can produce; this keeps the functions total
/// without a panic.
fn unreachable_prefix() -> IpNet {
    IpNet::V4(
        ipnet::Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
            .unwrap_or_else(|_| ipnet::Ipv4Net::default()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RoutingRequest {
        RoutingRequest {
            include: Vec::new(),
            exclude: Vec::new(),
            bypass_endpoints: Vec::new(),
            bypass_private: false,
            blackhole_ipv4: false,
            blackhole_ipv6: false,
        }
    }

    #[test]
    fn an_empty_include_list_means_the_default_route() {
        let plan = compute(&request(), true, false);
        assert_eq!(plan.tunnelled(), vec![default_v4()]);
    }

    #[test]
    fn a_family_the_tunnel_does_not_carry_gets_no_route() {
        let plan = compute(&request(), true, false);
        assert!(
            plan.routes
                .iter()
                .all(|route| route.prefix().addr().is_ipv4())
        );

        let mut spec = request();
        spec.include = vec!["fd00::/8".parse().expect("prefix")];
        let plan = compute(&spec, true, false);
        assert!(plan.is_empty(), "{plan:?}");
    }

    #[test]
    fn the_proxy_endpoints_are_always_bypassed() {
        let mut spec = request();
        spec.bypass_endpoints = vec!["203.0.113.7".parse().expect("address")];
        let plan = compute(&spec, true, false);
        assert!(
            plan.bypassed()
                .contains(&"203.0.113.7/32".parse().expect("prefix")),
            "{plan:?}"
        );
    }

    #[test]
    fn the_endpoint_bypass_survives_an_overlapping_exclude() {
        // A user who excludes 203.0.113.0/24 and also proxies through
        // 203.0.113.7 must still get the host route; the /32 is more specific.
        let mut spec = request();
        spec.exclude = vec!["203.0.113.0/24".parse().expect("prefix")];
        spec.bypass_endpoints = vec!["203.0.113.7".parse().expect("address")];
        let plan = compute(&spec, true, false);
        let bypassed = plan.bypassed();
        assert!(bypassed.contains(&"203.0.113.0/24".parse().expect("prefix")));
        assert!(bypassed.contains(&"203.0.113.7/32".parse().expect("prefix")));
    }

    #[test]
    fn private_space_is_bypassed_only_when_asked() {
        let plan = compute(&request(), true, false);
        assert!(plan.bypassed().is_empty());

        let mut spec = request();
        spec.bypass_private = true;
        let plan = compute(&spec, true, false);
        for text in PRIVATE_V4 {
            let prefix: IpNet = text.parse().expect("prefix");
            assert!(plan.bypassed().contains(&prefix), "{text} missing");
        }
    }

    #[test]
    fn unwanted_ipv6_is_blackholed_rather_than_left_to_leak() {
        let mut spec = request();
        spec.blackhole_ipv6 = true;
        let plan = compute(&spec, true, true);
        assert!(
            plan.routes.contains(&RouteAction::Blackhole(default_v6())),
            "{plan:?}"
        );
        assert!(
            !plan.tunnelled().contains(&default_v6()),
            "IPv6 cannot be both blackholed and tunnelled"
        );
    }

    #[test]
    fn unwanted_ipv4_is_blackholed_rather_than_left_to_leak() {
        let mut spec = request();
        spec.blackhole_ipv4 = true;
        let plan = compute(&spec, true, true);
        assert!(
            plan.routes.contains(&RouteAction::Blackhole(default_v4())),
            "{plan:?}"
        );
        assert!(
            !plan.tunnelled().contains(&default_v4()),
            "IPv4 cannot be both blackholed and tunnelled"
        );
    }

    #[test]
    fn a_duplicated_prefix_appears_once_with_the_later_action() {
        let mut spec = request();
        spec.include = vec!["198.51.100.0/24".parse().expect("prefix")];
        spec.exclude = vec!["198.51.100.0/24".parse().expect("prefix")];
        let plan = compute(&spec, true, false);
        let matching: Vec<_> = plan
            .routes
            .iter()
            .filter(|route| route.prefix().to_string() == "198.51.100.0/24")
            .collect();
        assert_eq!(matching.len(), 1);
        assert!(matches!(matching[0], RouteAction::Throw(_)));
    }

    #[test]
    fn tunnel_routes_are_installed_before_the_bypasses_that_override_them() {
        let mut spec = request();
        spec.bypass_private = true;
        spec.bypass_endpoints = vec!["203.0.113.7".parse().expect("address")];
        let plan = compute(&spec, true, false);
        let first_throw = plan
            .routes
            .iter()
            .position(|route| matches!(route, RouteAction::Throw(_)))
            .expect("a throw route");
        let last_tunnel = plan
            .routes
            .iter()
            .rposition(|route| matches!(route, RouteAction::Tunnel(_)))
            .expect("a tunnel route");
        assert!(last_tunnel < first_throw);
    }

    #[test]
    fn the_transparent_priority_never_collides_with_the_tunnel_priority() {
        for uid in [0u32, 1, 63, 64, 1000, u32::MAX] {
            assert_ne!(rule_priority(uid), transparent_rule_priority(uid));
            assert!(transparent_rule_priority(uid) > rule_priority(uid));
        }
        // And no two users share either.
        let tunnels: std::collections::BTreeSet<u32> = (0..64).map(rule_priority).collect();
        assert_eq!(tunnels.len(), 64);
    }

    #[test]
    fn rule_priorities_stay_inside_the_reserved_band() {
        for uid in [0u32, 1000, 65_534, u32::MAX] {
            let priority = rule_priority(uid);
            assert!(priority >= xraytui_netd_protocol::RULE_PRIORITY_BASE);
            assert!(
                priority
                    < xraytui_netd_protocol::RULE_PRIORITY_BASE
                        + xraytui_netd_protocol::TABLE_ID_SPAN
            );
        }
    }

    #[test]
    fn host_prefixes_use_the_full_width_of_the_address() {
        assert_eq!(
            host_prefix("203.0.113.7".parse().expect("address")).prefix_len(),
            32
        );
        assert_eq!(
            host_prefix("2001:db8::1".parse().expect("address")).prefix_len(),
            128
        );
    }
}
