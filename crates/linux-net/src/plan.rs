//! Saying exactly what would change, before anything does.
//!
//! `xraytui tun plan` is the answer to a reasonable question — *what is this
//! about to do to my machine?* — and the brief requires that it be answerable
//! without making a single change. Everything here is derived from the same
//! functions the apply path uses ([`crate::routing::compute`],
//! [`crate::nft::user_ruleset`]), so the plan cannot drift away from the
//! behaviour it describes.

use xraytui_netd_protocol::{DnsBackend, PlanRequest};

use crate::{cgroup, nft, routing};

/// Render the steps a [`PlanRequest`] would take, in order.
///
/// The uid is the credential from `SO_PEERCRED`; every resource name in the
/// output is derived from it, which is also what makes the plan a useful way to
/// check that a user cannot address somebody else's state.
#[must_use]
pub fn render(uid: u32, request: &PlanRequest) -> Vec<String> {
    let mut steps = Vec::new();
    let interface = &request.tun.interface;
    let table = xraytui_netd_protocol::table_for_uid(uid);
    let fwmark = xraytui_netd_protocol::fwmark_for_uid(uid);
    let priority = routing::rule_priority(uid);

    steps.push(format!(
        "create persistent tun {interface} (mtu {}, owner uid {uid})",
        request.tun.mtu
    ));
    if let Some(prefix) = request.tun.ipv4 {
        steps.push(format!("add address {prefix} to {interface}"));
    }
    if let Some(prefix) = request.tun.ipv6 {
        steps.push(format!("add address {prefix} to {interface}"));
    }
    steps.push(format!("bring {interface} up"));

    let plan = routing::compute(
        &request.routing,
        request.tun.ipv4.is_some(),
        request.tun.ipv6.is_some(),
    );
    for action in &plan.routes {
        match action {
            routing::RouteAction::Tunnel(prefix) => {
                steps.push(format!("route {prefix} via {interface} in table {table}"));
            }
            routing::RouteAction::Throw(prefix) => {
                steps.push(format!(
                    "route {prefix} throw in table {table} (leaves the tunnel)"
                ));
            }
            routing::RouteAction::Blackhole(prefix) => {
                steps.push(format!("blackhole {prefix} in table {table}"));
            }
        }
    }
    steps.push(format!(
        "add ip rule: fwmark {fwmark:#x} lookup {table} priority {priority}"
    ));

    if request.firewall.bypass_uid {
        steps.push(format!(
            "nftables: accept traffic from cgroup {} unmarked",
            cgroup::relative_path(uid, cgroup::CORE_PROFILE)
        ));
    }
    for entry in &request.firewall.cgroup_marks {
        steps.push(format!(
            "nftables: mark traffic from cgroup {} with {:#x}",
            cgroup::relative_path(uid, &entry.profile),
            entry.mark
        ));
    }
    if request.firewall.kill_switch {
        steps.push(format!(
            "nftables: drop traffic marked {fwmark:#x} that does not leave by {interface}"
        ));
    }
    if !request.firewall.cgroup_marks.is_empty() || request.firewall.kill_switch {
        steps.push(format!(
            "nftables: all of the above inside table {} {} only",
            xraytui_netd_protocol::NFT_FAMILY,
            xraytui_netd_protocol::NFT_TABLE
        ));
    }

    match request.dns.backend {
        DnsBackend::None => steps.push("dns: leave system resolver configuration alone".to_owned()),
        DnsBackend::SystemdResolved => {
            steps.push(format!(
                "dns: systemd-resolved SetLinkDNS on {interface} -> {}",
                join_addresses(&request.dns.servers)
            ));
            if !request.dns.domains.is_empty() {
                steps.push(format!(
                    "dns: systemd-resolved SetLinkDomains on {interface} -> {}",
                    request.dns.domains.join(", ")
                ));
            }
        }
        DnsBackend::Resolvconf => steps.push(format!(
            "dns: resolvconf -a {interface} <- {}",
            join_addresses(&request.dns.servers)
        )),
    }

    steps.push(format!(
        "lease: {} seconds, {} on expiry",
        request.tun.lease_ttl_secs,
        match request.tun.failure_policy {
            xraytui_netd_protocol::FailurePolicy::Restore => "remove every change listed above",
            xraytui_netd_protocol::FailurePolicy::Block =>
                "blackhole the table so traffic cannot fall back to direct",
        }
    ));

    steps
}

/// The nftables script a plan would apply, verbatim, for review.
///
/// Printing it is the point: an administrator asked to trust a privileged
/// helper with their firewall should be able to read exactly what it will add.
#[must_use]
pub fn firewall_script(uid: u32, request: &PlanRequest) -> String {
    let fwmark = xraytui_netd_protocol::fwmark_for_uid(uid);
    nft::user_ruleset(uid, &request.tun.interface, fwmark, &request.firewall)
        .map(|script| script.as_str().to_owned())
        .unwrap_or_else(|error| format!("# refused: {error}\n"))
}

fn join_addresses(addresses: &[std::net::IpAddr]) -> String {
    if addresses.is_empty() {
        return "(none)".to_owned();
    }
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_netd_protocol::{
        CgroupMark, DnsRequest, FailurePolicy, FirewallRequest, RoutingRequest, TunRequest,
    };

    fn request(uid: u32) -> PlanRequest {
        PlanRequest {
            tun: TunRequest {
                interface: xraytui_netd_protocol::interface_for_uid(uid),
                mtu: 1500,
                ipv4: "198.18.0.1/15".parse().ok(),
                ipv6: None,
                lease_ttl_secs: 30,
                failure_policy: FailurePolicy::Restore,
            },
            routing: RoutingRequest {
                include: Vec::new(),
                exclude: Vec::new(),
                bypass_endpoints: vec!["203.0.113.7".parse().expect("address")],
                bypass_private: true,
                blackhole_ipv6: true,
            },
            firewall: FirewallRequest {
                cgroup_marks: vec![CgroupMark {
                    profile: "work".into(),
                    mark: xraytui_netd_protocol::FWMARK_BASE + 1,
                }],
                kill_switch: true,
                bypass_uid: true,
            },
            dns: DnsRequest {
                backend: DnsBackend::SystemdResolved,
                servers: vec!["198.18.0.2".parse().expect("address")],
                domains: vec!["~.".into()],
            },
        }
    }

    #[test]
    fn every_step_names_only_resources_derived_from_the_uid() {
        let steps = render(1000, &request(1000));
        let joined = steps.join("\n");
        assert!(joined.contains("xraytui1000"));
        assert!(joined.contains(&format!("{}", xraytui_netd_protocol::table_for_uid(1000))));
        assert!(!joined.contains("eth0"));
        assert!(!joined.contains("u1001"));
    }

    #[test]
    fn the_plan_starts_with_creation_and_ends_with_the_lease() {
        let steps = render(1000, &request(1000));
        assert!(
            steps
                .first()
                .expect("first")
                .starts_with("create persistent tun")
        );
        assert!(steps.last().expect("last").starts_with("lease:"));
    }

    #[test]
    fn the_proxy_endpoint_bypass_is_visible_in_the_plan() {
        let steps = render(1000, &request(1000)).join("\n");
        assert!(steps.contains("203.0.113.7/32 throw"), "{steps}");
    }

    #[test]
    fn a_block_policy_says_so_in_plain_words() {
        let mut spec = request(1000);
        spec.tun.failure_policy = FailurePolicy::Block;
        let steps = render(1000, &spec);
        assert!(
            steps.last().expect("last").contains("blackhole the table"),
            "{steps:?}"
        );
    }

    #[test]
    fn the_none_dns_backend_says_it_will_not_touch_the_resolver() {
        let mut spec = request(1000);
        spec.dns.backend = DnsBackend::None;
        spec.dns.servers.clear();
        let steps = render(1000, &spec).join("\n");
        assert!(steps.contains("leave system resolver configuration alone"));
    }

    #[test]
    fn the_firewall_script_is_reviewable_and_names_only_our_table() {
        let text = firewall_script(1000, &request(1000));
        assert!(!text.is_empty());
        for line in text.lines() {
            assert!(
                line.contains(&format!(
                    "{} {}",
                    xraytui_netd_protocol::NFT_FAMILY,
                    xraytui_netd_protocol::NFT_TABLE
                )),
                "{line}"
            );
        }
    }

    #[test]
    fn planning_changes_nothing_observable() {
        // The function is pure; this asserts it stays that way by planning for
        // an interface that does not exist and expecting no error path at all.
        let mut spec = request(4242);
        spec.tun.interface = "xraytui4242".into();
        let steps = render(4242, &spec);
        assert!(!steps.is_empty());
        assert!(!std::path::Path::new("/sys/class/net/xraytui4242").exists());
    }
}
