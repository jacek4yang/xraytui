//! Privileged tests, run **only** inside a disposable network namespace.
//!
//! # How to run them
//!
//! ```sh
//! sudo ./scripts/netns-test.sh
//! ```
//!
//! The script creates a fresh network, mount and PID namespace with
//! `unshare(1)`, mounts a private cgroup v2 hierarchy inside it, and then runs
//! this test binary with `XRAYTUI_NETNS_TESTS=1`. Without that variable every
//! test below returns immediately, so `cargo test` on a developer's machine —
//! or in CI without privileges — never touches host networking.
//!
//! # What they prove
//!
//! | Test | Acceptance scenario |
//! |---|---|
//! | `a_tunnel_comes_up_with_its_addresses_and_routes` | C |
//! | `traffic_reaches_the_tunnel_through_the_mark` | C |
//! | `an_expired_lease_is_reclaimed` | J |
//! | `a_block_policy_leaves_the_table_blackholed` | J |
//! | `repeated_enable_and_disable_leaves_no_residue` | K |
//! | `a_process_is_classified_by_its_pidfd` | M |
//! | `the_firewall_marks_only_the_named_cgroup` | M |
//! | `dual_stack_routes_both_families_into_the_tunnel` | IPv4 + IPv6, both proxied |
//! | `a_legacy_lease_recovers_families_from_the_live_tun` | in-place v1 lease migration |
//! | `ipv4_only_blackholes_ipv6_despite_a_direct_route` | IPv4-only + IPv6 no-leak |
//! | `ipv6_only_blackholes_ipv4_despite_a_direct_route` | IPv6-only + IPv4 no-leak |
//! | `mixed_family_policy_can_proxy_ipv4_and_leave_ipv6_direct` | proxy IPv4 + direct IPv6 |
//! | `mixed_family_policy_can_proxy_ipv6_and_leave_ipv4_direct` | proxy IPv6 + direct IPv4 |
//! | `a_broken_tun_cannot_leak_either_family_past_the_kill_switch` | broken route + kill switch |
//! | `ipv6_disabled_kernel_refuses_ipv6_tun_but_keeps_ipv4_fail_closed` | kernel IPv6 disabled |
//! | `state_this_project_did_not_create_is_left_alone` | the safety property under all of them |

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::path::PathBuf;
use std::process::Command;

use xraytui_linux_net::netlink::Netlink;
use xraytui_linux_net::netlink::message::{
    AF_INET, AF_INET6, RTN_BLACKHOLE, RTN_THROW, RTPROT_XRAYTUI,
};
use xraytui_linux_net::nft::Nft;
use xraytui_linux_net::{Engine, EngineOptions, routing};
use xraytui_netd_protocol::{
    CgroupMark, DnsBackend, DnsRequest, FailurePolicy, FirewallRequest, NetdError, Operation,
    Outcome, RoutingRequest, TunRequest,
};

/// The uid every test acts as. Inside the namespace this is the real uid, so
/// `SO_PEERCRED` would report the same value.
const UID: u32 = 0;

/// Whether the privileged suite was asked for.
fn enabled() -> bool {
    std::env::var_os("XRAYTUI_NETNS_TESTS").is_some()
}

/// Refuse to run outside a namespace even if the variable is set by accident.
///
/// A network namespace of our own has exactly one interface — loopback — plus
/// whatever we made. Seeing a physical interface means the variable was set on
/// a real machine, and the right thing to do is stop.
fn assert_disposable_namespace() {
    let netlink = Netlink::open().expect("netlink");
    let links = netlink.links_with_prefix("").expect("list interfaces");
    let foreign: Vec<&String> = links
        .iter()
        .map(|(name, _)| name)
        .filter(|name| *name != "lo" && !name.starts_with("xraytui"))
        .collect();
    assert!(
        foreign.is_empty(),
        "refusing to run privileged tests outside a disposable namespace; found {foreign:?}"
    );
}

struct Fixture {
    engine: Engine,
    state: tempfile::TempDir,
    cgroup_root: Option<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        assert_disposable_namespace();
        let state = tempfile::tempdir().expect("temp dir");
        let cgroup_root = std::env::var_os("XRAYTUI_TEST_CGROUP_ROOT").map(PathBuf::from);
        let mut options = EngineOptions {
            state_dir: state.path().join("state"),
            nft: Nft::new("nft"),
            ..EngineOptions::default()
        };
        if let Some(root) = &cgroup_root {
            options.cgroup_root = root.clone();
        }
        let engine = Engine::new(options).expect("engine");
        Self {
            engine,
            state,
            cgroup_root,
        }
    }

    fn apply(&self, operation: Operation) -> Result<Outcome, NetdError> {
        self.engine
            .handle(UID, &operation, None)
            .map(|response| response.outcome)
    }

    fn interface(&self) -> String {
        xraytui_netd_protocol::interface_for_uid(UID)
    }

    fn table(&self) -> u32 {
        xraytui_netd_protocol::table_for_uid(UID)
    }

    fn lease_path(&self) -> PathBuf {
        self.state.path().join(format!("state/u{UID}.json"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Leave the namespace as we found it even when an assertion failed.
        let _ = self.engine.release(UID);
    }
}

fn tun_request() -> TunRequest {
    TunRequest {
        interface: xraytui_netd_protocol::interface_for_uid(UID),
        mtu: 1400,
        ipv4: Some("198.18.0.1/15".parse().expect("prefix")),
        ipv6: None,
        lease_ttl_secs: 30,
        failure_policy: FailurePolicy::Restore,
    }
}

fn routing_request() -> RoutingRequest {
    RoutingRequest {
        include: Vec::new(),
        exclude: vec!["198.51.100.0/24".parse().expect("prefix")],
        bypass_endpoints: vec!["203.0.113.7".parse().expect("address")],
        bypass_private: true,
        blackhole_ipv4: false,
        blackhole_ipv6: true,
    }
}

fn family_tun(ipv4: bool, ipv6: bool, failure_policy: FailurePolicy) -> TunRequest {
    TunRequest {
        interface: xraytui_netd_protocol::interface_for_uid(UID),
        mtu: 1400,
        ipv4: ipv4.then(|| "198.18.0.1/15".parse().expect("IPv4 TUN prefix")),
        ipv6: ipv6.then(|| "fdfe:dcba:9876::1/126".parse().expect("IPv6 TUN prefix")),
        lease_ttl_secs: 30,
        failure_policy,
    }
}

fn family_routing(blackhole_ipv4: bool, blackhole_ipv6: bool) -> RoutingRequest {
    RoutingRequest {
        include: Vec::new(),
        exclude: Vec::new(),
        bypass_endpoints: Vec::new(),
        bypass_private: false,
        blackhole_ipv4,
        blackhole_ipv6,
    }
}

// ---------------------------------------------------------------------------

#[test]
fn a_tunnel_comes_up_with_its_addresses_and_routes() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();

    let outcome = fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");
    let (interface, index, table, fwmark) = match outcome {
        Outcome::TunCreated {
            interface,
            index,
            table,
            fwmark,
            fd_attached,
        } => {
            assert!(fd_attached, "the liveness descriptor must be returned");
            (interface, index, table, fwmark)
        }
        other => panic!("unexpected outcome {other:?}"),
    };
    assert_eq!(interface, fixture.interface());
    assert_eq!(table, fixture.table());
    assert_eq!(fwmark, xraytui_netd_protocol::fwmark_for_uid(UID));

    let netlink = Netlink::open().expect("netlink");
    assert_eq!(netlink.link_index(&interface).expect("index"), index);

    // The device is up, with the requested MTU and address. `ip addr` carries
    // the address and `ip link` the MTU and flags, so both are consulted.
    let addresses = ip(&["-o", "addr", "show", &interface]);
    assert!(addresses.contains("198.18.0.1/15"), "{addresses}");
    let link = ip(&["-o", "link", "show", &interface]);
    assert!(link.contains("mtu 1400"), "{link}");
    assert!(
        link.contains("state UNKNOWN") || link.contains("UP"),
        "{link}"
    );

    fixture
        .apply(Operation::ApplyRouting(routing_request()))
        .expect("apply routing");

    let routes = netlink.routes_in_table(table).expect("routes");
    let default = routes
        .iter()
        .find(|route| route.destination.is_none() && route.family == AF_INET)
        .expect("a default route in the table");
    assert_eq!(
        default.oif,
        Some(index),
        "the default route must use the tunnel"
    );
    assert_eq!(
        default.protocol, RTPROT_XRAYTUI,
        "routes must be tagged as ours"
    );

    let bypass = routes
        .iter()
        .find(|route| {
            route
                .destination
                .is_some_and(|prefix| prefix.to_string() == "203.0.113.7/32")
        })
        .expect("the proxy endpoint must bypass the tunnel");
    assert_eq!(
        bypass.kind, RTN_THROW,
        "the endpoint must leave the table rather than be tunnelled"
    );

    assert!(
        routes.iter().any(|route| route
            .destination
            .is_some_and(|prefix| prefix.to_string() == "198.51.100.0/24")),
        "an excluded prefix must be present as a throw route"
    );
    assert!(
        routes.iter().any(|route| route
            .destination
            .is_some_and(|prefix| prefix.to_string() == "10.0.0.0/8")),
        "private space must be present when bypass_private is set"
    );

    let priority = routing::rule_priority(UID);
    let rules = netlink.rules(AF_INET).expect("rules");
    let rule = rules
        .iter()
        .find(|rule| rule.priority == priority)
        .expect("the fwmark rule must exist");
    assert_eq!(rule.fwmark, Some(fwmark));
    assert_eq!(rule.table, Some(table));
}

#[test]
fn traffic_reaches_the_tunnel_through_the_mark() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");
    fixture
        .apply(Operation::ApplyRouting(routing_request()))
        .expect("apply routing");

    let fwmark = xraytui_netd_protocol::fwmark_for_uid(UID);
    let interface = fixture.interface();

    // `ip route get` performs the kernel's own lookup, which is the only way to
    // assert that the arrangement really works rather than that it was merely
    // installed.
    //
    // An excluded prefix must leave our table via the `throw` route and fall
    // through to the main table. The namespace has no default route there, so
    // "network is unreachable" is the *correct* answer — what matters is that
    // the tunnel is not the answer.
    let excluded = ip_allow_failure(&[
        "route",
        "get",
        "198.51.100.1",
        "mark",
        &format!("{fwmark:#x}"),
    ]);
    assert!(
        !excluded.contains(&interface),
        "an excluded prefix must not be tunnelled even when marked: {excluded}"
    );
    assert!(
        excluded.contains("unreachable") || excluded.contains("Network is unreachable"),
        "an excluded prefix must fall through to ordinary routing: {excluded}"
    );

    let tunnelled = ip(&["route", "get", "192.0.2.1", "mark", &format!("{fwmark:#x}")]);
    assert!(
        tunnelled.contains(&interface),
        "marked traffic must be routed into the tunnel: {tunnelled}"
    );

    let endpoint = ip_allow_failure(&[
        "route",
        "get",
        "203.0.113.7",
        "mark",
        &format!("{fwmark:#x}"),
    ]);
    assert!(
        !endpoint.contains(&interface),
        "the proxy endpoint must never be routed into the tunnel it feeds: {endpoint}"
    );
}

#[test]
fn a_contradictory_family_update_preserves_the_working_routes() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            false,
            FailurePolicy::Restore,
        )))
        .expect("create IPv4-only TUN");
    fixture
        .apply(Operation::ApplyRouting(family_routing(false, true)))
        .expect("install working policy");

    let netlink = Netlink::open().expect("netlink");
    let before = netlink
        .routes_in_table(fixture.table())
        .expect("working routes");
    let error = fixture
        .apply(Operation::ApplyRouting(RoutingRequest {
            include: vec!["2001:db8:1234::/48".parse().expect("IPv6 prefix")],
            exclude: Vec::new(),
            bypass_endpoints: Vec::new(),
            bypass_private: false,
            blackhole_ipv4: false,
            blackhole_ipv6: true,
        }))
        .expect_err("the TUN has no IPv6 family");
    assert!(
        error.to_string().contains("not configured for IPv6"),
        "{error}"
    );
    let after = netlink
        .routes_in_table(fixture.table())
        .expect("routes after refusal");
    assert_eq!(
        after, before,
        "candidate validation must happen before the working table is flushed"
    );
}

#[test]
fn dual_stack_routes_both_families_into_the_tunnel() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let direct = DirectEgress::start();
    fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            true,
            FailurePolicy::Restore,
        )))
        .expect("create dual-stack TUN");
    fixture
        .apply(Operation::ApplyRouting(family_routing(false, false)))
        .expect("route both families");

    assert_marked_route("198.51.100.9", &fixture.interface(), &direct.interface);
    assert_marked_route("2001:db8:ffff::9", &fixture.interface(), &direct.interface);
    assert_eq!(
        marked_udp_source("198.51.100.9").as_deref(),
        Some("198.18.0.1")
    );
    assert_eq!(
        marked_udp_source("2001:db8:ffff::9").as_deref(),
        Some("fdfe:dcba:9876::1")
    );

    let netlink = Netlink::open().expect("netlink");
    let routes = netlink
        .routes_in_table(fixture.table())
        .expect("dual-stack routes");
    for family in [AF_INET, AF_INET6] {
        assert!(
            routes.iter().any(|route| {
                route.family == family && route.destination.is_none() && route.kind != RTN_BLACKHOLE
            }),
            "family {family} has no tunnel default: {routes:?}"
        );
        assert!(
            netlink
                .rules(family)
                .expect("policy rules")
                .iter()
                .any(|rule| rule.priority == routing::rule_priority(UID)),
            "family {family} has no policy rule"
        );
    }
}

#[test]
fn a_legacy_lease_recovers_families_from_the_live_tun() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            true,
            FailurePolicy::Restore,
        )))
        .expect("create dual-stack TUN");

    let lease_path = fixture.lease_path();
    let mut lease: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lease_path).expect("read current lease"))
            .expect("decode current lease");
    let object = lease.as_object_mut().expect("lease object");
    object.remove("ipv4");
    object.remove("ipv6");
    std::fs::write(
        &lease_path,
        serde_json::to_vec_pretty(&lease).expect("encode legacy lease"),
    )
    .expect("install legacy lease fixture");

    fixture
        .apply(Operation::ApplyRouting(family_routing(false, false)))
        .expect("recover both families from live TUN addresses");

    let netlink = Netlink::open().expect("netlink");
    let index = netlink.link_index(&fixture.interface()).expect("TUN index");
    let addresses = netlink.addresses_on_link(index).expect("TUN addresses");
    assert!(
        addresses.iter().any(|prefix| prefix.addr().is_ipv4()),
        "IPv4 address missing from netlink dump: {addresses:?}"
    );
    assert!(
        addresses.iter().any(|prefix| prefix.addr().is_ipv6()),
        "IPv6 address missing from netlink dump: {addresses:?}"
    );
    let routes = netlink
        .routes_in_table(fixture.table())
        .expect("recovered routes");
    for family in [AF_INET, AF_INET6] {
        assert!(
            routes.iter().any(|route| {
                route.family == family && route.destination.is_none() && route.oif == Some(index)
            }),
            "legacy lease did not recover family {family}: {routes:?}"
        );
    }
}

#[test]
fn ipv4_only_blackholes_ipv6_despite_a_direct_route() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let direct = DirectEgress::start();
    fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            false,
            FailurePolicy::Restore,
        )))
        .expect("create IPv4-only TUN");
    fixture
        .apply(Operation::ApplyRouting(family_routing(false, true)))
        .expect("route IPv4 and block IPv6");

    assert_marked_route("198.51.100.9", &fixture.interface(), &direct.interface);
    assert_marked_blackhole("2001:db8:ffff::9", &direct.interface);
    assert_eq!(
        marked_udp_source("198.51.100.9").as_deref(),
        Some("198.18.0.1")
    );
    assert!(
        marked_udp_source("2001:db8:ffff::9").is_none(),
        "marked IPv6 must fail rather than use the direct route"
    );
    assert_eq!(
        udp_source("2001:db8:ffff::9").as_deref(),
        Some("2001:db8:1::1"),
        "the host's direct IPv6 route must be usable so the no-leak assertion is meaningful"
    );
}

#[test]
fn ipv6_only_blackholes_ipv4_despite_a_direct_route() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let direct = DirectEgress::start();
    fixture
        .apply(Operation::CreateTun(family_tun(
            false,
            true,
            FailurePolicy::Restore,
        )))
        .expect("create IPv6-only TUN");
    fixture
        .apply(Operation::ApplyRouting(family_routing(true, false)))
        .expect("route IPv6 and block IPv4");

    assert_marked_blackhole("198.51.100.9", &direct.interface);
    assert_marked_route("2001:db8:ffff::9", &fixture.interface(), &direct.interface);
    assert!(
        marked_udp_source("198.51.100.9").is_none(),
        "marked IPv4 must fail rather than use the direct route"
    );
    assert_eq!(
        marked_udp_source("2001:db8:ffff::9").as_deref(),
        Some("fdfe:dcba:9876::1")
    );
    assert_eq!(
        udp_source("198.51.100.9").as_deref(),
        Some("192.0.2.1"),
        "the host's direct IPv4 route must be usable so the no-leak assertion is meaningful"
    );
}

#[test]
fn mixed_family_policy_can_proxy_ipv4_and_leave_ipv6_direct() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let direct = DirectEgress::start();
    fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            false,
            FailurePolicy::Restore,
        )))
        .expect("create IPv4-only TUN");
    fixture
        .apply(Operation::ApplyRouting(family_routing(false, false)))
        .expect("proxy IPv4 and leave IPv6 direct");

    assert_marked_route("198.51.100.9", &fixture.interface(), &direct.interface);
    assert_marked_route("2001:db8:ffff::9", &direct.interface, &fixture.interface());
    assert_eq!(
        marked_udp_source("2001:db8:ffff::9").as_deref(),
        Some("2001:db8:1::1")
    );
}

#[test]
fn mixed_family_policy_can_proxy_ipv6_and_leave_ipv4_direct() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let direct = DirectEgress::start();
    fixture
        .apply(Operation::CreateTun(family_tun(
            false,
            true,
            FailurePolicy::Restore,
        )))
        .expect("create IPv6-only TUN");
    fixture
        .apply(Operation::ApplyRouting(family_routing(false, false)))
        .expect("proxy IPv6 and leave IPv4 direct");

    assert_marked_route("198.51.100.9", &direct.interface, &fixture.interface());
    assert_marked_route("2001:db8:ffff::9", &fixture.interface(), &direct.interface);
    assert_eq!(
        marked_udp_source("198.51.100.9").as_deref(),
        Some("192.0.2.1")
    );
}

#[test]
fn a_broken_tun_cannot_leak_either_family_past_the_kill_switch() {
    if !enabled() {
        return;
    }
    let nft = Nft::new("nft");
    if !nft.available() {
        eprintln!("skipping: nft is not installed");
        return;
    }
    let fixture = Fixture::new();
    let direct = DirectEgress::start();
    fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            true,
            FailurePolicy::Block,
        )))
        .expect("create dual-stack TUN");
    fixture
        .apply(Operation::ApplyRouting(family_routing(false, false)))
        .expect("route both families");
    fixture
        .apply(Operation::ApplyFirewall(FirewallRequest {
            cgroup_marks: Vec::new(),
            kill_switch: true,
            bypass_uid: false,
        }))
        .expect("install kill switch");

    let interface = fixture.interface();
    ip(&["link", "delete", &interface]);
    // Deleting the route's device makes the kernel discard its routes. The
    // remaining marked lookup now resolves to the ordinary direct path: this
    // is the exact transient in which a kill switch has to do real work.
    assert_marked_route("198.51.100.9", &direct.interface, &interface);
    assert_marked_route("2001:db8:ffff::9", &direct.interface, &interface);
    assert_eq!(guard_packets(), 0, "the counter must start clean");

    assert_marked_udp_blocked("198.51.100.9");
    assert_marked_udp_blocked("2001:db8:ffff::9");
    assert_eq!(
        guard_packets(),
        2,
        "one IPv4 and one IPv6 packet must be stopped before direct egress"
    );
}

#[test]
fn ipv6_disabled_kernel_refuses_ipv6_tun_but_keeps_ipv4_fail_closed() {
    if !enabled() {
        return;
    }
    const INNER: &str = "XRAYTUI_IPV6_DISABLED_INNER";
    if std::env::var_os(INNER).is_none() {
        let executable = std::env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--net", "--fork", "--"])
            .arg(executable)
            .args([
                "--exact",
                "ipv6_disabled_kernel_refuses_ipv6_tun_but_keeps_ipv4_fail_closed",
                "--nocapture",
            ])
            .env(INNER, "1")
            .output()
            .expect("run the disabled-IPv6 child namespace");
        assert!(
            output.status.success(),
            "disabled-IPv6 child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    ip(&["link", "set", "lo", "up"]);
    for path in [
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    ] {
        std::fs::write(path, "1\n").expect("disable IPv6 inside disposable namespace");
    }
    assert!(
        std::path::Path::new("/proc/net/if_inet6").exists(),
        "the proc file remains present under sysctl disablement"
    );
    assert!(
        !xraytui_linux_net::capabilities::ipv6_tun_available(),
        "the capability probe must inspect the sysctls, not only file presence"
    );

    let fixture = Fixture::new();
    let error = fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            true,
            FailurePolicy::Restore,
        )))
        .expect_err("an IPv6 TUN must be refused before mutation");
    let text = error.to_string();
    assert!(text.contains("IPv6 TUN routing is unavailable"), "{text}");
    assert!(text.contains("IPv4 remains available"), "{text}");
    assert!(
        Netlink::open()
            .expect("netlink")
            .link_index(&fixture.interface())
            .is_err(),
        "the refused dual-stack request must leave no device"
    );

    fixture
        .apply(Operation::CreateTun(family_tun(
            true,
            false,
            FailurePolicy::Restore,
        )))
        .expect("IPv4 must remain available");
    fixture
        .apply(Operation::ApplyRouting(family_routing(false, true)))
        .expect("IPv4 route plus IPv6 blackhole must remain usable");
    let routes = Netlink::open()
        .expect("netlink")
        .routes_in_table(fixture.table())
        .expect("routes");
    assert!(
        routes.iter().any(|route| {
            route.family == AF_INET6 && route.kind == RTN_BLACKHOLE && route.destination.is_none()
        }),
        "IPv6 must remain fail-closed even when address configuration is disabled: {routes:?}"
    );
}

#[test]
fn an_expired_lease_is_reclaimed() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let mut request = tun_request();
    request.lease_ttl_secs = 1;
    fixture
        .apply(Operation::CreateTun(request))
        .expect("create tun");
    fixture
        .apply(Operation::ApplyRouting(routing_request()))
        .expect("apply routing");

    let netlink = Netlink::open().expect("netlink");
    assert!(netlink.link_index(&fixture.interface()).is_ok());

    // Sweep at a time past the deadline rather than sleeping: the lease uses
    // wall time, and the reaper takes the clock as a parameter for exactly this
    // reason.
    let removed = fixture
        .engine
        .recover(xraytui_linux_net::lease::now() + 3_600);
    assert!(
        removed.iter().any(|item| item.contains("expired lease")),
        "{removed:?}"
    );

    assert!(
        netlink.link_index(&fixture.interface()).is_err(),
        "the interface must be gone once the lease lapses"
    );
    assert!(
        netlink
            .routes_in_table(fixture.table())
            .expect("routes")
            .is_empty(),
        "the table must be empty once the lease lapses"
    );
    assert!(fixture.engine.leases().get(UID).is_none());
}

#[test]
fn a_block_policy_leaves_the_table_blackholed() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let mut request = tun_request();
    request.lease_ttl_secs = 1;
    request.failure_policy = FailurePolicy::Block;
    fixture
        .apply(Operation::CreateTun(request))
        .expect("create tun");
    fixture
        .apply(Operation::ApplyRouting(routing_request()))
        .expect("apply routing");

    let _ = fixture
        .engine
        .recover(xraytui_linux_net::lease::now() + 3_600);

    let netlink = Netlink::open().expect("netlink");
    assert!(
        netlink.link_index(&fixture.interface()).is_err(),
        "the device still goes; only the traffic decision is different"
    );

    let routes = netlink.routes_in_table(fixture.table()).expect("routes");
    assert!(
        routes
            .iter()
            .any(|route| route.kind == RTN_BLACKHOLE && route.destination.is_none()),
        "a lapsed block policy must discard traffic rather than let it out unprotected: {routes:?}"
    );

    let priority = routing::rule_priority(UID);
    let rules = netlink.rules(AF_INET).expect("rules");
    assert!(
        rules.iter().any(|rule| rule.priority == priority),
        "the rule must stay, or the blackhole would never be consulted"
    );

    // Tidy up: this is the one path that deliberately leaves state behind.
    let _ = ip_allow_failure(&["rule", "del", "priority", &priority.to_string()]);
    let _ = ip_allow_failure(&["rule", "del", "priority", &priority.to_string()]);
    let _ = netlink.flush_owned_routes(fixture.table());
}

#[test]
fn repeated_enable_and_disable_leaves_no_residue() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let netlink = Netlink::open().expect("netlink");
    let nft = Nft::new("nft");
    let has_cgroups = fixture.cgroup_root.is_some();

    let before_rules = netlink.rules(AF_INET).expect("rules").len();

    for round in 0..3 {
        fixture
            .apply(Operation::CreateTun(tun_request()))
            .unwrap_or_else(|error| panic!("round {round}: create tun: {error}"));
        fixture
            .apply(Operation::ApplyRouting(routing_request()))
            .unwrap_or_else(|error| panic!("round {round}: apply routing: {error}"));
        if has_cgroups && nft.available() {
            fixture
                .apply(Operation::ApplyFirewall(FirewallRequest {
                    cgroup_marks: vec![CgroupMark {
                        profile: "work".into(),
                        tproxy_port: Some(19001),
                    }],
                    kill_switch: true,
                    bypass_uid: true,
                }))
                .unwrap_or_else(|error| panic!("round {round}: apply firewall: {error}"));
        }

        let removed = fixture
            .engine
            .release(UID)
            .unwrap_or_else(|error| panic!("round {round}: release: {error}"));
        assert!(
            removed.iter().any(|item| item.contains("interface")),
            "round {round}: release reported {removed:?}"
        );

        assert!(
            netlink.link_index(&fixture.interface()).is_err(),
            "round {round}: the interface survived release"
        );
        assert!(
            netlink
                .routes_in_table(fixture.table())
                .expect("routes")
                .is_empty(),
            "round {round}: routes survived release"
        );
        assert_eq!(
            netlink.rules(AF_INET).expect("rules").len(),
            before_rules,
            "round {round}: policy rules accumulated"
        );
        if nft.available() {
            let chains = nft.chains().expect("chains");
            assert!(
                chains.is_empty(),
                "round {round}: nftables chains survived release: {chains:?}"
            );
        }
        assert!(
            fixture.engine.leases().get(UID).is_none(),
            "round {round}: the lease survived release"
        );
    }
}

#[test]
fn state_this_project_did_not_create_is_left_alone() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    let table = fixture.table();

    // Stand in for another tool that happens to use the same table: a static
    // route and a rule at a priority next to ours. `ip` is used here because
    // the point is to create state the way *something else* would.
    ip(&[
        "route",
        "add",
        "unreachable",
        "192.0.2.0/24",
        "proto",
        "static",
        "table",
        &table.to_string(),
    ]);
    let foreign_priority = routing::rule_priority(UID) + 1;
    ip(&[
        "rule",
        "add",
        "priority",
        &foreign_priority.to_string(),
        "from",
        "all",
        "lookup",
        "main",
    ]);

    fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");
    fixture
        .apply(Operation::ApplyRouting(routing_request()))
        .expect("apply routing");
    fixture.engine.release(UID).expect("release");

    let netlink = Netlink::open().expect("netlink");
    let survivors = netlink.routes_in_table(table).expect("routes");
    assert!(
        survivors.iter().any(|route| route
            .destination
            .is_some_and(|prefix| prefix.to_string() == "192.0.2.0/24")),
        "a route this project did not create was removed: {survivors:?}"
    );
    assert!(
        netlink
            .rules(AF_INET)
            .expect("rules")
            .iter()
            .any(|rule| rule.priority == foreign_priority),
        "a rule this project did not create was removed"
    );

    ip(&[
        "route",
        "del",
        "unreachable",
        "192.0.2.0/24",
        "table",
        &table.to_string(),
    ]);
    ip(&["rule", "del", "priority", &foreign_priority.to_string()]);
}

#[test]
fn a_process_is_classified_by_its_pidfd() {
    if !enabled() {
        return;
    }
    let Some(root) = std::env::var_os("XRAYTUI_TEST_CGROUP_ROOT") else {
        eprintln!("skipping: no private cgroup v2 hierarchy was provided");
        return;
    };
    let fixture = Fixture::new();
    let tree = xraytui_linux_net::cgroup::CgroupTree::new(PathBuf::from(&root));
    assert!(tree.is_usable(), "{root:?} is not a cgroup v2 hierarchy");

    fixture
        .apply(Operation::CreateCgroup {
            profile: "work".into(),
        })
        .expect("create cgroup");

    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn a process to classify");
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("pid fits"))
        .expect("valid pid");
    let pidfd =
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open");

    fixture
        .engine
        .handle(
            UID,
            &Operation::ClassifyProcess {
                profile: "work".into(),
            },
            Some(pidfd),
        )
        .expect("classify");

    let members = tree.members(UID, "work").expect("members");
    assert!(
        members.contains(&child.id()),
        "the process must be in its profile's cgroup: {members:?}"
    );

    // A cgroup with a live process in it cannot be removed, and saying so is
    // better than pretending it worked.
    assert!(
        fixture
            .apply(Operation::RemoveCgroup {
                profile: "work".into()
            })
            .is_err(),
        "removing a populated cgroup must be refused"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
    // The kernel needs a moment to empty cgroup.procs after the exit.
    for _ in 0..50 {
        if tree.members(UID, "work").expect("members").is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    fixture
        .apply(Operation::RemoveCgroup {
            profile: "work".into(),
        })
        .expect("remove cgroup once empty");
}

#[test]
fn the_firewall_marks_only_the_named_cgroup() {
    if !enabled() {
        return;
    }
    let nft = Nft::new("nft");
    if !nft.available() {
        eprintln!("skipping: nft is not installed");
        return;
    }
    if std::env::var_os("XRAYTUI_TEST_CGROUP_ROOT").is_none() {
        eprintln!("skipping: no private cgroup v2 hierarchy was provided");
        return;
    }
    let fixture = Fixture::new();
    fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");

    fixture
        .apply(Operation::ApplyFirewall(FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "work".into(),
                tproxy_port: Some(19007),
            }],
            kill_switch: true,
            bypass_uid: true,
        }))
        .expect("apply firewall");

    let listed = nft_list();
    assert!(listed.contains("u0-mark"), "{listed}");
    assert!(listed.contains("u0-guard"), "{listed}");
    assert!(listed.contains("u0-redirect"), "{listed}");
    // The kill switch is written against the tunnel's own mark, not a
    // profile's: a redirected profile never leaves by the tunnel at all.
    let tunnel_mark = xraytui_netd_protocol::fwmark_for_uid(UID);
    assert!(
        listed.contains(&format!("meta mark {tunnel_mark:#x}")),
        "the guard rule must match the tunnel mark: {listed}"
    );
    assert!(
        listed.contains("xraytui.slice/u0/work"),
        "the marking rule must name the profile cgroup: {listed}"
    );
    assert!(
        listed.contains("xraytui.slice/u0/core"),
        "the core's own traffic must be exempted: {listed}"
    );

    // Applying the same request again must be a no-op, not a second copy.
    fixture
        .apply(Operation::ApplyFirewall(FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "work".into(),
                tproxy_port: Some(19007),
            }],
            kill_switch: true,
            bypass_uid: true,
        }))
        .expect("apply firewall twice");
    let repeated = nft_list();
    assert_eq!(
        repeated.matches("xraytui.slice/u0/work").count(),
        listed.matches("xraytui.slice/u0/work").count(),
        "re-applying the ruleset duplicated rules"
    );

    fixture.engine.release(UID).expect("release");
    assert!(
        nft.chains().expect("chains").is_empty(),
        "release must remove the chains"
    );
}

/// Acceptance scenario M, proven rather than asserted.
///
/// Two processes running the *same program*, in two different profile cgroups,
/// must reach two different transparent listeners — and each listener must
/// recover the original destination, because that is what Xray's
/// `dokodemo-door` inbound needs in order to know where the traffic was going.
///
/// The listeners here stand in for Xray. What is under test is the kernel-side
/// arrangement: cgroup classification, per-profile marks, the local-delivery
/// table, and the `tproxy` rules.
#[test]
fn two_instances_of_one_program_reach_two_different_listeners() {
    if !enabled() {
        return;
    }
    let nft = Nft::new("nft");
    if !nft.available() {
        eprintln!("skipping: nft is not installed");
        return;
    }
    if std::env::var_os("XRAYTUI_TEST_CGROUP_ROOT").is_none() {
        eprintln!("skipping: no private cgroup v2 hierarchy was provided");
        return;
    }
    let fixture = Fixture::new();

    // The tunnel provides the route that lets the packet be created at all.
    fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");
    fixture
        .apply(Operation::ApplyRouting(RoutingRequest {
            include: Vec::new(),
            exclude: Vec::new(),
            bypass_endpoints: Vec::new(),
            bypass_private: false,
            blackhole_ipv4: false,
            blackhole_ipv6: true,
        }))
        .expect("apply routing");
    given_the_machine_has_a_default_route(&fixture.interface());

    let work_port = 19_001u16;
    let media_port = 19_002u16;
    fixture
        .apply(Operation::ApplyFirewall(FirewallRequest {
            cgroup_marks: vec![
                CgroupMark {
                    profile: "work".into(),
                    tproxy_port: Some(work_port),
                },
                CgroupMark {
                    profile: "media".into(),
                    tproxy_port: Some(media_port),
                },
            ],
            kill_switch: false,
            bypass_uid: true,
        }))
        .expect("apply firewall");

    let work = TransparentListener::start(work_port);
    let media = TransparentListener::start(media_port);

    // Same program, same arguments, different cgroup and different destination.
    connect_from_cgroup("work", "203.0.113.9", 8080);
    connect_from_cgroup("media", "198.51.100.7", 443);

    let work_got = work.wait();
    let media_got = media.wait();

    assert_eq!(
        work_got.as_deref(),
        Some("203.0.113.9:8080"),
        "the work profile's listener must receive the work process's connection, \
         with its original destination intact"
    );
    assert_eq!(
        media_got.as_deref(),
        Some("198.51.100.7:443"),
        "and the media profile's listener the other one"
    );
}

/// A classified application must still be able to talk to its own machine.
///
/// This is not a nicety. Without the loopback exemption a connection to
/// `127.0.0.1:anything` is marked, re-routed and handed to the profile's own
/// transparent listener, which reads its own address as the original destination
/// and dials itself through the proxy — a loop. The test asserts the ordinary
/// thing (localhost still works) in order to prove the dangerous thing cannot
/// happen.
#[test]
fn a_classified_application_still_reaches_its_own_machine() {
    if !enabled() {
        return;
    }
    let nft = Nft::new("nft");
    if !nft.available() || std::env::var_os("XRAYTUI_TEST_CGROUP_ROOT").is_none() {
        eprintln!("skipping: needs nft and a private cgroup v2 hierarchy");
        return;
    }
    let fixture = Fixture::new();
    fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");
    fixture
        .apply(Operation::ApplyFirewall(FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "work".into(),
                tproxy_port: Some(19_020),
            }],
            kill_switch: false,
            bypass_uid: true,
        }))
        .expect("apply firewall");
    given_the_machine_has_a_default_route(&fixture.interface());

    // The profile's transparent listener would say "REDIRECTED"; a perfectly
    // ordinary local service says "LOCAL". The classified process asks the local
    // service, and must hear from the local service.
    let redirected = TransparentListener::with_banner(19_020, "REDIRECTED");
    let local = LocalService::start("LOCAL");
    let answer = connect_from_cgroup_reading("work", "127.0.0.1", local.port());

    assert_eq!(
        answer, "LOCAL",
        "a connection to localhost must reach localhost, not the profile's \
         transparent listener"
    );
    drop(redirected);
}

#[test]
fn the_cgroup_match_really_matches_and_is_not_merely_installed() {
    // An earlier version of this suite asserted that the ruleset *listed* the
    // cgroup paths, which is a much weaker claim than that traffic from those
    // cgroups is marked. This asserts the counter moves.
    if !enabled() {
        return;
    }
    let nft = Nft::new("nft");
    if !nft.available() || std::env::var_os("XRAYTUI_TEST_CGROUP_ROOT").is_none() {
        eprintln!("skipping: needs nft and a private cgroup v2 hierarchy");
        return;
    }
    let fixture = Fixture::new();
    fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");
    fixture
        .apply(Operation::ApplyFirewall(FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "work".into(),
                tproxy_port: Some(19_010),
            }],
            kill_switch: false,
            bypass_uid: true,
        }))
        .expect("apply firewall");
    given_the_machine_has_a_default_route(&fixture.interface());

    let listener = TransparentListener::start(19_010);
    connect_from_cgroup("work", "192.0.2.55", 8443);
    assert_eq!(
        listener.wait().as_deref(),
        Some("192.0.2.55:8443"),
        "traffic from the profile's cgroup must actually be marked and redirected"
    );
}

#[test]
fn dns_is_left_alone_when_the_backend_is_none() {
    if !enabled() {
        return;
    }
    let fixture = Fixture::new();
    fixture
        .apply(Operation::CreateTun(tun_request()))
        .expect("create tun");
    let before = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    fixture
        .apply(Operation::ApplyDns(DnsRequest {
            backend: DnsBackend::None,
            servers: Vec::new(),
            domains: Vec::new(),
        }))
        .expect("apply dns");
    let after = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    assert_eq!(before, after, "the `none` backend must change nothing");
}

// --- helpers ---------------------------------------------------------------

/// A deterministic stand-in for the machine's ordinary physical uplink.
///
/// Both defaults are intentionally usable. A fail-closed test that observes a
/// blackhole therefore proves policy beat an available direct route rather
/// than merely observing that a fresh namespace had no Internet path.
struct DirectEgress {
    interface: String,
}

impl DirectEgress {
    fn start() -> Self {
        let interface = "direct0".to_owned();
        ip(&["link", "add", &interface, "type", "dummy"]);
        ip(&["addr", "add", "192.0.2.1/24", "dev", &interface]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            &interface,
            "nodad",
        ]);
        ip(&["link", "set", &interface, "up"]);
        ip(&["route", "add", "default", "dev", &interface]);
        ip(&["-6", "route", "add", "default", "dev", &interface]);
        Self { interface }
    }
}

impl Drop for DirectEgress {
    fn drop(&mut self) {
        let _ = ip_allow_failure(&["link", "delete", &self.interface]);
    }
}

fn marked_route(destination: &str) -> String {
    let mark = format!("{:#x}", xraytui_netd_protocol::fwmark_for_uid(UID));
    if destination.contains(':') {
        ip_allow_failure(&["-6", "route", "get", destination, "mark", &mark])
    } else {
        ip_allow_failure(&["route", "get", destination, "mark", &mark])
    }
}

fn assert_marked_route(destination: &str, expected: &str, forbidden: &str) {
    let route = marked_route(destination);
    assert!(
        route.contains(&format!("dev {expected}")),
        "marked route to {destination} must use {expected}: {route}"
    );
    assert!(
        !route.contains(&format!("dev {forbidden}")),
        "marked route to {destination} must not use {forbidden}: {route}"
    );
}

fn assert_marked_blackhole(destination: &str, direct: &str) {
    let route = marked_route(destination);
    assert!(
        route.contains("blackhole")
            || route.contains("unreachable")
            || route.contains("Invalid argument"),
        "marked route to {destination} must be rejected: {route}"
    );
    assert!(
        !route.contains(&format!("dev {direct}")),
        "marked route to {destination} leaked to {direct}: {route}"
    );
}

/// Ask the kernel to select a source address for a UDP socket.
///
/// `mark` is set before `connect`, so the same policy rule used by actual
/// traffic participates. A blackhole returns `None`; a usable TUN or direct
/// route returns its selected source address.
fn udp_source_with_mark(destination: &str, mark: u32) -> Option<String> {
    let program = concat!(
        "import socket,sys\n",
        "host=sys.argv[1]\n",
        "mark=int(sys.argv[2])\n",
        "family=socket.AF_INET6 if ':' in host else socket.AF_INET\n",
        "target=(host,9,0,0) if family==socket.AF_INET6 else (host,9)\n",
        "s=socket.socket(family,socket.SOCK_DGRAM)\n",
        "s.setsockopt(socket.SOL_SOCKET,36,mark)\n",
        "try:\n",
        "    s.connect(target)\n",
        "    print(s.getsockname()[0])\n",
        "except OSError:\n",
        "    print('')\n",
    );
    let output = Command::new("python3")
        .arg("-c")
        .arg(program)
        .arg(destination)
        .arg(mark.to_string())
        .output()
        .expect("select a UDP route");
    assert!(
        output.status.success(),
        "UDP route probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let source = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!source.is_empty()).then_some(source)
}

fn marked_udp_source(destination: &str) -> Option<String> {
    udp_source_with_mark(destination, xraytui_netd_protocol::fwmark_for_uid(UID))
}

fn udp_source(destination: &str) -> Option<String> {
    udp_source_with_mark(destination, 0)
}

fn assert_marked_udp_blocked(destination: &str) {
    let program = concat!(
        "import socket,sys\n",
        "host=sys.argv[1]\n",
        "mark=int(sys.argv[2])\n",
        "family=socket.AF_INET6 if ':' in host else socket.AF_INET\n",
        "target=(host,9,0,0) if family==socket.AF_INET6 else (host,9)\n",
        "s=socket.socket(family,socket.SOCK_DGRAM)\n",
        "s.setsockopt(socket.SOL_SOCKET,36,mark)\n",
        "try:\n",
        "    s.sendto(b'xraytui-kill-switch-probe',target)\n",
        "    print('sent')\n",
        "except OSError as error:\n",
        "    print('blocked:%d'%error.errno)\n",
    );
    let output = Command::new("python3")
        .arg("-c")
        .arg(program)
        .arg(destination)
        .arg(xraytui_netd_protocol::fwmark_for_uid(UID).to_string())
        .output()
        .expect("send marked UDP probe");
    assert!(
        output.status.success(),
        "marked UDP probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let answer = String::from_utf8_lossy(&output.stdout);
    assert!(
        answer.trim().starts_with("blocked:"),
        "kill switch allowed marked UDP to {destination}: {answer}"
    );
}

fn guard_packets() -> u64 {
    let chain = format!("u{UID}-guard");
    let output = Command::new("nft")
        .args(["list", "chain", "inet", "xraytui", &chain])
        .output()
        .expect("list kill-switch chain");
    assert!(
        output.status.success(),
        "cannot inspect kill-switch counter: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let words: Vec<&str> = text.split_whitespace().collect();
    words
        .windows(2)
        .find_map(|pair| {
            (pair[0] == "packets")
                .then(|| pair[1].parse::<u64>().ok())
                .flatten()
        })
        .expect("a packets counter in the guard chain")
}

/// A stand-in for Xray's transparent inbound.
///
/// It binds `127.0.0.1` with `IP_TRANSPARENT` — exactly what Xray's
/// `dokodemo-door` does when `sockopt.tproxy` is set — and reports the original
/// destination of the first connection, which is the whole point of `tproxy`.
///
/// Both halves of that were established by experiment, not assumed:
///
/// * without `IP_TRANSPARENT` the handshake never completes, because the
///   accepted socket's local address is the *original destination* and the
///   kernel will not send from an address this machine does not own unless the
///   listener is transparent;
/// * binding loopback rather than every address works only because the redirect
///   rule names `127.0.0.1` explicitly, and it is what keeps a transparent
///   listener unreachable from the network.
///
/// It is a child `python3` process rather than a thread because `IP_TRANSPARENT`
/// has no safe binding among this project's dependencies, and reaching for
/// `unsafe` in a test to save a subprocess would be a poor trade.
struct TransparentListener {
    child: std::process::Child,
    /// Held across calls: a buffered reader rebuilt per read could swallow the
    /// next line, and a flaky test is worse than none.
    output: std::io::BufReader<std::process::ChildStdout>,
    port: u16,
}

impl TransparentListener {
    fn start(port: u16) -> Self {
        Self::with_banner(port, "")
    }

    /// Start a listener that also writes `banner` back to whoever connects.
    fn with_banner(port: u16, banner: &str) -> Self {
        let program = format!(
            "import socket\n\
             s=socket.socket()\n\
             s.setsockopt(socket.SOL_IP,19,1)  # IP_TRANSPARENT\n\
             s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
             s.bind(('127.0.0.1',{port}))\n\
             s.listen(4)\n\
             print('ready',flush=True)\n\
             s.settimeout(15)\n\
             try:\n\
             \x20   c,_=s.accept()\n\
             \x20   print('%s:%d'%c.getsockname(),flush=True)\n\
             \x20   banner={banner:?}\n\
             \x20   if banner: c.sendall(banner.encode())\n\
             except Exception as e:\n\
             \x20   print('failed: %r'%(e,),flush=True)\n"
        );
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(&program)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start the transparent listener");
        let mut output = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        // Block until it says it is listening, so no test races the bind.
        let ready = read_line(&mut output);
        assert_eq!(
            ready.as_deref(),
            Some("ready"),
            "the listener on 127.0.0.1:{port} did not start"
        );
        Self {
            child,
            output,
            port,
        }
    }

    /// The original destination of the first connection, as `address:port`.
    fn wait(mut self) -> Option<String> {
        match read_line(&mut self.output) {
            Some(text) if text.contains(':') && !text.starts_with("failed") => Some(text),
            other => {
                eprintln!("listener on {} reported {other:?}", self.port);
                None
            }
        }
    }
}

impl Drop for TransparentListener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An ordinary local service: no transparent socket, no ceremony.
struct LocalService {
    listener: std::net::TcpListener,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl LocalService {
    fn start(banner: &'static str) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind a local service");
        let accepting = listener.try_clone().expect("clone the listener");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = accepting.accept() {
                use std::io::Write as _;
                let _ = stream.write_all(banner.as_bytes());
            }
        });
        Self {
            listener,
            handle: Some(handle),
        }
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().expect("local address").port()
    }
}

impl Drop for LocalService {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one line from a child's stdout, without waiting for it to exit.
fn read_line(output: &mut std::io::BufReader<std::process::ChildStdout>) -> Option<String> {
    use std::io::BufRead as _;
    let mut line = String::new();
    match output.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end().to_owned()),
    }
}

/// Connect from a process placed in a profile's cgroup.
///
/// A child process is used so the cgroup move affects the socket: the
/// association is recorded when the socket is created, so the *creating* task
/// has to be in the cgroup already.
fn connect_from_cgroup(profile: &str, host: &str, port: u16) {
    let _ = connect_from_cgroup_reading(profile, host, port);
}

/// The same, reporting whatever the far end sent back.
///
/// That reply is how a test tells *which* egress served the connection, which is
/// the claim scenario M actually makes.
fn connect_from_cgroup_reading(profile: &str, host: &str, port: u16) -> String {
    let path = format!(
        "{}/cgroup.procs",
        xraytui_linux_net::cgroup::CgroupTree::new(
            std::env::var("XRAYTUI_TEST_CGROUP_ROOT").expect("cgroup root")
        )
        .path_for(UID, profile)
        .display()
    );
    // The process writes its *own* pid into the cgroup before it creates the
    // socket. That order is the whole trick: the kernel records the cgroup at
    // socket-creation time, so moving a parent — or writing `$$` from a shell
    // subshell — classifies the wrong task and matches nothing.
    let program = format!(
        "import os,socket,sys\n\
         open({path:?},'w').write(str(os.getpid()))\n\
         s=socket.socket(); s.settimeout(8)\n\
         try:\n\
         \x20   s.connect(({host:?},{port}))\n\
         \x20   s.sendall(b'hello\\n')\n\
         \x20   sys.stdout.write(s.recv(64).decode('utf-8','replace'))\n\
         except Exception as e:\n\
         \x20   sys.stdout.write('failed: %r'%(e,))\n"
    );
    let output = Command::new("python3")
        .arg("-c")
        .arg(&program)
        .output()
        .expect("run the connecting process");
    assert!(
        output.status.success(),
        "the connecting process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Give the namespace the default route a real machine already has.
///
/// This is the *environment*, not the product. An application's `connect()`
/// picks a route before any packet exists, using the socket's mark — which is
/// zero, because the mark is set later, at `output`. So without a default route
/// in the main table `connect()` fails with `ENETUNREACH` and nothing this
/// project installed is ever consulted. A machine in transparent mode has one
/// via its physical interface; a fresh namespace does not, so the test supplies
/// it.
fn given_the_machine_has_a_default_route(interface: &str) {
    ip(&["route", "add", "default", "dev", interface]);
}

/// Run `ip(8)` and return its output.
///
/// Test-only. The implementation under test never shells out for networking —
/// that is the point of `crates/linux-net/src/netlink`. Here it is a deliberate
/// *independent* oracle: if the netlink code and iproute2 disagree, the test
/// should fail.
fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("run ip");
    assert!(
        output.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn ip_allow_failure(args: &[&str]) -> String {
    Command::new("ip")
        .args(args)
        .output()
        .map(|output| {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text
        })
        .unwrap_or_default()
}

fn nft_list() -> String {
    Command::new("nft")
        .args(["list", "table", "inet", "xraytui"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}
