//! End-to-end acceptance tests against a real Xray-core process.
//!
//! These are the tests that decide whether the central claim of the project is
//! true: that several egress profiles run concurrently through one supervised
//! core, and that one profile's target can be repointed without disturbing the
//! others and without a restart.
//!
//! Nothing here reaches the internet. Every "remote proxy server" is a
//! [`MockEgress`] on loopback, which is a SOCKS5 front end that splices to its
//! own identity service, so a test can read back *which* egress a connection
//! actually traversed.
//!
//! Scenario identifiers match `<mandatory_acceptance_scenarios>` in the project
//! specification and the table in `PLAN.md`.
//!
//! Skipped, loudly, when no Xray binary is present.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use xraytui_controller::{
    ApplyOutcome, ChangePlan, Engine, EngineConfig, discover_binary, probe_binary, validate_config,
};
use xraytui_domain::{
    Chain, ChainId, CoreStatus, DesiredState, EgressProfile, Endpoint, ListenerSpec, MkcpTransport,
    Node, NodeId, NodeSource, ProfileId, ProtocolSettings, Target, Transport, VlessSettings,
};
use xraytui_secrets::Secret;
use xraytui_test_support::{
    DnsRecordType, MockEgress, TcpDnsFixture, fixtures, free_port, probe_through_socks5, query_dns,
};
use xraytui_xray_api::ApiEndpoint;
use xraytui_xray_compiler::{CompileOptions, DnsOptions};

/// Locate an Xray binary, or `None` to skip.
fn xray_path() -> Option<std::path::PathBuf> {
    if let Ok(configured) = std::env::var("XRAYTUI_TEST_XRAY") {
        return discover_binary(&configured).ok();
    }
    discover_binary("").ok()
}

macro_rules! require_xray {
    ($name:literal) => {
        match xray_path() {
            Some(path) => path,
            None => {
                eprintln!(
                    "SKIPPED {}: no Xray-core binary on PATH (set XRAYTUI_TEST_XRAY)",
                    $name
                );
                return;
            }
        }
    };
}

/// An engine wired to a temporary directory and a free loopback API port.
async fn engine_for(state: DesiredState, dir: &std::path::Path) -> Engine {
    engine_for_with_compile(state, dir, CompileOptions::default()).await
}

async fn engine_for_with_compile(
    state: DesiredState,
    dir: &std::path::Path,
    compile: CompileOptions,
) -> Engine {
    let binary = xray_path().expect("checked by require_xray!");
    let info = probe_binary(&binary, None).await.expect("probe the binary");

    let api_port = free_port().expect("free port");
    let config = EngineConfig {
        compile,
        api_endpoint: ApiEndpoint::loopback(api_port),
        generated_config: dir.join("generated-xray.json"),
        last_good_config: dir.join("last-good-xray.json"),
        core_log: Some(dir.join("xray.log")),
        api_deadline: Duration::from_secs(20),
        ..Default::default()
    };

    let mut engine = Engine::new(config, info).expect("supported core");
    // Seed rather than apply: `apply` would start a generation here, and a
    // failure would silently roll the desired state back to empty, making the
    // test's own `rebuild_and_start` succeed while serving nothing.
    engine.seed(state).expect("no core is running yet");
    engine
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("free UDP port")
        .port()
}

async fn dns_answer(server: SocketAddr, name: &str, record_type: DnsRecordType) -> IpAddr {
    let mut last_error = None;
    for _ in 0..20 {
        match tokio::time::timeout(
            Duration::from_millis(500),
            query_dns(server, name, record_type),
        )
        .await
        {
            Ok(Ok(answer)) => return answer,
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some("query timed out".to_owned()),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "DNS query for {name} through {server} did not succeed: {}",
        last_error.unwrap_or_else(|| "no attempt".to_owned())
    );
}

/// Read the egress banner through a profile's SOCKS listener.
async fn egress_reached(port: u16) -> String {
    let address = format!("127.0.0.1:{port}")
        .parse()
        .expect("loopback address");
    probe_through_socks5(address, "probe.invalid", 80)
        .await
        .unwrap_or_else(|error| panic!("probe through 127.0.0.1:{port} failed: {error}"))
}

async fn ipv6_egress(name: &'static str, forwarding: bool) -> Option<MockEgress> {
    let result = if forwarding {
        MockEgress::start_forwarding_on(name, IpAddr::V6(Ipv6Addr::LOCALHOST)).await
    } else {
        MockEgress::start_on(name, IpAddr::V6(Ipv6Addr::LOCALHOST)).await
    };
    match result {
        Ok(egress) => Some(egress),
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {
            eprintln!(
                "SKIPPED IPv6 acceptance: ::1 is unavailable in this network namespace: {error}"
            );
            None
        }
        Err(error) => panic!("start IPv6 egress: {error}"),
    }
}

/// A second real Xray process used as a deterministic loopback protocol peer.
struct FixtureCore {
    child: Child,
    log: PathBuf,
}

impl FixtureCore {
    fn start(binary: &Path, config: &Path, log: PathBuf) -> Self {
        let stdout = std::fs::File::create(&log).expect("create fixture Xray log");
        let stderr = stdout.try_clone().expect("clone fixture Xray log");
        let child = Command::new(binary)
            .args(["run", "-config"])
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("start fixture Xray");
        Self { child, log }
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_else(|error| format!("<log error: {error}>"))
    }
}

impl Drop for FixtureCore {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_for_fixture_listener(core: &mut FixtureCore, address: SocketAddr) {
    for _ in 0..100 {
        if let Some(status) = core.child.try_wait().expect("inspect fixture Xray") {
            panic!(
                "fixture Xray exited with {status} before listening on {address}:\n{}",
                core.log_text()
            );
        }
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "fixture Xray never listened on {address}:\n{}",
        core.log_text()
    );
}

fn write_fixture_json(path: &Path, value: &serde_json::Value) {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize fixture Xray config"),
    )
    .expect("write fixture Xray config");
}

#[tokio::test]
async fn probed_mkcp_dialect_is_accepted_by_the_selected_core() {
    let binary = require_xray!("mKCP final-mask capability probe");
    let info = probe_binary(&binary, None).await.expect("probe Xray");
    let mut node = Node::new(
        NodeId::new("mkcp-probe").expect("valid"),
        "mKCP probe",
        NodeSource::Manual,
        Endpoint::new("127.0.0.1", 9),
        ProtocolSettings::Vless(VlessSettings {
            id: Secret::new("11111111-2222-3333-4444-555555555555"),
            flow: String::new(),
            encryption: "none".into(),
            level: None,
        }),
    );
    node.transport = Transport::Mkcp(MkcpTransport {
        header_type: Some("dtls".into()),
        seed: Some(Secret::new("synthetic-seed")),
        mtu: None,
        tti: None,
    });
    let outbound = xraytui_xray_compiler::outbound::build_with_dialect(
        &node,
        "node/mkcp-probe/out",
        None,
        info.mkcp_finalmask_dialect,
    )
    .expect("compile probe node");
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "log": { "loglevel": "none" },
        "outbounds": [outbound],
    }))
    .expect("JSON");
    let directory = tempfile::tempdir().expect("tempdir");
    validate_config(&info, &json, &directory.path().join("config.json"))
        .await
        .expect("the probed dialect must validate");
}

// ---------------------------------------------------------------- Scenario A

#[tokio::test(flavor = "multi_thread")]
async fn scenario_a_two_profiles_reach_their_own_egress_concurrently() {
    let _binary = require_xray!("scenario A");
    let dir = tempfile::tempdir().expect("tempdir");

    let egress_web = MockEgress::start("web").await.expect("start egress");
    let egress_dev = MockEgress::start("dev").await.expect("start egress");

    let web_port = free_port().expect("port");
    let dev_port = free_port().expect("port");

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("egress-web", "Web egress", egress_web.socks_addr()),
    );
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("egress-dev", "Dev egress", egress_dev.socks_addr()),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "web",
            Target::Node {
                id: NodeId::new("egress-web").expect("valid"),
            },
            web_port,
        ),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "development",
            Target::Node {
                id: NodeId::new("egress-dev").expect("valid"),
            },
            dev_port,
        ),
    );

    let mut engine = engine_for(state, dir.path()).await;
    let generation = engine.rebuild_and_start().await.expect("core must start");
    assert!(matches!(engine.runtime().core, CoreStatus::Running { .. }));

    // Simultaneous, not sequential: the point is that both paths are live at once.
    let (web_answer, dev_answer) = tokio::join!(egress_reached(web_port), egress_reached(dev_port));

    assert!(
        web_answer.contains("EGRESS web"),
        "web profile reached: {web_answer:?}"
    );
    assert!(
        dev_answer.contains("EGRESS dev"),
        "development profile reached: {dev_answer:?}"
    );
    assert_eq!(egress_web.connection_count(), 1);
    assert_eq!(egress_dev.connection_count(), 1);
    assert_eq!(engine.runtime().generation, generation);

    engine.stop_core().await;
}

// ---------------------------------------------------------------- Scenario B

#[tokio::test(flavor = "multi_thread")]
async fn scenario_b_switching_one_profile_leaves_the_other_alone_and_does_not_restart() {
    let _binary = require_xray!("scenario B");
    let dir = tempfile::tempdir().expect("tempdir");

    let egress_web = MockEgress::start("web").await.expect("start egress");
    let egress_dev = MockEgress::start("dev").await.expect("start egress");
    let egress_new = MockEgress::start("new").await.expect("start egress");

    let web_port = free_port().expect("port");
    let dev_port = free_port().expect("port");

    let mut state = DesiredState::default();
    for (id, egress) in [
        ("egress-web", &egress_web),
        ("egress-dev", &egress_dev),
        ("egress-new", &egress_new),
    ] {
        fixtures::add_node(
            &mut state,
            fixtures::socks_node(id, id, egress.socks_addr()),
        );
    }
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "web",
            Target::Node {
                id: NodeId::new("egress-web").expect("valid"),
            },
            web_port,
        ),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "development",
            Target::Node {
                id: NodeId::new("egress-dev").expect("valid"),
            },
            dev_port,
        ),
    );

    let mut engine = engine_for(state, dir.path()).await;
    engine.rebuild_and_start().await.expect("core must start");

    let pid_before = match engine.runtime().core {
        CoreStatus::Running { pid, .. } => pid,
        ref other => panic!("core is not running: {other:?}"),
    };
    let generation_before = engine.runtime().generation;

    assert!(egress_reached(dev_port).await.contains("EGRESS dev"));
    assert!(egress_reached(web_port).await.contains("EGRESS web"));

    // The planner must classify this as an API operation before we run it.
    let mut next = engine.desired().clone();
    if let Some(profile) = next
        .profiles
        .get_mut(&ProfileId::new("development").expect("valid"))
    {
        profile.target = Target::Node {
            id: NodeId::new("egress-new").expect("valid"),
        };
    }
    assert!(
        matches!(engine.plan(&next), ChangePlan::Selectors(_)),
        "a target change must not require a restart: {:?}",
        engine.plan(&next)
    );

    let outcome = engine
        .set_profile_target(
            &ProfileId::new("development").expect("valid"),
            Target::Node {
                id: NodeId::new("egress-new").expect("valid"),
            },
        )
        .await
        .expect("switch must succeed");
    match &outcome {
        ApplyOutcome::SwitchedSelectors { balancers } => {
            assert_eq!(balancers, &vec!["profile/development/selector".to_owned()]);
        }
        other => panic!("expected an API switch, got {other:?}"),
    }

    // New connections follow the new target...
    let dev_answer = egress_reached(dev_port).await;
    assert!(
        dev_answer.contains("EGRESS new"),
        "development after switch: {dev_answer:?}"
    );
    // ...the untouched profile is unchanged...
    let web_answer = egress_reached(web_port).await;
    assert!(
        web_answer.contains("EGRESS web"),
        "web after switch: {web_answer:?}"
    );
    // ...and the core was never restarted.
    match engine.runtime().core {
        CoreStatus::Running { pid, .. } => assert_eq!(pid, pid_before, "core was restarted"),
        ref other => panic!("core is not running: {other:?}"),
    }
    assert_eq!(
        engine.runtime().generation,
        generation_before,
        "generation changed"
    );
    assert_eq!(
        egress_dev.connection_count(),
        1,
        "old egress took no new connection"
    );

    engine.stop_core().await;
}

// ---------------------------------------------------------------- Scenario E

#[tokio::test(flavor = "multi_thread")]
async fn scenario_e_a_two_hop_chain_reaches_the_exit_through_the_first_hop() {
    let _binary = require_xray!("scenario E");
    let dir = tempfile::tempdir().expect("tempdir");

    // The transit hop must forward faithfully; an identifying egress would
    // swallow the connection and the test would prove nothing.
    let transit = MockEgress::start_forwarding("transit")
        .await
        .expect("start transit");
    let exit = MockEgress::start("exit").await.expect("start exit");
    let direct = MockEgress::start("direct-exit")
        .await
        .expect("start direct");

    let chain_port = free_port().expect("port");
    let direct_port = free_port().expect("port");

    let mut state = DesiredState::default();
    // A transit hop must advertise UDP, otherwise chain validation refuses it
    // for breaking UDP on every later hop. The refusal is the correct default;
    // a real transit proxy offers UDP ASSOCIATE, so the fixture says so too.
    let mut transit_node = fixtures::socks_node("hop-transit", "Transit", transit.socks_addr());
    transit_node.protocol =
        xraytui_domain::ProtocolSettings::Socks(xraytui_domain::SocksSettings {
            username: None,
            password: None,
            udp: true,
        });
    fixtures::add_node(&mut state, transit_node);
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("hop-exit", "Exit", exit.socks_addr()),
    );
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("solo", "Solo", direct.socks_addr()),
    );

    let chain_id = ChainId::new("transit-exit").expect("valid");
    state.chains.insert(
        chain_id.clone(),
        Chain {
            id: chain_id.clone(),
            name: "Transit to exit".into(),
            hops: vec![
                NodeId::new("hop-transit").expect("valid"),
                NodeId::new("hop-exit").expect("valid"),
            ],
            enabled: true,
        },
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks("chat", Target::Chain { id: chain_id }, chain_port),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "solo",
            Target::Node {
                id: NodeId::new("solo").expect("valid"),
            },
            direct_port,
        ),
    );

    let mut engine = engine_for(state, dir.path()).await;
    engine.rebuild_and_start().await.expect("core must start");

    let answer = egress_reached(chain_port).await;
    assert!(
        answer.contains("EGRESS exit"),
        "chain must terminate at the exit: {answer:?}"
    );
    assert_eq!(
        transit.connection_count(),
        1,
        "the exit must have been dialled through the transit hop, not directly"
    );

    // A profile that does not use the chain must not touch the transit hop.
    let solo_answer = egress_reached(direct_port).await;
    assert!(
        solo_answer.contains("EGRESS direct-exit"),
        "{solo_answer:?}"
    );
    assert_eq!(
        transit.connection_count(),
        1,
        "the non-chain profile used the transit hop"
    );

    engine.stop_core().await;
}

// ------------------------------------------------------------ IPv6 data path

#[tokio::test(flavor = "multi_thread")]
async fn an_ipv6_proxy_endpoint_reaches_an_ipv6_exit_through_real_xray() {
    let _binary = require_xray!("IPv6 proxy endpoint");
    let Some(egress) = ipv6_egress("ipv6-exit", false).await else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port().expect("port");

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("ipv6-exit", "IPv6 exit", egress.socks_addr()),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "ipv6",
            Target::Node {
                id: NodeId::new("ipv6-exit").expect("valid"),
            },
            port,
        ),
    );

    let mut engine = engine_for(state, dir.path()).await;
    engine.rebuild_and_start().await.expect("start real Xray");
    let answer = egress_reached(port).await;
    assert!(answer.contains("EGRESS ipv6-exit"), "{answer:?}");
    assert_eq!(egress.connection_count(), 1);
    assert!(egress.socks_addr().is_ipv6());
    engine.stop_core().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dual_stack_profiles_reach_distinct_ipv4_and_ipv6_exits_concurrently() {
    let _binary = require_xray!("dual-stack proxy endpoints");
    let ipv4 = MockEgress::start("dual-v4")
        .await
        .expect("start IPv4 egress");
    let Some(ipv6) = ipv6_egress("dual-v6", false).await else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let ipv4_port = free_port().expect("port");
    let ipv6_port = free_port().expect("port");

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("dual-v4", "Dual IPv4", ipv4.socks_addr()),
    );
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("dual-v6", "Dual IPv6", ipv6.socks_addr()),
    );
    for (profile, node, port) in [
        ("dual-v4", "dual-v4", ipv4_port),
        ("dual-v6", "dual-v6", ipv6_port),
    ] {
        fixtures::add_profile(
            &mut state,
            fixtures::profile_with_socks(
                profile,
                Target::Node {
                    id: NodeId::new(node).expect("valid"),
                },
                port,
            ),
        );
    }

    let mut engine = engine_for(state, dir.path()).await;
    engine.rebuild_and_start().await.expect("start real Xray");
    let (answer4, answer6) = tokio::join!(egress_reached(ipv4_port), egress_reached(ipv6_port));
    assert!(answer4.contains("EGRESS dual-v4"), "{answer4:?}");
    assert!(answer6.contains("EGRESS dual-v6"), "{answer6:?}");
    assert_eq!(ipv4.connection_count(), 1);
    assert_eq!(ipv6.connection_count(), 1);
    engine.stop_core().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_two_hop_ipv6_chain_reaches_its_exit_through_the_ipv6_transit() {
    let _binary = require_xray!("IPv6 chain");
    let Some(transit) = ipv6_egress("ipv6-transit", true).await else {
        return;
    };
    let Some(exit) = ipv6_egress("ipv6-chain-exit", false).await else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port().expect("port");

    let mut transit_node =
        fixtures::socks_node("ipv6-transit", "IPv6 transit", transit.socks_addr());
    transit_node.protocol =
        xraytui_domain::ProtocolSettings::Socks(xraytui_domain::SocksSettings {
            username: None,
            password: None,
            udp: true,
        });
    let mut state = DesiredState::default();
    fixtures::add_node(&mut state, transit_node);
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("ipv6-chain-exit", "IPv6 chain exit", exit.socks_addr()),
    );
    let chain_id = ChainId::new("ipv6-chain").expect("valid");
    state.chains.insert(
        chain_id.clone(),
        Chain {
            id: chain_id.clone(),
            name: "IPv6 transit to IPv6 exit".into(),
            hops: vec![
                NodeId::new("ipv6-transit").expect("valid"),
                NodeId::new("ipv6-chain-exit").expect("valid"),
            ],
            enabled: true,
        },
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks("ipv6-chain", Target::Chain { id: chain_id }, port),
    );

    let mut engine = engine_for(state, dir.path()).await;
    engine.rebuild_and_start().await.expect("start real Xray");
    let answer = egress_reached(port).await;
    assert!(answer.contains("EGRESS ipv6-chain-exit"), "{answer:?}");
    assert_eq!(transit.connection_count(), 1);
    assert_eq!(exit.connection_count(), 1);
    engine.stop_core().await;
}

// ---------------------------------------------------------- DNS route proof

#[tokio::test(flavor = "multi_thread")]
async fn split_dns_uses_direct_and_proxied_ipv6_chain_paths_without_crossing_them() {
    let _binary = require_xray!("split DNS through an IPv6 chain");
    let Some(first_hop) = ipv6_egress("dns-chain-first", true).await else {
        return;
    };
    let Some(second_hop) = ipv6_egress("dns-chain-second", true).await else {
        return;
    };
    let proxied_answer: IpAddr = "2001:db8::53".parse().expect("proxied answer");
    let direct_answer: IpAddr = "2001:db8::54".parse().expect("direct answer");
    let proxied_dns = TcpDnsFixture::start_on(IpAddr::V6(Ipv6Addr::LOCALHOST), proxied_answer)
        .await
        .expect("proxied IPv6 DNS fixture");
    let direct_dns =
        TcpDnsFixture::start_on("127.0.0.1".parse().expect("IPv4 loopback"), direct_answer)
            .await
            .expect("direct DNS fixture");
    let dir = tempfile::tempdir().expect("tempdir");
    let profile_port = free_port().expect("profile port");
    let dns_listen = SocketAddr::from(([127, 0, 0, 1], free_udp_port()));

    let mut first_node =
        fixtures::socks_node("dns-first", "DNS chain first", first_hop.socks_addr());
    first_node.protocol = xraytui_domain::ProtocolSettings::Socks(xraytui_domain::SocksSettings {
        username: None,
        password: None,
        udp: true,
    });
    let mut state = DesiredState::default();
    fixtures::add_node(&mut state, first_node);
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("dns-second", "DNS chain second", second_hop.socks_addr()),
    );
    let chain_id = ChainId::new("dns-ipv6-chain").expect("chain id");
    state.chains.insert(
        chain_id.clone(),
        Chain {
            id: chain_id.clone(),
            name: "DNS IPv6 chain".into(),
            hops: vec![
                NodeId::new("dns-first").expect("node id"),
                NodeId::new("dns-second").expect("node id"),
            ],
            enabled: true,
        },
    );
    let profile_id = ProfileId::new("dns-proxy").expect("profile id");
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks("dns-proxy", Target::Chain { id: chain_id }, profile_port),
    );
    state.default_profile = Some(profile_id);

    let options = CompileOptions {
        dns: DnsOptions {
            enabled: true,
            direct_servers: vec![format!("tcp://{}", direct_dns.address())],
            proxy_servers: vec![format!("tcp://{}", proxied_dns.address())],
            direct_domains: vec!["full:direct.test".into()],
            query_strategy: "UseIPv6".into(),
            listen: Some(dns_listen),
            allow_direct_fallback: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut engine = engine_for_with_compile(state, dir.path(), options).await;
    engine.rebuild_and_start().await.expect("start real Xray");

    assert_eq!(
        dns_answer(dns_listen, "proxy.test", DnsRecordType::Aaaa).await,
        proxied_answer
    );
    assert!(proxied_dns.query_count() >= 1);
    assert_eq!(direct_dns.query_count(), 0);
    assert!(first_hop.connection_count() >= 1);
    assert!(second_hop.connection_count() >= 1);
    let first_after_proxy = first_hop.connection_count();
    let second_after_proxy = second_hop.connection_count();

    assert_eq!(
        dns_answer(dns_listen, "direct.test", DnsRecordType::Aaaa).await,
        direct_answer
    );
    assert!(direct_dns.query_count() >= 1);
    assert_eq!(
        first_hop.connection_count(),
        first_after_proxy,
        "direct-domain DNS escaped through the proxy chain"
    );
    assert_eq!(
        second_hop.connection_count(),
        second_after_proxy,
        "direct-domain DNS escaped through the proxy chain"
    );
    engine.stop_core().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hostname_first_hop_bootstraps_directly_then_carries_dns_through_the_proxy() {
    let _binary = require_xray!("hostname bootstrap for proxied DNS");
    let proxy = MockEgress::start_forwarding("dns-bootstrap-proxy")
        .await
        .expect("forwarding proxy");
    let bootstrap_dns = TcpDnsFixture::start_on(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    )
    .await
    .expect("bootstrap DNS fixture");
    let proxied_answer: IpAddr = "192.0.2.53".parse().expect("proxied answer");
    let proxied_dns =
        TcpDnsFixture::start_on(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), proxied_answer)
            .await
            .expect("proxied DNS fixture");
    let dir = tempfile::tempdir().expect("tempdir");
    let profile_port = free_port().expect("profile port");
    let dns_listen = SocketAddr::from(([127, 0, 0, 1], free_udp_port()));

    let mut proxy_node = fixtures::socks_node(
        "dns-bootstrap-proxy",
        "DNS hostname bootstrap proxy",
        proxy.socks_addr(),
    );
    // Xray preserves endpoint spelling and its `full:` DNS matcher is
    // case-sensitive, so this mixed-case name guards exact-rule fidelity.
    proxy_node.endpoint.address = "Bootstrap-Proxy.TEST".into();
    let mut state = DesiredState::default();
    fixtures::add_node(&mut state, proxy_node);
    let profile_id = ProfileId::new("dns-bootstrap").expect("profile id");
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "dns-bootstrap",
            Target::Node {
                id: NodeId::new("dns-bootstrap-proxy").expect("node id"),
            },
            profile_port,
        ),
    );
    state.default_profile = Some(profile_id);

    let options = CompileOptions {
        dns: DnsOptions {
            enabled: true,
            direct_servers: Vec::new(),
            proxy_servers: vec![format!("tcp://{}", proxied_dns.address())],
            bootstrap_servers: vec![format!("tcp://{}", bootstrap_dns.address())],
            direct_domains: Vec::new(),
            query_strategy: "UseIPv4".into(),
            listen: Some(dns_listen),
            allow_direct_fallback: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut engine = engine_for_with_compile(state, dir.path(), options).await;
    engine.rebuild_and_start().await.expect("start real Xray");

    assert_eq!(
        dns_answer(dns_listen, "through-proxy.test", DnsRecordType::A).await,
        proxied_answer
    );
    assert!(
        bootstrap_dns.query_count() >= 1,
        "the first-hop hostname was not resolved by the bootstrap resolver"
    );
    assert!(
        proxied_dns.query_count() >= 1,
        "the user DNS query did not reach the proxied resolver"
    );
    assert!(
        proxy.connection_count() >= 1,
        "the proxied resolver was not reached through the selected profile"
    );
    engine.stop_core().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_hostname_bootstrap_never_uses_an_overlapping_direct_resolver() {
    let _binary = require_xray!("fail-closed hostname bootstrap for proxied DNS");
    let proxy = MockEgress::start_forwarding("dns-bootstrap-must-not-connect")
        .await
        .expect("forwarding proxy");
    let direct_dns = TcpDnsFixture::start_on(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    )
    .await
    .expect("ordinary direct DNS fixture");
    let proxied_dns = TcpDnsFixture::start_on(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "192.0.2.54".parse().expect("proxied answer"),
    )
    .await
    .expect("proxied DNS fixture");
    let bootstrap_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve unavailable bootstrap address");
    let unavailable_bootstrap = bootstrap_listener.local_addr().expect("bootstrap address");
    drop(bootstrap_listener);

    let dir = tempfile::tempdir().expect("tempdir");
    let profile_port = free_port().expect("profile port");
    let dns_listen = SocketAddr::from(([127, 0, 0, 1], free_udp_port()));
    let mut proxy_node = fixtures::socks_node(
        "dns-bootstrap-failure",
        "DNS bootstrap failure proxy",
        proxy.socks_addr(),
    );
    proxy_node.endpoint.address = "bootstrap-failure.test".into();
    let mut state = DesiredState::default();
    fixtures::add_node(&mut state, proxy_node);
    let profile_id = ProfileId::new("dns-bootstrap-failure").expect("profile id");
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "dns-bootstrap-failure",
            Target::Node {
                id: NodeId::new("dns-bootstrap-failure").expect("node id"),
            },
            profile_port,
        ),
    );
    state.default_profile = Some(profile_id);

    let options = CompileOptions {
        dns: DnsOptions {
            enabled: true,
            direct_servers: vec![format!("tcp://{}", direct_dns.address())],
            proxy_servers: vec![format!("tcp://{}", proxied_dns.address())],
            bootstrap_servers: vec![format!("tcp://{unavailable_bootstrap}")],
            direct_domains: vec!["full:bootstrap-failure.test".into()],
            query_strategy: "UseIPv4".into(),
            listen: Some(dns_listen),
            allow_direct_fallback: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut engine = engine_for_with_compile(state, dir.path(), options).await;
    engine.rebuild_and_start().await.expect("start real Xray");

    let outcome = tokio::time::timeout(
        Duration::from_secs(8),
        query_dns(dns_listen, "must-fail.test", DnsRecordType::A),
    )
    .await;
    assert!(
        !matches!(outcome, Ok(Ok(_))),
        "a failed bootstrap unexpectedly produced a DNS answer"
    );
    assert_eq!(
        direct_dns.query_count(),
        0,
        "bootstrap failure crossed into an overlapping ordinary direct resolver"
    );
    assert_eq!(
        proxied_dns.query_count(),
        0,
        "the proxied resolver was reached before its first-hop dependency existed"
    );
    assert_eq!(
        proxy.connection_count(),
        0,
        "Xray connected to the proxy without resolving its hostname"
    );
    engine.stop_core().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_proxied_dns_does_not_fall_back_to_a_direct_resolver() {
    let _binary = require_xray!("fail-closed proxied DNS");
    let Some(proxy) = ipv6_egress("dns-failure-proxy", true).await else {
        return;
    };
    let direct_dns = TcpDnsFixture::start_on(
        "127.0.0.1".parse().expect("IPv4 loopback"),
        "2001:db8::99".parse().expect("direct answer"),
    )
    .await
    .expect("direct DNS fixture");
    let unavailable = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("reserve unavailable address")
        .local_addr()
        .expect("reserved address");
    // Dropping the listener makes the failure deterministic: the routed TCP
    // connect receives ECONNREFUSED rather than waiting on the public network.
    let dir = tempfile::tempdir().expect("tempdir");
    let profile_port = free_port().expect("profile port");
    let dns_listen = SocketAddr::from(([127, 0, 0, 1], free_udp_port()));

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("dns-failure-proxy", "DNS failure proxy", proxy.socks_addr()),
    );
    let profile_id = ProfileId::new("dns-failure").expect("profile id");
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "dns-failure",
            Target::Node {
                id: NodeId::new("dns-failure-proxy").expect("node id"),
            },
            profile_port,
        ),
    );
    state.default_profile = Some(profile_id);
    let options = CompileOptions {
        dns: DnsOptions {
            enabled: true,
            direct_servers: vec![format!("tcp://{}", direct_dns.address())],
            proxy_servers: vec![format!("tcp://{unavailable}")],
            direct_domains: Vec::new(),
            query_strategy: "UseIPv6".into(),
            listen: Some(dns_listen),
            allow_direct_fallback: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut engine = engine_for_with_compile(state, dir.path(), options).await;
    engine.rebuild_and_start().await.expect("start real Xray");

    let outcome = tokio::time::timeout(
        Duration::from_secs(8),
        query_dns(dns_listen, "must-not-leak.test", DnsRecordType::Aaaa),
    )
    .await;
    assert!(
        !matches!(outcome, Ok(Ok(_))),
        "a failed proxied resolver unexpectedly produced a direct answer"
    );
    assert_eq!(
        direct_dns.query_count(),
        0,
        "proxied DNS failure leaked to the configured direct resolver"
    );
    assert!(
        proxy.connection_count() >= 1,
        "Xray did not attempt the configured proxied route"
    );
    engine.stop_core().await;
}

// ------------------------------------------------------- Share interoperability

#[tokio::test(flavor = "multi_thread")]
async fn exported_vless_reality_vision_reimports_and_carries_a_real_connection() {
    use std::os::unix::fs::PermissionsExt;

    let binary = require_xray!("VLESS REALITY share-link connection");
    let dir = tempfile::tempdir().expect("tempdir");
    let target_port = free_port().expect("target port");
    let server_port = free_port().expect("server port");
    let client_port = free_port().expect("client port");
    let egress = MockEgress::start("reality-share")
        .await
        .expect("start local egress");

    // REALITY mirrors a normal TLS target during its handshake. This synthetic
    // certificate and key are test-only, committed openly, and valid for the
    // loopback name `reality.test` until 2036.
    let certificate = dir.path().join("target-cert.pem");
    let private_key = dir.path().join("target-key.pem");
    std::fs::write(
        &certificate,
        include_bytes!("fixtures/reality-target-cert.pem"),
    )
    .expect("write target certificate");
    std::fs::write(
        &private_key,
        include_bytes!("fixtures/reality-target-key.pem"),
    )
    .expect("write target key");
    std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600))
        .expect("make target key private");

    let target_config = dir.path().join("target.json");
    write_fixture_json(
        &target_config,
        &serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": target_port,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": egress.identity_addr().ip().to_string(),
                    "port": egress.identity_addr().port(),
                    "network": "tcp"
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {"certificates": [{
                        "certificateFile": certificate,
                        "keyFile": private_key
                    }]}
                }
            }],
            "outbounds": [{"protocol": "freedom"}]
        }),
    );
    let mut target =
        FixtureCore::start(&binary, &target_config, dir.path().join("target-xray.log"));
    wait_for_fixture_listener(&mut target, SocketAddr::from(([127, 0, 0, 1], target_port))).await;

    // The pair came from `xray x25519`. It is deliberately synthetic and is
    // useful only inside this test.
    const PRIVATE_KEY: &str = "gHwLz-GumMhmgJ6lpOVPv7Kt7rDUJ-hy8S-2sc_8C00";
    const PUBLIC_KEY: &str = "0_0JQu2RfxY_tjAtwexl85D4OlSJzCbYh7Nx76pRKHQ";
    const UUID: &str = "11111111-2222-3333-4444-555555555555";
    const SHORT_ID: &str = "0123456789abcdef";

    let server_config = dir.path().join("server.json");
    write_fixture_json(
        &server_config,
        &serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "target": format!("127.0.0.1:{target_port}"),
                        "xver": 0,
                        "serverNames": ["reality.test"],
                        "privateKey": PRIVATE_KEY,
                        "shortIds": [SHORT_ID]
                    }
                }
            }],
            // Preview v26.7.28 makes protocol-server inbounds default-deny
            // private destinations. This explicit fixture-only rule permits
            // the loopback oracle; stable v26.3.27 ignores the new field.
            "outbounds": [{
                "protocol": "freedom",
                "settings": {"finalRules": [{"action": "allow"}]}
            }]
        }),
    );
    let mut server =
        FixtureCore::start(&binary, &server_config, dir.path().join("server-xray.log"));
    wait_for_fixture_listener(&mut server, SocketAddr::from(([127, 0, 0, 1], server_port))).await;

    // Import -> export -> independently decode PNG QR -> re-import. The node
    // used by the real client is the last value, not the original fixture.
    let original_link = format!(
        "vless://{UUID}@127.0.0.1:{server_port}?encryption=none&flow=xtls-rprx-vision\
         &security=reality&sni=reality.test&fp=chrome&pbk={PUBLIC_KEY}&sid={SHORT_ID}\
         &spx=%2F&type=tcp#REALITY%20Vision"
    );
    let original = xraytui_import::parse_uri(&original_link)
        .expect("import original REALITY link")
        .into_node()
        .expect("REALITY is executable");
    let export =
        xraytui_import::export_share_link(&original, xraytui_import::ShareOptions::default())
            .expect("lossless REALITY share export");
    assert_eq!(export.fidelity, xraytui_import::ExportFidelity::Lossless);
    let qr_path = dir.path().join("reality-share.png");
    xraytui_import::qr::render_png(export.link.expose(), &qr_path, 8).expect("render REALITY QR");
    let decoded = xraytui_import::qr::decode_png(&qr_path).expect("independent QR decode");
    assert_eq!(decoded.as_slice(), &[export.link.expose().to_owned()]);
    let shared = xraytui_import::parse_uri(&decoded[0])
        .expect("re-import decoded share link")
        .into_node()
        .expect("decoded REALITY link remains executable");
    assert_eq!(original.canonical_identity(), shared.canonical_identity());

    let node_id = shared.id.clone();
    let mut state = DesiredState::default();
    fixtures::add_node(&mut state, shared);
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks("shared", Target::Node { id: node_id }, client_port),
    );
    let mut client = engine_for(state, dir.path()).await;
    client.rebuild_and_start().await.unwrap_or_else(|error| {
        panic!(
            "start compiled REALITY client: {error}\nclient log:\n{}\nserver log:\n{}",
            std::fs::read_to_string(dir.path().join("xray.log")).unwrap_or_default(),
            server.log_text()
        )
    });

    let answer = probe_through_socks5(
        SocketAddr::from(([127, 0, 0, 1], client_port)),
        &egress.identity_addr().ip().to_string(),
        egress.identity_addr().port(),
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "REALITY connection failed: {error}\nserver log:\n{}",
            server.log_text()
        )
    });
    assert!(
        answer.contains("EGRESS reality-share"),
        "exported share did not reach the loopback egress: {answer:?}"
    );
    client.stop_core().await;
}

// ---------------------------------------------------------------- Scenario I

#[tokio::test(flavor = "multi_thread")]
async fn scenario_i_killing_the_core_is_noticed_and_schedules_a_restart() {
    let _binary = require_xray!("scenario I");
    let dir = tempfile::tempdir().expect("tempdir");

    let egress = MockEgress::start("only").await.expect("start egress");
    let port = free_port().expect("port");

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("only", "Only", egress.socks_addr()),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "web",
            Target::Node {
                id: NodeId::new("only").expect("valid"),
            },
            port,
        ),
    );

    let mut engine = engine_for(state, dir.path()).await;
    engine.rebuild_and_start().await.expect("core must start");
    assert!(egress_reached(port).await.contains("EGRESS only"));

    let pid = match engine.runtime().core {
        CoreStatus::Running { pid, .. } => pid,
        ref other => panic!("core is not running: {other:?}"),
    };

    // Kill the core the way a crash would.
    let raw = i32::try_from(pid).expect("pid fits");
    let target = rustix::process::Pid::from_raw(raw).expect("valid pid");
    rustix::process::kill_process(target, rustix::process::Signal::KILL).expect("kill");

    // The listener must stop accepting; that is the observable consequence.
    let mut listener_died = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let address: std::net::SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("loopback address");
        if tokio::net::TcpStream::connect(address).await.is_err() {
            listener_died = true;
            break;
        }
    }
    assert!(
        listener_died,
        "the profile listener outlived the core it belonged to"
    );

    // The supervisor schedules a restart rather than silently giving up.
    let delay = engine
        .note_core_exit("killed".into())
        .expect("a restart must be scheduled");
    assert!(delay >= Duration::from_millis(1));
    assert!(matches!(
        engine.runtime().core,
        CoreStatus::Restarting { .. }
    ));

    // And restarting really does bring the path back.
    engine.rebuild_and_start().await.expect("core must restart");
    assert!(egress_reached(port).await.contains("EGRESS only"));

    engine.stop_core().await;
}

// -------------------------------------------------- rollback / last-known-good

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_generation_rolls_back_to_the_previous_one() {
    let _binary = require_xray!("rollback");
    let dir = tempfile::tempdir().expect("tempdir");

    let egress = MockEgress::start("good").await.expect("start egress");
    let good_port = free_port().expect("port");

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("good", "Good", egress.socks_addr()),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_socks(
            "web",
            Target::Node {
                id: NodeId::new("good").expect("valid"),
            },
            good_port,
        ),
    );

    let mut engine = engine_for(state, dir.path()).await;
    let first = engine.rebuild_and_start().await.expect("core must start");
    assert!(egress_reached(good_port).await.contains("EGRESS good"));

    // Occupy a port, then ask for a profile that wants to bind it. The
    // configuration is valid — `xray run -test` passes — but the *runtime* start
    // fails, which is exactly the case a static test cannot catch.
    let squatter = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let taken = squatter.local_addr().expect("addr").port();

    let mut next = engine.desired().clone();
    let pid = ProfileId::new("broken").expect("valid");
    let mut broken = EgressProfile::new(pid.clone(), "Broken", Target::Direct);
    broken.socks = Some(ListenerSpec::loopback(taken));
    next.profiles.insert(pid, broken);

    let outcome = engine
        .apply(next)
        .await
        .expect("apply must resolve, not error");
    match outcome {
        ApplyOutcome::RolledBack { failed, restored } => {
            assert_ne!(failed, restored);
            assert!(
                restored > first,
                "the restored generation is a fresh start of the old state"
            );
        }
        other => panic!("expected a rollback, got {other:?}"),
    }

    // The working profile is serving again after the rollback.
    assert!(matches!(engine.runtime().core, CoreStatus::Running { .. }));
    assert!(egress_reached(good_port).await.contains("EGRESS good"));
    assert!(
        !engine
            .desired()
            .profiles
            .contains_key(&ProfileId::new("broken").expect("valid")),
        "the failed desired state must not be retained"
    );

    drop(squatter);
    engine.stop_core().await;
}

// ------------------------------------------------------------ generation gate

#[tokio::test(flavor = "multi_thread")]
async fn a_generation_is_only_healthy_after_listeners_and_overrides_are_verified() {
    let _binary = require_xray!("health gate");
    let dir = tempfile::tempdir().expect("tempdir");

    let egress = MockEgress::start("a").await.expect("start egress");
    let port = free_port().expect("port");

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("a", "A", egress.socks_addr()),
    );
    fixtures::add_profile(
        &mut state,
        fixtures::profile_with_both(
            "web",
            Target::Node {
                id: NodeId::new("a").expect("valid"),
            },
            port,
            free_port().expect("port"),
        ),
    );

    let mut engine = engine_for(state, dir.path()).await;
    let generation = engine.rebuild_and_start().await.expect("core must start");

    assert_eq!(engine.runtime().last_known_good, Some(generation));
    assert!(dir.path().join("last-good-xray.json").is_file());
    assert!(dir.path().join("generated-xray.json").is_file());

    // The override the compiler recorded really is in force in the core.
    let compiled = engine.compiled().expect("a compiled generation").clone();
    let client = engine.client().expect("an API client");
    let info = client
        .balancer_info("profile/web/selector")
        .await
        .expect("balancer must exist");
    assert_eq!(info.override_target.as_deref(), Some("node/a/out"));
    assert!(
        compiled
            .selector_overrides
            .contains(&("profile/web/selector".to_owned(), "node/a/out".to_owned()))
    );

    engine.stop_core().await;
}
