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

use std::net::SocketAddr;
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
use xraytui_test_support::{MockEgress, fixtures, free_port, probe_through_socks5};
use xraytui_xray_api::ApiEndpoint;

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
    let binary = xray_path().expect("checked by require_xray!");
    let info = probe_binary(&binary, None).await.expect("probe the binary");

    let api_port = free_port().expect("free port");
    let config = EngineConfig {
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

/// Read the egress banner through a profile's SOCKS listener.
async fn egress_reached(port: u16) -> String {
    let address = format!("127.0.0.1:{port}")
        .parse()
        .expect("loopback address");
    probe_through_socks5(address, "probe.invalid", 80)
        .await
        .unwrap_or_else(|error| panic!("probe through 127.0.0.1:{port} failed: {error}"))
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
    client
        .rebuild_and_start()
        .await
        .expect("start compiled REALITY client");

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
