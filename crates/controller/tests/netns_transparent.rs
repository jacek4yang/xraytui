//! Acceptance scenario M, end to end, inside a disposable network namespace.
//!
//! # The claim under test
//!
//! Two instances of the **same executable**, launched with no proxy settings and
//! no knowledge that they are being proxied, connect to the **same destination**
//! at the same time and leave by **two different exits** — through **one**
//! supervised Xray-core process — because each was launched under a different
//! profile.
//!
//! Nothing below the claim is mocked. The real privileged helper runs over its
//! real socket, installs the real nftables ruleset, the real policy routing and
//! a real TUN device; the real compiler produces the configuration; the real
//! `xray` binary runs it; the two instances are launched by the real
//! `xraytui exec --transparent`. The only stand-ins are the "remote proxy
//! servers", which are [`MockEgress`]es on loopback so that the answer says
//! *which* exit served the connection rather than merely that something worked.
//!
//! # How to run it
//!
//! ```sh
//! sudo ./scripts/netns-test.sh
//! ```
//!
//! Without `XRAYTUI_NETNS_TESTS=1` every test here returns immediately, so an
//! ordinary `cargo test` never touches host networking. The harness refuses to
//! run outside a namespace and this file checks again for itself.
//!
//! # Why it lives in this crate
//!
//! The kernel-side arrangement is proven in `xraytui-linux-net`'s own namespace
//! suite. What is proven *here* is the product claim, which needs the compiler,
//! the supervisor, the core and the command-line client as well — so this is the
//! crate that can see all of them at once.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use xraytui_controller::{
    ApplyOutcome, ChangePlan, Engine, EngineConfig, discover_binary, probe_binary,
};
use xraytui_domain::{CoreStatus, DesiredState, ListenerSpec, NodeId, ProfileId, Target};
use xraytui_linux_net::nft::Nft;
use xraytui_test_support::{MockEgress, fixtures, free_port};
use xraytui_xray_api::ApiEndpoint;

/// The uid the test acts as. Inside the namespace this is the real uid, so
/// `SO_PEERCRED` in the helper reports the same value.
const UID: u32 = 0;

/// A destination both instances use. Identical on purpose: the distinction under
/// test must come from the cgroup and nothing else.
const DESTINATION: &str = "203.0.113.9";
/// The same port for both, for the same reason.
const DESTINATION_PORT: u16 = 80;

fn enabled() -> bool {
    std::env::var_os("XRAYTUI_NETNS_TESTS").is_some()
}

/// Refuse to run outside a disposable namespace even if the variable is set.
fn assert_disposable_namespace() {
    let netlink = xraytui_linux_net::netlink::Netlink::open().expect("netlink");
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

/// Where this project's own binaries were built.
///
/// The test binary lives in `target/<profile>/deps/`, so its grandparent is the
/// directory holding `xraytui` and `xraytui-netd`.
fn binary_dir() -> PathBuf {
    if let Some(configured) = std::env::var_os("XRAYTUI_TEST_BIN_DIR") {
        return PathBuf::from(configured);
    }
    std::env::current_exe()
        .expect("current exe")
        .parent()
        .and_then(Path::parent)
        .expect("target directory")
        .to_path_buf()
}

fn xray_path() -> Option<PathBuf> {
    if let Ok(configured) = std::env::var("XRAYTUI_TEST_XRAY") {
        return discover_binary(&configured).ok();
    }
    discover_binary("").ok()
}

/// Run `ip(8)`, for preconditions only.
///
/// This is the *environment*, not the product: a machine in transparent mode has
/// a default route, because otherwise an application's `connect()` fails before
/// any packet — and therefore any nftables rule — exists. A fresh namespace has
/// no such route, so the test supplies one.
fn ip(args: &[&str]) {
    let output = Command::new("ip").args(args).output().expect("run ip");
    assert!(
        output.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ip_output(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("run ip");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn nft_ruleset() -> String {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .expect("run nft");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The privileged helper, running as it really does: its own process, its own
/// socket, `SO_PEERCRED` deciding who the caller is.
struct Helper {
    child: std::process::Child,
    socket: PathBuf,
}

impl Helper {
    fn start(directory: &Path, cgroup_root: &Path) -> Self {
        let socket = directory.join("netd.sock");
        // `Drop` kills and waits; clippy cannot see that across the struct.
        #[allow(clippy::zombie_processes, reason = "reaped in Drop")]
        let child = Command::new(binary_dir().join("xraytui-netd"))
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(directory.join("netd-state"))
            .arg("--cgroup-root")
            .arg(cgroup_root)
            .spawn()
            .expect("start xraytui-netd");
        for _ in 0..200 {
            if socket.exists() {
                return Self { child, socket };
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the helper never created {}", socket.display());
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One instance of the application: `xraytui exec --transparent`, a real
/// unprivileged-looking client, with a scrubbed environment.
///
/// `env_clear` is deliberate and load-bearing. The test's claim is that the two
/// instances differ *only* by profile, so neither may carry `ALL_PROXY`,
/// `HTTP_PROXY` or anything else an application might honour. `PATH` is put back
/// because the launcher has to find `python3`.
fn launch_instance(
    socket: &Path,
    config_root: &Path,
    profile: &str,
    destination: &str,
    port: u16,
) -> std::process::Child {
    let program = format!(
        "import socket,sys\n\
         s=socket.socket(); s.settimeout(20)\n\
         s.connect(({destination:?},{port}))\n\
         s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\n\
         sys.stdout.write(s.recv(128).decode('utf-8','replace'))\n\
         sys.stdout.flush()\n\
         sys.stdin.readline()\n"
    );
    Command::new(binary_dir().join("xraytui"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", config_root)
        .env("XRAYTUI_NETD_SOCKET", socket)
        .arg("--root")
        .arg(config_root)
        .arg("exec")
        .arg("--transparent")
        .arg("--profile")
        .arg(profile)
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(&program)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("launch an instance")
}

/// Read one line of an instance's answer, then let it exit.
fn answer_of(mut child: std::process::Child) -> String {
    use std::io::{BufRead as _, BufReader, Write as _};
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    let _ = reader.read_line(&mut line);
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }
    let _ = child.wait();
    if line.trim().is_empty()
        && let Some(mut stderr) = child.stderr.take()
    {
        use std::io::Read as _;
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        return format!("<no answer> {text}");
    }
    line.trim().to_owned()
}

#[test]
fn scenario_m_two_instances_of_one_executable_take_two_exits_at_once() {
    if !enabled() {
        return;
    }
    let Some(binary) = xray_path() else {
        eprintln!("SKIPPED scenario M: no Xray-core binary on PATH (set XRAYTUI_TEST_XRAY)");
        return;
    };
    if !Nft::new("nft").available() {
        eprintln!("SKIPPED scenario M: nft is not installed");
        return;
    }
    let Some(cgroups) = std::env::var_os("XRAYTUI_TEST_CGROUP_ROOT").map(PathBuf::from) else {
        eprintln!("SKIPPED scenario M: no private cgroup v2 hierarchy was provided");
        return;
    };
    assert_disposable_namespace();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let dir = tempfile::tempdir().expect("tempdir");

        // --- something of the fixture's own, to be left alone ---------------
        // If teardown is too enthusiastic, this is what notices.
        // A TUN device rather than a dummy: `dummy` is a module this kernel does
        // not have, and what matters is only that the interface is not ours.
        ip(&["tuntap", "add", "dev", "fixture0", "mode", "tun"]);
        ip(&["link", "set", "fixture0", "up"]);
        ip(&["addr", "add", "10.77.0.1/24", "dev", "fixture0"]);
        ip(&[
            "route",
            "add",
            "10.88.0.0/24",
            "dev",
            "fixture0",
            "table",
            "77",
        ]);
        ip(&[
            "rule",
            "add",
            "pref",
            "1234",
            "from",
            "10.77.0.1",
            "lookup",
            "77",
        ]);

        // --- the privileged helper, over its real socket --------------------
        let helper = Helper::start(dir.path(), &cgroups);
        let mut netd = xraytui_linux_net::transport::NetdClient::connect(&helper.socket)
            .await
            .expect("connect to the helper");

        let interface = xraytui_netd_protocol::interface_for_uid(UID);
        netd.call(xraytui_netd_protocol::Operation::CreateTun(
            xraytui_netd_protocol::TunRequest {
                interface: interface.clone(),
                mtu: 1500,
                ipv4: Some("10.66.0.2/24".parse().expect("prefix")),
                ipv6: None,
                lease_ttl_secs: 300,
                failure_policy: xraytui_netd_protocol::FailurePolicy::Restore,
            },
        ))
        .await
        .expect("create tun");
        netd.call(xraytui_netd_protocol::Operation::ApplyRouting(
            xraytui_netd_protocol::RoutingRequest {
                include: Vec::new(),
                exclude: Vec::new(),
                bypass_endpoints: Vec::new(),
                bypass_private: false,
                blackhole_ipv4: false,
                blackhole_ipv6: true,
            },
        ))
        .await
        .expect("apply routing");
        ip(&["route", "add", "default", "dev", &interface]);

        // --- three observably different exits -------------------------------
        let exit_a = MockEgress::start("alpha").await.expect("start egress");
        let exit_b = MockEgress::start("bravo").await.expect("start egress");
        let exit_c = MockEgress::start("charlie").await.expect("start egress");

        let port_a = free_port().expect("port");
        let port_b = free_port().expect("port");

        let mut state = DesiredState::default();
        for (id, egress) in [
            ("exit-alpha", &exit_a),
            ("exit-bravo", &exit_b),
            ("exit-charlie", &exit_c),
        ] {
            fixtures::add_node(
                &mut state,
                fixtures::socks_node(id, id, egress.socks_addr()),
            );
        }
        for (profile, node, port) in [
            ("profile-a", "exit-alpha", port_a),
            ("profile-b", "exit-bravo", port_b),
        ] {
            let mut built = fixtures::profile_with_socks(
                profile,
                Target::Node {
                    id: NodeId::new(node).expect("valid"),
                },
                free_port().expect("port"),
            );
            built.transparent = Some(ListenerSpec::loopback(port));
            fixtures::add_profile(&mut state, built);
        }

        // The client reads the configuration from disk rather than from the
        // daemon, so this is what `xraytui exec --transparent` will see.
        let config_root = dir.path().join("client");
        let paths = xraytui_config::Paths::rooted_at(&config_root);
        paths.ensure().expect("config directories");
        xraytui_config::store::save(&paths, &state).expect("write the configuration");

        // `bypass_private_networks` is on by default and would send this test's
        // traffic direct, because `geoip:private` is RFC 6890's special-purpose
        // registry — which *includes the documentation ranges* used here as
        // stand-in destinations. Verified against the pinned core, not assumed;
        // see docs/UPSTREAM-COMPATIBILITY.md. The bypass has its own tests in
        // the compiler; what is under test here is the egress path.
        let compile = xraytui_xray_compiler::CompileOptions {
            bypass_private_networks: false,
            ..Default::default()
        };
        let info = probe_binary(&binary, None).await.expect("probe the binary");
        let mut engine = Engine::new(
            EngineConfig {
                compile,
                api_endpoint: ApiEndpoint::loopback(free_port().expect("port")),
                generated_config: dir.path().join("generated-xray.json"),
                last_good_config: dir.path().join("last-good-xray.json"),
                core_log: Some(dir.path().join("xray.log")),
                api_deadline: Duration::from_secs(20),
                ..Default::default()
            },
            info,
        )
        .expect("supported core");
        engine.seed(state).expect("no core is running yet");
        engine.rebuild_and_start().await.expect("core must start");

        // The redirect is installed only now, so it names ports that are already
        // listening. The other order would send the first connection into a
        // black hole.
        netd.call(xraytui_netd_protocol::Operation::ApplyFirewall(
            xraytui_netd_protocol::FirewallRequest {
                mark_all: false,
                cgroup_marks: vec![
                    xraytui_netd_protocol::CgroupMark {
                        profile: "profile-a".into(),
                        tproxy_port: Some(port_a),
                    },
                    xraytui_netd_protocol::CgroupMark {
                        profile: "profile-b".into(),
                        tproxy_port: Some(port_b),
                    },
                ],
                kill_switch: false,
                bypass_uid: true,
            },
        ))
        .await
        .expect("apply firewall");

        let pid_before = match engine.runtime().core {
            CoreStatus::Running { pid, .. } => pid,
            ref other => panic!("core is not running: {other:?}"),
        };
        let generation_before = engine.runtime().generation;

        // --- the claim -------------------------------------------------------
        // Same executable, same arguments, same destination, same port, no proxy
        // environment. Both in flight at once.
        let first = launch_instance(
            &helper.socket,
            &config_root,
            "profile-a",
            DESTINATION,
            DESTINATION_PORT,
        );
        let second = launch_instance(
            &helper.socket,
            &config_root,
            "profile-b",
            DESTINATION,
            DESTINATION_PORT,
        );
        let answer_a = tokio::task::spawn_blocking(move || answer_of(first));
        let answer_b = tokio::task::spawn_blocking(move || answer_of(second));
        let (answer_a, answer_b) = tokio::join!(answer_a, answer_b);
        let answer_a = answer_a.expect("instance a");
        let answer_b = answer_b.expect("instance b");

        eprintln!("scenario M: instance under profile-a was answered by {answer_a:?}");
        eprintln!("scenario M: instance under profile-b was answered by {answer_b:?}");
        if !answer_a.contains("EGRESS") || !answer_b.contains("EGRESS") {
            for artefact in ["generated-xray.json", "xray.log"] {
                eprintln!(
                    "--- {artefact} ---\n{}",
                    std::fs::read_to_string(dir.path().join(artefact)).unwrap_or_default()
                );
            }
            eprintln!("--- ruleset ---\n{}", nft_ruleset());
        }

        assert!(
            answer_a.contains("EGRESS alpha"),
            "the instance launched under profile-a must leave by profile-a's exit; \
             it got {answer_a:?}"
        );
        assert!(
            answer_b.contains("EGRESS bravo"),
            "and the other instance — same executable, same destination, at the \
             same time — by profile-b's; it got {answer_b:?}"
        );

        // The distinction cannot have come from anything else: same program,
        // same argument vector, same destination and port, and no environment.
        assert_eq!(exit_a.connection_count(), 1);
        assert_eq!(exit_b.connection_count(), 1);
        assert_eq!(
            exit_c.connection_count(),
            0,
            "the third exit has not been selected yet"
        );

        // --- hot-switch profile-a, through the API, with the core untouched ---
        let mut next = engine.desired().clone();
        if let Some(profile) = next
            .profiles
            .get_mut(&ProfileId::new("profile-a").expect("valid"))
        {
            profile.target = Target::Node {
                id: NodeId::new("exit-charlie").expect("valid"),
            };
        }
        assert!(
            matches!(engine.plan(&next), ChangePlan::Selectors(_)),
            "switching a target must not need a restart: {:?}",
            engine.plan(&next)
        );
        let outcome = engine
            .set_profile_target(
                &ProfileId::new("profile-a").expect("valid"),
                Target::Node {
                    id: NodeId::new("exit-charlie").expect("valid"),
                },
            )
            .await
            .expect("switch must succeed");
        match &outcome {
            ApplyOutcome::SwitchedSelectors { balancers } => {
                assert_eq!(balancers, &vec!["profile/profile-a/selector".to_owned()]);
            }
            other => panic!("expected an API switch, got {other:?}"),
        }

        let third = launch_instance(
            &helper.socket,
            &config_root,
            "profile-a",
            DESTINATION,
            DESTINATION_PORT,
        );
        let fourth = launch_instance(
            &helper.socket,
            &config_root,
            "profile-b",
            DESTINATION,
            DESTINATION_PORT,
        );
        let after_a = tokio::task::spawn_blocking(move || answer_of(third));
        let after_b = tokio::task::spawn_blocking(move || answer_of(fourth));
        let (after_a, after_b) = tokio::join!(after_a, after_b);
        let after_a = after_a.expect("instance a again");
        let after_b = after_b.expect("instance b again");
        eprintln!("scenario M: after the switch, profile-a got {after_a:?}");
        eprintln!("scenario M: after the switch, profile-b got {after_b:?}");

        assert!(
            after_a.contains("EGRESS charlie"),
            "a new connection under profile-a must use the new exit: {after_a:?}"
        );
        assert!(
            after_b.contains("EGRESS bravo"),
            "and profile-b must be undisturbed: {after_b:?}"
        );
        match engine.runtime().core {
            CoreStatus::Running { pid, .. } => {
                assert_eq!(pid, pid_before, "the core was restarted")
            }
            ref other => panic!("core is not running: {other:?}"),
        }
        assert_eq!(
            engine.runtime().generation,
            generation_before,
            "a target switch must not start a new generation"
        );

        // --- teardown, and what must be left --------------------------------
        engine.stop_core().await;
        netd.call(xraytui_netd_protocol::Operation::Release)
            .await
            .expect("release");
        drop(netd);

        let ruleset = nft_ruleset();
        assert!(
            !ruleset.contains("u0-mark")
                && !ruleset.contains("u0-redirect")
                && !ruleset.contains("u0-guard"),
            "nftables chains survived teardown:\n{ruleset}"
        );
        let rules = ip_output(&["rule", "show"]);
        for priority in [
            xraytui_linux_net::routing::rule_priority(UID),
            xraytui_linux_net::routing::transparent_rule_priority(UID),
        ] {
            assert!(
                !rules.contains(&format!("{priority}:")),
                "policy rule {priority} survived teardown:\n{rules}"
            );
        }
        for table in [
            xraytui_netd_protocol::table_for_uid(UID),
            xraytui_netd_protocol::transparent_table_for_uid(UID),
        ] {
            let routes = ip_output(&["route", "show", "table", &table.to_string()]);
            assert!(
                routes.trim().is_empty(),
                "table {table} still has routes after teardown:\n{routes}"
            );
        }
        let links = ip_output(&["-brief", "link", "show"]);
        assert!(
            !links.contains(&interface),
            "the tunnel survived teardown:\n{links}"
        );
        let user_root = cgroups.join("xraytui.slice").join(format!("u{UID}"));
        assert!(
            !user_root.exists(),
            "profile cgroups survived teardown: {}",
            user_root.display()
        );
        assert!(
            !dir.path().join("netd-state").join("leases").exists()
                || std::fs::read_dir(dir.path().join("netd-state").join("leases"))
                    .map(|entries| entries.count())
                    .unwrap_or(0)
                    == 0,
            "a lease survived teardown"
        );

        // And what the test itself created is still there.
        assert!(
            ip_output(&["-brief", "link", "show"]).contains("fixture0"),
            "teardown removed an interface it did not create"
        );
        assert!(
            ip_output(&["rule", "show"]).contains("1234:"),
            "teardown removed a policy rule it did not create"
        );
        assert!(
            ip_output(&["route", "show", "table", "77"]).contains("10.88.0.0/24"),
            "teardown removed a route it did not create"
        );

        drop(helper);
    });
}
