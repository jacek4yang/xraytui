//! Combined system-path acceptance: uid marking -> Xray TUN and
//! systemd-resolved -> Xray DNS -> proxied IPv6 upstream.
//!
//! This test is intentionally absent from an ordinary `cargo test`: it needs a
//! disposable network/cgroup namespace, nftables, a private system D-Bus, a
//! real systemd-resolved and a real Xray with the privileges its Linux TUN
//! implementation currently requires. `scripts/combined-netns-test.sh` creates
//! that environment in a network-less privileged container.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use xraytui_config::{
    ConfigFile, DnsManager, DnsProxyFailurePolicy, FailurePolicy, Paths, store_toml,
};
use xraytui_domain::{DesiredState, NodeId, SystemMode, Target};
use xraytui_linux_net::transport::NetdClient;
use xraytui_netd_protocol::{Operation, Outcome};
use xraytui_test_support::{DnsRecordType, TcpDnsFixture, fixtures, free_port, query_dns};

const TEST_SWITCH: &str = "XRAYTUI_COMBINED_DNS_TESTS";
const TUN_V4: &str = "198.18.0.1";
const IPV4_DESTINATION: &str = "203.0.113.9";
const IPV6_DESTINATION: &str = "2001:db8:dead::9";

fn enabled() -> bool {
    std::env::var_os(TEST_SWITCH).is_some()
}

fn assert_disposable_namespace() {
    let netlink = xraytui_linux_net::netlink::Netlink::open().expect("netlink");
    let links = netlink.links_with_prefix("").expect("list links");
    let foreign: Vec<&str> = links
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| *name != "lo" && !name.starts_with("xraytui"))
        .collect();
    assert!(
        foreign.is_empty(),
        "refusing to run the combined privileged test outside a disposable namespace: {foreign:?}"
    );
    assert!(
        Path::new("/run/dbus/system_bus_socket").exists(),
        "the private system D-Bus is not running"
    );
}

fn binary_dir() -> PathBuf {
    std::env::var_os("XRAYTUI_TEST_BIN_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|path| path.parent()?.parent().map(Path::to_path_buf))
        })
        .expect("binary directory")
}

fn run_ip(arguments: &[&str]) -> String {
    let output = Command::new("ip").args(arguments).output().expect("run ip");
    assert!(
        output.status.success(),
        "ip {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn nft_ruleset() -> String {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .expect("list nftables");
    assert!(
        output.status.success(),
        "nft list ruleset failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn policy_routes(ipv6: bool) -> String {
    let table = xraytui_netd_protocol::table_for_uid(0).to_string();
    if ipv6 {
        run_ip(&["-6", "route", "show", "table", &table])
    } else {
        run_ip(&["route", "show", "table", &table])
    }
}

fn assert_dual_stack_blackhole(context: &str) {
    let ipv4 = policy_routes(false);
    assert!(
        ipv4.contains("blackhole default"),
        "{context} did not retain the IPv4 blackhole: {ipv4}"
    );
    let ipv6 = policy_routes(true);
    assert!(
        ipv6.contains("blackhole default"),
        "{context} did not retain the IPv6 blackhole: {ipv6}"
    );
}

fn tx_packets(interface: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/{interface}/statistics/tx_packets"))
        .expect("read tx counter")
        .trim()
        .parse()
        .expect("numeric tx counter")
}

struct DirectLeakSentinel {
    interface: &'static str,
}

impl DirectLeakSentinel {
    fn start() -> Self {
        let interface = "leak0";
        run_ip(&["link", "add", interface, "type", "dummy"]);
        run_ip(&["addr", "add", "192.0.2.1/24", "dev", interface]);
        run_ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            interface,
            "nodad",
        ]);
        run_ip(&["link", "set", interface, "up"]);
        run_ip(&["route", "add", "203.0.113.0/24", "dev", interface]);
        run_ip(&["-6", "route", "add", "2001:db8:dead::/48", "dev", interface]);
        for fallback in ["9.9.9.9/32", "1.1.1.1/32", "8.8.8.8/32"] {
            run_ip(&["route", "add", fallback, "dev", interface]);
        }
        for fallback in [
            "2620:fe::9/128",
            "2606:4700:4700::1111/128",
            "2001:4860:4860::8888/128",
        ] {
            run_ip(&["-6", "route", "add", fallback, "dev", interface]);
        }
        for arguments in [
            vec!["add", "table", "inet", "xraytui_acceptance"],
            vec![
                "add",
                "chain",
                "inet",
                "xraytui_acceptance",
                "egress",
                "{",
                "type",
                "filter",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            vec![
                "add",
                "rule",
                "inet",
                "xraytui_acceptance",
                "egress",
                "oifname",
                interface,
                "meta",
                "l4proto",
                "{",
                "tcp",
                ",",
                "udp",
                "}",
                "th",
                "dport",
                "{",
                "53",
                ",",
                "853",
                "}",
                "counter",
            ],
        ] {
            let status = Command::new("nft")
                .args(&arguments)
                .status()
                .expect("install DNS leak counter");
            assert!(status.success(), "nft {arguments:?}");
        }
        Self { interface }
    }

    fn dns_packets(&self) -> u64 {
        let output = Command::new("nft")
            .args(["list", "chain", "inet", "xraytui_acceptance", "egress"])
            .output()
            .expect("read DNS leak counter");
        let text = String::from_utf8_lossy(&output.stdout);
        let (_, after) = text.split_once("counter packets ").expect("packet counter");
        after
            .split_whitespace()
            .next()
            .expect("packet count")
            .parse()
            .expect("numeric packet count")
    }
}

impl Drop for DirectLeakSentinel {
    fn drop(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "xraytui_acceptance"])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", self.interface])
            .status();
    }
}

struct ProcessGuard {
    child: Child,
    graceful: bool,
}

impl ProcessGuard {
    fn terminate(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let signal = if self.graceful { "-TERM" } else { "-KILL" };
        let _ = Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn start_helper(directory: &Path) -> ProcessGuard {
    let socket = Path::new(xraytui_netd_protocol::DEFAULT_SOCKET);
    if socket.exists() {
        std::fs::remove_file(socket).expect("remove stale test socket");
    }
    let child = Command::new(binary_dir().join("xraytui-netd"))
        .arg("--socket")
        .arg(socket)
        .arg("--state-dir")
        .arg(directory.join("netd-state"))
        .arg("--cgroup-root")
        .arg("/sys/fs/cgroup")
        .arg("--reap-interval")
        .arg("1")
        .env("XRAYTUI_NETD_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start helper");
    let guard = ProcessGuard {
        child,
        graceful: true,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if socket.exists() {
            return guard;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("helper did not create {}", socket.display());
}

fn start_daemon(root: &Path) -> ProcessGuard {
    let child = Command::new(binary_dir().join("xraytuid"))
        .arg("--root")
        .arg(root)
        .env("XRAYTUI_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start daemon");
    ProcessGuard {
        child,
        graceful: true,
    }
}

fn status(root: &Path) -> Option<serde_json::Value> {
    let output = Command::new(binary_dir().join("xraytui"))
        .arg("--root")
        .arg(root)
        .args(["status", "--format", "json"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| serde_json::from_slice(&output.stdout).ok())
        .flatten()
}

fn run_cli(root: &Path, arguments: &[&str]) {
    let output = Command::new(binary_dir().join("xraytui"))
        .arg("--root")
        .arg(root)
        .args(arguments)
        .output()
        .expect("run xraytui command");
    assert!(
        output.status.success(),
        "xraytui {arguments:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wait_active(root: &Path, different_from: Option<u32>) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let pid = status(root).and_then(|value| {
            let core = &value["runtime"]["core"];
            (core["state"] == "running")
                .then(|| core["pid"].as_u64())
                .flatten()
                .and_then(|pid| u32::try_from(pid).ok())
        });
        let rules = nft_ruleset();
        if let Some(pid) = pid
            && different_from != Some(pid)
            && Path::new("/sys/class/net/xraytui0").exists()
            && rules.contains("xraytui.slice/u0/core")
            && rules.contains("hook postrouting")
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "TUN activation did not complete");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_link_absent(interface: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if !Path::new(&format!("/sys/class/net/{interface}")).exists() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{interface} remained after the core failure"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn tunnel_probe(destination: &str, port: u16) -> Result<String, String> {
    let address = if destination.contains(':') {
        format!("[{destination}]:{port}")
    } else {
        format!("{destination}:{port}")
    };
    let mut stream = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(address))
        .await
        .map_err(|_| "TUN connection timed out".to_owned())?
        .map_err(|error| format!("TUN connection failed: {error}"))?;
    stream
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .await
        .map_err(|error| format!("write failed: {error}"))?;
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
        .await
        .map_err(|_| "egress answer timed out".to_owned())?
        .map_err(|error| format!("read egress answer failed: {error}"))?;
    Ok(String::from_utf8_lossy(&answer).into_owned())
}

fn failure_diagnostics(root: &Path) -> String {
    fn command(program: &str, arguments: &[&str]) -> String {
        Command::new(program)
            .args(arguments)
            .output()
            .map(|output| {
                format!(
                    "$ {program} {}\n{}{}",
                    arguments.join(" "),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .unwrap_or_else(|error| format!("$ {program}: {error}\n"))
    }

    let paths = Paths::rooted_at(root);
    let core_pid = status(root)
        .and_then(|value| value["runtime"]["core"]["pid"].as_u64())
        .unwrap_or_default();
    [
        command("ps", &["-ef"]),
        command("ls", &["-l", &format!("/proc/{core_pid}/fd")]),
        command("cat", &[&format!("/proc/{core_pid}/status")]),
        command("ip", &["-details", "-statistics", "address", "show"]),
        command("ip", &["rule", "show"]),
        command("ip", &["-6", "rule", "show"]),
        command(
            "ip",
            &[
                "route",
                "show",
                "table",
                &xraytui_netd_protocol::table_for_uid(0).to_string(),
            ],
        ),
        command(
            "ip",
            &[
                "-6",
                "route",
                "show",
                "table",
                &xraytui_netd_protocol::table_for_uid(0).to_string(),
            ],
        ),
        command("nft", &["list", "ruleset"]),
        command("resolvectl", &["status"]),
        format!(
            "generated config:\n{}\ncore log:\n{}\nresolved log:\n{}",
            std::fs::read_to_string(paths.generated_config()).unwrap_or_default(),
            std::fs::read_to_string(paths.core_log()).unwrap_or_default(),
            std::fs::read_to_string("/tmp/xraytui-resolved.log").unwrap_or_default()
        ),
    ]
    .join("\n")
}

struct CombinedEgress {
    address: SocketAddr,
    connections: Arc<AtomicU64>,
    dns_connections: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl CombinedEgress {
    async fn start(dns: SocketAddr) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind combined SOCKS egress");
        let address = listener.local_addr().expect("SOCKS address");
        let connections = Arc::new(AtomicU64::new(0));
        let dns_connections = Arc::new(AtomicU64::new(0));
        let all = Arc::clone(&connections);
        let dns_count = Arc::clone(&dns_connections);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let all = Arc::clone(&all);
                let dns_count = Arc::clone(&dns_count);
                tokio::spawn(async move {
                    all.fetch_add(1, Ordering::Relaxed);
                    let _ = serve_combined_socks(stream, dns, dns_count).await;
                });
            }
        });
        Self {
            address,
            connections,
            dns_connections,
            task,
        }
    }
}

impl Drop for CombinedEgress {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_combined_socks(
    mut client: TcpStream,
    dns: SocketAddr,
    dns_count: Arc<AtomicU64>,
) -> std::io::Result<()> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;
    client.write_all(&[5, 0]).await?;

    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await?;
    match request[3] {
        1 => {
            let mut address = [0_u8; 4];
            client.read_exact(&mut address).await?;
        }
        3 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length).await?;
            let mut address = vec![0_u8; usize::from(length[0])];
            client.read_exact(&mut address).await?;
        }
        4 => {
            let mut address = [0_u8; 16];
            client.read_exact(&mut address).await?;
        }
        _ => return Err(std::io::Error::other("unsupported SOCKS address type")),
    }
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;

    if port == dns.port() {
        dns_count.fetch_add(1, Ordering::Relaxed);
        let mut upstream = TcpStream::connect(dns).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    } else {
        let mut scratch = [0_u8; 1024];
        let _ = tokio::time::timeout(Duration::from_millis(250), client.read(&mut scratch)).await;
        client.write_all(b"EGRESS combined\n").await?;
    }
    Ok(())
}

fn write_configuration(
    root: &Path,
    xray: &Path,
    proxy: SocketAddr,
    proxied_dns: SocketAddr,
    direct_dns: SocketAddr,
) {
    let paths = Paths::rooted_at(root);
    paths.ensure().expect("create private paths");

    let mut config = ConfigFile::default();
    config.core.binary = xray.display().to_string();
    config.core.asset_dir = xray.parent().map(Path::to_path_buf);
    config.runtime.failure_policy = FailurePolicy::Block;
    config.runtime.restart_backoff_min_ms = 3_000;
    config.runtime.restart_backoff_max_ms = 3_000;
    config.runtime.start_health_deadline_ms = 20_000;
    config.tun.ipv4 = true;
    config.tun.ipv6 = true;
    config.tun.bypass_private_networks = false;
    config.dns.manager = DnsManager::SystemdResolved;
    config.dns.enabled = true;
    config.dns.listen = Some(SocketAddr::new(TUN_V4.parse().expect("TUN IPv4"), 53));
    config.dns.proxy_servers = vec![format!("tcp://{proxied_dns}")];
    config.dns.direct_servers = vec![format!("tcp://{direct_dns}")];
    config.dns.direct_domains = vec!["full:direct-only.example".into()];
    config.dns.proxy_failure_policy = DnsProxyFailurePolicy::Block;
    config.dns.query_strategy = "UseIPv6".into();
    store_toml(&paths.config_file(), &config).expect("write config.toml");

    let mut state = DesiredState::default();
    fixtures::add_node(
        &mut state,
        fixtures::socks_node("combined-egress", "Combined egress", proxy),
    );
    let profile = fixtures::profile_with_socks(
        "combined",
        Target::Node {
            id: NodeId::new("combined-egress").expect("node id"),
        },
        free_port().expect("profile port"),
    );
    let profile_id = fixtures::add_profile(&mut state, profile);
    state.default_profile = Some(profile_id);
    state.mode = SystemMode::Global;
    xraytui_config::store::save(&paths, &state).expect("write desired state");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn combined_tun_resolved_and_proxied_dns_is_dual_stack_and_fail_closed() {
    if !enabled() {
        return;
    }
    assert_disposable_namespace();
    let xray = PathBuf::from(
        std::env::var_os("XRAYTUI_TEST_XRAY").expect("XRAYTUI_TEST_XRAY is required"),
    );
    assert!(
        xray.is_file(),
        "{} is not a real Xray binary",
        xray.display()
    );

    let leak = DirectLeakSentinel::start();
    let proxied_dns = TcpDnsFixture::start_on(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "2001:db8:cafe::53".parse().expect("proxied answer"),
    )
    .await
    .expect("start proxied IPv6 DNS");
    let direct_dns = TcpDnsFixture::start_on(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "192.0.2.53".parse().expect("direct answer"),
    )
    .await
    .expect("start direct DNS sentinel");
    let egress = CombinedEgress::start(proxied_dns.address()).await;

    let directory = tempfile::tempdir().expect("test directory");
    write_configuration(
        directory.path(),
        &xray,
        egress.address,
        proxied_dns.address(),
        direct_dns.address(),
    );
    let mut helper = start_helper(directory.path());
    let mut daemon = start_daemon(directory.path());

    let first_pid = wait_active(directory.path(), None).await;
    assert!(Path::new("/sys/class/net/xraytui0").exists(), "TUN missing");
    let cgroup =
        std::fs::read_to_string(format!("/proc/{first_pid}/cgroup")).expect("read Xray cgroup");
    assert!(cgroup.contains("xraytui.slice/u0/core"), "{cgroup}");
    let rules = nft_ruleset();
    let core_bypass = rules.find("xraytui.slice/u0/core").expect("core bypass");
    let uid_mark = rules.find("meta skuid 0 meta mark set").expect("uid mark");
    assert!(core_bypass < uid_mark, "{rules}");

    let direct_before = tx_packets(leak.interface);
    let tun_tx_before = tx_packets("xraytui0");
    for destination in [IPV4_DESTINATION, IPV6_DESTINATION] {
        let answer = tunnel_probe(destination, 18_080)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "{destination}: {error}; SOCKS connections={}; TUN tx before={}, after={}\n{}",
                    egress.connections.load(Ordering::Relaxed),
                    tun_tx_before,
                    tx_packets("xraytui0"),
                    failure_diagnostics(directory.path())
                )
            });
        assert!(
            answer.contains("EGRESS combined"),
            "{destination}: {answer:?}"
        );
    }
    assert_eq!(
        tx_packets(leak.interface),
        direct_before,
        "IPv4 or IPv6 escaped through the available direct sentinel"
    );

    let answer = tokio::time::timeout(
        Duration::from_secs(10),
        query_dns(
            SocketAddr::from(([127, 0, 0, 53], 53)),
            "combined-a.example",
            DnsRecordType::Aaaa,
        ),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "resolved query timed out; proxied={}, SOCKS={}, direct={}\n{}",
            proxied_dns.query_count(),
            egress.connections.load(Ordering::Relaxed),
            direct_dns.query_count(),
            failure_diagnostics(directory.path())
        )
    })
    .expect("resolved query failed");
    assert_eq!(answer, "2001:db8:cafe::53".parse::<IpAddr>().unwrap());
    assert!(
        proxied_dns.query_count() >= 1,
        "proxied resolver was not used"
    );
    assert!(
        egress.dns_connections.load(Ordering::Relaxed) >= 1,
        "the IPv6 resolver did not traverse the selected SOCKS outbound"
    );
    assert_eq!(
        direct_dns.query_count(),
        0,
        "DNS leaked to the direct resolver"
    );

    // Adding an unused node is a structural mutation, so the daemon must
    // validate and restart Xray. On Linux that requires relinquishing the old
    // non-multiqueue TUN before `xray run -test` opens the prepared candidate.
    // This catches an EBUSY failure that config-only tests cannot observe.
    let before_mutation = tx_packets(leak.interface);
    run_cli(
        directory.path(),
        &[
            "node",
            "import",
            "socks://127.0.0.1:9#Unused-structural-fixture",
        ],
    );
    let after_mutation_pid = wait_active(directory.path(), Some(first_pid)).await;
    assert_eq!(
        tx_packets(leak.interface),
        before_mutation,
        "structural handover leaked through the direct sentinel"
    );
    assert!(
        tunnel_probe(IPV6_DESTINATION, 18_080)
            .await
            .expect("IPv6 did not recover after structural update")
            .contains("EGRESS combined")
    );

    // The explicit restart command follows the same transaction and must not
    // try to validate while the previous core still owns the TUN.
    run_cli(directory.path(), &["restart"]);
    let live_pid = wait_active(directory.path(), Some(after_mutation_pid)).await;
    assert_eq!(leak.dns_packets(), 0, "DNS escaped during planned restarts");

    Command::new("kill")
        .args(["-KILL", &live_pid.to_string()])
        .status()
        .expect("kill Xray");
    wait_link_absent("xraytui0").await;
    let blocked_rules = nft_ruleset();
    assert!(
        blocked_rules.contains("meta skuid 0 meta mark set"),
        "{blocked_rules}"
    );
    assert_dual_stack_blackhole("core failure");
    let before_blocked_probe = tx_packets(leak.interface);
    for destination in [IPV4_DESTINATION, IPV6_DESTINATION] {
        let bind = if destination.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = std::net::UdpSocket::bind(bind).expect("bind UDP leak probe");
        let target = if destination.contains(':') {
            format!("[{destination}]:9")
        } else {
            format!("{destination}:9")
        };
        let _ = socket.send_to(b"must-not-leak", target);
    }
    assert_eq!(
        tx_packets(leak.interface),
        before_blocked_probe,
        "failure-policy block leaked during restart backoff"
    );

    let second_pid = wait_active(directory.path(), Some(live_pid)).await;
    assert_ne!(second_pid, live_pid);
    assert_eq!(leak.dns_packets(), 0, "DNS escaped during Xray recovery");
    let answer = tokio::time::timeout(
        Duration::from_secs(10),
        query_dns(
            SocketAddr::from(([127, 0, 0, 53], 53)),
            "combined-b.example",
            DnsRecordType::Aaaa,
        ),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "DNS recovery query timed out; proxied={}, SOCKS={}, direct={}\n{}",
            proxied_dns.query_count(),
            egress.connections.load(Ordering::Relaxed),
            direct_dns.query_count(),
            failure_diagnostics(directory.path())
        )
    })
    .expect("DNS did not recover after Xray restart");
    assert_eq!(answer, "2001:db8:cafe::53".parse::<IpAddr>().unwrap());
    assert!(egress.connections.load(Ordering::Relaxed) >= 4);
    assert_eq!(direct_dns.query_count(), 0, "recovery leaked DNS directly");

    // An explicit down is orderly and must restore the host completely.
    run_cli(directory.path(), &["down"]);
    wait_link_absent("xraytui0").await;
    let down_rules = nft_ruleset();
    assert!(
        !down_rules.contains("u0-mark") && !down_rules.contains("u0-guard"),
        "orderly down left firewall state: {down_rules}"
    );

    // A daemon crash is different: block policy must survive loss of the last
    // authenticated helper connection. This closes the race where CoreFailed
    // installed a blackhole and connection cleanup immediately removed it.
    run_cli(directory.path(), &["up"]);
    let crash_pid = wait_active(directory.path(), Some(second_pid)).await;
    assert_ne!(crash_pid, second_pid);
    daemon.graceful = false;
    daemon.terminate();
    wait_link_absent("xraytui0").await;
    let crashed_rules = nft_ruleset();
    assert!(
        crashed_rules.contains("meta skuid 0 meta mark set"),
        "daemon crash removed the uid guard: {crashed_rules}"
    );
    assert_dual_stack_blackhole("daemon crash");
    let before_daemon_crash_probe = tx_packets(leak.interface);
    for destination in [IPV4_DESTINATION, IPV6_DESTINATION] {
        let bind = if destination.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = std::net::UdpSocket::bind(bind).expect("bind daemon-crash leak probe");
        let target = if destination.contains(':') {
            format!("[{destination}]:9")
        } else {
            format!("{destination}:9")
        };
        let _ = socket.send_to(b"daemon-crash-must-not-leak", target);
    }
    assert_eq!(
        tx_packets(leak.interface),
        before_daemon_crash_probe,
        "failure-policy block leaked after daemon death"
    );

    // The daemon was killed rather than allowed to reap its child. Stop a
    // surviving orphan explicitly so the fixture can also verify cgroup
    // cleanup instead of relying on container teardown.
    let _ = Command::new("kill")
        .args(["-KILL", &crash_pid.to_string()])
        .status();

    // Cleanup is explicit because the crash path intentionally leaves the
    // configured block policy in force.
    let mut cleanup = NetdClient::connect(xraytui_netd_protocol::DEFAULT_SOCKET)
        .await
        .expect("connect for acceptance cleanup");
    assert!(
        matches!(
            cleanup.call(Operation::Release).await,
            Ok(Outcome::Recovered { .. })
        ),
        "helper refused acceptance cleanup"
    );
    drop(cleanup);
    let final_rules = nft_ruleset();
    assert!(
        !final_rules.contains("u0-mark") && !final_rules.contains("u0-guard"),
        "explicit cleanup left firewall state: {final_rules}"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !Path::new("/sys/fs/cgroup/xraytui.slice/u0/core").exists(),
        "the helper reaper did not remove the now-empty core cgroup"
    );
    helper.terminate();
}
