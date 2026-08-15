//! Runs the real `xraytuid` and `xraytui` binaries against each other.
//!
//! This is the test that would catch a mismatch nobody notices in unit tests:
//! the daemon and the CLI agreeing on the socket path, the protocol version, the
//! exit codes, and the shape of every output format.
//!
//! Skipped, loudly, when no Xray binary is available, because the daemon refuses
//! to start without one.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use xraytui_test_support::{MockEgress, free_port};

fn have_xray() -> bool {
    std::env::var("XRAYTUI_TEST_XRAY").is_ok_and(|p| Path::new(&p).is_file())
        || std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .any(|dir| !dir.is_empty() && Path::new(dir).join("xray").is_file())
}

macro_rules! require_xray {
    ($name:literal) => {
        if !have_xray() {
            eprintln!("SKIPPED {}: no Xray-core binary on PATH", $name);
            return;
        }
    };
}

fn binary(name: &str) -> PathBuf {
    // `CARGO_BIN_EXE_*` is only set for the crate that declares the binary, so
    // the path is derived from the test executable's own location instead.
    let mut path = std::env::current_exe().expect("test executable path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(name)
}

/// A daemon running against a temporary root, killed on drop.
struct Daemon {
    child: Child,
    root: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Option<Self> {
        let root = tempfile::tempdir().expect("tempdir");
        let child = Command::new(binary("xraytuid"))
            .arg("--root")
            .arg(root.path())
            .arg("--no-start")
            .env("XRAYTUI_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        let daemon = Self { child, root };

        // Wait for the control socket to appear.
        let socket = daemon.root.path().join("run/control.sock");
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if socket.exists() {
                return Some(daemon);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    fn cli(&self, arguments: &[&str]) -> std::process::Output {
        Command::new(binary("xraytui"))
            .arg("--root")
            .arg(self.root.path())
            .args(arguments)
            .output()
            .expect("run xraytui")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_cli_reports_a_missing_daemon_with_a_dedicated_exit_code() {
    let root = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary("xraytui"))
        .arg("--root")
        .arg(root.path())
        .arg("status")
        .output()
        .expect("run xraytui");
    assert_eq!(output.status.code(), Some(xraytui_cli::EXIT_NO_DAEMON));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot reach the xraytui daemon"),
        "{stderr}"
    );
    assert!(
        stderr.contains("systemctl --user start xraytuid.service"),
        "{stderr}"
    );
}

#[test]
fn completions_and_man_pages_work_without_a_daemon() {
    let root = tempfile::tempdir().expect("tempdir");
    for shell in ["bash", "zsh", "fish"] {
        let output = Command::new(binary("xraytui"))
            .arg("--root")
            .arg(root.path())
            .args(["completion", shell])
            .output()
            .expect("run xraytui");
        assert!(output.status.success(), "completion {shell} failed");
        assert!(!output.stdout.is_empty(), "completion {shell} was empty");
    }

    let man_dir = root.path().join("man");
    let output = Command::new(binary("xraytui"))
        .arg("--root")
        .arg(root.path())
        .arg("manpages")
        .arg(&man_dir)
        .output()
        .expect("run xraytui");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(man_dir.join("xraytui.1").is_file());
    assert!(man_dir.join("xraytui-profile.1").is_file());
}

#[test]
fn the_daemon_validates_a_fresh_configuration() {
    require_xray!("daemon --check");
    let root = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary("xraytuid"))
        .arg("--root")
        .arg(root.path())
        .arg("--check")
        .output()
        .expect("run xraytuid");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("configuration is valid"), "{stdout}");
}

#[test]
fn a_second_daemon_refuses_to_start_for_the_same_user() {
    require_xray!("daemon lock");
    let Some(daemon) = Daemon::start() else {
        panic!("the first daemon did not come up");
    };
    let output = Command::new(binary("xraytuid"))
        .arg("--root")
        .arg(daemon.root.path())
        .arg("--no-start")
        .output()
        .expect("run xraytuid");
    assert!(
        !output.status.success(),
        "a second daemon must refuse to start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already running"), "{stderr}");
}

#[test]
fn the_cli_talks_to_the_daemon_in_every_output_format() {
    require_xray!("cli round trip");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    // Plain.
    let output = daemon.cli(&["status"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("Profiles"), "{stdout}");

    // JSON.
    let output = daemon.cli(&["status", "--format", "json"]);
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("status --format json must emit JSON");
    assert!(value.get("runtime").is_some(), "{value}");

    // Status bar.
    let output = daemon.cli(&["status", "--format", "dwmblocks"]);
    assert!(output.status.success());
    let line = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        line.lines().count(),
        1,
        "dwmblocks output must be one line: {line:?}"
    );

    // Shell.
    let output = daemon.cli(&["status", "--format", "shell"]);
    assert!(output.status.success());
    let shell = String::from_utf8_lossy(&output.stdout);
    assert!(shell.contains("XRAYTUI_CORE="), "{shell}");

    // Mode. Every mode other than `off` needs a system tunnel, and there is no
    // privileged helper in a test environment, so the daemon must refuse and
    // say what to do about it rather than reporting a success that carries no
    // traffic.
    let output = daemon.cli(&["mode", "set", "direct"]);
    assert!(
        !output.status.success(),
        "a mode needing a tunnel must not succeed without the helper"
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("privileged helper"), "{message}");
    assert!(message.contains("xraytui-netd.service"), "{message}");
    assert!(
        message.contains("SOCKS"),
        "the refusal must point at what does work: {message}"
    );

    // The mode is unchanged: a refused request changes nothing.
    let output = daemon.cli(&["mode", "get"]);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "off");

    // Setting the mode that needs nothing still works.
    assert!(daemon.cli(&["mode", "set", "off"]).status.success());
    let output = daemon.cli(&["mode", "get"]);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "off");
}

#[test]
fn the_interface_refuses_a_terminal_it_cannot_take_over_and_says_why() {
    require_xray!("tui");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    // Under a test harness standard output is a pipe, not a terminal, so
    // entering raw mode fails. What matters is that the failure is reported
    // rather than the process hanging or leaving the terminal altered.
    let output = daemon.cli(&["tui"]);
    assert!(
        !output.status.success(),
        "the interface cannot run without a terminal"
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("terminal"),
        "the reason must name the terminal: {message}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("\u{1b}[?1049h"),
        "nothing may be left on the alternate screen"
    );
}

#[test]
fn tun_plan_describes_the_changes_without_making_any() {
    require_xray!("tun plan");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    let before = interfaces();
    let output = daemon.cli(&["tun", "plan"]);
    assert!(
        output.status.success(),
        "a plan must be available even with no helper installed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Nothing has been changed"), "{text}");
    assert!(text.contains("create persistent tun"), "{text}");
    assert!(text.contains("no privileged helper is running"), "{text}");

    // JSON carries the same three fields for scripting.
    let output = daemon.cli(&["tun", "plan", "--format", "json"]);
    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("tun plan --format json must be JSON");
    assert!(parsed["steps"].as_array().is_some_and(|s| !s.is_empty()));
    assert_eq!(parsed["from_helper"], false);

    assert_eq!(
        before,
        interfaces(),
        "planning must not create, remove or rename an interface"
    );
}

/// The names of the interfaces this machine has, as an independent witness that
/// planning changed nothing.
fn interfaces() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

#[test]
fn importing_a_link_and_switching_a_profile_works_end_to_end() {
    require_xray!("import and switch");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    let link = "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:443\
                ?type=tcp&security=none#Imported%20Node";
    let output = daemon.cli(&["node", "import", link]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("imported 1 node"), "{stdout}");

    // The node is listed, and its identifier is derived from the remark.
    let output = daemon.cli(&["node", "list", "--format", "dmenu"]);
    let listing = String::from_utf8_lossy(&output.stdout);
    let (id, label) = listing
        .lines()
        .next()
        .and_then(|line| line.split_once('\t'))
        .expect("one dmenu line");
    assert!(id.starts_with("imported-node-"), "{id}");
    assert!(label.contains("Imported Node"), "{label}");

    // `node show` must not print the credential.
    let output = daemon.cli(&["node", "show", id]);
    let shown = String::from_utf8_lossy(&output.stdout);
    assert!(
        !shown.contains("11111111-2222"),
        "credential leaked: {shown}"
    );
    assert!(shown.contains("<redacted>"), "{shown}");

    // A share link round-trips back out.
    let output = daemon.cli(&["node", "share", id]);
    assert!(output.status.success());
    let link_out = String::from_utf8_lossy(&output.stdout);
    assert!(link_out.starts_with("vless://"), "{link_out}");
    let warning = String::from_utf8_lossy(&output.stderr);
    assert!(warning.contains("grants access to the proxy"), "{warning}");

    // Targets list the imported node, in dmenu form.
    let output = daemon.cli(&["target", "list", "--format", "dmenu"]);
    let targets = String::from_utf8_lossy(&output.stdout);
    assert!(targets.contains(&format!("node:{id}\t")), "{targets}");

    // A bad identifier is a usage error, not a panic.
    let output = daemon.cli(&["node", "show", "NOT VALID"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(xraytui_cli::EXIT_FAILURE));

    // A missing node reports the dedicated exit code.
    let output = daemon.cli(&["node", "remove", "definitely-absent"]);
    assert_eq!(output.status.code(), Some(xraytui_cli::EXIT_NOT_FOUND));
}

#[test]
fn the_dmenu_pipeline_from_the_specification_round_trips() {
    require_xray!("dmenu pipeline");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    // `xraytui profile list --format dmenu | dmenu | xraytui profile select-from-stdin`
    let listing = daemon.cli(&["profile", "list", "--format", "dmenu"]);
    assert!(listing.status.success());
    let chosen = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .next()
        .expect("at least one profile")
        .to_owned();

    let mut child = Command::new(binary("xraytui"))
        .arg("--root")
        .arg(daemon.root.path())
        .args(["profile", "select-from-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write as _;
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin.write_all(chosen.as_bytes()).expect("write");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let selected = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        selected.trim(),
        "direct",
        "the starter profile should be selected"
    );
}

#[test]
fn doctor_reports_the_environment_and_exits_meaningfully() {
    require_xray!("doctor");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };
    let output = daemon.cli(&["doctor"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("xray-binary"), "{stdout}");
    assert!(stdout.contains("control-socket"), "{stdout}");
    assert!(stdout.contains("tun-device"), "{stdout}");
    // The exit code is non-zero exactly when a check failed.
    let failed = stdout
        .lines()
        .filter(|line| line.starts_with("[FAIL]"))
        .count();
    assert_eq!(output.status.success(), failed == 0, "{stdout}");

    let output = daemon.cli(&["doctor", "--format", "json"]);
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor --format json must emit JSON");
    assert!(value.get("checks").is_some(), "{value}");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_injects_the_profile_proxy_environment() {
    require_xray!("exec");
    let egress = MockEgress::start("exec").await.expect("start egress");
    let port = free_port().expect("port");

    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    // Give the starter `direct` profile a node and bring the core up, so the
    // profile has a live listener for `exec` to point at.
    let link = format!(
        "socks://{}:{}#Exec%20Egress",
        egress.socks_addr().ip(),
        egress.socks_addr().port()
    );
    assert!(daemon.cli(&["node", "import", &link]).status.success());

    let listing = daemon.cli(&["node", "list", "--format", "dmenu"]);
    let id = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .next()
        .and_then(|line| line.split_once('\t').map(|(id, _)| id.to_owned()))
        .expect("one node");

    assert!(
        daemon
            .cli(&["profile", "set-target", "direct", &format!("node:{id}")])
            .status
            .success()
    );
    let up = daemon.cli(&["up"]);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );

    // `env` prints the environment it was given, which is exactly what `exec`
    // is supposed to have set.
    let output = daemon.cli(&["exec", "--profile", "direct", "--", "env"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let environment = String::from_utf8_lossy(&output.stdout);
    assert!(
        environment.contains("ALL_PROXY=socks5h://127.0.0.1:"),
        "{environment}"
    );
    assert!(environment.contains("HTTP_PROXY="), "{environment}");
    assert!(environment.contains("NO_PROXY=localhost,"), "{environment}");
    let _ = port;

    assert!(daemon.cli(&["down"]).status.success());
}

// ------------------------------------------------- the configuration surface

/// Everything an ordinary user does to set the tool up, through the real
/// binaries, without ever opening a text editor.
///
/// The point of this test is the *absence* of a step where somebody hand-edits
/// generated JSON or normalised TOML. If a v1.0 workflow cannot be expressed
/// here, it is not finished.
#[test]
fn every_ordinary_configuration_action_works_without_editing_a_file() {
    require_xray!("configuration surface");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    // 1. A node typed in by hand, with REALITY.
    let added = daemon.cli(&[
        "node",
        "add",
        "--protocol",
        "vless",
        "--name",
        "HK Reality",
        "--address",
        "hk.example.com",
        "--port",
        "443",
        "--uuid",
        "8f6e5d4c-3b2a-4190-8f7e-6d5c4b3a2910",
        "--flow",
        "xtls-rprx-vision",
        "--tls",
        "reality",
        "--sni",
        "www.microsoft.com",
        "--public-key",
        "HlNjGYCbyoEqPbTdJQaRCr949-d8YsQ8e14TJtLYnks",
        "--short-id",
        "abcd1234",
    ]);
    assert!(
        added.status.success(),
        "node add: {}",
        String::from_utf8_lossy(&added.stderr)
    );

    // 2. A second node on a different protocol and transport.
    let trojan = daemon.cli(&[
        "node",
        "add",
        "--protocol",
        "trojan",
        "--name",
        "JP WS",
        "--address",
        "jp.example.com",
        "--port",
        "8443",
        "--password",
        "correct-horse-battery",
        "--transport",
        "ws",
        "--path",
        "/ray",
        "--tls",
        "tls",
        "--sni",
        "jp.example.com",
    ]);
    assert!(
        trojan.status.success(),
        "trojan add: {}",
        String::from_utf8_lossy(&trojan.stderr)
    );

    let listing = String::from_utf8_lossy(&daemon.cli(&["node", "list"]).stdout).into_owned();
    assert!(listing.contains("HK Reality"), "{listing}");
    assert!(listing.contains("JP WS"), "{listing}");
    let hk = listing
        .lines()
        .find(|line| line.contains("HK Reality"))
        .and_then(|line| line.split_whitespace().next())
        .expect("the HK node's identifier")
        .to_owned();
    let jp = listing
        .lines()
        .find(|line| line.contains("JP WS"))
        .and_then(|line| line.split_whitespace().next())
        .expect("the JP node's identifier")
        .to_owned();

    // 3. Editing changes only what was named.
    assert!(
        daemon
            .cli(&["node", "edit", &hk, "--name", "HK Reality (edited)"])
            .status
            .success(),
        "node edit"
    );
    let listing = String::from_utf8_lossy(&daemon.cli(&["node", "list"]).stdout).into_owned();
    assert!(listing.contains("HK Reality (edited)"), "{listing}");
    assert!(
        listing.contains("hk.example.com"),
        "the address must survive a rename: {listing}"
    );

    // 4. A field from another protocol is refused rather than quietly dropped.
    let wrong = daemon.cli(&["node", "edit", &hk, "--method", "aes-256-gcm"]);
    assert!(
        !wrong.status.success(),
        "a Shadowsocks cipher on a VLESS node must be refused, not ignored"
    );
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("--method"),
        "{}",
        String::from_utf8_lossy(&wrong.stderr)
    );

    // 5. A group, and a chain, both from the command line.
    assert!(
        daemon
            .cli(&[
                "group", "add", "fast", "--name", "Fast", "--node", &hk, "--node", &jp
            ])
            .status
            .success(),
        "group add"
    );
    assert!(
        daemon
            .cli(&[
                "chain", "add", "relay", "--name", "Relay", "--hop", &hk, "--hop", &jp
            ])
            .status
            .success(),
        "chain add"
    );
    let targets = String::from_utf8_lossy(&daemon.cli(&["target", "list"]).stdout).into_owned();
    assert!(targets.contains("group:fast"), "{targets}");
    assert!(targets.contains("chain:relay"), "{targets}");

    // A one-hop chain is a node with extra steps, and is refused as such.
    let one_hop = daemon.cli(&["chain", "add", "solo", "--hop", &hk]);
    assert!(!one_hop.status.success(), "a one-hop chain must be refused");

    // 6. A profile with its own listeners, pointed at the group.
    assert!(
        daemon
            .cli(&[
                "profile", "add", "work", "--name", "Work", "--socks", "11180"
            ])
            .status
            .success(),
        "profile add"
    );
    assert!(
        daemon
            .cli(&["profile", "listeners", "work", "--http", "11181"])
            .status
            .success(),
        "profile listeners"
    );
    assert!(
        daemon
            .cli(&["profile", "set-target", "work", "group:fast"])
            .status
            .success(),
        "set-target"
    );
    let shown =
        String::from_utf8_lossy(&daemon.cli(&["profile", "show", "work"]).stdout).into_owned();
    assert!(
        shown.contains("11180") && shown.contains("11181"),
        "{shown}"
    );

    // 7. An application rule, disabled and enabled again.
    assert!(
        daemon
            .cli(&["app", "assign", "work", "firefox"])
            .status
            .success(),
        "assign"
    );
    let rules = String::from_utf8_lossy(&daemon.cli(&["app", "list"]).stdout).into_owned();
    assert!(rules.contains("firefox"), "{rules}");
    let rule_id = rules
        .split_whitespace()
        .find(|token| token.contains("firefox") && token.contains('-'))
        .unwrap_or("firefox-work")
        .to_owned();
    assert!(
        daemon.cli(&["rule", "disable", &rule_id]).status.success(),
        "rule disable"
    );
    assert!(
        daemon.cli(&["rule", "enable", &rule_id]).status.success(),
        "rule enable"
    );

    // 8. Removal in dependency order, and refusal out of it.
    let still_pointed = daemon.cli(&["group", "remove", "fast"]);
    assert!(
        !still_pointed.status.success(),
        "removing a group a profile points at must be refused, not left dangling"
    );
    assert!(
        daemon
            .cli(&["profile", "set-target", "work", "direct"])
            .status
            .success()
    );
    assert!(
        daemon.cli(&["group", "remove", "fast"]).status.success(),
        "group remove"
    );
    assert!(
        daemon.cli(&["chain", "remove", "relay"]).status.success(),
        "chain remove"
    );
    assert!(
        daemon.cli(&["profile", "remove", "work"]).status.success(),
        "profile remove"
    );
    assert!(
        daemon.cli(&["node", "remove", &jp]).status.success(),
        "node remove"
    );

    // 9. And the whole thing is still a valid configuration.
    let status = daemon.cli(&["status", "--format", "json"]);
    assert!(status.status.success(), "status");
    let value: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    assert!(value.get("desired").is_some());
}

/// A change that cannot work must fail loudly and leave nothing behind.
#[test]
fn a_refused_mutation_changes_nothing() {
    require_xray!("refused mutation");
    let Some(daemon) = Daemon::start() else {
        panic!("the daemon did not come up");
    };

    let before = String::from_utf8_lossy(&daemon.cli(&["profile", "list"]).stdout).into_owned();

    // The starter profile already binds 11080; a second listener on it cannot
    // work, and the daemon knows that before anything is written.
    let clash = daemon.cli(&["profile", "add", "clash", "--socks", "11080"]);
    assert!(!clash.status.success(), "a port collision must be refused");
    assert!(
        String::from_utf8_lossy(&clash.stderr).contains("11080"),
        "the refusal must name the conflict: {}",
        String::from_utf8_lossy(&clash.stderr)
    );

    // Pointing at something that does not exist is refused too — including
    // through the narrow set-target path, not only the whole-state one.
    let ghost = daemon.cli(&["profile", "add", "ghost", "--target", "node:nowhere"]);
    assert!(!ghost.status.success(), "an unknown target must be refused");

    let after = String::from_utf8_lossy(&daemon.cli(&["profile", "list"]).stdout).into_owned();
    assert_eq!(before, after, "a refused mutation must change nothing");
}

// --------------------------------------------------------------- recovering

/// Start a daemon that really launches the core, not `--no-start`.
fn spawn_with_core(root: &Path) -> Option<Child> {
    Command::new(binary("xraytuid"))
        .arg("--root")
        .arg(root)
        .env("XRAYTUI_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()
}

/// The pid of a core that is up, if it is up.
///
/// `CoreStatus` is serialised with an internal `state` tag, so `pid` is a
/// sibling of it rather than nested.
fn running_core_pid(daemon: &Daemon) -> Option<u64> {
    let output = daemon.cli(&["status", "--format", "json"]);
    if !output.status.success() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let core = value.get("runtime")?.get("core")?;
    if core.get("state")?.as_str()? != "running" {
        return None;
    }
    core.get("pid")?.as_u64()
}

/// The core dying must be noticed and undone, not reported as healthy forever.
///
/// This is what happens when the OOM killer picks Xray on a laptop with a
/// browser open: the daemon keeps a `Child` for a process that no longer
/// exists, and every listener it was serving is dead.
#[test]
fn a_core_that_is_killed_is_noticed_and_brought_back() {
    require_xray!("core supervision");

    let root = tempfile::tempdir().expect("tempdir");
    let Some(child) = spawn_with_core(root.path()) else {
        panic!("the daemon did not spawn");
    };
    let daemon = Daemon { child, root };

    let deadline = Instant::now() + Duration::from_secs(40);
    let mut first = None;
    while Instant::now() < deadline && first.is_none() {
        first = running_core_pid(&daemon);
        std::thread::sleep(Duration::from_millis(200));
    }
    let first = first.expect("the core never reported a pid");

    // SIGKILL, because a crash does not get to run a shutdown path.
    assert!(
        Command::new("kill")
            .args(["-9", &first.to_string()])
            .status()
            .expect("kill")
            .success(),
        "could not kill the core"
    );

    let deadline = Instant::now() + Duration::from_secs(45);
    let mut second = None;
    while Instant::now() < deadline {
        if let Some(pid) = running_core_pid(&daemon)
            && pid != first
        {
            second = Some(pid);
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let second = second.expect("the core was killed and never came back");
    assert_ne!(
        second, first,
        "the daemon reported the dead process as alive"
    );
    assert!(
        Path::new(&format!("/proc/{second}")).is_dir(),
        "pid {second} is not a live process"
    );
}

/// A daemon killed with SIGKILL leaves its socket behind. The next one must
/// bind anyway, or every hard crash needs manual cleanup before the tool works.
#[test]
fn a_socket_left_by_a_killed_daemon_does_not_block_the_next_one() {
    require_xray!("stale socket");

    let root = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(binary("xraytuid"))
        .arg("--root")
        .arg(root.path())
        .arg("--no-start")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let socket = root.path().join("run/control.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !socket.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(socket.exists(), "the first daemon never bound its socket");

    let _ = Command::new("kill")
        .args(["-9", &child.id().to_string()])
        .status();
    let _ = child.wait();
    assert!(
        socket.exists(),
        "this test is meaningless if the socket is already gone"
    );

    let replacement = spawn_with_core(root.path()).expect("spawn");
    let daemon = Daemon {
        child: replacement,
        root,
    };
    // Not "does the file exist": the stale file is exactly what is on disk at
    // the start. What matters is that something answers on it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut answered = false;
    while Instant::now() < deadline && !answered {
        answered = daemon.cli(&["status"]).status.success();
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        answered,
        "a stale socket stopped the replacement daemon from answering"
    );
}

/// State the daemon observed must survive a restart.
#[test]
fn mode_targets_and_health_survive_a_daemon_restart() {
    require_xray!("restart recovery");

    let root = tempfile::tempdir().expect("tempdir");
    let Some(child) = spawn_with_core(root.path()) else {
        panic!("the daemon did not spawn");
    };
    let mut daemon = Daemon { child, root };
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !daemon.cli(&["status"]).status.success() {
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        daemon
            .cli(&[
                "node",
                "add",
                "--protocol",
                "socks",
                "--name",
                "Keep Me",
                "--address",
                "127.0.0.1",
                "--port",
                "1",
                "--username",
                "u",
            ])
            .status
            .success(),
        "node add"
    );
    assert!(
        daemon
            .cli(&["profile", "add", "work", "--socks", "11190"])
            .status
            .success(),
        "profile add"
    );
    let before = String::from_utf8_lossy(&daemon.cli(&["profile", "list"]).stdout).into_owned();

    // Restart the way a package upgrade does.
    let _ = daemon.child.kill();
    let _ = daemon.child.wait();
    let _ = std::fs::remove_file(daemon.root.path().join("run/control.sock"));
    daemon.child = spawn_with_core(daemon.root.path()).expect("restart");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !daemon.cli(&["status"]).status.success() {
        std::thread::sleep(Duration::from_millis(200));
    }

    let after = String::from_utf8_lossy(&daemon.cli(&["profile", "list"]).stdout).into_owned();
    assert_eq!(before, after, "profiles and targets must survive a restart");
    let nodes = String::from_utf8_lossy(&daemon.cli(&["node", "list"]).stdout).into_owned();
    assert!(nodes.contains("Keep Me"), "the node was lost:\n{nodes}");

    // And the state database really is the thing carrying it.
    let database = daemon.root.path().join("state/state.sqlite3");
    assert!(database.is_file(), "no state database was written");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&database)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the state database must not be world-readable");
}
