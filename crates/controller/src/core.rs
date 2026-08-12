//! Discovery and supervision of the external Xray-core process.
//!
//! The start sequence is the part worth reading. Passing `xray run -test` proves
//! only that the *configuration* is well formed; it says nothing about whether
//! the ports are free, the TUN device is attachable, or the commander came up.
//! So a generation is only marked healthy after the process is running, the API
//! answers, the listeners accept a connection, and every persisted selector
//! override has been re-applied.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use xraytui_domain::GenerationId;
use xraytui_xray_api::{ApiClient, ApiEndpoint, Capabilities};

use crate::ControllerError;

/// Lowest Xray release whose commander has the routing API xraytui needs.
///
/// Below 1.8.0 there is no `ruleTag`, no `RemoveRule` and no `ListRule`, so a
/// generation could not be reconciled against a live core.
pub const MINIMUM_XRAY_VERSION: Version = Version { major: 1, minor: 8, patch: 0 };

/// A parsed `major.minor.patch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Major component.
    pub major: u32,
    /// Minor component.
    pub minor: u32,
    /// Patch component.
    pub patch: u32,
}

impl Version {
    /// Parse the first `x.y.z` found in a version banner.
    ///
    /// Xray prints `Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go…)`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        for token in text.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
            let cleaned = token.trim_start_matches('v');
            let mut parts = cleaned.split('.');
            let major = parts.next()?.parse::<u32>();
            let Ok(major) = major else { continue };
            let Some(Ok(minor)) = parts.next().map(str::parse::<u32>) else {
                continue;
            };
            let patch = parts
                .next()
                .map(|p| p.trim_end_matches(|c: char| !c.is_ascii_digit()))
                .and_then(|p| p.parse::<u32>().ok())
                .unwrap_or(0);
            return Some(Self { major, minor, patch });
        }
        None
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What was learned about an Xray binary before it was ever run for real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreInfo {
    /// Absolute path to the binary.
    pub binary: PathBuf,
    /// Version parsed from `xray version`.
    pub version: Version,
    /// The full first line of the banner, for display.
    pub banner: String,
    /// Directory holding `geoip.dat`/`geosite.dat`, when one was found.
    pub asset_dir: Option<PathBuf>,
    /// Whether geodata files are present; `geosite:` rules fail without them.
    pub has_geodata: bool,
}

impl CoreInfo {
    /// Whether this binary is new enough to drive.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.version >= MINIMUM_XRAY_VERSION
    }
}

/// Locate an Xray binary.
///
/// `configured` wins if it is set; otherwise `PATH` is searched. The path is
/// canonicalised and checked to be a regular executable file, so a later `exec`
/// cannot be redirected by a symlink swapped in between the check and the spawn
/// — the resolved path is what gets executed.
///
/// # Errors
/// Returns [`ControllerError::CoreNotFound`] when nothing usable is found.
pub fn discover_binary(configured: &str) -> Result<PathBuf, ControllerError> {
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        return canonical_executable(&path)
            .ok_or_else(|| ControllerError::CoreNotFound { searched: configured.to_owned() });
    }
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join("xray");
        if let Some(resolved) = canonical_executable(&candidate) {
            return Ok(resolved);
        }
    }
    Err(ControllerError::CoreNotFound {
        searched: format!("PATH ({} entries)", path_var.split(':').count()),
    })
}

fn canonical_executable(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let resolved = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&resolved).ok()?;
    if !metadata.is_file() {
        return None;
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return None;
    }
    Some(resolved)
}

/// Find the geodata directory Xray would use.
#[must_use]
pub fn discover_asset_dir(configured: Option<&Path>, binary: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = configured {
        candidates.push(dir.to_path_buf());
    }
    if let Some(dir) = std::env::var_os("XRAY_LOCATION_ASSET") {
        candidates.push(PathBuf::from(dir));
    }
    if let Some(parent) = binary.parent() {
        candidates.push(parent.to_path_buf());
    }
    candidates.extend(
        [
            "/usr/share/xray",
            "/usr/local/share/xray",
            "/usr/lib/xray",
            "/opt/xray",
        ]
        .into_iter()
        .map(PathBuf::from),
    );
    candidates.into_iter().find(|dir| dir.join("geoip.dat").is_file())
}

/// Run `xray version` and record what it says.
///
/// # Errors
/// Propagates spawn failures and an unparseable banner.
pub async fn probe_binary(
    binary: &Path,
    configured_asset_dir: Option<&Path>,
) -> Result<CoreInfo, ControllerError> {
    let output = Command::new(binary)
        .arg("version")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|source| ControllerError::CoreSpawn {
            binary: binary.display().to_string(),
            source,
        })?;
    let banner = String::from_utf8_lossy(&output.stdout);
    let first_line = banner.lines().next().unwrap_or_default().trim().to_owned();
    let version = Version::parse(&first_line).ok_or_else(|| ControllerError::CoreUnusable {
        detail: format!("could not parse a version from {first_line:?}"),
    })?;
    let asset_dir = discover_asset_dir(configured_asset_dir, binary);
    let has_geodata = asset_dir
        .as_ref()
        .is_some_and(|dir| dir.join("geoip.dat").is_file() && dir.join("geosite.dat").is_file());
    Ok(CoreInfo {
        binary: binary.to_path_buf(),
        version,
        banner: first_line,
        asset_dir,
        has_geodata,
    })
}

/// Validate a configuration with `xray run -test`.
///
/// The configuration is written to a private file inside `dir` first; it is never
/// passed on the command line, so it cannot appear in `ps` output.
///
/// # Errors
/// Returns [`ControllerError::ConfigRejected`] with Xray's own message.
pub async fn validate_config(
    info: &CoreInfo,
    config_json: &str,
    path: &Path,
) -> Result<(), ControllerError> {
    xraytui_config::write_private_atomic(path, config_json.as_bytes())
        .map_err(|source| ControllerError::Config(Box::new(source)))?;

    let mut command = Command::new(&info.binary);
    command
        .arg("run")
        .arg("-test")
        .arg("-config")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_environment(&mut command, info);

    let output = command.output().await.map_err(|source| ControllerError::CoreSpawn {
        binary: info.binary.display().to_string(),
        source,
    })?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
        .filter(|line| line.contains("Failed") || line.contains("error") || line.contains("invalid"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("; ");
    Err(ControllerError::ConfigRejected {
        detail: if detail.is_empty() {
            format!("xray exited with status {}", output.status)
        } else {
            detail
        },
    })
}

/// Environment handed to the core.
///
/// Only `XRAY_LOCATION_ASSET` is set. Credentials never travel in the
/// environment — they are in the 0600 configuration file the core reads.
fn apply_environment(command: &mut Command, info: &CoreInfo) {
    command.env_clear();
    if let Some(dir) = &info.asset_dir {
        command.env("XRAY_LOCATION_ASSET", dir);
    }
    // A minimal, predictable environment. `PATH` is not needed by the core, and
    // omitting it removes one way for a hostile environment to influence it.
    command.env("HOME", std::env::var_os("HOME").unwrap_or_default());
}

/// A running Xray process together with the generation it was started for.
#[derive(Debug)]
pub struct RunningCore {
    child: Child,
    generation: GenerationId,
    endpoint: ApiEndpoint,
    version: Version,
    started_unix: i64,
}

impl RunningCore {
    /// Process id, or `None` once it has been reaped.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Generation this process was started for.
    #[must_use]
    pub fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Where its commander listens.
    #[must_use]
    pub fn endpoint(&self) -> &ApiEndpoint {
        &self.endpoint
    }

    /// Version reported by the binary.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Unix seconds at which the process was spawned.
    #[must_use]
    pub fn started_unix(&self) -> i64 {
        self.started_unix
    }

    /// Whether the process has exited, without blocking.
    ///
    /// # Errors
    /// Propagates the `wait` failure.
    pub fn has_exited(&mut self) -> Result<Option<std::process::ExitStatus>, std::io::Error> {
        self.child.try_wait()
    }

    /// Wait for the process to exit.
    ///
    /// # Errors
    /// Propagates the `wait` failure.
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, std::io::Error> {
        self.child.wait().await
    }

    /// Ask the process to exit, escalating to `SIGKILL` after `grace`.
    ///
    /// Returns the exit status when one could be collected.
    pub async fn shutdown(&mut self, grace: Duration) -> Option<std::process::ExitStatus> {
        if let Some(pid) = self.child.id() {
            // SIGTERM lets the core close listeners and flush logs. `start_kill`
            // would send SIGKILL, which loses that.
            let raw = i32::try_from(pid).unwrap_or(0);
            if raw > 0 {
                // Safety of the value is guaranteed by `Pid::from_raw` rejecting
                // non-positive ids; a reaped pid simply yields ESRCH.
                if let Ok(pid) = rustix::process::Pid::from_raw(raw).ok_or(()) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
                }
            }
        }
        match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(Ok(status)) => Some(status),
            Ok(Err(_)) => None,
            Err(_) => {
                let _ = self.child.start_kill();
                self.child.wait().await.ok()
            }
        }
    }
}

/// How to start a core.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// Generation being started.
    pub generation: GenerationId,
    /// Path the generated configuration was written to.
    pub config_path: PathBuf,
    /// Where the commander will listen.
    pub endpoint: ApiEndpoint,
    /// Where to append the core's own log output.
    pub log_path: Option<PathBuf>,
}

/// Spawn the core.
///
/// The configuration must already have been validated and written; this function
/// deliberately does not accept JSON, so there is exactly one place a
/// configuration reaches disk.
///
/// # Errors
/// Propagates spawn failures.
pub async fn spawn(info: &CoreInfo, spec: &LaunchSpec) -> Result<RunningCore, ControllerError> {
    let mut command = Command::new(&info.binary);
    command
        .arg("run")
        .arg("-config")
        .arg(&spec.config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Give the core its own process group so a Ctrl-C in the terminal that
        // launched the daemon does not race the daemon's own shutdown handling.
        .process_group(0);
    apply_environment(&mut command, info);

    let mut child = command.spawn().map_err(|source| ControllerError::CoreSpawn {
        binary: info.binary.display().to_string(),
        source,
    })?;

    // Drain the core's output into the log so a full pipe buffer can never block
    // it. Lines are also kept in a bounded ring for the Logs page.
    if let Some(stdout) = child.stdout.take() {
        spawn_log_pump(stdout, spec.log_path.clone(), "xray");
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_pump(stderr, spec.log_path.clone(), "xray");
    }

    Ok(RunningCore {
        child,
        generation: spec.generation,
        endpoint: spec.endpoint.clone(),
        version: info.version,
        started_unix: unix_now(),
    })
}

fn spawn_log_pump<R>(reader: R, path: Option<PathBuf>, target: &'static str)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        let mut file = match &path {
            Some(path) => tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .ok(),
            None => None,
        };
        while let Ok(Some(line)) = lines.next_line().await {
            // The core's own log can echo configuration values, so it is
            // redacted before it reaches either destination.
            let safe = xraytui_secrets::redact_text(&line);
            tracing::debug!(target: "xraytui::core", core = target, "{safe}");
            if let Some(file) = file.as_mut() {
                use tokio::io::AsyncWriteExt;
                let _ = file.write_all(safe.as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
        }
    });
}

/// Everything that has to be true before a generation counts as healthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthGate {
    /// Deadline for the API to start answering.
    pub api_deadline: Duration,
    /// Listener addresses that must accept a TCP connection.
    pub listeners: Vec<std::net::SocketAddr>,
    /// Deadline for each listener check.
    pub listener_timeout: Duration,
    /// Selector overrides to re-apply, in order.
    pub overrides: Vec<(String, String)>,
}

/// The result of running the health gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    /// Detected commander capabilities.
    pub capabilities: Capabilities,
    /// Listeners that did not accept a connection.
    pub failed_listeners: Vec<std::net::SocketAddr>,
    /// Overrides that the core rejected.
    pub failed_overrides: Vec<(String, String)>,
    /// Outbound tags the core reports, for ownership reconciliation.
    pub outbound_tags: Vec<String>,
}

impl HealthReport {
    /// Whether the generation may be marked healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.capabilities.is_sufficient()
            && self.failed_listeners.is_empty()
            && self.failed_overrides.is_empty()
    }

    /// A one-line explanation for the dashboard.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.is_healthy() {
            return "healthy".to_owned();
        }
        let mut parts = Vec::new();
        let missing = self.capabilities.missing();
        if !missing.is_empty() {
            parts.push(format!("missing API: {}", missing.join(", ")));
        }
        if !self.failed_listeners.is_empty() {
            parts.push(format!(
                "listeners not accepting: {}",
                self.failed_listeners
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !self.failed_overrides.is_empty() {
            parts.push(format!(
                "profile selectors not applied: {}",
                self.failed_overrides
                    .iter()
                    .map(|(balancer, _)| balancer.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        parts.join("; ")
    }
}

/// Wait for the core to be ready, then apply the health gate.
///
/// This is where "passing `-test` does not mean it runs" is handled: the API has
/// to answer, the listeners have to accept, and every override has to stick.
///
/// # Errors
/// Returns [`ControllerError::Api`] if the commander never answers.
pub async fn run_health_gate(
    endpoint: &ApiEndpoint,
    gate: &HealthGate,
) -> Result<(ApiClient, HealthReport), ControllerError> {
    let mut client =
        ApiClient::connect_ready(endpoint, gate.api_deadline, Duration::from_millis(100))
            .await
            .map_err(|source| ControllerError::Api(Box::new(source)))?;

    let probe_balancer = gate.overrides.first().map(|(balancer, _)| balancer.clone());
    let capabilities = Capabilities::probe(&mut client, probe_balancer.as_deref()).await;

    let mut failed_listeners = Vec::new();
    for address in &gate.listeners {
        if !listener_accepts(*address, gate.listener_timeout).await {
            failed_listeners.push(*address);
        }
    }

    // Overrides are process state: Xray forgets them on restart, so they are
    // re-applied here on every start. Without this a restarted core would route
    // by the compiled selector rather than by what the user last chose.
    let mut failed_overrides = Vec::new();
    for (balancer, target) in &gate.overrides {
        if client.override_balancer(balancer, target).await.is_err() {
            failed_overrides.push((balancer.clone(), target.clone()));
        }
    }

    let outbound_tags = client.list_outbound_tags().await.unwrap_or_default();

    Ok((
        client,
        HealthReport { capabilities, failed_listeners, failed_overrides, outbound_tags },
    ))
}

async fn listener_accepts(address: std::net::SocketAddr, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await,
        Ok(Ok(_))
    )
}

/// Restart backoff with a ceiling and a failure budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartPolicy {
    /// First delay.
    pub min: Duration,
    /// Longest delay.
    pub max: Duration,
    /// Consecutive failures after which the controller gives up.
    pub budget: u32,
}

impl RestartPolicy {
    /// Delay before attempt number `attempt` (1-based).
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(16);
        let scaled = self.min.saturating_mul(1_u32 << shift);
        scaled.min(self.max)
    }

    /// Whether another attempt is allowed.
    #[must_use]
    pub fn may_retry(&self, attempt: u32) -> bool {
        attempt < self.budget
    }
}

/// Unix seconds, saturating rather than panicking before the epoch.
#[must_use]
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Statistics counter names Xray uses, so callers do not hard-code them.
#[must_use]
pub fn outbound_traffic_counters(tag: &str) -> BTreeMap<&'static str, String> {
    let mut names = BTreeMap::new();
    names.insert("uplink", format!("outbound>>>{tag}>>>traffic>>>uplink"));
    names.insert("downlink", format!("outbound>>>{tag}>>>traffic>>>downlink"));
    names
}

/// Statistics counter names for an inbound.
#[must_use]
pub fn inbound_traffic_counters(tag: &str) -> BTreeMap<&'static str, String> {
    let mut names = BTreeMap::new();
    names.insert("uplink", format!("inbound>>>{tag}>>>traffic>>>uplink"));
    names.insert("downlink", format!("inbound>>>{tag}>>>traffic>>>downlink"));
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parses_the_real_banner() {
        let banner = "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)";
        assert_eq!(Version::parse(banner), Some(Version { major: 26, minor: 3, patch: 27 }));
    }

    #[test]
    fn version_parses_tolerantly() {
        assert_eq!(Version::parse("Xray v1.8.4 x"), Some(Version { major: 1, minor: 8, patch: 4 }));
        assert_eq!(Version::parse("Xray 1.8 x"), Some(Version { major: 1, minor: 8, patch: 0 }));
        assert_eq!(Version::parse("no version here"), None);
        assert_eq!(Version::parse(""), None);
    }

    #[test]
    fn version_ordering_drives_the_minimum() {
        assert!(Version { major: 26, minor: 3, patch: 27 } >= MINIMUM_XRAY_VERSION);
        assert!(Version { major: 1, minor: 8, patch: 0 } >= MINIMUM_XRAY_VERSION);
        assert!(Version { major: 1, minor: 7, patch: 9 } < MINIMUM_XRAY_VERSION);
        // Numeric, not lexical: 26.3.9 must sort below 26.3.27.
        assert!(Version { major: 26, minor: 3, patch: 9 } < Version { major: 26, minor: 3, patch: 27 });
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let policy = RestartPolicy {
            min: Duration::from_millis(500),
            max: Duration::from_secs(60),
            budget: 8,
        };
        assert_eq!(policy.delay(1), Duration::from_millis(500));
        assert_eq!(policy.delay(2), Duration::from_secs(1));
        assert_eq!(policy.delay(3), Duration::from_secs(2));
        assert_eq!(policy.delay(20), Duration::from_secs(60));
        assert!(policy.may_retry(7));
        assert!(!policy.may_retry(8));
    }

    #[test]
    fn missing_binaries_are_reported_not_guessed() {
        let error = discover_binary("/nonexistent/xray").expect_err("must fail");
        assert!(matches!(error, ControllerError::CoreNotFound { .. }), "{error:?}");
    }

    #[test]
    fn a_directory_is_not_an_executable() {
        assert!(canonical_executable(Path::new("/tmp")).is_none());
    }

    #[test]
    fn health_report_explains_each_failure_kind() {
        let capabilities = Capabilities {
            handler: true,
            routing: true,
            balancer_override: true,
            rule_management: true,
            test_route: true,
            stats: true,
            logger: true,
        };
        let healthy = HealthReport {
            capabilities,
            failed_listeners: vec![],
            failed_overrides: vec![],
            outbound_tags: vec![],
        };
        assert!(healthy.is_healthy());
        assert_eq!(healthy.describe(), "healthy");

        let unhealthy = HealthReport {
            capabilities,
            failed_listeners: vec!["127.0.0.1:1080".parse().expect("addr")],
            failed_overrides: vec![("profile/web/selector".into(), "node/a/out".into())],
            outbound_tags: vec![],
        };
        assert!(!unhealthy.is_healthy());
        let description = unhealthy.describe();
        assert!(description.contains("127.0.0.1:1080"), "{description}");
        assert!(description.contains("profile/web/selector"), "{description}");
    }

    #[test]
    fn counter_names_match_xrays_format() {
        let counters = outbound_traffic_counters("node/hk-01/out");
        assert_eq!(
            counters.get("uplink").map(String::as_str),
            Some("outbound>>>node/hk-01/out>>>traffic>>>uplink")
        );
        let counters = inbound_traffic_counters("inbound/profile/web/socks");
        assert_eq!(
            counters.get("downlink").map(String::as_str),
            Some("inbound>>>inbound/profile/web/socks>>>traffic>>>downlink")
        );
    }

    #[tokio::test]
    async fn listener_check_fails_for_a_closed_port() {
        assert!(
            !listener_accepts("127.0.0.1:1".parse().expect("addr"), Duration::from_millis(200)).await
        );
    }

    #[tokio::test]
    async fn listener_check_succeeds_for_an_open_port() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("addr");
        assert!(listener_accepts(address, Duration::from_millis(500)).await);
    }
}
