//! Observed runtime state: core status, health, statistics, network state.
//!
//! Nothing here is user-editable. It is what the daemon *sees*, as opposed to the
//! desired state in [`crate::state`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{ChainId, GenerationId, GroupId, NodeId, ProfileId};
use crate::policy::{SystemMode, Target};

/// Lifecycle of the supervised Xray process.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum CoreStatus {
    /// Not running and not wanted.
    #[default]
    Stopped,
    /// A start is in progress.
    Starting {
        /// Which generation is being brought up.
        generation: GenerationId,
    },
    /// Running and past all health gates.
    Running {
        /// Live generation.
        generation: GenerationId,
        /// Process id.
        pid: u32,
        /// Xray version string.
        version: String,
        /// Unix seconds when the process started.
        since_unix: i64,
    },
    /// Running but a health gate has not been satisfied.
    Degraded {
        /// Live generation.
        generation: GenerationId,
        /// Process id.
        pid: u32,
        /// What is unhealthy.
        detail: String,
    },
    /// Exited unexpectedly; a restart is scheduled.
    Restarting {
        /// Consecutive failure count driving the backoff.
        attempt: u32,
        /// Milliseconds until the next attempt.
        backoff_ms: u64,
        /// Why the previous attempt ended.
        reason: String,
    },
    /// Failed permanently; manual intervention needed.
    Failed {
        /// Bounded, credential-free explanation.
        reason: String,
    },
}

impl CoreStatus {
    /// Whether the data plane can currently carry traffic.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Running { .. } | Self::Degraded { .. })
    }

    /// Live generation, if any.
    #[must_use]
    pub fn generation(&self) -> Option<GenerationId> {
        match self {
            Self::Starting { generation }
            | Self::Running { generation, .. }
            | Self::Degraded { generation, .. } => Some(*generation),
            _ => None,
        }
    }

    /// One-word status for the dashboard.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting { .. } => "starting",
            Self::Running { .. } => "running",
            Self::Degraded { .. } => "degraded",
            Self::Restarting { .. } => "restarting",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Result of one connectivity probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// When the probe finished, unix milliseconds.
    pub at_unix_ms: i64,
    /// Round-trip milliseconds on success.
    pub latency_ms: Option<u32>,
    /// Outcome.
    pub outcome: ProbeOutcome,
    /// Which probe was run.
    pub kind: ProbeKind,
}

/// What a probe measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeKind {
    /// TCP connect through the outbound.
    TcpConnect,
    /// TCP connect plus TLS handshake.
    TlsHandshake,
    /// Small HTTP request through the outbound.
    HttpRequest,
    /// DNS resolution through the profile.
    DnsResolve,
    /// End-to-end request through a full chain.
    ChainEndToEnd,
}

/// Probe outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ProbeOutcome {
    /// Reached the test target.
    Ok,
    /// Connection refused, reset or unreachable.
    ConnectFailed {
        /// Bounded description.
        detail: String,
    },
    /// TLS negotiation failed.
    TlsFailed {
        /// Bounded description.
        detail: String,
    },
    /// The request did not complete within the deadline.
    Timeout,
    /// The probe was cancelled by the user or by shutdown.
    Cancelled,
    /// Could not run: no core, unsupported node, missing listener.
    NotRun {
        /// Why.
        reason: String,
    },
}

impl ProbeOutcome {
    /// Whether the path is usable.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// Rolling health verdict for one selectable entity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthRecord {
    /// Most recent probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<ProbeResult>,
    /// Consecutive failures since the last success.
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Successful probes in the bounded history window.
    #[serde(default)]
    pub successes: u32,
    /// Total probes in the bounded history window.
    #[serde(default)]
    pub attempts: u32,
    /// Exponential moving average of latency, milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ema_latency_ms: Option<u32>,
}

impl HealthRecord {
    /// Fraction of recent probes that succeeded, `0.0..=1.0`.
    #[must_use]
    pub fn confidence(&self) -> f32 {
        if self.attempts == 0 {
            0.0
        } else {
            self.successes as f32 / self.attempts as f32
        }
    }

    /// Coarse state for display.
    #[must_use]
    pub fn state(&self) -> HealthState {
        match self.last.as_ref().map(|p| &p.outcome) {
            None => HealthState::Unknown,
            Some(outcome) if outcome.is_ok() => {
                if self.consecutive_failures == 0 {
                    HealthState::Up
                } else {
                    HealthState::Flapping
                }
            }
            Some(ProbeOutcome::NotRun { .. }) => HealthState::Unknown,
            Some(_) => HealthState::Down,
        }
    }

    /// Fold a new probe result into the record.
    pub fn record(&mut self, result: ProbeResult) {
        const EMA_WINDOW: u32 = 8;
        self.attempts = self.attempts.saturating_add(1).min(1024);
        if result.outcome.is_ok() {
            self.successes = self.successes.saturating_add(1);
            self.consecutive_failures = 0;
            if let Some(latency) = result.latency_ms {
                self.ema_latency_ms = Some(match self.ema_latency_ms {
                    None => latency,
                    Some(previous) => {
                        let n = EMA_WINDOW;
                        (previous.saturating_mul(n - 1).saturating_add(latency)) / n
                    }
                });
            }
        } else if !matches!(result.outcome, ProbeOutcome::Cancelled | ProbeOutcome::NotRun { .. }) {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
        self.last = Some(result);
    }
}

/// Coarse health for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    /// Never probed.
    Unknown,
    /// Last probe succeeded and no recent failures.
    Up,
    /// Last probe succeeded but failures happened recently.
    Flapping,
    /// Last probe failed.
    Down,
}

impl HealthState {
    /// Two-to-eight character label for narrow columns.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "--",
            Self::Up => "up",
            Self::Flapping => "flap",
            Self::Down => "down",
        }
    }
}

/// Traffic counters for one entity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficCounters {
    /// Total bytes sent.
    pub uplink_bytes: u64,
    /// Total bytes received.
    pub downlink_bytes: u64,
    /// Bytes per second sent, computed from consecutive samples.
    pub uplink_bps: u64,
    /// Bytes per second received.
    pub downlink_bps: u64,
}

/// Live runtime status of one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRuntime {
    /// Profile identifier.
    pub id: ProfileId,
    /// Configured target.
    pub target: Target,
    /// Concrete outbound the selector currently points at.
    ///
    /// For a group this is the balancer's chosen member, for a chain the chain
    /// terminal, for a node the node itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_outbound: Option<String>,
    /// Health of the effective path.
    #[serde(default)]
    pub health: HealthRecord,
    /// Traffic through this profile's routing stage.
    #[serde(default)]
    pub traffic: TrafficCounters,
    /// SOCKS listener address, if configured and bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_listen: Option<String>,
    /// HTTP listener address, if configured and bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_listen: Option<String>,
    /// Whether both configured listeners accepted a loopback probe.
    #[serde(default)]
    pub listeners_healthy: bool,
}

/// Whether the TUN device and its network state are in place.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum TunStatus {
    /// Not requested.
    #[default]
    Disabled,
    /// Requested; the helper is applying state.
    Configuring,
    /// Device exists, routes and rules applied, lease held.
    Active {
        /// Interface name.
        interface: String,
        /// IPv4 address assigned to the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ipv4: Option<String>,
        /// IPv6 address assigned to the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ipv6: Option<String>,
        /// Routing table id in use.
        table: u32,
        /// Firewall mark in use.
        fwmark: u32,
        /// Seconds until the lease expires if no heartbeat arrives.
        lease_ttl_secs: u64,
    },
    /// The helper refused or failed.
    Failed {
        /// Bounded explanation.
        reason: String,
    },
}

impl TunStatus {
    /// One-word status for the dashboard.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Disabled => "off",
            Self::Configuring => "configuring",
            Self::Active { .. } => "on",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Whether DNS is under management and healthy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum DnsStatus {
    /// No DNS management requested.
    #[default]
    Unmanaged,
    /// Managed and answering.
    Healthy {
        /// Backend in use.
        manager: String,
        /// Resolver the system was pointed at.
        resolver: String,
    },
    /// Managed but not answering.
    Unhealthy {
        /// Backend in use.
        manager: String,
        /// Bounded explanation.
        reason: String,
    },
    /// Previous state has been restored after teardown.
    Restored,
}

impl DnsStatus {
    /// One-word status for the dashboard.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unmanaged => "unmanaged",
            Self::Healthy { .. } => "healthy",
            Self::Unhealthy { .. } => "unhealthy",
            Self::Restored => "restored",
        }
    }
}

/// One live connection as reported by routing statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// Unix milliseconds when the routing decision was observed.
    pub at_unix_ms: i64,
    /// Inbound tag that accepted the connection.
    pub inbound: String,
    /// Outbound tag chosen.
    pub outbound: String,
    /// `tcp` or `udp`.
    pub network: String,
    /// Destination domain if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Destination IP if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Destination port.
    #[serde(default)]
    pub port: u16,
    /// Rule tag that produced the decision, when Xray reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_tag: Option<String>,
    /// Sniffed protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// The complete observed state broadcast to clients.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeState {
    /// Desired system mode.
    #[serde(default)]
    pub mode: SystemMode,
    /// Core lifecycle.
    #[serde(default)]
    pub core: CoreStatus,
    /// TUN state.
    #[serde(default)]
    pub tun: TunStatus,
    /// DNS state.
    #[serde(default)]
    pub dns: DnsStatus,
    /// Live per-profile status, ordered by profile id.
    #[serde(default)]
    pub profiles: Vec<ProfileRuntime>,
    /// Health of individual nodes.
    #[serde(default)]
    pub node_health: BTreeMap<NodeId, HealthRecord>,
    /// Health of groups, aggregated from members.
    #[serde(default)]
    pub group_health: BTreeMap<GroupId, HealthRecord>,
    /// Health of chains, measured end to end.
    #[serde(default)]
    pub chain_health: BTreeMap<ChainId, HealthRecord>,
    /// Machine-wide counters.
    #[serde(default)]
    pub total_traffic: TrafficCounters,
    /// Generation currently applied.
    #[serde(default)]
    pub generation: GenerationId,
    /// Generation to roll back to, if the current one fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_good: Option<GenerationId>,
    /// Whether any non-loopback listener is currently bound.
    #[serde(default)]
    pub lan_exposed: bool,
    /// Bounded list of recent warnings shown in the dashboard.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl RuntimeState {
    /// Look up one profile's runtime record.
    #[must_use]
    pub fn profile(&self, id: &ProfileId) -> Option<&ProfileRuntime> {
        self.profiles.iter().find(|p| &p.id == id)
    }

    /// Whether everything the user asked for is in place.
    #[must_use]
    pub fn is_fully_healthy(&self) -> bool {
        matches!(self.core, CoreStatus::Running { .. })
            && !matches!(self.tun, TunStatus::Failed { .. })
            && !matches!(self.dns, DnsStatus::Unhealthy { .. })
            && self.profiles.iter().all(|p| p.health.state() != HealthState::Down)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(ok: bool, latency: u32) -> ProbeResult {
        ProbeResult {
            at_unix_ms: 0,
            latency_ms: ok.then_some(latency),
            outcome: if ok {
                ProbeOutcome::Ok
            } else {
                ProbeOutcome::ConnectFailed { detail: "refused".into() }
            },
            kind: ProbeKind::TcpConnect,
        }
    }

    #[test]
    fn health_starts_unknown() {
        assert_eq!(HealthRecord::default().state(), HealthState::Unknown);
        assert!((HealthRecord::default().confidence() - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn health_tracks_successes_and_failures() {
        let mut record = HealthRecord::default();
        record.record(probe(true, 40));
        assert_eq!(record.state(), HealthState::Up);
        assert_eq!(record.ema_latency_ms, Some(40));

        record.record(probe(false, 0));
        assert_eq!(record.state(), HealthState::Down);
        assert_eq!(record.consecutive_failures, 1);

        record.record(probe(true, 80));
        assert_eq!(record.state(), HealthState::Up);
        assert_eq!(record.consecutive_failures, 0);
        // EMA moves towards the new sample without jumping to it.
        let ema = record.ema_latency_ms.expect("ema");
        assert!((40..80).contains(&ema), "ema was {ema}");
    }

    #[test]
    fn cancelled_probes_do_not_count_as_failures() {
        let mut record = HealthRecord::default();
        record.record(probe(true, 10));
        record.record(ProbeResult {
            at_unix_ms: 0,
            latency_ms: None,
            outcome: ProbeOutcome::Cancelled,
            kind: ProbeKind::TcpConnect,
        });
        assert_eq!(record.consecutive_failures, 0);
    }

    #[test]
    fn core_status_reports_generation_and_usability() {
        let running = CoreStatus::Running {
            generation: GenerationId(3),
            pid: 42,
            version: "26.3.27".into(),
            since_unix: 0,
        };
        assert!(running.is_usable());
        assert_eq!(running.generation(), Some(GenerationId(3)));
        assert_eq!(running.label(), "running");
        assert!(!CoreStatus::Stopped.is_usable());
        assert_eq!(CoreStatus::Stopped.generation(), None);
    }

    #[test]
    fn tun_and_dns_labels_are_short() {
        assert_eq!(TunStatus::Disabled.label(), "off");
        assert_eq!(DnsStatus::Unmanaged.label(), "unmanaged");
    }
}
