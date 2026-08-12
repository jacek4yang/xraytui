//! The versioned request/response protocol between `xraytui` and `xraytuid`.

use serde::{Deserialize, Serialize};
use xraytui_domain::{
    AppRuleId, ChainId, DesiredState, Diagnostic, GroupId, NodeId, ProfileId, RoutingRuleId,
    RuntimeState, SubscriptionDiff, SubscriptionId, SystemMode, Target,
};

/// Protocol version. Bumped whenever a message changes shape incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

/// The first frame a client sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Highest protocol version the client understands.
    pub protocol_version: u32,
    /// Client name and version, for the daemon log.
    pub client: String,
}

/// The first frame the daemon sends back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Welcome {
    /// Negotiation succeeded.
    Accepted {
        /// Version both sides will use.
        protocol_version: u32,
        /// Daemon version string.
        daemon: String,
        /// Optional feature flags, for forward compatibility.
        features: Vec<String>,
    },
    /// The client is too new or too old.
    Rejected {
        /// Version the daemon speaks.
        daemon_protocol_version: u32,
        /// Explanation.
        reason: String,
    },
}

/// A client-to-daemon frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Correlates a response with its request; echoed back verbatim.
    pub id: u64,
    /// What to do.
    pub request: Request,
}

/// A daemon-to-client frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    /// The request this answers. Event frames carry `0`.
    pub id: u64,
    /// The answer.
    pub payload: ReplyPayload,
}

/// What a reply carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReplyPayload {
    /// A successful response.
    Ok(Response),
    /// A structured failure.
    Err(IpcError),
    /// One item of a streamed response; terminated by `StreamEnd`.
    Stream(Event),
    /// End of a stream started by this request id.
    StreamEnd,
}

/// Everything a client can ask for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    /// Liveness check.
    Ping,
    /// Full desired + observed state.
    GetState,
    /// Observed state only, which is much smaller.
    GetRuntime,
    /// Replace the whole desired state.
    SetDesired(Box<DesiredState>),
    /// Validate a desired state without applying it.
    Validate(Box<DesiredState>),
    /// Bring the core up.
    Up,
    /// Take the core down.
    Down,
    /// Restart the core.
    Restart,
    /// Read the current system mode.
    GetMode,
    /// Change the system mode.
    SetMode(SystemMode),
    /// Advance to the next mode in the cycle.
    CycleMode,
    /// Point a profile at a target.
    SetProfileTarget {
        /// Profile to change.
        profile: ProfileId,
        /// New target.
        target: Target,
    },
    /// Point a manual group at one of its members.
    SetGroupSelection {
        /// Group to change.
        group: GroupId,
        /// New selection.
        target: Target,
    },
    /// Import share links, an Xray configuration, or a file's contents.
    Import {
        /// Raw text to parse.
        text: String,
        /// Where it came from, for provenance.
        origin: ImportOrigin,
    },
    /// Delete a node.
    RemoveNode(NodeId),
    /// Probe one entity.
    Test(TestTarget),
    /// Compute a subscription update without committing it.
    SubscriptionDiff(SubscriptionId),
    /// Compute and commit a subscription update.
    SubscriptionUpdate(SubscriptionId),
    /// Update every enabled subscription.
    SubscriptionUpdateAll,
    /// Ask the core what a hypothetical connection would do.
    ExplainRoute {
        /// Destination domain, if any.
        domain: Option<String>,
        /// Destination IP, if any.
        ip: Option<String>,
        /// Destination port.
        port: u16,
        /// `tcp` or `udp`.
        network: String,
        /// Inbound tag to simulate arrival on.
        inbound_tag: Option<String>,
    },
    /// The generated Xray configuration for the running generation.
    GetGeneratedConfig,
    /// Environment and capability report.
    Doctor,
    /// Subscribe to state changes and log lines. Streams until cancelled.
    Subscribe(SubscriptionFilter),
    /// Cancel an in-flight streaming request.
    Cancel {
        /// Request id to cancel.
        id: u64,
    },
    /// Ask the daemon to exit.
    Shutdown,
}

/// Where imported text came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportOrigin {
    /// Typed or pasted by the user.
    Manual,
    /// Read from a file.
    File {
        /// Path, for provenance display only.
        path: String,
    },
    /// A raw Xray configuration document.
    XrayJson,
}

/// What to probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestTarget {
    /// One node.
    Node(NodeId),
    /// Every member of a group.
    Group(GroupId),
    /// A chain, end to end.
    Chain(ChainId),
    /// A profile's current path.
    Profile(ProfileId),
}

/// Which events a subscriber wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    /// Runtime state snapshots.
    pub state: bool,
    /// Daemon and core log lines.
    pub logs: bool,
    /// Routing decisions observed from the core.
    pub connections: bool,
    /// Probe results.
    pub health: bool,
}

impl SubscriptionFilter {
    /// Everything.
    #[must_use]
    pub fn all() -> Self {
        Self { state: true, logs: true, connections: true, health: true }
    }

    /// State only, which is what the dashboard needs.
    #[must_use]
    pub fn state_only() -> Self {
        Self { state: true, ..Self::default() }
    }
}

/// Everything the daemon can answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    /// Acknowledgement with nothing to say.
    Ack,
    /// Liveness answer.
    Pong {
        /// Daemon version.
        daemon: String,
        /// Seconds the daemon has been up.
        uptime_secs: u64,
    },
    /// Desired and observed state together.
    State {
        /// What the user asked for.
        desired: Box<DesiredState>,
        /// What is actually happening.
        runtime: Box<RuntimeState>,
    },
    /// Observed state alone.
    Runtime(Box<RuntimeState>),
    /// Validation result.
    Diagnostics(Vec<Diagnostic>),
    /// The current system mode.
    Mode(SystemMode),
    /// Result of applying a change.
    Applied {
        /// Whether the core had to restart.
        restarted: bool,
        /// Balancer tags that were repointed, when it did not.
        switched: Vec<String>,
        /// Non-fatal notes.
        warnings: Vec<String>,
    },
    /// Result of an import.
    Imported {
        /// Identifiers of nodes that were added.
        added: Vec<NodeId>,
        /// How many entries were preserved as unsupported.
        unsupported: usize,
        /// Reasons entries were rejected. Never contains credentials.
        rejected: Vec<String>,
    },
    /// A probe result.
    Probe(Box<xraytui_domain::ProbeResult>),
    /// Probe results for several entities.
    Probes(Vec<(String, xraytui_domain::ProbeResult)>),
    /// A subscription diff.
    Diff(Box<SubscriptionDiff>),
    /// The outbound a hypothetical connection would take.
    RouteDecision {
        /// Outbound tag chosen.
        outbound: String,
        /// Balancers consulted.
        groups: Vec<String>,
        /// Which rule matched, when the core reported one.
        rule: Option<String>,
    },
    /// The generated Xray configuration, with credentials intact.
    ///
    /// Only ever sent over the user's own 0700 socket.
    GeneratedConfig(String),
    /// Environment report.
    Doctor(Box<DoctorReport>),
}

/// Structured diagnosis of the local environment.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DoctorReport {
    /// One line per check.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Whether every check passed.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.checks.iter().all(|check| check.status != CheckStatus::Fail)
    }

    /// Number of failing checks.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.checks.iter().filter(|c| c.status == CheckStatus::Fail).count()
    }
}

/// One environment check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Short name, e.g. `xray-binary`.
    pub name: String,
    /// Outcome.
    pub status: CheckStatus,
    /// What was found.
    pub detail: String,
    /// What to do about it, when it is not `Pass`.
    pub remedy: Option<String>,
}

/// Outcome of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Everything is as it should be.
    Pass,
    /// Usable, but something is worth knowing.
    Warn,
    /// Something xraytui needs is missing or broken.
    Fail,
    /// Could not be determined in this environment.
    Skipped,
}

impl CheckStatus {
    /// Four-character label for aligned terminal output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "ok  ",
            Self::Warn => "warn",
            Self::Fail => "FAIL",
            Self::Skipped => "skip",
        }
    }
}

/// A streamed event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Event {
    /// A new runtime snapshot.
    State(Box<RuntimeState>),
    /// A log line, already redacted.
    Log {
        /// Unix milliseconds.
        at_unix_ms: i64,
        /// `error`, `warn`, `info`, `debug` or `trace`.
        level: String,
        /// Emitting subsystem.
        target: String,
        /// The message.
        message: String,
    },
    /// A routing decision observed from the core.
    Connection(Box<xraytui_domain::ConnectionRecord>),
    /// A probe finished.
    Health {
        /// Which entity was probed.
        subject: String,
        /// The result.
        result: Box<xraytui_domain::ProbeResult>,
    },
    /// The subscriber fell behind and events were dropped.
    Lagged {
        /// How many were lost.
        dropped: u64,
    },
}

/// A structured failure.
///
/// Every variant is safe to display: none of them carries a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum IpcError {
    /// The client and daemon do not speak a common protocol version.
    #[error("protocol version mismatch: daemon speaks {daemon}, client asked for {client}")]
    Version {
        /// Daemon's version.
        daemon: u32,
        /// Client's version.
        client: u32,
    },
    /// The named entity does not exist.
    #[error("{kind} '{id}' does not exist")]
    NotFound {
        /// Entity kind.
        kind: String,
        /// Identifier.
        id: String,
    },
    /// The request was structurally invalid.
    #[error("{0}")]
    Invalid(String),
    /// Validation of the supplied desired state failed.
    #[error("configuration is not valid")]
    Diagnostics(Vec<Diagnostic>),
    /// The core is not running and the operation needs it.
    #[error("the Xray core is not running")]
    CoreNotRunning,
    /// The operation failed inside the daemon.
    #[error("{0}")]
    Internal(String),
    /// The daemon is shutting down.
    #[error("the daemon is shutting down")]
    ShuttingDown,
    /// The request was cancelled by the client.
    #[error("cancelled")]
    Cancelled,
    /// Too many requests in flight on one connection.
    #[error("too many concurrent requests on this connection (limit {limit})")]
    TooBusy {
        /// The cap.
        limit: usize,
    },
}

/// Identifiers for rules, so the CLI can address them without a domain import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleRef {
    /// An application rule.
    App(AppRuleId),
    /// A destination routing rule.
    Routing(RoutingRuleId),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut buffer = Vec::new();
        ciborium::into_writer(value, &mut buffer).expect("encode");
        ciborium::from_reader(buffer.as_slice()).expect("decode")
    }

    #[test]
    fn requests_round_trip_through_cbor() {
        let requests = vec![
            Request::Ping,
            Request::GetState,
            Request::SetMode(SystemMode::Rule),
            Request::CycleMode,
            Request::SetProfileTarget {
                profile: ProfileId::new("web").expect("valid"),
                target: Target::Direct,
            },
            Request::Import { text: "x".into(), origin: ImportOrigin::Manual },
            Request::Test(TestTarget::Node(NodeId::new("a").expect("valid"))),
            Request::Subscribe(SubscriptionFilter::all()),
            Request::Cancel { id: 3 },
        ];
        for request in requests {
            let envelope = Envelope { id: 1, request };
            assert_eq!(round_trip(&envelope), envelope);
        }
    }

    #[test]
    fn replies_round_trip_through_cbor() {
        let replies = vec![
            ReplyPayload::Ok(Response::Ack),
            ReplyPayload::Ok(Response::Mode(SystemMode::Global)),
            ReplyPayload::Err(IpcError::CoreNotRunning),
            ReplyPayload::Err(IpcError::NotFound { kind: "node".into(), id: "a".into() }),
            ReplyPayload::StreamEnd,
        ];
        for payload in replies {
            let reply = Reply { id: 9, payload };
            assert_eq!(round_trip(&reply), reply);
        }
    }

    #[test]
    fn a_full_state_response_round_trips() {
        let response = Response::State {
            desired: Box::new(DesiredState::default()),
            runtime: Box::new(RuntimeState::default()),
        };
        assert_eq!(round_trip(&response), response);
    }

    #[test]
    fn error_messages_are_human_readable_and_carry_no_secrets() {
        let error = IpcError::NotFound { kind: "profile".into(), id: "web".into() };
        assert_eq!(error.to_string(), "profile 'web' does not exist");
        let error = IpcError::Version { daemon: 1, client: 2 };
        assert!(error.to_string().contains("daemon speaks 1"));
    }

    #[test]
    fn negotiation_messages_round_trip() {
        let hello = Hello { protocol_version: PROTOCOL_VERSION, client: "xraytui/0.1.0".into() };
        assert_eq!(round_trip(&hello), hello);
        let welcome = Welcome::Accepted {
            protocol_version: PROTOCOL_VERSION,
            daemon: "xraytuid/0.1.0".into(),
            features: vec!["tun".into()],
        };
        assert_eq!(round_trip(&welcome), welcome);
    }

    #[test]
    fn subscription_filters_are_explicit() {
        assert_eq!(
            SubscriptionFilter::state_only(),
            SubscriptionFilter { state: true, logs: false, connections: false, health: false }
        );
        let all = SubscriptionFilter::all();
        assert!(all.state && all.logs && all.connections && all.health);
    }

    #[test]
    fn doctor_report_summarises_failures() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck {
                    name: "xray-binary".into(),
                    status: CheckStatus::Pass,
                    detail: "found".into(),
                    remedy: None,
                },
                DoctorCheck {
                    name: "tun".into(),
                    status: CheckStatus::Fail,
                    detail: "/dev/net/tun is not readable".into(),
                    remedy: Some("load the tun module".into()),
                },
            ],
        };
        assert!(!report.is_ok());
        assert_eq!(report.failures(), 1);
        assert_eq!(CheckStatus::Fail.label().len(), 4);
    }
}
