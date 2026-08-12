//! xraytui domain model.
//!
//! This crate is the vocabulary the rest of the project speaks. It knows nothing
//! about Xray JSON, terminals, command lines, gRPC or Linux networking — those
//! live in `xraytui-xray-compiler`, `xraytui-tui`, `xraytui-cli`,
//! `xraytui-xray-api` and `xraytui-linux-net` respectively.
//!
//! Keeping the model independent is what makes the compiler testable without a
//! core and the TUI testable without a daemon.
//!
//! ```
//! use xraytui_domain::{DesiredState, EgressProfile, ProfileId, Target};
//!
//! let mut state = DesiredState::default();
//! let id = ProfileId::new("web").expect("valid slug");
//! state
//!     .profiles
//!     .insert(id.clone(), EgressProfile::new(id, "Web", Target::Direct));
//!
//! // `Direct` needs no node, so the only diagnostic is the missing-default note.
//! assert!(state.validate().iter().all(|d| d.severity != xraytui_domain::Severity::Error));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ids;
pub mod node;
pub mod policy;
pub mod runtime;
pub mod state;
pub mod subscription;

pub use ids::{
    AppRuleId, ChainId, GenerationId, GroupId, IdError, NodeId, ProfileId, RoutingRuleId,
    SubscriptionId, slugify, validate_slug,
};
pub use node::{
    Compatibility, Endpoint, GrpcTransport, HttpProxySettings, HttpUpgradeTransport,
    HysteriaSettings, MkcpTransport, MuxSettings, Node, NodeSource, ProtocolSettings, RawTransport,
    RealitySettings, ShadowsocksSettings, SocketSettings, SocksSettings, TlsSettings, Transport,
    TransportSecurity, TrojanSettings, UnsupportedNode, UnsupportedReason, VlessSettings,
    VmessSettings, WebsocketTransport, WireguardPeer, WireguardSettings, XhttpTransport,
};
pub use policy::{
    AppMatcher, ApplicationRule, Chain, ChainError, EgressProfile, Group, GroupMembership,
    GroupStrategy, KillSwitch, ListenerSpec, MatcherShape, ProfileDnsPolicy, RoutingMatch,
    RoutingRule, RuleAction, SystemMode, Target, TargetParseError,
};
pub use runtime::{
    ConnectionRecord, CoreStatus, DnsStatus, HealthRecord, HealthState, ProbeKind, ProbeOutcome,
    ProbeResult, ProfileRuntime, RuntimeState, TrafficCounters, TunStatus,
};
pub use state::{DesiredState, Diagnostic, Severity};
pub use subscription::{DiffCounts, NodeChange, Subscription, SubscriptionDiff, SubscriptionMeta};

/// Version of the aggregate desired-state schema.
///
/// Bumping this requires a migration in `xraytui-config`.
pub const STATE_SCHEMA_VERSION: u32 = 1;
