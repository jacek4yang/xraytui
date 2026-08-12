//! The desired-state controller.
//!
//! [`Engine`] owns the difference between *what the user asked for*
//! ([`xraytui_domain::DesiredState`]) and *what is actually running*
//! ([`xraytui_domain::RuntimeState`]), and closes it. It is the only component
//! that talks to Xray, and the only one that decides when a configuration change
//! needs a restart rather than an API call.
//!
//! # The central distinction
//!
//! | Change | How it is applied |
//! |---|---|
//! | a profile's target | one `OverrideBalancerTarget` RPC, no restart |
//! | a group's manual selection | one `OverrideBalancerTarget` RPC, no restart |
//! | adding/removing nodes, listeners, rules, TUN, DNS | recompile and restart |
//!
//! The first row is what makes several profiles independently switchable while
//! traffic is flowing. [`Engine::plan`] decides which row a change falls into,
//! and it is tested directly.

#![forbid(unsafe_code)]
// Production paths must not panic; test modules are exempt so assertions stay
// readable.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(missing_docs)]

pub mod core;
pub mod engine;
pub mod health;

pub use core::{
    CoreInfo, HealthGate, HealthReport, LaunchSpec, RestartPolicy, RunningCore, Version,
    discover_binary, probe_binary, spawn, validate_config,
};
pub use engine::{ApplyOutcome, ChangePlan, Engine, EngineConfig};
pub use health::{ProbeRequest, probe_through_socks};

/// Everything that can go wrong in the controller.
#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    /// No Xray binary could be found.
    #[error("no Xray-core binary found (searched {searched}); install xray or set [core] binary")]
    CoreNotFound {
        /// What was searched.
        searched: String,
    },
    /// The binary exists but cannot be used.
    #[error("Xray-core is unusable: {detail}")]
    CoreUnusable {
        /// Explanation.
        detail: String,
    },
    /// The binary is older than [`core::MINIMUM_XRAY_VERSION`].
    #[error("Xray-core {found} is too old; xraytui needs at least {minimum}")]
    CoreTooOld {
        /// Version found.
        found: Version,
        /// Minimum required.
        minimum: Version,
    },
    /// The process could not be started.
    #[error("cannot run {binary}: {source}")]
    CoreSpawn {
        /// Binary path.
        binary: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Xray refused the generated configuration.
    #[error("Xray rejected the generated configuration: {detail}")]
    ConfigRejected {
        /// Xray's own message.
        detail: String,
    },
    /// Compilation failed before the core was involved.
    #[error(transparent)]
    Compile(#[from] xraytui_xray_compiler::CompileError),
    /// A configuration file could not be read or written.
    #[error(transparent)]
    Config(Box<xraytui_config::ConfigError>),
    /// The commander could not be reached or refused a call.
    #[error(transparent)]
    Api(Box<xraytui_xray_api::ApiError>),
    /// The core started but did not pass its health gate.
    #[error("generation {generation} did not become healthy: {detail}")]
    Unhealthy {
        /// Generation involved.
        generation: xraytui_domain::GenerationId,
        /// What failed.
        detail: String,
    },
    /// A rollback was attempted and also failed.
    #[error("rollback to generation {generation} also failed: {detail}")]
    RollbackFailed {
        /// Generation that was rolled back to.
        generation: xraytui_domain::GenerationId,
        /// What failed.
        detail: String,
    },
    /// The core is not running and the operation needs it.
    #[error("the Xray core is not running")]
    CoreNotRunning,
    /// The request referred to something that does not exist.
    #[error("{0}")]
    NotFound(String),
    /// The request was structurally invalid.
    #[error("{0}")]
    Invalid(String),
    /// An I/O failure not covered by a more specific variant.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl From<xraytui_config::ConfigError> for ControllerError {
    fn from(source: xraytui_config::ConfigError) -> Self {
        Self::Config(Box::new(source))
    }
}

impl From<xraytui_xray_api::ApiError> for ControllerError {
    fn from(source: xraytui_xray_api::ApiError) -> Self {
        Self::Api(Box::new(source))
    }
}
