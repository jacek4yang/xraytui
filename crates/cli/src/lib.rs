//! The `xraytui` command-line front end.
//!
//! Every command that changes state goes through the daemon; read-only commands
//! prefer the daemon but say so clearly when it is not running rather than
//! silently reporting a stale file.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | success |
//! | 1 | the operation failed |
//! | 2 | usage error (clap) |
//! | 3 | the daemon is not reachable |
//! | 4 | the requested entity does not exist |
//! | 5 | the core is not running |
//!
//! Scripts can therefore distinguish "not running" from "no such profile"
//! without parsing messages.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod args;
pub mod exec;
pub mod output;
pub mod run;

pub use args::{Cli, Command, Format};
pub use run::main;

/// Exit code for a failed operation.
pub const EXIT_FAILURE: i32 = 1;
/// Exit code when the daemon cannot be reached.
pub const EXIT_NO_DAEMON: i32 = 3;
/// Exit code when the named entity does not exist.
pub const EXIT_NOT_FOUND: i32 = 4;
/// Exit code when the core is not running.
pub const EXIT_CORE_DOWN: i32 = 5;

/// Errors surfaced to the user, each mapped to a stable exit code.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The daemon is not running or the socket is unreachable.
    #[error(transparent)]
    NoDaemon(#[from] xraytui_ipc::IpcClientError),
    /// The daemon reported a failure.
    #[error("{0}")]
    Daemon(String),
    /// The named entity does not exist.
    #[error("{0}")]
    NotFound(String),
    /// The core is not running.
    #[error("the Xray core is not running; start it with `xraytui up`")]
    CoreDown,
    /// The request was malformed.
    #[error("{0}")]
    Usage(String),
    /// An I/O failure.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl CliError {
    /// The process exit code for this error.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NoDaemon(_) => EXIT_NO_DAEMON,
            Self::NotFound(_) => EXIT_NOT_FOUND,
            Self::CoreDown => EXIT_CORE_DOWN,
            _ => EXIT_FAILURE,
        }
    }
}

impl From<xraytui_ipc::IpcError> for CliError {
    fn from(error: xraytui_ipc::IpcError) -> Self {
        match error {
            xraytui_ipc::IpcError::NotFound { kind, id } => {
                Self::NotFound(format!("{kind} '{id}' does not exist"))
            }
            xraytui_ipc::IpcError::CoreNotRunning => Self::CoreDown,
            xraytui_ipc::IpcError::Invalid(message) => Self::Usage(message),
            xraytui_ipc::IpcError::Diagnostics(diagnostics) => Self::Daemon(
                diagnostics
                    .iter()
                    .map(|d| format!("[{}] {}", d.code, d.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            other => Self::Daemon(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_distinguish_the_common_failures() {
        assert_eq!(CliError::CoreDown.exit_code(), EXIT_CORE_DOWN);
        assert_eq!(CliError::NotFound("x".into()).exit_code(), EXIT_NOT_FOUND);
        assert_eq!(CliError::Other("x".into()).exit_code(), EXIT_FAILURE);
    }

    #[test]
    fn daemon_errors_map_to_the_right_kind() {
        let error: CliError = xraytui_ipc::IpcError::NotFound {
            kind: "profile".into(),
            id: "web".into(),
        }
        .into();
        assert_eq!(error.exit_code(), EXIT_NOT_FOUND);
        assert!(error.to_string().contains("profile 'web'"));

        let error: CliError = xraytui_ipc::IpcError::CoreNotRunning.into();
        assert_eq!(error.exit_code(), EXIT_CORE_DOWN);
    }
}
