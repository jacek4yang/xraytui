//! Where the Xray commander listens, and how that is recorded on disk.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The address of a running core's gRPC commander.
///
/// A Unix socket is preferred whenever the running Xray accepts one, because a
/// loopback TCP port has no per-user access control on Linux — any local account
/// that can reach `127.0.0.1` can drive the data plane. See
/// `docs/THREAT-MODEL.md`, T1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum ApiEndpoint {
    /// `host:port` on loopback.
    Tcp {
        /// Authority in `host:port` form.
        authority: String,
    },
    /// Absolute path to a Unix-domain socket.
    Unix {
        /// Socket path.
        path: String,
    },
}

impl ApiEndpoint {
    /// Loopback TCP on the given port.
    #[must_use]
    pub fn loopback(port: u16) -> Self {
        Self::Tcp { authority: format!("127.0.0.1:{port}") }
    }

    /// A Unix socket.
    pub fn unix(path: impl AsRef<Path>) -> Self {
        Self::Unix { path: path.as_ref().to_string_lossy().into_owned() }
    }

    /// The string Xray's `api.listen` field expects.
    #[must_use]
    pub fn xray_listen(&self) -> String {
        match self {
            Self::Tcp { authority } => authority.clone(),
            Self::Unix { path } => path.clone(),
        }
    }

    /// Whether this endpoint is reachable by other local users.
    #[must_use]
    pub fn is_locally_shared(&self) -> bool {
        matches!(self, Self::Tcp { .. })
    }
}

impl fmt::Display for ApiEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { authority } => write!(f, "tcp://{authority}"),
            Self::Unix { path } => write!(f, "unix://{path}"),
        }
    }
}

/// The contents of `$XDG_RUNTIME_DIR/xraytui/xray-api.json`, mode 0600.
///
/// Written after the core reports ready so a second `xraytui` process, or a
/// recovering daemon, can find the commander without guessing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiEndpointFile {
    /// Format version.
    pub version: u32,
    /// Where the commander is.
    pub endpoint: ApiEndpoint,
    /// PID of the core that owns it.
    pub pid: u32,
    /// Generation the core was started with.
    pub generation: u64,
    /// Xray version string, for diagnostics.
    pub xray_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_strings_match_what_xray_expects() {
        assert_eq!(ApiEndpoint::loopback(10085).xray_listen(), "127.0.0.1:10085");
        assert_eq!(ApiEndpoint::unix("/run/user/1000/x.sock").xray_listen(), "/run/user/1000/x.sock");
    }

    #[test]
    fn tcp_is_flagged_as_locally_shared() {
        assert!(ApiEndpoint::loopback(1).is_locally_shared());
        assert!(!ApiEndpoint::unix("/tmp/s").is_locally_shared());
    }

    #[test]
    fn endpoint_round_trips_through_json() {
        for endpoint in [ApiEndpoint::loopback(1), ApiEndpoint::unix("/tmp/s")] {
            let json = serde_json::to_string(&endpoint).expect("serialise");
            let back: ApiEndpoint = serde_json::from_str(&json).expect("deserialise");
            assert_eq!(endpoint, back);
        }
    }

    #[test]
    fn display_is_unambiguous() {
        assert_eq!(ApiEndpoint::loopback(1).to_string(), "tcp://127.0.0.1:1");
        assert_eq!(ApiEndpoint::unix("/tmp/s").to_string(), "unix:///tmp/s");
    }
}
