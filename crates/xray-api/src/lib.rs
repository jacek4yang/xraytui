//! Xray-core gRPC client.
//!
//! Generated from the protobuf files vendored at the pinned Xray tag. The client
//! speaks the four command services xraytui needs:
//!
//! | Service | Used for |
//! |---|---|
//! | `HandlerService` | listing/adding/removing inbounds and outbounds at runtime |
//! | `RoutingService` | profile switching, rule management, route testing, event stream |
//! | `StatsService` | traffic counters and process statistics |
//! | `LoggerService` | log rotation |
//!
//! Xray's commander does **not** serve gRPC reflection, so capability discovery
//! is done by probing each service with a cheap read-only RPC and treating
//! `Unimplemented` as "absent" ([`Capabilities::probe`]).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::Duration;

use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};

pub mod proto {
    //! Generated protobuf types.
    //!
    //! The module tree mirrors the protobuf package tree exactly, because
    //! prost's generated code addresses sibling packages with `super::super::…`
    //! paths. Renaming or flattening a level here breaks compilation of the
    //! generated files rather than of anything hand-written.
    #![allow(missing_docs, clippy::all, clippy::pedantic)]

    /// `xray.*`
    pub mod xray {
        /// `xray.common.*`
        pub mod common {
            /// `xray.common.serial`
            pub mod serial {
                tonic::include_proto!("xray.common.serial");
            }
            /// `xray.common.net`
            pub mod net {
                tonic::include_proto!("xray.common.net");
            }
            /// `xray.common.protocol`
            pub mod protocol {
                tonic::include_proto!("xray.common.protocol");
            }
        }
        /// `xray.core`
        ///
        /// The proxyman protos refer to it as `core.InboundHandlerConfig`, which
        /// resolves relative to the enclosing `xray` package.
        pub mod core {
            tonic::include_proto!("xray.core");
        }
        /// `xray.app.*`
        pub mod app {
            /// `xray.app.proxyman.*`
            pub mod proxyman {
                /// `xray.app.proxyman.command`
                pub mod command {
                    tonic::include_proto!("xray.app.proxyman.command");
                }
            }
            /// `xray.app.router.*`
            pub mod router {
                /// `xray.app.router.command`
                pub mod command {
                    tonic::include_proto!("xray.app.router.command");
                }
            }
            /// `xray.app.stats.*`
            pub mod stats {
                /// `xray.app.stats.command`
                pub mod command {
                    tonic::include_proto!("xray.app.stats.command");
                }
            }
            /// `xray.app.log.*`
            pub mod log {
                /// `xray.app.log.command`
                pub mod command {
                    tonic::include_proto!("xray.app.log.command");
                }
            }
        }
    }

    pub use xray::app::log::command as log;
    pub use xray::app::proxyman::command as proxyman;
    pub use xray::app::router::command as router;
    pub use xray::app::stats::command as stats;
}

use proto::log::logger_service_client::LoggerServiceClient;
use proto::proxyman::handler_service_client::HandlerServiceClient;
use proto::router::routing_service_client::RoutingServiceClient;
use proto::stats::stats_service_client::StatsServiceClient;

pub use proto::router::{RoutingContext, TestRouteRequest};
pub use proto::stats::Stat;

mod client;
mod endpoint;

pub use client::{ApiClient, BalancerInfo, Capabilities, RouteDecision, RouteQuery, SysStats};
pub use endpoint::{ApiEndpoint, ApiEndpointFile};

/// Failures talking to the Xray commander.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The transport could not be established.
    #[error("cannot reach the Xray API at {endpoint}: {source}")]
    Connect {
        /// Endpoint that was tried.
        endpoint: String,
        /// Underlying transport error.
        #[source]
        source: tonic::transport::Error,
    },
    /// The RPC failed.
    #[error("Xray API call {call} failed: {status}")]
    Call {
        /// Which RPC.
        call: &'static str,
        /// gRPC status.
        #[source]
        status: Box<tonic::Status>,
    },
    /// The endpoint string could not be understood.
    #[error("invalid Xray API endpoint {0:?}")]
    InvalidEndpoint(String),
    /// The core did not become ready inside the deadline.
    #[error("Xray API did not become ready within {0:?}")]
    NotReady(Duration),
    /// A response was missing a field the caller needs.
    #[error("Xray API response for {call} was missing {field}")]
    MissingField {
        /// Which RPC.
        call: &'static str,
        /// Which field.
        field: &'static str,
    },
}

impl ApiError {
    fn call(call: &'static str, status: tonic::Status) -> Self {
        Self::Call { call, status: Box::new(status) }
    }

    /// Whether the failure means "this Xray build does not have that feature".
    #[must_use]
    pub fn is_unimplemented(&self) -> bool {
        matches!(self, Self::Call { status, .. } if status.code() == tonic::Code::Unimplemented)
    }

    /// Whether a retry could plausibly succeed.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Connect { .. } | Self::NotReady(_) => true,
            Self::Call { status, .. } => matches!(
                status.code(),
                tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Aborted
            ),
            _ => false,
        }
    }
}

/// Bundle of the four service clients over one multiplexed channel.
#[derive(Clone)]
pub(crate) struct Services {
    pub(crate) handler: HandlerServiceClient<Channel>,
    pub(crate) routing: RoutingServiceClient<Channel>,
    pub(crate) stats: StatsServiceClient<Channel>,
    pub(crate) logger: LoggerServiceClient<Channel>,
}

impl Services {
    pub(crate) fn new(channel: Channel) -> Self {
        Self {
            handler: HandlerServiceClient::new(channel.clone()),
            routing: RoutingServiceClient::new(channel.clone()),
            stats: StatsServiceClient::new(channel.clone()),
            logger: LoggerServiceClient::new(channel),
        }
    }
}

/// Build a channel for a TCP endpoint.
pub(crate) async fn connect_tcp(authority: &str, timeout: Duration) -> Result<Channel, ApiError> {
    let uri = format!("http://{authority}");
    let endpoint = Endpoint::from_shared(uri.clone())
        .map_err(|_| ApiError::InvalidEndpoint(authority.to_owned()))?
        .connect_timeout(timeout)
        .timeout(timeout)
        .tcp_nodelay(true);
    endpoint
        .connect()
        .await
        .map_err(|source| ApiError::Connect { endpoint: authority.to_owned(), source })
}

/// Build a channel for a Unix-domain endpoint.
///
/// The URI is a placeholder — tonic requires one, but the connector ignores it
/// and dials the socket path instead.
pub(crate) async fn connect_uds(path: &str, timeout: Duration) -> Result<Channel, ApiError> {
    let path = path.to_owned();
    let endpoint = Endpoint::try_from("http://[::]:50051")
        .map_err(|_| ApiError::InvalidEndpoint(path.clone()))?
        .connect_timeout(timeout)
        .timeout(timeout);
    let connect_path = path.clone();
    endpoint
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let connect_path = connect_path.clone();
            async move {
                let stream = UnixStream::connect(connect_path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|source| ApiError::Connect { endpoint: path, source })
}
