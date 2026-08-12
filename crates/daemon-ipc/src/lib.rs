//! Versioned IPC between `xraytui` and `xraytuid`.
//!
//! Length-prefixed CBOR over a Unix-domain socket. The socket lives in a
//! mode-0700 directory inside `XDG_RUNTIME_DIR`, so the filesystem provides the
//! access control; the daemon additionally reads `SO_PEERCRED` and refuses any
//! connection from a different UID, because a directory mode is a weaker promise
//! than a credential check.
//!
//! ```no_run
//! # async fn example() -> Result<(), xraytui_ipc::IpcClientError> {
//! use xraytui_ipc::{Client, Request};
//!
//! let mut client = Client::connect("/run/user/1000/xraytui/control.sock").await?;
//! let response = client.request(Request::GetRuntime).await?;
//! println!("{response:?}");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(missing_docs)]

pub mod client;
pub mod frame;
pub mod protocol;
pub mod server;

pub use client::{Client, IpcClientError};
pub use frame::{FrameError, MAX_FRAME_BYTES, MAX_NETD_FRAME_BYTES, read_frame, write_frame};
pub use protocol::{
    CheckStatus, DoctorCheck, DoctorReport, Envelope, Event, Hello, ImportOrigin, IpcError,
    PROTOCOL_VERSION, Reply, ReplyPayload, Request, Response, RuleRef, SubscriptionFilter,
    TestTarget, Welcome,
};
pub use server::{PeerCredentials, Server, ServerHandler, listen};

/// Maximum requests a single connection may have in flight.
///
/// Bounds the work one client can queue inside the daemon; the limit is per
/// connection, so a well-behaved client is never affected by a badly behaved one.
pub const MAX_INFLIGHT_PER_CONNECTION: usize = 64;

/// Capacity of the broadcast channel that fans events out to subscribers.
///
/// A subscriber that falls further behind than this receives an
/// [`Event::Lagged`] instead of blocking the producer.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;
