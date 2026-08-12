//! The client side of the control socket.

use std::path::Path;

use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::frame::{FrameError, MAX_FRAME_BYTES, read_frame, write_frame};
use crate::protocol::{
    Envelope, Event, Hello, IpcError, PROTOCOL_VERSION, Reply, ReplyPayload, Request, Response,
    SubscriptionFilter, Welcome,
};

/// Failures a client can see.
#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    /// The socket could not be reached.
    #[error(
        "cannot reach the xraytui daemon at {path}: {source}\n\
         start it with: systemctl --user start xraytuid.service"
    )]
    Connect {
        /// Socket path.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Framing or transport failure.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The daemon refused the protocol version.
    #[error("{0}")]
    Rejected(String),
    /// The daemon returned a structured error.
    #[error(transparent)]
    Daemon(#[from] IpcError),
    /// The daemon answered a different request than the one asked.
    #[error("daemon replied to request {got} while {expected} was outstanding")]
    Mismatched {
        /// Id received.
        got: u64,
        /// Id expected.
        expected: u64,
    },
}

/// A connected control client.
pub struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: u64,
    daemon: String,
    features: Vec<String>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("daemon", &self.daemon).finish_non_exhaustive()
    }
}

impl Client {
    /// Connect and negotiate the protocol version.
    ///
    /// # Errors
    /// Returns [`IpcClientError::Connect`] when the daemon is not running, and
    /// [`IpcClientError::Rejected`] on a version mismatch.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, IpcClientError> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path).await.map_err(|source| IpcClientError::Connect {
            path: path.display().to_string(),
            source,
        })?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let hello = Hello {
            protocol_version: PROTOCOL_VERSION,
            client: format!("xraytui/{}", env!("CARGO_PKG_VERSION")),
        };
        write_frame(&mut writer, &hello, MAX_FRAME_BYTES).await?;
        let welcome: Welcome = read_frame(&mut reader, MAX_FRAME_BYTES).await?;
        match welcome {
            Welcome::Accepted { daemon, features, .. } => Ok(Self {
                reader,
                writer,
                next_id: 1,
                daemon,
                features,
            }),
            Welcome::Rejected { reason, .. } => Err(IpcClientError::Rejected(reason)),
        }
    }

    /// The daemon's version string.
    #[must_use]
    pub fn daemon_version(&self) -> &str {
        &self.daemon
    }

    /// Feature flags the daemon advertised.
    #[must_use]
    pub fn features(&self) -> &[String] {
        &self.features
    }

    /// Send a request and wait for its response.
    ///
    /// # Errors
    /// Propagates transport failures and daemon errors.
    pub async fn request(&mut self, request: Request) -> Result<Response, IpcClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        write_frame(&mut self.writer, &Envelope { id, request }, MAX_FRAME_BYTES).await?;

        loop {
            let reply: Reply = read_frame(&mut self.reader, MAX_FRAME_BYTES).await?;
            if reply.id != id {
                // A stream belonging to an earlier subscription; ignore it here.
                if matches!(reply.payload, ReplyPayload::Stream(_) | ReplyPayload::StreamEnd) {
                    continue;
                }
                return Err(IpcClientError::Mismatched { got: reply.id, expected: id });
            }
            return match reply.payload {
                ReplyPayload::Ok(response) => Ok(response),
                ReplyPayload::Err(error) => Err(IpcClientError::Daemon(error)),
                ReplyPayload::Stream(_) | ReplyPayload::StreamEnd => {
                    Err(IpcClientError::Daemon(IpcError::Internal(
                        "daemon streamed a response to a unary request".into(),
                    )))
                }
            };
        }
    }

    /// Start an event subscription, consuming the client.
    ///
    /// A subscription takes over the connection: the returned stream owns the
    /// read half. Callers that need both a subscription and ordinary requests
    /// open two connections, which keeps the framing single-threaded and simple.
    ///
    /// # Errors
    /// Propagates transport failures.
    pub async fn subscribe(
        &mut self,
        filter: SubscriptionFilter,
    ) -> Result<EventStream<'_>, IpcClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        write_frame(
            &mut self.writer,
            &Envelope { id, request: Request::Subscribe(filter) },
            MAX_FRAME_BYTES,
        )
        .await?;
        Ok(EventStream { reader: &mut self.reader, id })
    }
}

/// A borrowed stream of events for one subscription.
pub struct EventStream<'a> {
    reader: &'a mut BufReader<OwnedReadHalf>,
    id: u64,
}

impl EventStream<'_> {
    /// Await the next event, or `None` when the stream ends.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            let reply: Reply = read_frame(self.reader, MAX_FRAME_BYTES).await.ok()?;
            if reply.id != self.id {
                continue;
            }
            match reply.payload {
                ReplyPayload::Stream(event) => return Some(event),
                ReplyPayload::StreamEnd => return None,
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connecting_to_nothing_explains_how_to_start_the_daemon() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!("tempdir"));
        let error = Client::connect(dir.path().join("absent.sock"))
            .await
            .expect_err("must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("cannot reach the xraytui daemon"), "{rendered}");
        assert!(rendered.contains("systemctl --user start xraytuid.service"), "{rendered}");
    }
}
