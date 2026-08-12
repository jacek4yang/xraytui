//! The daemon side of the control socket.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::frame::{FrameError, MAX_FRAME_BYTES, read_frame, write_frame};
use crate::protocol::{
    Envelope, Event, Hello, IpcError, PROTOCOL_VERSION, Reply, ReplyPayload, Request, Response,
    SubscriptionFilter, Welcome,
};
use crate::{EVENT_CHANNEL_CAPACITY, MAX_INFLIGHT_PER_CONNECTION};

/// Credentials of the process on the other end of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Peer's effective user id.
    pub uid: u32,
    /// Peer's effective group id.
    pub gid: u32,
    /// Peer's process id.
    ///
    /// Recorded for logging only. PIDs are reusable, so authorisation never
    /// depends on this value.
    pub pid: i32,
}

/// What the daemon must provide to serve the socket.
///
/// Keeping this a trait means the whole protocol layer is testable with a stub
/// handler, without a core, a compiler or a filesystem.
///
/// `handle` returns an explicit `impl Future + Send` rather than being an
/// `async fn`: connections are served on spawned tasks, which requires the
/// future to be `Send`, and a bare `async fn` in a trait does not promise that.
pub trait ServerHandler: Send + Sync + 'static {
    /// Handle one request.
    fn handle(
        &self,
        peer: PeerCredentials,
        request: Request,
    ) -> impl std::future::Future<Output = Result<Response, IpcError>> + Send;

    /// Subscribe to the event stream.
    fn subscribe(&self, filter: SubscriptionFilter) -> broadcast::Receiver<Event>;

    /// Daemon version string, sent in the welcome frame.
    fn version(&self) -> String {
        format!("xraytuid/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Optional feature flags advertised to clients.
    fn features(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Errors from binding or serving the socket.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The socket could not be bound.
    #[error("cannot bind {path}: {source}")]
    Bind {
        /// Socket path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The containing directory was unusable.
    #[error("{0}")]
    Directory(String),
    /// Accept failed unrecoverably.
    #[error("accept failed: {0}")]
    Accept(#[source] std::io::Error),
}

/// A bound control socket.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
}

impl Server {
    /// The path the socket is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serve until the future returned by `shutdown` resolves.
    ///
    /// Each connection is handled by its own task; a client that misbehaves
    /// closes only its own connection.
    pub async fn serve<H, S>(self, handler: Arc<H>, shutdown: S)
    where
        H: ServerHandler,
        S: std::future::Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let handler = Arc::clone(&handler);
                            tokio::spawn(async move {
                                if let Err(error) = serve_connection(stream, handler).await {
                                    tracing::debug!(%error, "control connection ended");
                                }
                            });
                        }
                        Err(error) => {
                            tracing::warn!(%error, "accept failed");
                            // A transient accept failure must not spin the loop.
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind the control socket, replacing a stale one.
///
/// The parent directory is created 0700 and the socket itself is set to 0600.
/// A socket file that is still being listened on is *not* removed; that would let
/// a second daemon hijack the first one's clients.
///
/// # Errors
/// Returns [`ServerError::Bind`] when the socket cannot be created, and
/// [`ServerError::Directory`] when a live daemon already owns it.
pub fn listen(path: &Path) -> Result<Server, ServerError> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().unwrap_or(Path::new("."));
    xraytui_config::ensure_private_dir(parent)
        .map_err(|error| ServerError::Directory(error.to_string()))?;

    if path.exists() {
        // A connect that succeeds means someone is listening; refuse rather than
        // unlink another daemon's socket out from under it.
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(ServerError::Directory(format!(
                    "{} is already served by a running daemon",
                    path.display()
                )));
            }
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    let listener = UnixListener::bind(path).map_err(|source| ServerError::Bind {
        path: path.to_path_buf(),
        source,
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        ServerError::Bind { path: path.to_path_buf(), source }
    })?;

    Ok(Server { listener, path: path.to_path_buf() })
}

/// Read the peer's credentials from a connected socket.
///
/// # Errors
/// Propagates the `getsockopt` failure.
pub fn peer_credentials(stream: &UnixStream) -> std::io::Result<PeerCredentials> {
    let credentials = stream.peer_cred()?;
    Ok(PeerCredentials {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid: credentials.pid().unwrap_or(0),
    })
}

async fn serve_connection<H: ServerHandler>(
    stream: UnixStream,
    handler: Arc<H>,
) -> Result<(), FrameError> {
    let peer = peer_credentials(&stream).map_err(FrameError::Io)?;
    let own_uid = rustix::process::getuid().as_raw();
    if peer.uid != own_uid {
        // Belt and braces over the 0700 directory: refuse anything that is not
        // the owning user, whatever the filesystem happens to allow.
        tracing::warn!(peer_uid = peer.uid, own_uid, "refusing control connection from another uid");
        return Ok(());
    }

    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let writer = Arc::new(tokio::sync::Mutex::new(writer));

    // Version negotiation happens before anything else is accepted.
    let hello: Hello = read_frame(&mut reader, MAX_FRAME_BYTES).await?;
    let welcome = if hello.protocol_version == PROTOCOL_VERSION {
        Welcome::Accepted {
            protocol_version: PROTOCOL_VERSION,
            daemon: handler.version(),
            features: handler.features(),
        }
    } else {
        Welcome::Rejected {
            daemon_protocol_version: PROTOCOL_VERSION,
            reason: format!(
                "this daemon speaks protocol {PROTOCOL_VERSION}; the client asked for {}",
                hello.protocol_version
            ),
        }
    };
    {
        let mut guard = writer.lock().await;
        write_frame(&mut *guard, &welcome, MAX_FRAME_BYTES).await?;
    }
    if matches!(welcome, Welcome::Rejected { .. }) {
        return Ok(());
    }

    let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PER_CONNECTION));
    let mut streams: std::collections::HashMap<u64, tokio::task::AbortHandle> =
        std::collections::HashMap::new();

    loop {
        let envelope: Envelope = match read_frame(&mut reader, MAX_FRAME_BYTES).await {
            Ok(envelope) => envelope,
            Err(FrameError::Closed) => break,
            Err(error @ FrameError::TooLarge { .. }) => {
                // The stream is now out of sync; the only safe move is to close.
                tracing::warn!(%error, "closing control connection after an oversized frame");
                break;
            }
            Err(FrameError::Decode(detail)) => {
                let reply = Reply {
                    id: 0,
                    payload: ReplyPayload::Err(IpcError::Invalid(format!(
                        "malformed request: {detail}"
                    ))),
                };
                let mut guard = writer.lock().await;
                write_frame(&mut *guard, &reply, MAX_FRAME_BYTES).await?;
                continue;
            }
            Err(error) => return Err(error),
        };

        if let Request::Cancel { id } = envelope.request {
            if let Some(handle) = streams.remove(&id) {
                handle.abort();
            }
            let reply = Reply { id: envelope.id, payload: ReplyPayload::Ok(Response::Ack) };
            let mut guard = writer.lock().await;
            write_frame(&mut *guard, &reply, MAX_FRAME_BYTES).await?;
            continue;
        }

        if let Request::Subscribe(filter) = envelope.request {
            let receiver = handler.subscribe(filter);
            let writer = Arc::clone(&writer);
            let id = envelope.id;
            let task = tokio::spawn(async move { pump_events(id, receiver, filter, writer).await });
            streams.insert(id, task.abort_handle());
            continue;
        }

        let Ok(permit) = Arc::clone(&inflight).try_acquire_owned() else {
            let reply = Reply {
                id: envelope.id,
                payload: ReplyPayload::Err(IpcError::TooBusy {
                    limit: MAX_INFLIGHT_PER_CONNECTION,
                }),
            };
            let mut guard = writer.lock().await;
            write_frame(&mut *guard, &reply, MAX_FRAME_BYTES).await?;
            continue;
        };

        let handler = Arc::clone(&handler);
        let writer = Arc::clone(&writer);
        tokio::spawn(async move {
            let payload = match handler.handle(peer, envelope.request).await {
                Ok(response) => ReplyPayload::Ok(response),
                Err(error) => ReplyPayload::Err(error),
            };
            let reply = Reply { id: envelope.id, payload };
            let mut guard = writer.lock().await;
            let _ = write_frame(&mut *guard, &reply, MAX_FRAME_BYTES).await;
            drop(permit);
        });
    }

    for (_, handle) in streams {
        handle.abort();
    }
    Ok(())
}

async fn pump_events(
    id: u64,
    mut receiver: broadcast::Receiver<Event>,
    filter: SubscriptionFilter,
    writer: Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
) {
    loop {
        let event = match receiver.recv().await {
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(dropped)) => Event::Lagged { dropped },
            Err(broadcast::error::RecvError::Closed) => break,
        };
        if !wanted(&event, filter) {
            continue;
        }
        let reply = Reply { id, payload: ReplyPayload::Stream(event) };
        let mut guard = writer.lock().await;
        if write_frame(&mut *guard, &reply, MAX_FRAME_BYTES).await.is_err() {
            break;
        }
    }
    let reply = Reply { id, payload: ReplyPayload::StreamEnd };
    let mut guard = writer.lock().await;
    let _ = write_frame(&mut *guard, &reply, MAX_FRAME_BYTES).await;
}

fn wanted(event: &Event, filter: SubscriptionFilter) -> bool {
    match event {
        Event::State(_) => filter.state,
        Event::Log { .. } => filter.logs,
        Event::Connection(_) => filter.connections,
        Event::Health { .. } => filter.health,
        Event::Lagged { .. } => true,
    }
}

/// Build the broadcast channel a handler hands out from [`ServerHandler::subscribe`].
#[must_use]
pub fn event_channel() -> (broadcast::Sender<Event>, broadcast::Receiver<Event>) {
    broadcast::channel(EVENT_CHANNEL_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;

    struct Stub {
        events: broadcast::Sender<Event>,
    }

    impl ServerHandler for Stub {
        fn handle(
            &self,
            _peer: PeerCredentials,
            request: Request,
        ) -> impl std::future::Future<Output = Result<Response, IpcError>> + Send {
            async move {
                match request {
                    Request::Ping => {
                        Ok(Response::Pong { daemon: "stub".into(), uptime_secs: 1 })
                    }
                    Request::GetMode => Ok(Response::Mode(xraytui_domain::SystemMode::Rule)),
                    Request::RemoveNode(id) => {
                        Err(IpcError::NotFound { kind: "node".into(), id: id.to_string() })
                    }
                    _ => Ok(Response::Ack),
                }
            }
        }

        fn subscribe(&self, _filter: SubscriptionFilter) -> broadcast::Receiver<Event> {
            self.events.subscribe()
        }

        fn version(&self) -> String {
            "stub/0".into()
        }
    }

    async fn start() -> (tempfile::TempDir, PathBuf, broadcast::Sender<Event>) {
        let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!("tempdir"));
        let path = dir.path().join("control.sock");
        let (events, _) = event_channel();
        let server = listen(&path).unwrap_or_else(|_| unreachable!("bind"));
        let handler = Arc::new(Stub { events: events.clone() });
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            server
                .serve(handler, async move {
                    let _ = stop_rx.await;
                })
                .await;
        });
        // Keep the stopper alive for the duration of the test process.
        std::mem::forget(stop_tx);
        (dir, path, events)
    }

    #[tokio::test]
    async fn request_and_response_round_trip() {
        let (_dir, path, _events) = start().await;
        let mut client = Client::connect(&path).await.unwrap_or_else(|_| unreachable!("connect"));
        let response = client.request(Request::Ping).await.unwrap_or_else(|_| unreachable!("ping"));
        assert!(matches!(response, Response::Pong { .. }));
        let response =
            client.request(Request::GetMode).await.unwrap_or_else(|_| unreachable!("mode"));
        assert_eq!(response, Response::Mode(xraytui_domain::SystemMode::Rule));
    }

    #[tokio::test]
    async fn structured_errors_reach_the_client() {
        let (_dir, path, _events) = start().await;
        let mut client = Client::connect(&path).await.unwrap_or_else(|_| unreachable!("connect"));
        let id = xraytui_domain::NodeId::new("missing").unwrap_or_else(|_| unreachable!("valid"));
        let error = client
            .request(Request::RemoveNode(id))
            .await
            .expect_err("must be an error");
        assert!(error.to_string().contains("node 'missing' does not exist"), "{error}");
    }

    #[tokio::test]
    async fn the_socket_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path, _events) = start().await;
        let mode = std::fs::metadata(&path)
            .unwrap_or_else(|_| unreachable!("metadata"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn a_live_socket_is_not_stolen_by_a_second_daemon() {
        let (_dir, path, _events) = start().await;
        let error = listen(&path).expect_err("must refuse");
        assert!(matches!(error, ServerError::Directory(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_stale_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!("tempdir"));
        let path = dir.path().join("control.sock");
        // A plain file standing in for a socket left by a dead daemon.
        std::fs::write(&path, b"stale").unwrap_or_else(|_| unreachable!("write"));
        let server = listen(&path).unwrap_or_else(|_| unreachable!("must replace"));
        assert_eq!(server.path(), path);
    }

    #[tokio::test]
    async fn events_stream_until_cancelled() {
        let (_dir, path, events) = start().await;
        let mut client = Client::connect(&path).await.unwrap_or_else(|_| unreachable!("connect"));
        let mut stream = client
            .subscribe(SubscriptionFilter::all())
            .await
            .unwrap_or_else(|_| unreachable!("subscribe"));

        // The subscription is registered asynchronously on the server, so a
        // one-shot publish would race it. Publishing until the reader is
        // satisfied is both non-flaky and closer to how the daemon behaves.
        let publisher = tokio::spawn(async move {
            loop {
                let _ = events.send(Event::Log {
                    at_unix_ms: 0,
                    level: "info".into(),
                    target: "test".into(),
                    message: "hello".into(),
                });
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });

        for _ in 0..3 {
            let event = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap_or_else(|_| unreachable!("no event arrived"))
                .unwrap_or_else(|| unreachable!("stream ended early"));
            assert!(matches!(event, Event::Log { .. }));
        }
        publisher.abort();
    }

    #[tokio::test]
    async fn filters_drop_unwanted_event_kinds() {
        let (_dir, path, events) = start().await;
        let mut client = Client::connect(&path).await.unwrap_or_else(|_| unreachable!("connect"));
        let mut stream = client
            .subscribe(SubscriptionFilter::state_only())
            .await
            .unwrap_or_else(|_| unreachable!("subscribe"));

        let publisher = tokio::spawn(async move {
            loop {
                let _ = events.send(Event::Log {
                    at_unix_ms: 0,
                    level: "info".into(),
                    target: "t".into(),
                    message: "ignored".into(),
                });
                let _ = events.send(Event::State(Box::new(
                    xraytui_domain::RuntimeState::default(),
                )));
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .unwrap_or_else(|_| unreachable!("no event arrived"))
            .unwrap_or_else(|| unreachable!("stream ended early"));
        assert!(matches!(event, Event::State(_)), "log event was not filtered out");
        publisher.abort();
    }

    #[tokio::test]
    async fn an_oversized_frame_closes_the_connection_rather_than_allocating() {
        use tokio::io::AsyncWriteExt;
        let (_dir, path, _events) = start().await;
        let mut raw = UnixStream::connect(&path).await.unwrap_or_else(|_| unreachable!("connect"));
        // Skip negotiation and declare an enormous frame.
        raw.write_all(&u32::MAX.to_be_bytes())
            .await
            .unwrap_or_else(|_| unreachable!("write"));
        raw.flush().await.unwrap_or_else(|_| unreachable!("flush"));
        // The server must close rather than wait for 4 GiB.
        let mut buffer = [0_u8; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut raw, &mut buffer),
        )
        .await
        .unwrap_or_else(|_| unreachable!("server did not close the connection"));
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    }

    #[tokio::test]
    async fn a_version_mismatch_is_rejected_politely() {
        let (_dir, path, _events) = start().await;
        let stream = UnixStream::connect(&path).await.unwrap_or_else(|_| unreachable!("connect"));
        let (reader, mut writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let hello = Hello { protocol_version: 999, client: "future/1".into() };
        write_frame(&mut writer, &hello, MAX_FRAME_BYTES)
            .await
            .unwrap_or_else(|_| unreachable!("write"));
        let welcome: Welcome = read_frame(&mut reader, MAX_FRAME_BYTES)
            .await
            .unwrap_or_else(|_| unreachable!("read"));
        match welcome {
            Welcome::Rejected { daemon_protocol_version, reason } => {
                assert_eq!(daemon_protocol_version, PROTOCOL_VERSION);
                assert!(reason.contains("999"), "{reason}");
            }
            other => unreachable!("expected a rejection, got {other:?}"),
        }
    }
}
