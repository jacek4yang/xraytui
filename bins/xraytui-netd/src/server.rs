//! The helper's socket: accept, identify, apply, tidy up.
//!
//! # What identifies a caller
//!
//! `SO_PEERCRED`, read once when the connection is accepted, and nothing else.
//! The uid it yields is passed to [`Engine::handle`] for every operation on that
//! connection; no message carries a uid, so there is nothing to spoof. The pid
//! in the credential is used for log lines only — it can be recycled, so it is
//! never an input to a decision.
//!
//! # What happens when a caller goes away
//!
//! The kernel closes the socket. That is the *primary* teardown signal, and it
//! is immediate. The lease deadline is the backstop for the other failure —
//! this helper being killed — and is swept on a timer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::net::{UnixListener, UnixStream};
use xraytui_linux_net::transport::{TransportError, receive_message, send_message};
use xraytui_linux_net::{Engine, lease};
use xraytui_netd_protocol::{NetdError, NetdReply, NetdRequest, Operation};

use crate::notify;

/// How the server is configured.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Where to listen.
    pub socket: PathBuf,
    /// Group that may reach the socket.
    pub group: Option<String>,
    /// How often to sweep expired leases.
    pub reap_interval: Duration,
}

/// Tracks how many live connections each uid has.
///
/// Teardown happens when the *last* one closes: a user may legitimately run
/// `xraytui tun status` alongside their daemon, and the short-lived connection
/// closing must not pull the tunnel out from under the long-lived one.
#[derive(Debug, Default)]
struct Connections {
    per_uid: std::sync::Mutex<HashMap<u32, usize>>,
}

impl Connections {
    fn open(&self, uid: u32) {
        if let Ok(mut map) = self.per_uid.lock() {
            *map.entry(uid).or_insert(0) += 1;
        }
    }

    /// Decrement, returning true when this was the last connection for the uid.
    fn close(&self, uid: u32) -> bool {
        let Ok(mut map) = self.per_uid.lock() else {
            return false;
        };
        match map.get_mut(&uid) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => {
                map.remove(&uid);
                true
            }
            None => false,
        }
    }
}

/// Listen and serve until the process is asked to stop.
///
/// # Errors
/// Fails only for conditions that make serving impossible: the socket path
/// cannot be created, or the listener cannot be bound.
pub async fn serve(engine: Engine, options: ServerOptions) -> anyhow::Result<()> {
    let listener = bind(&options)?;
    let engine = Arc::new(engine);
    let connections = Arc::new(Connections::default());

    // Reconcile before announcing readiness: state left by a previous run must
    // not outlive the run that created it.
    let recovered = engine.recover(lease::now());
    for item in &recovered {
        tracing::info!(item, "removed state left by a previous run");
    }

    notify::ready(&format!("listening on {}", options.socket.display()));
    tracing::info!(socket = %options.socket.display(), "xraytui-netd is serving");

    let reaper = tokio::spawn({
        let engine = Arc::clone(&engine);
        let interval = options.reap_interval;
        async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let engine = Arc::clone(&engine);
                let removed =
                    tokio::task::spawn_blocking(move || engine.recover(lease::now())).await;
                match removed {
                    Ok(items) => {
                        for item in items {
                            tracing::warn!(item, "reclaimed after a lease expired");
                        }
                    }
                    Err(error) => tracing::error!(%error, "the lease sweep panicked"),
                }
            }
        }
    });

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install the SIGTERM handler")?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("install the SIGINT handler")?;

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let engine = Arc::clone(&engine);
                    let connections = Arc::clone(&connections);
                    tokio::spawn(async move {
                        if let Err(error) = handle(stream, engine, connections).await {
                            tracing::debug!(%error, "connection ended");
                        }
                    });
                }
                Err(error) => {
                    tracing::error!(%error, "cannot accept on the helper socket");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }

    notify::stopping();
    reaper.abort();
    tracing::info!("xraytui-netd is stopping; project-owned state stays until its lease lapses");
    let _ = std::fs::remove_file(&options.socket);
    Ok(())
}

fn bind(options: &ServerOptions) -> anyhow::Result<UnixListener> {
    if let Some(parent) = options.socket.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // A stale socket from a previous run would otherwise make the bind fail.
    // Removing it is safe because only root can write this directory.
    match std::fs::metadata(&options.socket) {
        Ok(_) => {
            let _ = std::fs::remove_file(&options.socket);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", options.socket.display()));
        }
    }

    let listener = UnixListener::bind(&options.socket)
        .with_context(|| format!("bind {}", options.socket.display()))?;

    // The filesystem is the first gate and the credential check is the second.
    // Without a group, the socket stays root-only, which is the safe default for
    // a helper started by hand.
    let mode = if options.group.is_some() {
        0o660
    } else {
        0o600
    };
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&options.socket, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("set the mode of {}", options.socket.display()))?;

    if let Some(group) = &options.group {
        match group_id(group) {
            Some(gid) => {
                rustix::fs::chown(&options.socket, None, Some(unsafe_free_gid(gid))).with_context(
                    || format!("give {} to group {group}", options.socket.display()),
                )?;
            }
            None => {
                tracing::warn!(
                    group,
                    "the group does not exist; the socket stays root-only"
                );
                std::fs::set_permissions(&options.socket, std::fs::Permissions::from_mode(0o600))
                    .ok();
            }
        }
    }
    Ok(listener)
}

/// Look a group up in `/etc/group`.
///
/// Reading the file avoids linking NSS into the privileged binary. A machine
/// using LDAP or SSSD for groups will not find `xraytui` this way, which is why
/// a missing group leaves the socket root-only and says so rather than opening
/// it up.
fn group_id(name: &str) -> Option<u32> {
    let contents = std::fs::read_to_string("/etc/group").ok()?;
    for line in contents.lines() {
        let mut fields = line.split(':');
        if fields.next()? == name {
            let _password = fields.next()?;
            return fields.next()?.parse().ok();
        }
    }
    None
}

fn unsafe_free_gid(gid: u32) -> rustix::fs::Gid {
    // `Gid::from_raw` is a plain newtype conversion in rustix and needs no
    // unsafe; the name here only marks that the value came from a text file.
    rustix::fs::Gid::from_raw(gid)
}

async fn handle(
    stream: UnixStream,
    engine: Arc<Engine>,
    connections: Arc<Connections>,
) -> Result<(), TransportError> {
    let credentials = stream.peer_cred().map_err(TransportError::Io)?;
    let uid = credentials.uid();
    connections.open(uid);
    tracing::debug!(uid, pid = ?credentials.pid(), "helper connection opened");

    let result = converse(&stream, uid, &engine).await;

    if connections.close(uid) {
        // The owner is gone. Release now rather than waiting for the lease: a
        // machine that has lost its proxy should not keep a tunnel that nothing
        // is feeding.
        let engine = Arc::clone(&engine);
        let released = tokio::task::spawn_blocking(move || engine.release(uid)).await;
        match released {
            Ok(Ok(removed)) if !removed.is_empty() => {
                for item in removed {
                    tracing::info!(uid, item, "released after the last connection closed");
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::error!(uid, %error, "release failed"),
            Err(error) => tracing::error!(uid, %error, "the release task panicked"),
        }
    }
    result
}

async fn converse(
    stream: &UnixStream,
    uid: u32,
    engine: &Arc<Engine>,
) -> Result<(), TransportError> {
    loop {
        let (request, descriptors): (NetdRequest, Vec<std::os::fd::OwnedFd>) =
            match receive_message(stream).await {
                Ok(message) => message,
                Err(TransportError::Closed) => return Ok(()),
                Err(error) => return Err(error),
            };

        if request.protocol_version != xraytui_netd_protocol::NETD_PROTOCOL_VERSION {
            let reply = NetdReply {
                id: request.id,
                result: Err(NetdError::Version {
                    helper: xraytui_netd_protocol::NETD_PROTOCOL_VERSION,
                    caller: request.protocol_version,
                }),
            };
            send_message(stream, &reply, &[]).await?;
            return Ok(());
        }

        let name = request.operation.name();
        let mutating = request.operation.is_mutating();
        let descriptor = descriptors.into_iter().next();
        let engine = Arc::clone(engine);
        let operation = request.operation;
        let applied =
            tokio::task::spawn_blocking(move || engine.handle(uid, &operation, descriptor)).await;

        let (result, returned) = match applied {
            Ok(Ok(response)) => {
                if mutating {
                    tracing::info!(uid, operation = name, "applied");
                }
                (Ok(response.outcome), response.descriptor)
            }
            Ok(Err(error)) => {
                tracing::info!(uid, operation = name, %error, "refused");
                (Err(error), None)
            }
            Err(error) => {
                tracing::error!(uid, operation = name, %error, "the operation task panicked");
                (
                    Err(NetdError::Internal(
                        "the helper failed while applying this operation".into(),
                    )),
                    None,
                )
            }
        };

        let reply = NetdReply {
            id: request.id,
            result,
        };
        match &returned {
            Some(handle) => {
                send_message(stream, &reply, &[std::os::fd::AsFd::as_fd(handle)]).await?;
            }
            None => send_message(stream, &reply, &[]).await?,
        }

        if matches!(request_kind(name), RequestKind::Terminal) {
            notify::status("idle");
        }
    }
}

enum RequestKind {
    Ordinary,
    Terminal,
}

fn request_kind(name: &str) -> RequestKind {
    if name == Operation::Release.name() {
        RequestKind::Terminal
    } else {
        RequestKind::Ordinary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_connection_closing_is_the_one_that_triggers_release() {
        let connections = Connections::default();
        connections.open(1000);
        connections.open(1000);
        assert!(!connections.close(1000), "the first close must not release");
        assert!(connections.close(1000), "the last close must release");
        assert!(
            !connections.close(1000),
            "closing again must not release twice"
        );
    }

    #[test]
    fn connections_from_different_users_are_counted_separately() {
        let connections = Connections::default();
        connections.open(1000);
        connections.open(1001);
        assert!(connections.close(1000));
        assert!(connections.close(1001));
    }

    #[test]
    fn a_group_that_exists_resolves_and_one_that_does_not_returns_none() {
        // `root` exists on every system this targets.
        assert_eq!(group_id("root"), Some(0));
        assert_eq!(group_id("a-group-that-does-not-exist-4242"), None);
    }

    #[tokio::test]
    async fn without_a_group_the_socket_is_root_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("temp dir");
        let options = ServerOptions {
            socket: dir.path().join("netd.sock"),
            group: None,
            reap_interval: Duration::from_secs(5),
        };
        let _listener = bind(&options).expect("bind");
        let mode = std::fs::metadata(&options.socket)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn a_stale_socket_from_a_previous_run_is_replaced() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("netd.sock");
        std::fs::write(&path, b"stale").expect("write");
        let options = ServerOptions {
            socket: path,
            group: None,
            reap_interval: Duration::from_secs(5),
        };
        assert!(bind(&options).is_ok());
    }

    #[tokio::test]
    async fn an_unknown_group_leaves_the_socket_root_only_rather_than_open() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("temp dir");
        let options = ServerOptions {
            socket: dir.path().join("netd.sock"),
            group: Some("a-group-that-does-not-exist-4242".into()),
            reap_interval: Duration::from_secs(5),
        };
        let _listener = bind(&options).expect("bind");
        let mode = std::fs::metadata(&options.socket)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
