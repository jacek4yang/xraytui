//! The helper socket: framed CBOR with file descriptors attached.
//!
//! The user-facing control socket (`xraytui-ipc`) carries no descriptors, so it
//! can use ordinary reads and writes. The helper socket must carry two:
//!
//! * the **TUN descriptor**, returned to the daemon as a liveness handle — when
//!   the daemon dies the kernel closes it, and that is what makes teardown
//!   automatic rather than dependent on a timeout;
//! * a **`pidfd`**, sent by the daemon to say *this exact process*, which a
//!   process id could not do without a race.
//!
//! # Framing
//!
//! A four-byte big-endian length, then that many bytes of CBOR. The length is
//! checked against [`MAX_FRAME`] *before* anything is allocated, so a hostile
//! or broken peer cannot ask the helper to reserve memory it does not have.
//!
//! Descriptors ride on the `sendmsg` that carries the length prefix. Four bytes
//! are written atomically by any Unix stream socket, so the descriptors and the
//! message they belong to cannot be separated by a partial write.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::Interest;
use tokio::net::UnixStream;
use xraytui_netd_protocol::{NetdReply, NetdRequest, Operation, Outcome};

/// Largest helper message. Requests here are lists of prefixes and marks; a
/// quarter of a megabyte is already far more than any of them need.
pub const MAX_FRAME: usize = 256 * 1024;

/// Most descriptors any single message carries.
const MAX_FDS: usize = 2;

/// Errors the helper transport can report.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The socket could not be reached.
    #[error("cannot reach the helper at {path}: {source}")]
    Connect {
        /// Socket path.
        path: String,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A read or write failed.
    #[error("helper socket: {0}")]
    Io(#[from] std::io::Error),
    /// The peer closed the connection.
    #[error("the helper closed the connection")]
    Closed,
    /// A frame declared a length that is not acceptable.
    #[error("frame of {declared} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge {
        /// What the peer asked for.
        declared: usize,
    },
    /// A message could not be encoded.
    #[error("cannot encode a helper message: {0}")]
    Encode(String),
    /// A message could not be decoded.
    #[error("cannot decode a helper message: {0}")]
    Decode(String),
    /// The helper answered a different request.
    #[error("the helper answered request {answered}, not {expected}")]
    Mismatch {
        /// What came back.
        answered: u64,
        /// What was asked.
        expected: u64,
    },
    /// The helper refused the operation.
    #[error(transparent)]
    Refused(#[from] xraytui_netd_protocol::NetdError),
}

/// Send a value, optionally attaching descriptors.
///
/// # Errors
/// See [`TransportError`].
pub async fn send_message<T: Serialize>(
    stream: &UnixStream,
    value: &T,
    descriptors: &[BorrowedFd<'_>],
) -> Result<(), TransportError> {
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body)
        .map_err(|error| TransportError::Encode(error.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(TransportError::TooLarge {
            declared: body.len(),
        });
    }
    let prefix = u32::try_from(body.len())
        .map_err(|_| TransportError::TooLarge {
            declared: body.len(),
        })?
        .to_be_bytes();

    if descriptors.is_empty() {
        write_all(stream, &prefix).await?;
        write_all(stream, &body).await?;
        return Ok(());
    }

    let limited = &descriptors[..descriptors.len().min(MAX_FDS)];
    stream
        .async_io(Interest::WRITABLE, || {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            // A buffer sized for MAX_FDS always has room for `limited`.
            let _ = ancillary.push(SendAncillaryMessage::ScmRights(limited));
            let written = rustix::net::sendmsg(
                stream,
                &[IoSlice::new(&prefix)],
                &mut ancillary,
                SendFlags::empty(),
            )?;
            if written == prefix.len() {
                Ok(())
            } else {
                // A four-byte write on a Unix stream socket is atomic; a short
                // write means the socket is in a state we should not paper over.
                Err(std::io::Error::other(
                    "the helper socket accepted a partial length prefix",
                ))
            }
        })
        .await?;

    write_all(stream, &body).await?;
    Ok(())
}

/// Write every byte, through a shared reference to the socket.
///
/// `tokio`'s `AsyncWrite` for `UnixStream` needs `&mut self`, which the
/// descriptor-passing path cannot give: it borrows the same socket immutably to
/// call `sendmsg`. Readiness plus a raw `send` gives the same behaviour without
/// splitting the socket, and keeps both halves of a message on one code path.
async fn write_all(stream: &UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let written = stream
            .async_io(Interest::WRITABLE, || {
                rustix::net::send(stream, &bytes[offset..], SendFlags::empty())
                    .map_err(std::io::Error::from)
            })
            .await?;
        if written == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        offset += written;
    }
    Ok(())
}

/// Read exactly `buffer.len()` bytes, through a shared reference to the socket.
async fn read_exact(stream: &UnixStream, buffer: &mut [u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        let read = stream
            .async_io(Interest::READABLE, || {
                rustix::net::recv(stream, &mut buffer[offset..], RecvFlags::empty())
                    .map(|(read, _)| read)
                    .map_err(std::io::Error::from)
            })
            .await?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        offset += read;
    }
    Ok(())
}

/// Receive a value and any descriptors that came with it.
///
/// # Errors
/// See [`TransportError`].
pub async fn receive_message<T: DeserializeOwned>(
    stream: &UnixStream,
) -> Result<(T, Vec<OwnedFd>), TransportError> {
    let mut prefix = [0u8; 4];
    let mut descriptors = Vec::new();

    let read = stream
        .async_io(Interest::READABLE, || {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let result = rustix::net::recvmsg(
                stream,
                &mut [IoSliceMut::new(&mut prefix)],
                &mut ancillary,
                RecvFlags::empty(),
            )?;
            let mut received = Vec::new();
            for message in ancillary.drain() {
                if let RecvAncillaryMessage::ScmRights(fds) = message {
                    received.extend(fds);
                }
            }
            Ok((result.bytes, received))
        })
        .await
        .map(|(bytes, fds)| {
            descriptors = fds;
            bytes
        })?;

    if read == 0 {
        return Err(TransportError::Closed);
    }
    if read < prefix.len() {
        // Read the rest of the prefix without ancillary data; descriptors, if
        // any, already arrived with the first byte.
        read_exact(stream, &mut prefix[read..]).await?;
    }

    let declared = u32::from_be_bytes(prefix) as usize;
    if declared > MAX_FRAME {
        return Err(TransportError::TooLarge { declared });
    }
    let mut body = vec![0u8; declared];
    read_exact(stream, &mut body).await?;
    let value = ciborium::from_reader(body.as_slice())
        .map_err(|error| TransportError::Decode(error.to_string()))?;
    Ok((value, descriptors))
}

/// The daemon's side of the helper socket.
///
/// Deliberately thin: it holds a connection, numbers requests and returns the
/// helper's answer. All of the policy lives in the helper, where the privilege
/// is.
#[derive(Debug)]
pub struct NetdClient {
    stream: UnixStream,
    next_id: u64,
}

impl NetdClient {
    /// Connect to the helper.
    ///
    /// # Errors
    /// [`TransportError::Connect`] if the socket is absent — which is the
    /// normal state on a machine where the helper is not installed, and the
    /// caller is expected to degrade rather than fail.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path)
            .await
            .map_err(|source| TransportError::Connect {
                path: path.display().to_string(),
                source,
            })?;
        Ok(Self { stream, next_id: 0 })
    }

    /// Wrap an already-connected socket. Used by the tests.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        Self { stream, next_id: 0 }
    }

    /// Send one operation and wait for its outcome.
    ///
    /// # Errors
    /// [`TransportError::Refused`] carries the helper's own reason.
    pub async fn call(&mut self, operation: Operation) -> Result<Outcome, TransportError> {
        self.call_with(operation, &[])
            .await
            .map(|(outcome, _)| outcome)
    }

    /// Send one operation, attaching descriptors, and collect any that come back.
    ///
    /// # Errors
    /// See [`TransportError`].
    pub async fn call_with(
        &mut self,
        operation: Operation,
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(Outcome, Vec<OwnedFd>), TransportError> {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let id = self.next_id;
        let request = NetdRequest {
            id,
            protocol_version: xraytui_netd_protocol::NETD_PROTOCOL_VERSION,
            operation,
        };
        send_message(&self.stream, &request, descriptors).await?;
        let (reply, received): (NetdReply, Vec<OwnedFd>) = receive_message(&self.stream).await?;
        if reply.id != id {
            return Err(TransportError::Mismatch {
                answered: reply.id,
                expected: id,
            });
        }
        let outcome = reply.result?;
        Ok((outcome, received))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_netd_protocol::NetdError;

    #[tokio::test]
    async fn a_message_round_trips_without_descriptors() {
        let (left, right) = UnixStream::pair().expect("socket pair");
        let request = NetdRequest {
            id: 7,
            protocol_version: 1,
            operation: Operation::Ping,
        };
        send_message(&left, &request, &[]).await.expect("send");
        let (received, fds): (NetdRequest, Vec<OwnedFd>) =
            receive_message(&right).await.expect("receive");
        assert_eq!(received, request);
        assert!(fds.is_empty());
    }

    #[tokio::test]
    async fn a_descriptor_arrives_with_its_message() {
        let (left, right) = UnixStream::pair().expect("socket pair");
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), b"proof").expect("write");
        let handle = std::fs::File::open(file.path()).expect("open");

        let request = NetdRequest {
            id: 1,
            protocol_version: 1,
            operation: Operation::DeleteTun,
        };
        send_message(&left, &request, &[std::os::fd::AsFd::as_fd(&handle)])
            .await
            .expect("send");

        let (received, fds): (NetdRequest, Vec<OwnedFd>) =
            receive_message(&right).await.expect("receive");
        assert_eq!(received.id, 1);
        assert_eq!(fds.len(), 1);

        // The descriptor really refers to the same file.
        use std::io::Read as _;
        let mut reopened = std::fs::File::from(fds.into_iter().next().expect("one fd"));
        let mut contents = String::new();
        reopened.read_to_string(&mut contents).expect("read");
        assert_eq!(contents, "proof");
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_before_anything_is_allocated() {
        let (left, right) = UnixStream::pair().expect("socket pair");
        // Claim four gigabytes without sending them.
        write_all(&left, &u32::MAX.to_be_bytes())
            .await
            .expect("write");
        let error = receive_message::<NetdRequest>(&right)
            .await
            .expect_err("must refuse");
        assert!(
            matches!(error, TransportError::TooLarge { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_closed_peer_is_reported_as_closed() {
        let (left, right) = UnixStream::pair().expect("socket pair");
        drop(left);
        let error = receive_message::<NetdRequest>(&right)
            .await
            .expect_err("must fail");
        assert!(matches!(error, TransportError::Closed), "{error:?}");
    }

    #[tokio::test]
    async fn the_client_rejects_a_reply_to_a_different_request() {
        let (left, right) = UnixStream::pair().expect("socket pair");
        let mut client = NetdClient::from_stream(left);
        let responder = tokio::spawn(async move {
            let (_request, _fds): (NetdRequest, Vec<OwnedFd>) =
                receive_message(&right).await.expect("receive");
            let reply = NetdReply {
                id: 999,
                result: Ok(Outcome::Ack),
            };
            send_message(&right, &reply, &[]).await.expect("send");
        });
        let error = client.call(Operation::Ping).await.expect_err("mismatch");
        assert!(
            matches!(error, TransportError::Mismatch { .. }),
            "{error:?}"
        );
        responder.await.expect("responder");
    }

    #[tokio::test]
    async fn a_refusal_reaches_the_caller_with_its_reason() {
        let (left, right) = UnixStream::pair().expect("socket pair");
        let mut client = NetdClient::from_stream(left);
        let responder = tokio::spawn(async move {
            let (request, _fds): (NetdRequest, Vec<OwnedFd>) =
                receive_message(&right).await.expect("receive");
            let reply = NetdReply {
                id: request.id,
                result: Err(NetdError::NoLease),
            };
            send_message(&right, &reply, &[]).await.expect("send");
        });
        let error = client.call(Operation::Release).await.expect_err("refused");
        assert!(
            matches!(error, TransportError::Refused(NetdError::NoLease)),
            "{error:?}"
        );
        responder.await.expect("responder");
    }

    #[tokio::test]
    async fn connecting_to_a_missing_socket_is_an_ordinary_error() {
        let error = NetdClient::connect("/nonexistent/netd.sock")
            .await
            .expect_err("must fail");
        assert!(matches!(error, TransportError::Connect { .. }), "{error:?}");
    }
}
