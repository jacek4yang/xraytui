//! Length-prefixed CBOR framing.
//!
//! Wire format: a 4-byte big-endian length followed by that many bytes of CBOR.
//! The length is validated **before** anything is allocated, so a hostile local
//! process cannot make the peer reserve gigabytes by lying about a frame size.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame accepted on the user control socket.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Largest frame accepted on the privileged helper socket.
///
/// Deliberately much smaller: everything the helper accepts is a short typed
/// operation, so a large frame is a bug or an attack either way.
pub const MAX_NETD_FRAME_BYTES: usize = 256 * 1024;

/// Framing failures.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer closed the connection cleanly.
    #[error("connection closed")]
    Closed,
    /// The declared length exceeded the cap.
    #[error("frame declares {declared} bytes, over the {limit} byte limit")]
    TooLarge {
        /// Length the peer declared.
        declared: usize,
        /// Cap in force.
        limit: usize,
    },
    /// A frame declared zero bytes.
    #[error("frame is empty")]
    Empty,
    /// Transport failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The body was not valid CBOR for the expected type.
    #[error("malformed message: {0}")]
    Decode(String),
    /// The value could not be encoded.
    #[error("could not encode message: {0}")]
    Encode(String),
}

/// Read one frame and decode it.
///
/// # Errors
/// Returns [`FrameError::Closed`] at a clean end of stream, and
/// [`FrameError::TooLarge`] before allocating for an oversized frame.
pub async fn read_frame<R, T>(reader: &mut R, limit: usize) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut header = [0_u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            return Err(FrameError::Closed);
        }
        Err(error) => return Err(FrameError::Io(error)),
    }

    let declared = u32::from_be_bytes(header) as usize;
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > limit {
        // Refuse before allocating. The connection is unusable afterwards
        // because the stream is out of sync, so callers close it.
        return Err(FrameError::TooLarge { declared, limit });
    }

    let mut body = vec![0_u8; declared];
    reader.read_exact(&mut body).await?;
    ciborium::from_reader(body.as_slice()).map_err(|error| FrameError::Decode(error.to_string()))
}

/// Encode and write one frame.
///
/// # Errors
/// Returns [`FrameError::TooLarge`] rather than writing a frame the peer is
/// required to reject.
pub async fn write_frame<W, T>(writer: &mut W, value: &T, limit: usize) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body)
        .map_err(|error| FrameError::Encode(error.to_string()))?;
    if body.len() > limit {
        return Err(FrameError::TooLarge { declared: body.len(), limit });
    }
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        declared: body.len(),
        limit,
    })?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Sample {
        id: u64,
        text: String,
    }

    #[tokio::test]
    async fn a_frame_round_trips() {
        let sample = Sample { id: 7, text: "hello".into() };
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &sample, MAX_FRAME_BYTES).await.expect("write");
        let mut cursor = std::io::Cursor::new(buffer);
        let back: Sample = read_frame(&mut cursor, MAX_FRAME_BYTES).await.expect("read");
        assert_eq!(back, sample);
    }

    #[tokio::test]
    async fn several_frames_stream_in_order() {
        let mut buffer = Vec::new();
        for id in 0..5 {
            let sample = Sample { id, text: format!("m{id}") };
            write_frame(&mut buffer, &sample, MAX_FRAME_BYTES).await.expect("write");
        }
        let mut cursor = std::io::Cursor::new(buffer);
        for id in 0..5 {
            let back: Sample = read_frame(&mut cursor, MAX_FRAME_BYTES).await.expect("read");
            assert_eq!(back.id, id);
        }
        let end: Result<Sample, _> = read_frame(&mut cursor, MAX_FRAME_BYTES).await;
        assert!(matches!(end, Err(FrameError::Closed)), "{end:?}");
    }

    #[tokio::test]
    async fn an_oversized_declaration_is_refused_without_allocating() {
        // Declare 4 GiB but send nothing. A reader that allocated first would
        // die here; this one must return an error immediately.
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(buffer);
        let result: Result<Sample, _> = read_frame(&mut cursor, MAX_FRAME_BYTES).await;
        assert!(
            matches!(result, Err(FrameError::TooLarge { limit: MAX_FRAME_BYTES, .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_frame_is_refused() {
        let mut cursor = std::io::Cursor::new(0_u32.to_be_bytes().to_vec());
        let result: Result<Sample, _> = read_frame(&mut cursor, MAX_FRAME_BYTES).await;
        assert!(matches!(result, Err(FrameError::Empty)), "{result:?}");
    }

    #[tokio::test]
    async fn a_truncated_body_is_an_error_not_a_hang() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &Sample { id: 1, text: "x".into() }, MAX_FRAME_BYTES)
            .await
            .expect("write");
        buffer.truncate(buffer.len() - 1);
        let mut cursor = std::io::Cursor::new(buffer);
        let result: Result<Sample, _> = read_frame(&mut cursor, MAX_FRAME_BYTES).await;
        assert!(result.is_err(), "{result:?}");
    }

    #[tokio::test]
    async fn garbage_bodies_are_decode_errors() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&4_u32.to_be_bytes());
        buffer.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let mut cursor = std::io::Cursor::new(buffer);
        let result: Result<Sample, _> = read_frame(&mut cursor, MAX_FRAME_BYTES).await;
        assert!(matches!(result, Err(FrameError::Decode(_))), "{result:?}");
    }

    #[tokio::test]
    async fn writing_over_the_limit_is_refused() {
        let sample = Sample { id: 1, text: "x".repeat(1024) };
        let mut buffer = Vec::new();
        let result = write_frame(&mut buffer, &sample, 64).await;
        assert!(matches!(result, Err(FrameError::TooLarge { limit: 64, .. })), "{result:?}");
        assert!(buffer.is_empty(), "nothing may be written for a refused frame");
    }

    #[tokio::test]
    async fn the_netd_limit_is_much_smaller_than_the_user_limit() {
        assert!(MAX_NETD_FRAME_BYTES < MAX_FRAME_BYTES / 8);
    }
}
