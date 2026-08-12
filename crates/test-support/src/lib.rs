//! Test doubles for xraytui.
//!
//! Everything here is local. No test in this repository requires a public proxy,
//! a public DNS resolver or internet access.
//!
//! The central idea is the [`MockEgress`]: a minimal SOCKS5 server that ignores
//! the requested destination and connects to its own identity service instead.
//! A client that fetches any URL through egress `A` gets back `EGRESS A`, so a
//! test can *prove* which proxy a connection actually traversed rather than
//! inferring it from timing or logs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub mod fixtures;
pub mod http_fixture;

pub use http_fixture::HttpFixtureServer;


/// Bind an ephemeral loopback port and return it.
///
/// The listener is dropped before returning, so there is a small race window.
/// Tests that must not race bind the listener themselves; this helper exists for
/// configuration that needs a port number before the server is constructed.
///
/// # Errors
/// Propagates the bind failure.
pub fn free_port() -> io::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.local_addr().map(|a| a.port())
}

/// A locally distinguishable egress.
///
/// Two servers are started:
///
/// * an **identity** TCP service that writes `EGRESS <name>\n` and closes;
/// * a **SOCKS5** front end that accepts any CONNECT request and splices the
///   client to the identity service, whatever destination was asked for.
///
/// Pointing an Xray `socks` outbound at the SOCKS5 port therefore makes the
/// egress identity observable end to end.
pub struct MockEgress {
    name: String,
    mode: EgressMode,
    socks_addr: SocketAddr,
    identity_addr: SocketAddr,
    connections: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

/// What the SOCKS5 front end does with a CONNECT request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    /// Ignore the requested destination and splice to this egress's own identity
    /// service. Use for an exit node, where the point is to observe *which*
    /// egress the traffic left through.
    Identify,
    /// Connect to the destination that was actually requested. Use for an
    /// intermediate chain hop, where the traffic has to keep travelling.
    Forward,
}

impl MockEgress {
    /// Start an identifying egress named `name`.
    ///
    /// # Errors
    /// Propagates bind failures.
    pub async fn start(name: impl Into<String>) -> io::Result<Self> {
        Self::start_with_mode(name, EgressMode::Identify).await
    }

    /// Start a faithfully forwarding egress, for use as an intermediate hop.
    ///
    /// A chain can only be proven with one of these in front: an identifying
    /// egress would swallow the connection at the first hop, so reaching the
    /// exit would be indistinguishable from never leaving hop one.
    ///
    /// # Errors
    /// Propagates bind failures.
    pub async fn start_forwarding(name: impl Into<String>) -> io::Result<Self> {
        Self::start_with_mode(name, EgressMode::Forward).await
    }

    /// Start an egress with an explicit mode.
    ///
    /// # Errors
    /// Propagates bind failures.
    pub async fn start_with_mode(name: impl Into<String>, mode: EgressMode) -> io::Result<Self> {
        let name = name.into();

        let identity_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let identity_addr = identity_listener.local_addr()?;
        let banner = format!("EGRESS {name}\n");
        let identity_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = identity_listener.accept().await else {
                    return;
                };
                let banner = banner.clone();
                tokio::spawn(async move {
                    // Consume whatever the client sends (an HTTP request line, a
                    // bare probe byte, nothing at all) before answering, so the
                    // service works for both raw and HTTP-shaped probes.
                    let mut scratch = [0_u8; 1024];
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(200),
                        stream.read(&mut scratch),
                    )
                    .await;
                    let _ = stream.write_all(banner.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });

        let socks_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let socks_addr = socks_listener.local_addr()?;
        let connections = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&connections);
        let socks_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = socks_listener.accept().await else {
                    return;
                };
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _ = serve_socks5(stream, identity_addr, mode).await;
                });
            }
        });

        Ok(Self {
            name,
            mode,
            socks_addr,
            identity_addr,
            connections,
            tasks: vec![identity_task, socks_task],
        })
    }

    /// Egress name, as it appears in the identity banner.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Address of the SOCKS5 front end, to be used as a node endpoint.
    #[must_use]
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// Address of the identity service.
    #[must_use]
    pub fn identity_addr(&self) -> SocketAddr {
        self.identity_addr
    }

    /// The banner a client reaching this egress will read.
    #[must_use]
    pub fn banner(&self) -> String {
        format!("EGRESS {}\n", self.name)
    }

    /// How many SOCKS connections have been accepted.
    #[must_use]
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// What this egress does with a CONNECT request.
    #[must_use]
    pub fn mode(&self) -> EgressMode {
        self.mode
    }
}

impl Drop for MockEgress {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Minimal SOCKS5 server: no authentication, CONNECT only.
async fn serve_socks5(
    mut client: TcpStream,
    identity: SocketAddr,
    mode: EgressMode,
) -> io::Result<()> {
    let mut requested_host = String::new();
    let mut requested_port: u16 = 0;
    // Greeting: VER NMETHODS METHODS...
    let mut header = [0_u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let mut methods = vec![0_u8; usize::from(header[1])];
    client.read_exact(&mut methods).await?;
    // Select "no authentication".
    client.write_all(&[0x05, 0x00]).await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await?;
    if request[1] != 0x01 {
        // Only CONNECT is implemented; reply "command not supported".
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    }
    match request[3] {
        0x01 => {
            let mut address = [0_u8; 4];
            client.read_exact(&mut address).await?;
            requested_host = std::net::Ipv4Addr::from(address).to_string();
        }
        0x03 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length).await?;
            let mut host = vec![0_u8; usize::from(length[0])];
            client.read_exact(&mut host).await?;
            requested_host = String::from_utf8_lossy(&host).into_owned();
        }
        0x04 => {
            let mut address = [0_u8; 16];
            client.read_exact(&mut address).await?;
            requested_host = std::net::Ipv6Addr::from(address).to_string();
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    }
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    requested_port = u16::from_be_bytes(port);

    let upstream = match mode {
        // Substituting the identity service for the requested destination is
        // what makes the egress observable end to end.
        EgressMode::Identify => TcpStream::connect(identity).await,
        EgressMode::Forward => {
            TcpStream::connect((requested_host.as_str(), requested_port)).await
        }
    };
    let mut upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            // SOCKS5 "host unreachable".
            client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(error);
        }
    };

    // Success, bound address 0.0.0.0:0.
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Perform a SOCKS5 CONNECT through `proxy` and read the reply.
///
/// Returns whatever the far side wrote, which for a [`MockEgress`] is its banner.
///
/// # Errors
/// Propagates I/O failures and SOCKS protocol errors.
pub async fn probe_through_socks5(
    proxy: SocketAddr,
    request_host: &str,
    request_port: u16,
) -> io::Result<String> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 handshake refused"));
    }

    let host = request_host.as_bytes();
    if host.len() > 255 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "hostname too long"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&request_port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(io::Error::other(format!("SOCKS5 CONNECT failed with code {}", reply[1])));
    }
    match reply[3] {
        0x01 => {
            let mut skip = [0_u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut skip = vec![0_u8; usize::from(length[0]) + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0_u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        other => {
            return Err(io::Error::other(format!("unexpected SOCKS5 address type {other}")));
        }
    }

    // Nudge the far side, then read its answer.
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
    let mut response = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut response),
    )
    .await;
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "no answer from egress")),
    }
    Ok(String::from_utf8_lossy(&response).into_owned())
}

/// Perform an HTTP CONNECT through an HTTP proxy and read the reply.
///
/// # Errors
/// Propagates I/O failures and non-2xx CONNECT responses.
pub async fn probe_through_http_connect(
    proxy: SocketAddr,
    request_host: &str,
    request_port: u16,
) -> io::Result<String> {
    let mut stream = TcpStream::connect(proxy).await?;
    let request = format!(
        "CONNECT {request_host}:{request_port} HTTP/1.1\r\nHost: {request_host}:{request_port}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    // Read just the status line and headers.
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut byte),
        )
        .await;
        match read {
            Ok(Ok(_)) => header.push(byte[0]),
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no CONNECT response"));
            }
        }
        if header.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "CONNECT response too large"));
        }
    }
    let status = String::from_utf8_lossy(&header);
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return Err(io::Error::other(format!(
            "CONNECT refused: {}",
            status.lines().next().unwrap_or_default()
        )));
    }

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
    let mut response = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut response),
    )
    .await;
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "no answer from egress")),
    }
    Ok(String::from_utf8_lossy(&response).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn egress_identifies_itself_through_socks5() {
        let egress = MockEgress::start("alpha").await.expect("start egress");
        let answer = probe_through_socks5(egress.socks_addr(), "irrelevant.invalid", 80)
            .await
            .expect("probe");
        assert!(answer.contains("EGRESS alpha"), "{answer:?}");
        assert_eq!(egress.connection_count(), 1);
    }

    #[tokio::test]
    async fn two_egresses_are_distinguishable() {
        let a = MockEgress::start("a").await.expect("start a");
        let b = MockEgress::start("b").await.expect("start b");
        let answer_a = probe_through_socks5(a.socks_addr(), "x.invalid", 80).await.expect("probe a");
        let answer_b = probe_through_socks5(b.socks_addr(), "x.invalid", 80).await.expect("probe b");
        assert!(answer_a.contains("EGRESS a"), "{answer_a:?}");
        assert!(answer_b.contains("EGRESS b"), "{answer_b:?}");
        assert_ne!(answer_a, answer_b);
    }

    #[test]
    fn free_port_returns_a_usable_port() {
        let port = free_port().expect("port");
        assert!(port > 0);
    }
}
