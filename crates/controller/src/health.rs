//! Connectivity probes.
//!
//! A probe measures the *usable path*, not the reachability of a server: it
//! opens a connection through the profile's own SOCKS listener and asks for the
//! configured test URL. ICMP is never used — Xray's TUN has no ICMP support at
//! all, and a server that answers ping may still refuse to proxy.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use xraytui_domain::{ProbeKind, ProbeOutcome, ProbeResult};

/// One probe to run.
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// Loopback SOCKS listener to go through.
    pub socks: SocketAddr,
    /// Host to ask the proxy for.
    pub host: String,
    /// Port to ask the proxy for.
    pub port: u16,
    /// Optional HTTP request path; when set, a small GET is issued.
    pub http_path: Option<String>,
    /// Deadline for the whole probe.
    pub timeout: Duration,
}

impl ProbeRequest {
    /// Build a request from a test URL.
    ///
    /// Returns `None` when the URL is not http/https or has no host.
    #[must_use]
    pub fn from_url(socks: SocketAddr, url: &str, timeout: Duration) -> Option<Self> {
        let parsed = url::Url::parse(url).ok()?;
        let host = parsed.host_str()?.to_owned();
        let port = parsed.port_or_known_default()?;
        match parsed.scheme() {
            "http" | "https" => {}
            _ => return None,
        }
        Some(Self {
            socks,
            host,
            port,
            http_path: Some(parsed.path().to_owned()),
            timeout,
        })
    }

    /// Which probe kind this request represents.
    #[must_use]
    pub fn kind(&self) -> ProbeKind {
        if self.http_path.is_some() {
            ProbeKind::HttpRequest
        } else {
            ProbeKind::TcpConnect
        }
    }
}

/// Run one probe through a local SOCKS5 listener.
///
/// The whole operation is wrapped in a single deadline, so a wedged proxy cannot
/// hold a probe slot open indefinitely.
pub async fn probe_through_socks(request: &ProbeRequest) -> ProbeResult {
    let started = Instant::now();
    let outcome = match tokio::time::timeout(request.timeout, run(request)).await {
        Ok(Ok(())) => ProbeOutcome::Ok,
        Ok(Err(outcome)) => outcome,
        Err(_) => ProbeOutcome::Timeout,
    };
    let latency = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    ProbeResult {
        at_unix_ms: unix_millis(),
        latency_ms: matches!(outcome, ProbeOutcome::Ok).then_some(latency),
        outcome,
        kind: request.kind(),
    }
}

async fn run(request: &ProbeRequest) -> Result<(), ProbeOutcome> {
    let mut stream = TcpStream::connect(request.socks)
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;

    // SOCKS5 greeting, no authentication.
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;
    if greeting != [0x05, 0x00] {
        return Err(ProbeOutcome::ConnectFailed {
            detail: "local SOCKS listener refused the handshake".into(),
        });
    }

    // CONNECT to a domain name, so the proxy resolves it remotely.
    let host = request.host.as_bytes();
    let length = u8::try_from(host.len()).map_err(|_| ProbeOutcome::NotRun {
        reason: "test URL hostname is longer than 255 bytes".into(),
    })?;
    let mut connect = vec![0x05, 0x01, 0x00, 0x03, length];
    connect.extend_from_slice(host);
    connect.extend_from_slice(&request.port.to_be_bytes());
    stream
        .write_all(&connect)
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;

    let mut reply = [0_u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;
    if reply.first() != Some(&0x05) {
        return Err(ProbeOutcome::ConnectFailed { detail: "not a SOCKS5 reply".into() });
    }
    match reply.get(1) {
        Some(0x00) => {}
        Some(code) => {
            return Err(ProbeOutcome::ConnectFailed {
                detail: format!("proxy refused with SOCKS5 code {code}"),
            });
        }
        None => return Err(ProbeOutcome::ConnectFailed { detail: "truncated reply".into() }),
    }
    // Consume the bound address.
    let skip = match reply.get(3) {
        Some(0x01) => 6,
        Some(0x04) => 18,
        Some(0x03) => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;
            usize::from(length.first().copied().unwrap_or(0)) + 2
        }
        _ => return Err(ProbeOutcome::ConnectFailed { detail: "unknown address type".into() }),
    };
    let mut discard = vec![0_u8; skip];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;

    let Some(path) = &request.http_path else {
        return Ok(());
    };

    let path = if path.is_empty() { "/" } else { path.as_str() };
    let get = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xraytui-probe\r\nConnection: close\r\n\r\n",
        request.host
    );
    stream
        .write_all(get.as_bytes())
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;

    // Only the status line is read: the probe measures reachability, never
    // content. Reading a bounded prefix also caps what a hostile endpoint can
    // make the client allocate.
    let mut buffer = [0_u8; 64];
    let read = stream
        .read(&mut buffer)
        .await
        .map_err(|error| ProbeOutcome::ConnectFailed { detail: describe(&error) })?;
    if read == 0 {
        return Err(ProbeOutcome::ConnectFailed {
            detail: "endpoint closed the connection without answering".into(),
        });
    }
    Ok(())
}

/// I/O errors are summarised by kind: the message may embed an address.
fn describe(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
        std::io::ErrorKind::ConnectionReset => "connection reset".into(),
        std::io::ErrorKind::TimedOut => "timed out".into(),
        std::io::ErrorKind::UnexpectedEof => "connection closed early".into(),
        std::io::ErrorKind::HostUnreachable => "host unreachable".into(),
        std::io::ErrorKind::NetworkUnreachable => "network unreachable".into(),
        other => format!("{other:?}"),
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_built_from_http_urls_only() {
        let socks: SocketAddr = "127.0.0.1:1080".parse().unwrap_or_else(|_| {
            unreachable!("literal address")
        });
        let request =
            ProbeRequest::from_url(socks, "http://cp.example/generate_204", Duration::from_secs(1))
                .unwrap_or_else(|| unreachable!("valid URL"));
        assert_eq!(request.host, "cp.example");
        assert_eq!(request.port, 80);
        assert_eq!(request.http_path.as_deref(), Some("/generate_204"));
        assert_eq!(request.kind(), ProbeKind::HttpRequest);

        let https =
            ProbeRequest::from_url(socks, "https://example.com/", Duration::from_secs(1))
                .unwrap_or_else(|| unreachable!("valid URL"));
        assert_eq!(https.port, 443);

        assert!(ProbeRequest::from_url(socks, "ftp://example.com", Duration::from_secs(1)).is_none());
        assert!(ProbeRequest::from_url(socks, "not a url", Duration::from_secs(1)).is_none());
    }

    #[tokio::test]
    async fn a_closed_listener_is_a_connect_failure_not_a_hang() {
        let request = ProbeRequest {
            socks: "127.0.0.1:1".parse().unwrap_or_else(|_| unreachable!("literal")),
            host: "example.invalid".into(),
            port: 80,
            http_path: None,
            timeout: Duration::from_millis(500),
        };
        let result = probe_through_socks(&request).await;
        assert!(matches!(result.outcome, ProbeOutcome::ConnectFailed { .. }), "{result:?}");
        assert_eq!(result.latency_ms, None);
    }

    #[tokio::test]
    async fn a_listener_that_never_answers_times_out() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap_or_else(|_| {
            unreachable!("bind loopback")
        });
        let address = listener.local_addr().unwrap_or_else(|_| unreachable!("addr"));
        // Accept but never reply.
        tokio::spawn(async move {
            let _keep = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let request = ProbeRequest {
            socks: address,
            host: "example.invalid".into(),
            port: 80,
            http_path: None,
            timeout: Duration::from_millis(300),
        };
        let result = probe_through_socks(&request).await;
        assert_eq!(result.outcome, ProbeOutcome::Timeout);
    }

    #[tokio::test]
    async fn a_working_proxy_reports_success_with_a_latency() {
        let egress = xraytui_test_support::MockEgress::start("probe")
            .await
            .unwrap_or_else(|_| unreachable!("start egress"));
        let request = ProbeRequest {
            socks: egress.socks_addr(),
            host: "example.invalid".into(),
            port: 80,
            http_path: Some("/".into()),
            timeout: Duration::from_secs(5),
        };
        let result = probe_through_socks(&request).await;
        assert_eq!(result.outcome, ProbeOutcome::Ok, "{result:?}");
        assert!(result.latency_ms.is_some());
    }

    #[test]
    fn error_descriptions_carry_no_addresses() {
        let error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "127.0.0.1:1080");
        assert_eq!(describe(&error), "connection refused");
    }
}
