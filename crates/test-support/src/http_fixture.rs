//! A tiny HTTP/1.1 server for subscription tests.
//!
//! Supports exactly what the subscription client exercises: fixed bodies,
//! `ETag`/`If-None-Match`, `Last-Modified`/`If-Modified-Since`, arbitrary extra
//! headers such as `Subscription-Userinfo`, redirects, and a deliberately
//! oversized body for the size-cap test.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// What the server answers for a given path.
#[derive(Debug, Clone)]
pub struct Route {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
    /// Extra response headers.
    pub headers: Vec<(String, String)>,
    /// `ETag` value; a matching `If-None-Match` yields 304.
    pub etag: Option<String>,
    /// `Last-Modified` value; a matching `If-Modified-Since` yields 304.
    pub last_modified: Option<String>,
}

impl Route {
    /// A 200 response with a text body.
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            headers: Vec::new(),
            etag: None,
            last_modified: None,
        }
    }

    /// A redirect to `location`.
    pub fn redirect(status: u16, location: impl Into<String>) -> Self {
        Self {
            status,
            body: Vec::new(),
            headers: vec![("Location".to_owned(), location.into())],
            etag: None,
            last_modified: None,
        }
    }

    /// Attach an `ETag`.
    #[must_use]
    pub fn with_etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = Some(etag.into());
        self
    }

    /// Attach an arbitrary header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// A local HTTP server whose routes can be rewritten between requests.
pub struct HttpFixtureServer {
    addr: SocketAddr,
    routes: Arc<RwLock<HashMap<String, Route>>>,
    requests: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl HttpFixtureServer {
    /// Start on an ephemeral loopback port.
    ///
    /// # Errors
    /// Propagates the bind failure.
    pub async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let routes: Arc<RwLock<HashMap<String, Route>>> = Arc::new(RwLock::new(HashMap::new()));
        let requests = Arc::new(AtomicU64::new(0));

        let served = Arc::clone(&routes);
        let counter = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let served = Arc::clone(&served);
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _ = handle(stream, served).await;
                });
            }
        });

        Ok(Self { addr, routes, requests, task })
    }

    /// Base URL, without a trailing slash.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Full URL for a path beginning with `/`.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Install or replace a route.
    pub async fn set_route(&self, path: impl Into<String>, route: Route) {
        self.routes.write().await.insert(path.into(), route);
    }

    /// Number of requests received since start.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for HttpFixtureServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(
    mut stream: TcpStream,
    routes: Arc<RwLock<HashMap<String, Route>>>,
) -> io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut chunk),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))??;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > 64 * 1024 {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buffer);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or_default();
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let mut if_none_match = None;
    let mut if_modified_since = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("if-none-match: ") {
            if_none_match = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("If-None-Match: ") {
            if_none_match = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("if-modified-since: ") {
            if_modified_since = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("If-Modified-Since: ") {
            if_modified_since = Some(value.trim().to_owned());
        }
    }

    let routes = routes.read().await;
    let Some(route) = routes.get(path) else {
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response).await?;
        return Ok(());
    };

    let not_modified = route.etag.as_deref().is_some_and(|e| if_none_match.as_deref() == Some(e))
        || route
            .last_modified
            .as_deref()
            .is_some_and(|m| if_modified_since.as_deref() == Some(m));

    let mut response = if not_modified {
        String::from("HTTP/1.1 304 Not Modified\r\n")
    } else {
        format!("HTTP/1.1 {} {}\r\n", route.status, reason(route.status))
    };
    if let Some(etag) = &route.etag {
        response.push_str(&format!("ETag: {etag}\r\n"));
    }
    if let Some(modified) = &route.last_modified {
        response.push_str(&format!("Last-Modified: {modified}\r\n"));
    }
    for (name, value) in &route.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    let body: &[u8] = if not_modified { &[] } else { &route.body };
    response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    response.push_str("Connection: close\r\n\r\n");

    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serves_a_body_and_counts_requests() {
        let server = HttpFixtureServer::start().await.expect("start");
        server.set_route("/sub", Route::ok("hello")).await;
        let mut stream = TcpStream::connect(server.addr).await.expect("connect");
        stream.write_all(b"GET /sub HTTP/1.1\r\nHost: x\r\n\r\n").await.expect("write");
        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut response)
            .await
            .expect("read");
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.ends_with("hello"), "{response}");
        assert_eq!(server.request_count(), 1);
    }

    #[tokio::test]
    async fn honours_if_none_match() {
        let server = HttpFixtureServer::start().await.expect("start");
        server.set_route("/sub", Route::ok("hello").with_etag("\"v1\"")).await;
        let mut stream = TcpStream::connect(server.addr).await.expect("connect");
        stream
            .write_all(b"GET /sub HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"v1\"\r\n\r\n")
            .await
            .expect("write");
        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut response)
            .await
            .expect("read");
        assert!(response.contains("304 Not Modified"), "{response}");
    }
}
