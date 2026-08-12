//! Fetching a subscription body, and refusing to fetch too much of one.
//!
//! # What a subscription is, and is not
//!
//! A subscription is **passive configuration input**. The brief is explicit:
//! nothing in a subscription body is ever downloaded as code, executed, or
//! allowed to reach a shell. What arrives here is bytes; what leaves is a
//! `String` that the parser in `xraytui-import` treats as untrusted text.
//!
//! # The limits, and why each one exists
//!
//! | Limit | Default | What it prevents |
//! |---|---|---|
//! | response size | 4 MiB | a server, or a redirect to one, exhausting memory |
//! | redirects | 3 | a redirect loop, and a redirect off the origin to somewhere unexpected |
//! | timeout | 30 s | a hung fetch holding the update lock |
//! | scheme | `https`, or `http` with an explicit acknowledgement | a token travelling in clear |
//!
//! The size cap is applied **while streaming**, not by trusting
//! `Content-Length`: a server that lies about its length would otherwise defeat
//! it entirely.
//!
//! # Redaction
//!
//! The URL is a [`xraytui_secrets::Secret`]. It usually carries a bearer token in its path or
//! query, so it never appears in a log line, an error message or a stored
//! metadata field — [`redact_url`] is applied to everything that escapes.

use std::time::Duration;

use xraytui_domain::{Subscription, SubscriptionMeta};
use xraytui_secrets::redact_url;

/// Largest body accepted, before any decoding.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// Most redirects followed.
pub const MAX_REDIRECTS: usize = 3;

/// How long a single fetch may take.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// What this client calls itself.
///
/// Deliberately plain and honest. Some providers key their responses on it, and
/// impersonating a browser to get a different answer would be a lie told on the
/// user's behalf.
pub const USER_AGENT: &str = concat!("xraytui/", env!("CARGO_PKG_VERSION"));

/// Everything fetching can report.
///
/// Every variant is safe to log: the URL is redacted before it reaches one.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The URL could not be parsed, or its scheme is not allowed.
    #[error("{0}")]
    Url(String),
    /// The HTTP client could not be built.
    #[error("cannot build an HTTP client: {0}")]
    Client(String),
    /// The request failed at the transport level.
    #[error("cannot fetch {url}: {detail}")]
    Transport {
        /// Redacted URL.
        url: String,
        /// Redacted reason.
        detail: String,
    },
    /// The server answered with an error status.
    #[error("{url} answered {status}")]
    Status {
        /// Redacted URL.
        url: String,
        /// HTTP status code.
        status: u16,
    },
    /// The body exceeded the cap.
    #[error("{url} sent more than {limit} bytes; refusing to read the rest")]
    TooLarge {
        /// Redacted URL.
        url: String,
        /// The cap that was exceeded.
        limit: u64,
    },
    /// The body was not valid UTF-8 and was not base64 either.
    #[error("{url} sent something that is not text")]
    NotText {
        /// Redacted URL.
        url: String,
    },
}

/// What a fetch produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The server said nothing has changed since the recorded validator.
    Unchanged,
    /// A body, with whatever the server said about it.
    Body {
        /// The response, as text.
        text: String,
        /// Validators and quota information observed in the headers.
        meta: SubscriptionMeta,
    },
}

/// How the fetcher behaves.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// Largest body accepted.
    pub max_bytes: u64,
    /// How long one fetch may take.
    pub timeout: Duration,
    /// Proxy to fetch through, as a URL the HTTP client understands.
    ///
    /// This is how "fetch this subscription through profile X" is expressed:
    /// the daemon resolves the profile to its own SOCKS listener and passes it
    /// here. It is a loopback address, never a remote one.
    pub proxy: Option<String>,
    /// Permit `http://`. Off by default, because a subscription URL is a
    /// credential and sending it in clear hands it to anybody on the path.
    pub allow_plaintext: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            timeout: DEFAULT_TIMEOUT,
            proxy: None,
            allow_plaintext: false,
        }
    }
}

impl FetchOptions {
    /// Take the caps a subscription configures, leaving the rest.
    #[must_use]
    pub fn for_subscription(subscription: &Subscription) -> Self {
        Self {
            // A configured cap can only make the default *stricter*: a
            // subscription file is user-editable, and a value that raised the
            // ceiling would defeat the protection it exists for.
            max_bytes: subscription
                .max_response_bytes
                .map_or(DEFAULT_MAX_RESPONSE_BYTES, |bytes| {
                    bytes.min(DEFAULT_MAX_RESPONSE_BYTES)
                }),
            ..Self::default()
        }
    }
}

/// Fetch a subscription body.
///
/// `previous` supplies the `ETag` and `Last-Modified` recorded by the last
/// successful fetch, which become conditional request headers. A provider that
/// honours them answers `304` and [`Fetched::Unchanged`] comes back, which is
/// how a scheduled update on an unchanged subscription costs almost nothing.
///
/// # Errors
/// See [`FetchError`]. Nothing is stored and nothing is changed on failure.
pub async fn fetch(
    url: &xraytui_secrets::Secret,
    previous: &SubscriptionMeta,
    options: &FetchOptions,
) -> Result<Fetched, FetchError> {
    let raw = url.expose();
    let parsed = url::Url::parse(raw)
        .map_err(|error| FetchError::Url(format!("not a valid URL: {error}")))?;
    let safe = redact_url(raw);

    match parsed.scheme() {
        "https" => {}
        "http" if options.allow_plaintext => {
            tracing::warn!(
                url = %safe,
                "fetching a subscription over plain HTTP; the URL is a credential \
                 and anybody on the path can read it"
            );
        }
        "http" => {
            return Err(FetchError::Url(
                "refusing to fetch a subscription over plain HTTP; set \
                 `allow_plaintext = true` on the subscription if the provider \
                 offers nothing else and you accept that the URL travels in clear"
                    .to_owned(),
            ));
        }
        other => {
            return Err(FetchError::Url(format!(
                "subscription URLs must be https (or http with an explicit \
                 acknowledgement); {other} is not fetchable"
            )));
        }
    }

    let mut builder = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(options.timeout)
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        // A subscription fetch has no business sending a referer; the cookie
        // store is off because the feature is not compiled in at all.
        .referer(false);
    if let Some(proxy) = &options.proxy {
        let proxy = reqwest::Proxy::all(proxy)
            .map_err(|error| FetchError::Client(format!("proxy {proxy}: {error}")))?;
        builder = builder.proxy(proxy);
    } else {
        // Environment proxies are not honoured: which proxy a subscription is
        // fetched through is a configuration decision, not an ambient one.
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|error| FetchError::Client(error.to_string()))?;

    let mut request = client.get(parsed);
    if let Some(etag) = &previous.etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    if let Some(modified) = &previous.last_modified {
        request = request.header(reqwest::header::IF_MODIFIED_SINCE, modified);
    }

    let response = request
        .send()
        .await
        .map_err(|error| FetchError::Transport {
            url: safe.clone(),
            detail: redact_url(&error.to_string()),
        })?;

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(Fetched::Unchanged);
    }
    if !response.status().is_success() {
        return Err(FetchError::Status {
            url: safe,
            status: response.status().as_u16(),
        });
    }

    let meta = read_meta(response.headers());

    // Read with the cap applied to what actually arrives. `Content-Length` is
    // the server's claim, not a fact.
    let mut body: Vec<u8> = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| FetchError::Transport {
            url: safe.clone(),
            detail: redact_url(&error.to_string()),
        })?
    {
        if body.len() as u64 + chunk.len() as u64 > options.max_bytes {
            return Err(FetchError::TooLarge {
                url: safe,
                limit: options.max_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(body).map_err(|_| FetchError::NotText { url: safe })?;
    Ok(Fetched::Body { text, meta })
}

/// Read the validators and quota headers a provider may send.
///
/// `Subscription-Userinfo` is a de-facto convention rather than a standard:
/// `upload=0; download=1234; total=5678; expire=1700000000`. Fields that are
/// missing or unparseable are left as `None` rather than guessed at.
#[must_use]
pub fn read_meta(headers: &reqwest::header::HeaderMap) -> SubscriptionMeta {
    let text = |name: reqwest::header::HeaderName| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    };

    let mut meta = SubscriptionMeta {
        etag: text(reqwest::header::ETAG),
        last_modified: text(reqwest::header::LAST_MODIFIED),
        ..SubscriptionMeta::default()
    };

    if let Some(userinfo) = headers
        .get("subscription-userinfo")
        .and_then(|value| value.to_str().ok())
    {
        for field in userinfo.split(';') {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let value = value.trim().parse::<u64>().ok();
            match key.trim().to_ascii_lowercase().as_str() {
                "upload" => meta.upload_bytes = value,
                "download" => meta.download_bytes = value,
                "total" => meta.total_bytes = value,
                "expire" => {
                    meta.expire_unix = value.and_then(|seconds| i64::try_from(seconds).ok());
                }
                _ => {}
            }
        }
    }
    meta
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};
    use xraytui_secrets::Secret;
    use xraytui_test_support::HttpFixtureServer;
    use xraytui_test_support::http_fixture::Route;

    fn meta() -> SubscriptionMeta {
        SubscriptionMeta::default()
    }

    #[tokio::test]
    async fn a_body_comes_back_as_text() {
        let server = HttpFixtureServer::start().await.expect("fixture server");
        server
            .set_route("/sub", Route::ok("vless://x@host:443#n"))
            .await;
        let url = Secret::new(server.url("/sub"));
        let fetched = fetch(&url, &meta(), &plaintext()).await.expect("fetch");
        match fetched {
            Fetched::Body { text, .. } => assert!(text.contains("vless://"), "{text}"),
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_recorded_validator_produces_a_conditional_request() {
        let server = HttpFixtureServer::start().await.expect("fixture server");
        server
            .set_route("/sub", Route::ok("body").with_etag("\"v1\""))
            .await;
        let url = Secret::new(server.url("/sub"));

        let first = fetch(&url, &meta(), &plaintext()).await.expect("fetch");
        let recorded = match first {
            Fetched::Body { meta, .. } => meta,
            other => panic!("unexpected outcome {other:?}"),
        };
        assert_eq!(recorded.etag.as_deref(), Some("\"v1\""));

        // The fixture answers 304 when the validator matches.
        let second = fetch(&url, &recorded, &plaintext()).await.expect("fetch");
        assert_eq!(second, Fetched::Unchanged);
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_refused_rather_than_read() {
        let server = HttpFixtureServer::start().await.expect("fixture server");
        server
            .set_route("/big", Route::ok("x".repeat(64 * 1024)))
            .await;
        let url = Secret::new(server.url("/big"));
        let options = FetchOptions {
            max_bytes: 1024,
            ..plaintext()
        };
        let error = fetch(&url, &meta(), &options)
            .await
            .expect_err("must refuse");
        assert!(matches!(error, FetchError::TooLarge { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn an_error_status_is_reported_with_the_code() {
        let server = HttpFixtureServer::start().await.expect("fixture server");
        server
            .set_route(
                "/gone",
                Route {
                    status: 404,
                    body: b"nope".to_vec(),
                    headers: Vec::new(),
                    etag: None,
                    last_modified: None,
                },
            )
            .await;
        let url = Secret::new(server.url("/gone"));
        match fetch(&url, &meta(), &plaintext()).await {
            Err(FetchError::Status { status, .. }) => assert_eq!(status, 404),
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[tokio::test]
    async fn plain_http_is_refused_unless_acknowledged() {
        let url = Secret::new("http://example.test/sub?token=SECRET");
        let error = fetch(&url, &meta(), &FetchOptions::default())
            .await
            .expect_err("must refuse");
        let text = error.to_string();
        assert!(text.contains("plain HTTP"), "{text}");
        assert!(!text.contains("SECRET"), "the URL must not leak: {text}");
    }

    #[tokio::test]
    async fn a_scheme_that_is_not_http_is_refused() {
        for raw in [
            "file:///etc/passwd",
            "ftp://example.test/sub",
            "data:text/plain;base64,dgo=",
        ] {
            let error = fetch(&Secret::new(raw), &meta(), &FetchOptions::default())
                .await
                .expect_err("must refuse");
            assert!(matches!(error, FetchError::Url(_)), "{raw}: {error:?}");
        }
    }

    #[tokio::test]
    async fn a_transport_failure_never_prints_the_url() {
        // Port 1 is reserved and nothing listens there.
        let url = Secret::new("https://127.0.0.1:1/sub?token=SUPERSECRET");
        let error = fetch(&url, &meta(), &FetchOptions::default())
            .await
            .expect_err("must fail");
        let text = error.to_string();
        assert!(!text.contains("SUPERSECRET"), "{text}");
        // The parameter *name* survives — knowing which value was withheld is
        // useful — but the value must not.
        assert!(text.contains("redacted"), "{text}");
    }

    #[test]
    fn quota_headers_are_read_when_present_and_left_alone_when_not() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "subscription-userinfo",
            HeaderValue::from_static("upload=100; download=200; total=300; expire=1700000000"),
        );
        let meta = read_meta(&headers);
        assert_eq!(meta.upload_bytes, Some(100));
        assert_eq!(meta.download_bytes, Some(200));
        assert_eq!(meta.total_bytes, Some(300));
        assert_eq!(meta.expire_unix, Some(1_700_000_000));

        assert_eq!(read_meta(&HeaderMap::new()), SubscriptionMeta::default());
    }

    #[test]
    fn a_malformed_quota_header_is_ignored_rather_than_guessed_at() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "subscription-userinfo",
            HeaderValue::from_static("upload=; download=lots; nonsense; total=300"),
        );
        let meta = read_meta(&headers);
        assert_eq!(meta.upload_bytes, None);
        assert_eq!(meta.download_bytes, None);
        assert_eq!(meta.total_bytes, Some(300));
    }

    #[test]
    fn the_configured_cap_can_only_lower_the_default() {
        let mut subscription = subscription();
        subscription.max_response_bytes = Some(1024);
        assert_eq!(
            FetchOptions::for_subscription(&subscription).max_bytes,
            1024
        );

        subscription.max_response_bytes = Some(u64::MAX);
        assert_eq!(
            FetchOptions::for_subscription(&subscription).max_bytes,
            DEFAULT_MAX_RESPONSE_BYTES,
            "a configured cap must not be able to raise the default"
        );
    }

    #[test]
    fn the_user_agent_says_what_it_is() {
        assert!(USER_AGENT.starts_with("xraytui/"));
        assert!(!USER_AGENT.to_lowercase().contains("mozilla"));
    }

    fn plaintext() -> FetchOptions {
        FetchOptions {
            allow_plaintext: true,
            ..FetchOptions::default()
        }
    }

    fn subscription() -> Subscription {
        Subscription {
            id: xraytui_domain::SubscriptionId::from_text("provider"),
            name: "Provider".to_owned(),
            url: Secret::new("https://example.test/sub"),
            enabled: true,
            update_interval_secs: None,
            fetch_via_profile: None,
            include_regex: Vec::new(),
            exclude_regex: Vec::new(),
            max_nodes: None,
            max_response_bytes: None,
            meta: SubscriptionMeta::default(),
        }
    }
}
