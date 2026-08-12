//! Secret wrapper types and redaction helpers.
//!
//! Two things live here:
//!
//! * [`Secret`] — a string-like value that never reveals itself through [`Debug`],
//!   [`std::fmt::Display`] or accidental serialisation of a struct, and that
//!   zeroizes on drop.
//! * [`redact`] — best-effort scrubbing of URLs, share links and free text before
//!   they reach logs, diagnostics or the terminal.
//!
//! The rule enforced throughout xraytui: anything that grants access to a proxy
//! endpoint is a secret. That includes UUIDs, passwords, pre-shared keys, REALITY
//! private material, subscription tokens, and complete share links or QR payloads.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

/// Placeholder substituted for any redacted value.
pub const REDACTED: &str = "<redacted>";

/// A secret string.
///
/// `Debug` and `Display` both print [`REDACTED`]. The inner value is only
/// reachable through [`Secret::expose`], which is deliberately verbose so that
/// every exposure site is greppable.
///
/// ```
/// # use xraytui_secrets::Secret;
/// let s = Secret::new("hunter2");
/// assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
/// assert_eq!(s.expose(), "hunter2");
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Secret(String);

impl Secret {
    /// Wrap a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Reveal the secret. Every call site is an auditable exposure point.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// True when the secret carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Length in bytes. Safe to log — it does not reveal content.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// A stable, non-reversible fingerprint suitable for diffing two
    /// configurations without revealing either value.
    ///
    /// This is FNV-1a, not a cryptographic hash: it exists to answer "did this
    /// field change?", never to authenticate anything.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.0.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{hash:016x}")
    }

    /// Consume the wrapper, returning a value that zeroizes when it goes out of
    /// scope. Used when handing material to a serialiser that needs `&str`.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        Zeroizing::new(self.0.clone())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl Serialize for Secret {
    /// Serialises the real value.
    ///
    /// This is correct: `Secret` is used in `secrets.toml` and in the generated
    /// Xray configuration, both of which are written with mode 0600. Redaction
    /// for *display* purposes goes through [`RedactedSecret`] or [`redact`],
    /// never through the plain serialiser, so that a round trip is lossless.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// Newtype whose `Serialize` impl emits [`REDACTED`] instead of the value.
///
/// Used by diagnostic exports and by any structure that may be rendered to a
/// terminal or written to a world-readable file.
#[derive(Debug, Clone, Copy)]
pub struct RedactedSecret<'a>(pub &'a Secret);

impl Serialize for RedactedSecret<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Query-parameter names whose values are always scrubbed.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "auth",
    "authorization",
    "key",
    "apikey",
    "api_key",
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "sub",
    "subscribe",
    "sid",
    "uuid",
    "id",
    "psk",
    "pbk",
    "sid_short",
];

/// URI schemes that are share links and therefore secret in their entirety.
const SHARE_SCHEMES: &[&str] = &[
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "socks://",
    "http-proxy://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "wireguard://",
    "xraytui://",
];

/// Any path segment at least this long inside a subscription URL is assumed to be
/// a token rather than a human-meaningful path component.
const LONG_PATH_SEGMENT: usize = 24;

/// Redact a URL for logging: strips userinfo, scrubs sensitive query values, and
/// replaces long opaque path segments.
///
/// Falls back to a scheme-and-host summary when the input does not parse.
/// Longest token handed to the URL parser. Anything longer is summarised
/// instead, so a pathological log line cannot become a parsing cost.
const MAX_URL_BYTES: usize = 4096;

/// Fallback for a URL-shaped token that could not be parsed.
///
/// Returns the scheme and nothing else. This must **not** delegate to
/// [`redact_text`]: that function routes URL-shaped tokens back here, and the two
/// would recurse until the stack was exhausted. A malformed URL in a log line is
/// exactly the input that triggers it, so the bug would have been reachable from
/// any subscription body.
fn summarise_unparseable(input: &str) -> String {
    match input.split_once("://") {
        Some((scheme, _)) if scheme.len() <= 32 => format!("{scheme}://{REDACTED}"),
        _ => REDACTED.to_owned(),
    }
}

/// Redact a URL for logging: strips userinfo, scrubs sensitive query values,
/// and replaces long opaque path segments.
///
/// Falls back to a scheme-only summary when the input does not parse or is
/// implausibly long.
#[must_use]
pub fn redact_url(input: &str) -> String {
    if input.len() > MAX_URL_BYTES {
        return summarise_unparseable(input);
    }
    let Ok(mut url) = url::Url::parse(input) else {
        return summarise_unparseable(input);
    };

    if !url.username().is_empty() {
        let _ = url.set_username(REDACTED);
    }
    if url.password().is_some() {
        let _ = url.set_password(Some(REDACTED));
    }

    let scrubbed_query: Option<String> = url.query().map(|_| {
        url.query_pairs()
            .map(|(k, v)| {
                let lowered = k.to_ascii_lowercase();
                if SENSITIVE_QUERY_KEYS.contains(&lowered.as_str()) || v.len() >= LONG_PATH_SEGMENT
                {
                    format!("{k}={REDACTED}")
                } else {
                    format!("{k}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("&")
    });

    let scrubbed_path: String = url
        .path()
        .split('/')
        .map(|segment| {
            if segment.len() >= LONG_PATH_SEGMENT {
                REDACTED.to_owned()
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/");

    url.set_path(&scrubbed_path);
    url.set_query(scrubbed_query.as_deref());
    if !url.fragment().unwrap_or_default().is_empty() {
        // The fragment of a share link is the display name, which is not secret,
        // but the fragment of a subscription URL sometimes carries a token.
        let fragment = url.fragment().unwrap_or_default().to_owned();
        if fragment.len() >= LONG_PATH_SEGMENT {
            url.set_fragment(Some(REDACTED));
        }
    }
    url.to_string()
}

/// Redact free text: whole share links are replaced, embedded URLs are scrubbed.
///
/// This is the function the tracing layer applies to every recorded string field.
#[must_use]
pub fn redact_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for (index, token) in input.split_whitespace().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(&redact_token(token));
    }
    if input.ends_with(char::is_whitespace) && !out.is_empty() {
        out.push(' ');
    }
    out
}

fn redact_token(token: &str) -> String {
    let lowered = token.to_ascii_lowercase();
    if SHARE_SCHEMES.iter().any(|s| lowered.starts_with(s)) {
        let scheme_end = token.find("//").map_or(0, |i| i + 2);
        return format!("{}{REDACTED}", &token[..scheme_end]);
    }
    if lowered.starts_with("http://") || lowered.starts_with("https://") {
        return redact_url(token);
    }
    token.to_owned()
}

/// Convenience wrapper for the common "this is a share link" case.
///
/// Always returns a constant so no length information leaks either.
#[must_use]
pub fn redact_share_link(_link: &str) -> &'static str {
    "<share-link redacted>"
}

/// Alias kept for readability at call sites that redact a single value.
#[must_use]
pub fn redact(input: &str) -> String {
    redact_text(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_and_display_are_redacted() {
        let s = Secret::new("super-secret-uuid");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(format!("{s}"), REDACTED);
        assert!(!format!("{s:?}").contains("super-secret"));
    }

    #[test]
    fn secret_round_trips_through_serde() {
        let s = Secret::new("value");
        let json = serde_json::to_string(&s).expect("serialise");
        assert_eq!(json, "\"value\"");
        let back: Secret = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.expose(), "value");
    }

    #[test]
    fn redacted_wrapper_hides_value() {
        let s = Secret::new("value");
        let json = serde_json::to_string(&RedactedSecret(&s)).expect("serialise");
        assert_eq!(json, "\"<redacted>\"");
    }

    #[test]
    fn fingerprint_is_stable_and_differs() {
        let a = Secret::new("a");
        let b = Secret::new("b");
        assert_eq!(a.fingerprint(), Secret::new("a").fingerprint());
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_is_fixed_width_hex_and_hides_its_input() {
        // A hex digest may legitimately contain any hex character, so "does not
        // contain a byte of the input" is not a meaningful property. What matters
        // is that the output is a fixed-width digest rather than the value.
        for secret in ["a", "", "hunter2", &"x".repeat(4096), "香港-01"] {
            let fingerprint = Secret::new(secret).fingerprint();
            assert_eq!(fingerprint.len(), 16, "{secret:?} -> {fingerprint}");
            assert!(
                fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "{fingerprint}"
            );
            assert_ne!(fingerprint, secret);
        }
    }

    #[test]
    fn malformed_urls_terminate_instead_of_recursing() {
        // Regression: `redact_url` used to fall back to `redact_text`, which
        // routes URL-shaped tokens straight back into `redact_url`. Any log line
        // holding a malformed URL then exhausted the stack, and a subscription
        // body is exactly the input that produces one. Found by the
        // `xraytui-import` property tests.
        for input in [
            "http://[[[[[[[[",
            "https://[",
            "http://%%%",
            "http://:::::",
            "https://host:99999999",
            "http://",
        ] {
            let redacted = redact_url(input);
            assert!(redacted.contains(REDACTED), "{input} -> {redacted}");
            let via_text = redact_text(&format!("fetching {input} now"));
            assert!(via_text.starts_with("fetching "), "{via_text}");
            assert!(via_text.ends_with(" now"), "{via_text}");
        }
    }

    #[test]
    fn very_long_tokens_are_summarised_rather_than_parsed() {
        let long = format!("https://example.com/{}", "a".repeat(8192));
        let redacted = redact_url(&long);
        assert!(redacted.len() < 64, "{redacted}");
        assert!(redacted.starts_with("https://"), "{redacted}");
    }

    #[test]
    fn hostile_text_always_terminates() {
        for input in [
            "[".repeat(4096),
            format!("http://{}", "[".repeat(4096)),
            format!("{}://x", "a".repeat(64)),
            "\u{1}\u{2}".repeat(100),
            "vless://".repeat(500),
        ] {
            let _ = redact_text(&input);
        }
    }

    #[test]
    fn subscription_url_token_is_scrubbed() {
        let redacted =
            redact_url("https://example.com/sub/9f1c8b2ea4d64f0b8c7d3e5a1b2c3d4e?token=abcdefgh");
        assert!(
            !redacted.contains("9f1c8b2ea4d64f0b8c7d3e5a1b2c3d4e"),
            "{redacted}"
        );
        assert!(!redacted.contains("abcdefgh"), "{redacted}");
        assert!(
            redacted.starts_with("https://example.com/sub/"),
            "{redacted}"
        );
    }

    #[test]
    fn userinfo_is_scrubbed() {
        let redacted = redact_url("https://user:pw@example.com/x");
        assert!(!redacted.contains("pw"), "{redacted}");
        assert!(!redacted.contains("user@"), "{redacted}");
    }

    #[test]
    fn share_links_are_replaced_entirely() {
        let text = "importing vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality#HK";
        let redacted = redact_text(text);
        assert!(!redacted.contains("11111111"), "{redacted}");
        assert!(!redacted.contains("1.2.3.4"), "{redacted}");
        assert!(redacted.contains("vless://<redacted>"), "{redacted}");
        assert!(redacted.starts_with("importing "), "{redacted}");
    }

    #[test]
    fn ordinary_text_is_untouched() {
        assert_eq!(
            redact_text("core started, 3 profiles"),
            "core started, 3 profiles"
        );
    }

    #[test]
    fn short_query_values_survive() {
        let redacted = redact_url("https://example.com/a?type=ws&host=cdn.example.com");
        assert!(redacted.contains("type=ws"), "{redacted}");
        assert!(redacted.contains("host=cdn.example.com"), "{redacted}");
    }
}
