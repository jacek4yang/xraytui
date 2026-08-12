//! Share-link, QR and Xray JSON import/export.
//!
//! This crate is the hostile boundary described in `docs/THREAT-MODEL.md`: every
//! byte it looks at is attacker-influenced. It therefore obeys three rules that
//! are not negotiable and are enforced by tests:
//!
//! 1. **No panics.** No `unwrap`, no `expect`, no indexing, no string slicing.
//!    Every input is bounded before it is allocated for ([`MAX_LINK_BYTES`],
//!    [`MAX_LINKS`], [`MAX_BATCH_BYTES`], [`MAX_JSON_BYTES`]).
//! 2. **No credentials in errors.** [`ImportError`] and [`ExportError`] are
//!    structured and interpolate only protocol tokens, field names and sizes, so
//!    the whole error type is safe to log at any level.
//! 3. **Nothing is thrown away.** A link xraytui does not understand becomes an
//!    [`UnsupportedNode`] that still carries the original text, and unknown URI
//!    parameters are kept in [`Node::extra`] so that import → export round trips
//!    do not destroy information.
//!
//! # Entry points
//!
//! | Input | Function |
//! |---|---|
//! | one share link | [`parse_uri`] / [`parse_uri_with_source`] |
//! | a list of links, one per line | [`parse_many`] |
//! | one Xray outbound object | [`parse_xray_outbound`] |
//! | a whole Xray config | [`parse_xray_config`] |
//! | a node → a share link | [`to_share_link`] |
//! | terminal / PNG QR codes | [`qr`] |
//!
//! ```
//! use xraytui_import::{parse_uri, ImportedEntry};
//!
//! let entry = parse_uri("vless://11111111-2222-3333-4444-555555555555@example.com:443\
//!                        ?type=ws&path=/ray&security=tls&sni=example.com#HK%2001")
//!     .expect("valid link");
//! let node = entry.as_node().expect("supported protocol");
//! assert_eq!(node.name, "HK 01");
//! assert_eq!(node.summary(), "vless/ws+tls  example.com:443");
//! ```
//!
//! # What is *not* here
//!
//! Fetching subscriptions (`xraytui-subscription`) and compiling nodes into Xray
//! JSON (`xraytui-xray-compiler`). This crate only reads foreign formats and
//! writes share links.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The parsers must not be able to panic on hostile input. Tests are exempt so
// that assertions can still use `expect`.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

mod b64;
mod export;
mod link;
pub mod qr;
mod xray;

pub use b64::{
    decode_base64_flexible, decode_base64_utf8, encode_standard, encode_url_safe_no_pad,
    looks_like_base64, MAX_BASE64_INPUT,
};
pub use export::to_share_link;
pub use xray::{parse_xray_config, parse_xray_outbound};

use xraytui_domain::{Node, NodeId, NodeSource, UnsupportedNode};
use xraytui_secrets::redact_text;

/// Largest accepted single share link, in bytes.
///
/// Real links are a few hundred bytes; the limit exists so that a subscription
/// body consisting of one enormous line cannot force a large allocation.
pub const MAX_LINK_BYTES: usize = 64 * 1024;

/// Largest number of entries [`parse_many`] will produce from one input.
///
/// Matches the `max_nodes` subscription limit in `docs/THREAT-MODEL.md`.
pub const MAX_LINKS: usize = 10_000;

/// Largest accepted input for [`parse_many`], in bytes.
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Largest accepted Xray configuration for [`parse_xray_config`], in bytes.
pub const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;

/// Longest display name kept from a link fragment or an outbound tag.
pub const MAX_NAME_CHARS: usize = 128;

/// Why an entry could not be imported.
///
/// Every variant is safe to log: no field of any variant ever holds a
/// credential, a full link, or unbounded attacker text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// The input was empty or whitespace only.
    #[error("input is empty")]
    Empty,
    /// The input exceeded a size limit.
    #[error("input is {size} bytes, over the {limit} byte limit")]
    TooLarge {
        /// Size of the offending input in bytes.
        size: usize,
        /// Limit that was exceeded.
        limit: usize,
    },
    /// The input did not start with `scheme://`.
    #[error("input does not look like a share link (expected `scheme://…`)")]
    NotAShareLink,
    /// The URI syntax itself was invalid.
    #[error("`{scheme}`: invalid URI ({reason})")]
    Uri {
        /// Scheme the input claimed, sanitised.
        scheme: String,
        /// Why the generic URI parser rejected it.
        reason: url::ParseError,
    },
    /// A field the protocol requires was absent.
    #[error("`{scheme}`: missing `{field}`")]
    MissingField {
        /// Protocol token.
        scheme: &'static str,
        /// Name of the missing field.
        field: &'static str,
    },
    /// A field was present but could not be interpreted.
    #[error("`{scheme}`: invalid `{field}`")]
    InvalidField {
        /// Protocol token.
        scheme: &'static str,
        /// Name of the invalid field.
        field: &'static str,
    },
    /// The payload was not decodable as base64 in any accepted alphabet.
    #[error("`{scheme}`: payload is not valid base64")]
    InvalidBase64 {
        /// Protocol token.
        scheme: &'static str,
    },
    /// The decoded payload was not valid UTF-8.
    #[error("`{scheme}`: payload is not valid UTF-8")]
    InvalidUtf8 {
        /// Protocol token.
        scheme: &'static str,
    },
    /// The decoded payload was not the JSON object the format requires.
    #[error("`{scheme}`: payload is not a JSON object")]
    InvalidJson {
        /// Protocol token.
        scheme: &'static str,
    },
    /// More entries than [`MAX_LINKS`] were offered in one batch.
    #[error("input holds more than {limit} entries; the rest were ignored")]
    TooManyEntries {
        /// The limit that was hit.
        limit: usize,
    },
    /// A supposed Xray configuration was not valid JSON.
    #[error("Xray config is not valid JSON")]
    ConfigNotJson,
    /// A supposed Xray configuration contained no outbound objects.
    #[error("Xray config contains no outbounds")]
    NoOutbounds,
    /// An outbound entry was not a JSON object.
    #[error("Xray outbound is not a JSON object")]
    NotAnObject,
    /// An outbound object had no usable `protocol` field.
    #[error("Xray outbound has no `protocol` field")]
    MissingProtocol,
}

/// Why a node could not be turned back into a share link.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    /// No community standard exists for this protocol's share links.
    #[error("{protocol} has no standard share link format")]
    NoStandardFormat {
        /// Protocol token.
        protocol: &'static str,
    },
    /// The protocol has a link format, but it cannot express this node.
    #[error("a {protocol} share link cannot express {feature}")]
    Unrepresentable {
        /// Protocol token.
        protocol: &'static str,
        /// The setting that has no representation.
        feature: &'static str,
    },
    /// A field the link format requires was empty on the node.
    #[error("node cannot be exported: `{field}` is empty")]
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },
    /// The generated link would be larger than [`MAX_LINK_BYTES`].
    #[error("generated link would be over the {limit} byte limit")]
    TooLarge {
        /// The limit that would be exceeded.
        limit: usize,
    },
}

/// One successfully classified entry.
///
/// "Classified" is weaker than "supported": an entry xraytui recognises but
/// cannot compile is still a result, not an error, because losing it silently
/// would leave the user with a shorter node list than their provider sent.
#[derive(Debug, Clone, PartialEq, Eq)]
// The enum is created and destructured immediately by the parsers; the size
// difference between a `Node` and an `UnsupportedNode` never reaches a
// collection, and boxing here would only obscure the API.
#[allow(clippy::large_enum_variant)]
pub enum ImportedEntry {
    /// A node xraytui can compile (possibly with a caveat in `notes`).
    Supported(Node),
    /// A recognised proxy definition xraytui cannot compile.
    Unsupported(UnsupportedNode),
}

impl ImportedEntry {
    /// Whether this entry produced a compilable node.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }

    /// The node, when the entry is supported.
    #[must_use]
    pub fn as_node(&self) -> Option<&Node> {
        match self {
            Self::Supported(node) => Some(node),
            Self::Unsupported(_) => None,
        }
    }

    /// The unsupported record, when the entry is not supported.
    #[must_use]
    pub fn as_unsupported(&self) -> Option<&UnsupportedNode> {
        match self {
            Self::Unsupported(node) => Some(node),
            Self::Supported(_) => None,
        }
    }

    /// Consume the entry, yielding the node when it is supported.
    #[must_use]
    pub fn into_node(self) -> Option<Node> {
        match self {
            Self::Supported(node) => Some(node),
            Self::Unsupported(_) => None,
        }
    }

    /// Identifier assigned to the entry.
    #[must_use]
    pub fn id(&self) -> &NodeId {
        match self {
            Self::Supported(node) => &node.id,
            Self::Unsupported(node) => &node.id,
        }
    }

    /// Display name, which may be empty when the source carried none.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Supported(node) => &node.name,
            Self::Unsupported(node) => &node.name,
        }
    }
}

/// An entry that could not be classified at all.
///
/// Kept so that `xraytui sub update` can report "3 lines ignored" with a reason
/// instead of quietly dropping them. Both fields are safe to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedEntry {
    /// 1-based position in the input: line number for link lists, outbound index
    /// for Xray configurations.
    pub index: usize,
    /// The offending text with credentials removed and length bounded.
    pub redacted: String,
    /// Why it was rejected.
    pub error: ImportError,
}

/// The result of importing many entries at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportBatch {
    /// Nodes xraytui can compile.
    pub nodes: Vec<Node>,
    /// Recognised entries xraytui cannot compile.
    pub unsupported: Vec<UnsupportedNode>,
    /// Entries that could not be classified.
    pub rejected: Vec<RejectedEntry>,
}

impl ImportBatch {
    /// An empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// File a classified entry into the right bucket.
    pub fn push(&mut self, entry: ImportedEntry) {
        match entry {
            ImportedEntry::Supported(node) => self.nodes.push(node),
            ImportedEntry::Unsupported(node) => self.unsupported.push(node),
        }
    }

    /// Number of classified entries, supported or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len().saturating_add(self.unsupported.len())
    }

    /// Whether nothing at all was classified.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.unsupported.is_empty()
    }

    /// Whether any input line was rejected.
    #[must_use]
    pub fn has_rejects(&self) -> bool {
        !self.rejected.is_empty()
    }
}

/// Parse one share link, attributing it to [`NodeSource::Manual`].
///
/// # Errors
/// Returns [`ImportError`] when the input is empty, oversized, not a URI, or
/// syntactically broken for its scheme. A URI with a scheme xraytui does not
/// implement is *not* an error: it returns
/// [`ImportedEntry::Unsupported`].
pub fn parse_uri(input: &str) -> Result<ImportedEntry, ImportError> {
    parse_uri_with_source(input, NodeSource::Manual)
}

/// Parse one share link with an explicit provenance.
///
/// # Errors
/// See [`parse_uri`].
pub fn parse_uri_with_source(
    input: &str,
    source: NodeSource,
) -> Result<ImportedEntry, ImportError> {
    link::parse(input, source)
}

/// Parse a newline-separated list of share links.
///
/// Blank lines and `#`, `;` or `//` comment lines are skipped. Every line that
/// fails becomes a [`RejectedEntry`] instead of aborting the batch, because one
/// broken line in a subscription must not lose the other 300. At most
/// [`MAX_LINKS`] entries are classified; the overflow is reported as a single
/// [`ImportError::TooManyEntries`] reject.
#[must_use]
pub fn parse_many(input: &str, source: NodeSource) -> ImportBatch {
    let mut batch = ImportBatch::new();
    if input.len() > MAX_BATCH_BYTES {
        batch.rejected.push(RejectedEntry {
            index: 0,
            redacted: String::new(),
            error: ImportError::TooLarge { size: input.len(), limit: MAX_BATCH_BYTES },
        });
        return batch;
    }

    for (offset, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || is_comment(line) {
            continue;
        }
        let index = offset.saturating_add(1);
        if batch.len() >= MAX_LINKS {
            batch.rejected.push(RejectedEntry {
                index,
                redacted: String::new(),
                error: ImportError::TooManyEntries { limit: MAX_LINKS },
            });
            break;
        }
        match link::parse(line, source.clone()) {
            Ok(entry) => batch.push(entry),
            Err(error) => batch.rejected.push(RejectedEntry {
                index,
                redacted: redacted_excerpt(line),
                error,
            }),
        }
    }
    batch
}

/// Derive a node identifier from a display name, falling back to a token.
///
/// Shared by the link and Xray-JSON importers so both produce the same shape.
pub(crate) fn link_id(name: &str, fallback: &str) -> NodeId {
    link::make_id_for(name, fallback)
}

fn is_comment(line: &str) -> bool {
    line.starts_with('#') || line.starts_with(';') || line.starts_with("//")
}

/// Redact a line and bound its length so it is safe to show in a diagnostic.
pub(crate) fn redacted_excerpt(line: &str) -> String {
    const MAX_EXCERPT_CHARS: usize = 80;
    let redacted = redact_text(line);
    let mut out: String = redacted.chars().take(MAX_EXCERPT_CHARS).collect();
    if out.chars().count() < redacted.chars().count() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{Compatibility, ProtocolSettings};

    const VLESS: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&path=%2Fray&security=tls&sni=cdn.example.com#HK%2001";

    #[test]
    fn empty_and_blank_inputs_are_rejected() {
        assert_eq!(parse_uri(""), Err(ImportError::Empty));
        assert_eq!(parse_uri("   \n\t "), Err(ImportError::Empty));
    }

    #[test]
    fn oversized_input_is_refused_before_parsing() {
        let huge = format!("vless://{}@h:1", "a".repeat(MAX_LINK_BYTES));
        let err = parse_uri(&huge).expect_err("must refuse");
        assert!(matches!(err, ImportError::TooLarge { limit: MAX_LINK_BYTES, .. }), "{err:?}");
    }

    #[test]
    fn non_uri_text_is_not_a_share_link() {
        assert_eq!(parse_uri("just some words"), Err(ImportError::NotAShareLink));
        assert_eq!(parse_uri("mailto:a@b.example"), Err(ImportError::NotAShareLink));
        assert_eq!(parse_uri("://nohost"), Err(ImportError::NotAShareLink));
    }

    #[test]
    fn parse_many_files_entries_into_buckets() {
        let input = format!(
            "# a comment\n\n{VLESS}\nssr://Zm9v\ngarbage line\n// another comment\n{VLESS}\n"
        );
        let batch = parse_many(&input, NodeSource::Manual);
        assert_eq!(batch.nodes.len(), 2);
        assert_eq!(batch.unsupported.len(), 1);
        assert_eq!(batch.rejected.len(), 1);
        assert_eq!(batch.len(), 3);
        assert!(batch.has_rejects());
        assert_eq!(batch.rejected.first().map(|r| r.index), Some(5));
    }

    #[test]
    fn parse_many_stops_at_the_entry_limit() {
        let mut input = String::new();
        for _ in 0..(MAX_LINKS + 5) {
            input.push_str(VLESS);
            input.push('\n');
        }
        let batch = parse_many(&input, NodeSource::Manual);
        assert_eq!(batch.nodes.len(), MAX_LINKS);
        assert_eq!(
            batch.rejected.first().map(|r| r.error.clone()),
            Some(ImportError::TooManyEntries { limit: MAX_LINKS })
        );
    }

    #[test]
    fn parse_many_refuses_an_oversized_body() {
        let input = "x".repeat(MAX_BATCH_BYTES + 1);
        let batch = parse_many(&input, NodeSource::Manual);
        assert!(batch.is_empty());
        assert_eq!(batch.rejected.len(), 1);
    }

    #[test]
    fn parse_many_carries_the_source_through() {
        let source = NodeSource::File { path: "/tmp/links.txt".into() };
        let batch = parse_many(VLESS, source.clone());
        assert_eq!(batch.nodes.first().map(|n| n.source.clone()), Some(source));
    }

    #[test]
    fn rejected_lines_are_redacted_and_bounded() {
        let broken = format!("vless://{}", "z".repeat(500));
        let batch = parse_many(&broken, NodeSource::Manual);
        let rejected = batch.rejected.first().expect("one reject");
        assert!(!rejected.redacted.contains("zzzz"), "{}", rejected.redacted);
        assert!(rejected.redacted.chars().count() <= 81, "{}", rejected.redacted);
    }

    #[test]
    fn error_display_never_contains_a_credential() {
        // Every input here carries a distinctive credential; none of it may reach
        // an error message.
        let inputs = [
            "vless://SUPERSECRETUUID@:443",
            "vless://SUPERSECRETUUID@host:99999",
            "trojan://SUPERSECRETPASSWORD@host",
            "vmess://%%%SUPERSECRET%%%",
            "vmess://U1VQRVJTRUNSRVQ=",
            "ss://SUPERSECRETPASSWORD",
            "ss://YWVzLTI1Ni1nY206U1VQRVJTRUNSRVQ=",
            "socks://SUPERSECRETPASSWORD@",
            "hysteria2://SUPERSECRETPASSWORD@host:443",
        ];
        for input in inputs {
            let rendered = match parse_uri(input) {
                Ok(entry) => format!("{entry:?}"),
                Err(error) => format!("{error} / {error:?}"),
            };
            assert!(!rendered.contains("SUPERSECRET"), "{input} -> {rendered}");
        }
    }

    #[test]
    fn entry_accessors_agree_with_the_variant() {
        let entry = parse_uri(VLESS).expect("valid");
        assert!(entry.is_supported());
        assert!(entry.as_unsupported().is_none());
        assert_eq!(entry.name(), "HK 01");
        assert!(entry.id().as_str().starts_with("hk-01-"));
        let node = entry.into_node().expect("supported");
        assert!(matches!(node.protocol, ProtocolSettings::Vless(_)));
        assert_eq!(node.compatibility, Compatibility::Supported);

        let entry = parse_uri("tuic://x@host:443#T").expect("classified");
        assert!(!entry.is_supported());
        assert!(entry.as_node().is_none());
        assert!(entry.into_node().is_none());
    }

    #[test]
    fn batch_helpers_behave() {
        let mut batch = ImportBatch::new();
        assert!(batch.is_empty());
        assert!(!batch.has_rejects());
        batch.push(parse_uri(VLESS).expect("valid"));
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Arbitrary text must never panic the URI parser, and must terminate.
        #[test]
        fn parse_uri_never_panics(raw in ".*") {
            let _ = parse_uri(&raw);
        }

        /// The same, for text that looks link-shaped enough to reach a parser.
        #[test]
        fn share_shaped_input_never_panics(
            scheme in "(vless|vmess|trojan|ss|socks|socks5|http|http-proxy|ssr|hy2|tuic|zz)",
            rest in "[ -~]{0,160}",
        ) {
            let link = format!("{scheme}://{rest}");
            let _ = parse_uri(&link);
        }

        /// Arbitrary bytes read as lossy UTF-8 must never panic the batch parser.
        #[test]
        fn parse_many_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let text = String::from_utf8_lossy(&bytes);
            let batch = parse_many(&text, xraytui_domain::NodeSource::Manual);
            prop_assert!(batch.len() <= MAX_LINKS);
        }

        /// Every produced node must be internally consistent enough to display.
        #[test]
        fn produced_nodes_have_valid_identifiers(rest in "[ -~]{0,80}") {
            let link = format!("vless://{rest}");
            if let Ok(entry) = parse_uri(&link) {
                prop_assert!(xraytui_domain::validate_slug(entry.id().as_str()).is_ok());
                prop_assert!(entry.name().chars().count() <= MAX_NAME_CHARS);
            }
        }
    }
}
