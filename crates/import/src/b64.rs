//! Base64 decoding that tolerates what real subscription providers emit.
//!
//! In practice a share link or subscription body may use the standard alphabet
//! or the URL-safe one, may or may not be padded, and may have newlines folded
//! into it. Rather than guessing, every accepted combination is tried in turn.

use base64::Engine;
use base64::engine::general_purpose::{
    STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};

/// Largest base64 payload accepted, in bytes.
///
/// Decoding is a 3/4 expansion, so this bounds the allocation at ~6 MiB.
pub const MAX_BASE64_INPUT: usize = 8 * 1024 * 1024;

/// Decode base64 in whichever common variant the input happens to use.
///
/// Whitespace anywhere in the input is discarded first, which is what makes
/// line-folded subscription bodies work. Returns `None` when the input is
/// oversized or decodes under none of the four alphabet/padding combinations.
///
/// ```
/// # use xraytui_import::decode_base64_flexible;
/// assert_eq!(decode_base64_flexible("aGk=").as_deref(), Some(&b"hi"[..]));
/// assert_eq!(decode_base64_flexible("aGk").as_deref(), Some(&b"hi"[..]));
/// assert_eq!(decode_base64_flexible("a\nG\nk").as_deref(), Some(&b"hi"[..]));
/// assert_eq!(decode_base64_flexible("%%%"), None);
/// ```
#[must_use]
pub fn decode_base64_flexible(input: &str) -> Option<Vec<u8>> {
    if input.len() > MAX_BASE64_INPUT {
        return None;
    }
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    // Ordered so that the most common encoding is tried first.
    STANDARD
        .decode(&compact)
        .or_else(|_| URL_SAFE.decode(&compact))
        .or_else(|_| STANDARD_NO_PAD.decode(compact.trim_end_matches('=')))
        .or_else(|_| URL_SAFE_NO_PAD.decode(compact.trim_end_matches('=')))
        .ok()
}

/// Decode base64 and require the result to be UTF-8.
#[must_use]
pub fn decode_base64_utf8(input: &str) -> Option<String> {
    let bytes = decode_base64_flexible(input)?;
    String::from_utf8(bytes).ok()
}

/// Encode with the standard padded alphabet, as share links expect.
#[must_use]
pub fn encode_standard(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Encode with the URL-safe unpadded alphabet, used by SIP002 `ss://` links.
#[must_use]
pub fn encode_url_safe_no_pad(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Whether a string is plausibly a base64 blob rather than plain text.
///
/// Used to tell a base64-encoded subscription body from a plain link list
/// without decoding the whole thing twice.
#[must_use]
pub fn looks_like_base64(input: &str) -> bool {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 8 {
        return false;
    }
    compact
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_alphabet_and_padding_combination_decodes() {
        // "hello?~" contains bytes that differ between the two alphabets.
        let raw = b"\xfb\xff\xbe";
        for encoded in [
            STANDARD.encode(raw),
            STANDARD_NO_PAD.encode(raw),
            URL_SAFE.encode(raw),
            URL_SAFE_NO_PAD.encode(raw),
        ] {
            assert_eq!(
                decode_base64_flexible(&encoded).as_deref(),
                Some(&raw[..]),
                "failed for {encoded}"
            );
        }
    }

    #[test]
    fn embedded_whitespace_is_ignored() {
        assert_eq!(decode_base64_flexible(" aG\r\nVs bG8= ").as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn garbage_and_empty_input_yield_none() {
        assert_eq!(decode_base64_flexible(""), None);
        assert_eq!(decode_base64_flexible("   "), None);
        assert_eq!(decode_base64_flexible("%%%"), None);
        assert_eq!(decode_base64_flexible("a"), None);
    }

    #[test]
    fn oversized_input_is_refused_without_allocating() {
        let huge = "A".repeat(MAX_BASE64_INPUT + 1);
        assert_eq!(decode_base64_flexible(&huge), None);
    }

    #[test]
    fn utf8_decoding_rejects_invalid_sequences() {
        let invalid = STANDARD.encode([0xff, 0xfe]);
        assert_eq!(decode_base64_utf8(&invalid), None);
        assert_eq!(decode_base64_utf8(&STANDARD.encode("ok")).as_deref(), Some("ok"));
    }

    #[test]
    fn base64_detection_separates_bodies_from_link_lists() {
        assert!(looks_like_base64("dmxlc3M6Ly94QGgxOjQ0Mw=="));
        assert!(!looks_like_base64("vless://x@h:443"));
        assert!(!looks_like_base64("short"));
    }

    #[test]
    fn round_trip_through_both_encoders() {
        let raw = b"method:password";
        assert_eq!(decode_base64_flexible(&encode_standard(raw)).as_deref(), Some(&raw[..]));
        assert_eq!(
            decode_base64_flexible(&encode_url_safe_no_pad(raw)).as_deref(),
            Some(&raw[..])
        );
    }
}
