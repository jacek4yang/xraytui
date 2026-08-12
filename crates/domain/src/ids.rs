//! Strongly typed identifiers.
//!
//! Every entity in the model is addressed by a distinct newtype so that a
//! `NodeId` can never be passed where a `ProfileId` is expected. All of them wrap
//! a validated slug: lowercase ASCII alphanumerics plus `-` and `_`, 1..=64 bytes,
//! never starting or ending with a separator.
//!
//! The slug restriction is not cosmetic. Identifiers end up inside generated Xray
//! tags, nftables comments, cgroup directory names and systemd unit arguments, so
//! they must be free of `/`, whitespace, quotes and shell metacharacters by
//! construction rather than by escaping at each use site.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum identifier length in bytes.
pub const MAX_ID_LEN: usize = 64;

/// Why an identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// The identifier had no characters.
    #[error("identifier is empty")]
    Empty,
    /// The identifier exceeded [`MAX_ID_LEN`].
    #[error("identifier is longer than {MAX_ID_LEN} bytes ({0} bytes)")]
    TooLong(usize),
    /// A byte outside `[a-z0-9_-]` appeared.
    #[error("identifier contains invalid character {0:?}; allowed: a-z 0-9 - _")]
    InvalidChar(char),
    /// A leading or trailing separator.
    #[error("identifier must not start or end with '-' or '_'")]
    EdgeSeparator,
}

/// Validate a slug, returning it unchanged on success.
///
/// Uppercase input is *rejected* rather than silently lowercased so that two
/// configurations that differ only in case cannot compile to the same tag.
pub fn validate_slug(raw: &str) -> Result<(), IdError> {
    if raw.is_empty() {
        return Err(IdError::Empty);
    }
    if raw.len() > MAX_ID_LEN {
        return Err(IdError::TooLong(raw.len()));
    }
    for ch in raw.chars() {
        let ok = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_';
        if !ok {
            return Err(IdError::InvalidChar(ch));
        }
    }
    let first = raw.as_bytes().first().copied().unwrap_or(b'-');
    let last = raw.as_bytes().last().copied().unwrap_or(b'-');
    if matches!(first, b'-' | b'_') || matches!(last, b'-' | b'_') {
        return Err(IdError::EdgeSeparator);
    }
    Ok(())
}

/// Best-effort conversion of arbitrary text into a valid slug.
///
/// Used when importing a node whose remark is `香港 01 | IEPL`: the display name
/// keeps the original text, the identifier gets a machine-safe derivative. The
/// caller is responsible for uniquifying the result.
#[must_use]
pub fn slugify(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_ID_LEN));
    let mut last_sep = true;
    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' {
            if last_sep {
                continue;
            }
            last_sep = true;
        } else {
            last_sep = false;
        }
        if out.len() + 1 > MAX_ID_LEN {
            break;
        }
        out.push(mapped);
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("item");
    }
    out
}

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Create a validated ", $kind, " identifier.")]
            pub fn new(raw: impl Into<String>) -> Result<Self, IdError> {
                let raw = raw.into();
                validate_slug(&raw)?;
                Ok(Self(raw))
            }

            #[doc = concat!("Derive a ", $kind, " identifier from arbitrary text.")]
            #[must_use]
            pub fn from_text(raw: &str) -> Self {
                Self(slugify(raw))
            }

            /// Borrow the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume the wrapper, yielding the inner string.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }

            #[doc = "The entity kind this identifier addresses, for diagnostics."]
            #[must_use]
            pub const fn kind() -> &'static str {
                $kind
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::new(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

typed_id!(
    /// Identifies a normalized outbound endpoint.
    NodeId,
    "node"
);
typed_id!(
    /// Identifies a logical collection of nodes or chains.
    GroupId,
    "group"
);
typed_id!(
    /// Identifies an ordered multi-hop path.
    ChainId,
    "chain"
);
typed_id!(
    /// Identifies an independently selectable egress slot.
    ProfileId,
    "profile"
);
typed_id!(
    /// Identifies a subscription namespace.
    SubscriptionId,
    "subscription"
);
typed_id!(
    /// Identifies an ordered application-matching rule.
    AppRuleId,
    "application rule"
);
typed_id!(
    /// Identifies an ordered destination/metadata routing rule.
    RoutingRuleId,
    "routing rule"
);

/// Monotonically increasing identifier for a compiled Xray configuration.
///
/// A generation bundles: the compiled JSON, the selector overrides that were in
/// force, the network state that was applied, and the health verdict. Rollback is
/// expressed as "return to generation N".
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct GenerationId(pub u64);

impl GenerationId {
    /// The generation before anything has been compiled.
    pub const ZERO: Self = Self(0);

    /// The next generation after this one.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for GenerationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gen{}", self.0)
    }
}

/// Generate a fresh sortable identifier suffix.
///
/// UUID v7 is used because its leading timestamp makes generated node identifiers
/// sort in import order, which keeps large lists stable in the TUI.
#[must_use]
pub fn fresh_suffix() -> String {
    let uuid = uuid::Uuid::now_v7();
    uuid.simple().to_string()[..12].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_slugs_are_accepted() {
        for good in ["a", "hk-01", "profile_web", "n0de", "a".repeat(64).as_str()] {
            assert!(NodeId::new(good).is_ok(), "{good} should be valid");
        }
    }

    #[test]
    fn invalid_slugs_are_rejected() {
        assert_eq!(NodeId::new(""), Err(IdError::Empty));
        assert_eq!(NodeId::new("a".repeat(65)), Err(IdError::TooLong(65)));
        assert_eq!(NodeId::new("HK-01"), Err(IdError::InvalidChar('H')));
        assert_eq!(NodeId::new("a b"), Err(IdError::InvalidChar(' ')));
        assert_eq!(NodeId::new("a/b"), Err(IdError::InvalidChar('/')));
        assert_eq!(NodeId::new("-a"), Err(IdError::EdgeSeparator));
        assert_eq!(NodeId::new("a-"), Err(IdError::EdgeSeparator));
    }

    #[test]
    fn slugify_handles_unicode_and_punctuation() {
        assert_eq!(slugify("香港 01 | IEPL"), "01-iepl");
        assert_eq!(slugify("Japan #2 (fast)"), "japan-2-fast");
        assert_eq!(slugify("!!!"), "item");
        assert_eq!(slugify(""), "item");
        assert!(slugify(&"x".repeat(200)).len() <= MAX_ID_LEN);
    }

    #[test]
    fn slugify_output_always_validates() {
        for raw in ["香港", "---", "a--b", "  spaces  ", "ÄÖÜ", "🎉🎉", "9"] {
            let slug = slugify(raw);
            assert!(validate_slug(&slug).is_ok(), "{raw:?} -> {slug:?}");
        }
    }

    #[test]
    fn ids_are_distinct_types() {
        let node = NodeId::new("x").expect("valid");
        let profile = ProfileId::new("x").expect("valid");
        assert_eq!(node.as_str(), profile.as_str());
        // The following would not compile, which is the point:
        // let _: NodeId = profile;
    }

    #[test]
    fn generation_increments() {
        assert_eq!(GenerationId::ZERO.next(), GenerationId(1));
        assert_eq!(GenerationId(7).to_string(), "gen7");
    }

    #[test]
    fn debug_shows_kind() {
        let id = ProfileId::new("web").expect("valid");
        assert_eq!(format!("{id:?}"), "ProfileId(web)");
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn slugify_never_panics_and_always_validates(raw in ".*") {
            let slug = slugify(&raw);
            prop_assert!(validate_slug(&slug).is_ok(), "{raw:?} -> {slug:?}");
            prop_assert!(slug.len() <= MAX_ID_LEN);
        }

        #[test]
        fn validated_ids_round_trip(raw in "[a-z0-9][a-z0-9_-]{0,40}[a-z0-9]") {
            let id = NodeId::new(raw.clone()).expect("generated valid");
            prop_assert_eq!(id.as_str(), raw.as_str());
        }
    }
}
