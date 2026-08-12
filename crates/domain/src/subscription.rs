//! Subscription records and the transactional diff they produce.

use serde::{Deserialize, Serialize};
use xraytui_secrets::Secret;

use crate::ids::{NodeId, SubscriptionId};
use crate::node::{Node, UnsupportedNode};

/// A remote source of nodes with its own namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// Stable identifier; also the node namespace.
    pub id: SubscriptionId,
    /// Display name.
    pub name: String,
    /// Fetch URL. Secret: it usually contains a bearer token.
    pub url: Secret,
    /// Whether automatic updates run.
    #[serde(default = "crate::node::default_true")]
    pub enabled: bool,
    /// Seconds between automatic updates; `None` disables them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_interval_secs: Option<u64>,
    /// Route the fetch through this profile instead of going direct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_via_profile: Option<crate::ids::ProfileId>,
    /// Regular expressions a node name must match to be kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_regex: Vec<String>,
    /// Regular expressions that drop a node after inclusion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_regex: Vec<String>,
    /// Optional per-subscription override of the global response size cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    /// Optional per-subscription override of the global node count cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<usize>,
    /// Cached HTTP validators and server-reported metadata.
    #[serde(default)]
    pub meta: SubscriptionMeta,
}

/// Everything learned from the last successful fetch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionMeta {
    /// `ETag` from the last successful response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// `Last-Modified` from the last successful response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// Unix seconds of the last successful update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_unix: Option<i64>,
    /// Unix seconds of the last attempt, successful or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_unix: Option<i64>,
    /// Error text from the last failed attempt. Redacted before storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Bytes uploaded, from a `Subscription-Userinfo` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_bytes: Option<u64>,
    /// Bytes downloaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_bytes: Option<u64>,
    /// Total quota in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// Expiry, unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_unix: Option<i64>,
    /// Number of nodes after the last successful update.
    #[serde(default)]
    pub node_count: usize,
}

impl SubscriptionMeta {
    /// Remaining quota in bytes, when the server reported enough to compute it.
    #[must_use]
    pub fn remaining_bytes(&self) -> Option<u64> {
        let total = self.total_bytes?;
        let used = self.upload_bytes.unwrap_or(0).saturating_add(self.download_bytes.unwrap_or(0));
        Some(total.saturating_sub(used))
    }
}

/// One entry of a subscription update diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "kebab-case")]
pub enum NodeChange {
    /// A node not previously present.
    Added {
        /// The new node.
        node: Box<Node>,
    },
    /// A node whose definition changed.
    Changed {
        /// Node identifier, preserved across the change.
        id: NodeId,
        /// New definition.
        node: Box<Node>,
        /// Field names that differ, for display. Never contains values.
        fields: Vec<String>,
    },
    /// A node present before but absent now.
    Removed {
        /// Node identifier.
        id: NodeId,
        /// Display name, for the confirmation prompt.
        name: String,
        /// Whether a profile, group, chain or rule currently points at it.
        in_use: bool,
    },
    /// A recognised proxy definition that cannot be compiled.
    Unsupported {
        /// The preserved record.
        node: Box<UnsupportedNode>,
    },
    /// An entry that could not be parsed at all.
    Rejected {
        /// Bounded, credential-free explanation.
        reason: String,
    },
}

impl NodeChange {
    /// Single-character marker used in the TUI diff view.
    #[must_use]
    pub fn marker(&self) -> char {
        match self {
            Self::Added { .. } => '+',
            Self::Changed { .. } => '~',
            Self::Removed { .. } => '-',
            Self::Unsupported { .. } => '?',
            Self::Rejected { .. } => '!',
        }
    }
}

/// The complete result of computing an update without committing it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionDiff {
    /// Ordered changes.
    pub changes: Vec<NodeChange>,
    /// Server metadata observed during the fetch.
    pub meta: SubscriptionMeta,
    /// Number of duplicate entries collapsed during normalisation.
    pub deduplicated: usize,
    /// Number of entries removed by include/exclude filters.
    pub filtered_out: usize,
}

impl SubscriptionDiff {
    /// Counts by change kind: `(added, changed, removed, unsupported, rejected)`.
    #[must_use]
    pub fn counts(&self) -> DiffCounts {
        let mut counts = DiffCounts::default();
        for change in &self.changes {
            match change {
                NodeChange::Added { .. } => counts.added += 1,
                NodeChange::Changed { .. } => counts.changed += 1,
                NodeChange::Removed { .. } => counts.removed += 1,
                NodeChange::Unsupported { .. } => counts.unsupported += 1,
                NodeChange::Rejected { .. } => counts.rejected += 1,
            }
        }
        counts
    }

    /// True when committing the diff would change nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.iter().all(|c| matches!(c, NodeChange::Rejected { .. })) && self.changes.is_empty()
    }

    /// Nodes that would be removed while something still points at them.
    #[must_use]
    pub fn removals_in_use(&self) -> Vec<&NodeId> {
        self.changes
            .iter()
            .filter_map(|c| match c {
                NodeChange::Removed { id, in_use: true, .. } => Some(id),
                _ => None,
            })
            .collect()
    }
}

/// Per-kind change counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffCounts {
    /// Nodes added.
    pub added: usize,
    /// Nodes changed.
    pub changed: usize,
    /// Nodes removed.
    pub removed: usize,
    /// Entries preserved as unsupported.
    pub unsupported: usize,
    /// Entries rejected outright.
    pub rejected: usize,
}

impl DiffCounts {
    /// Compact summary such as `+3 ~1 -2 ?1`.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.added > 0 {
            parts.push(format!("+{}", self.added));
        }
        if self.changed > 0 {
            parts.push(format!("~{}", self.changed));
        }
        if self.removed > 0 {
            parts.push(format!("-{}", self.removed));
        }
        if self.unsupported > 0 {
            parts.push(format!("?{}", self.unsupported));
        }
        if self.rejected > 0 {
            parts.push(format!("!{}", self.rejected));
        }
        if parts.is_empty() {
            "no changes".to_owned()
        } else {
            parts.join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_quota_is_computed_when_possible() {
        let meta = SubscriptionMeta {
            upload_bytes: Some(10),
            download_bytes: Some(20),
            total_bytes: Some(100),
            ..Default::default()
        };
        assert_eq!(meta.remaining_bytes(), Some(70));
        assert_eq!(SubscriptionMeta::default().remaining_bytes(), None);
    }

    #[test]
    fn remaining_quota_saturates_instead_of_underflowing() {
        let meta = SubscriptionMeta {
            upload_bytes: Some(200),
            download_bytes: Some(200),
            total_bytes: Some(100),
            ..Default::default()
        };
        assert_eq!(meta.remaining_bytes(), Some(0));
    }

    #[test]
    fn diff_summary_is_compact() {
        let counts = DiffCounts { added: 3, changed: 1, removed: 2, unsupported: 1, rejected: 0 };
        assert_eq!(counts.summary(), "+3 ~1 -2 ?1");
        assert_eq!(DiffCounts::default().summary(), "no changes");
    }

    #[test]
    fn subscription_url_is_not_revealed_by_debug() {
        let sub = Subscription {
            id: SubscriptionId::new("s1").expect("valid"),
            name: "provider".into(),
            url: Secret::new("https://example.com/sub?token=abcdef"),
            enabled: true,
            update_interval_secs: None,
            fetch_via_profile: None,
            include_regex: vec![],
            exclude_regex: vec![],
            max_response_bytes: None,
            max_nodes: None,
            meta: SubscriptionMeta::default(),
        };
        let rendered = format!("{sub:?}");
        assert!(!rendered.contains("abcdef"), "{rendered}");
    }
}
