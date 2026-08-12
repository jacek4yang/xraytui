//! Turning a subscription body into nodes, without trusting any of it.
//!
//! # What arrives
//!
//! Providers send one of three things, and none of them says which:
//!
//! * a list of share links, one per line;
//! * the same list, base64-encoded, sometimes with padding and sometimes URL-safe;
//! * a JSON document in one of several unrelated shapes.
//!
//! Detection is by trying, in that order, and taking the first that yields at
//! least one recognisable entry. A body that yields nothing is an error rather
//! than an empty update, because "the provider sent us nothing" and "the
//! provider removed all your nodes" look identical otherwise, and only one of
//! them should delete anything.
//!
//! # The filters
//!
//! `include_regex` keeps only names that match; `exclude_regex` then drops names
//! that match. Both are compiled with the same bounded engine the group filters
//! use — an unbounded regex on text a provider controls is a denial of service
//! waiting to be handed to you. `max_nodes` caps the result, keeping the first
//! entries in the order the provider sent them.

use xraytui_domain::{Node, NodeId, NodeSource, Subscription, UnsupportedNode};
use xraytui_import::{ImportBatch, RejectedEntry};

/// Everything normalisation can report.
#[derive(Debug, thiserror::Error)]
pub enum NormaliseError {
    /// Nothing in the body could be classified.
    ///
    /// Deliberately an error: an empty result must never be mistaken for "the
    /// provider removed everything".
    #[error(
        "nothing in the response looked like a node ({bytes} bytes, {lines} lines); \
         refusing to treat that as an empty subscription"
    )]
    NothingRecognised {
        /// Size of the body.
        bytes: usize,
        /// How many lines it had.
        lines: usize,
    },
    /// A configured filter is not a pattern this engine accepts.
    #[error("{field} pattern {pattern:?} is not usable: {reason}")]
    Pattern {
        /// Which field.
        field: &'static str,
        /// The pattern.
        pattern: String,
        /// Why it was refused.
        reason: String,
    },
}

/// What a body turned into.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Normalised {
    /// Nodes the compiler can use, in provider order.
    pub nodes: Vec<Node>,
    /// Entries recognised as proxies but not compilable.
    pub unsupported: Vec<UnsupportedNode>,
    /// Lines that could not be classified at all.
    pub rejected: Vec<RejectedEntry>,
    /// How many duplicates were collapsed.
    pub deduplicated: usize,
    /// How many entries the filters removed.
    pub filtered_out: usize,
}

/// Parse, filter, deduplicate and cap a subscription body.
///
/// # Errors
/// See [`NormaliseError`].
pub fn normalise(subscription: &Subscription, body: &str) -> Result<Normalised, NormaliseError> {
    let source = NodeSource::Subscription {
        id: subscription.id.clone(),
    };

    let decoded = decode(body);
    let batch = xraytui_import::parse_many(&decoded, source);
    if batch.is_empty() {
        return Err(NormaliseError::NothingRecognised {
            bytes: body.len(),
            lines: body.lines().count(),
        });
    }

    let include = compile_all("include_regex", &subscription.include_regex)?;
    let exclude = compile_all("exclude_regex", &subscription.exclude_regex)?;

    let ImportBatch {
        nodes,
        unsupported,
        rejected,
    } = batch;

    let before = nodes.len();
    let mut kept: Vec<Node> = nodes
        .into_iter()
        .filter(|node| keep(&node.name, &include, &exclude))
        .collect();
    let filtered_out = before - kept.len();

    // Providers repeat entries; two identical definitions must become one node,
    // not two that differ only by a suffix.
    let mut seen = std::collections::HashSet::new();
    let mut deduplicated = 0;
    kept.retain(|node| {
        if seen.insert(node.canonical_identity()) {
            true
        } else {
            deduplicated += 1;
            false
        }
    });

    // Two different nodes can legitimately share a slugified name; the identity
    // above has already established they are different, so the *identifier* is
    // what has to be made unique.
    let mut used: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    for node in &mut kept {
        if !used.insert(node.id.clone()) {
            let fresh = NodeId::from_text(&format!(
                "{}-{}",
                node.id.as_str(),
                xraytui_domain::fresh_suffix()
            ));
            node.id = fresh.clone();
            used.insert(fresh);
        }
    }

    let mut capped = 0;
    if let Some(limit) = subscription.max_nodes
        && kept.len() > limit
    {
        capped = kept.len() - limit;
        kept.truncate(limit);
    }

    Ok(Normalised {
        nodes: kept,
        unsupported,
        rejected,
        deduplicated,
        filtered_out: filtered_out + capped,
    })
}

/// Decode a body that may or may not be base64.
///
/// Tried rather than detected: the encodings overlap — a list of share links is
/// also valid base64 alphabet in places — so the only reliable test is whether
/// decoding yields something that looks more like links than the original did.
#[must_use]
pub fn decode(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // A body that already contains a scheme is not encoded.
    if trimmed.contains("://") {
        return trimmed.to_owned();
    }
    match xraytui_import::decode_base64_flexible(trimmed) {
        Some(bytes) => match String::from_utf8(bytes) {
            Ok(text) if text.contains("://") => text,
            _ => trimmed.to_owned(),
        },
        None => trimmed.to_owned(),
    }
}

fn compile_all(
    field: &'static str,
    patterns: &[String],
) -> Result<Vec<xraytui_domain::Pattern>, NormaliseError> {
    patterns
        .iter()
        .map(|pattern| {
            xraytui_domain::Pattern::new(pattern).map_err(|reason| NormaliseError::Pattern {
                field,
                pattern: pattern.clone(),
                reason: reason.to_string(),
            })
        })
        .collect()
}

fn keep(
    name: &str,
    include: &[xraytui_domain::Pattern],
    exclude: &[xraytui_domain::Pattern],
) -> bool {
    if !include.is_empty() && !include.iter().any(|pattern| pattern.is_match(name)) {
        return false;
    }
    !exclude.iter().any(|pattern| pattern.is_match(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn subscription() -> Subscription {
        Subscription {
            id: xraytui_domain::SubscriptionId::from_text("provider"),
            name: "Provider".to_owned(),
            url: xraytui_secrets::Secret::new("https://example.test/sub"),
            enabled: true,
            update_interval_secs: None,
            fetch_via_profile: None,
            include_regex: Vec::new(),
            exclude_regex: Vec::new(),
            max_nodes: None,
            max_response_bytes: None,
            meta: xraytui_domain::SubscriptionMeta::default(),
        }
    }

    fn body() -> String {
        [
            "vless://11111111-1111-1111-1111-111111111111@198.51.100.1:443?type=tcp&security=none#HK%20One",
            "vless://22222222-2222-2222-2222-222222222222@198.51.100.2:443?type=tcp&security=none#JP%20Two",
            "vless://33333333-3333-3333-3333-333333333333@198.51.100.3:443?type=tcp&security=none#HK%20Three",
        ]
        .join("\n")
    }

    #[test]
    fn a_plain_list_is_parsed() {
        let result = normalise(&subscription(), &body()).expect("normalise");
        assert_eq!(result.nodes.len(), 3);
        assert_eq!(result.deduplicated, 0);
        assert_eq!(result.filtered_out, 0);
    }

    #[test]
    fn a_base64_body_is_decoded_first() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(body());
        let result = normalise(&subscription(), &encoded).expect("normalise");
        assert_eq!(result.nodes.len(), 3);
    }

    #[test]
    fn a_url_safe_base64_body_without_padding_is_decoded_too() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body());
        let result = normalise(&subscription(), &encoded).expect("normalise");
        assert_eq!(result.nodes.len(), 3);
    }

    #[test]
    fn every_node_is_attributed_to_the_subscription_that_supplied_it() {
        let subscription = subscription();
        let result = normalise(&subscription, &body()).expect("normalise");
        for node in &result.nodes {
            assert!(
                node.source.owned_by(&subscription.id),
                "{:?} is not owned by the subscription",
                node.id
            );
        }
    }

    #[test]
    fn an_empty_body_is_an_error_not_an_empty_update() {
        // This is the whole reason the error exists: an empty result would
        // otherwise diff as "remove every node you have".
        for body in ["", "   \n\n  ", "not a link at all", "# a comment"] {
            let error = normalise(&subscription(), body).expect_err("must refuse");
            assert!(
                matches!(error, NormaliseError::NothingRecognised { .. }),
                "{body:?}: {error:?}"
            );
        }
    }

    #[test]
    fn an_include_filter_keeps_only_what_matches() {
        let mut subscription = subscription();
        subscription.include_regex = vec!["^HK".to_owned()];
        let result = normalise(&subscription, &body()).expect("normalise");
        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.filtered_out, 1);
        assert!(result.nodes.iter().all(|node| node.name.starts_with("HK")));
    }

    #[test]
    fn an_exclude_filter_runs_after_the_include_filter() {
        let mut subscription = subscription();
        subscription.include_regex = vec!["^HK".to_owned()];
        subscription.exclude_regex = vec!["Three".to_owned()];
        let result = normalise(&subscription, &body()).expect("normalise");
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].name, "HK One");
    }

    #[test]
    fn a_pattern_the_engine_will_not_accept_is_reported_rather_than_ignored() {
        let mut subscription = subscription();
        subscription.include_regex = vec!["(a+)+b".to_owned()];
        let error = normalise(&subscription, &body()).expect_err("must refuse");
        assert!(matches!(error, NormaliseError::Pattern { .. }), "{error:?}");
    }

    #[test]
    fn duplicates_are_collapsed_and_counted() {
        let mut text = body();
        text.push('\n');
        text.push_str(&body());
        let result = normalise(&subscription(), &text).expect("normalise");
        assert_eq!(result.nodes.len(), 3);
        assert_eq!(result.deduplicated, 3);
    }

    #[test]
    fn two_different_nodes_with_the_same_name_both_survive_with_distinct_ids() {
        let text = [
            "vless://11111111-1111-1111-1111-111111111111@198.51.100.1:443?type=tcp&security=none#Same",
            "vless://22222222-2222-2222-2222-222222222222@198.51.100.2:443?type=tcp&security=none#Same",
        ]
        .join("\n");
        let result = normalise(&subscription(), &text).expect("normalise");
        assert_eq!(result.nodes.len(), 2, "neither may be lost");
        assert_ne!(
            result.nodes[0].id, result.nodes[1].id,
            "two nodes cannot share an identifier"
        );
    }

    #[test]
    fn the_node_cap_keeps_the_first_entries_in_provider_order() {
        let mut subscription = subscription();
        subscription.max_nodes = Some(2);
        let result = normalise(&subscription, &body()).expect("normalise");
        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.nodes[0].name, "HK One");
        assert_eq!(result.nodes[1].name, "JP Two");
        assert_eq!(result.filtered_out, 1);
    }

    #[test]
    fn an_unrecognised_line_is_reported_rather_than_dropped_silently() {
        let mut text = body();
        text.push_str("\nnonsense://what@is:this\n");
        let result = normalise(&subscription(), &text).expect("normalise");
        assert_eq!(result.nodes.len(), 3);
        assert!(
            !result.unsupported.is_empty() || !result.rejected.is_empty(),
            "the odd line must be accounted for somewhere"
        );
    }

    #[test]
    fn decoding_leaves_a_body_that_is_already_links_alone() {
        let text = body();
        assert_eq!(decode(&text), text.trim());
    }

    #[test]
    fn decoding_something_that_is_neither_leaves_it_alone() {
        assert_eq!(decode("hello world"), "hello world");
        assert_eq!(decode(""), "");
    }
}
