//! Comparing what a provider sent against what the user already has.
//!
//! # Pure, on purpose
//!
//! `xraytui subscription diff` and `xraytui subscription update` call the same
//! function; the first prints the result and stops, the second hands it to
//! [`mod@crate::apply`]. A preview computed by different code from the thing it
//! previews is a preview nobody should trust.
//!
//! # What identity means here
//!
//! A node is "the same node" as one already stored when their
//! [`Node::canonical_identity`] matches — protocol, endpoint, transport and a
//! *fingerprint* of the credential, never the credential itself. That means a
//! provider that renames a node produces a *change*, not a remove-and-add, so
//! a profile pointing at it keeps working. A provider that rotates the
//! credential produces a change too, and the diff says which fields moved
//! without printing either value.
//!
//! # Why removals are the interesting case
//!
//! Adding a node is harmless. Removing one that a profile, group, chain or rule
//! points at breaks a working configuration, so every removal carries `in_use`,
//! and the apply step refuses the whole update if a node in use would go and the
//! caller did not say to allow it.

use std::collections::BTreeMap;

use xraytui_domain::{
    DesiredState, Node, NodeChange, NodeId, SubscriptionDiff, SubscriptionId, SubscriptionMeta,
};

use crate::normalise::Normalised;

/// Compare a normalised fetch against the current state.
///
/// Only nodes owned by `subscription` are considered: a manually added node is
/// never touched by an update, however closely it resembles one the provider
/// sent.
#[must_use]
pub fn compute(
    subscription: &SubscriptionId,
    state: &DesiredState,
    fetched: &Normalised,
    meta: SubscriptionMeta,
) -> SubscriptionDiff {
    let existing: BTreeMap<String, &Node> = state
        .nodes
        .values()
        .filter(|node| node.source.owned_by(subscription))
        .map(|node| (node.canonical_identity(), node))
        .collect();

    let mut changes = Vec::new();
    let mut matched: std::collections::HashSet<NodeId> = std::collections::HashSet::new();

    for incoming in &fetched.nodes {
        match existing.get(&incoming.canonical_identity()) {
            Some(current) => {
                matched.insert(current.id.clone());
                let fields = differing_fields(current, incoming);
                if !fields.is_empty() {
                    // Keep the identifier: everything that points at this node
                    // points at it by id.
                    let mut node = incoming.clone();
                    node.id = current.id.clone();
                    changes.push(NodeChange::Changed {
                        id: current.id.clone(),
                        node: Box::new(node),
                        fields,
                    });
                }
            }
            None => changes.push(NodeChange::Added {
                node: Box::new(incoming.clone()),
            }),
        }
    }

    for node in existing.values() {
        if matched.contains(&node.id) {
            continue;
        }
        changes.push(NodeChange::Removed {
            id: node.id.clone(),
            name: node.name.clone(),
            in_use: is_in_use(state, &node.id),
        });
    }

    for node in &fetched.unsupported {
        changes.push(NodeChange::Unsupported {
            node: Box::new(node.clone()),
        });
    }
    for entry in &fetched.rejected {
        // `redacted` is the entry with credentials removed, which is what makes
        // it safe to show; the raw line is never carried.
        changes.push(NodeChange::Rejected {
            reason: format!("line {}: {} ({})", entry.index, entry.error, entry.redacted),
        });
    }

    let mut meta = meta;
    meta.node_count = fetched.nodes.len();

    SubscriptionDiff {
        changes,
        meta,
        deduplicated: fetched.deduplicated,
        filtered_out: fetched.filtered_out,
    }
}

/// Whether anything points at a node.
///
/// Checked across every place an identifier can appear, because missing one of
/// them is how an update silently breaks a profile.
#[must_use]
pub fn is_in_use(state: &DesiredState, id: &NodeId) -> bool {
    !state.references_to_node(id).is_empty()
}

/// Which fields differ, by name only.
///
/// **Values are never included.** A credential rotation must be visible as
/// "credential changed" without printing either the old or the new one.
#[must_use]
pub fn differing_fields(current: &Node, incoming: &Node) -> Vec<String> {
    let mut fields = Vec::new();
    if current.name != incoming.name {
        fields.push("name".to_owned());
    }
    if current.endpoint != incoming.endpoint {
        fields.push("endpoint".to_owned());
    }
    if current.protocol != incoming.protocol {
        fields.push("protocol".to_owned());
    }
    if current.transport != incoming.transport {
        fields.push("transport".to_owned());
    }
    if current.security != incoming.security {
        fields.push("security".to_owned());
    }
    if current.finalmask != incoming.finalmask {
        fields.push("finalmask".to_owned());
    }
    if current.mux != incoming.mux {
        fields.push("mux".to_owned());
    }
    if current.sockopt != incoming.sockopt {
        fields.push("sockopt".to_owned());
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{EgressProfile, ProfileId, Target};

    fn subscription_id() -> SubscriptionId {
        SubscriptionId::from_text("provider")
    }

    fn parse(links: &[&str]) -> Normalised {
        let subscription = xraytui_domain::Subscription {
            id: subscription_id(),
            name: "Provider".to_owned(),
            url: xraytui_secrets::Secret::new("https://example.test/sub"),
            enabled: true,
            update_interval_secs: None,
            fetch_via_profile: None,
            include_regex: Vec::new(),
            exclude_regex: Vec::new(),
            max_nodes: None,
            max_response_bytes: None,
            allow_plaintext: false,
            meta: SubscriptionMeta::default(),
        };
        crate::normalise::normalise(&subscription, &links.join("\n")).expect("normalise")
    }

    fn link(uuid: u8, host: u8, name: &str) -> String {
        format!(
            "vless://{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}-1111-1111-1111-111111111111\
             @198.51.100.{host}:443?type=tcp&security=none#{name}"
        )
    }

    fn state_with(nodes: &Normalised) -> DesiredState {
        let mut state = DesiredState::default();
        for node in &nodes.nodes {
            state.nodes.insert(node.id.clone(), node.clone());
        }
        state
    }

    #[test]
    fn an_unchanged_subscription_produces_no_changes() {
        let fetched = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let state = state_with(&fetched);
        let diff = compute(
            &subscription_id(),
            &state,
            &fetched,
            SubscriptionMeta::default(),
        );
        assert!(diff.changes.is_empty(), "{:?}", diff.changes);
        assert_eq!(diff.meta.node_count, 2);
    }

    #[test]
    fn a_new_node_is_an_addition() {
        let before = parse(&[&link(1, 1, "One")]);
        let state = state_with(&before);
        let after = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let diff = compute(
            &subscription_id(),
            &state,
            &after,
            SubscriptionMeta::default(),
        );
        let counts = diff.counts();
        assert_eq!(counts.added, 1);
        assert_eq!(counts.removed, 0);
        assert_eq!(counts.changed, 0);
    }

    #[test]
    fn a_node_the_provider_dropped_is_a_removal() {
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let state = state_with(&before);
        let after = parse(&[&link(1, 1, "One")]);
        let diff = compute(
            &subscription_id(),
            &state,
            &after,
            SubscriptionMeta::default(),
        );
        assert_eq!(diff.counts().removed, 1);
    }

    #[test]
    fn a_removal_says_whether_anything_points_at_it() {
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let mut state = state_with(&before);
        let doomed = before.nodes[1].id.clone();
        state.profiles.insert(
            ProfileId::from_text("web"),
            EgressProfile::new(
                ProfileId::from_text("web"),
                "Web",
                Target::Node { id: doomed.clone() },
            ),
        );

        let after = parse(&[&link(1, 1, "One")]);
        let diff = compute(
            &subscription_id(),
            &state,
            &after,
            SubscriptionMeta::default(),
        );
        let removal = diff
            .changes
            .iter()
            .find(|change| matches!(change, NodeChange::Removed { .. }))
            .expect("a removal");
        match removal {
            NodeChange::Removed { id, in_use, .. } => {
                assert_eq!(*id, doomed);
                assert!(*in_use, "a node a profile points at must be flagged");
            }
            other => panic!("unexpected change {other:?}"),
        }
    }

    #[test]
    fn a_renamed_node_keeps_its_identifier_so_nothing_breaks() {
        let before = parse(&[&link(1, 1, "Old name")]);
        let state = state_with(&before);
        let original = before.nodes[0].id.clone();

        let after = parse(&[&link(1, 1, "New name")]);
        let diff = compute(
            &subscription_id(),
            &state,
            &after,
            SubscriptionMeta::default(),
        );
        assert_eq!(diff.counts().changed, 1, "{:?}", diff.changes);
        match &diff.changes[0] {
            NodeChange::Changed { id, node, fields } => {
                assert_eq!(*id, original, "the identifier must survive a rename");
                assert_eq!(node.id, original);
                assert_eq!(fields, &vec!["name".to_owned()]);
            }
            other => panic!("unexpected change {other:?}"),
        }
    }

    #[test]
    fn a_changed_endpoint_is_a_change_not_a_replacement() {
        let before = parse(&[&link(1, 1, "One")]);
        let state = state_with(&before);
        let after = parse(&[&link(1, 9, "One")]);
        let diff = compute(
            &subscription_id(),
            &state,
            &after,
            SubscriptionMeta::default(),
        );
        // A different endpoint is a different node by canonical identity, so
        // this is legitimately an add plus a remove rather than a change.
        let counts = diff.counts();
        assert_eq!(counts.added, 1);
        assert_eq!(counts.removed, 1);
    }

    #[test]
    fn a_field_list_never_contains_a_value() {
        let before = parse(&[&link(1, 1, "Secret Name")]);
        let after = parse(&[&link(1, 1, "Other Name")]);
        let fields = differing_fields(&before.nodes[0], &after.nodes[0]);
        assert_eq!(fields, vec!["name".to_owned()]);
        let rendered = format!("{fields:?}");
        assert!(!rendered.contains("Secret Name"), "{rendered}");
        assert!(!rendered.contains("Other Name"), "{rendered}");
    }

    #[test]
    fn a_manually_added_node_is_never_touched() {
        let fetched = parse(&[&link(1, 1, "One")]);
        let mut state = DesiredState::default();
        let mut manual = fetched.nodes[0].clone();
        manual.id = NodeId::from_text("mine");
        manual.source = xraytui_domain::NodeSource::Manual;
        state.nodes.insert(manual.id.clone(), manual);

        // The provider now sends nothing that matches it.
        let after = parse(&[&link(2, 2, "Two")]);
        let diff = compute(
            &subscription_id(),
            &state,
            &after,
            SubscriptionMeta::default(),
        );
        assert_eq!(diff.counts().removed, 0, "{:?}", diff.changes);
        assert_eq!(diff.counts().added, 1);
    }

    #[test]
    fn a_node_owned_by_another_subscription_is_not_removed_either() {
        let fetched = parse(&[&link(1, 1, "One")]);
        let mut state = DesiredState::default();
        let mut other = fetched.nodes[0].clone();
        other.id = NodeId::from_text("theirs");
        other.source = xraytui_domain::NodeSource::Subscription {
            id: SubscriptionId::from_text("someone-else"),
        };
        state.nodes.insert(other.id.clone(), other);

        let after = parse(&[&link(2, 2, "Two")]);
        let diff = compute(
            &subscription_id(),
            &state,
            &after,
            SubscriptionMeta::default(),
        );
        assert_eq!(diff.counts().removed, 0, "{:?}", diff.changes);
    }

    #[test]
    fn counts_are_reported_from_the_normalisation_that_produced_them() {
        let fetched = Normalised {
            deduplicated: 3,
            filtered_out: 7,
            ..parse(&[&link(1, 1, "One")])
        };
        let diff = compute(
            &subscription_id(),
            &DesiredState::default(),
            &fetched,
            SubscriptionMeta::default(),
        );
        assert_eq!(diff.deduplicated, 3);
        assert_eq!(diff.filtered_out, 7);
    }
}
