//! Applying a diff, all of it or none of it.
//!
//! # The transaction
//!
//! [`apply`] takes the desired state by value, changes a clone, and gives back
//! either the new state or the reason it refused. The caller's state is never
//! partially modified, because it is never modified at all — there is nothing to
//! roll back, which is a stronger guarantee than rolling back correctly.
//!
//! The validation at the end is the important part: a subscription update that
//! produces a state the compiler would reject is refused *here*, with the
//! provider's changes named, rather than later when the core will not start.
//!
//! # The two refusals
//!
//! * **A node in use would be removed.** Something points at it — a profile, a
//!   group, a chain, a rule — and letting it go would break a working setup.
//!   `allow_removing_used` says the user has seen the list and accepted it.
//! * **Everything would be removed.** A provider that returns an empty list, or
//!   a filter that suddenly matches nothing, should not silently empty a user's
//!   node list. Refused unless the diff genuinely contains no additions and the
//!   caller asked for it.

use xraytui_domain::{DesiredState, NodeChange, Subscription, SubscriptionDiff, SubscriptionId};

/// Why an update was refused.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// Nodes something points at would be removed.
    #[error(
        "this update removes {} node(s) that are still in use ({}); \
         re-run with --allow-removing-used if that is what you want",
        names.len(),
        names.join(", ")
    )]
    RemovesNodesInUse {
        /// Display names of the nodes involved.
        names: Vec<String>,
    },
    /// The update would leave the subscription with nothing.
    #[error(
        "this update would remove all {removed} of this subscription's nodes and add none; \
         refusing, because a provider outage looks exactly like this"
    )]
    WouldEmpty {
        /// How many would go.
        removed: usize,
    },
    /// The resulting state is not valid.
    #[error("the updated configuration would not be valid: {0}")]
    Invalid(String),
}

/// What an application did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplyOutcome {
    /// Nodes added.
    pub added: usize,
    /// Nodes updated in place.
    pub changed: usize,
    /// Nodes removed.
    pub removed: usize,
    /// Identifiers that were removed, for the caller to report.
    pub removed_ids: Vec<String>,
    /// Warnings that did not prevent the update.
    pub warnings: Vec<String>,
}

/// How permissive to be.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApplyOptions {
    /// Remove nodes even when something points at them.
    pub allow_removing_used: bool,
    /// Permit an update that removes everything and adds nothing.
    pub allow_emptying: bool,
}

/// Apply a diff to a state, or refuse and change nothing.
///
/// # Errors
/// See [`ApplyError`]. On any error the state passed in is returned untouched
/// by virtue of never having been borrowed mutably.
pub fn apply(
    state: &DesiredState,
    subscription: &Subscription,
    diff: &SubscriptionDiff,
    options: ApplyOptions,
) -> Result<(DesiredState, ApplyOutcome), ApplyError> {
    let counts = diff.counts();

    let in_use: Vec<String> = diff
        .changes
        .iter()
        .filter_map(|change| match change {
            NodeChange::Removed { name, in_use, .. } if *in_use => Some(name.clone()),
            _ => None,
        })
        .collect();
    if !in_use.is_empty() && !options.allow_removing_used {
        return Err(ApplyError::RemovesNodesInUse { names: in_use });
    }

    let owned = state
        .nodes
        .values()
        .filter(|node| node.source.owned_by(&subscription.id))
        .count();
    if !options.allow_emptying
        && counts.added == 0
        && counts.removed > 0
        && counts.removed >= owned
        && owned > 0
    {
        return Err(ApplyError::WouldEmpty {
            removed: counts.removed,
        });
    }

    // From here the work happens on a copy. Nothing the caller holds changes
    // unless this function returns Ok.
    let mut next = state.clone();
    let mut outcome = ApplyOutcome::default();

    for change in &diff.changes {
        match change {
            NodeChange::Added { node } => {
                next.nodes.insert(node.id.clone(), (**node).clone());
                outcome.added += 1;
            }
            NodeChange::Changed { id, node, .. } => {
                next.nodes.insert(id.clone(), (**node).clone());
                outcome.changed += 1;
            }
            NodeChange::Removed { id, name, .. } => {
                next.nodes.remove(id);
                // A node that is gone must also stop being pointed at, or the
                // compiler would emit a selector naming an outbound that does
                // not exist.
                outcome.warnings.extend(detach(&mut next, id, name));
                outcome.removed += 1;
                outcome.removed_ids.push(name.clone());
            }
            NodeChange::Unsupported { node } => {
                // Kept rather than discarded: a user needs to know their
                // provider is sending them something this build cannot use.
                next.unsupported.insert(node.id.clone(), (**node).clone());
                outcome.warnings.push(format!(
                    "{}: {} is not compilable ({})",
                    node.name,
                    node.detected_protocol,
                    node.reason.describe()
                ));
            }
            NodeChange::Rejected { reason } => {
                outcome
                    .warnings
                    .push(format!("an entry was not understood: {reason}"));
            }
        }
    }

    let mut updated = subscription.clone();
    updated.meta = diff.meta.clone();
    next.subscriptions.insert(updated.id.clone(), updated);

    // The last gate: a state the compiler would reject must not be stored.
    let diagnostics = next.validate();
    let fatal: Vec<String> = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == xraytui_domain::Severity::Error)
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect();
    if !fatal.is_empty() {
        return Err(ApplyError::Invalid(fatal.join("; ")));
    }
    outcome.warnings.extend(
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity != xraytui_domain::Severity::Error)
            .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message)),
    );

    Ok((next, outcome))
}

/// Remove every reference to a node that has gone, and say what was changed.
///
/// The three kinds of reference need three different answers:
///
/// * **A group** keeps working with one member fewer, so the member is dropped.
/// * **A chain** cannot: a two-hop chain that quietly becomes one hop is a
///   privacy change nobody asked for. It is disabled with its hops intact, so
///   the user can repair it rather than rebuild it.
/// * **A profile or a rule** that pointed at the node is repointed at
///   [`Target::Block`], **not** `direct`. Sending that traffic unproxied because
///   a provider dropped a server is a leak; refusing to carry it is visible and
///   safe, and the warning says exactly which profile to fix.
fn detach(state: &mut DesiredState, id: &xraytui_domain::NodeId, name: &str) -> Vec<String> {
    let gone = xraytui_domain::Target::Node { id: id.clone() };
    let mut warnings = Vec::new();

    for group in state.groups.values_mut() {
        group.membership.nodes.retain(|member| member != id);
        if group.manual_selection.as_ref() == Some(&gone) {
            group.manual_selection = None;
            warnings.push(format!(
                "group '{}' had {name} selected; it will pick again",
                group.id
            ));
        }
        if group.fallback.as_ref() == Some(&gone) {
            group.fallback = None;
        }
    }

    for chain in state.chains.values_mut() {
        if chain.hops.contains(id) && chain.enabled {
            chain.enabled = false;
            warnings.push(format!(
                "chain '{}' used {name} as a hop and has been disabled;                  its hops are kept so you can repair it",
                chain.id
            ));
        }
    }

    for profile in state.profiles.values_mut() {
        if profile.target == gone {
            profile.target = xraytui_domain::Target::Block;
            warnings.push(format!(
                "profile '{}' pointed at {name}, which the provider removed;                  it now blocks rather than going direct — point it somewhere",
                profile.id
            ));
        }
        if profile.fallback.as_ref() == Some(&gone) {
            profile.fallback = None;
        }
    }

    for rule in state.app_rules.values_mut() {
        if let xraytui_domain::RuleAction::Target { target } = &rule.action
            && *target == gone
        {
            rule.action = xraytui_domain::RuleAction::Target {
                target: xraytui_domain::Target::Block,
            };
            warnings.push(format!(
                "application rule '{}' pointed at {name} and now blocks",
                rule.id
            ));
        }
    }
    for rule in state.routing_rules.values_mut() {
        if let xraytui_domain::RuleAction::Target { target } = &rule.action
            && *target == gone
        {
            rule.action = xraytui_domain::RuleAction::Target {
                target: xraytui_domain::Target::Block,
            };
            warnings.push(format!(
                "routing rule '{}' pointed at {name} and now blocks",
                rule.id
            ));
        }
    }

    warnings
}

/// Which subscription a diff belongs to, for the caller's log line.
#[must_use]
pub fn describe(subscription: &SubscriptionId, outcome: &ApplyOutcome) -> String {
    format!(
        "{subscription}: +{} ~{} -{}",
        outcome.added, outcome.changed, outcome.removed
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{EgressProfile, NodeId, ProfileId, SubscriptionMeta, Target};

    fn subscription() -> Subscription {
        Subscription {
            id: SubscriptionId::from_text("provider"),
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
        }
    }

    fn link(uuid: u8, host: u8, name: &str) -> String {
        format!(
            "vless://{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}-1111-1111-1111-111111111111\
             @198.51.100.{host}:443?type=tcp&security=none#{name}"
        )
    }

    fn parse(links: &[&str]) -> crate::normalise::Normalised {
        crate::normalise::normalise(&subscription(), &links.join("\n")).expect("normalise")
    }

    fn state_with(nodes: &crate::normalise::Normalised) -> DesiredState {
        let mut state = DesiredState::default();
        for node in &nodes.nodes {
            state.nodes.insert(node.id.clone(), node.clone());
        }
        state
            .subscriptions
            .insert(subscription().id, subscription());
        state
    }

    fn diff_between(
        state: &DesiredState,
        fetched: &crate::normalise::Normalised,
    ) -> SubscriptionDiff {
        crate::diff::compute(
            &subscription().id,
            state,
            fetched,
            SubscriptionMeta::default(),
        )
    }

    #[test]
    fn an_addition_lands_in_the_new_state_and_not_the_old_one() {
        let before = parse(&[&link(1, 1, "One")]);
        let state = state_with(&before);
        let after = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let diff = diff_between(&state, &after);

        let (next, outcome) =
            apply(&state, &subscription(), &diff, ApplyOptions::default()).expect("apply");
        assert_eq!(outcome.added, 1);
        assert_eq!(next.nodes.len(), 2);
        assert_eq!(state.nodes.len(), 1, "the original must be untouched");
    }

    #[test]
    fn removing_a_node_something_points_at_is_refused_by_default() {
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let mut state = state_with(&before);
        let doomed = before.nodes[1].id.clone();
        state.profiles.insert(
            ProfileId::from_text("web"),
            EgressProfile::new(
                ProfileId::from_text("web"),
                "Web",
                Target::Node { id: doomed },
            ),
        );

        let after = parse(&[&link(1, 1, "One")]);
        let diff = diff_between(&state, &after);
        let error = apply(&state, &subscription(), &diff, ApplyOptions::default())
            .expect_err("must refuse");
        assert!(
            matches!(error, ApplyError::RemovesNodesInUse { .. }),
            "{error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("--allow-removing-used"), "{text}");
    }

    #[test]
    fn removing_a_node_in_use_is_allowed_when_the_caller_says_so() {
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let mut state = state_with(&before);
        let doomed = before.nodes[1].id.clone();
        state.groups.insert(
            xraytui_domain::GroupId::from_text("all"),
            xraytui_domain::Group {
                id: xraytui_domain::GroupId::from_text("all"),
                name: "All".to_owned(),
                strategy: xraytui_domain::GroupStrategy::Random,
                membership: xraytui_domain::GroupMembership {
                    nodes: vec![before.nodes[0].id.clone(), doomed.clone()],
                    ..Default::default()
                },
                manual_selection: None,
                fallback: None,
            },
        );

        let after = parse(&[&link(1, 1, "One")]);
        let diff = diff_between(&state, &after);
        let options = ApplyOptions {
            allow_removing_used: true,
            ..ApplyOptions::default()
        };
        let (next, outcome) = apply(&state, &subscription(), &diff, options).expect("apply");
        assert_eq!(outcome.removed, 1);
        assert!(!next.nodes.contains_key(&doomed));
        // And the group no longer names a node that is gone.
        let group = &next.groups[&xraytui_domain::GroupId::from_text("all")];
        assert!(!group.membership.nodes.contains(&doomed));
    }

    #[test]
    fn a_chain_that_loses_a_hop_is_disabled_rather_than_shortened() {
        // Silently turning a two-hop chain into a one-hop one changes what the
        // user's traffic does without telling them.
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let mut state = state_with(&before);
        state.chains.insert(
            xraytui_domain::ChainId::from_text("pair"),
            xraytui_domain::Chain {
                id: xraytui_domain::ChainId::from_text("pair"),
                name: "Pair".to_owned(),
                hops: vec![before.nodes[0].id.clone(), before.nodes[1].id.clone()],
                enabled: true,
            },
        );

        let after = parse(&[&link(1, 1, "One")]);
        let diff = diff_between(&state, &after);
        let options = ApplyOptions {
            allow_removing_used: true,
            ..ApplyOptions::default()
        };
        let (next, _) = apply(&state, &subscription(), &diff, options).expect("apply");
        let chain = &next.chains[&xraytui_domain::ChainId::from_text("pair")];
        assert!(!chain.enabled, "the chain must be disabled, not shortened");
        assert_eq!(chain.hops.len(), 2, "the hops must be left for repair");
    }

    #[test]
    fn a_profile_left_pointing_at_nothing_blocks_rather_than_going_direct() {
        // The failure this prevents: a provider drops a server, and the traffic
        // that was going through it silently starts going out unproxied.
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let mut state = state_with(&before);
        let doomed = before.nodes[1].id.clone();
        state.profiles.insert(
            ProfileId::from_text("web"),
            EgressProfile::new(
                ProfileId::from_text("web"),
                "Web",
                Target::Node { id: doomed },
            ),
        );

        let after = parse(&[&link(1, 1, "One")]);
        let diff = diff_between(&state, &after);
        let options = ApplyOptions {
            allow_removing_used: true,
            ..ApplyOptions::default()
        };
        let (next, outcome) = apply(&state, &subscription(), &diff, options).expect("apply");
        assert_eq!(
            next.profiles[&ProfileId::from_text("web")].target,
            Target::Block,
            "a profile with nowhere to go must block, never go direct"
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|warning| warning.contains("blocks rather than going direct")),
            "{:?}",
            outcome.warnings
        );
    }

    #[test]
    fn a_rule_left_pointing_at_nothing_blocks_too() {
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let mut state = state_with(&before);
        let doomed = before.nodes[1].id.clone();
        state.app_rules.insert(
            xraytui_domain::AppRuleId::from_text("browser"),
            xraytui_domain::ApplicationRule {
                id: xraytui_domain::AppRuleId::from_text("browser"),
                priority: 10,
                process: vec![xraytui_domain::AppMatcher("firefox".to_owned())],
                action: xraytui_domain::RuleAction::Target {
                    target: Target::Node { id: doomed },
                },
                enabled: true,
                note: None,
            },
        );

        let after = parse(&[&link(1, 1, "One")]);
        let diff = diff_between(&state, &after);
        let options = ApplyOptions {
            allow_removing_used: true,
            ..ApplyOptions::default()
        };
        let (next, _) = apply(&state, &subscription(), &diff, options).expect("apply");
        assert_eq!(
            next.app_rules[&xraytui_domain::AppRuleId::from_text("browser")].action,
            xraytui_domain::RuleAction::Target {
                target: Target::Block
            }
        );
    }

    #[test]
    fn an_update_that_would_remove_everything_is_refused() {
        let before = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let state = state_with(&before);

        // A provider outage: nothing recognisable comes back. Normalisation
        // would refuse first, but a filter that matches nothing produces the
        // same diff without an error, so the guard has to be here too.
        let empty = crate::normalise::Normalised::default();
        let diff = diff_between(&state, &empty);
        let error = apply(&state, &subscription(), &diff, ApplyOptions::default())
            .expect_err("must refuse");
        assert!(matches!(error, ApplyError::WouldEmpty { .. }), "{error:?}");
    }

    #[test]
    fn emptying_is_permitted_when_the_caller_insists() {
        let before = parse(&[&link(1, 1, "One")]);
        let state = state_with(&before);
        let empty = crate::normalise::Normalised::default();
        let diff = diff_between(&state, &empty);
        let options = ApplyOptions {
            allow_emptying: true,
            allow_removing_used: true,
        };
        let (next, outcome) = apply(&state, &subscription(), &diff, options).expect("apply");
        assert_eq!(outcome.removed, 1);
        assert!(next.nodes.is_empty());
    }

    #[test]
    fn a_rename_updates_in_place_and_leaves_the_profile_working() {
        let before = parse(&[&link(1, 1, "Old")]);
        let mut state = state_with(&before);
        let id = before.nodes[0].id.clone();
        state.profiles.insert(
            ProfileId::from_text("web"),
            EgressProfile::new(
                ProfileId::from_text("web"),
                "Web",
                Target::Node { id: id.clone() },
            ),
        );

        let after = parse(&[&link(1, 1, "New")]);
        let diff = diff_between(&state, &after);
        let (next, outcome) =
            apply(&state, &subscription(), &diff, ApplyOptions::default()).expect("apply");
        assert_eq!(outcome.changed, 1);
        assert_eq!(next.nodes[&id].name, "New");
        assert_eq!(
            next.profiles[&ProfileId::from_text("web")].target,
            Target::Node { id },
            "the profile must still point at the same node"
        );
    }

    #[test]
    fn the_subscription_metadata_is_stored_with_the_result() {
        let before = parse(&[&link(1, 1, "One")]);
        let state = state_with(&before);
        let after = parse(&[&link(1, 1, "One"), &link(2, 2, "Two")]);
        let mut diff = diff_between(&state, &after);
        diff.meta.etag = Some("\"v2\"".to_owned());

        let (next, _) =
            apply(&state, &subscription(), &diff, ApplyOptions::default()).expect("apply");
        assert_eq!(
            next.subscriptions[&subscription().id].meta.etag.as_deref(),
            Some("\"v2\"")
        );
    }

    #[test]
    fn unsupported_and_rejected_entries_become_warnings_not_failures() {
        let state = DesiredState::default();
        let diff = SubscriptionDiff {
            changes: vec![
                NodeChange::Unsupported {
                    node: Box::new(xraytui_domain::UnsupportedNode {
                        id: NodeId::from_text("odd"),
                        name: "Odd".to_owned(),
                        source: xraytui_domain::NodeSource::Subscription {
                            id: SubscriptionId::from_text("provider"),
                        },
                        detected_protocol: "tuic".to_owned(),
                        reason: xraytui_domain::UnsupportedReason::ForeignCore {
                            core: "tuic".to_owned(),
                        },
                        requires_core: None,
                        original: xraytui_secrets::Secret::new("tuic://…"),
                        redacted_original: "tuic://…".to_owned(),
                    }),
                },
                NodeChange::Rejected {
                    reason: "not a URI".to_owned(),
                },
            ],
            meta: SubscriptionMeta::default(),
            deduplicated: 0,
            filtered_out: 0,
        };
        let (next, outcome) =
            apply(&state, &subscription(), &diff, ApplyOptions::default()).expect("apply");
        assert_eq!(outcome.added, 0);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|warning| warning.contains("Odd") && warning.contains("tuic")),
            "{:?}",
            outcome.warnings
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|warning| warning.contains("not a URI")),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            next.unsupported.len(),
            1,
            "an entry this build cannot use is kept, so the user can see it"
        );
    }

    #[test]
    fn the_summary_line_is_compact_and_complete() {
        let outcome = ApplyOutcome {
            added: 2,
            changed: 1,
            removed: 3,
            ..ApplyOutcome::default()
        };
        assert_eq!(
            describe(&SubscriptionId::from_text("provider"), &outcome),
            "provider: +2 ~1 -3"
        );
    }

    #[test]
    fn nothing_at_all_to_do_is_a_success_that_changes_nothing() {
        let before = parse(&[&link(1, 1, "One")]);
        let state = state_with(&before);
        let diff = diff_between(&state, &before);
        let (next, outcome) =
            apply(&state, &subscription(), &diff, ApplyOptions::default()).expect("apply");
        assert_eq!((outcome.added, outcome.changed, outcome.removed), (0, 0, 0));
        assert_eq!(next.nodes, state.nodes);
    }

    #[test]
    fn a_removal_of_a_node_that_is_not_there_is_harmless() {
        let state = DesiredState::default();
        let diff = SubscriptionDiff {
            changes: vec![NodeChange::Removed {
                id: NodeId::from_text("ghost"),
                name: "Ghost".to_owned(),
                in_use: false,
            }],
            meta: SubscriptionMeta::default(),
            deduplicated: 0,
            filtered_out: 0,
        };
        let (next, outcome) =
            apply(&state, &subscription(), &diff, ApplyOptions::default()).expect("apply");
        assert_eq!(outcome.removed, 1);
        assert!(next.nodes.is_empty());
    }
}
