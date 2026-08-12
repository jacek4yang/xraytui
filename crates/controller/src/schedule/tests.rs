//! The scheduler, with the clock as a parameter.

use super::*;
use xraytui_domain::{
    Chain, ChainId, DesiredState, EgressProfile, Group, GroupId, GroupMembership, GroupStrategy,
    NodeId, ProfileId, Target,
};

const NOW: u64 = 1_000_000;

fn schedule_with(intervals: &[(&str, u64)]) -> Schedule {
    let mut schedule = Schedule::new();
    for (key, interval) in intervals {
        schedule.insert(Entry::new(*key, *interval, NOW));
    }
    schedule
}

// --- deadlines -------------------------------------------------------------

#[test]
fn a_new_entry_is_due_one_interval_from_now_not_immediately() {
    // A daemon that starts up should serve the user before doing housekeeping.
    let schedule = schedule_with(&[("a", 300)]);
    assert!(schedule.due(NOW, 10).is_empty());
    assert!(
        !schedule
            .due(NOW + 300 + 300 / JITTER_DIVISOR, 10)
            .is_empty()
    );
}

#[test]
fn an_entry_can_be_asked_for_immediately_when_that_is_what_is_wanted() {
    let mut schedule = Schedule::new();
    schedule.insert(Entry::new("a", 300, NOW).due_immediately());
    assert_eq!(schedule.due(NOW, 10), vec!["a".to_owned()]);
}

#[test]
fn success_pushes_the_deadline_out_by_one_interval() {
    let mut schedule = schedule_with(&[("a", 300)]);
    schedule.succeeded("a", NOW);
    let entry = schedule.get("a").expect("entry");
    assert!(entry.due_at >= NOW + 300);
    assert!(entry.due_at < NOW + 300 + 300 / JITTER_DIVISOR + 1);
    assert_eq!(entry.failures, 0);
}

#[test]
fn a_failure_doubles_the_wait_and_a_success_undoes_it() {
    let mut schedule = schedule_with(&[("a", 300)]);

    schedule.failed("a", NOW);
    assert_eq!(schedule.get("a").expect("entry").effective_interval(), 600);
    schedule.failed("a", NOW);
    assert_eq!(schedule.get("a").expect("entry").effective_interval(), 1200);
    schedule.failed("a", NOW);
    assert_eq!(schedule.get("a").expect("entry").effective_interval(), 2400);

    schedule.succeeded("a", NOW);
    assert_eq!(schedule.get("a").expect("entry").effective_interval(), 300);
}

#[test]
fn backoff_stops_at_the_cap_however_long_something_stays_broken() {
    let mut schedule = schedule_with(&[("a", 300)]);
    for _ in 0..100 {
        schedule.failed("a", NOW);
    }
    let entry = schedule.get("a").expect("entry");
    assert_eq!(entry.effective_interval(), 300 << MAX_BACKOFF_STEPS);
    assert!(
        entry.effective_interval() < 86_400,
        "a broken thing must still be retried within a day"
    );
}

#[test]
fn an_absurd_interval_cannot_overflow_the_deadline() {
    let mut schedule = Schedule::new();
    schedule.insert(Entry::new("a", u64::MAX, u64::MAX - 1));
    for _ in 0..10 {
        schedule.failed("a", u64::MAX - 1);
    }
    assert!(schedule.get("a").is_some(), "it must still exist");
}

#[test]
fn an_interval_below_the_floor_is_raised_to_it() {
    let schedule = schedule_with(&[("a", 0), ("b", 1)]);
    assert_eq!(
        schedule.get("a").expect("entry").interval_secs,
        MINIMUM_INTERVAL_SECS
    );
    assert_eq!(
        schedule.get("b").expect("entry").interval_secs,
        MINIMUM_INTERVAL_SECS
    );
}

// --- jitter ----------------------------------------------------------------

#[test]
fn jitter_spreads_entries_without_leaving_the_window() {
    let offsets: Vec<u64> = (0..64)
        .map(|index| jitter(&format!("node-{index}"), 800))
        .collect();
    for offset in &offsets {
        assert!(*offset < 800 / JITTER_DIVISOR, "{offset} left the window");
    }
    let distinct: std::collections::HashSet<u64> = offsets.iter().copied().collect();
    assert!(
        distinct.len() > 16,
        "jitter must actually spread things: {distinct:?}"
    );
}

#[test]
fn jitter_is_the_same_on_every_run_so_deadlines_are_reproducible() {
    assert_eq!(jitter("node-a", 800), jitter("node-a", 800));
    assert_ne!(jitter("node-a", 800), jitter("node-b", 800));
}

#[test]
fn a_short_interval_gets_no_jitter_rather_than_a_division_by_zero() {
    assert_eq!(jitter("a", 0), 0);
    assert_eq!(jitter("a", 4), 0);
}

// --- selection -------------------------------------------------------------

#[test]
fn the_most_important_thing_runs_first_when_several_are_due() {
    let mut schedule = Schedule::new();
    schedule.insert(
        Entry::new("background", 300, NOW)
            .due_immediately()
            .with_priority(priority::BACKGROUND),
    );
    schedule.insert(
        Entry::new("active", 300, NOW)
            .due_immediately()
            .with_priority(priority::ACTIVE),
    );
    schedule.insert(
        Entry::new("candidate", 300, NOW)
            .due_immediately()
            .with_priority(priority::CANDIDATE),
    );
    assert_eq!(
        schedule.due(NOW, 10),
        vec![
            "active".to_owned(),
            "candidate".to_owned(),
            "background".to_owned()
        ]
    );
}

#[test]
fn the_limit_is_what_keeps_a_suspended_laptop_from_stampeding() {
    let mut schedule = Schedule::new();
    for index in 0..100 {
        schedule.insert(Entry::new(format!("node-{index:03}"), 300, NOW).due_immediately());
    }
    // A week later everything is overdue; only a few may run at once.
    let due = schedule.due(NOW + 604_800, 5);
    assert_eq!(due.len(), 5);
}

#[test]
fn nothing_is_due_before_its_deadline() {
    let schedule = schedule_with(&[("a", 300), ("b", 600)]);
    assert!(schedule.due(NOW, 10).is_empty());
    assert!(schedule.due(NOW + 100, 10).is_empty());
}

#[test]
fn the_next_deadline_is_reported_so_a_caller_can_sleep_until_it() {
    let schedule = schedule_with(&[("a", 300), ("b", 900)]);
    let next = schedule.next_due().expect("a deadline");
    assert!(next >= NOW + 300);
    assert!(next < NOW + 900);
    assert_eq!(Schedule::new().next_due(), None);
}

// --- membership ------------------------------------------------------------

#[test]
fn re_inserting_an_unchanged_entry_does_not_reset_its_timer() {
    // Re-reading a configuration file must not cause a burst.
    let mut schedule = schedule_with(&[("a", 300)]);
    schedule.failed("a", NOW);
    let before = schedule.get("a").expect("entry").clone();

    schedule.insert(Entry::new("a", 300, NOW + 50));
    let after = schedule.get("a").expect("entry");
    assert_eq!(after.due_at, before.due_at);
    assert_eq!(after.failures, before.failures);
}

#[test]
fn changing_an_interval_does_reset_the_timer() {
    let mut schedule = schedule_with(&[("a", 300)]);
    let before = schedule.get("a").expect("entry").due_at;
    schedule.insert(Entry::new("a", 60, NOW));
    assert_ne!(schedule.get("a").expect("entry").due_at, before);
}

#[test]
fn an_entry_that_no_longer_applies_stops_being_scheduled() {
    let mut schedule = schedule_with(&[("a", 300), ("b", 300), ("c", 300)]);
    let keep: std::collections::BTreeSet<String> =
        ["a".to_owned(), "c".to_owned()].into_iter().collect();
    schedule.retain_keys(&keep);
    assert_eq!(schedule.len(), 2);
    assert!(schedule.get("b").is_none());

    schedule.remove("a");
    assert_eq!(schedule.len(), 1);
}

#[test]
fn recording_an_outcome_for_something_that_is_gone_is_harmless() {
    let mut schedule = Schedule::new();
    schedule.succeeded("ghost", NOW);
    schedule.failed("ghost", NOW);
    assert!(schedule.is_empty());
}

// --- node priorities -------------------------------------------------------

fn state() -> DesiredState {
    let mut state = DesiredState::default();
    for id in [
        "active",
        "candidate-a",
        "candidate-b",
        "hop-one",
        "hop-two",
        "idle",
    ] {
        let node = xraytui_domain::Node::new(
            NodeId::from_text(id),
            id,
            xraytui_domain::NodeSource::Manual,
            xraytui_domain::Endpoint::new("198.51.100.1", 443),
            xraytui_domain::ProtocolSettings::Vless(xraytui_domain::VlessSettings {
                id: xraytui_secrets::Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: String::new(),
                encryption: "none".to_owned(),
                level: None,
            }),
        );
        state.nodes.insert(node.id.clone(), node);
    }

    state.groups.insert(
        GroupId::from_text("pool"),
        Group {
            id: GroupId::from_text("pool"),
            name: "Pool".to_owned(),
            strategy: GroupStrategy::LeastPing,
            membership: GroupMembership {
                nodes: vec![
                    NodeId::from_text("candidate-a"),
                    NodeId::from_text("candidate-b"),
                ],
                ..Default::default()
            },
            manual_selection: None,
            fallback: None,
        },
    );
    state.chains.insert(
        ChainId::from_text("pair"),
        Chain {
            id: ChainId::from_text("pair"),
            name: "Pair".to_owned(),
            hops: vec![NodeId::from_text("hop-one"), NodeId::from_text("hop-two")],
            enabled: true,
        },
    );

    state.profiles.insert(
        ProfileId::from_text("web"),
        EgressProfile::new(
            ProfileId::from_text("web"),
            "Web",
            Target::Node {
                id: NodeId::from_text("active"),
            },
        ),
    );
    state.profiles.insert(
        ProfileId::from_text("media"),
        EgressProfile::new(
            ProfileId::from_text("media"),
            "Media",
            Target::Group {
                id: GroupId::from_text("pool"),
            },
        ),
    );
    state.profiles.insert(
        ProfileId::from_text("chat"),
        EgressProfile::new(
            ProfileId::from_text("chat"),
            "Chat",
            Target::Chain {
                id: ChainId::from_text("pair"),
            },
        ),
    );
    state
}

#[test]
fn what_a_profile_is_using_right_now_is_probed_first() {
    let priorities = node_priorities(&state());
    assert_eq!(priorities[&NodeId::from_text("active")], priority::ACTIVE);
}

#[test]
fn a_group_member_ranks_above_an_unused_node_and_below_the_active_one() {
    let priorities = node_priorities(&state());
    assert_eq!(
        priorities[&NodeId::from_text("candidate-a")],
        priority::CANDIDATE
    );
    assert!(
        priorities[&NodeId::from_text("candidate-a")] > priorities[&NodeId::from_text("active")]
    );
    assert!(priorities[&NodeId::from_text("candidate-a")] < priorities[&NodeId::from_text("idle")]);
}

#[test]
fn a_chain_hop_is_probed_because_the_chain_is_only_as_good_as_its_hops() {
    let priorities = node_priorities(&state());
    assert_eq!(
        priorities[&NodeId::from_text("hop-one")],
        priority::CHAIN_HOP
    );
    assert_eq!(
        priorities[&NodeId::from_text("hop-two")],
        priority::CHAIN_HOP
    );
}

#[test]
fn a_node_nothing_points_at_is_still_probed_eventually() {
    let priorities = node_priorities(&state());
    assert_eq!(priorities[&NodeId::from_text("idle")], priority::CONFIGURED);
}

#[test]
fn a_disabled_profile_does_not_raise_anything() {
    let mut state = state();
    for profile in state.profiles.values_mut() {
        profile.enabled = false;
    }
    let priorities = node_priorities(&state);
    assert!(
        priorities
            .values()
            .all(|level| *level == priority::CONFIGURED),
        "{priorities:?}"
    );
}

#[test]
fn every_node_gets_a_priority_and_nothing_else_does() {
    let state = state();
    let priorities = node_priorities(&state);
    assert_eq!(priorities.len(), state.nodes.len());
    for id in state.nodes.keys() {
        assert!(priorities.contains_key(id));
    }
}

#[test]
fn the_priority_bands_are_ordered_the_way_the_names_suggest() {
    // A const block, so reordering the bands fails the *build* rather than a
    // test somebody might not run.
    const _: () = {
        assert!(priority::ACTIVE < priority::CANDIDATE);
        assert!(priority::CANDIDATE < priority::CHAIN_HOP);
        assert!(priority::CHAIN_HOP < priority::CONFIGURED);
        assert!(priority::CONFIGURED < priority::BACKGROUND);
    };
    // And an ordinary assertion so the test is not empty.
    let mut bands = [
        priority::BACKGROUND,
        priority::ACTIVE,
        priority::CHAIN_HOP,
        priority::CONFIGURED,
        priority::CANDIDATE,
    ];
    bands.sort_unstable();
    assert_eq!(
        bands,
        [
            priority::ACTIVE,
            priority::CANDIDATE,
            priority::CHAIN_HOP,
            priority::CONFIGURED,
            priority::BACKGROUND,
        ]
    );
}
