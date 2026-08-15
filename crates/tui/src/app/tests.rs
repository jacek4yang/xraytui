//! Every key binding, pressed.
//!
//! The help overlay lists fourteen bindings. Each is exercised here, so the
//! reference and the behaviour cannot drift apart — a test at the bottom walks
//! [`KEYS`] and fails if a binding is documented but does nothing.

use super::*;
use xraytui_domain::{
    AppMatcher, ApplicationRule, Chain, EgressProfile, Group, GroupStrategy, Node, ProfileRuntime,
    RuleAction,
};

fn node(id: &str) -> Node {
    Node::new(
        xraytui_domain::NodeId::from_text(id),
        format!("node {id}"),
        xraytui_domain::NodeSource::Manual,
        xraytui_domain::Endpoint::new("198.51.100.1", 443),
        xraytui_domain::ProtocolSettings::Vless(xraytui_domain::VlessSettings {
            id: xraytui_secrets::Secret::new("11111111-2222-3333-4444-555555555555"),
            flow: String::new(),
            encryption: "none".to_owned(),
            level: None,
        }),
    )
}

fn subscription(id: &str, url: &str) -> xraytui_domain::Subscription {
    xraytui_domain::Subscription {
        id: xraytui_domain::SubscriptionId::from_text(id),
        name: format!("{id} feed"),
        url: xraytui_secrets::Secret::new(url),
        enabled: true,
        update_interval_secs: None,
        fetch_via_profile: None,
        include_regex: Vec::new(),
        exclude_regex: Vec::new(),
        max_nodes: None,
        max_response_bytes: None,
        allow_plaintext: false,
        meta: xraytui_domain::SubscriptionMeta::default(),
    }
}

fn state() -> (DesiredState, RuntimeState) {
    let mut desired = DesiredState::default();

    for id in ["alpha", "beta"] {
        desired
            .nodes
            .insert(xraytui_domain::NodeId::from_text(id), node(id));
    }

    let profile = EgressProfile::new(
        xraytui_domain::ProfileId::from_text("web"),
        "Web",
        Target::Node {
            id: xraytui_domain::NodeId::from_text("alpha"),
        },
    );
    desired.profiles.insert(profile.id.clone(), profile);

    let second = EgressProfile::new(
        xraytui_domain::ProfileId::from_text("media"),
        "Media",
        Target::Direct,
    );
    desired.profiles.insert(second.id.clone(), second);

    let third = EgressProfile::new(
        xraytui_domain::ProfileId::from_text("work"),
        "Work",
        Target::Block,
    );
    desired.profiles.insert(third.id.clone(), third);

    let group = Group {
        id: xraytui_domain::GroupId::from_text("eu"),
        name: "Europe".to_owned(),
        strategy: GroupStrategy::LeastPing,
        membership: xraytui_domain::GroupMembership::default(),
        manual_selection: None,
        fallback: None,
    };
    desired.groups.insert(group.id.clone(), group);

    let chain = Chain {
        id: xraytui_domain::ChainId::from_text("via-eu"),
        name: "Via Europe".to_owned(),
        hops: vec![
            xraytui_domain::NodeId::from_text("alpha"),
            xraytui_domain::NodeId::from_text("beta"),
        ],
        enabled: true,
    };
    desired.chains.insert(chain.id.clone(), chain);

    let rule = ApplicationRule {
        id: xraytui_domain::AppRuleId::from_text("browser"),
        priority: 10,
        process: vec![AppMatcher("firefox".to_owned())],
        action: RuleAction::Profile {
            id: xraytui_domain::ProfileId::from_text("web"),
        },
        enabled: true,
        note: None,
    };
    desired.app_rules.insert(rule.id.clone(), rule);

    let subscription = subscription("provider", "https://example.test/sub?token=SUPERSECRET");
    desired
        .subscriptions
        .insert(subscription.id.clone(), subscription);

    let mut runtime = RuntimeState::default();
    runtime.profiles.push(ProfileRuntime {
        id: xraytui_domain::ProfileId::from_text("web"),
        target: Target::Node {
            id: xraytui_domain::NodeId::from_text("alpha"),
        },
        effective_outbound: Some("node/alpha/out".to_owned()),
        health: xraytui_domain::HealthRecord::default(),
        traffic: xraytui_domain::TrafficCounters::default(),
        socks_listen: Some("127.0.0.1:11080".to_owned()),
        http_listen: None,
        listeners_healthy: true,
    });

    (desired, runtime)
}

fn app() -> App {
    let (desired, runtime) = state();
    App::new(desired, runtime)
}

// --- navigation ------------------------------------------------------------

#[test]
fn q_quits_and_says_so_both_ways() {
    let mut app = app();
    assert_eq!(app.on_key(Key::Char('q')), Action::Quit);
    assert!(app.should_quit);
}

#[test]
fn tab_and_shift_tab_walk_the_panes_in_opposite_directions() {
    let mut app = app();
    assert_eq!(app.view, View::Profiles);
    app.on_key(Key::Tab);
    assert_eq!(app.view, View::Nodes);
    app.on_key(Key::BackTab);
    assert_eq!(app.view, View::Profiles);
    // And they wrap.
    app.on_key(Key::BackTab);
    assert_eq!(app.view, View::Logs);
    app.on_key(Key::Tab);
    assert_eq!(app.view, View::Profiles);
}

#[test]
fn the_digits_select_the_pane_printed_beside_them() {
    let mut app = app();
    for view in View::ALL {
        app.on_key(Key::Char(view.digit()));
        assert_eq!(app.view, view, "{} did not select {view:?}", view.digit());
    }
}

#[test]
fn switching_panes_puts_the_cursor_back_at_the_top() {
    let mut app = app();
    app.on_key(Key::Char('j'));
    assert_eq!(app.cursor, 1);
    app.on_key(Key::Tab);
    assert_eq!(app.cursor, 0);
}

#[test]
fn the_cursor_cannot_leave_the_list_in_either_direction() {
    let mut app = app();
    let len = app.rows().len();
    assert!(len >= 2);
    for _ in 0..(len + 5) {
        app.on_key(Key::Char('j'));
    }
    assert_eq!(app.cursor, len - 1, "j must stop at the last row");
    for _ in 0..(len + 5) {
        app.on_key(Key::Char('k'));
    }
    assert_eq!(app.cursor, 0, "k must stop at the first row");
}

#[test]
fn g_and_shift_g_jump_to_the_ends() {
    let mut app = app();
    app.on_key(Key::Char('G'));
    assert_eq!(app.cursor, app.rows().len() - 1);
    app.on_key(Key::Char('g'));
    assert_eq!(app.cursor, 0);
}

#[test]
fn page_keys_move_further_but_still_stay_inside() {
    let mut app = app();
    app.on_key(Key::PageDown);
    assert_eq!(app.cursor, app.rows().len() - 1);
    app.on_key(Key::PageUp);
    assert_eq!(app.cursor, 0);
}

#[test]
fn an_empty_pane_leaves_the_cursor_at_zero_rather_than_underflowing() {
    let mut app = App::default();
    app.on_key(Key::Char('j'));
    app.on_key(Key::Char('G'));
    app.on_key(Key::PageDown);
    assert_eq!(app.cursor, 0);
    assert!(app.selected().is_none());
}

// --- overlays --------------------------------------------------------------

#[test]
fn the_help_overlay_opens_and_any_key_closes_it() {
    let mut app = app();
    app.on_key(Key::Char('?'));
    assert_eq!(app.overlay, Overlay::Help);
    app.on_key(Key::Char('x'));
    assert_eq!(app.overlay, Overlay::None);
}

#[test]
fn while_help_is_up_q_closes_it_rather_than_quitting() {
    // An overlay that lets a keystroke through to the pane behind it is an
    // interface people stop trusting.
    let mut app = app();
    app.on_key(Key::Char('?'));
    assert_eq!(app.on_key(Key::Char('q')), Action::None);
    assert!(!app.should_quit);
}

#[test]
fn the_filter_narrows_the_list_and_enter_applies_it() {
    let mut app = app();
    app.on_key(Key::Char('/'));
    for c in "med".chars() {
        app.on_key(Key::Char(c));
    }
    // The list narrows while typing, before Enter.
    assert_eq!(app.rows().len(), 1);
    assert_eq!(app.rows()[0].id, "media");

    app.on_key(Key::Enter);
    assert_eq!(app.overlay, Overlay::None);
    assert_eq!(app.filter, "med");
    assert_eq!(app.rows().len(), 1);
}

#[test]
fn escape_cancels_a_filter_being_typed_without_applying_it() {
    let mut app = app();
    let before = app.rows().len();
    app.on_key(Key::Char('/'));
    app.on_key(Key::Char('z'));
    app.on_key(Key::Escape);
    assert_eq!(app.overlay, Overlay::None);
    assert_eq!(app.filter, "");
    assert_eq!(app.rows().len(), before);
}

#[test]
fn escape_clears_a_filter_that_was_applied() {
    let mut app = app();
    let before = app.rows().len();
    app.on_key(Key::Char('/'));
    app.on_key(Key::Char('m'));
    app.on_key(Key::Enter);
    assert!(app.rows().len() < before);
    app.on_key(Key::Escape);
    assert_eq!(app.filter, "");
    assert_eq!(app.rows().len(), before);
}

#[test]
fn backspace_removes_the_last_character_of_a_filter() {
    let mut app = app();
    app.on_key(Key::Char('/'));
    app.on_key(Key::Char('m'));
    app.on_key(Key::Char('z'));
    assert!(app.rows().is_empty());
    app.on_key(Key::Backspace);
    assert_eq!(app.rows().len(), 1);
}

#[test]
fn a_filter_that_matches_nothing_says_so_rather_than_showing_everything() {
    let mut app = app();
    app.on_key(Key::Char('/'));
    for c in "nothing-matches-this".chars() {
        app.on_key(Key::Char(c));
    }
    assert!(app.rows().is_empty());
}

#[test]
fn while_filtering_q_types_a_q_rather_than_quitting() {
    let mut app = app();
    app.on_key(Key::Char('/'));
    assert_eq!(app.on_key(Key::Char('q')), Action::None);
    assert!(!app.should_quit);
    assert_eq!(app.active_filter(), "q");
}

// --- actions ---------------------------------------------------------------

#[test]
fn enter_opens_a_picker_listing_every_target_a_profile_could_take() {
    let mut app = app();
    app.on_key(Key::Enter);
    match &app.overlay {
        Overlay::TargetPicker { candidates, .. } => {
            assert!(candidates.contains(&Target::Direct));
            assert!(candidates.contains(&Target::Block));
            assert!(
                candidates
                    .iter()
                    .any(|target| matches!(target, Target::Node { .. }))
            );
            assert!(
                candidates
                    .iter()
                    .any(|target| matches!(target, Target::Group { .. }))
            );
            assert!(
                candidates
                    .iter()
                    .any(|target| matches!(target, Target::Chain { .. }))
            );
        }
        other => panic!("expected a picker, got {other:?}"),
    }
}

#[test]
fn the_picker_opens_on_the_target_the_profile_already_has() {
    let mut app = app();
    // Row 0 is `media`, whose target is `direct`.
    app.on_key(Key::Enter);
    match &app.overlay {
        Overlay::TargetPicker {
            candidates,
            selected,
            profile,
        } => {
            assert_eq!(profile, "media");
            assert_eq!(candidates[*selected], Target::Direct);
        }
        other => panic!("expected a picker, got {other:?}"),
    }
}

#[test]
fn choosing_in_the_picker_asks_for_exactly_that_target() {
    let mut app = app();
    app.on_key(Key::Enter);
    app.on_key(Key::Char('j'));
    let expected = match &app.overlay {
        Overlay::TargetPicker {
            candidates,
            selected,
            ..
        } => candidates[*selected].clone(),
        other => panic!("expected a picker, got {other:?}"),
    };
    match app.on_key(Key::Enter) {
        Action::SetTarget { profile, target } => {
            assert_eq!(profile, "media");
            assert_eq!(target, expected);
        }
        other => panic!("expected a target change, got {other:?}"),
    }
    assert_eq!(app.overlay, Overlay::None);
}

#[test]
fn escaping_the_picker_changes_nothing() {
    let mut app = app();
    app.on_key(Key::Enter);
    assert_eq!(app.on_key(Key::Escape), Action::None);
    assert_eq!(app.overlay, Overlay::None);
}

#[test]
fn enter_outside_the_profiles_pane_explains_itself() {
    let mut app = app();
    app.on_key(Key::Char('2'));
    match app.on_key(Key::Enter) {
        Action::Notice(message) => assert!(message.contains("Profiles"), "{message}"),
        other => panic!("expected a notice, got {other:?}"),
    }
}

#[test]
fn t_probes_the_selected_node_and_only_in_the_nodes_pane() {
    let mut app = app();
    match app.on_key(Key::Char('t')) {
        Action::Notice(message) => assert!(message.contains("Nodes"), "{message}"),
        other => panic!("expected a notice, got {other:?}"),
    }
    app.on_key(Key::Char('2'));
    match app.on_key(Key::Char('t')) {
        Action::TestNode { node } => assert_eq!(node, "alpha"),
        other => panic!("expected a probe, got {other:?}"),
    }
}

#[test]
fn the_lifecycle_keys_ask_for_the_right_thing() {
    let mut app = app();
    assert_eq!(app.on_key(Key::Char('r')), Action::Refresh);
    assert_eq!(app.on_key(Key::Char('m')), Action::CycleMode);
    assert_eq!(app.on_key(Key::Char('u')), Action::Up);
    assert_eq!(app.on_key(Key::Char('d')), Action::Down);
}

#[test]
fn a_confirmation_needs_y_and_anything_else_leaves_it_up() {
    let mut app = app();
    app.overlay = Overlay::Confirm {
        prompt: "really?".to_owned(),
        action: Box::new(Action::Down),
    };
    assert_eq!(app.on_key(Key::Char('x')), Action::None);
    assert!(matches!(app.overlay, Overlay::Confirm { .. }));
    assert_eq!(app.on_key(Key::Char('y')), Action::Down);
    assert_eq!(app.overlay, Overlay::None);
}

#[test]
fn a_confirmation_answered_no_does_nothing() {
    let mut app = app();
    app.overlay = Overlay::Confirm {
        prompt: "really?".to_owned(),
        action: Box::new(Action::Down),
    };
    assert_eq!(app.on_key(Key::Char('n')), Action::None);
    assert_eq!(app.overlay, Overlay::None);
}

// --- state -----------------------------------------------------------------

#[test]
fn every_pane_produces_rows_from_the_same_state() {
    let mut app = app();
    for view in View::ALL {
        app.view = view;
        // Logs start empty; everything else has fixture data.
        if view == View::Logs {
            continue;
        }
        assert!(!app.rows().is_empty(), "{view:?} produced no rows");
    }
}

#[test]
fn the_groups_pane_shows_chains_alongside_groups() {
    let mut app = app();
    app.view = View::Groups;
    let ids: Vec<String> = app.rows().into_iter().map(|row| row.id).collect();
    assert!(ids.contains(&"eu".to_owned()), "{ids:?}");
    assert!(ids.contains(&"via-eu".to_owned()), "{ids:?}");
}

#[test]
fn the_log_pane_shows_the_newest_line_first() {
    let mut app = app();
    app.view = View::Logs;
    app.push_log("first");
    app.push_log("second");
    let rows = app.rows();
    assert_eq!(rows[0].primary, "second");
    assert_eq!(rows[1].primary, "first");
}

#[test]
fn the_log_buffer_is_bounded() {
    let mut app = App::default();
    for index in 0..(LOG_CAPACITY + 50) {
        app.push_log(format!("line {index}"));
    }
    assert_eq!(app.logs.len(), LOG_CAPACITY);
    // The oldest lines are the ones that went.
    assert_eq!(app.logs[0], format!("line {}", 50));
}

#[test]
fn a_refresh_that_shortens_the_list_keeps_the_cursor_inside_it() {
    let mut app = app();
    app.on_key(Key::Char('G'));
    assert!(app.cursor > 0);
    app.update(DesiredState::default(), RuntimeState::default());
    assert_eq!(app.cursor, 0);
    assert!(app.selected().is_none());
}

#[test]
fn losing_the_daemon_is_visible_in_the_headline() {
    let mut app = app();
    assert!(!app.headline().contains("unreachable"));
    app.connected = false;
    assert!(app.headline().contains("unreachable"), "{}", app.headline());
}

#[test]
fn a_subscription_url_is_never_shown() {
    // Share links and subscription URLs carry reusable credentials. `Secret`'s
    // Display redacts; this asserts the pane relies on that rather than
    // reaching past it.
    let mut app = app();
    app.view = View::Subscriptions;
    let rendered = format!("{:?}", app.rows());
    assert!(!rendered.contains("SUPERSECRET"), "{rendered}");
    assert!(!rendered.contains("token="), "{rendered}");
}

#[test]
fn every_documented_key_does_something() {
    // The help overlay is generated from `KEYS`; a binding listed there that
    // does nothing is a lie told to every user who reads it.
    // A label may name several keys — "u / d", "j / k, arrows" — so every
    // single-character token is taken, not only whole labels.
    let single_keys: Vec<char> = KEYS
        .iter()
        .flat_map(|(key, _)| key.split(['/', ',', ' ']))
        .map(str::trim)
        .filter(|token| token.chars().count() == 1)
        .filter_map(|token| token.chars().next())
        .collect();
    assert!(
        single_keys.len() >= 10,
        "expected the reference to list single-key bindings, found {single_keys:?}"
    );
    for key in single_keys {
        let mut app = app();
        // Start in the middle of the list, so that a key which moves the cursor
        // has somewhere to move it in either direction.
        app.cursor = 1;
        let before = format!("{:?}{:?}{}", app.view, app.overlay, app.cursor);
        let action = app.on_key(Key::Char(key));
        let after = format!("{:?}{:?}{}", app.view, app.overlay, app.cursor);
        assert!(
            action != Action::None || before != after,
            "{key:?} is documented but neither acted nor changed anything"
        );
    }
}

#[test]
fn an_undocumented_key_is_ignored_rather_than_guessed_at() {
    let mut app = app();
    let before = format!("{:?}{:?}{}", app.view, app.overlay, app.cursor);
    assert_eq!(app.on_key(Key::Char('z')), Action::None);
    assert_eq!(app.on_key(Key::Other), Action::None);
    assert_eq!(
        format!("{:?}{:?}{}", app.view, app.overlay, app.cursor),
        before
    );
}

// --- editing ---------------------------------------------------------------

/// The keys that open each form, from the pane they belong to.
#[test]
fn the_editing_keys_open_the_right_form() {
    use crate::edit::FormKind;

    let mut app = app();

    app.view = View::Nodes;
    assert_eq!(app.on_key(Key::Char('a')), Action::None);
    match &app.overlay {
        Overlay::Form(form) => assert_eq!(form.kind, FormKind::NodeAdd),
        other => panic!("expected a node form, got {other:?}"),
    }

    app.overlay = Overlay::None;
    assert_eq!(app.on_key(Key::Char('i')), Action::None);
    match &app.overlay {
        Overlay::Form(form) => assert_eq!(form.kind, FormKind::ImportLinks),
        other => panic!("expected an import form, got {other:?}"),
    }

    app.overlay = Overlay::None;
    app.view = View::Profiles;
    assert_eq!(app.on_key(Key::Char('a')), Action::None);
    match &app.overlay {
        Overlay::Form(form) => assert_eq!(form.kind, FormKind::Profile),
        other => panic!("expected a profile form, got {other:?}"),
    }
}

/// A key that does not apply to the current pane says so instead of doing
/// nothing: silence looks like a broken keyboard.
#[test]
fn an_editing_key_in_the_wrong_pane_explains_itself() {
    let mut app = app();
    app.view = View::Logs;
    match app.on_key(Key::Char('e')) {
        Action::Notice(message) => assert!(message.contains("Nodes"), "{message}"),
        other => panic!("expected a notice, got {other:?}"),
    }
}

#[test]
fn a_completed_node_form_produces_an_add_action() {
    let mut app = app();
    app.view = View::Nodes;
    app.on_key(Key::Char('a'));

    for (field, text) in [
        ("name", "HK 02"),
        ("address", "hk2.example.com"),
        ("port", "443"),
        ("uuid", "11111111-2222-3333-4444-555555555555"),
    ] {
        let Overlay::Form(form) = &mut app.overlay else {
            panic!("the form closed early");
        };
        form.cursor = form
            .fields
            .iter()
            .position(|candidate| candidate.key == field)
            .expect("field");
        for character in text.chars() {
            app.on_key(Key::Char(character));
        }
    }

    // Move to the last field and submit.
    let Overlay::Form(form) = &mut app.overlay else {
        panic!("the form closed early");
    };
    form.cursor = form.fields.len() - 1;
    match app.on_key(Key::Enter) {
        Action::AddNode(draft) => {
            let node = draft.create().expect("the draft must build");
            assert_eq!(node.name, "HK 02");
            assert_eq!(node.endpoint.port, 443);
        }
        other => panic!("expected AddNode, got {other:?}"),
    }
}

/// A form that cannot be applied keeps the user's text and says what is wrong.
#[test]
fn an_invalid_form_is_returned_with_its_error_and_its_text() {
    let mut app = app();
    app.view = View::Nodes;
    app.on_key(Key::Char('a'));

    // Name only: no address, no port, no credential.
    let Overlay::Form(form) = &mut app.overlay else {
        panic!("no form");
    };
    form.cursor = form
        .fields
        .iter()
        .position(|field| field.key == "name")
        .expect("name");
    for character in "incomplete".chars() {
        app.on_key(Key::Char(character));
    }
    let Overlay::Form(form) = &mut app.overlay else {
        panic!("no form");
    };
    form.cursor = form.fields.len() - 1;

    assert_eq!(app.on_key(Key::Enter), Action::None);
    match &app.overlay {
        Overlay::Form(form) => {
            assert!(form.error.is_some(), "the reason must be shown");
            assert_eq!(
                form.value("name"),
                "incomplete",
                "losing a half-filled form to an error is the fastest way to make \
                 somebody stop using an interface"
            );
        }
        other => panic!("the form must stay open, got {other:?}"),
    }
}

#[test]
fn escape_closes_a_form_without_changing_anything() {
    let mut app = app();
    app.view = View::Nodes;
    app.on_key(Key::Char('a'));
    assert_eq!(app.on_key(Key::Escape), Action::None);
    assert_eq!(app.overlay, Overlay::None);
    assert_eq!(app.status, "cancelled");
}

#[test]
fn removing_a_node_asks_first() {
    let mut app = app();
    app.view = View::Nodes;
    app.cursor = 0;
    assert_eq!(app.on_key(Key::Char('D')), Action::None);
    match &app.overlay {
        Overlay::Confirm { prompt, .. } => assert!(prompt.contains("remove"), "{prompt}"),
        other => panic!("a deletion must be confirmed, got {other:?}"),
    }
    // n keeps it.
    assert_eq!(app.on_key(Key::Char('n')), Action::None);
    assert_eq!(app.overlay, Overlay::None);
}

#[test]
fn a_qr_overlay_closes_on_any_of_the_obvious_keys() {
    let mut app = app();
    for key in [Key::Escape, Key::Enter, Key::Char('q')] {
        app.overlay = Overlay::Qr {
            art: "▀▀".to_owned(),
            node: "hk-01".to_owned(),
        };
        app.on_key(key);
        assert_eq!(app.overlay, Overlay::None, "{key:?} must close the QR view");
    }
}
