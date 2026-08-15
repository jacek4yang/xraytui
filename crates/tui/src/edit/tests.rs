//! Tests for the editing forms.
//!
//! Every one is a sequence of keystrokes: the forms are pure, so the whole
//! editing workflow is testable without a terminal.

use super::*;

fn type_text(form: &mut Form, text: &str) {
    for character in text.chars() {
        assert_eq!(form.on_key(Key::Char(character)), Outcome::Editing);
    }
}

fn go_to(form: &mut Form, key: &str) {
    let index = form
        .fields
        .iter()
        .position(|field| field.key == key)
        .unwrap_or_else(|| panic!("no field {key}"));
    form.cursor = index;
}

fn sample_node() -> Node {
    let mut form = Form::node_add();
    go_to(&mut form, "name");
    type_text(&mut form, "HK 01");
    go_to(&mut form, "address");
    type_text(&mut form, "hk.example.com");
    go_to(&mut form, "port");
    type_text(&mut form, "443");
    go_to(&mut form, "uuid");
    type_text(&mut form, "11111111-2222-3333-4444-555555555555");
    form.draft().create().expect("create")
}

#[test]
fn typing_a_node_produces_the_same_draft_the_cli_would() {
    let node = sample_node();
    assert_eq!(node.name, "HK 01");
    assert_eq!(node.endpoint.port, 443);
    assert_eq!(node.protocol.xray_protocol(), "vless");
}

#[test]
fn enter_moves_down_and_submits_on_the_last_field() {
    let mut form = Form::subscription();
    assert_eq!(form.cursor, 0);
    assert_eq!(form.on_key(Key::Enter), Outcome::Editing);
    assert_eq!(form.cursor, 1);
    assert_eq!(
        form.on_key(Key::Enter),
        Outcome::Submit,
        "filling a form top to bottom must work without learning anything"
    );
}

#[test]
fn escape_cancels() {
    let mut form = Form::node_add();
    type_text(&mut form, "abc");
    assert_eq!(form.on_key(Key::Escape), Outcome::Cancelled);
}

#[test]
fn tab_wraps_in_both_directions() {
    let mut form = Form::subscription();
    form.on_key(Key::BackTab);
    assert_eq!(
        form.cursor, 1,
        "back from the first field wraps to the last"
    );
    form.on_key(Key::Tab);
    assert_eq!(form.cursor, 0);
}

#[test]
fn backspace_deletes_from_the_focused_field_only() {
    let mut form = Form::subscription();
    type_text(&mut form, "https://x");
    form.on_key(Key::Backspace);
    assert_eq!(form.value("url"), "https://");
    assert_eq!(form.value("name"), "");
}

#[test]
fn a_field_cannot_grow_without_bound() {
    let mut form = Form::subscription();
    for _ in 0..2_000 {
        form.on_key(Key::Char('x'));
    }
    assert!(
        form.value("url").chars().count() <= 512,
        "a pasted file must not become an unbounded allocation"
    );
}

#[test]
fn the_url_and_the_credentials_are_marked_secret() {
    assert!(
        Form::subscription().fields[0].secret,
        "a subscription URL carries a token"
    );
    let node = Form::node_add();
    for key in ["uuid", "password", "public_key", "short_id"] {
        let field = node
            .fields
            .iter()
            .find(|field| field.key == key)
            .unwrap_or_else(|| panic!("no field {key}"));
        assert!(field.secret, "{key} must not be rendered in the clear");
    }
}

#[test]
fn editing_prefills_everything_except_the_credentials() {
    let node = sample_node();
    let form = Form::node_edit(&node);
    assert_eq!(form.value("name"), "HK 01");
    assert_eq!(form.value("address"), "hk.example.com");
    assert_eq!(form.value("port"), "443");
    assert_eq!(
        form.value("uuid"),
        "",
        "a person editing a port must never have to retype a UUID, and a \
         screen-share must never show one"
    );

    // A blank credential on an edit means "keep it".
    let updated = form.draft().edit(&node).expect("edit");
    assert_eq!(updated.protocol, node.protocol, "the UUID survived");
    assert_eq!(updated.id, node.id);
}

#[test]
fn an_edit_form_changes_only_what_was_retyped() {
    let node = sample_node();
    let mut form = Form::node_edit(&node);
    go_to(&mut form, "port");
    for _ in 0..3 {
        form.on_key(Key::Backspace);
    }
    type_text(&mut form, "8443");

    let updated = form.draft().edit(&node).expect("edit");
    assert_eq!(updated.endpoint.port, 8443);
    assert_eq!(updated.endpoint.address, "hk.example.com");
    assert_eq!(updated.name, "HK 01");
}

#[test]
fn a_form_refuses_the_same_wrong_combinations_the_cli_does() {
    let mut form = Form::node_add();
    go_to(&mut form, "address");
    type_text(&mut form, "hk.example.com");
    go_to(&mut form, "port");
    type_text(&mut form, "443");
    go_to(&mut form, "uuid");
    type_text(&mut form, "u");
    // A Shadowsocks cipher on a VLESS node: the shared draft refuses it, so the
    // interface cannot accidentally be more permissive than the command line.
    go_to(&mut form, "method");
    type_text(&mut form, "aes-256-gcm");

    let error = form.draft().create().expect_err("must refuse");
    assert!(format!("{error}").contains("--method"), "{error}");
}

#[test]
fn a_grpc_form_sends_the_path_field_as_the_service_name() {
    let mut form = Form::node_add();
    go_to(&mut form, "transport");
    for _ in 0..3 {
        form.on_key(Key::Backspace);
    }
    type_text(&mut form, "grpc");
    go_to(&mut form, "path");
    type_text(&mut form, "TunService");
    assert_eq!(form.draft().service_name.as_deref(), Some("TunService"));
}

#[test]
fn listener_ports_round_trip() {
    let form = Form::listeners("work", Some(1080), None);
    assert_eq!(form.value("socks"), "1080");
    assert_eq!(form.value("http"), "");
    assert!(matches!(form.kind, FormKind::Listeners { .. }));
}
