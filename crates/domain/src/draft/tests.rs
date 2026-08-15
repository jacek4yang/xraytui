//! Tests for the shared node builder.

use super::*;

fn draft(protocol: &str) -> NodeDraft {
    NodeDraft {
        protocol: Some(protocol.to_owned()),
        name: Some("HK 01".to_owned()),
        address: Some("hk.example.com".to_owned()),
        port: Some(443),
        ..NodeDraft::default()
    }
}

#[test]
fn a_vless_node_is_built_from_typed_fields() {
    let mut d = draft("vless");
    d.uuid = Some("11111111-2222-3333-4444-555555555555".to_owned());
    d.flow = Some("xtls-rprx-vision".to_owned());
    let node = d.create().expect("create");

    assert_eq!(node.protocol.xray_protocol(), "vless");
    assert_eq!(node.endpoint.address, "hk.example.com");
    assert_eq!(node.endpoint.port, 443);
    assert_eq!(node.name, "HK 01");
    assert_eq!(node.source, NodeSource::Manual);
    assert!(node.enabled);
    assert!(node.id.as_str().starts_with("hk-01-"), "{}", node.id);
}

#[test]
fn two_nodes_with_the_same_name_get_different_identifiers() {
    let mut first = draft("trojan");
    first.password = Some("p".to_owned());
    let mut second = first.clone();
    second.address = Some("other.example.com".to_owned());

    let a = first.create().expect("create");
    let b = second.create().expect("create");
    assert_ne!(
        a.id, b.id,
        "two providers both call a node 'HK 01'; they cannot share an identifier"
    );
}

#[test]
fn every_supported_protocol_builds() {
    for protocol in PROTOCOLS {
        let mut d = draft(protocol);
        match *protocol {
            "vless" | "vmess" => {
                d.uuid = Some("11111111-2222-3333-4444-555555555555".to_owned());
            }
            "trojan" => d.password = Some("secret".to_owned()),
            "shadowsocks" => {
                d.password = Some("secret".to_owned());
                d.method = Some("aes-256-gcm".to_owned());
            }
            "http" | "socks" => {
                d.username = Some("user".to_owned());
                d.password = Some("secret".to_owned());
            }
            _ => {}
        }
        let node = d
            .create()
            .unwrap_or_else(|error| panic!("{protocol}: {error}"));
        assert_eq!(node.protocol.xray_protocol(), *protocol);
    }
}

#[test]
fn a_field_from_another_protocol_is_refused_rather_than_ignored() {
    let mut d = draft("vless");
    d.uuid = Some("11111111-2222-3333-4444-555555555555".to_owned());
    d.method = Some("aes-256-gcm".to_owned());

    let error = d.create().expect_err("must refuse");
    assert!(
        matches!(error, DraftError::Irrelevant { .. }),
        "silently dropping it would produce a node that does something else: {error}"
    );
    assert!(format!("{error}").contains("--method"));
}

#[test]
fn vmess_has_no_flow() {
    let mut d = draft("vmess");
    d.uuid = Some("11111111-2222-3333-4444-555555555555".to_owned());
    d.flow = Some("xtls-rprx-vision".to_owned());
    let error = d.create().expect_err("must refuse");
    assert!(format!("{error}").contains("--flow"), "{error}");
}

#[test]
fn a_missing_credential_names_the_flag_to_use() {
    let error = draft("trojan").create().expect_err("must refuse");
    assert!(format!("{error}").contains("--password"), "{error}");

    let error = draft("shadowsocks").create().expect_err("must refuse");
    let text = format!("{error}");
    assert!(
        text.contains("--method") || text.contains("--password"),
        "{text}"
    );
}

#[test]
fn security_is_inferred_from_the_fields_that_imply_it() {
    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.public_key = Some("aaaa".to_owned());
    assert_eq!(
        d.create().expect("create").security.xray_security(),
        "reality"
    );

    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.sni = Some("example.com".to_owned());
    assert_eq!(d.create().expect("create").security.xray_security(), "tls");

    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    assert_eq!(d.create().expect("create").security.xray_security(), "none");
}

#[test]
fn reality_without_a_public_key_is_refused() {
    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.tls = Some("reality".to_owned());
    let error = d.create().expect_err("must refuse");
    assert!(format!("{error}").contains("--public-key"), "{error}");
}

#[test]
fn a_draft_never_disables_certificate_verification() {
    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.tls = Some("tls".to_owned());
    d.sni = Some("example.com".to_owned());
    match d.create().expect("create").security {
        TransportSecurity::Tls(tls) => assert!(
            !tls.allow_insecure,
            "turning off verification must be a deliberate act, not a side effect of a form"
        ),
        other => panic!("expected TLS, got {other:?}"),
    }
}

#[test]
fn transports_build_with_their_own_fields() {
    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.transport = Some("ws".to_owned());
    d.path = Some("/ray".to_owned());
    d.host = Some("cdn.example.com".to_owned());
    assert_eq!(d.create().expect("create").transport.xray_network(), "ws");

    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.transport = Some("grpc".to_owned());
    d.service_name = Some("TunService".to_owned());
    assert_eq!(d.create().expect("create").transport.xray_network(), "grpc");

    // `tcp` is what every share link and every tutorial still says.
    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.transport = Some("tcp".to_owned());
    assert_eq!(d.create().expect("create").transport.xray_network(), "raw");
}

#[test]
fn an_unknown_transport_lists_the_accepted_ones() {
    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.transport = Some("carrier-pigeon".to_owned());
    let error = d.create().expect_err("must refuse");
    assert!(format!("{error}").contains("raw"), "{error}");
}

#[test]
fn an_empty_address_or_zero_port_is_refused() {
    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.address = Some("   ".to_owned());
    assert!(d.create().is_err());

    let mut d = draft("vless");
    d.uuid = Some("u".to_owned());
    d.port = Some(0);
    assert!(d.create().is_err());
}

// --- editing ---------------------------------------------------------------

fn existing() -> Node {
    let mut d = draft("vless");
    d.uuid = Some("11111111-2222-3333-4444-555555555555".to_owned());
    d.flow = Some("xtls-rprx-vision".to_owned());
    d.create().expect("create")
}

#[test]
fn an_edit_changes_only_what_was_given() {
    let before = existing();
    let edit = NodeDraft {
        name: Some("HK 01 (new)".to_owned()),
        ..NodeDraft::default()
    };
    let after = edit.edit(&before).expect("edit");

    assert_eq!(after.name, "HK 01 (new)");
    assert_eq!(
        after.id, before.id,
        "the identifier is what profiles, groups and chains point at"
    );
    assert_eq!(after.endpoint, before.endpoint);
    assert_eq!(after.protocol, before.protocol);
    assert_eq!(after.security, before.security);
}

#[test]
fn an_edit_can_clear_a_flow() {
    let before = existing();
    let edit = NodeDraft {
        flow: Some(String::new()),
        ..NodeDraft::default()
    };
    match edit.edit(&before).expect("edit").protocol {
        ProtocolSettings::Vless(settings) => assert!(
            settings.flow.is_empty(),
            "an empty value must clear rather than be treated as absent"
        ),
        other => panic!("expected VLESS, got {other:?}"),
    }
}

#[test]
fn an_edit_refuses_a_field_from_another_protocol() {
    let before = existing();
    let edit = NodeDraft {
        method: Some("aes-256-gcm".to_owned()),
        ..NodeDraft::default()
    };
    let error = edit.edit(&before).expect_err("must refuse");
    assert!(
        format!("{error}").contains("--method"),
        "an edit that ignores a field is exactly as wrong as a create that does: {error}"
    );
}

#[test]
fn an_edit_cannot_change_the_protocol() {
    let before = existing();
    let edit = NodeDraft {
        protocol: Some("trojan".to_owned()),
        ..NodeDraft::default()
    };
    let error = edit.edit(&before).expect_err("must refuse");
    assert!(format!("{error}").contains("remove it"), "{error}");
}

#[test]
fn editing_a_subscription_node_makes_it_manual() {
    let mut before = existing();
    before.source = NodeSource::Subscription {
        id: crate::SubscriptionId::new("upstream").expect("id"),
    };
    let edit = NodeDraft {
        name: Some("mine".to_owned()),
        ..NodeDraft::default()
    };
    assert_eq!(
        edit.edit(&before).expect("edit").source,
        NodeSource::Manual,
        "otherwise the next subscription update silently reverts the edit"
    );
}

#[test]
fn an_edit_that_mentions_no_transport_leaves_it_alone() {
    let mut before = existing();
    before.transport = Transport::Websocket(WebsocketTransport {
        path: "/ray".to_owned(),
        host: None,
        headers: std::collections::BTreeMap::new(),
    });
    let edit = NodeDraft {
        name: Some("renamed".to_owned()),
        ..NodeDraft::default()
    };
    assert_eq!(
        edit.edit(&before).expect("edit").transport.xray_network(),
        "ws"
    );
}
