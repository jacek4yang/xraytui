//! Validates generated configurations against a real Xray-core binary.
//!
//! Skipped (with a printed note, not a silent pass) when no Xray binary is
//! available. Set `XRAYTUI_TEST_XRAY` to point at a specific binary; otherwise
//! `xray` is looked up on `PATH`.

use std::collections::BTreeMap;
use std::process::Command;

use xraytui_domain::{
    AppMatcher, AppRuleId, ApplicationRule, Chain, ChainId, DesiredState, EgressProfile, Endpoint,
    Group, GroupId, GroupMembership, GroupStrategy, ListenerSpec, Node, NodeId, NodeSource,
    ProfileId, ProtocolSettings, RoutingMatch, RoutingRuleId, RuleAction, SystemMode, Target,
    TrojanSettings, VlessSettings,
};
use xraytui_secrets::Secret;
use xraytui_xray_compiler::{CompileOptions, DnsOptions, TunOptions, compile};

fn xray_binary() -> Option<String> {
    if let Ok(path) = std::env::var("XRAYTUI_TEST_XRAY") {
        return std::path::Path::new(&path).is_file().then_some(path);
    }
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = std::path::Path::new(dir).join("xray");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Run `xray run -test -config <file>` and return stdout+stderr on failure.
fn validate(json: &str) -> Result<(), String> {
    let Some(binary) = xray_binary() else {
        return Err("SKIP".into());
    };
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let path = dir.path().join("config.json");
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    let output = Command::new(&binary)
        .args(["run", "-test", "-config"])
        .arg(&path)
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "xray rejected the configuration\n--- stdout ---\n{}\n--- stderr ---\n{}\n--- config ---\n{json}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn check(name: &str, json: &str) {
    match validate(json) {
        Ok(()) => {}
        Err(message) if message == "SKIP" => {
            eprintln!("SKIPPED {name}: no Xray binary found (set XRAYTUI_TEST_XRAY)");
        }
        Err(message) => panic!("{name}: {message}"),
    }
}

fn trojan_node(id: &str, name: &str) -> Node {
    Node::new(
        NodeId::new(id).expect("valid"),
        name,
        NodeSource::Manual,
        Endpoint::new(format!("{id}.example.com"), 443),
        ProtocolSettings::Trojan(TrojanSettings { password: Secret::new("pw"), flow: String::new() }),
    )
}

fn vless_reality_node(id: &str) -> Node {
    let mut node = Node::new(
        NodeId::new(id).expect("valid"),
        format!("VLESS {id}"),
        NodeSource::Manual,
        Endpoint::new("1.2.3.4", 443),
        ProtocolSettings::Vless(VlessSettings {
            id: Secret::new("11111111-2222-3333-4444-555555555555"),
            flow: "xtls-rprx-vision".into(),
            encryption: "none".into(),
            level: None,
        }),
    );
    node.security = xraytui_domain::TransportSecurity::Reality(xraytui_domain::RealitySettings {
        server_name: Some("www.example.org".into()),
        // A syntactically valid X25519 public key; REALITY rejects malformed ones
        // at configuration load time, which is exactly what this test exercises.
        public_key: Secret::new("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"),
        short_id: Some(Secret::new("6ba85179e30d4fc2")),
        spider_x: Some("/".into()),
        fingerprint: Some("chrome".into()),
        mldsa65_verify: None,
    });
    node
}

fn full_state() -> DesiredState {
    let mut state = DesiredState::default();
    state.mode = SystemMode::Rule;

    for node in [
        trojan_node("hk-01", "HK 01"),
        trojan_node("hk-02", "HK 02"),
        trojan_node("us-01", "US 01"),
        vless_reality_node("jp-02"),
    ] {
        state.nodes.insert(node.id.clone(), node);
    }

    let group = GroupId::new("auto-hk").expect("valid");
    state.groups.insert(
        group.clone(),
        Group {
            id: group.clone(),
            name: "Auto HK".into(),
            strategy: GroupStrategy::LeastPing,
            membership: GroupMembership { include_regex: vec!["^HK".into()], ..Default::default() },
            manual_selection: None,
            fallback: Some(Target::Direct),
        },
    );

    let chain = ChainId::new("hk-us").expect("valid");
    state.chains.insert(
        chain.clone(),
        Chain {
            id: chain.clone(),
            name: "HK to US".into(),
            hops: vec![NodeId::new("hk-01").expect("valid"), NodeId::new("us-01").expect("valid")],
            enabled: true,
        },
    );

    let mut web = EgressProfile::new(
        ProfileId::new("web").expect("valid"),
        "Web",
        Target::Group { id: group },
    );
    web.socks = Some(ListenerSpec::loopback(11080));
    web.http = Some(ListenerSpec::loopback(11081));

    let mut development = EgressProfile::new(
        ProfileId::new("development").expect("valid"),
        "Development",
        Target::Node { id: NodeId::new("jp-02").expect("valid") },
    );
    development.socks = Some(ListenerSpec::loopback(12080));
    development.http = Some(ListenerSpec::loopback(12081));

    let chat = EgressProfile::new(
        ProfileId::new("chat").expect("valid"),
        "Chat",
        Target::Chain { id: chain },
    );
    let direct =
        EgressProfile::new(ProfileId::new("direct").expect("valid"), "Direct", Target::Direct);

    for profile in [web, development, chat, direct] {
        state.profiles.insert(profile.id.clone(), profile);
    }
    state.default_profile = Some(ProfileId::new("web").expect("valid"));

    for (id, priority, processes, action) in [
        ("firefox-web", 100, vec!["firefox", "/usr/lib/firefox/firefox"], "web"),
        ("rust-development", 110, vec!["cargo", "rustc", "rustup", "git"], "development"),
        ("telegram-chat", 120, vec!["telegram-desktop"], "chat"),
    ] {
        let rule_id = AppRuleId::new(id).expect("valid");
        state.app_rules.insert(
            rule_id.clone(),
            ApplicationRule {
                id: rule_id,
                priority,
                process: processes.into_iter().map(|p| AppMatcher(p.to_owned())).collect(),
                action: RuleAction::Profile { id: ProfileId::new(action).expect("valid") },
                enabled: true,
                note: None,
            },
        );
    }

    let steam = AppRuleId::new("steam-direct").expect("valid");
    state.app_rules.insert(
        steam.clone(),
        ApplicationRule {
            id: steam,
            priority: 130,
            process: vec![AppMatcher("steam".into()), AppMatcher("/usr/lib/steam/".into())],
            action: RuleAction::Target { target: Target::Direct },
            enabled: true,
            note: None,
        },
    );

    let private = RoutingRuleId::new("private-direct").expect("valid");
    state.routing_rules.insert(
        private.clone(),
        xraytui_domain::RoutingRule {
            id: private,
            priority: 1000,
            matcher: RoutingMatch { ip: vec!["geoip:private".into()], ..Default::default() },
            action: RuleAction::Target { target: Target::Direct },
            enabled: true,
            note: None,
        },
    );
    let ads = RoutingRuleId::new("ads-block").expect("valid");
    state.routing_rules.insert(
        ads.clone(),
        xraytui_domain::RoutingRule {
            id: ads,
            priority: 1100,
            matcher: RoutingMatch {
                domain: vec!["geosite:category-ads-all".into()],
                ..Default::default()
            },
            action: RuleAction::Target { target: Target::Block },
            enabled: true,
            note: None,
        },
    );
    let fallback = RoutingRuleId::new("fallback").expect("valid");
    state.routing_rules.insert(
        fallback.clone(),
        xraytui_domain::RoutingRule {
            id: fallback,
            priority: 10_000,
            matcher: RoutingMatch::default(),
            action: RuleAction::Profile { id: ProfileId::new("web").expect("valid") },
            enabled: true,
            note: None,
        },
    );

    state
}

#[test]
fn minimal_configuration_is_accepted() {
    let mut state = DesiredState::default();
    let profile =
        EgressProfile::new(ProfileId::new("direct").expect("valid"), "Direct", Target::Direct);
    state.profiles.insert(profile.id.clone(), profile);
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    check("minimal", &compiled.to_json().expect("json"));
}

#[test]
fn full_configuration_with_groups_chains_and_profiles_is_accepted() {
    let state = full_state();
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    check("full", &compiled.to_json().expect("json"));
}

#[test]
fn tun_and_dns_configuration_is_accepted() {
    let state = full_state();
    let options = CompileOptions {
        tun: Some(TunOptions { name: "xraytui0".into(), mtu: 1500 }),
        dns: DnsOptions {
            enabled: true,
            direct_servers: vec!["127.0.0.53".into(), "localhost".into()],
            proxy_servers: vec!["https://1.1.1.1/dns-query".into()],
            direct_domains: vec!["geosite:private".into()],
            listen: Some("127.0.0.1:15353".parse().expect("addr")),
            query_strategy: "UseIP".into(),
            non_ip_query: "drop".into(),
        },
        sniffing: xraytui_xray_compiler::SniffingOptions {
            enabled: true,
            dest_override: vec!["http".into(), "tls".into(), "quic".into()],
            route_only: true,
        },
        ..Default::default()
    };
    let compiled = compile(&state, &options).expect("compile");
    check("tun+dns", &compiled.to_json().expect("json"));
}

#[test]
fn every_balancer_strategy_is_accepted() {
    for strategy in [
        GroupStrategy::Random,
        GroupStrategy::RoundRobin,
        GroupStrategy::LeastPing,
        GroupStrategy::LeastLoad,
        GroupStrategy::Manual,
    ] {
        let mut state = DesiredState::default();
        for node in [trojan_node("a", "A"), trojan_node("b", "B")] {
            state.nodes.insert(node.id.clone(), node);
        }
        let group = GroupId::new("g").expect("valid");
        state.groups.insert(
            group.clone(),
            Group {
                id: group.clone(),
                name: "G".into(),
                strategy,
                membership: GroupMembership {
                    nodes: vec![NodeId::new("a").expect("valid"), NodeId::new("b").expect("valid")],
                    ..Default::default()
                },
                manual_selection: (strategy == GroupStrategy::Manual)
                    .then(|| Target::Node { id: NodeId::new("a").expect("valid") }),
                fallback: None,
            },
        );
        let profile = EgressProfile::new(
            ProfileId::new("p").expect("valid"),
            "P",
            Target::Group { id: group },
        );
        state.profiles.insert(profile.id.clone(), profile);
        let compiled = compile(&state, &CompileOptions::default()).expect("compile");
        check(&format!("strategy-{strategy:?}"), &compiled.to_json().expect("json"));
    }
}

#[test]
fn every_transport_and_security_combination_is_accepted() {
    use xraytui_domain::{
        GrpcTransport, HttpUpgradeTransport, MkcpTransport, RawTransport, TlsSettings, Transport,
        TransportSecurity, WebsocketTransport, XhttpTransport,
    };

    let transports: Vec<(&str, Transport)> = vec![
        ("raw", Transport::Raw(RawTransport::default())),
        (
            "xhttp",
            Transport::Xhttp(XhttpTransport {
                host: Some("cdn.example.com".into()),
                path: Some("/x".into()),
                mode: Some("auto".into()),
                extra: None,
            }),
        ),
        (
            "grpc",
            Transport::Grpc(GrpcTransport {
                service_name: "GunService".into(),
                multi_mode: true,
                authority: None,
            }),
        ),
        (
            "ws",
            Transport::Websocket(WebsocketTransport {
                path: "/ws".into(),
                host: Some("cdn.example.com".into()),
                headers: BTreeMap::new(),
            }),
        ),
        (
            "httpupgrade",
            Transport::HttpUpgrade(HttpUpgradeTransport {
                path: "/hu".into(),
                host: Some("cdn.example.com".into()),
            }),
        ),
        (
            "kcp",
            Transport::Mkcp(MkcpTransport {
                header_type: Some("dtls".into()),
                seed: Some(Secret::new("seed")),
            }),
        ),
    ];

    for (label, transport) in transports {
        for (security_label, security) in [
            ("none", TransportSecurity::None),
            (
                "tls",
                TransportSecurity::Tls(TlsSettings {
                    server_name: Some("example.com".into()),
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    fingerprint: Some("chrome".into()),
                    allow_insecure: false,
                }),
            ),
        ] {
            let mut state = DesiredState::default();
            let mut node = trojan_node("n", "N");
            node.transport = transport.clone();
            node.security = security.clone();
            state.nodes.insert(node.id.clone(), node);
            let profile = EgressProfile::new(
                ProfileId::new("p").expect("valid"),
                "P",
                Target::Node { id: NodeId::new("n").expect("valid") },
            );
            state.profiles.insert(profile.id.clone(), profile);
            let compiled = compile(&state, &CompileOptions::default()).expect("compile");
            check(
                &format!("transport-{label}-{security_label}"),
                &compiled.to_json().expect("json"),
            );
        }
    }
}

#[test]
fn vless_reality_configuration_is_accepted() {
    let mut state = DesiredState::default();
    let node = vless_reality_node("r");
    state.nodes.insert(node.id.clone(), node);
    let profile = EgressProfile::new(
        ProfileId::new("p").expect("valid"),
        "P",
        Target::Node { id: NodeId::new("r").expect("valid") },
    );
    state.profiles.insert(profile.id.clone(), profile);
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    check("vless-reality", &compiled.to_json().expect("json"));
}
