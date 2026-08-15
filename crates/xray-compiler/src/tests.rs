//! Compiler tests.
//!
//! These assert the *structure* the daemon relies on: that each profile owns an
//! independently overridable balancer, that groups go through a loopback second
//! stage, that chains link with `dialerProxy` in traffic order, and that the
//! output is byte-stable.

use super::*;
use xraytui_domain::{
    AppRuleId, ApplicationRule, Chain, EgressProfile, Endpoint, Group, GroupMembership, Node,
    NodeSource, ProtocolSettings, RoutingMatch, TrojanSettings,
};
use xraytui_secrets::Secret;

fn node(id: &str, name: &str) -> Node {
    Node::new(
        NodeId::new(id).expect("valid"),
        name,
        NodeSource::Manual,
        Endpoint::new(format!("{id}.example.com"), 443),
        ProtocolSettings::Trojan(TrojanSettings {
            password: Secret::new("pw"),
            flow: String::new(),
        }),
    )
}

fn base_state() -> DesiredState {
    let mut state = DesiredState::default();
    for (id, name) in [
        ("hk-01", "HK 01"),
        ("hk-02", "HK 02"),
        ("jp-02", "JP 02"),
        ("us-01", "US 01"),
    ] {
        let n = node(id, name);
        state.nodes.insert(n.id.clone(), n);
    }
    state
}

fn profile(id: &str, target: Target) -> EgressProfile {
    EgressProfile::new(ProfileId::new(id).expect("valid"), id, target)
}

fn find_balancer<'a>(compiled: &'a Compiled, tag: &str) -> &'a Balancer {
    compiled
        .config
        .routing
        .as_ref()
        .expect("routing")
        .balancers
        .iter()
        .find(|b| b.tag == tag)
        .unwrap_or_else(|| panic!("balancer {tag} not found"))
}

fn find_outbound<'a>(compiled: &'a Compiled, tag: &str) -> &'a Outbound {
    compiled
        .config
        .outbounds
        .iter()
        .find(|o| o.tag == tag)
        .unwrap_or_else(|| panic!("outbound {tag} not found"))
}

fn rule_tags(compiled: &Compiled) -> Vec<String> {
    compiled
        .config
        .routing
        .as_ref()
        .expect("routing")
        .rules
        .iter()
        .filter_map(|r| r.rule_tag.clone())
        .collect()
}

#[test]
fn blackhole_is_the_first_outbound() {
    let mut state = base_state();
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile(
            "web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        ),
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    assert_eq!(compiled.config.outbounds[0].tag, tags::CONTROL_BLOCK);
    assert_eq!(compiled.config.outbounds[0].protocol, "blackhole");
}

#[test]
fn every_profile_gets_its_own_selector_balancer() {
    let mut state = base_state();
    for (id, target) in [
        (
            "web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        ),
        (
            "development",
            Target::Node {
                id: NodeId::new("jp-02").expect("valid"),
            },
        ),
        ("direct", Target::Direct),
    ] {
        state
            .profiles
            .insert(ProfileId::new(id).expect("valid"), profile(id, target));
    }
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");

    let web = find_balancer(&compiled, "profile/web/selector");
    let dev = find_balancer(&compiled, "profile/development/selector");
    let direct = find_balancer(&compiled, "profile/direct/selector");

    assert_eq!(web.selector, vec!["node/hk-01/out"]);
    assert_eq!(dev.selector, vec!["node/jp-02/out"]);
    assert_eq!(direct.selector, vec!["control/direct"]);

    // Overrides are what the daemon replays after every start.
    assert!(
        compiled
            .selector_overrides
            .contains(&("profile/web/selector".into(), "node/hk-01/out".into()))
    );
    assert!(compiled.selector_overrides.contains(&(
        "profile/development/selector".into(),
        "node/jp-02/out".into()
    )));
}

#[test]
fn switching_one_profile_changes_only_that_selector() {
    let mut state = base_state();
    for (id, target) in [
        (
            "web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        ),
        (
            "development",
            Target::Node {
                id: NodeId::new("jp-02").expect("valid"),
            },
        ),
    ] {
        state
            .profiles
            .insert(ProfileId::new(id).expect("valid"), profile(id, target));
    }
    let before = compile(&state, &CompileOptions::default()).expect("compile");

    state
        .profiles
        .get_mut(&ProfileId::new("development").expect("valid"))
        .expect("profile")
        .target = Target::Node {
        id: NodeId::new("us-01").expect("valid"),
    };
    let after = compile(&state, &CompileOptions::default()).expect("compile");

    assert_eq!(
        find_balancer(&before, "profile/web/selector").selector,
        find_balancer(&after, "profile/web/selector").selector
    );
    assert_eq!(
        find_balancer(&after, "profile/development/selector").selector,
        vec!["node/us-01/out"]
    );
    // The outbound set is unchanged, which is what makes this a pure API switch
    // rather than a restart.
    let before_tags: Vec<&String> = before.config.outbounds.iter().map(|o| &o.tag).collect();
    let after_tags: Vec<&String> = after.config.outbounds.iter().map(|o| &o.tag).collect();
    assert_eq!(before_tags, after_tags);
}

#[test]
fn per_profile_listeners_route_to_their_own_selector() {
    let mut state = base_state();
    let mut web = profile(
        "web",
        Target::Node {
            id: NodeId::new("hk-01").expect("valid"),
        },
    );
    web.socks = Some(ListenerSpec::loopback(11080));
    web.http = Some(ListenerSpec::loopback(11081));
    let mut dev = profile(
        "development",
        Target::Node {
            id: NodeId::new("jp-02").expect("valid"),
        },
    );
    dev.socks = Some(ListenerSpec::loopback(12080));
    state.profiles.insert(web.id.clone(), web);
    state.profiles.insert(dev.id.clone(), dev);

    let compiled = compile(&state, &CompileOptions::default()).expect("compile");

    let inbound_tags: Vec<&String> = compiled.config.inbounds.iter().map(|i| &i.tag).collect();
    assert!(inbound_tags.contains(&&"inbound/profile/web/socks".to_owned()));
    assert!(inbound_tags.contains(&&"inbound/profile/web/http".to_owned()));
    assert!(inbound_tags.contains(&&"inbound/profile/development/socks".to_owned()));

    let routing = compiled.config.routing.as_ref().expect("routing");
    let web_rule = routing
        .rules
        .iter()
        .find(|r| r.rule_tag.as_deref() == Some("rule/profile/web/inbound"))
        .expect("web inbound rule");
    assert_eq!(
        web_rule.balancer_tag.as_deref(),
        Some("profile/web/selector")
    );
    assert_eq!(
        web_rule.inbound_tag,
        vec!["inbound/profile/web/socks", "inbound/profile/web/http"]
    );

    assert_eq!(
        compiled.listeners[&ProfileId::new("web").expect("valid")].socks,
        Some("127.0.0.1:11080".parse().expect("addr"))
    );
}

#[test]
fn socks_inbound_enables_udp_for_remote_dns() {
    let mut state = base_state();
    let mut web = profile("web", Target::Direct);
    web.socks = Some(ListenerSpec::loopback(11080));
    state.profiles.insert(web.id.clone(), web);
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    let inbound = compiled
        .config
        .inbounds
        .iter()
        .find(|i| i.tag == "inbound/profile/web/socks")
        .expect("socks inbound");
    let settings = inbound.settings.as_ref().expect("settings");
    assert_eq!(settings["udp"], serde_json::json!(true));
    assert_eq!(settings["auth"], serde_json::json!("noauth"));
}

#[test]
fn groups_compile_through_a_loopback_second_stage() {
    let mut state = base_state();
    let group_id = GroupId::new("auto-hk").expect("valid");
    state.groups.insert(
        group_id.clone(),
        Group {
            id: group_id.clone(),
            name: "Auto HK".into(),
            strategy: GroupStrategy::LeastPing,
            membership: GroupMembership {
                include_regex: vec!["^HK".into()],
                ..Default::default()
            },
            manual_selection: None,
            fallback: None,
        },
    );
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile(
            "web",
            Target::Group {
                id: group_id.clone(),
            },
        ),
    );

    let compiled = compile(&state, &CompileOptions::default()).expect("compile");

    // 1. The profile selector targets the group entry, not the balancer.
    assert_eq!(
        find_balancer(&compiled, "profile/web/selector").selector,
        vec!["group/auto-hk/entry"]
    );

    // 2. The entry is a loopback outbound re-injecting with its own inbound tag.
    let entry = find_outbound(&compiled, "group/auto-hk/entry");
    assert_eq!(entry.protocol, "loopback");
    assert_eq!(
        entry.settings.as_ref().expect("settings")["inboundTag"],
        serde_json::json!("group/auto-hk/entry")
    );

    // 3. A rule catches that inbound tag and dispatches to the group balancer.
    let routing = compiled.config.routing.as_ref().expect("routing");
    let stage2 = routing
        .rules
        .iter()
        .find(|r| r.rule_tag.as_deref() == Some("rule/group/auto-hk/stage2"))
        .expect("stage 2 rule");
    assert_eq!(stage2.inbound_tag, vec!["group/auto-hk/entry"]);
    assert_eq!(
        stage2.balancer_tag.as_deref(),
        Some("group/auto-hk/balancer")
    );

    // 4. The balancer's candidates are the matching members.
    let balancer = find_balancer(&compiled, "group/auto-hk/balancer");
    assert_eq!(balancer.selector, vec!["node/hk-01/out", "node/hk-02/out"]);
    assert_eq!(
        balancer.strategy.as_ref().expect("strategy").strategy_type,
        "leastPing"
    );

    // 5. leastPing needs liveness data, so an observatory is emitted.
    let observatory = compiled.config.observatory.as_ref().expect("observatory");
    assert_eq!(
        observatory.subject_selector,
        vec!["node/hk-01/out", "node/hk-02/out"]
    );
}

#[test]
fn empty_group_blocks_rather_than_failing_the_whole_config() {
    let mut state = base_state();
    let group_id = GroupId::new("empty").expect("valid");
    state.groups.insert(
        group_id.clone(),
        Group {
            id: group_id.clone(),
            name: "Empty".into(),
            strategy: GroupStrategy::Random,
            membership: GroupMembership {
                include_regex: vec!["^NOTHING".into()],
                ..Default::default()
            },
            manual_selection: None,
            fallback: None,
        },
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    assert_eq!(
        find_balancer(&compiled, "group/empty/balancer").selector,
        vec!["control/block"]
    );
    assert!(
        compiled.warnings.iter().any(|w| w.contains("group.empty")),
        "{:?}",
        compiled.warnings
    );
}

#[test]
fn chains_link_hops_with_dialer_proxy_in_traffic_order() {
    let mut state = base_state();
    let chain_id = ChainId::new("hk-us").expect("valid");
    state.chains.insert(
        chain_id.clone(),
        Chain {
            id: chain_id.clone(),
            name: "HK to US".into(),
            hops: vec![
                NodeId::new("hk-01").expect("valid"),
                NodeId::new("us-01").expect("valid"),
            ],
            enabled: true,
        },
    );
    state.profiles.insert(
        ProfileId::new("chat").expect("valid"),
        profile("chat", Target::Chain { id: chain_id }),
    );

    let compiled = compile(&state, &CompileOptions::default()).expect("compile");

    // Local -> HK -> US -> Internet.
    let hop0 = find_outbound(&compiled, "chain/hk-us/hop0");
    let terminal = find_outbound(&compiled, "chain/hk-us/terminal");

    // The first hop dials directly.
    assert!(
        hop0.stream_settings
            .as_ref()
            .and_then(|s| s.sockopt.as_ref())
            .and_then(|s| s.dialer_proxy.as_ref())
            .is_none()
    );
    // The terminal dials through the first hop.
    assert_eq!(
        terminal
            .stream_settings
            .as_ref()
            .and_then(|s| s.sockopt.as_ref())
            .and_then(|s| s.dialer_proxy.as_deref()),
        Some("chain/hk-us/hop0")
    );
    // Routing points at the terminal, i.e. the exit.
    assert_eq!(
        find_balancer(&compiled, "profile/chat/selector").selector,
        vec!["chain/hk-us/terminal"]
    );
    // Hop outbounds are clones: the original node definition is untouched.
    assert_eq!(
        find_outbound(&compiled, "node/hk-01/out").tag,
        "node/hk-01/out"
    );
}

#[test]
fn three_hop_chain_links_backwards_from_the_terminal() {
    let mut state = base_state();
    let chain_id = ChainId::new("abc").expect("valid");
    state.chains.insert(
        chain_id.clone(),
        Chain {
            id: chain_id.clone(),
            name: "A B C".into(),
            hops: vec![
                NodeId::new("hk-01").expect("valid"),
                NodeId::new("jp-02").expect("valid"),
                NodeId::new("us-01").expect("valid"),
            ],
            enabled: true,
        },
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    let dialer = |tag: &str| {
        find_outbound(&compiled, tag)
            .stream_settings
            .as_ref()
            .and_then(|s| s.sockopt.as_ref())
            .and_then(|s| s.dialer_proxy.clone())
    };
    assert_eq!(dialer("chain/abc/hop0"), None);
    assert_eq!(dialer("chain/abc/hop1").as_deref(), Some("chain/abc/hop0"));
    assert_eq!(
        dialer("chain/abc/terminal").as_deref(),
        Some("chain/abc/hop1")
    );
}

#[test]
fn application_rules_compile_to_the_process_matcher() {
    let mut state = base_state();
    state.profiles.insert(
        ProfileId::new("development").expect("valid"),
        profile(
            "development",
            Target::Node {
                id: NodeId::new("jp-02").expect("valid"),
            },
        ),
    );
    let rule_id = AppRuleId::new("rust-development").expect("valid");
    state.app_rules.insert(
        rule_id.clone(),
        ApplicationRule {
            id: rule_id,
            priority: 110,
            process: vec![
                AppMatcher("cargo".into()),
                AppMatcher("/usr/bin/rustc".into()),
                AppMatcher("/opt/rust/".into()),
            ],
            action: RuleAction::Profile {
                id: ProfileId::new("development").expect("valid"),
            },
            enabled: true,
            note: None,
        },
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    let routing = compiled.config.routing.as_ref().expect("routing");
    let rule = routing
        .rules
        .iter()
        .find(|r| r.rule_tag.as_deref() == Some("rule/app/rust-development"))
        .expect("app rule");
    assert_eq!(rule.process, vec!["cargo", "/usr/bin/rustc", "/opt/rust/"]);
    assert_eq!(
        rule.balancer_tag.as_deref(),
        Some("profile/development/selector")
    );
}

#[test]
fn generated_rule_order_puts_safety_first_and_catch_all_last() {
    let mut state = base_state();
    state.mode = SystemMode::Rule;
    state.default_profile = Some(ProfileId::new("web").expect("valid"));
    let mut web = profile(
        "web",
        Target::Node {
            id: NodeId::new("hk-01").expect("valid"),
        },
    );
    web.socks = Some(ListenerSpec::loopback(11080));
    state.profiles.insert(web.id.clone(), web);

    let block_id = xraytui_domain::RoutingRuleId::new("ads").expect("valid");
    state.routing_rules.insert(
        block_id.clone(),
        xraytui_domain::RoutingRule {
            id: block_id,
            priority: 500,
            matcher: RoutingMatch {
                domain: vec!["geosite:category-ads".into()],
                ..Default::default()
            },
            action: RuleAction::Target {
                target: Target::Block,
            },
            enabled: true,
            note: None,
        },
    );
    let proxy_id = xraytui_domain::RoutingRuleId::new("cn-direct").expect("valid");
    state.routing_rules.insert(
        proxy_id.clone(),
        xraytui_domain::RoutingRule {
            id: proxy_id,
            priority: 900,
            matcher: RoutingMatch {
                ip: vec!["geoip:cn".into()],
                ..Default::default()
            },
            action: RuleAction::Target {
                target: Target::Direct,
            },
            enabled: true,
            note: None,
        },
    );

    let mut options = CompileOptions {
        tun: Some(TunOptions {
            name: "xraytui0".into(),
            mtu: 1500,
        }),
        ..Default::default()
    };
    options.dns.enabled = true;
    let compiled = compile(&state, &options).expect("compile");

    let order = rule_tags(&compiled);
    let index = |tag: &str| {
        order
            .iter()
            .position(|t| t == tag)
            .unwrap_or_else(|| panic!("{tag} missing: {order:?}"))
    };

    assert_eq!(
        order.first().map(String::as_str),
        Some("rule/system/core-bypass")
    );
    assert!(index("rule/system/dns-intercept") < index("rule/profile/web/inbound"));
    assert!(index("rule/profile/web/inbound") < index("rule/system/private-direct"));
    assert!(index("rule/system/private-direct") < index("rule/user/ads"));
    assert!(index("rule/user/ads") < index("rule/user/cn-direct"));
    assert_eq!(
        order.last().map(String::as_str),
        Some("rule/system/mode-fallback")
    );

    // The catch-all must actually be a catch-all with a target. Upstream refuses
    // a rule with zero conditions, so the broadest legal condition stands in.
    let routing = compiled.config.routing.as_ref().expect("routing");
    let last = routing.rules.last().expect("rules");
    assert_eq!(last.network.as_deref(), Some("tcp,udp"));
    assert!(last.domain.is_empty() && last.ip.is_empty() && last.process.is_empty());
    assert!(last.has_target());
    assert_eq!(last.balancer_tag.as_deref(), Some("profile/web/selector"));
}

#[test]
fn block_rules_are_emitted_before_proxy_rules_regardless_of_priority() {
    let mut state = base_state();
    let low_priority_block = xraytui_domain::RoutingRuleId::new("late-block").expect("valid");
    state.routing_rules.insert(
        low_priority_block.clone(),
        xraytui_domain::RoutingRule {
            id: low_priority_block,
            priority: 9000,
            matcher: RoutingMatch {
                domain: vec!["bad.example".into()],
                ..Default::default()
            },
            action: RuleAction::Target {
                target: Target::Block,
            },
            enabled: true,
            note: None,
        },
    );
    let early_proxy = xraytui_domain::RoutingRuleId::new("early-proxy").expect("valid");
    state.routing_rules.insert(
        early_proxy.clone(),
        xraytui_domain::RoutingRule {
            id: early_proxy,
            priority: 10,
            matcher: RoutingMatch {
                domain: vec!["example".into()],
                ..Default::default()
            },
            action: RuleAction::Target {
                target: Target::Direct,
            },
            enabled: true,
            note: None,
        },
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    let order = rule_tags(&compiled);
    let block = order
        .iter()
        .position(|t| t == "rule/user/late-block")
        .expect("block rule");
    let proxy = order
        .iter()
        .position(|t| t == "rule/user/early-proxy")
        .expect("proxy rule");
    assert!(block < proxy, "{order:?}");
}

#[test]
fn modes_change_only_the_fallback_rule() {
    let mut state = base_state();
    state.default_profile = Some(ProfileId::new("web").expect("valid"));
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile(
            "web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        ),
    );

    let mut fallback_of = |mode: SystemMode| {
        state.mode = mode;
        let compiled = compile(&state, &CompileOptions::default()).expect("compile");
        let routing = compiled.config.routing.as_ref().expect("routing");
        let last = routing.rules.last().expect("rules").clone();
        (last.outbound_tag, last.balancer_tag)
    };

    assert_eq!(
        fallback_of(SystemMode::Direct),
        (Some("control/direct".into()), None)
    );
    assert_eq!(
        fallback_of(SystemMode::Off),
        (Some("control/direct".into()), None)
    );
    assert_eq!(
        fallback_of(SystemMode::Global),
        (None, Some("profile/web/selector".into()))
    );
    assert_eq!(
        fallback_of(SystemMode::Rule),
        (None, Some("profile/web/selector".into()))
    );
}

#[test]
fn kill_switch_controls_the_balancer_fallback() {
    let mut state = base_state();
    let make = |kill_switch: KillSwitch, fallback: Option<Target>| {
        let mut p = profile(
            "web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        );
        p.kill_switch = kill_switch;
        p.fallback = fallback;
        p
    };

    for (kill_switch, fallback, expected) in [
        // The common case emits no fallbackTag at all, which is what keeps the
        // default configuration free of active liveness probing.
        (KillSwitch::Off, None, None),
        (KillSwitch::Block, None, Some("control/block")),
        (KillSwitch::FallbackOnly, None, Some("control/block")),
        (
            KillSwitch::FallbackOnly,
            Some(Target::Node {
                id: NodeId::new("us-01").expect("valid"),
            }),
            Some("node/us-01/out"),
        ),
    ] {
        let p = make(kill_switch, fallback);
        state.profiles.insert(p.id.clone(), p);
        let compiled = compile(&state, &CompileOptions::default()).expect("compile");
        assert_eq!(
            find_balancer(&compiled, "profile/web/selector")
                .fallback_tag
                .as_deref(),
            expected,
            "kill switch {kill_switch:?}"
        );
        // A fallbackTag without liveness observation makes the core refuse to
        // start, so the two must always appear together.
        assert_eq!(
            expected.is_some(),
            compiled.config.observatory.is_some(),
            "kill switch {kill_switch:?}: fallbackTag and observatory must agree"
        );
    }
}

#[test]
fn default_configuration_emits_no_observatory() {
    let mut state = base_state();
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile(
            "web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        ),
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    assert!(compiled.config.observatory.is_none());
    assert!(compiled.config.burst_observatory.is_none());
}

#[test]
fn least_load_uses_the_burst_observatory() {
    let mut state = base_state();
    let group_id = GroupId::new("g").expect("valid");
    state.groups.insert(
        group_id.clone(),
        Group {
            id: group_id.clone(),
            name: "G".into(),
            strategy: GroupStrategy::LeastLoad,
            membership: GroupMembership {
                nodes: vec![NodeId::new("hk-01").expect("valid")],
                ..Default::default()
            },
            manual_selection: None,
            fallback: None,
        },
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    assert!(compiled.config.burst_observatory.is_some());
    assert!(compiled.config.observatory.is_none());
}

#[test]
fn tun_inbound_has_no_port_and_carries_the_interface_name() {
    let mut state = base_state();
    state.mode = SystemMode::Rule;
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile("web", Target::Direct),
    );
    state.default_profile = Some(ProfileId::new("web").expect("valid"));
    let options = CompileOptions {
        tun: Some(TunOptions {
            name: "xraytui0".into(),
            mtu: 1420,
        }),
        ..Default::default()
    };
    let compiled = compile(&state, &options).expect("compile");
    let tun = compiled
        .config
        .inbounds
        .iter()
        .find(|i| i.tag == "inbound/system/tun")
        .expect("tun inbound");
    assert_eq!(tun.protocol, "tun");
    assert_eq!(tun.port, None);
    assert_eq!(tun.listen, None);
    let settings = tun.settings.as_ref().expect("settings");
    assert_eq!(settings["name"], serde_json::json!("xraytui0"));
    assert_eq!(settings["MTU"], serde_json::json!(1420));
}

#[test]
fn output_is_byte_stable_across_compilations() {
    let mut state = base_state();
    for (id, target) in [
        (
            "web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        ),
        (
            "development",
            Target::Node {
                id: NodeId::new("jp-02").expect("valid"),
            },
        ),
    ] {
        let mut p = profile(id, target);
        p.socks = Some(ListenerSpec::loopback(if id == "web" {
            11080
        } else {
            12080
        }));
        state.profiles.insert(p.id.clone(), p);
    }
    let a = compile(&state, &CompileOptions::default())
        .expect("compile")
        .to_json()
        .expect("json");
    let b = compile(&state, &CompileOptions::default())
        .expect("compile")
        .to_json()
        .expect("json");
    assert_eq!(a, b);
    // And stable across a clone that reorders insertion.
    let mut reordered = DesiredState {
        mode: state.mode,
        default_profile: state.default_profile.clone(),
        ..Default::default()
    };
    for (id, node) in state.nodes.iter().rev() {
        reordered.nodes.insert(id.clone(), node.clone());
    }
    for (id, p) in state.profiles.iter().rev() {
        reordered.profiles.insert(id.clone(), p.clone());
    }
    let c = compile(&reordered, &CompileOptions::default())
        .expect("compile")
        .to_json()
        .expect("json");
    assert_eq!(a, c);
}

#[test]
fn invalid_state_is_refused_with_the_diagnostic_codes() {
    let mut state = DesiredState::default();
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile(
            "web",
            Target::Node {
                id: NodeId::new("missing").expect("valid"),
            },
        ),
    );
    let err = compile(&state, &CompileOptions::default()).expect_err("must refuse");
    match err {
        CompileError::Invalid(message) => {
            assert!(message.contains("target.unknown-node"), "{message}");
        }
        other => panic!("unexpected error {other:?}"),
    }
}

#[test]
fn tag_round_trip_holds_for_every_target_kind() {
    let targets = [
        Target::Node {
            id: NodeId::new("hk-01").expect("valid"),
        },
        Target::Chain {
            id: ChainId::new("hk-us").expect("valid"),
        },
        Target::Group {
            id: GroupId::new("auto").expect("valid"),
        },
        Target::Direct,
        Target::Block,
    ];
    for target in targets {
        let tag = tag_for_target(&target);
        assert_eq!(target_for_tag(&tag), Some(target.clone()), "tag {tag}");
    }
    assert_eq!(target_for_tag("chain/hk-us/hop0"), None);
    assert_eq!(
        profile_of_selector("profile/web/selector").map(|p| p.to_string()),
        Some("web".into())
    );
    assert_eq!(profile_of_selector("node/x/out"), None);
}

#[test]
fn owned_tags_cover_everything_the_generation_created() {
    let mut state = base_state();
    let group_id = GroupId::new("g").expect("valid");
    state.groups.insert(
        group_id.clone(),
        Group {
            id: group_id.clone(),
            name: "G".into(),
            strategy: GroupStrategy::Random,
            membership: GroupMembership {
                nodes: vec![NodeId::new("hk-01").expect("valid")],
                ..Default::default()
            },
            manual_selection: None,
            fallback: None,
        },
    );
    let mut p = profile("web", Target::Group { id: group_id });
    p.socks = Some(ListenerSpec::loopback(11080));
    state.profiles.insert(p.id.clone(), p);

    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    for outbound in &compiled.config.outbounds {
        assert!(
            compiled.owned_tags.contains(&outbound.tag),
            "{} not owned",
            outbound.tag
        );
    }
    for inbound in &compiled.config.inbounds {
        assert!(
            compiled.owned_tags.contains(&inbound.tag),
            "{} not owned",
            inbound.tag
        );
    }
    for balancer in &compiled.config.routing.as_ref().expect("routing").balancers {
        assert!(
            compiled.owned_tags.contains(&balancer.tag),
            "{} not owned",
            balancer.tag
        );
    }
}

#[test]
fn manual_group_selection_becomes_a_runtime_override() {
    let mut state = base_state();
    let group_id = GroupId::new("manual").expect("valid");
    state.groups.insert(
        group_id.clone(),
        Group {
            id: group_id.clone(),
            name: "Manual".into(),
            strategy: GroupStrategy::Manual,
            membership: GroupMembership {
                nodes: vec![
                    NodeId::new("hk-01").expect("valid"),
                    NodeId::new("hk-02").expect("valid"),
                ],
                ..Default::default()
            },
            manual_selection: Some(Target::Node {
                id: NodeId::new("hk-02").expect("valid"),
            }),
            fallback: None,
        },
    );
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    assert!(
        compiled
            .selector_overrides
            .contains(&("group/manual/balancer".into(), "node/hk-02/out".into())),
        "{:?}",
        compiled.selector_overrides
    );
}

#[test]
fn disabled_profiles_and_nodes_are_omitted() {
    let mut state = base_state();
    state
        .nodes
        .get_mut(&NodeId::new("us-01").expect("valid"))
        .expect("node")
        .enabled = false;
    let mut disabled = profile("off", Target::Direct);
    disabled.enabled = false;
    state.profiles.insert(disabled.id.clone(), disabled);
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile("web", Target::Direct),
    );

    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    assert!(
        compiled
            .config
            .outbounds
            .iter()
            .all(|o| o.tag != "node/us-01/out")
    );
    assert!(
        compiled
            .config
            .routing
            .as_ref()
            .expect("routing")
            .balancers
            .iter()
            .all(|b| b.tag != "profile/off/selector")
    );
}

#[test]
fn dns_configuration_intercepts_port_53_and_tags_its_own_queries() {
    let mut state = base_state();
    state.profiles.insert(
        ProfileId::new("web").expect("valid"),
        profile("web", Target::Direct),
    );
    let options = CompileOptions {
        tun: Some(TunOptions {
            name: "xraytui0".into(),
            mtu: 1500,
        }),
        dns: DnsOptions {
            enabled: true,
            direct_servers: vec!["127.0.0.53".into()],
            proxy_servers: vec!["https://1.1.1.1/dns-query".into()],
            direct_domains: vec!["geosite:private".into()],
            listen: Some("127.0.0.1:15353".parse().expect("addr")),
            ..Default::default()
        },
        ..Default::default()
    };
    let compiled = compile(&state, &options).expect("compile");

    let dns = compiled.config.dns.as_ref().expect("dns block");
    assert_eq!(dns.tag.as_deref(), Some("inbound/system/dns-query"));
    assert!(dns.servers.len() >= 3);

    let routing = compiled.config.routing.as_ref().expect("routing");
    let intercept = routing
        .rules
        .iter()
        .find(|r| r.rule_tag.as_deref() == Some("rule/system/dns-intercept"))
        .expect("dns intercept rule");
    assert_eq!(intercept.port.as_deref(), Some("53"));
    assert_eq!(intercept.outbound_tag.as_deref(), Some("control/dns"));
    assert!(
        intercept
            .inbound_tag
            .contains(&"inbound/system/tun".to_owned())
    );

    assert!(
        compiled
            .config
            .outbounds
            .iter()
            .any(|o| o.tag == "control/dns")
    );
}

#[test]
fn core_bypass_rule_uses_the_upstream_self_matcher() {
    let state = base_state();
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    let routing = compiled.config.routing.as_ref().expect("routing");
    let bypass = routing
        .rules
        .iter()
        .find(|r| r.rule_tag.as_deref() == Some("rule/system/core-bypass"))
        .expect("core bypass rule");
    // `self/` is the exact token upstream's NewProcessNameMatcher recognises for
    // "the Xray process itself".
    assert_eq!(bypass.process, vec!["self/"]);
    assert_eq!(bypass.outbound_tag.as_deref(), Some("control/direct"));
}

#[test]
fn every_generated_rule_has_exactly_one_target() {
    let mut state = base_state();
    state.mode = SystemMode::Rule;
    state.default_profile = Some(ProfileId::new("web").expect("valid"));
    let mut web = profile("web", Target::Direct);
    web.socks = Some(ListenerSpec::loopback(11080));
    state.profiles.insert(web.id.clone(), web);
    let group_id = GroupId::new("g").expect("valid");
    state.groups.insert(
        group_id.clone(),
        Group {
            id: group_id,
            name: "G".into(),
            strategy: GroupStrategy::Random,
            membership: GroupMembership {
                nodes: vec![NodeId::new("hk-01").expect("valid")],
                ..Default::default()
            },
            manual_selection: None,
            fallback: None,
        },
    );
    let options = CompileOptions {
        tun: Some(TunOptions {
            name: "xraytui0".into(),
            mtu: 1500,
        }),
        dns: DnsOptions {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let compiled = compile(&state, &options).expect("compile");
    for rule in &compiled.config.routing.as_ref().expect("routing").rules {
        assert!(
            rule.has_target(),
            "rule {:?} has no unique target",
            rule.rule_tag
        );
        assert_eq!(rule.rule_type, "field");
        assert!(rule.rule_tag.is_some());
    }
}

// --- transparent listeners (acceptance scenario M) -------------------------

fn state_with_a_transparent_profile() -> DesiredState {
    let mut state = base_state();
    let mut profile = EgressProfile::new(
        ProfileId::new("work").expect("valid"),
        "Work",
        Target::Node {
            id: NodeId::new("hk-01").expect("valid"),
        },
    );
    profile.transparent = Some(ListenerSpec::loopback(19_007));
    state.profiles.insert(profile.id.clone(), profile);
    state
}

#[test]
fn a_transparent_profile_gets_a_dokodemo_inbound_that_asks_for_a_transparent_socket() {
    let compiled = compile(
        &state_with_a_transparent_profile(),
        &CompileOptions::default(),
    )
    .expect("compile");
    let inbound = compiled
        .config
        .inbounds
        .iter()
        .find(|inbound| inbound.tag == "inbound/profile/work/transparent")
        .expect("a transparent inbound");

    assert_eq!(inbound.protocol, "dokodemo-door");
    assert_eq!(inbound.listen.as_deref(), Some("127.0.0.1"));
    assert_eq!(inbound.port, Some(19_007));
    let settings = inbound.settings.as_ref().expect("settings");
    // Without `followRedirect` the inbound forwards everything to one fixed
    // address; it is what makes the original destination be used.
    assert_eq!(settings["followRedirect"], serde_json::json!(true));
    assert_eq!(settings["network"], serde_json::json!("tcp,udp"));
    // And without the socket option the kernel refuses to complete a handshake
    // for a connection addressed elsewhere. Proven in the namespace suite.
    let sockopt = inbound
        .stream_settings
        .as_ref()
        .and_then(|stream| stream.sockopt.as_ref())
        .expect("sockopt");
    assert_eq!(sockopt.tproxy.as_deref(), Some("tproxy"));

    assert_eq!(
        compiled.listeners[&ProfileId::new("work").expect("valid")].transparent,
        Some("127.0.0.1:19007".parse().expect("address")),
        "the daemon learns the redirect port from here, so it must be recorded"
    );
    assert!(
        compiled
            .owned_tags
            .contains("inbound/profile/work/transparent")
    );
}

#[test]
fn traffic_from_a_transparent_inbound_reaches_that_profiles_own_selector() {
    // This is the mapping acceptance scenario M depends on: one inbound tag,
    // one selector, no sharing.
    let compiled = compile(
        &state_with_a_transparent_profile(),
        &CompileOptions::default(),
    )
    .expect("compile");
    let rules = &compiled.config.routing.as_ref().expect("routing").rules;
    let rule = rules
        .iter()
        .find(|rule| rule.rule_tag.as_deref() == Some("rule/profile/work/inbound"))
        .expect("the profile rule");
    assert!(
        rule.inbound_tag
            .contains(&"inbound/profile/work/transparent".to_owned())
    );
    assert_eq!(rule.balancer_tag.as_deref(), Some("profile/work/selector"));

    // And no other rule may claim that inbound tag for a different target.
    let claimants: Vec<&str> = rules
        .iter()
        .filter(|rule| {
            rule.inbound_tag
                .iter()
                .any(|tag| tag == "inbound/profile/work/transparent")
        })
        .filter_map(|rule| rule.balancer_tag.as_deref())
        .collect();
    assert_eq!(claimants, vec!["profile/work/selector"]);
}

#[test]
fn every_transparent_inbound_maps_to_exactly_one_selector() {
    let mut state = state_with_a_transparent_profile();
    let mut second = EgressProfile::new(
        ProfileId::new("media").expect("valid"),
        "Media",
        Target::Node {
            id: NodeId::new("jp-02").expect("valid"),
        },
    );
    second.transparent = Some(ListenerSpec::loopback(19_008));
    state.profiles.insert(second.id.clone(), second);

    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    let rules = &compiled.config.routing.as_ref().expect("routing").rules;
    for id in ["work", "media"] {
        let tag = format!("inbound/profile/{id}/transparent");
        let targets: Vec<&str> = rules
            .iter()
            .filter(|rule| rule.inbound_tag.contains(&tag))
            .filter_map(|rule| rule.balancer_tag.as_deref())
            .collect();
        assert_eq!(
            targets,
            vec![format!("profile/{id}/selector").as_str()],
            "{tag} must reach exactly its own selector"
        );
    }
}

#[test]
fn a_profile_without_a_transparent_listener_gets_no_transparent_inbound() {
    let mut state = state_with_a_transparent_profile();
    state
        .profiles
        .get_mut(&ProfileId::new("work").expect("valid"))
        .expect("the profile")
        .transparent = None;
    let compiled = compile(&state, &CompileOptions::default()).expect("compile");
    assert!(
        !compiled
            .config
            .inbounds
            .iter()
            .any(|inbound| inbound.tag.ends_with("/transparent"))
    );
    assert!(
        !compiled
            .owned_tags
            .iter()
            .any(|tag| tag.ends_with("/transparent"))
    );
}

#[test]
fn private_space_bypasses_a_transparent_profile_before_the_profile_can_claim_it() {
    // Order is the whole point: the profile rule matches by inbound tag alone,
    // so a bypass placed after it would never be reached.
    let compiled = compile(
        &state_with_a_transparent_profile(),
        &CompileOptions::default(),
    )
    .expect("compile");
    let rules = &compiled.config.routing.as_ref().expect("routing").rules;
    let bypass = rules
        .iter()
        .position(|rule| rule.rule_tag.as_deref() == Some("rule/system/transparent-private-direct"))
        .expect("the transparent private bypass");
    let profile = rules
        .iter()
        .position(|rule| rule.rule_tag.as_deref() == Some("rule/profile/work/inbound"))
        .expect("the profile rule");
    assert!(bypass < profile, "the bypass must come first");
    assert_eq!(
        rules[bypass].outbound_tag.as_deref(),
        Some(tags::CONTROL_DIRECT)
    );
    assert_eq!(rules[bypass].ip, vec!["geoip:private".to_owned()]);
    // It applies only to traffic that never opted in.
    assert_eq!(
        rules[bypass].inbound_tag,
        vec!["inbound/profile/work/transparent".to_owned()]
    );
}

#[test]
fn the_private_bypass_is_absent_when_the_user_turned_it_off() {
    let options = CompileOptions {
        bypass_private_networks: false,
        ..Default::default()
    };
    let compiled = compile(&state_with_a_transparent_profile(), &options).expect("compile");
    assert!(
        !compiled
            .config
            .routing
            .as_ref()
            .expect("routing")
            .rules
            .iter()
            .any(|rule| rule.rule_tag.as_deref() == Some("rule/system/transparent-private-direct"))
    );
}

#[test]
fn a_transparent_inbound_has_its_dns_intercepted_like_the_tunnel() {
    // The redirect is by mark, not by port, so port 53 arrives here too. Left
    // alone it would be forwarded to whatever the application thought its
    // resolver was, which is exactly the leak the DNS module exists to close.
    let options = CompileOptions {
        dns: DnsOptions {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let compiled = compile(&state_with_a_transparent_profile(), &options).expect("compile");
    let rule = compiled
        .config
        .routing
        .as_ref()
        .expect("routing")
        .rules
        .iter()
        .find(|rule| rule.rule_tag.as_deref() == Some("rule/system/dns-intercept"))
        .expect("the dns intercept rule");
    assert!(
        rule.inbound_tag
            .contains(&"inbound/profile/work/transparent".to_owned()),
        "{:?}",
        rule.inbound_tag
    );
}
