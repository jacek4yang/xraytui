//! Translation of a [`Node`] into an Xray outbound object.
//!
//! Kept separate from the routing compiler because it is the part that tracks
//! upstream's protocol JSON most closely and therefore changes most often.

use serde_json::{Map, Value, json};
use xraytui_domain::{
    MuxSettings, Node, ProtocolSettings, RealitySettings, SocketSettings, TlsSettings, Transport,
    TransportSecurity,
};
use xraytui_secrets::Secret;
use xraytui_xray_model::{MuxConfig, Outbound, SockOpt, StreamSettings};

use crate::{CompileError, MkcpFinalmaskDialect};

/// Build the outbound object for a node under the given tag.
///
/// `dialer_proxy` sets `streamSettings.sockopt.dialerProxy`, which is how chain
/// hops are linked. It is applied even when the node itself declared no socket
/// options.
///
/// # Errors
/// Returns [`CompileError::UnsupportedNode`] when the node cannot be represented.
pub fn build(node: &Node, tag: &str, dialer_proxy: Option<&str>) -> Result<Outbound, CompileError> {
    build_with_dialect(node, tag, dialer_proxy, MkcpFinalmaskDialect::default())
}

/// Build an outbound using the final-mask dialect accepted by the selected
/// Xray binary.
///
/// # Errors
/// Returns [`CompileError::UnsupportedNode`] when the node cannot be represented.
pub fn build_with_dialect(
    node: &Node,
    tag: &str,
    dialer_proxy: Option<&str>,
    mkcp_dialect: MkcpFinalmaskDialect,
) -> Result<Outbound, CompileError> {
    build_with_dialect_and_domain_strategy(node, tag, dialer_proxy, mkcp_dialect, None)
}

/// Build an outbound while overriding only its endpoint-resolution strategy.
///
/// This is reserved for compiler-proven bootstrap dials. It does not mutate the
/// node model and must never be applied to later chain hops, whose hostname may
/// intentionally be resolved by the preceding proxy.
pub(crate) fn build_with_dialect_and_domain_strategy(
    node: &Node,
    tag: &str,
    dialer_proxy: Option<&str>,
    mkcp_dialect: MkcpFinalmaskDialect,
    domain_strategy: Option<&str>,
) -> Result<Outbound, CompileError> {
    if !node.is_compilable() {
        return Err(CompileError::UnsupportedNode {
            node: node.id.to_string(),
            reason: if node.enabled {
                "protocol is not supported by the configured Xray release".into()
            } else {
                "node is disabled".into()
            },
        });
    }

    let settings = protocol_settings(node, domain_strategy)?;
    let stream = if node.protocol.accepts_stream_settings() {
        Some(stream_settings(
            node,
            dialer_proxy,
            mkcp_dialect,
            domain_strategy,
        )?)
    } else if dialer_proxy.is_some() {
        // WireGuard carries its own transport, so there is nowhere
        // to hang a dialerProxy. Refusing is better than emitting a config that
        // silently ignores the chain hop.
        return Err(CompileError::UnsupportedNode {
            node: node.id.to_string(),
            reason: format!(
                "{} cannot be used as a chain hop because it does not accept stream settings",
                node.protocol.xray_protocol()
            ),
        });
    } else {
        None
    };

    Ok(Outbound {
        tag: tag.to_owned(),
        protocol: node.protocol.xray_protocol().to_owned(),
        settings: Some(settings),
        stream_settings: stream,
        mux: mux_config(&node.mux),
        send_through: None,
    })
}

fn protocol_settings(node: &Node, domain_strategy: Option<&str>) -> Result<Value, CompileError> {
    let address = node.endpoint.address.clone();
    let port = node.endpoint.port;

    let value = match &node.protocol {
        ProtocolSettings::Vless(v) => {
            let mut user = Map::new();
            user.insert("id".into(), json!(v.id.expose()));
            user.insert("encryption".into(), json!(v.encryption));
            if !v.flow.is_empty() {
                user.insert("flow".into(), json!(v.flow));
            }
            if let Some(level) = v.level {
                user.insert("level".into(), json!(level));
            }
            json!({ "vnext": [{ "address": address, "port": port, "users": [Value::Object(user)] }] })
        }
        ProtocolSettings::Vmess(v) => {
            if v.alter_id != 0 {
                return Err(CompileError::UnsupportedNode {
                    node: node.id.to_string(),
                    reason: format!(
                        "VMess alterId {} is not supported by modern Xray; use alterId 0 (VMessAEAD)",
                        v.alter_id
                    ),
                });
            }
            let mut user = Map::new();
            user.insert("id".into(), json!(v.id.expose()));
            user.insert("security".into(), json!(v.security));
            if let Some(level) = v.level {
                user.insert("level".into(), json!(level));
            }
            json!({ "vnext": [{ "address": address, "port": port, "users": [Value::Object(user)] }] })
        }
        ProtocolSettings::Trojan(t) => {
            let mut server = Map::new();
            server.insert("address".into(), json!(address));
            server.insert("port".into(), json!(port));
            server.insert("password".into(), json!(t.password.expose()));
            if !t.flow.is_empty() {
                server.insert("flow".into(), json!(t.flow));
            }
            json!({ "servers": [Value::Object(server)] })
        }
        ProtocolSettings::Shadowsocks(s) => {
            let mut server = Map::new();
            server.insert("address".into(), json!(address));
            server.insert("port".into(), json!(port));
            server.insert("method".into(), json!(s.method));
            server.insert("password".into(), json!(s.password.expose()));
            if s.uot {
                server.insert("uot".into(), json!(true));
                if let Some(version) = s.uot_version {
                    server.insert("uotVersion".into(), json!(version));
                }
            }
            json!({ "servers": [Value::Object(server)] })
        }
        ProtocolSettings::Http(h) => {
            let mut server = Map::new();
            server.insert("address".into(), json!(address));
            server.insert("port".into(), json!(port));
            if let Some(user) = &h.username {
                server.insert(
                    "users".into(),
                    json!([{ "user": user, "pass": expose_or_empty(h.password.as_ref()) }]),
                );
            }
            json!({ "servers": [Value::Object(server)] })
        }
        ProtocolSettings::Socks(s) => {
            let mut server = Map::new();
            server.insert("address".into(), json!(address));
            server.insert("port".into(), json!(port));
            if let Some(user) = &s.username {
                server.insert(
                    "users".into(),
                    json!([{ "user": user, "pass": expose_or_empty(s.password.as_ref()) }]),
                );
            }
            json!({ "servers": [Value::Object(server)] })
        }
        ProtocolSettings::Wireguard(w) => {
            let peers: Vec<Value> = w
                .peers
                .iter()
                .map(|p| {
                    let mut peer = Map::new();
                    peer.insert("publicKey".into(), json!(p.public_key));
                    peer.insert("endpoint".into(), json!(p.endpoint));
                    if let Some(psk) = &p.pre_shared_key {
                        peer.insert("preSharedKey".into(), json!(psk.expose()));
                    }
                    if !p.allowed_ips.is_empty() {
                        peer.insert("allowedIPs".into(), json!(p.allowed_ips));
                    }
                    if let Some(keep_alive) = p.keep_alive {
                        peer.insert("keepAlive".into(), json!(keep_alive));
                    }
                    Value::Object(peer)
                })
                .collect();
            let mut settings = Map::new();
            settings.insert("secretKey".into(), json!(w.secret_key.expose()));
            settings.insert("address".into(), json!(w.address));
            settings.insert("peers".into(), Value::Array(peers));
            if let Some(mtu) = w.mtu {
                settings.insert("mtu".into(), json!(mtu));
            }
            if !w.reserved.is_empty() {
                settings.insert("reserved".into(), json!(w.reserved));
            }
            if let Some(strategy) = domain_strategy.or(w.domain_strategy.as_deref()) {
                settings.insert("domainStrategy".into(), json!(strategy));
            }
            Value::Object(settings)
        }
        ProtocolSettings::Hysteria(h) => {
            let _ = h;
            json!({ "version": 2, "address": address, "port": port })
        }
    };
    Ok(value)
}

/// Map a legacy mKCP `headerType` onto the current UDP mask identifier.
///
/// Returns `None` for `none`, and for values the pinned release does not
/// register, in which case only the mKCP mask itself is emitted.
fn mkcp_header_mask(header: &str) -> Option<&'static str> {
    match mkcp_legacy_header(header)? {
        "srtp" => Some("header-srtp"),
        "utp" => Some("header-utp"),
        "wechat" => Some("header-wechat"),
        "dtls" => Some("header-dtls"),
        "wireguard" => Some("header-wireguard"),
        "dns" => Some("header-dns"),
        _ => None,
    }
}

fn mkcp_legacy_header(header: &str) -> Option<&'static str> {
    match header {
        "srtp" => Some("srtp"),
        "utp" => Some("utp"),
        "wechat-video" | "wechat" => Some("wechat"),
        "dtls" => Some("dtls"),
        "wireguard" => Some("wireguard"),
        "dns" => Some("dns"),
        _ => None,
    }
}

fn expose_or_empty(secret: Option<&Secret>) -> &str {
    secret.map_or("", Secret::expose)
}

fn stream_settings(
    node: &Node,
    dialer_proxy: Option<&str>,
    mkcp_dialect: MkcpFinalmaskDialect,
    domain_strategy: Option<&str>,
) -> Result<StreamSettings, CompileError> {
    let hysteria = match &node.protocol {
        ProtocolSettings::Hysteria(settings) => Some(settings),
        _ => None,
    };
    let mut stream = StreamSettings {
        network: Some(
            if hysteria.is_some() {
                "hysteria"
            } else {
                node.transport.xray_network()
            }
            .to_owned(),
        ),
        security: Some(node.security.xray_security().to_owned()),
        ..Default::default()
    };

    if let Some(hysteria) = hysteria {
        let transport_is_default = matches!(
            &node.transport,
            Transport::Raw(raw)
                if raw.host.is_empty()
                    && raw.path.is_none()
                    && raw.header_type.as_deref().is_none_or(|header| header == "none")
        );
        if !transport_is_default {
            return Err(CompileError::UnsupportedNode {
                node: node.id.to_string(),
                reason: "Xray-native Hysteria uses its own QUIC transport and cannot combine it with another stream transport".to_owned(),
            });
        }
        if !matches!(node.security, TransportSecurity::Tls(_)) {
            return Err(CompileError::UnsupportedNode {
                node: node.id.to_string(),
                reason: "Xray-native Hysteria requires TLS security settings".to_owned(),
            });
        }
        let mut settings = Map::new();
        settings.insert("version".into(), json!(2));
        settings.insert("auth".into(), json!(hysteria.auth.expose()));
        if let Some(up) = &hysteria.up {
            settings.insert("up".into(), json!(up));
        }
        if let Some(down) = &hysteria.down {
            settings.insert("down".into(), json!(down));
        }
        stream.hysteria_settings = Some(Value::Object(settings));
        stream.finalmask = hysteria_finalmask(node, hysteria)?;
    } else {
        match &node.transport {
            Transport::Raw(raw) => {
                if raw.header_type.as_deref().is_some_and(|t| t != "none") {
                    let mut request = Map::new();
                    if let Some(path) = &raw.path {
                        request.insert("path".into(), json!([path]));
                    }
                    if !raw.host.is_empty() {
                        request.insert("headers".into(), json!({ "Host": raw.host }));
                    }
                    stream.raw_settings = Some(json!({
                        "header": { "type": raw.header_type, "request": Value::Object(request) }
                    }));
                }
            }
            Transport::Xhttp(x) => {
                let mut settings = Map::new();
                if let Some(host) = &x.host {
                    settings.insert("host".into(), json!(host));
                }
                if let Some(path) = &x.path {
                    settings.insert("path".into(), json!(path));
                }
                if let Some(mode) = &x.mode {
                    settings.insert("mode".into(), json!(mode));
                }
                if let Some(extra) = &x.extra {
                    settings.insert("extra".into(), extra.clone());
                }
                stream.xhttp_settings = Some(Value::Object(settings));
            }
            Transport::Grpc(g) => {
                let mut settings = Map::new();
                settings.insert("serviceName".into(), json!(g.service_name));
                if g.multi_mode {
                    settings.insert("multiMode".into(), json!(true));
                }
                if let Some(authority) = &g.authority {
                    settings.insert("authority".into(), json!(authority));
                }
                stream.grpc_settings = Some(Value::Object(settings));
            }
            Transport::Websocket(w) => {
                let mut settings = Map::new();
                settings.insert("path".into(), json!(w.path));
                if let Some(host) = &w.host {
                    settings.insert("host".into(), json!(host));
                }
                if !w.headers.is_empty() {
                    settings.insert("headers".into(), json!(w.headers));
                }
                stream.ws_settings = Some(Value::Object(settings));
            }
            Transport::HttpUpgrade(h) => {
                let mut settings = Map::new();
                settings.insert("path".into(), json!(h.path));
                if let Some(host) = &h.host {
                    settings.insert("host".into(), json!(host));
                }
                stream.httpupgrade_settings = Some(Value::Object(settings));
            }
            Transport::Mkcp(m) => {
                // The pinned Xray release removed `kcpSettings.header` and
                // `kcpSettings.seed` and refuses any configuration that still sets
                // them. Share links, however, still carry `headerType` and `seed`, so
                // they are translated into the replacement `finalmask` masks here.
                let mut settings = Map::new();
                if let Some(mtu) = m.mtu {
                    settings.insert("mtu".into(), json!(mtu));
                }
                if let Some(tti) = m.tti {
                    if !(10..=5000).contains(&tti) {
                        return Err(CompileError::UnsupportedNode {
                            node: node.id.to_string(),
                            reason: format!("mKCP tti {tti} is outside Xray's 10..=5000 ms range"),
                        });
                    }
                    settings.insert("tti".into(), json!(tti));
                }
                stream.kcp_settings = Some(Value::Object(settings));
                if node.finalmask.is_none() {
                    let mut masks = Vec::new();
                    if let Some(header) = m.header_type.as_deref() {
                        match mkcp_dialect {
                            MkcpFinalmaskDialect::Layered => {
                                if let Some(mask_type) = mkcp_header_mask(header) {
                                    masks.push(json!({ "type": mask_type }));
                                }
                            }
                            MkcpFinalmaskDialect::UnifiedLegacy => {
                                if let Some(header) = mkcp_legacy_header(header) {
                                    masks.push(json!({
                                        "type": "mkcp-legacy",
                                        "settings": { "header": header }
                                    }));
                                }
                            }
                        }
                    }
                    masks.push(match (mkcp_dialect, &m.seed) {
                        (MkcpFinalmaskDialect::Layered, Some(seed)) => json!({
                            "type": "mkcp-aes128gcm",
                            "settings": { "password": seed.expose() }
                        }),
                        (MkcpFinalmaskDialect::Layered, None) => {
                            json!({ "type": "mkcp-original" })
                        }
                        (MkcpFinalmaskDialect::UnifiedLegacy, Some(seed)) => json!({
                            "type": "mkcp-legacy",
                            "settings": { "value": seed.expose() }
                        }),
                        (MkcpFinalmaskDialect::UnifiedLegacy, None) => {
                            json!({ "type": "mkcp-legacy" })
                        }
                    });
                    stream.finalmask = Some(json!({ "udp": masks }));
                }
            }
        }
    }

    if hysteria.is_none()
        && let Some(finalmask) = &node.finalmask
    {
        if !finalmask.is_object() {
            return Err(CompileError::UnsupportedNode {
                node: node.id.to_string(),
                reason: "finalmask must be a JSON object".to_owned(),
            });
        }
        stream.finalmask = Some(finalmask.clone());
    }

    match &node.security {
        TransportSecurity::None => {}
        TransportSecurity::Tls(tls) => {
            stream.tls_settings = Some(tls_json(tls, node)?);
        }
        TransportSecurity::Reality(reality) => {
            stream.reality_settings = Some(reality_json(reality, node));
        }
    }

    let sockopt = sockopt_json(&node.sockopt, dialer_proxy, domain_strategy);
    if sockopt.is_some() {
        stream.sockopt = sockopt;
    }
    Ok(stream)
}

fn hysteria_finalmask(
    node: &Node,
    hysteria: &xraytui_domain::HysteriaSettings,
) -> Result<Option<Value>, CompileError> {
    let mut root = match &node.finalmask {
        Some(Value::Object(object)) => object.clone(),
        Some(_) => {
            return Err(CompileError::UnsupportedNode {
                node: node.id.to_string(),
                reason: "finalmask must be a JSON object".to_owned(),
            });
        }
        None => Map::new(),
    };

    if let Some(obfs) = &hysteria.obfs {
        let udp = root.entry("udp".to_owned()).or_insert_with(|| json!([]));
        let Some(masks) = udp.as_array_mut() else {
            return Err(CompileError::UnsupportedNode {
                node: node.id.to_string(),
                reason: "Hysteria obfuscation requires finalmask.udp to be an array".to_owned(),
            });
        };
        let salamander = masks
            .iter()
            .filter(|mask| mask.get("type").and_then(Value::as_str) == Some("salamander"))
            .collect::<Vec<_>>();
        if salamander.iter().any(|mask| {
            mask.pointer("/settings/password").and_then(Value::as_str) != Some(obfs.expose())
        }) {
            return Err(CompileError::UnsupportedNode {
                node: node.id.to_string(),
                reason:
                    "Hysteria has conflicting salamander passwords in typed settings and finalmask"
                        .to_owned(),
            });
        }
        if salamander.is_empty() {
            masks.push(json!({
                "type": "salamander",
                "settings": { "password": obfs.expose() }
            }));
        }
    }

    if let Some(ports) = &hysteria.port_hopping {
        let quic = root
            .entry("quicParams".to_owned())
            .or_insert_with(|| json!({}));
        let Some(quic) = quic.as_object_mut() else {
            return Err(CompileError::UnsupportedNode {
                node: node.id.to_string(),
                reason: "Hysteria port hopping requires finalmask.quicParams to be an object"
                    .to_owned(),
            });
        };
        let requested = ports.replace(':', "-");
        if let Some(existing) = quic
            .get("udpHop")
            .and_then(Value::as_object)
            .and_then(|hop| hop.get("ports"))
        {
            if existing.as_str() != Some(requested.as_str()) {
                return Err(CompileError::UnsupportedNode {
                    node: node.id.to_string(),
                    reason: "Hysteria has conflicting port-hopping settings".to_owned(),
                });
            }
        } else {
            quic.insert("udpHop".to_owned(), json!({ "ports": requested }));
        }
    }

    Ok((!root.is_empty()).then_some(Value::Object(root)))
}

fn tls_json(tls: &TlsSettings, node: &Node) -> Result<Value, CompileError> {
    if tls.allow_insecure {
        return Err(CompileError::UnsupportedNode {
            node: node.id.to_string(),
            reason: "TLS allowInsecure was removed by Xray-core after 2026-06-01; configure pinnedPeerCertSha256 and/or verifyPeerCertByName instead".to_owned(),
        });
    }
    let mut settings = Map::new();
    let sni = tls
        .server_name
        .clone()
        .unwrap_or_else(|| node.endpoint.address.clone());
    settings.insert("serverName".into(), json!(sni));
    if !tls.alpn.is_empty() {
        settings.insert("alpn".into(), json!(tls.alpn));
    }
    if let Some(fingerprint) = &tls.fingerprint {
        settings.insert("fingerprint".into(), json!(fingerprint));
    }
    if let Some(ech) = &tls.ech_config_list {
        settings.insert("echConfigList".into(), json!(ech));
    }
    if let Some(force) = &tls.ech_force_query {
        settings.insert("echForceQuery".into(), json!(force));
    }
    if let Some(pins) = &tls.pinned_peer_cert_sha256 {
        settings.insert("pinnedPeerCertSha256".into(), json!(pins));
    }
    if let Some(names) = &tls.verify_peer_cert_by_name {
        settings.insert("verifyPeerCertByName".into(), json!(names));
    }
    if let Some(suites) = &tls.cipher_suites {
        settings.insert("cipherSuites".into(), json!(suites));
    }
    Ok(Value::Object(settings))
}

fn reality_json(reality: &RealitySettings, node: &Node) -> Value {
    let mut settings = Map::new();
    let sni = reality
        .server_name
        .clone()
        .unwrap_or_else(|| node.endpoint.address.clone());
    settings.insert("serverName".into(), json!(sni));
    settings.insert("publicKey".into(), json!(reality.public_key.expose()));
    if let Some(short_id) = &reality.short_id {
        settings.insert("shortId".into(), json!(short_id.expose()));
    }
    if let Some(spider) = &reality.spider_x {
        settings.insert("spiderX".into(), json!(spider));
    }
    if let Some(fingerprint) = &reality.fingerprint {
        settings.insert("fingerprint".into(), json!(fingerprint));
    }
    if let Some(mldsa) = &reality.mldsa65_verify {
        settings.insert("mldsa65Verify".into(), json!(mldsa.expose()));
    }
    Value::Object(settings)
}

fn sockopt_json(
    sockopt: &SocketSettings,
    dialer_proxy: Option<&str>,
    domain_strategy: Option<&str>,
) -> Option<SockOpt> {
    let built = SockOpt {
        mark: sockopt.mark,
        tcp_fast_open: sockopt.tcp_fast_open,
        tcp_keep_alive_interval: sockopt.tcp_keep_alive_interval,
        interface: sockopt.interface.clone(),
        domain_strategy: domain_strategy
            .map(str::to_owned)
            .or_else(|| sockopt.domain_strategy.clone()),
        dialer_proxy: dialer_proxy.map(str::to_owned),
        // A dialing socket is never transparent; only the transparent inbound
        // sets this, and inbounds do not come through here.
        tproxy: None,
    };
    let empty = built.mark.is_none()
        && built.tcp_fast_open.is_none()
        && built.tcp_keep_alive_interval.is_none()
        && built.interface.is_none()
        && built.domain_strategy.is_none()
        && built.dialer_proxy.is_none();
    (!empty).then_some(built)
}

fn mux_config(mux: &MuxSettings) -> Option<MuxConfig> {
    if !mux.enabled {
        return None;
    }
    Some(MuxConfig {
        enabled: true,
        concurrency: mux.concurrency,
        xudp_concurrency: mux.xudp_concurrency,
        xudp_proxy_udp_443: mux.xudp_proxy_udp_443.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{
        Endpoint, NodeId, NodeSource, RealitySettings, ShadowsocksSettings, VlessSettings,
        VmessSettings, WebsocketTransport,
    };

    fn vless_node() -> Node {
        let mut node = Node::new(
            NodeId::new("hk-01").expect("valid"),
            "HK 01",
            NodeSource::Manual,
            Endpoint::new("example.com", 443),
            ProtocolSettings::Vless(VlessSettings {
                id: Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: "xtls-rprx-vision".into(),
                encryption: "none".into(),
                level: None,
            }),
        );
        node.security = TransportSecurity::Reality(RealitySettings {
            server_name: Some("www.example.org".into()),
            public_key: Secret::new("PUBKEY"),
            short_id: Some(Secret::new("ab12")),
            spider_x: Some("/".into()),
            fingerprint: Some("chrome".into()),
            mldsa65_verify: None,
        });
        node
    }

    #[test]
    fn vless_reality_outbound_has_expected_shape() {
        let node = vless_node();
        let outbound = build(&node, "node/hk-01", None).expect("build");
        assert_eq!(outbound.tag, "node/hk-01");
        assert_eq!(outbound.protocol, "vless");
        let json = serde_json::to_value(&outbound).expect("serialise");
        assert_eq!(json["settings"]["vnext"][0]["address"], "example.com");
        assert_eq!(
            json["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(json["streamSettings"]["security"], "reality");
        assert_eq!(
            json["streamSettings"]["realitySettings"]["publicKey"],
            "PUBKEY"
        );
        assert_eq!(
            json["streamSettings"]["realitySettings"]["serverName"],
            "www.example.org"
        );
        assert!(json["streamSettings"].get("sockopt").is_none());
    }

    #[test]
    fn dialer_proxy_is_attached_for_chain_hops() {
        let node = vless_node();
        let outbound = build(&node, "chain/c/hop1", Some("chain/c/hop0")).expect("build");
        let json = serde_json::to_value(&outbound).expect("serialise");
        assert_eq!(
            json["streamSettings"]["sockopt"]["dialerProxy"],
            "chain/c/hop0"
        );
        // The terminal's own transport and security must survive chaining.
        assert_eq!(json["streamSettings"]["security"], "reality");
        assert_eq!(json["streamSettings"]["network"], "raw");
    }

    #[test]
    fn mkcp_legacy_dialect_preserves_header_and_seed_as_two_layers() {
        let mut node = vless_node();
        node.transport = Transport::Mkcp(xraytui_domain::MkcpTransport {
            header_type: Some("dtls".into()),
            seed: Some(Secret::new("synthetic-seed")),
            mtu: None,
            tti: None,
        });
        let outbound =
            build_with_dialect(&node, "node/x", None, MkcpFinalmaskDialect::UnifiedLegacy)
                .expect("build");
        let json = serde_json::to_value(outbound).expect("JSON");
        assert_eq!(
            json.pointer("/streamSettings/finalmask/udp/0/type"),
            Some(&json!("mkcp-legacy"))
        );
        assert_eq!(
            json.pointer("/streamSettings/finalmask/udp/0/settings/header"),
            Some(&json!("dtls"))
        );
        assert_eq!(
            json.pointer("/streamSettings/finalmask/udp/1/settings/value"),
            Some(&json!("synthetic-seed"))
        );
    }

    #[test]
    fn websocket_transport_is_emitted() {
        let mut node = vless_node();
        node.transport = Transport::Websocket(WebsocketTransport {
            path: "/ws".into(),
            host: Some("cdn.example.com".into()),
            headers: Default::default(),
        });
        let outbound = build(&node, "node/x", None).expect("build");
        let json = serde_json::to_value(&outbound).expect("serialise");
        assert_eq!(json["streamSettings"]["network"], "ws");
        assert_eq!(json["streamSettings"]["wsSettings"]["path"], "/ws");
        assert_eq!(
            json["streamSettings"]["wsSettings"]["host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn tls_sni_defaults_to_the_endpoint_address() {
        let mut node = vless_node();
        node.security = TransportSecurity::Tls(TlsSettings::default());
        let outbound = build(&node, "node/x", None).expect("build");
        let json = serde_json::to_value(&outbound).expect("serialise");
        assert_eq!(
            json["streamSettings"]["tlsSettings"]["serverName"],
            "example.com"
        );
        assert!(
            json["streamSettings"]["tlsSettings"]
                .get("allowInsecure")
                .is_none()
        );
    }

    #[test]
    fn vmess_with_alter_id_is_rejected_rather_than_silently_broken() {
        let mut node = vless_node();
        node.protocol = ProtocolSettings::Vmess(VmessSettings {
            id: Secret::new("uuid"),
            security: "auto".into(),
            alter_id: 64,
            level: None,
        });
        let err = build(&node, "node/x", None).expect_err("must reject");
        assert!(
            matches!(err, CompileError::UnsupportedNode { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn disabled_nodes_are_not_compiled() {
        let mut node = vless_node();
        node.enabled = false;
        assert!(build(&node, "node/x", None).is_err());
    }

    #[test]
    fn shadowsocks_password_is_emitted_verbatim() {
        let mut node = vless_node();
        node.protocol = ProtocolSettings::Shadowsocks(ShadowsocksSettings {
            method: "2022-blake3-aes-256-gcm".into(),
            password: Secret::new("cGFzcw=="),
            uot: true,
            uot_version: Some(2),
        });
        node.security = TransportSecurity::None;
        let outbound = build(&node, "node/x", None).expect("build");
        let json = serde_json::to_value(&outbound).expect("serialise");
        assert_eq!(json["settings"]["servers"][0]["password"], "cGFzcw==");
        assert_eq!(json["settings"]["servers"][0]["uotVersion"], 2);
    }

    #[test]
    fn wireguard_cannot_be_a_chain_hop() {
        let mut node = vless_node();
        node.protocol = ProtocolSettings::Wireguard(Box::new(xraytui_domain::WireguardSettings {
            secret_key: Secret::new("k"),
            address: vec!["10.0.0.2/32".into()],
            peers: vec![],
            mtu: None,
            reserved: vec![],
            domain_strategy: None,
        }));
        assert!(build(&node, "node/x", None).is_ok());
        let err = build(&node, "chain/c/hop1", Some("chain/c/hop0")).expect_err("must reject");
        assert!(
            matches!(err, CompileError::UnsupportedNode { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn hysteria_uses_xrays_protocol_and_stream_split() {
        let mut node = Node::new(
            NodeId::new("hy").expect("valid"),
            "HY",
            NodeSource::Manual,
            Endpoint::new("hy.example", 443),
            ProtocolSettings::Hysteria(xraytui_domain::HysteriaSettings {
                auth: Secret::new("synthetic-auth"),
                obfs: Some(Secret::new("synthetic-obfs")),
                up: None,
                down: None,
                port_hopping: Some("20000-30000,40000".to_owned()),
            }),
        );
        node.security = TransportSecurity::Tls(TlsSettings {
            server_name: Some("edge.example".to_owned()),
            ..Default::default()
        });

        let outbound = build(&node, "node/hy/out", Some("node/bootstrap/out")).expect("build");
        assert_eq!(
            outbound
                .settings
                .as_ref()
                .and_then(|value| value.get("version")),
            Some(&json!(2))
        );
        assert_eq!(
            outbound
                .settings
                .as_ref()
                .and_then(|value| value.get("address")),
            Some(&json!("hy.example"))
        );
        let stream = outbound.stream_settings.expect("Hysteria stream settings");
        assert_eq!(stream.network.as_deref(), Some("hysteria"));
        assert_eq!(stream.security.as_deref(), Some("tls"));
        assert_eq!(
            stream
                .hysteria_settings
                .as_ref()
                .and_then(|value| value.get("auth")),
            Some(&json!("synthetic-auth"))
        );
        let finalmask = stream.finalmask.expect("Hysteria finalmask");
        assert_eq!(
            finalmask.pointer("/udp/0/type").and_then(Value::as_str),
            Some("salamander")
        );
        assert_eq!(
            finalmask
                .pointer("/quicParams/udpHop/ports")
                .and_then(Value::as_str),
            Some("20000-30000,40000")
        );
        assert_eq!(
            stream.sockopt.and_then(|sockopt| sockopt.dialer_proxy),
            Some("node/bootstrap/out".to_owned())
        );
    }

    #[test]
    fn hysteria_rejects_any_duplicate_salamander_with_a_different_password() {
        let mut node = Node::new(
            NodeId::new("hy-conflict").expect("valid"),
            "HY conflict",
            NodeSource::Manual,
            Endpoint::new("hy.example", 443),
            ProtocolSettings::Hysteria(xraytui_domain::HysteriaSettings {
                auth: Secret::new("synthetic-auth"),
                obfs: Some(Secret::new("right")),
                up: None,
                down: None,
                port_hopping: None,
            }),
        );
        node.security = TransportSecurity::Tls(TlsSettings::default());
        node.finalmask = Some(json!({
            "udp": [
                {"type": "salamander", "settings": {"password": "right"}},
                {"type": "salamander", "settings": {"password": "wrong"}}
            ]
        }));
        let error = build(&node, "node/hy-conflict/out", None).expect_err("must reject conflict");
        assert!(error.to_string().contains("conflicting salamander"));
    }
}
