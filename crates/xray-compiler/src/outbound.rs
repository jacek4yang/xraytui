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
use xraytui_xray_model::{
    FinalMask, Mask as XrayMask, MuxConfig, Outbound, SockOpt, StreamSettings,
};

use crate::CompileError;

/// Build the outbound object for a node under the given tag.
///
/// `dialer_proxy` sets `streamSettings.sockopt.dialerProxy`, which is how chain
/// hops are linked. It is applied even when the node itself declared no socket
/// options.
///
/// # Errors
/// Returns [`CompileError::UnsupportedNode`] when the node cannot be represented.
pub fn build(node: &Node, tag: &str, dialer_proxy: Option<&str>) -> Result<Outbound, CompileError> {
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

    let settings = protocol_settings(node)?;
    let stream = if node.protocol.accepts_stream_settings() {
        Some(stream_settings(node, dialer_proxy))
    } else if dialer_proxy.is_some() {
        // WireGuard and Hysteria carry their own transport, so there is nowhere
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

fn protocol_settings(node: &Node) -> Result<Value, CompileError> {
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
            if let Some(strategy) = &w.domain_strategy {
                settings.insert("domainStrategy".into(), json!(strategy));
            }
            Value::Object(settings)
        }
        ProtocolSettings::Hysteria(h) => {
            let mut server = Map::new();
            server.insert("address".into(), json!(address));
            server.insert("port".into(), json!(port));
            server.insert("auth".into(), json!(h.auth.expose()));
            if let Some(obfs) = &h.obfs {
                server.insert("obfs".into(), json!(obfs.expose()));
            }
            if let Some(up) = &h.up {
                server.insert("up".into(), json!(up));
            }
            if let Some(down) = &h.down {
                server.insert("down".into(), json!(down));
            }
            json!({ "servers": [Value::Object(server)] })
        }
    };
    Ok(value)
}

/// Map a legacy mKCP `headerType` onto the current UDP mask identifier.
///
/// Returns `None` for `none`, and for values the pinned release does not
/// register, in which case only the mKCP mask itself is emitted.
fn mkcp_header_mask(header: &str) -> Option<&'static str> {
    match header {
        "srtp" => Some("header-srtp"),
        "utp" => Some("header-utp"),
        "wechat-video" | "wechat" => Some("header-wechat"),
        "dtls" => Some("header-dtls"),
        "wireguard" => Some("header-wireguard"),
        "dns" => Some("header-dns"),
        _ => None,
    }
}

fn expose_or_empty(secret: Option<&Secret>) -> &str {
    secret.map_or("", Secret::expose)
}

fn stream_settings(node: &Node, dialer_proxy: Option<&str>) -> StreamSettings {
    let mut stream = StreamSettings {
        network: Some(node.transport.xray_network().to_owned()),
        security: Some(node.security.xray_security().to_owned()),
        ..Default::default()
    };

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
            stream.kcp_settings = Some(Value::Object(Map::new()));
            let mut masks: Vec<XrayMask> = Vec::new();
            if let Some(header) = m.header_type.as_deref()
                && let Some(mask_type) = mkcp_header_mask(header)
            {
                masks.push(XrayMask {
                    mask_type: mask_type.to_owned(),
                    settings: None,
                });
            }
            masks.push(match &m.seed {
                Some(seed) => XrayMask {
                    mask_type: "mkcp-aes128gcm".to_owned(),
                    settings: Some(json!({ "password": seed.expose() })),
                },
                None => XrayMask {
                    mask_type: "mkcp-original".to_owned(),
                    settings: None,
                },
            });
            stream.finalmask = Some(FinalMask {
                tcp: Vec::new(),
                udp: masks,
            });
        }
    }

    match &node.security {
        TransportSecurity::None => {}
        TransportSecurity::Tls(tls) => stream.tls_settings = Some(tls_json(tls, node)),
        TransportSecurity::Reality(reality) => {
            stream.reality_settings = Some(reality_json(reality, node));
        }
    }

    let sockopt = sockopt_json(&node.sockopt, dialer_proxy);
    if sockopt.is_some() {
        stream.sockopt = sockopt;
    }
    stream
}

fn tls_json(tls: &TlsSettings, node: &Node) -> Value {
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
    if tls.allow_insecure {
        // Only ever set through an explicit, visible user action; the importers
        // never produce it. See docs/THREAT-MODEL.md.
        settings.insert("allowInsecure".into(), json!(true));
    }
    Value::Object(settings)
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

fn sockopt_json(sockopt: &SocketSettings, dialer_proxy: Option<&str>) -> Option<SockOpt> {
    let built = SockOpt {
        mark: sockopt.mark,
        tcp_fast_open: sockopt.tcp_fast_open,
        tcp_keep_alive_interval: sockopt.tcp_keep_alive_interval,
        interface: sockopt.interface.clone(),
        domain_strategy: sockopt.domain_strategy.clone(),
        dialer_proxy: dialer_proxy.map(str::to_owned),
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
}
