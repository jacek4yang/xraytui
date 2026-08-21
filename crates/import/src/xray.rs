//! Importing raw Xray outbound JSON.
//!
//! Accepts a whole configuration, a bare `outbounds` array, or a single outbound
//! object, so `xraytui node import --xray-json` works on whatever fragment the
//! user pasted.

use std::collections::BTreeMap;

use serde_json::Value;
use xraytui_domain::{
    Endpoint, GrpcTransport, HttpProxySettings, HttpUpgradeTransport, HysteriaSettings,
    MkcpTransport, Node, NodeSource, ProtocolSettings, RawTransport, RealitySettings,
    ShadowsocksSettings, SocksSettings, TlsSettings, Transport, TransportSecurity, TrojanSettings,
    UnsupportedNode, UnsupportedReason, VlessSettings, VmessSettings, WebsocketTransport,
    XhttpTransport,
};
use xraytui_secrets::Secret;

use crate::{
    ImportBatch, ImportError, ImportedEntry, MAX_JSON_BYTES, MAX_NAME_CHARS, RejectedEntry,
};

/// Parse a whole Xray configuration, a bare array, or a single outbound.
///
/// Never fails as a whole: an unparseable document yields a batch holding one
/// [`RejectedEntry`], and individual bad outbounds are rejected one by one.
#[must_use]
pub fn parse_xray_config(text: &str, source: NodeSource) -> ImportBatch {
    let mut batch = ImportBatch::new();
    if text.len() > MAX_JSON_BYTES {
        batch.rejected.push(RejectedEntry {
            index: 0,
            redacted: String::new(),
            error: ImportError::TooLarge {
                size: text.len(),
                limit: MAX_JSON_BYTES,
            },
        });
        return batch;
    }
    let Ok(document) = serde_json::from_str::<Value>(text) else {
        batch.rejected.push(RejectedEntry {
            index: 0,
            redacted: String::new(),
            error: ImportError::ConfigNotJson,
        });
        return batch;
    };

    let outbounds: Vec<&Value> = match &document {
        Value::Array(items) => items.iter().collect(),
        Value::Object(object) => match object.get("outbounds") {
            Some(Value::Array(items)) => items.iter().collect(),
            _ => vec![&document],
        },
        _ => {
            batch.rejected.push(RejectedEntry {
                index: 0,
                redacted: String::new(),
                error: ImportError::NotAnObject,
            });
            return batch;
        }
    };

    if outbounds.is_empty() {
        batch.rejected.push(RejectedEntry {
            index: 0,
            redacted: String::new(),
            error: ImportError::NoOutbounds,
        });
        return batch;
    }

    for (offset, outbound) in outbounds.iter().enumerate() {
        let index = offset.saturating_add(1);
        match parse_xray_outbound(outbound, source.clone()) {
            Ok(entry) => batch.push(entry),
            Err(error) => batch.rejected.push(RejectedEntry {
                index,
                redacted: outbound
                    .get("tag")
                    .and_then(Value::as_str)
                    .map(|tag| tag.chars().take(64).collect())
                    .unwrap_or_default(),
                error,
            }),
        }
    }
    batch
}

/// Parse one Xray outbound object into a node.
///
/// Outbounds xraytui uses internally (`freedom`, `blackhole`, `loopback`, `dns`)
/// are classified as unsupported rather than imported, because they are routing
/// actions rather than endpoints.
///
/// # Errors
/// Returns [`ImportError`] when the value is not an object, has no `protocol`,
/// or is missing a field the protocol requires.
pub fn parse_xray_outbound(
    value: &Value,
    source: NodeSource,
) -> Result<ImportedEntry, ImportError> {
    let object = value.as_object().ok_or(ImportError::NotAnObject)?;
    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .ok_or(ImportError::MissingProtocol)?
        .to_ascii_lowercase();

    let tag = object
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name: String = tag.chars().take(MAX_NAME_CHARS).collect();
    let settings = object.get("settings").and_then(Value::as_object);
    let stream = object.get("streamSettings").and_then(Value::as_object);

    let make_unsupported = |reason: UnsupportedReason, core: Option<&str>| {
        let rendered = serde_json::to_string(value).unwrap_or_default();
        ImportedEntry::Unsupported(UnsupportedNode {
            id: crate::link_id(&name, &protocol),
            name: name.clone(),
            source: source.clone(),
            detected_protocol: protocol.clone(),
            reason,
            requires_core: core.map(str::to_owned),
            redacted_original: format!("{{\"protocol\":\"{protocol}\",\"tag\":\"{name}\"}}"),
            original: Secret::new(rendered),
        })
    };

    match protocol.as_str() {
        "freedom" | "blackhole" | "loopback" | "dns" => {
            return Ok(make_unsupported(
                UnsupportedReason::Malformed {
                    detail: format!(
                        "`{protocol}` is a routing action, not a proxy endpoint; use a direct or \
                         block target instead"
                    ),
                },
                None,
            ));
        }
        "wireguard" => {
            // Modelled by the domain but not yet reconstructed from Xray JSON;
            // preserving the complete object is safer than dropping a peer or
            // device-only field while pretending the result is executable.
            return Ok(make_unsupported(
                UnsupportedReason::Malformed {
                    detail: format!(
                        "`{protocol}` outbounds are preserved verbatim; edit them in the manual \
                         editor to make them selectable"
                    ),
                },
                None,
            ));
        }
        _ => {}
    }

    let Some(settings) = settings else {
        return Err(ImportError::MissingField {
            scheme: "xray",
            field: "settings",
        });
    };

    let (endpoint, protocol_settings) = match protocol.as_str() {
        "vless" => {
            let (address, port, user) = first_vnext_user(settings)?;
            (
                Endpoint::new(address, port),
                ProtocolSettings::Vless(VlessSettings {
                    id: Secret::new(string_field(&user, "id")?),
                    flow: user
                        .get("flow")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    encryption: user
                        .get("encryption")
                        .and_then(Value::as_str)
                        .unwrap_or("none")
                        .to_owned(),
                    level: user
                        .get("level")
                        .and_then(Value::as_u64)
                        .and_then(|l| u32::try_from(l).ok()),
                }),
            )
        }
        "vmess" => {
            let (address, port, user) = first_vnext_user(settings)?;
            (
                Endpoint::new(address, port),
                ProtocolSettings::Vmess(VmessSettings {
                    id: Secret::new(string_field(&user, "id")?),
                    security: user
                        .get("security")
                        .and_then(Value::as_str)
                        .unwrap_or("auto")
                        .to_owned(),
                    alter_id: user
                        .get("alterId")
                        .and_then(Value::as_u64)
                        .and_then(|a| u16::try_from(a).ok())
                        .unwrap_or(0),
                    level: user
                        .get("level")
                        .and_then(Value::as_u64)
                        .and_then(|l| u32::try_from(l).ok()),
                }),
            )
        }
        "trojan" => {
            let server = first_server(settings)?;
            (
                endpoint_of(&server)?,
                ProtocolSettings::Trojan(TrojanSettings {
                    password: Secret::new(string_field(&server, "password")?),
                    flow: server
                        .get("flow")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                }),
            )
        }
        "shadowsocks" => {
            let server = first_server(settings)?;
            (
                endpoint_of(&server)?,
                ProtocolSettings::Shadowsocks(ShadowsocksSettings {
                    method: string_field(&server, "method")?,
                    password: Secret::new(string_field(&server, "password")?),
                    uot: server.get("uot").and_then(Value::as_bool).unwrap_or(false),
                    uot_version: server
                        .get("uotVersion")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok()),
                }),
            )
        }
        "socks" => {
            let server = first_server(settings)?;
            let (username, password) = first_user_credentials(&server);
            (
                endpoint_of(&server)?,
                ProtocolSettings::Socks(SocksSettings {
                    username,
                    password,
                    udp: true,
                }),
            )
        }
        "http" => {
            let server = first_server(settings)?;
            let (username, password) = first_user_credentials(&server);
            (
                endpoint_of(&server)?,
                ProtocolSettings::Http(HttpProxySettings { username, password }),
            )
        }
        "hysteria" => {
            if settings.get("version").and_then(Value::as_i64) != Some(2) {
                return Err(ImportError::InvalidField {
                    scheme: "xray",
                    field: "version",
                });
            }
            let stream = stream.ok_or(ImportError::MissingField {
                scheme: "xray",
                field: "streamSettings",
            })?;
            if stream.get("network").and_then(Value::as_str) != Some("hysteria") {
                return Err(ImportError::InvalidField {
                    scheme: "xray",
                    field: "streamSettings.network",
                });
            }
            let hysteria = stream
                .get("hysteriaSettings")
                .and_then(Value::as_object)
                .ok_or(ImportError::MissingField {
                    scheme: "xray",
                    field: "hysteriaSettings",
                })?;
            if hysteria.get("version").and_then(Value::as_i64) != Some(2) {
                return Err(ImportError::InvalidField {
                    scheme: "xray",
                    field: "hysteriaSettings.version",
                });
            }
            let finalmask = stream.get("finalmask");
            let obfs = finalmask
                .and_then(|mask| mask.pointer("/udp"))
                .and_then(Value::as_array)
                .and_then(|masks| {
                    masks
                        .iter()
                        .find(|mask| mask.get("type").and_then(Value::as_str) == Some("salamander"))
                })
                .and_then(|mask| mask.pointer("/settings/password"))
                .and_then(Value::as_str)
                .map(Secret::new);
            let port_hopping = finalmask
                .and_then(|mask| mask.pointer("/quicParams/udpHop/ports"))
                .and_then(Value::as_str)
                .map(|ports| ports.replace(':', "-"));
            (
                endpoint_of(settings)?,
                ProtocolSettings::Hysteria(HysteriaSettings {
                    auth: Secret::new(string_field(hysteria, "auth")?),
                    obfs,
                    up: hysteria
                        .get("up")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    down: hysteria
                        .get("down")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    port_hopping,
                }),
            )
        }
        other => {
            return Ok(make_unsupported(
                UnsupportedReason::UnknownScheme {
                    scheme: other.to_owned(),
                },
                None,
            ));
        }
    };

    let mut node = Node::new(
        crate::link_id(&name, &protocol),
        name,
        source,
        endpoint,
        protocol_settings,
    );
    if let Some(stream) = stream {
        node.transport = transport_from_stream(stream);
        node.security = security_from_stream(stream, &node.endpoint.address);
        node.finalmask = stream.get("finalmask").cloned();
    }
    Ok(ImportedEntry::Supported(node))
}

type Object = serde_json::Map<String, Value>;

fn string_field(object: &Object, field: &'static str) -> Result<String, ImportError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(ImportError::MissingField {
            scheme: "xray",
            field,
        })
}

fn first_vnext_user(settings: &Object) -> Result<(String, u16, Object), ImportError> {
    let vnext = settings
        .get("vnext")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .ok_or(ImportError::MissingField {
            scheme: "xray",
            field: "vnext",
        })?;
    let address = string_field(vnext, "address")?;
    let port = vnext
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .ok_or(ImportError::InvalidField {
            scheme: "xray",
            field: "port",
        })?;
    let user = vnext
        .get("users")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .cloned()
        .ok_or(ImportError::MissingField {
            scheme: "xray",
            field: "users",
        })?;
    Ok((address, port, user))
}

fn first_server(settings: &Object) -> Result<Object, ImportError> {
    settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .cloned()
        .ok_or(ImportError::MissingField {
            scheme: "xray",
            field: "servers",
        })
}

fn endpoint_of(server: &Object) -> Result<Endpoint, ImportError> {
    let address = string_field(server, "address")?;
    let port = server
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .ok_or(ImportError::InvalidField {
            scheme: "xray",
            field: "port",
        })?;
    Ok(Endpoint::new(address, port))
}

fn first_user_credentials(server: &Object) -> (Option<String>, Option<Secret>) {
    let user = server
        .get("users")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object);
    let Some(user) = user else {
        return (None, None);
    };
    let username = user.get("user").and_then(Value::as_str).map(str::to_owned);
    let password = user.get("pass").and_then(Value::as_str).map(Secret::new);
    (username, password)
}

fn transport_from_stream(stream: &Object) -> Transport {
    let network = stream
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("raw");
    let settings = |key: &str| stream.get(key).and_then(Value::as_object);
    let text = |object: Option<&Object>, key: &str| {
        object
            .and_then(|o| o.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    match network {
        "ws" | "websocket" => {
            let ws = settings("wsSettings");
            Transport::Websocket(WebsocketTransport {
                path: text(ws, "path").unwrap_or_else(|| "/".to_owned()),
                host: text(ws, "host"),
                headers: BTreeMap::new(),
            })
        }
        "grpc" => {
            let grpc = settings("grpcSettings");
            Transport::Grpc(GrpcTransport {
                service_name: text(grpc, "serviceName").unwrap_or_default(),
                multi_mode: grpc
                    .and_then(|o| o.get("multiMode"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                authority: text(grpc, "authority"),
            })
        }
        "xhttp" | "splithttp" => {
            let xhttp = settings("xhttpSettings").or_else(|| settings("splithttpSettings"));
            Transport::Xhttp(XhttpTransport {
                host: text(xhttp, "host"),
                path: text(xhttp, "path"),
                mode: text(xhttp, "mode"),
                extra: xhttp.and_then(|o| o.get("extra")).cloned(),
            })
        }
        "httpupgrade" => {
            let hu = settings("httpupgradeSettings");
            Transport::HttpUpgrade(HttpUpgradeTransport {
                path: text(hu, "path").unwrap_or_else(|| "/".to_owned()),
                host: text(hu, "host"),
            })
        }
        "kcp" | "mkcp" => {
            let kcp = settings("kcpSettings");
            Transport::Mkcp(MkcpTransport {
                header_type: kcp
                    .and_then(|o| o.get("header"))
                    .and_then(Value::as_object)
                    .and_then(|h| h.get("type"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                seed: text(kcp, "seed").map(Secret::new),
                mtu: kcp
                    .and_then(|o| o.get("mtu"))
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                tti: kcp
                    .and_then(|o| o.get("tti"))
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
            })
        }
        _ => {
            let raw = settings("rawSettings").or_else(|| settings("tcpSettings"));
            Transport::Raw(RawTransport {
                header_type: raw
                    .and_then(|o| o.get("header"))
                    .and_then(Value::as_object)
                    .and_then(|h| h.get("type"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                host: Vec::new(),
                path: None,
            })
        }
    }
}

fn security_from_stream(stream: &Object, address: &str) -> TransportSecurity {
    let text = |object: Option<&Object>, key: &str| {
        object
            .and_then(|o| o.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    match stream
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("none")
    {
        "tls" => {
            let tls = stream.get("tlsSettings").and_then(Value::as_object);
            TransportSecurity::Tls(TlsSettings {
                server_name: tls
                    .and_then(|o| o.get("serverName"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| Some(address.to_owned())),
                alpn: tls
                    .and_then(|o| o.get("alpn"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                fingerprint: tls
                    .and_then(|o| o.get("fingerprint"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                // Preserved rather than silently dropped, so that re-exporting a
                // config the user already had does not change its behaviour.
                allow_insecure: tls
                    .and_then(|o| o.get("allowInsecure"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                ech_config_list: text(tls, "echConfigList"),
                ech_force_query: text(tls, "echForceQuery"),
                pinned_peer_cert_sha256: text(tls, "pinnedPeerCertSha256"),
                verify_peer_cert_by_name: text(tls, "verifyPeerCertByName"),
                cipher_suites: text(tls, "cipherSuites"),
            })
        }
        "reality" => {
            let reality = stream.get("realitySettings").and_then(Value::as_object);
            let field = |key: &str| {
                reality
                    .and_then(|o| o.get(key))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            };
            TransportSecurity::Reality(RealitySettings {
                server_name: field("serverName").or_else(|| Some(address.to_owned())),
                public_key: Secret::new(field("publicKey").unwrap_or_default()),
                short_id: field("shortId").map(Secret::new),
                spider_x: field("spiderX"),
                fingerprint: field("fingerprint"),
                mldsa65_verify: field("mldsa65Verify").map(Secret::new),
            })
        }
        _ => TransportSecurity::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_whole_config_is_walked() {
        let config = serde_json::json!({
            "outbounds": [
                { "tag": "control/block", "protocol": "blackhole" },
                {
                    "tag": "hk", "protocol": "vless",
                    "settings": { "vnext": [{ "address": "h.example", "port": 443,
                        "users": [{ "id": "uuid", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
                    "streamSettings": { "network": "ws", "security": "tls",
                        "wsSettings": { "path": "/x", "host": "cdn.example" },
                        "tlsSettings": { "serverName": "cdn.example", "alpn": ["h2"] } }
                }
            ]
        });
        let batch = parse_xray_config(&config.to_string(), NodeSource::XrayJson);
        assert_eq!(batch.nodes.len(), 1);
        assert_eq!(
            batch.unsupported.len(),
            1,
            "blackhole must be preserved, not imported"
        );
        let node = batch.nodes.first().expect("node");
        assert_eq!(node.name, "hk");
        assert_eq!(node.endpoint, Endpoint::new("h.example", 443));
        assert!(matches!(node.transport, Transport::Websocket(_)));
        assert!(matches!(node.security, TransportSecurity::Tls(_)));
    }

    #[test]
    fn a_bare_outbound_object_is_accepted() {
        let outbound = serde_json::json!({
            "tag": "t", "protocol": "trojan",
            "settings": { "servers": [{ "address": "h.example", "port": 443, "password": "pw" }] }
        });
        let batch = parse_xray_config(&outbound.to_string(), NodeSource::XrayJson);
        assert_eq!(batch.nodes.len(), 1);
    }

    #[test]
    fn a_bare_array_is_accepted() {
        let array = serde_json::json!([{
            "tag": "s", "protocol": "shadowsocks",
            "settings": { "servers": [{ "address": "h.example", "port": 8388,
                "method": "aes-256-gcm", "password": "pw" }] }
        }]);
        let batch = parse_xray_config(&array.to_string(), NodeSource::XrayJson);
        assert_eq!(batch.nodes.len(), 1);
    }

    #[test]
    fn broken_documents_produce_rejects_not_panics() {
        for text in [
            "",
            "{",
            "null",
            "[]",
            "{\"outbounds\":[]}",
            "{\"outbounds\":[1,2]}",
        ] {
            let batch = parse_xray_config(text, NodeSource::XrayJson);
            assert!(batch.is_empty(), "{text} unexpectedly produced nodes");
            assert!(batch.has_rejects(), "{text} produced no reject");
        }
    }

    #[test]
    fn oversized_documents_are_refused() {
        let huge = "x".repeat(MAX_JSON_BYTES + 1);
        let batch = parse_xray_config(&huge, NodeSource::XrayJson);
        assert!(matches!(
            batch.rejected.first().map(|r| r.error.clone()),
            Some(ImportError::TooLarge { .. })
        ));
    }

    #[test]
    fn missing_fields_are_reported_without_the_payload() {
        let outbound = serde_json::json!({ "tag": "x", "protocol": "vless", "settings": {} });
        let error = parse_xray_outbound(&outbound, NodeSource::XrayJson).expect_err("must refuse");
        assert_eq!(
            error,
            ImportError::MissingField {
                scheme: "xray",
                field: "vnext"
            }
        );
    }

    #[test]
    fn reality_settings_are_recovered() {
        let outbound = serde_json::json!({
            "tag": "r", "protocol": "vless",
            "settings": { "vnext": [{ "address": "1.2.3.4", "port": 443,
                "users": [{ "id": "uuid", "encryption": "none" }] }] },
            "streamSettings": { "network": "raw", "security": "reality",
                "realitySettings": { "serverName": "www.example.org", "publicKey": "PUB",
                    "shortId": "ab12", "fingerprint": "chrome" } }
        });
        let node = parse_xray_outbound(&outbound, NodeSource::XrayJson)
            .expect("parse")
            .into_node()
            .expect("supported");
        match &node.security {
            TransportSecurity::Reality(reality) => {
                assert_eq!(reality.public_key.expose(), "PUB");
                assert_eq!(reality.server_name.as_deref(), Some("www.example.org"));
            }
            other => panic!("wrong security: {other:?}"),
        }
    }

    #[test]
    fn unknown_protocols_are_preserved_with_their_original() {
        let outbound = serde_json::json!({ "tag": "z", "protocol": "brand-new", "settings": {} });
        let entry = parse_xray_outbound(&outbound, NodeSource::XrayJson).expect("classify");
        let unsupported = entry.as_unsupported().expect("unsupported");
        assert_eq!(unsupported.detected_protocol, "brand-new");
        assert!(unsupported.original.expose().contains("brand-new"));
        assert!(!unsupported.redacted_original.contains("settings"));
    }

    #[test]
    fn xray_native_hysteria_is_reconstructed_from_protocol_stream_and_finalmask() {
        let outbound = serde_json::json!({
            "tag": "hy", "protocol": "hysteria",
            "settings": {"version": 2, "address": "hy.example", "port": 443},
            "streamSettings": {
                "network": "hysteria", "security": "tls",
                "hysteriaSettings": {"version": 2, "auth": "synthetic-auth"},
                "tlsSettings": {"serverName": "edge.example"},
                "finalmask": {
                    "udp": [{"type": "salamander", "settings": {"password": "synthetic-obfs"}}],
                    "quicParams": {"udpHop": {"ports": "20000-30000,40000"}}
                }
            }
        });
        let node = parse_xray_outbound(&outbound, NodeSource::XrayJson)
            .expect("parse")
            .into_node()
            .expect("supported");
        let ProtocolSettings::Hysteria(hysteria) = &node.protocol else {
            panic!("expected Hysteria");
        };
        assert_eq!(hysteria.auth.expose(), "synthetic-auth");
        assert_eq!(
            hysteria.obfs.as_ref().map(Secret::expose),
            Some("synthetic-obfs")
        );
        assert_eq!(hysteria.port_hopping.as_deref(), Some("20000-30000,40000"));
        assert!(matches!(node.security, TransportSecurity::Tls(_)));
        assert_eq!(
            node.finalmask
                .as_ref()
                .and_then(|mask| mask.pointer("/quicParams/udpHop/ports"))
                .and_then(Value::as_str),
            Some("20000-30000,40000")
        );

        let export = crate::export_share_link(&node, crate::ShareOptions::default())
            .expect("typed finalmask features fit the Hysteria2 link");
        assert_eq!(export.fidelity, crate::ExportFidelity::Lossless);
        let reimported = crate::parse_uri(export.link.expose())
            .expect("re-import Hysteria2 link")
            .into_node()
            .expect("supported Hysteria2 link");
        assert_eq!(node.canonical_identity(), reimported.canonical_identity());
    }
}
