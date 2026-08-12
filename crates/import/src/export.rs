//! Share-link generation.
//!
//! The inverse of [`crate::link`]. Two properties are tested rather than assumed:
//!
//! * a link parsed and re-exported yields a node with the same
//!   [`Node::canonical_identity`];
//! * unknown parameters captured into [`Node::extra`] on import are re-emitted,
//!   so a round trip through xraytui does not strip fields a future Xray adds.
//!
//! The result is a [`Secret`], because a share link grants proxy access. Callers
//! that display one are expected to warn first.

use std::fmt::Write as _;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use xraytui_domain::{Node, ProtocolSettings, Transport, TransportSecurity};
use xraytui_secrets::Secret;

use crate::b64::encode_standard;
use crate::{ExportError, MAX_LINK_BYTES};

/// Characters escaped inside a query value or fragment.
const QUERY: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'&')
    .add(b'=')
    .add(b'?')
    .add(b'/')
    .add(b'%')
    .add(b'+');

/// Characters escaped inside userinfo.
const USERINFO: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'%');

fn escape_query(value: &str) -> String {
    utf8_percent_encode(value, QUERY).to_string()
}

fn escape_userinfo(value: &str) -> String {
    utf8_percent_encode(value, USERINFO).to_string()
}

/// Turn a node back into a share link in its community-standard format.
///
/// # Errors
/// Returns [`ExportError::NoStandardFormat`] for protocols with no agreed link
/// syntax (WireGuard, Hysteria), and [`ExportError::EmptyField`] when a field the
/// format requires is missing.
pub fn to_share_link(node: &Node) -> Result<Secret, ExportError> {
    let link = match &node.protocol {
        ProtocolSettings::Vless(_) => authority_link(node, "vless")?,
        ProtocolSettings::Trojan(_) => authority_link(node, "trojan")?,
        ProtocolSettings::Socks(_) => authority_link(node, "socks")?,
        ProtocolSettings::Http(_) => authority_link(node, "http-proxy")?,
        ProtocolSettings::Vmess(_) => vmess_link(node)?,
        ProtocolSettings::Shadowsocks(_) => shadowsocks_link(node)?,
        ProtocolSettings::Wireguard(_) => {
            return Err(ExportError::NoStandardFormat {
                protocol: "wireguard",
            });
        }
        ProtocolSettings::Hysteria(_) => {
            return Err(ExportError::NoStandardFormat {
                protocol: "hysteria",
            });
        }
    };
    if link.len() > MAX_LINK_BYTES {
        return Err(ExportError::TooLarge {
            limit: MAX_LINK_BYTES,
        });
    }
    Ok(Secret::new(link))
}

/// Query parameters describing this node's transport and security.
fn query_parameters(node: &Node) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    params.push(("type".to_owned(), node.transport.xray_network().to_owned()));

    match &node.transport {
        Transport::Raw(raw) => {
            if let Some(header) = &raw.header_type {
                params.push(("headerType".to_owned(), header.clone()));
            }
            if let Some(host) = raw.host.first() {
                params.push(("host".to_owned(), host.clone()));
            }
            if let Some(path) = &raw.path {
                params.push(("path".to_owned(), path.clone()));
            }
        }
        Transport::Xhttp(x) => {
            if let Some(host) = &x.host {
                params.push(("host".to_owned(), host.clone()));
            }
            if let Some(path) = &x.path {
                params.push(("path".to_owned(), path.clone()));
            }
            if let Some(mode) = &x.mode {
                params.push(("mode".to_owned(), mode.clone()));
            }
        }
        Transport::Grpc(g) => {
            params.push(("serviceName".to_owned(), g.service_name.clone()));
            if g.multi_mode {
                params.push(("mode".to_owned(), "multi".to_owned()));
            }
            if let Some(authority) = &g.authority {
                params.push(("authority".to_owned(), authority.clone()));
            }
        }
        Transport::Websocket(ws) => {
            params.push(("path".to_owned(), ws.path.clone()));
            if let Some(host) = &ws.host {
                params.push(("host".to_owned(), host.clone()));
            }
        }
        Transport::HttpUpgrade(hu) => {
            params.push(("path".to_owned(), hu.path.clone()));
            if let Some(host) = &hu.host {
                params.push(("host".to_owned(), host.clone()));
            }
        }
        Transport::Mkcp(kcp) => {
            if let Some(header) = &kcp.header_type {
                params.push(("headerType".to_owned(), header.clone()));
            }
            if let Some(seed) = &kcp.seed {
                params.push(("seed".to_owned(), seed.expose().to_owned()));
            }
        }
    }

    match &node.security {
        TransportSecurity::None => {
            params.push(("security".to_owned(), "none".to_owned()));
        }
        TransportSecurity::Tls(tls) => {
            params.push(("security".to_owned(), "tls".to_owned()));
            if let Some(sni) = &tls.server_name {
                params.push(("sni".to_owned(), sni.clone()));
            }
            if !tls.alpn.is_empty() {
                params.push(("alpn".to_owned(), tls.alpn.join(",")));
            }
            if let Some(fingerprint) = &tls.fingerprint {
                params.push(("fp".to_owned(), fingerprint.clone()));
            }
        }
        TransportSecurity::Reality(reality) => {
            params.push(("security".to_owned(), "reality".to_owned()));
            if let Some(sni) = &reality.server_name {
                params.push(("sni".to_owned(), sni.clone()));
            }
            params.push(("pbk".to_owned(), reality.public_key.expose().to_owned()));
            if let Some(short_id) = &reality.short_id {
                params.push(("sid".to_owned(), short_id.expose().to_owned()));
            }
            if let Some(spider) = &reality.spider_x {
                params.push(("spx".to_owned(), spider.clone()));
            }
            if let Some(fingerprint) = &reality.fingerprint {
                params.push(("fp".to_owned(), fingerprint.clone()));
            }
            if let Some(mldsa) = &reality.mldsa65_verify {
                params.push(("mldsa65Verify".to_owned(), mldsa.expose().to_owned()));
            }
        }
    }

    if let ProtocolSettings::Vless(vless) = &node.protocol {
        if !vless.flow.is_empty() {
            params.push(("flow".to_owned(), vless.flow.clone()));
        }
        if vless.encryption != "none" {
            params.push(("encryption".to_owned(), vless.encryption.clone()));
        }
    }

    // Anything the importer did not understand goes back out untouched.
    for (key, value) in &node.extra {
        if let Some(text) = value.as_str() {
            params.push((key.clone(), text.to_owned()));
        } else {
            params.push((key.clone(), value.to_string()));
        }
    }

    params
}

fn render_query(params: &[(String, String)]) -> String {
    params
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| format!("{}={}", escape_query(key), escape_query(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn authority_link(node: &Node, scheme: &'static str) -> Result<String, ExportError> {
    if node.endpoint.address.is_empty() {
        return Err(ExportError::EmptyField { field: "address" });
    }
    let userinfo = match &node.protocol {
        ProtocolSettings::Vless(v) => {
            if v.id.is_empty() {
                return Err(ExportError::EmptyField { field: "id" });
            }
            escape_userinfo(v.id.expose())
        }
        ProtocolSettings::Trojan(t) => {
            if t.password.is_empty() {
                return Err(ExportError::EmptyField { field: "password" });
            }
            escape_userinfo(t.password.expose())
        }
        ProtocolSettings::Socks(s) => credentials(s.username.as_deref(), s.password.as_ref()),
        ProtocolSettings::Http(h) => credentials(h.username.as_deref(), h.password.as_ref()),
        _ => return Err(ExportError::NoStandardFormat { protocol: scheme }),
    };

    let mut link = String::new();
    let _ = write!(link, "{scheme}://");
    if !userinfo.is_empty() {
        let _ = write!(link, "{userinfo}@");
    }
    let _ = write!(link, "{}", node.endpoint.authority());
    let query = render_query(&query_parameters(node));
    if !query.is_empty() {
        let _ = write!(link, "?{query}");
    }
    if !node.name.is_empty() {
        let _ = write!(link, "#{}", escape_query(&node.name));
    }
    Ok(link)
}

fn credentials(username: Option<&str>, password: Option<&Secret>) -> String {
    match (username, password) {
        (Some(user), Some(pass)) => {
            format!(
                "{}:{}",
                escape_userinfo(user),
                escape_userinfo(pass.expose())
            )
        }
        (Some(user), None) => escape_userinfo(user),
        _ => String::new(),
    }
}

fn vmess_link(node: &Node) -> Result<String, ExportError> {
    let ProtocolSettings::Vmess(vmess) = &node.protocol else {
        return Err(ExportError::NoStandardFormat { protocol: "vmess" });
    };
    if vmess.id.is_empty() {
        return Err(ExportError::EmptyField { field: "id" });
    }

    let (net, host, path, header_type) = match &node.transport {
        Transport::Raw(raw) => (
            "tcp",
            raw.host.first().cloned().unwrap_or_default(),
            raw.path.clone().unwrap_or_default(),
            raw.header_type.clone().unwrap_or_else(|| "none".to_owned()),
        ),
        Transport::Websocket(ws) => (
            "ws",
            ws.host.clone().unwrap_or_default(),
            ws.path.clone(),
            "none".to_owned(),
        ),
        Transport::Grpc(g) => (
            "grpc",
            String::new(),
            g.service_name.clone(),
            "none".to_owned(),
        ),
        Transport::Xhttp(x) => (
            "xhttp",
            x.host.clone().unwrap_or_default(),
            x.path.clone().unwrap_or_default(),
            "none".to_owned(),
        ),
        Transport::HttpUpgrade(hu) => (
            "httpupgrade",
            hu.host.clone().unwrap_or_default(),
            hu.path.clone(),
            "none".to_owned(),
        ),
        Transport::Mkcp(kcp) => (
            "kcp",
            String::new(),
            String::new(),
            kcp.header_type.clone().unwrap_or_else(|| "none".to_owned()),
        ),
    };

    let (tls, sni, alpn, fingerprint) = match &node.security {
        TransportSecurity::None => (String::new(), String::new(), String::new(), String::new()),
        TransportSecurity::Tls(t) => (
            "tls".to_owned(),
            t.server_name.clone().unwrap_or_default(),
            t.alpn.join(","),
            t.fingerprint.clone().unwrap_or_default(),
        ),
        TransportSecurity::Reality(r) => (
            "reality".to_owned(),
            r.server_name.clone().unwrap_or_default(),
            String::new(),
            r.fingerprint.clone().unwrap_or_default(),
        ),
    };

    let payload = serde_json::json!({
        "v": "2",
        "ps": node.name,
        "add": node.endpoint.address,
        "port": node.endpoint.port.to_string(),
        "id": vmess.id.expose(),
        "aid": vmess.alter_id.to_string(),
        "scy": vmess.security,
        "net": net,
        "type": header_type,
        "host": host,
        "path": path,
        "tls": tls,
        "sni": sni,
        "alpn": alpn,
        "fp": fingerprint,
    });
    Ok(format!(
        "vmess://{}",
        encode_standard(payload.to_string().as_bytes())
    ))
}

fn shadowsocks_link(node: &Node) -> Result<String, ExportError> {
    let ProtocolSettings::Shadowsocks(ss) = &node.protocol else {
        return Err(ExportError::NoStandardFormat {
            protocol: "shadowsocks",
        });
    };
    if ss.method.is_empty() {
        return Err(ExportError::EmptyField { field: "method" });
    }
    // SIP002 form: the userinfo is base64, the endpoint is plain.
    let userinfo = crate::b64::encode_url_safe_no_pad(
        format!("{}:{}", ss.method, ss.password.expose()).as_bytes(),
    );
    let mut link = format!("ss://{userinfo}@{}", node.endpoint.authority());
    let extras: Vec<(String, String)> = node
        .extra
        .iter()
        .map(|(key, value)| {
            let text = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            (key.clone(), text)
        })
        .collect();
    let query = render_query(&extras);
    if !query.is_empty() {
        let _ = write!(link, "?{query}");
    }
    if !node.name.is_empty() {
        let _ = write!(link, "#{}", escape_query(&node.name));
    }
    Ok(link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ImportedEntry, parse_uri};
    use xraytui_domain::NodeSource;

    fn round_trip(link: &str) -> (Node, Node) {
        let first = parse_uri(link)
            .expect("first parse")
            .into_node()
            .expect("supported");
        let exported = to_share_link(&first).expect("export");
        let second = parse_uri(exported.expose())
            .expect("second parse")
            .into_node()
            .expect("supported");
        (first, second)
    }

    #[test]
    fn vless_round_trips() {
        let (a, b) = round_trip(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443\
             ?type=ws&path=%2Fray&security=tls&sni=cdn.example.com&flow=xtls-rprx-vision#HK%2001",
        );
        assert_eq!(a.canonical_identity(), b.canonical_identity());
        assert_eq!(a.name, b.name);
        assert_eq!(a.transport, b.transport);
        assert_eq!(a.security, b.security);
    }

    #[test]
    fn vless_reality_round_trips() {
        let (a, b) = round_trip(
            "vless://uuid@1.2.3.4:443?security=reality&pbk=PUB&sid=ab12&spx=%2F&fp=chrome&type=grpc\
             &serviceName=GunService#R",
        );
        assert_eq!(a.canonical_identity(), b.canonical_identity());
        assert_eq!(a.security, b.security);
        assert_eq!(a.transport, b.transport);
    }

    #[test]
    fn trojan_round_trips() {
        let (a, b) = round_trip("trojan://pw@h.example:443?type=tcp&security=tls&sni=h.example#T");
        assert_eq!(a.canonical_identity(), b.canonical_identity());
    }

    #[test]
    fn vmess_round_trips() {
        let payload = serde_json::json!({
            "v": "2", "ps": "JP 02", "add": "jp.example.com", "port": "443",
            "id": "22222222-3333-4444-5555-666666666666", "aid": "0", "scy": "auto",
            "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/vm", "tls": "tls"
        });
        let link = format!(
            "vmess://{}",
            encode_standard(payload.to_string().as_bytes())
        );
        let (a, b) = round_trip(&link);
        assert_eq!(a.canonical_identity(), b.canonical_identity());
        assert_eq!(a.name, b.name);
        assert_eq!(a.endpoint, b.endpoint);
    }

    #[test]
    fn shadowsocks_round_trips() {
        let userinfo = crate::b64::encode_url_safe_no_pad(b"aes-256-gcm:secret");
        let (a, b) = round_trip(&format!("ss://{userinfo}@ss.example:8388#SS"));
        assert_eq!(a.canonical_identity(), b.canonical_identity());
        assert_eq!(a.name, b.name);
    }

    #[test]
    fn socks_round_trips_with_credentials() {
        let (a, b) = round_trip("socks://user:pass@127.0.0.1:1080#S");
        assert_eq!(a.canonical_identity(), b.canonical_identity());
    }

    #[test]
    fn unknown_parameters_survive_the_round_trip() {
        let (_, b) = round_trip("vless://uuid@h.example:443?type=tcp&futureField=42#N");
        assert_eq!(
            b.extra.get("futureField"),
            Some(&serde_json::Value::String("42".into()))
        );
    }

    #[test]
    fn names_with_spaces_and_unicode_survive() {
        for name in ["HK%2001", "%E9%A6%99%E6%B8%AF", "a%26b", "a%23b"] {
            let link = format!("vless://uuid@h.example:443?type=tcp#{name}");
            let (a, b) = round_trip(&link);
            assert_eq!(a.name, b.name, "name {name}");
        }
    }

    #[test]
    fn protocols_without_a_standard_format_are_refused_clearly() {
        let node = Node::new(
            xraytui_domain::NodeId::new("w").expect("valid"),
            "W",
            NodeSource::Manual,
            xraytui_domain::Endpoint::new("h.example", 1),
            ProtocolSettings::Wireguard(Box::new(xraytui_domain::WireguardSettings {
                secret_key: Secret::new("k"),
                address: vec![],
                peers: vec![],
                mtu: None,
                reserved: vec![],
                domain_strategy: None,
            })),
        );
        let error = to_share_link(&node).expect_err("must refuse");
        assert_eq!(
            error,
            ExportError::NoStandardFormat {
                protocol: "wireguard"
            }
        );
    }

    #[test]
    fn exported_links_are_secrets_not_plain_strings() {
        let node = parse_uri("vless://uuid@h.example:443?type=tcp#N")
            .expect("parse")
            .into_node()
            .expect("supported");
        let link = to_share_link(&node).expect("export");
        assert_eq!(format!("{link:?}"), "Secret(<redacted>)");
        assert!(link.expose().starts_with("vless://"));
    }

    #[test]
    fn every_supported_protocol_either_exports_or_says_why() {
        let links = [
            "vless://uuid@h.example:443?type=tcp#a",
            "trojan://pw@h.example:443#b",
            "socks://127.0.0.1:1080#c",
            "http-proxy://127.0.0.1:8080#d",
        ];
        for link in links {
            let entry = parse_uri(link).expect("parse");
            let ImportedEntry::Supported(node) = entry else {
                panic!("{link} should be supported");
            };
            to_share_link(&node).unwrap_or_else(|e| panic!("{link}: {e}"));
        }
    }
}
