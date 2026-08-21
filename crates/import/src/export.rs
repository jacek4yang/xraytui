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

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use xraytui_domain::{Node, ProtocolSettings, Transport, TransportSecurity};
use xraytui_secrets::Secret;

use crate::b64::encode_standard;
use crate::{ExportError, MAX_LINK_BYTES};

/// How faithfully a generated representation preserves the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportFidelity {
    /// Every connection-critical field is represented directly.
    Lossless,
    /// The syntax differs, but mainstream importers are expected to create an
    /// equivalent connection.
    Compatible,
    /// Meaningful fields were omitted after an explicit opt-in.
    Lossy,
    /// No safe standard representation exists.
    Unsupported,
}

/// VMess has two widely deployed encodings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VmessShareFormat {
    /// Prefer classic v2rayN JSON for broad compatibility, and use the modern
    /// authority form when classic JSON cannot represent standardized fields.
    #[default]
    Auto,
    /// Base64-encoded v2rayN JSON.
    Classic,
    /// `vmess://uuid@host:port?...` from the Xray share-link proposal.
    Standard,
}

/// Share-link generation policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShareOptions {
    /// Permit omission of fields that no standard link can carry.
    pub allow_lossy: bool,
    /// VMess dialect selection.
    pub vmess_format: VmessShareFormat,
}

/// A generated link plus an explicit fidelity classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareExport {
    /// Credential-bearing link. Debug output is always redacted.
    pub link: Secret,
    /// Fidelity of this representation.
    pub fidelity: ExportFidelity,
    /// Non-secret field names or compatibility notes.
    pub notes: Vec<String>,
}

fn escape_query(value: &str) -> String {
    // Over-encoding unreserved punctuation is harmless and is preferable to
    // missing a reserved byte added by a future JSON-shaped field.
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn escape_userinfo(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

/// Turn a node back into a share link in its community-standard format.
///
/// # Errors
/// Returns [`ExportError::Unrepresentable`] when a modeled node cannot fit its
/// ecosystem format, and [`ExportError::EmptyField`] when a required field is
/// missing.
pub fn to_share_link(node: &Node) -> Result<Secret, ExportError> {
    export_share_link(node, ShareOptions::default()).map(|export| export.link)
}

/// Turn a node into a standard ecosystem share link and report its fidelity.
///
/// The default policy refuses lossy output. Set [`ShareOptions::allow_lossy`]
/// only in an explicit user action; it must never be used as a fallback.
///
/// # Errors
/// Returns [`ExportError`] when no standard exists, a required value is empty,
/// or meaningful settings would be omitted without an explicit opt-in.
pub fn export_share_link(node: &Node, options: ShareOptions) -> Result<ShareExport, ExportError> {
    let mut notes = lossy_features(node);
    if matches!(options.vmess_format, VmessShareFormat::Classic)
        && matches!(node.protocol, ProtocolSettings::Vmess(_))
    {
        notes.extend(vmess_classic_lossy_features(node));
    }
    if matches!(options.vmess_format, VmessShareFormat::Standard)
        && matches!(node.protocol, ProtocolSettings::Vmess(_))
    {
        notes.extend(vmess_standard_lossy_features(node));
    }
    if matches!(options.vmess_format, VmessShareFormat::Auto)
        && !vmess_classic_lossy_features(node).is_empty()
        && matches!(node.protocol, ProtocolSettings::Vmess(_))
    {
        notes.extend(vmess_standard_lossy_features(node));
    }
    if !notes.is_empty() && !options.allow_lossy {
        return Err(ExportError::LossyRefused {
            features: notes.join(", "),
        });
    }

    let (link, mut fidelity) = match &node.protocol {
        ProtocolSettings::Vless(_) => (authority_link(node, "vless")?, ExportFidelity::Lossless),
        ProtocolSettings::Trojan(_) => (authority_link(node, "trojan")?, ExportFidelity::Lossless),
        ProtocolSettings::Socks(_) => (authority_link(node, "socks")?, ExportFidelity::Compatible),
        ProtocolSettings::Http(_) => (
            authority_link(node, "http-proxy")?,
            ExportFidelity::Compatible,
        ),
        ProtocolSettings::Vmess(_) => vmess_link(node, options.vmess_format)?,
        ProtocolSettings::Shadowsocks(_) => (shadowsocks_link(node)?, ExportFidelity::Lossless),
        ProtocolSettings::Wireguard(_) => (wireguard_link(node)?, ExportFidelity::Lossless),
        ProtocolSettings::Hysteria(_) => (hysteria2_link(node)?, ExportFidelity::Lossless),
    };
    if !notes.is_empty() {
        fidelity = ExportFidelity::Lossy;
    }
    if link.len() > MAX_LINK_BYTES {
        return Err(ExportError::TooLarge {
            limit: MAX_LINK_BYTES,
        });
    }
    notes.shrink_to_fit();
    Ok(ShareExport {
        link: Secret::new(link),
        fidelity,
        notes,
    })
}

fn lossy_features(node: &Node) -> Vec<String> {
    let mut features = Vec::new();
    if node.mux.enabled {
        features.push("mux".to_owned());
    }
    if node.sockopt != Default::default() {
        features.push("socket options".to_owned());
    }
    match &node.security {
        TransportSecurity::Tls(tls) => {
            if tls.ech_force_query.is_some() {
                features.push("TLS echForceQuery".to_owned());
            }
            if tls.cipher_suites.is_some() {
                features.push("TLS cipherSuites".to_owned());
            }
        }
        TransportSecurity::None | TransportSecurity::Reality(_) => {}
    }
    if let Transport::Websocket(ws) = &node.transport
        && ws
            .headers
            .keys()
            .any(|key| !key.eq_ignore_ascii_case("host"))
    {
        features.push("WebSocket custom headers".to_owned());
    }
    match &node.protocol {
        ProtocolSettings::Shadowsocks(ss) => {
            if ss.uot || ss.uot_version.is_some() {
                features.push("Shadowsocks UDP-over-TCP".to_owned());
            }
            if !matches!(node.transport, Transport::Raw(_))
                || !matches!(node.security, TransportSecurity::None)
                || node.finalmask.is_some()
            {
                features.push("Shadowsocks stream settings".to_owned());
            }
        }
        ProtocolSettings::Socks(socks) => {
            if !socks.udp {
                features.push("SOCKS UDP disabled".to_owned());
            }
            if !matches!(node.transport, Transport::Raw(ref raw) if *raw == Default::default())
                || !matches!(node.security, TransportSecurity::None)
                || node.finalmask.is_some()
            {
                features.push("SOCKS stream settings".to_owned());
            }
        }
        ProtocolSettings::Wireguard(wireguard) => {
            if wireguard.peers.len() > 1 {
                features.push("additional WireGuard peers".to_owned());
            }
            if wireguard.address.is_empty() {
                features.push("WireGuard implicit local address".to_owned());
            }
            if let Some(peer) = wireguard.peers.first() {
                let default_routes = peer.allowed_ips.is_empty()
                    || (peer.allowed_ips.len() == 2
                        && peer.allowed_ips.iter().any(|ip| ip == "0.0.0.0/0")
                        && peer.allowed_ips.iter().any(|ip| ip == "::0/0"));
                if !default_routes {
                    features.push("WireGuard allowed IPs".to_owned());
                }
                if peer.keep_alive.is_some_and(|seconds| seconds != 0) {
                    features.push("WireGuard persistent keepalive".to_owned());
                }
            }
            if wireguard
                .domain_strategy
                .as_ref()
                .is_some_and(|strategy| !strategy.eq_ignore_ascii_case("forceip"))
            {
                features.push("WireGuard domain strategy".to_owned());
            }
            if !matches!(node.transport, Transport::Raw(_))
                || !matches!(node.security, TransportSecurity::None)
                || node.finalmask.is_some()
            {
                features.push("WireGuard stream settings".to_owned());
            }
        }
        ProtocolSettings::Http(_) => {
            if !matches!(node.transport, Transport::Raw(ref raw) if *raw == Default::default())
                || !matches!(node.security, TransportSecurity::None)
                || node.finalmask.is_some()
            {
                features.push("HTTP proxy stream settings".to_owned());
            }
        }
        ProtocolSettings::Vless(vless) => {
            if vless.level.is_some() {
                features.push("VLESS user level".to_owned());
            }
        }
        ProtocolSettings::Vmess(vmess) => {
            if vmess.level.is_some() {
                features.push("VMess user level".to_owned());
            }
        }
        ProtocolSettings::Hysteria(hysteria) => {
            if hysteria.up.is_some() || hysteria.down.is_some() {
                features.push("Hysteria bandwidth hints".to_owned());
            }
            if !matches!(node.transport, Transport::Raw(ref raw) if raw.host.is_empty()
                && raw.path.is_none()
                && raw.header_type.as_deref().is_none_or(|header| header == "none"))
            {
                features.push("Hysteria alternate stream transport".to_owned());
            }
            if hysteria
                .unrepresented_finalmask(node.finalmask.as_ref())
                .is_some()
            {
                features.push("Hysteria custom finalmask".to_owned());
            }
            if let TransportSecurity::Tls(tls) = &node.security {
                if tls.fingerprint.is_some() {
                    features.push("Hysteria TLS fingerprint".to_owned());
                }
                if tls.verify_peer_cert_by_name.is_some() {
                    features.push("Hysteria TLS verified certificate names".to_owned());
                }
            }
        }
        ProtocolSettings::Trojan(_) => {}
    }
    features
}

/// Query parameters describing this node's transport and security.
fn query_parameters(node: &Node) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    let network = match node.transport {
        Transport::Raw(_) => "tcp",
        _ => node.transport.xray_network(),
    };
    params.push(("type".to_owned(), network.to_owned()));

    match &node.transport {
        Transport::Raw(raw) => {
            if let Some(header) = &raw.header_type {
                params.push(("headerType".to_owned(), header.clone()));
            }
            if !raw.host.is_empty() {
                params.push(("host".to_owned(), raw.host.join(",")));
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
            if let Some(extra) = &x.extra {
                params.push(("extra".to_owned(), extra.to_string()));
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
            let header_host = ws
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("host"))
                .map(|(_, value)| value);
            if let Some(host) = ws.host.as_ref().or(header_host) {
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
            if let Some(mtu) = kcp.mtu {
                params.push(("mtu".to_owned(), mtu.to_string()));
            }
            if let Some(tti) = kcp.tti {
                params.push(("tti".to_owned(), tti.to_string()));
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
            if tls.allow_insecure {
                params.push(("insecure".to_owned(), "1".to_owned()));
                params.push(("allowInsecure".to_owned(), "1".to_owned()));
            }
            if let Some(ech) = &tls.ech_config_list {
                params.push(("ech".to_owned(), ech.clone()));
            }
            if let Some(pins) = &tls.pinned_peer_cert_sha256 {
                params.push(("pcs".to_owned(), pins.clone()));
            }
            if let Some(names) = &tls.verify_peer_cert_by_name {
                params.push(("vcn".to_owned(), names.clone()));
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
                params.push(("pqv".to_owned(), mldsa.expose().to_owned()));
            }
        }
    }

    if let Some(finalmask) = &node.finalmask {
        params.push(("fm".to_owned(), finalmask.to_string()));
    }

    if let ProtocolSettings::Vless(vless) = &node.protocol {
        if !vless.flow.is_empty() {
            params.push(("flow".to_owned(), vless.flow.clone()));
        }
        params.push(("encryption".to_owned(), vless.encryption.clone()));
    } else if let ProtocolSettings::Vmess(vmess) = &node.protocol {
        params.push(("encryption".to_owned(), vmess.security.clone()));
    } else if let ProtocolSettings::Trojan(trojan) = &node.protocol
        && !trojan.flow.is_empty()
    {
        params.push(("flow".to_owned(), trojan.flow.clone()));
    }

    // Anything the importer did not understand goes back out untouched.
    for (key, value) in &node.extra {
        if params.iter().any(|(existing, _)| existing == key) {
            continue;
        }
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
        ProtocolSettings::Vmess(v) => {
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

fn vmess_link(
    node: &Node,
    format: VmessShareFormat,
) -> Result<(String, ExportFidelity), ExportError> {
    let selected = match format {
        VmessShareFormat::Auto if vmess_classic_lossy_features(node).is_empty() => {
            VmessShareFormat::Classic
        }
        VmessShareFormat::Auto => VmessShareFormat::Standard,
        explicit => explicit,
    };
    match selected {
        VmessShareFormat::Classic => Ok((vmess_classic_link(node)?, ExportFidelity::Compatible)),
        VmessShareFormat::Standard => {
            Ok((authority_link(node, "vmess")?, ExportFidelity::Lossless))
        }
        // The guard above always resolves `Auto`; retaining a safe fallback
        // keeps this hostile-boundary crate free of panic paths.
        VmessShareFormat::Auto => Ok((vmess_classic_link(node)?, ExportFidelity::Compatible)),
    }
}

fn vmess_classic_lossy_features(node: &Node) -> Vec<String> {
    let mut features = Vec::new();
    if node.finalmask.is_some() {
        features.push("VMess finalmask".to_owned());
    }
    if !node.extra.is_empty() {
        features.push("VMess extension parameters".to_owned());
    }
    if let Transport::Xhttp(xhttp) = &node.transport
        && xhttp.extra.is_some()
    {
        features.push("VMess XHTTP extra".to_owned());
    }
    if let Transport::Mkcp(kcp) = &node.transport
        && (kcp.mtu.is_some() || kcp.tti.is_some())
    {
        features.push("VMess mKCP tuning".to_owned());
    }
    if let Transport::Raw(raw) = &node.transport
        && raw.host.len() > 1
    {
        features.push("VMess RAW additional Host values".to_owned());
    }
    match &node.security {
        TransportSecurity::Reality(_) => features.push("VMess REALITY fields".to_owned()),
        TransportSecurity::Tls(tls) if tls.ech_config_list.is_some() => {
            features.push("VMess TLS ECH".to_owned());
        }
        TransportSecurity::None | TransportSecurity::Tls(_) => {}
    }
    features
}

fn vmess_standard_lossy_features(node: &Node) -> Vec<String> {
    match &node.protocol {
        ProtocolSettings::Vmess(vmess) if vmess.alter_id != 0 => {
            vec!["VMess alterId".to_owned()]
        }
        _ => Vec::new(),
    }
}

fn vmess_classic_link(node: &Node) -> Result<String, ExportError> {
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
            ws.host
                .clone()
                .or_else(|| {
                    ws.headers
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case("host"))
                        .map(|(_, value)| value.clone())
                })
                .unwrap_or_default(),
            ws.path.clone(),
            "none".to_owned(),
        ),
        Transport::Grpc(g) => (
            "grpc",
            g.authority.clone().unwrap_or_default(),
            g.service_name.clone(),
            if g.multi_mode { "multi" } else { "gun" }.to_owned(),
        ),
        Transport::Xhttp(x) => (
            "xhttp",
            x.host.clone().unwrap_or_default(),
            x.path.clone().unwrap_or_default(),
            x.mode.clone().unwrap_or_default(),
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
            kcp.seed
                .as_ref()
                .map(|seed| seed.expose().to_owned())
                .unwrap_or_default(),
            kcp.header_type.clone().unwrap_or_else(|| "none".to_owned()),
        ),
    };

    let (tls, sni, alpn, fingerprint, insecure, vcn, pcs) = match &node.security {
        TransportSecurity::None => (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ),
        TransportSecurity::Tls(t) => (
            "tls".to_owned(),
            t.server_name.clone().unwrap_or_default(),
            t.alpn.join(","),
            t.fingerprint.clone().unwrap_or_default(),
            if t.allow_insecure { "1" } else { "0" }.to_owned(),
            t.verify_peer_cert_by_name.clone().unwrap_or_default(),
            t.pinned_peer_cert_sha256.clone().unwrap_or_default(),
        ),
        TransportSecurity::Reality(r) => (
            "reality".to_owned(),
            r.server_name.clone().unwrap_or_default(),
            String::new(),
            r.fingerprint.clone().unwrap_or_default(),
            String::new(),
            String::new(),
            String::new(),
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
        "insecure": insecure,
        "vcn": vcn,
        "pcs": pcs,
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

fn wireguard_link(node: &Node) -> Result<String, ExportError> {
    let ProtocolSettings::Wireguard(wireguard) = &node.protocol else {
        return Err(ExportError::NoStandardFormat {
            protocol: "wireguard",
        });
    };
    if wireguard.secret_key.is_empty() {
        return Err(ExportError::EmptyField {
            field: "secret key",
        });
    }
    let peer = wireguard
        .peers
        .first()
        .ok_or(ExportError::Unrepresentable {
            protocol: "wireguard",
            feature: "a node without a peer",
        })?;
    if peer.public_key.is_empty() {
        return Err(ExportError::EmptyField {
            field: "peer public key",
        });
    }
    if !wireguard.reserved.is_empty() && wireguard.reserved.len() != 3 {
        return Err(ExportError::Unrepresentable {
            protocol: "wireguard",
            feature: "a reserved-byte list whose length is not three",
        });
    }
    let endpoint = parse_wireguard_endpoint(&peer.endpoint)?;
    let mut params = vec![("publickey".to_owned(), peer.public_key.clone())];
    if let Some(pre_shared_key) = &peer.pre_shared_key {
        params.push((
            "presharedkey".to_owned(),
            pre_shared_key.expose().to_owned(),
        ));
    }
    if !wireguard.reserved.is_empty() {
        params.push((
            "reserved".to_owned(),
            wireguard
                .reserved
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    if !wireguard.address.is_empty() {
        params.push(("address".to_owned(), wireguard.address.join(",")));
    }
    if let Some(mtu) = wireguard.mtu {
        params.push(("mtu".to_owned(), mtu.to_string()));
    }
    for (key, value) in &node.extra {
        if params.iter().any(|(existing, _)| existing == key) {
            continue;
        }
        params.push((
            key.clone(),
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string()),
        ));
    }

    let mut link = format!(
        "wireguard://{}@{}",
        escape_userinfo(wireguard.secret_key.expose()),
        endpoint.authority()
    );
    let query = render_query(&params);
    if !query.is_empty() {
        let _ = write!(link, "?{query}");
    }
    if !node.name.is_empty() {
        let _ = write!(link, "#{}", escape_query(&node.name));
    }
    Ok(link)
}

fn hysteria2_link(node: &Node) -> Result<String, ExportError> {
    let ProtocolSettings::Hysteria(hysteria) = &node.protocol else {
        return Err(ExportError::NoStandardFormat {
            protocol: "hysteria",
        });
    };
    if hysteria.auth.is_empty() {
        return Err(ExportError::EmptyField { field: "auth" });
    }
    let TransportSecurity::Tls(tls) = &node.security else {
        return Err(ExportError::Unrepresentable {
            protocol: "hysteria2",
            feature: "a node without TLS",
        });
    };

    let mut params = vec![("security".to_owned(), "tls".to_owned())];
    if let Some(sni) = &tls.server_name {
        params.push(("sni".to_owned(), sni.clone()));
    }
    if !tls.alpn.is_empty() {
        params.push(("alpn".to_owned(), tls.alpn.join(",")));
    }
    if tls.allow_insecure {
        params.push(("insecure".to_owned(), "1".to_owned()));
    }
    if let Some(ech) = &tls.ech_config_list {
        params.push(("ech".to_owned(), ech.clone()));
    }
    if let Some(pin) = &tls.pinned_peer_cert_sha256 {
        params.push(("pinSHA256".to_owned(), pin.clone()));
    }
    if let Some(obfs) = &hysteria.obfs {
        params.push(("obfs".to_owned(), "salamander".to_owned()));
        params.push(("obfs-password".to_owned(), obfs.expose().to_owned()));
    }
    if let Some(ports) = &hysteria.port_hopping {
        params.push(("mport".to_owned(), ports.replace(':', "-")));
    }
    for (key, value) in &node.extra {
        if params.iter().any(|(existing, _)| existing == key) {
            continue;
        }
        params.push((
            key.clone(),
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string()),
        ));
    }

    let mut link = format!(
        "hysteria2://{}@{}?{}",
        escape_userinfo(hysteria.auth.expose()),
        node.endpoint.authority(),
        render_query(&params)
    );
    if !node.name.is_empty() {
        let _ = write!(link, "#{}", escape_query(&node.name));
    }
    Ok(link)
}

fn parse_wireguard_endpoint(endpoint: &str) -> Result<xraytui_domain::Endpoint, ExportError> {
    let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(ExportError::Unrepresentable {
            protocol: "wireguard",
            feature: "an invalid peer endpoint",
        })?;
        let port = tail.strip_prefix(':').ok_or(ExportError::Unrepresentable {
            protocol: "wireguard",
            feature: "a peer endpoint without a port",
        })?;
        (host, port)
    } else {
        endpoint
            .rsplit_once(':')
            .ok_or(ExportError::Unrepresentable {
                protocol: "wireguard",
                feature: "a peer endpoint without a port",
            })?
    };
    let port =
        port.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(ExportError::Unrepresentable {
                protocol: "wireguard",
                feature: "an invalid peer port",
            })?;
    if host.is_empty() {
        return Err(ExportError::Unrepresentable {
            protocol: "wireguard",
            feature: "an empty peer endpoint",
        });
    }
    Ok(xraytui_domain::Endpoint::new(host, port))
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
    fn modern_vless_reality_xhttp_fields_round_trip_losslessly() {
        let link = "vless://11111111-2222-3333-4444-555555555555@[2001:db8::10]:443\
                    ?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com\
                    &fp=chrome&pbk=PUBLICKEY&sid=0123456789abcdef&spx=%2Fdocs&pqv=MLDSA\
                    &type=xhttp&host=cdn.example.com&path=%2Fvery%2Flong%2Fpath&mode=auto\
                    &extra=%7B%22scMaxEachPostBytes%22%3A1000000%2C%22noGRPCHeader%22%3Atrue%7D\
                    &fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22padding%22%7D%5D%7D\
                    #%E9%A6%99%E6%B8%AF%20XHTTP";
        let first = parse_uri(link)
            .expect("import")
            .into_node()
            .expect("supported");
        let exported = export_share_link(&first, ShareOptions::default()).expect("export");
        assert_eq!(exported.fidelity, ExportFidelity::Lossless);
        assert!(exported.link.expose().contains("type=xhttp"));
        assert!(exported.link.expose().contains("pqv=MLDSA"));
        assert!(exported.link.expose().contains("fm=%7B"));
        let second = parse_uri(exported.link.expose())
            .expect("re-import")
            .into_node()
            .expect("supported");
        assert_eq!(first.canonical_identity(), second.canonical_identity());
        assert_eq!(first.finalmask, second.finalmask);
        assert_eq!(first.transport, second.transport);
        assert_eq!(first.security, second.security);
        assert_eq!(first.name, second.name);
    }

    #[test]
    fn tls_ech_pins_verified_names_and_mkcp_tuning_round_trip() {
        let link = "vless://uuid@example.com:443?encryption=none&type=kcp&headerType=none\
                    &seed=synthetic&mtu=1200&tti=50&security=tls&sni=edge.example.com\
                    &alpn=h2%2Chttp%2F1.1&fp=chrome&ech=ECHDATA&pcs=0123&vcn=edge.example.com#TLS";
        let (first, second) = round_trip(link);
        assert_eq!(first.canonical_identity(), second.canonical_identity());
        assert_eq!(first.transport, second.transport);
        assert_eq!(first.security, second.security);
    }

    #[test]
    fn vmess_auto_uses_standard_form_when_classic_would_drop_modern_fields() {
        let link = "vmess://11111111-2222-3333-4444-555555555555@example.com:443\
                    ?encryption=auto&type=xhttp&path=%2Fx&mode=auto\
                    &extra=%7B%22noSSEHeader%22%3Atrue%7D&security=tls&sni=example.com#VM";
        let node = parse_uri(link)
            .expect("import")
            .into_node()
            .expect("supported");
        let export = export_share_link(&node, ShareOptions::default()).expect("export");
        assert_eq!(export.fidelity, ExportFidelity::Lossless);
        assert!(export.link.expose().contains('@'));
        let imported = parse_uri(export.link.expose())
            .expect("re-import")
            .into_node()
            .expect("supported");
        assert_eq!(node.canonical_identity(), imported.canonical_identity());
    }

    #[test]
    fn explicit_classic_vmess_refuses_modern_field_loss() {
        let node = parse_uri(
            "vmess://uuid@example.com:443?encryption=auto&type=xhttp\
             &extra=%7B%22noSSEHeader%22%3Atrue%7D&security=tls#VM",
        )
        .expect("import")
        .into_node()
        .expect("supported");
        let error = export_share_link(
            &node,
            ShareOptions {
                allow_lossy: false,
                vmess_format: VmessShareFormat::Classic,
            },
        )
        .expect_err("must refuse");
        assert!(matches!(error, ExportError::LossyRefused { .. }));
    }

    #[test]
    fn lossy_export_requires_opt_in_and_reports_fidelity() {
        let mut node = parse_uri("vless://uuid@example.com:443?encryption=none&type=tcp#N")
            .expect("import")
            .into_node()
            .expect("supported");
        node.sockopt.interface = Some("wg0".into());
        assert!(matches!(
            export_share_link(&node, ShareOptions::default()),
            Err(ExportError::LossyRefused { .. })
        ));
        let export = export_share_link(
            &node,
            ShareOptions {
                allow_lossy: true,
                ..ShareOptions::default()
            },
        )
        .expect("explicit lossy export");
        assert_eq!(export.fidelity, ExportFidelity::Lossy);
        assert_eq!(export.notes, vec!["socket options"]);
    }

    #[test]
    fn every_modeled_field_without_a_share_parameter_is_reported_as_lossy() {
        let mut vless = parse_uri("vless://uuid@example.com:443?type=tcp#V")
            .expect("import")
            .into_node()
            .expect("supported");
        let ProtocolSettings::Vless(settings) = &mut vless.protocol else {
            panic!("VLESS");
        };
        settings.level = Some(7);
        assert!(matches!(
            export_share_link(&vless, ShareOptions::default()),
            Err(ExportError::LossyRefused { ref features }) if features.contains("user level")
        ));

        let mut socks = parse_uri("socks://socks.example:1080#S")
            .expect("import")
            .into_node()
            .expect("supported");
        socks.security = TransportSecurity::Tls(xraytui_domain::TlsSettings {
            server_name: Some("socks.example".to_owned()),
            ..Default::default()
        });
        assert!(matches!(
            export_share_link(&socks, ShareOptions::default()),
            Err(ExportError::LossyRefused { ref features }) if features.contains("SOCKS stream settings")
        ));

        let mut http = parse_uri("http-proxy://http.example:8080#H")
            .expect("import")
            .into_node()
            .expect("supported");
        http.finalmask = Some(serde_json::json!({ "tcp": [{ "type": "sudoku" }] }));
        assert!(matches!(
            export_share_link(&http, ShareOptions::default()),
            Err(ExportError::LossyRefused { ref features }) if features.contains("HTTP proxy stream settings")
        ));
    }

    #[test]
    fn standard_vmess_never_silently_drops_alter_id() {
        let payload = serde_json::json!({
            "v": "2", "ps": "legacy", "add": "vmess.example", "port": "443",
            "id": "22222222-3333-4444-5555-666666666666", "aid": "64",
            "scy": "auto", "net": "tcp", "type": "none"
        });
        let node = parse_uri(&format!(
            "vmess://{}",
            encode_standard(payload.to_string().as_bytes())
        ))
        .expect("import")
        .into_node()
        .expect("preserved node");
        assert!(matches!(
            export_share_link(
                &node,
                ShareOptions {
                    vmess_format: VmessShareFormat::Standard,
                    ..Default::default()
                }
            ),
            Err(ExportError::LossyRefused { ref features }) if features.contains("alterId")
        ));
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
    fn wireguard_from_v2rayn_and_v2rayng_round_trips_losslessly() {
        let link = "wireguard://PRIVATE%2BKEY%3D@[2001:db8::1]:51820\
                    ?publickey=PUBLIC%2BKEY%3D&presharedkey=PSK%2BVALUE%3D\
                    &reserved=1%2C2%2C3&address=172.16.0.2%2F32%2Cfd00%3A%3A2%2F128\
                    &mtu=1420#WG%20%E6%97%A5%E6%9C%AC";
        let first = parse_uri(link)
            .expect("import")
            .into_node()
            .expect("supported");
        let exported = export_share_link(&first, ShareOptions::default()).expect("export");
        assert_eq!(exported.fidelity, ExportFidelity::Lossless);
        assert!(exported.link.expose().starts_with("wireguard://"));
        assert!(exported.link.expose().contains("publickey="));
        let second = parse_uri(exported.link.expose())
            .expect("re-import")
            .into_node()
            .expect("supported");
        assert_eq!(first.canonical_identity(), second.canonical_identity());
        assert_eq!(first.protocol, second.protocol);
        assert_eq!(first.endpoint, second.endpoint);
    }

    #[test]
    fn wireguard_non_default_peer_routes_require_lossy_opt_in() {
        let mut node = parse_uri(
            "wireguard://private@wg.example:51820?publickey=public\
             &address=172.16.0.2%2F32#WG",
        )
        .expect("import")
        .into_node()
        .expect("supported");
        let ProtocolSettings::Wireguard(wireguard) = &mut node.protocol else {
            panic!("expected WireGuard");
        };
        wireguard.peers[0].allowed_ips = vec!["10.0.0.0/8".to_owned()];
        let error = export_share_link(&node, ShareOptions::default()).expect_err("must refuse");
        assert!(
            matches!(error, ExportError::LossyRefused { ref features } if features.contains("allowed IPs"))
        );
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
    fn hysteria_without_required_tls_is_refused_clearly() {
        let node = Node::new(
            xraytui_domain::NodeId::new("h").expect("valid"),
            "H",
            NodeSource::Manual,
            xraytui_domain::Endpoint::new("h.example", 1),
            ProtocolSettings::Hysteria(xraytui_domain::HysteriaSettings {
                auth: Secret::new("synthetic-auth"),
                obfs: None,
                up: None,
                down: None,
                port_hopping: None,
            }),
        );
        let error = to_share_link(&node).expect_err("must refuse");
        assert_eq!(
            error,
            ExportError::Unrepresentable {
                protocol: "hysteria2",
                feature: "a node without TLS",
            }
        );
    }

    #[test]
    fn xray_native_hysteria2_round_trips_through_the_de_facto_link() {
        let link = "hysteria2://synthetic-auth@hy.example:443?security=tls&sni=edge.example\
                    &alpn=h3&obfs=salamander&obfs-password=synthetic-obfs\
                    &mport=20000-30000%2C40000\
                    &pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
                    #Xray%20Hysteria2";
        let first = parse_uri(link)
            .expect("import")
            .into_node()
            .expect("supported");
        let export = export_share_link(&first, ShareOptions::default()).expect("export");
        assert_eq!(export.fidelity, ExportFidelity::Lossless);
        assert!(export.link.expose().starts_with("hysteria2://"));
        let second = parse_uri(export.link.expose())
            .expect("re-import")
            .into_node()
            .expect("supported");
        assert_eq!(first.canonical_identity(), second.canonical_identity());
        assert_eq!(first.protocol, second.protocol);
        assert_eq!(first.security, second.security);
    }

    #[test]
    fn hysteria_colon_port_range_is_normalized_before_identity_and_export() {
        let original = parse_uri(
            "hysteria2://synthetic@example.com:443?security=tls&mport=20000%3A30000#range",
        )
        .expect("import")
        .into_node()
        .expect("supported");
        let export = export_share_link(&original, ShareOptions::default()).expect("export");
        assert!(export.link.expose().contains("mport=20000%2D30000"));
        let imported = parse_uri(export.link.expose())
            .expect("re-import")
            .into_node()
            .expect("supported");
        assert_eq!(original.canonical_identity(), imported.canonical_identity());
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
            "wireguard://private@wg.example:51820?publickey=public&address=172.16.0.2%2F32#e",
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
