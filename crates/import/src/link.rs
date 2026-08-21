//! Share-link parsing.
//!
//! One function per scheme, all reached through [`parse`]. Every one of them
//! returns `Result<ImportedEntry, ImportError>`: a *recognised but uncompilable*
//! protocol is an `Ok(Unsupported)`, and only genuinely broken syntax is an
//! `Err`. That distinction is what stops a subscription update from silently
//! shrinking the user's node list.

use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;
use xraytui_domain::{
    Compatibility, Endpoint, GrpcTransport, HttpProxySettings, HttpUpgradeTransport, MkcpTransport,
    Node, NodeId, NodeSource, ProtocolSettings, RawTransport, RealitySettings, ShadowsocksSettings,
    SocksSettings, TlsSettings, Transport, TransportSecurity, TrojanSettings, UnsupportedNode,
    UnsupportedReason, VlessSettings, VmessSettings, WebsocketTransport, WireguardPeer,
    WireguardSettings, XhttpTransport, slugify,
};
use xraytui_secrets::Secret;

use crate::b64::decode_base64_utf8;
use crate::{ImportError, ImportedEntry, MAX_LINK_BYTES, MAX_NAME_CHARS};

/// Parse one share link.
pub(crate) fn parse(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ImportError::Empty);
    }
    if trimmed.len() > MAX_LINK_BYTES {
        return Err(ImportError::TooLarge {
            size: trimmed.len(),
            limit: MAX_LINK_BYTES,
        });
    }

    let Some((raw_scheme, rest)) = trimmed.split_once("://") else {
        return Err(ImportError::NotAShareLink);
    };
    if raw_scheme.is_empty() || !raw_scheme.chars().all(is_scheme_char) {
        return Err(ImportError::NotAShareLink);
    }
    let scheme = raw_scheme.to_ascii_lowercase();

    match scheme.as_str() {
        "vless" => parse_vless(trimmed, source),
        "trojan" => parse_trojan(trimmed, source),
        "vmess" => parse_vmess(rest, trimmed, source),
        "ss" => parse_shadowsocks(rest, trimmed, source),
        "socks" | "socks5" => parse_socks(trimmed, source),
        "http-proxy" | "https-proxy" => parse_http_proxy(trimmed, source),
        "wireguard" => parse_wireguard(trimmed, source),
        "hysteria2" | "hy2" => parse_hysteria2(trimmed, source),
        // Bare `http://`/`https://` is a subscription URL far more often than it
        // is a proxy share link, so it is not treated as one here.
        other => Ok(ImportedEntry::Unsupported(unsupported(
            other, trimmed, source,
        ))),
    }
}

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

// ---------------------------------------------------------------- helpers

/// Percent-decode a fragment into a display name, bounded in length.
fn decode_name(fragment: Option<&str>) -> String {
    let Some(raw) = fragment else {
        return String::new();
    };
    let decoded = percent_decode_str(raw).decode_utf8_lossy();
    decoded.trim().chars().take(MAX_NAME_CHARS).collect()
}

/// Derive a validated identifier from a display name.
///
/// The random suffix keeps two nodes with the same remark distinct, and the
/// truncation keeps the result inside `MAX_ID_LEN` after the suffix is appended.
pub(crate) fn make_id_for(name: &str, fallback: &str) -> NodeId {
    make_id(name, fallback)
}

fn make_id(name: &str, fallback: &str) -> NodeId {
    const SUFFIX_LEN: usize = 12;
    const SEPARATOR_LEN: usize = 1;
    let budget = xraytui_domain::ids::MAX_ID_LEN.saturating_sub(SUFFIX_LEN + SEPARATOR_LEN);
    let base_source = if name.trim().is_empty() {
        fallback
    } else {
        name
    };
    let mut base = slugify(base_source);
    if base.len() > budget {
        base.truncate(budget);
        while base.ends_with('-') {
            base.pop();
        }
    }
    if base.is_empty() {
        base.push_str("node");
    }
    let candidate = format!("{base}-{}", xraytui_domain::ids::fresh_suffix());
    NodeId::new(candidate).unwrap_or_else(|_| {
        // `slugify` output plus a hex suffix is always a valid slug, so this arm
        // is unreachable in practice; it exists so the function cannot panic.
        NodeId::from_text("node")
    })
}

/// A recognised-but-uncompilable entry.
fn unsupported(scheme: &str, original: &str, source: NodeSource) -> UnsupportedNode {
    let (reason, requires_core) = classify_foreign(scheme);
    let name = original
        .split_once('#')
        .map(|(_, fragment)| decode_name(Some(fragment)))
        .unwrap_or_default();
    UnsupportedNode {
        id: make_id(&name, scheme),
        name,
        source,
        detected_protocol: scheme.to_owned(),
        reason,
        requires_core,
        redacted_original: xraytui_secrets::redact_text(original),
        original: Secret::new(original),
    }
}

fn classify_foreign(scheme: &str) -> (UnsupportedReason, Option<String>) {
    match scheme {
        "tuic" => (
            UnsupportedReason::ForeignCore {
                core: "tuic".into(),
            },
            Some("sing-box".into()),
        ),
        "ssr" => (
            UnsupportedReason::ForeignCore {
                core: "shadowsocksr".into(),
            },
            Some("shadowsocksr".into()),
        ),
        "snell" => (
            UnsupportedReason::ForeignCore {
                core: "snell".into(),
            },
            Some("surge".into()),
        ),
        "juicity" | "naive" | "brook" => (
            UnsupportedReason::ForeignCore {
                core: scheme.to_owned(),
            },
            None,
        ),
        other => (
            UnsupportedReason::UnknownScheme {
                scheme: other.to_owned(),
            },
            None,
        ),
    }
}

/// The pieces every authority-shaped link needs.
struct Authority {
    userinfo: String,
    host: String,
    port: u16,
    name: String,
    query: BTreeMap<String, String>,
}

/// Parse `scheme://userinfo@host:port?query#fragment` with the `url` crate.
///
/// Errors never quote the input, so `userinfo` cannot leak into a message.
fn split_authority(input: &str, scheme: &'static str) -> Result<Authority, ImportError> {
    let parsed = url::Url::parse(input).map_err(|reason| ImportError::Uri {
        scheme: scheme.to_owned(),
        reason,
    })?;
    let host = parsed.host_str().unwrap_or_default().to_owned();
    if host.is_empty() {
        return Err(ImportError::MissingField {
            scheme,
            field: "host",
        });
    }
    let port = parsed.port().ok_or(ImportError::MissingField {
        scheme,
        field: "port",
    })?;
    // `url` splits userinfo at the first `:`, so both halves have to be put back
    // together — otherwise `socks://user:pass@host` silently loses its password.
    let username = percent_decode_str(parsed.username())
        .decode_utf8_lossy()
        .into_owned();
    let userinfo = match parsed.password() {
        Some(password) => {
            let password = percent_decode_str(password)
                .decode_utf8_lossy()
                .into_owned();
            format!("{username}:{password}")
        }
        None => username,
    };
    let query: BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    Ok(Authority {
        userinfo,
        host: strip_brackets(&host),
        port,
        name: decode_name(parsed.fragment()),
        query,
    })
}

fn strip_brackets(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned()
}

/// Query keys the transport/security parsers consume; anything else is kept.
const KNOWN_QUERY_KEYS: &[&str] = &[
    "type",
    "net",
    "headertype",
    "headerType",
    "host",
    "path",
    "servicename",
    "serviceName",
    "mode",
    "authority",
    "security",
    "sni",
    "peer",
    "alpn",
    "fp",
    "pbk",
    "sid",
    "spx",
    "flow",
    "encryption",
    "allowinsecure",
    "allowInsecure",
    "insecure",
    "seed",
    "mtu",
    "tti",
    "mldsa65verify",
    "mldsa65Verify",
    "pqv",
    "ech",
    "pcs",
    "vcn",
    "fm",
    "multimode",
    "multiMode",
    "extra",
    "obfs",
    "obfs-password",
    "plugin",
    "udp",
];

fn extras(query: &BTreeMap<String, String>) -> BTreeMap<String, serde_json::Value> {
    query
        .iter()
        .filter(|(key, _)| !KNOWN_QUERY_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect()
}

fn get<'a>(query: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| query.get(*key))
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn any_true(query: &BTreeMap<String, String>, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        query
            .get(*key)
            .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true"))
    })
}

fn optional_u32(
    query: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<Option<u32>, ImportError> {
    get(query, &[key])
        .map(|value| {
            value.parse::<u32>().map_err(|_| ImportError::InvalidField {
                scheme: "share-link",
                field: key,
            })
        })
        .transpose()
}

fn optional_i32(
    query: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<Option<i32>, ImportError> {
    get(query, &[key])
        .map(|value| {
            value
                .parse::<i32>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or(ImportError::InvalidField {
                    scheme: "wireguard",
                    field: key,
                })
        })
        .transpose()
}

fn build_transport(query: &BTreeMap<String, String>) -> Result<Transport, ImportError> {
    let kind = get(query, &["type", "net"])
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    let host = get(query, &["host"]).map(str::to_owned);
    let path = get(query, &["path"]).map(str::to_owned);
    let transport = match kind.as_str() {
        "ws" | "websocket" => Transport::Websocket(WebsocketTransport {
            path: path.unwrap_or_else(|| "/".to_owned()),
            host,
            headers: BTreeMap::new(),
        }),
        "grpc" | "gun" => Transport::Grpc(GrpcTransport {
            service_name: get(query, &["serviceName", "servicename", "path"])
                .unwrap_or_default()
                .to_owned(),
            multi_mode: matches!(
                get(query, &["mode", "multiMode", "multimode"]),
                Some("multi")
            ),
            authority: get(query, &["authority"]).map(str::to_owned),
        }),
        "xhttp" | "splithttp" => Transport::Xhttp(XhttpTransport {
            host,
            path,
            mode: get(query, &["mode"]).map(str::to_owned),
            extra: get(query, &["extra"])
                .map(|raw| {
                    serde_json::from_str(raw).map_err(|_| ImportError::InvalidField {
                        scheme: "share-link",
                        field: "extra",
                    })
                })
                .transpose()?,
        }),
        "httpupgrade" => Transport::HttpUpgrade(HttpUpgradeTransport {
            path: path.unwrap_or_else(|| "/".to_owned()),
            host,
        }),
        "kcp" | "mkcp" => Transport::Mkcp(MkcpTransport {
            header_type: get(query, &["headerType", "headertype"]).map(str::to_owned),
            seed: get(query, &["seed"]).map(Secret::new),
            mtu: optional_u32(query, "mtu")?,
            tti: optional_u32(query, "tti")?,
        }),
        "tcp" | "raw" => Transport::Raw(RawTransport {
            header_type: get(query, &["headerType", "headertype"]).map(str::to_owned),
            host: host
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            path,
        }),
        _ => {
            return Err(ImportError::InvalidField {
                scheme: "share-link",
                field: "type",
            });
        }
    };
    Ok(transport)
}

fn build_security(
    query: &BTreeMap<String, String>,
    host: &str,
) -> Result<TransportSecurity, ImportError> {
    let kind = get(query, &["security"])
        .unwrap_or("none")
        .to_ascii_lowercase();
    let sni = get(query, &["sni", "peer"]).map(str::to_owned);
    let fingerprint = get(query, &["fp"]).map(str::to_owned);
    let security = match kind.as_str() {
        "tls" | "xtls" => TransportSecurity::Tls(TlsSettings {
            server_name: sni.or_else(|| Some(host.to_owned())),
            alpn: get(query, &["alpn"])
                .map(|value| value.split(',').map(|a| a.trim().to_owned()).collect())
                .unwrap_or_default(),
            fingerprint,
            // Preserve the request, but `finish` makes it unavailable because
            // current Xray rejects this removed field. It is never enabled by a
            // silent fallback.
            allow_insecure: any_true(query, &["insecure", "allowInsecure", "allowinsecure"]),
            ech_config_list: get(query, &["ech"]).map(str::to_owned),
            ech_force_query: None,
            pinned_peer_cert_sha256: get(query, &["pcs"]).map(str::to_owned),
            verify_peer_cert_by_name: get(query, &["vcn"]).map(str::to_owned),
            cipher_suites: None,
        }),
        "reality" => TransportSecurity::Reality(RealitySettings {
            server_name: sni.or_else(|| Some(host.to_owned())),
            public_key: Secret::new(get(query, &["pbk"]).ok_or(ImportError::MissingField {
                scheme: "share-link",
                field: "pbk",
            })?),
            short_id: get(query, &["sid"]).map(Secret::new),
            spider_x: get(query, &["spx"]).map(str::to_owned),
            fingerprint,
            mldsa65_verify: get(query, &["pqv", "mldsa65Verify", "mldsa65verify"]).map(Secret::new),
        }),
        "" | "none" => TransportSecurity::None,
        _ => {
            return Err(ImportError::InvalidField {
                scheme: "share-link",
                field: "security",
            });
        }
    };
    Ok(security)
}

fn finish(
    mut node: Node,
    query: &BTreeMap<String, String>,
    mut notes: Vec<String>,
) -> Result<ImportedEntry, ImportError> {
    node.transport = build_transport(query)?;
    node.security = build_security(query, &node.endpoint.address)?;
    node.finalmask = get(query, &["fm"])
        .map(|raw| {
            let value: serde_json::Value =
                serde_json::from_str(raw).map_err(|_| ImportError::InvalidField {
                    scheme: "share-link",
                    field: "fm",
                })?;
            if !value.is_object() {
                return Err(ImportError::InvalidField {
                    scheme: "share-link",
                    field: "fm",
                });
            }
            Ok(value)
        })
        .transpose()?;
    node.extra = extras(query);
    if matches!(&node.security, TransportSecurity::Reality(_)) {
        let mut retained_tls_only = Vec::new();
        for key in [
            "alpn",
            "ech",
            "pcs",
            "vcn",
            "allowinsecure",
            "allowInsecure",
            "insecure",
        ] {
            if let Some(value) = query.get(key) {
                node.extra
                    .insert(key.to_owned(), serde_json::Value::String(value.clone()));
                retained_tls_only.push(key);
            }
        }
        if !retained_tls_only.is_empty() {
            notes.push(format!(
                "REALITY link fields {} are preserved for ecosystem round trips, but current Xray REALITY settings do not consume them",
                retained_tls_only.join(", ")
            ));
        }
    }
    if matches!(
        &node.security,
        TransportSecurity::Tls(TlsSettings {
            allow_insecure: true,
            ..
        })
    ) {
        node.compatibility = Compatibility::Unsupported;
        notes.push(
            "link requires TLS allowInsecure, which Xray-core removed after 2026-06-01; use certificate pins (pcs) or verified names (vcn)".to_owned(),
        );
    }
    if !notes.is_empty() {
        if node.compatibility == Compatibility::Supported {
            node.compatibility = Compatibility::Degraded;
        }
        node.notes = notes;
    }
    Ok(ImportedEntry::Supported(node))
}

// ----------------------------------------------------------------- VLESS

fn parse_vless(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let authority = split_authority(input, "vless")?;
    if authority.userinfo.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "vless",
            field: "id",
        });
    }
    let node = Node::new(
        make_id(&authority.name, "vless"),
        authority.name.clone(),
        source,
        Endpoint::new(authority.host.clone(), authority.port),
        ProtocolSettings::Vless(VlessSettings {
            id: Secret::new(authority.userinfo.clone()),
            flow: get(&authority.query, &["flow"])
                .unwrap_or_default()
                .to_owned(),
            encryption: get(&authority.query, &["encryption"])
                .unwrap_or("none")
                .to_owned(),
            level: None,
        }),
    );
    finish(node, &authority.query, Vec::new())
}

// ---------------------------------------------------------------- Trojan

fn parse_trojan(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let authority = split_authority(input, "trojan")?;
    if authority.userinfo.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "trojan",
            field: "password",
        });
    }
    let node = Node::new(
        make_id(&authority.name, "trojan"),
        authority.name.clone(),
        source,
        Endpoint::new(authority.host.clone(), authority.port),
        ProtocolSettings::Trojan(TrojanSettings {
            password: Secret::new(authority.userinfo.clone()),
            flow: get(&authority.query, &["flow"])
                .unwrap_or_default()
                .to_owned(),
        }),
    );
    // Trojan is TLS by definition; make that implicit default explicit before
    // the common parser consumes TLS extensions such as ECH and certificate
    // pins.
    let mut query = authority.query;
    query
        .entry("security".into())
        .or_insert_with(|| "tls".into());
    finish(node, &query, Vec::new())
}

// ----------------------------------------------------------------- VMess

/// The classic v2rayN `vmess://` payload.
#[derive(Debug, serde::Deserialize)]
struct VmessPayload {
    #[serde(default)]
    ps: Option<String>,
    #[serde(default)]
    add: Option<String>,
    #[serde(default)]
    port: Option<serde_json::Value>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    aid: Option<serde_json::Value>,
    #[serde(default)]
    scy: Option<String>,
    #[serde(default)]
    net: Option<String>,
    #[serde(default, rename = "type")]
    header_type: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    tls: Option<String>,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    alpn: Option<String>,
    #[serde(default)]
    fp: Option<String>,
    #[serde(default)]
    insecure: Option<serde_json::Value>,
    #[serde(default)]
    ech: Option<String>,
    #[serde(default)]
    vcn: Option<String>,
    #[serde(default)]
    pcs: Option<String>,
    #[serde(default)]
    pbk: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    spx: Option<String>,
    #[serde(default)]
    pqv: Option<String>,
    #[serde(default)]
    fm: Option<String>,
    #[serde(default)]
    extra: Option<String>,
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

fn number_field(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn parse_vmess(
    payload: &str,
    original: &str,
    source: NodeSource,
) -> Result<ImportedEntry, ImportError> {
    if payload
        .split('#')
        .next()
        .is_some_and(|body| body.contains('@'))
    {
        return parse_vmess_authority(original, source);
    }
    // The fragment, if any, is not part of the base64 blob.
    let blob = payload.split('#').next().unwrap_or(payload);
    let decoded = decode_base64_utf8(blob).ok_or(ImportError::InvalidBase64 { scheme: "vmess" })?;
    let value: serde_json::Value =
        serde_json::from_str(&decoded).map_err(|_| ImportError::InvalidJson { scheme: "vmess" })?;
    if !value.is_object() {
        return Err(ImportError::InvalidJson { scheme: "vmess" });
    }
    let parsed: VmessPayload =
        serde_json::from_value(value).map_err(|_| ImportError::InvalidJson { scheme: "vmess" })?;

    let host = parsed.add.unwrap_or_default();
    if host.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "vmess",
            field: "add",
        });
    }
    let port = number_field(parsed.port.as_ref())
        .and_then(|p| u16::try_from(p).ok())
        .ok_or(ImportError::InvalidField {
            scheme: "vmess",
            field: "port",
        })?;
    let id = parsed.id.unwrap_or_default();
    if id.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "vmess",
            field: "id",
        });
    }

    let alter_id = number_field(parsed.aid.as_ref())
        .and_then(|a| u16::try_from(a).ok())
        .unwrap_or(0);
    let mut notes = Vec::new();
    if alter_id != 0 {
        notes.push(format!(
            "link declares alterId {alter_id}; modern Xray only supports VMessAEAD (alterId 0), \
             so this node cannot be compiled until it is set to 0"
        ));
    }

    let name = parsed
        .ps
        .unwrap_or_default()
        .chars()
        .take(MAX_NAME_CHARS)
        .collect::<String>();
    let mut query: BTreeMap<String, String> = BTreeMap::new();
    let network = parsed.net.unwrap_or_else(|| "tcp".to_owned());
    query.insert("type".into(), network.clone());
    if let Some(header) = parsed.header_type {
        match network.as_str() {
            "xhttp" | "splithttp" | "grpc" => {
                query.insert("mode".into(), header);
            }
            _ => {
                query.insert("headerType".into(), header);
            }
        }
    }
    if let Some(host_header) = parsed.host {
        if network == "grpc" {
            query.insert("authority".into(), host_header);
        } else {
            query.insert("host".into(), host_header);
        }
    }
    if let Some(path) = parsed.path {
        match network.as_str() {
            "grpc" => {
                query.insert("serviceName".into(), path);
            }
            "kcp" | "mkcp" => {
                query.insert("seed".into(), path);
            }
            _ => {
                query.insert("path".into(), path);
            }
        }
    }
    match parsed.tls.as_deref() {
        Some("tls") | Some("reality") => {
            query.insert("security".into(), parsed.tls.clone().unwrap_or_default());
        }
        _ => {}
    }
    if let Some(sni) = parsed.sni {
        query.insert("sni".into(), sni);
    }
    if let Some(alpn) = parsed.alpn {
        query.insert("alpn".into(), alpn);
    }
    if let Some(fingerprint) = parsed.fp {
        query.insert("fp".into(), fingerprint);
    }
    let insecure = parsed.insecure.as_ref().is_some_and(|value| match value {
        serde_json::Value::String(text) => matches!(text.as_str(), "1" | "true"),
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value.as_u64() == Some(1),
        _ => false,
    });
    if insecure {
        query.insert("insecure".into(), "1".into());
    }
    for (key, value) in [
        ("ech", parsed.ech),
        ("vcn", parsed.vcn),
        ("pcs", parsed.pcs),
        ("pbk", parsed.pbk),
        ("sid", parsed.sid),
        ("spx", parsed.spx),
        ("pqv", parsed.pqv),
        ("fm", parsed.fm),
        ("extra", parsed.extra),
    ] {
        if let Some(value) = value {
            query.insert(key.to_owned(), value);
        }
    }

    let mut node = Node::new(
        make_id(&name, "vmess"),
        name,
        source,
        Endpoint::new(host, port),
        ProtocolSettings::Vmess(VmessSettings {
            id: Secret::new(id),
            security: parsed
                .scy
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "auto".to_owned()),
            alter_id,
            level: None,
        }),
    );
    if alter_id != 0 {
        node.compatibility = Compatibility::Unsupported;
    }
    let entry = finish(node.clone(), &query, notes)?;
    if let ImportedEntry::Supported(built) = entry {
        node = built;
    }
    node.extra.extend(parsed.unknown);
    let _ = original;
    Ok(ImportedEntry::Supported(node))
}

fn parse_vmess_authority(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let authority = split_authority(input, "vmess")?;
    if authority.userinfo.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "vmess",
            field: "id",
        });
    }
    let node = Node::new(
        make_id(&authority.name, "vmess"),
        authority.name.clone(),
        source,
        Endpoint::new(authority.host.clone(), authority.port),
        ProtocolSettings::Vmess(VmessSettings {
            id: Secret::new(authority.userinfo),
            security: get(&authority.query, &["encryption"])
                .unwrap_or("auto")
                .to_owned(),
            alter_id: 0,
            level: None,
        }),
    );
    finish(node, &authority.query, Vec::new())
}

// ----------------------------------------------------------- Shadowsocks

fn parse_shadowsocks(
    payload: &str,
    original: &str,
    source: NodeSource,
) -> Result<ImportedEntry, ImportError> {
    let (before_fragment, fragment) = match payload.split_once('#') {
        Some((body, fragment)) => (body, Some(fragment)),
        None => (payload, None),
    };
    let (body, query_text) = match before_fragment.split_once('?') {
        Some((body, query)) => (body, Some(query)),
        None => (before_fragment, None),
    };

    // Two encodings are in the wild:
    //   (a) SIP002:  ss://base64(method:password)@host:port
    //   (b) legacy:  ss://base64(method:password@host:port)
    let (userinfo, endpoint_text) = match body.rsplit_once('@') {
        Some((userinfo, endpoint)) => {
            let decoded = decode_base64_utf8(userinfo).unwrap_or_else(|| {
                percent_decode_str(userinfo)
                    .decode_utf8_lossy()
                    .into_owned()
            });
            (decoded, endpoint.to_owned())
        }
        None => {
            let decoded =
                decode_base64_utf8(body).ok_or(ImportError::InvalidBase64 { scheme: "ss" })?;
            let (userinfo, endpoint) =
                decoded.rsplit_once('@').ok_or(ImportError::InvalidField {
                    scheme: "ss",
                    field: "userinfo",
                })?;
            (userinfo.to_owned(), endpoint.to_owned())
        }
    };

    let (method, password) = userinfo.split_once(':').ok_or(ImportError::InvalidField {
        scheme: "ss",
        field: "method",
    })?;
    if method.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "ss",
            field: "method",
        });
    }

    let (host, port_text) = endpoint_text
        .rsplit_once(':')
        .ok_or(ImportError::MissingField {
            scheme: "ss",
            field: "port",
        })?;
    let host = strip_brackets(host);
    if host.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "ss",
            field: "host",
        });
    }
    let port: u16 = port_text
        .trim()
        .parse()
        .map_err(|_| ImportError::InvalidField {
            scheme: "ss",
            field: "port",
        })?;

    let query: BTreeMap<String, String> = query_text
        .map(|text| {
            url::form_urlencoded::parse(text.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();

    let mut notes = Vec::new();
    if let Some(plugin) = get(&query, &["plugin"]) {
        let plugin_name = plugin.split(';').next().unwrap_or("unknown");
        notes.push(format!(
            "link requests the SIP003 plugin `{plugin_name}`; xraytui never executes plugins, so \
             this node is preserved but not compiled"
        ));
    }

    let name = decode_name(fragment);
    let mut node = Node::new(
        make_id(&name, "ss"),
        name,
        source,
        Endpoint::new(host, port),
        ProtocolSettings::Shadowsocks(ShadowsocksSettings {
            method: method.to_owned(),
            password: Secret::new(password),
            uot: matches!(get(&query, &["udp"]), Some("true") | Some("1")),
            uot_version: None,
        }),
    );
    node.extra = extras(&query);
    if let Some(plugin) = get(&query, &["plugin"]) {
        node.extra.insert(
            "plugin".into(),
            serde_json::Value::String(plugin.to_owned()),
        );
    }
    if !notes.is_empty() {
        node.compatibility = Compatibility::Unsupported;
        node.notes = notes;
    }
    let _ = original;
    Ok(ImportedEntry::Supported(node))
}

// ------------------------------------------------------------ Xray Hysteria2

fn parse_hysteria2(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let authority = split_authority(input, "hysteria2")?;
    if authority.userinfo.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "hysteria2",
            field: "auth",
        });
    }

    let mut notes = Vec::new();
    let security = get(&authority.query, &["security"]).unwrap_or("tls");
    if security != "tls" {
        notes.push(format!(
            "Hysteria2 link requests security={security}; Xray's Hysteria transport requires TLS"
        ));
    }
    let obfs_kind = get(&authority.query, &["obfs"]);
    let obfs_password = get(&authority.query, &["obfs-password"]);
    let obfs = match (obfs_kind, obfs_password) {
        (Some("salamander"), Some(password)) => Some(Secret::new(password)),
        (None, Some(password)) => {
            notes.push(
                "Hysteria2 link omitted obfs=salamander; inferred it from obfs-password".to_owned(),
            );
            Some(Secret::new(password))
        }
        (Some("none") | None, None) => None,
        (Some("salamander"), None) => {
            notes.push("Hysteria2 salamander obfuscation has no password".to_owned());
            None
        }
        (Some(kind), _) => {
            notes.push(format!(
                "Hysteria2 obfuscation '{kind}' is not available in the pinned Xray release"
            ));
            None
        }
    };

    let allow_insecure = any_true(
        &authority.query,
        &["insecure", "allowInsecure", "allowinsecure"],
    );
    if allow_insecure {
        notes.push(
            "link requires TLS allowInsecure, which Xray-core removed after 2026-06-01; use pinSHA256/pcs instead".to_owned(),
        );
    }

    let mut node = Node::new(
        make_id(&authority.name, "hysteria2"),
        authority.name,
        source,
        Endpoint::new(authority.host, authority.port),
        ProtocolSettings::Hysteria(xraytui_domain::HysteriaSettings {
            auth: Secret::new(authority.userinfo),
            obfs,
            up: get(&authority.query, &["up", "upmbps"]).map(str::to_owned),
            down: get(&authority.query, &["down", "downmbps"]).map(str::to_owned),
            // v2rayN canonicalises the older `20000:30000` spelling to the
            // Hysteria URI/Xray `20000-30000` spelling on export. Normalising
            // at import keeps the stable identity unchanged across a round trip.
            port_hopping: get(&authority.query, &["mport"]).map(|ports| ports.replace(':', "-")),
        }),
    );
    node.security = TransportSecurity::Tls(TlsSettings {
        server_name: get(&authority.query, &["sni"]).map(str::to_owned),
        alpn: get(&authority.query, &["alpn"])
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_owned())
                    .collect()
            })
            .unwrap_or_default(),
        fingerprint: get(&authority.query, &["fp"]).map(str::to_owned),
        allow_insecure,
        ech_config_list: get(&authority.query, &["ech"]).map(str::to_owned),
        ech_force_query: None,
        pinned_peer_cert_sha256: get(&authority.query, &["pinSHA256", "pcs"]).map(str::to_owned),
        verify_peer_cert_by_name: get(&authority.query, &["vcn"]).map(str::to_owned),
        cipher_suites: None,
    });
    if !notes.is_empty() {
        node.compatibility = if security == "tls"
            && !allow_insecure
            && !notes
                .iter()
                .any(|note| note.contains("not available") || note.contains("no password"))
        {
            Compatibility::Degraded
        } else {
            Compatibility::Unsupported
        };
        node.notes = notes;
    }
    node.extra = authority
        .query
        .into_iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "security"
                    | "sni"
                    | "alpn"
                    | "fp"
                    | "insecure"
                    | "allowInsecure"
                    | "allowinsecure"
                    | "ech"
                    | "pinSHA256"
                    | "pcs"
                    | "vcn"
                    | "obfs"
                    | "obfs-password"
                    | "mport"
                    | "up"
                    | "upmbps"
                    | "down"
                    | "downmbps"
            )
        })
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect();
    Ok(ImportedEntry::Supported(node))
}

// ------------------------------------------------------------ WireGuard

fn parse_wireguard(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let authority = split_authority(input, "wireguard")?;
    if authority.userinfo.is_empty() {
        return Err(ImportError::MissingField {
            scheme: "wireguard",
            field: "secret key",
        });
    }
    let public_key = get(&authority.query, &["publickey"]).ok_or(ImportError::MissingField {
        scheme: "wireguard",
        field: "publickey",
    })?;
    let address = get(&authority.query, &["address"])
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let reserved = get(&authority.query, &["reserved"])
        .map(|value| {
            let parsed = value
                .split(',')
                .map(str::trim)
                .map(str::parse::<u8>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ImportError::InvalidField {
                    scheme: "wireguard",
                    field: "reserved",
                })?;
            if !parsed.is_empty() && parsed.len() != 3 {
                return Err(ImportError::InvalidField {
                    scheme: "wireguard",
                    field: "reserved",
                });
            }
            Ok(parsed)
        })
        .transpose()?
        .unwrap_or_default();

    let endpoint = Endpoint::new(authority.host.clone(), authority.port);
    let mut node = Node::new(
        make_id(&authority.name, "wireguard"),
        authority.name,
        source,
        endpoint.clone(),
        ProtocolSettings::Wireguard(Box::new(WireguardSettings {
            secret_key: Secret::new(authority.userinfo),
            address,
            peers: vec![WireguardPeer {
                public_key: public_key.to_owned(),
                pre_shared_key: get(&authority.query, &["presharedkey"]).map(Secret::new),
                endpoint: endpoint.authority(),
                allowed_ips: Vec::new(),
                keep_alive: None,
            }],
            mtu: optional_i32(&authority.query, "mtu")?,
            reserved,
            domain_strategy: None,
        })),
    );
    node.extra = authority
        .query
        .into_iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "publickey" | "presharedkey" | "reserved" | "address" | "mtu"
            )
        })
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect();
    Ok(ImportedEntry::Supported(node))
}

// ------------------------------------------------------------ SOCKS/HTTP

/// Decode `user:pass`, which some providers base64 and some send verbatim.
fn split_credentials(userinfo: &str) -> (Option<String>, Option<Secret>) {
    if userinfo.is_empty() {
        return (None, None);
    }
    let decoded = decode_base64_utf8(userinfo)
        .filter(|text| text.contains(':'))
        .unwrap_or_else(|| userinfo.to_owned());
    match decoded.split_once(':') {
        Some((user, password)) => (Some(user.to_owned()), Some(Secret::new(password))),
        None => (Some(decoded), None),
    }
}

fn parse_socks(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let authority = split_authority(input, "socks")?;
    let (username, password) = split_credentials(&authority.userinfo);
    let node = Node::new(
        make_id(&authority.name, "socks"),
        authority.name.clone(),
        source,
        Endpoint::new(authority.host.clone(), authority.port),
        ProtocolSettings::Socks(SocksSettings {
            username,
            password,
            udp: !matches!(get(&authority.query, &["udp"]), Some("false") | Some("0")),
        }),
    );
    finish(node, &authority.query, Vec::new())
}

fn parse_http_proxy(input: &str, source: NodeSource) -> Result<ImportedEntry, ImportError> {
    let authority = split_authority(input, "http")?;
    let (username, password) = split_credentials(&authority.userinfo);
    let node = Node::new(
        make_id(&authority.name, "http"),
        authority.name.clone(),
        source,
        Endpoint::new(authority.host.clone(), authority.port),
        ProtocolSettings::Http(HttpProxySettings { username, password }),
    );
    finish(node, &authority.query, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_of(link: &str) -> Node {
        parse(link, NodeSource::Manual)
            .expect("link must parse")
            .into_node()
            .expect("link must be supported")
    }

    #[test]
    fn vless_with_websocket_and_tls() {
        let node = node_of(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443\
             ?type=ws&path=%2Fray&security=tls&sni=cdn.example.com&flow=xtls-rprx-vision#HK%2001",
        );
        assert_eq!(node.name, "HK 01");
        assert_eq!(node.endpoint, Endpoint::new("example.com", 443));
        match &node.protocol {
            ProtocolSettings::Vless(v) => {
                assert_eq!(v.id.expose(), "11111111-2222-3333-4444-555555555555");
                assert_eq!(v.flow, "xtls-rprx-vision");
                assert_eq!(v.encryption, "none");
            }
            other => panic!("wrong protocol: {other:?}"),
        }
        match &node.transport {
            Transport::Websocket(ws) => {
                assert_eq!(ws.path, "/ray");
                assert_eq!(ws.host, None);
            }
            other => panic!("wrong transport: {other:?}"),
        }
        match &node.security {
            TransportSecurity::Tls(tls) => {
                assert_eq!(tls.server_name.as_deref(), Some("cdn.example.com"));
                assert!(!tls.allow_insecure);
            }
            other => panic!("wrong security: {other:?}"),
        }
    }

    #[test]
    fn any_allow_insecure_alias_set_true_is_never_hidden_by_a_false_alias() {
        let node =
            node_of("vless://uuid@h.example:443?security=tls&insecure=0&allowInsecure=TRUE#unsafe");
        let TransportSecurity::Tls(tls) = &node.security else {
            panic!("expected TLS");
        };
        assert!(tls.allow_insecure);
        assert_eq!(node.compatibility, Compatibility::Unsupported);
    }

    #[test]
    fn vless_with_reality() {
        let node = node_of(
            "vless://uuid@1.2.3.4:443?security=reality&pbk=PUB&sid=ab12&spx=%2F&fp=chrome&type=tcp#R",
        );
        match &node.security {
            TransportSecurity::Reality(reality) => {
                assert_eq!(reality.public_key.expose(), "PUB");
                assert_eq!(
                    reality.short_id.as_ref().map(|s| s.expose().to_owned()),
                    Some("ab12".into())
                );
                assert_eq!(reality.spider_x.as_deref(), Some("/"));
                assert_eq!(reality.fingerprint.as_deref(), Some("chrome"));
                assert_eq!(reality.server_name.as_deref(), Some("1.2.3.4"));
            }
            other => panic!("wrong security: {other:?}"),
        }
    }

    #[test]
    fn reality_tls_only_extensions_are_preserved_instead_of_silently_consumed() {
        let input = "vless://uuid@1.2.3.4:443?security=reality&pbk=PUB&sid=ab12\
                     &fp=chrome&alpn=h2%2Ch3&ech=synthetic-ech&pcs=synthetic-pin\
                     &vcn=cdn.example.com&type=tcp#R";
        let node = node_of(input);
        for key in ["alpn", "ech", "pcs", "vcn"] {
            assert!(
                node.extra.contains_key(key),
                "missing {key}: {:?}",
                node.extra
            );
        }
        assert_eq!(node.compatibility, Compatibility::Degraded);
        assert!(
            node.notes
                .iter()
                .any(|note| note.contains("current Xray REALITY settings do not consume"))
        );

        let link = crate::export_share_link(&node, crate::ShareOptions::default())
            .expect("extensions fit the authority link")
            .link;
        let reparsed = crate::parse_uri(link.expose())
            .expect("reparse")
            .into_node()
            .expect("supported");
        assert_eq!(node.canonical_identity(), reparsed.canonical_identity());
    }

    #[test]
    fn unknown_query_parameters_are_preserved() {
        let node = node_of("vless://uuid@h.example:443?type=tcp&futureField=42#N");
        assert_eq!(
            node.extra.get("futureField"),
            Some(&serde_json::Value::String("42".into()))
        );
        assert!(!node.extra.contains_key("type"));
    }

    #[test]
    fn trojan_defaults_to_tls_even_without_the_parameter() {
        let node = node_of("trojan://pw@h.example:443#T");
        assert!(matches!(node.security, TransportSecurity::Tls(_)));
        match &node.protocol {
            ProtocolSettings::Trojan(t) => assert_eq!(t.password.expose(), "pw"),
            other => panic!("wrong protocol: {other:?}"),
        }
    }

    #[test]
    fn vmess_classic_payload() {
        let payload = serde_json::json!({
            "v": "2", "ps": "JP 02", "add": "jp.example.com", "port": "443",
            "id": "22222222-3333-4444-5555-666666666666", "aid": "0", "scy": "auto",
            "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/vm",
            "tls": "tls", "sni": "cdn.example.com"
        });
        let link = format!(
            "vmess://{}",
            crate::b64::encode_standard(payload.to_string().as_bytes())
        );
        let node = node_of(&link);
        assert_eq!(node.name, "JP 02");
        assert_eq!(node.endpoint, Endpoint::new("jp.example.com", 443));
        assert!(matches!(node.transport, Transport::Websocket(_)));
        assert!(matches!(node.security, TransportSecurity::Tls(_)));
        assert_eq!(node.compatibility, Compatibility::Supported);
    }

    #[test]
    fn vmess_with_alter_id_is_preserved_but_not_executable() {
        let payload = serde_json::json!({
            "ps": "old", "add": "h.example", "port": 443, "id": "u", "aid": 64, "net": "tcp"
        });
        let link = format!(
            "vmess://{}",
            crate::b64::encode_standard(payload.to_string().as_bytes())
        );
        let node = node_of(&link);
        assert_eq!(node.compatibility, Compatibility::Unsupported);
        assert!(
            node.notes.first().is_some_and(|n| n.contains("alterId")),
            "{:?}",
            node.notes
        );
    }

    #[test]
    fn shadowsocks_sip002_and_legacy_forms_agree() {
        let userinfo = crate::b64::encode_url_safe_no_pad(b"aes-256-gcm:secret");
        let sip002 = format!("ss://{userinfo}@ss.example:8388#SS");
        let legacy = format!(
            "ss://{}#SS",
            crate::b64::encode_standard(b"aes-256-gcm:secret@ss.example:8388")
        );
        let a = node_of(&sip002);
        let b = node_of(&legacy);
        assert_eq!(a.canonical_identity(), b.canonical_identity());
        assert_eq!(a.endpoint, Endpoint::new("ss.example", 8388));
        match &a.protocol {
            ProtocolSettings::Shadowsocks(ss) => {
                assert_eq!(ss.method, "aes-256-gcm");
                assert_eq!(ss.password.expose(), "secret");
            }
            other => panic!("wrong protocol: {other:?}"),
        }
    }

    #[test]
    fn shadowsocks_plugin_is_preserved_but_not_executable() {
        let userinfo = crate::b64::encode_url_safe_no_pad(b"aes-256-gcm:secret");
        let link = format!("ss://{userinfo}@ss.example:8388?plugin=obfs-local%3Bobfs%3Dhttp#P");
        let node = node_of(&link);
        assert_eq!(node.compatibility, Compatibility::Unsupported);
        assert_eq!(
            node.extra.get("plugin").and_then(serde_json::Value::as_str),
            Some("obfs-local;obfs=http")
        );
        assert!(
            node.notes.first().is_some_and(|n| n.contains("obfs-local")),
            "{:?}",
            node.notes
        );
    }

    #[test]
    fn mature_client_wireguard_dialect_is_imported_without_guessing_defaults() {
        let node = node_of(
            "wireguard://PRIVATE%2BKEY%3D@[2001:db8::1]:51820\
             ?publickey=PUBLIC%2BKEY%3D&presharedkey=PSK%2BVALUE%3D\
             &reserved=1%2C2%2C3&address=172.16.0.2%2F32%2Cfd00%3A%3A2%2F128&mtu=1420\
             #WG%20%E6%97%A5%E6%9C%AC",
        );
        assert_eq!(node.name, "WG 日本");
        assert_eq!(node.endpoint, Endpoint::new("2001:db8::1", 51820));
        let ProtocolSettings::Wireguard(wireguard) = &node.protocol else {
            panic!("expected WireGuard");
        };
        assert_eq!(wireguard.secret_key.expose(), "PRIVATE+KEY=");
        assert_eq!(wireguard.address, ["172.16.0.2/32", "fd00::2/128"]);
        assert_eq!(wireguard.reserved, [1, 2, 3]);
        assert_eq!(wireguard.mtu, Some(1420));
        assert_eq!(wireguard.peers[0].public_key, "PUBLIC+KEY=");
        assert_eq!(
            wireguard.peers[0]
                .pre_shared_key
                .as_ref()
                .map(Secret::expose),
            Some("PSK+VALUE=")
        );
        assert_eq!(wireguard.peers[0].endpoint, "[2001:db8::1]:51820");
        assert!(wireguard.peers[0].allowed_ips.is_empty());
    }

    #[test]
    fn socks_credentials_are_accepted_plain_and_base64() {
        let plain = node_of("socks://user:pass@127.0.0.1:1080#S");
        let encoded = format!(
            "socks://{}@127.0.0.1:1080#S",
            crate::b64::encode_url_safe_no_pad(b"user:pass")
        );
        let encoded = node_of(&encoded);
        for node in [plain, encoded] {
            match &node.protocol {
                ProtocolSettings::Socks(s) => {
                    assert_eq!(s.username.as_deref(), Some("user"));
                    assert_eq!(
                        s.password.as_ref().map(|p| p.expose().to_owned()),
                        Some("pass".into())
                    );
                }
                other => panic!("wrong protocol: {other:?}"),
            }
        }
    }

    #[test]
    fn foreign_schemes_are_classified_not_rejected() {
        for (link, core) in [
            ("tuic://uuid@h.example:443#T", Some("tuic")),
            ("ssr://Zm9v", Some("shadowsocksr")),
        ] {
            let entry = parse(link, NodeSource::Manual).expect("must classify");
            let unsupported = entry.as_unsupported().expect("must be unsupported");
            match (&unsupported.reason, core) {
                (UnsupportedReason::ForeignCore { core: found }, Some(expected)) => {
                    assert_eq!(found, expected, "{link}");
                }
                other => panic!("{link}: unexpected classification {other:?}"),
            }
            assert!(!unsupported.redacted_original.contains("pw"), "{link}");
        }
    }

    #[test]
    fn hysteria2_link_maps_to_xray_native_hysteria_semantics() {
        let node = node_of(
            "hysteria2://synthetic-auth@hy.example:443?security=tls&sni=edge.example\
             &alpn=h3&obfs=salamander&obfs-password=synthetic-obfs&mport=20000-30000%2C40000\
             &pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef#HY2",
        );
        let ProtocolSettings::Hysteria(hysteria) = &node.protocol else {
            panic!("expected Xray Hysteria");
        };
        assert_eq!(hysteria.auth.expose(), "synthetic-auth");
        assert_eq!(
            hysteria.obfs.as_ref().map(Secret::expose),
            Some("synthetic-obfs")
        );
        assert_eq!(hysteria.port_hopping.as_deref(), Some("20000-30000,40000"));
        let TransportSecurity::Tls(tls) = &node.security else {
            panic!("expected TLS");
        };
        assert_eq!(tls.server_name.as_deref(), Some("edge.example"));
        assert_eq!(tls.alpn, ["h3"]);
        assert_eq!(
            tls.pinned_peer_cert_sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(node.compatibility, Compatibility::Supported);
    }

    #[test]
    fn genuinely_unknown_schemes_say_so() {
        let entry = parse("wibble://x@h:1#W", NodeSource::Manual).expect("must classify");
        let unsupported = entry.as_unsupported().expect("unsupported");
        assert!(
            matches!(&unsupported.reason, UnsupportedReason::UnknownScheme { scheme } if scheme == "wibble")
        );
        assert_eq!(unsupported.name, "W");
    }

    #[test]
    fn ipv6_endpoints_lose_their_brackets() {
        let node = node_of("vless://uuid@[2001:db8::1]:443?type=tcp#v6");
        assert_eq!(node.endpoint.address, "2001:db8::1");
        assert_eq!(node.endpoint.authority(), "[2001:db8::1]:443");
    }

    #[test]
    fn missing_required_fields_are_errors_without_credentials() {
        for (link, expected_field) in [
            ("vless://@h.example:443", "id"),
            ("trojan://@h.example:443", "password"),
        ] {
            let error = parse(link, NodeSource::Manual).expect_err("must refuse");
            let rendered = error.to_string();
            assert!(rendered.contains(expected_field), "{link} -> {rendered}");
        }
    }

    #[test]
    fn truncated_and_malformed_payloads_are_bounded_errors() {
        for link in [
            "vmess://",
            "vmess://!!!!",
            "vmess://eyJhIjox", // valid base64, JSON object, no `add`
            "ss://",
            "ss://@h:1",
            "ss://YWJj",              // base64 without an `@`
            "socks://h.example",      // no port
            "vless://uuid@h.example", // no port
        ] {
            let result = parse(link, NodeSource::Manual);
            assert!(result.is_err(), "{link} should be an error, got {result:?}");
        }
    }

    #[test]
    fn identifiers_derived_from_names_stay_valid() {
        for name in [
            "香港%20%2001",
            "%F0%9F%8E%89",
            "",
            "%2D%2D%2D",
            &"x".repeat(300),
        ] {
            let link = format!("vless://uuid@h.example:443?type=tcp#{name}");
            let node = node_of(&link);
            assert!(
                xraytui_domain::validate_slug(node.id.as_str()).is_ok(),
                "{name} -> {}",
                node.id
            );
            assert!(node.name.chars().count() <= MAX_NAME_CHARS);
        }
    }

    #[test]
    fn every_transport_token_maps_to_a_transport() {
        for (token, expected) in [
            ("tcp", "raw"),
            ("raw", "raw"),
            ("ws", "ws"),
            ("grpc", "grpc"),
            ("xhttp", "xhttp"),
            ("httpupgrade", "httpu"),
            ("kcp", "kcp"),
        ] {
            let link = format!("vless://uuid@h.example:443?type={token}#T");
            assert_eq!(node_of(&link).transport.label(), expected, "token {token}");
        }
        let error = parse(
            "vless://uuid@h.example:443?type=something-new#T",
            NodeSource::Manual,
        )
        .expect_err("unknown transports must not silently become raw");
        assert!(matches!(
            error,
            ImportError::InvalidField { field: "type", .. }
        ));
    }
}
