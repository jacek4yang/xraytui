//! Normalized outbound endpoints.
//!
//! A [`Node`] is xraytui's own representation of "somewhere traffic can leave
//! through". It is deliberately *not* Xray JSON: it is versioned, it separates
//! secrets from display data, and it preserves fields it does not understand so
//! that import → export round trips do not destroy information.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use xraytui_secrets::Secret;

use crate::ids::{NodeId, SubscriptionId};

/// Schema version of the node representation. Bumped by migrations.
pub const NODE_SCHEMA_VERSION: u32 = 1;

/// Where a node came from. Determines which namespace may modify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NodeSource {
    /// Created by the user in the TUI or by `xraytui node import`.
    Manual,
    /// Owned by a subscription namespace. Only that subscription may modify it.
    Subscription {
        /// Owning subscription.
        id: SubscriptionId,
    },
    /// Imported from a local file or stdin.
    File {
        /// Path as supplied, for provenance display only.
        path: String,
    },
    /// Imported from a raw Xray outbound JSON object.
    XrayJson,
}

impl NodeSource {
    /// Subscription that owns this node, if any.
    #[must_use]
    pub fn subscription(&self) -> Option<&SubscriptionId> {
        match self {
            Self::Subscription { id } => Some(id),
            _ => None,
        }
    }

    /// True when a subscription update is allowed to delete or rewrite this node.
    #[must_use]
    pub fn owned_by(&self, subscription: &SubscriptionId) -> bool {
        self.subscription().is_some_and(|id| id == subscription)
    }
}

/// Host and port of the remote endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Hostname, IPv4 literal or IPv6 literal (without brackets).
    pub address: String,
    /// TCP/UDP port.
    pub port: u16,
}

impl Endpoint {
    /// Construct an endpoint.
    pub fn new(address: impl Into<String>, port: u16) -> Self {
        Self { address: address.into(), port }
    }

    /// Render as `host:port`, bracketing IPv6 literals.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.address.contains(':') && !self.address.starts_with('[') {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }
}

/// Protocol-specific outbound settings.
///
/// Only families that the pinned Xray release implements natively appear here.
/// Anything else becomes an [`UnsupportedNode`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ProtocolSettings {
    /// VLESS.
    Vless(VlessSettings),
    /// VMess.
    Vmess(VmessSettings),
    /// Trojan.
    Trojan(TrojanSettings),
    /// Shadowsocks (including 2022 ciphers).
    Shadowsocks(ShadowsocksSettings),
    /// Plain HTTP CONNECT proxy.
    Http(HttpProxySettings),
    /// SOCKS5 proxy.
    Socks(SocksSettings),
    /// WireGuard outbound.
    Wireguard(Box<WireguardSettings>),
    /// Hysteria outbound (v2 semantics as implemented by the pinned core).
    Hysteria(HysteriaSettings),
}

impl ProtocolSettings {
    /// Lowercase protocol name as Xray spells it.
    #[must_use]
    pub fn xray_protocol(&self) -> &'static str {
        match self {
            Self::Vless(_) => "vless",
            Self::Vmess(_) => "vmess",
            Self::Trojan(_) => "trojan",
            Self::Shadowsocks(_) => "shadowsocks",
            Self::Http(_) => "http",
            Self::Socks(_) => "socks",
            Self::Wireguard(_) => "wireguard",
            Self::Hysteria(_) => "hysteria",
        }
    }

    /// Whether the protocol can carry UDP to the remote side.
    ///
    /// Used by chain validation: an intermediate hop that cannot carry UDP breaks
    /// UDP for every hop after it.
    #[must_use]
    pub fn supports_udp(&self) -> bool {
        match self {
            Self::Vless(_) | Self::Vmess(_) | Self::Shadowsocks(_) => true,
            Self::Trojan(_) => true,
            Self::Socks(s) => s.udp,
            Self::Http(_) => false,
            Self::Wireguard(_) | Self::Hysteria(_) => true,
        }
    }

    /// Whether the protocol accepts a stream transport (`streamSettings`).
    ///
    /// WireGuard and Hysteria carry their own transport and must not be given one.
    #[must_use]
    pub fn accepts_stream_settings(&self) -> bool {
        !matches!(self, Self::Wireguard(_) | Self::Hysteria(_))
    }
}

/// VLESS outbound user settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessSettings {
    /// User UUID. Secret: it is the credential.
    pub id: Secret,
    /// XTLS flow, e.g. `xtls-rprx-vision`. Empty means unset.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
    /// VLESS `encryption` field. Defaults to `none`.
    #[serde(default = "default_vless_encryption")]
    pub encryption: String,
    /// Optional user level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
}

fn default_vless_encryption() -> String {
    "none".to_owned()
}

/// VMess outbound user settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmessSettings {
    /// User UUID.
    pub id: Secret,
    /// Encryption method (`auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`).
    #[serde(default = "default_vmess_security")]
    pub security: String,
    /// Legacy alterId. Non-zero values are rejected by modern cores.
    #[serde(default)]
    pub alter_id: u16,
    /// Optional user level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
}

fn default_vmess_security() -> String {
    "auto".to_owned()
}

/// Trojan outbound settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrojanSettings {
    /// Trojan password.
    pub password: Secret,
    /// Optional flow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
}

/// Shadowsocks outbound settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksSettings {
    /// Cipher name as Xray spells it (`aes-256-gcm`, `2022-blake3-aes-256-gcm`, …).
    pub method: String,
    /// Password or base64 PSK for 2022 ciphers.
    pub password: Secret,
    /// UDP over TCP.
    #[serde(default)]
    pub uot: bool,
    /// UoT protocol version when `uot` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uot_version: Option<u8>,
}

/// HTTP CONNECT outbound settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProxySettings {
    /// Optional username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
}

/// SOCKS5 outbound settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksSettings {
    /// Optional username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Whether the remote SOCKS server offers UDP ASSOCIATE.
    #[serde(default = "crate::node::default_true")]
    pub udp: bool,
}

/// WireGuard outbound settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardSettings {
    /// Local private key.
    pub secret_key: Secret,
    /// Local tunnel addresses.
    pub address: Vec<String>,
    /// Peers.
    pub peers: Vec<WireguardPeer>,
    /// Tunnel MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<i32>,
    /// Reserved bytes for some providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reserved: Vec<u8>,
    /// Address resolution strategy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<String>,
}

/// A WireGuard peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardPeer {
    /// Peer public key.
    pub public_key: String,
    /// Optional pre-shared key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<Secret>,
    /// `host:port`.
    pub endpoint: String,
    /// Allowed IPs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<u32>,
}

/// Hysteria outbound settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HysteriaSettings {
    /// Authentication string.
    pub auth: Secret,
    /// Optional obfuscation password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Secret>,
    /// Upload bandwidth hint, e.g. `100 mbps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<String>,
    /// Download bandwidth hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
}

pub(crate) const fn default_true() -> bool {
    true
}

/// Stream transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Transport {
    /// `raw` (formerly `tcp`), optionally with HTTP header obfuscation.
    Raw(RawTransport),
    /// XHTTP.
    Xhttp(XhttpTransport),
    /// gRPC.
    Grpc(GrpcTransport),
    /// WebSocket.
    Websocket(WebsocketTransport),
    /// HTTPUpgrade.
    HttpUpgrade(HttpUpgradeTransport),
    /// mKCP.
    Mkcp(MkcpTransport),
}

impl Default for Transport {
    fn default() -> Self {
        Self::Raw(RawTransport::default())
    }
}

impl Transport {
    /// Network name as Xray's `streamSettings.network` spells it.
    #[must_use]
    pub fn xray_network(&self) -> &'static str {
        match self {
            Self::Raw(_) => "raw",
            Self::Xhttp(_) => "xhttp",
            Self::Grpc(_) => "grpc",
            Self::Websocket(_) => "ws",
            Self::HttpUpgrade(_) => "httpupgrade",
            Self::Mkcp(_) => "kcp",
        }
    }

    /// Short label for the TUI.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Raw(_) => "raw",
            Self::Xhttp(_) => "xhttp",
            Self::Grpc(_) => "grpc",
            Self::Websocket(_) => "ws",
            Self::HttpUpgrade(_) => "httpu",
            Self::Mkcp(_) => "kcp",
        }
    }
}

/// RAW/TCP transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RawTransport {
    /// `none` or `http` header obfuscation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    /// Host header values when `header_type == "http"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    /// Request path when `header_type == "http"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// XHTTP transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct XhttpTransport {
    /// Virtual host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Request path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `auto`, `packet-up`, `stream-up`, `stream-one`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Extra settings preserved verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// gRPC transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GrpcTransport {
    /// gRPC service name.
    #[serde(default)]
    pub service_name: String,
    /// Multi-mode.
    #[serde(default)]
    pub multi_mode: bool,
    /// Authority override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
}

/// WebSocket transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WebsocketTransport {
    /// Request path.
    #[serde(default)]
    pub path: String,
    /// `Host` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Additional request headers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// HTTPUpgrade transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HttpUpgradeTransport {
    /// Request path.
    #[serde(default)]
    pub path: String,
    /// `Host` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// mKCP transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MkcpTransport {
    /// Header obfuscation type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    /// Obfuscation seed. Treated as a credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<Secret>,
}

/// Transport-layer security.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "security", rename_all = "lowercase")]
pub enum TransportSecurity {
    /// No TLS.
    None,
    /// Standard TLS.
    Tls(TlsSettings),
    /// REALITY.
    Reality(RealitySettings),
}

impl Default for TransportSecurity {
    fn default() -> Self {
        Self::None
    }
}

impl TransportSecurity {
    /// Name as Xray's `streamSettings.security` spells it.
    #[must_use]
    pub fn xray_security(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls(_) => "tls",
            Self::Reality(_) => "reality",
        }
    }
}

/// Standard TLS settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TlsSettings {
    /// SNI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// ALPN list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// uTLS fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Disable certificate verification.
    ///
    /// Never set by an importer. Setting it requires an explicit, visible user
    /// action and is surfaced as a warning wherever the node is displayed.
    #[serde(default)]
    pub allow_insecure: bool,
}

/// REALITY settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RealitySettings {
    /// Target SNI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// Server public key (`pbk`). A credential.
    pub public_key: Secret,
    /// Short id (`sid`). A credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<Secret>,
    /// SpiderX path (`spx`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spider_x: Option<String>,
    /// uTLS fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Optional REALITY `mldsa65Verify` material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_verify: Option<Secret>,
}

/// Multiplexing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MuxSettings {
    /// Whether mux is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Concurrency (-1 disables, 0 uses core default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<i16>,
    /// XUDP concurrency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xudp_concurrency: Option<i16>,
    /// `reject`, `allow` or `skip` for UDP/443.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xudp_proxy_udp_443: Option<String>,
}

/// Socket-level options applied to the outbound dialer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SocketSettings {
    /// SO_MARK value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<u32>,
    /// TCP fast open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fast_open: Option<bool>,
    /// TCP keep-alive interval in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_interval: Option<i32>,
    /// Bind to a specific interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Address family preference: `AsIs`, `UseIP`, `UseIPv4`, `UseIPv6`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<String>,
}

/// How well xraytui understands a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compatibility {
    /// Fully supported by the pinned Xray release.
    Supported,
    /// Supported but with a caveat recorded in [`Node::notes`].
    Degraded,
    /// Preserved but not compilable.
    Unsupported,
}

/// A normalized outbound endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Schema version of this record.
    #[serde(default = "default_node_schema")]
    pub schema_version: u32,
    /// Stable identifier used in generated tags.
    pub id: NodeId,
    /// Display name. Arbitrary Unicode; may be Chinese, may contain emoji.
    pub name: String,
    /// Provenance.
    pub source: NodeSource,
    /// Remote endpoint.
    pub endpoint: Endpoint,
    /// Protocol family and credentials.
    pub protocol: ProtocolSettings,
    /// Stream transport.
    #[serde(default)]
    pub transport: Transport,
    /// Transport security.
    #[serde(default)]
    pub security: TransportSecurity,
    /// Multiplexing.
    #[serde(default)]
    pub mux: MuxSettings,
    /// Socket options.
    #[serde(default)]
    pub sockopt: SocketSettings,
    /// Free-form user tags used by group filters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// User-assigned region label used by group filters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Whether the node may be selected or probed.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether xraytui can compile the node.
    #[serde(default = "default_compat")]
    pub compatibility: Compatibility,
    /// Human-readable caveats, e.g. "alterId ignored by core >= 1.5".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Unknown URI parameters and JSON fields, preserved for lossless re-export.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn default_node_schema() -> u32 {
    NODE_SCHEMA_VERSION
}

const fn default_compat() -> Compatibility {
    Compatibility::Supported
}

impl Node {
    /// Minimal constructor used by importers and the manual editor.
    pub fn new(
        id: NodeId,
        name: impl Into<String>,
        source: NodeSource,
        endpoint: Endpoint,
        protocol: ProtocolSettings,
    ) -> Self {
        Self {
            schema_version: NODE_SCHEMA_VERSION,
            id,
            name: name.into(),
            source,
            endpoint,
            protocol,
            transport: Transport::default(),
            security: TransportSecurity::default(),
            mux: MuxSettings::default(),
            sockopt: SocketSettings::default(),
            tags: Vec::new(),
            region: None,
            enabled: true,
            compatibility: Compatibility::Supported,
            notes: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Canonical identity used for deduplication.
    ///
    /// Two nodes that differ only in display name, tags or subscription are the
    /// same endpoint. The identity intentionally includes credentials — otherwise
    /// two accounts on the same server would collapse into one — but it is hashed
    /// through [`Secret::fingerprint`] so the identity itself is not a secret and
    /// can be logged.
    #[must_use]
    pub fn canonical_identity(&self) -> String {
        let mut parts = vec![
            self.protocol.xray_protocol().to_owned(),
            self.endpoint.address.to_ascii_lowercase(),
            self.endpoint.port.to_string(),
            self.transport.xray_network().to_owned(),
            self.security.xray_security().to_owned(),
        ];
        match &self.protocol {
            ProtocolSettings::Vless(v) => {
                parts.push(v.id.fingerprint());
                parts.push(v.flow.clone());
                parts.push(v.encryption.clone());
            }
            ProtocolSettings::Vmess(v) => parts.push(v.id.fingerprint()),
            ProtocolSettings::Trojan(t) => parts.push(t.password.fingerprint()),
            ProtocolSettings::Shadowsocks(s) => {
                parts.push(s.method.clone());
                parts.push(s.password.fingerprint());
            }
            ProtocolSettings::Http(h) => {
                parts.push(h.username.clone().unwrap_or_default());
                parts.push(h.password.as_ref().map(Secret::fingerprint).unwrap_or_default());
            }
            ProtocolSettings::Socks(s) => {
                parts.push(s.username.clone().unwrap_or_default());
                parts.push(s.password.as_ref().map(Secret::fingerprint).unwrap_or_default());
            }
            ProtocolSettings::Wireguard(w) => parts.push(w.secret_key.fingerprint()),
            ProtocolSettings::Hysteria(h) => parts.push(h.auth.fingerprint()),
        }
        // Transport discriminators that change reachability.
        match &self.transport {
            Transport::Raw(r) => {
                parts.push(r.header_type.clone().unwrap_or_default());
                parts.push(r.path.clone().unwrap_or_default());
            }
            Transport::Xhttp(x) => {
                parts.push(x.host.clone().unwrap_or_default());
                parts.push(x.path.clone().unwrap_or_default());
                parts.push(x.mode.clone().unwrap_or_default());
            }
            Transport::Grpc(g) => parts.push(g.service_name.clone()),
            Transport::Websocket(w) => {
                parts.push(w.path.clone());
                parts.push(w.host.clone().unwrap_or_default());
            }
            Transport::HttpUpgrade(h) => {
                parts.push(h.path.clone());
                parts.push(h.host.clone().unwrap_or_default());
            }
            Transport::Mkcp(m) => {
                parts.push(m.header_type.clone().unwrap_or_default());
                parts.push(m.seed.as_ref().map(Secret::fingerprint).unwrap_or_default());
            }
        }
        match &self.security {
            TransportSecurity::None => {}
            TransportSecurity::Tls(t) => {
                parts.push(t.server_name.clone().unwrap_or_default());
                parts.push(t.alpn.join(","));
            }
            TransportSecurity::Reality(r) => {
                parts.push(r.server_name.clone().unwrap_or_default());
                parts.push(r.public_key.fingerprint());
                parts.push(r.short_id.as_ref().map(Secret::fingerprint).unwrap_or_default());
            }
        }
        parts.join("|")
    }

    /// Whether the node can be compiled into an Xray outbound.
    #[must_use]
    pub fn is_compilable(&self) -> bool {
        self.enabled && self.compatibility != Compatibility::Unsupported
    }

    /// Short one-line summary for lists: `vless/raw+reality  1.2.3.4:443`.
    #[must_use]
    pub fn summary(&self) -> String {
        let security = match self.security {
            TransportSecurity::None => String::new(),
            _ => format!("+{}", self.security.xray_security()),
        };
        format!(
            "{}/{}{}  {}",
            self.protocol.xray_protocol(),
            self.transport.label(),
            security,
            self.endpoint.authority()
        )
    }
}

/// A node xraytui recognised as a proxy definition but cannot compile.
///
/// Kept visible so the user is never silently missing entries after a
/// subscription update, and re-exportable so no information is lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedNode {
    /// Stable identifier.
    pub id: NodeId,
    /// Display name, if one could be recovered.
    pub name: String,
    /// Provenance.
    pub source: NodeSource,
    /// Detected protocol token, e.g. `hysteria2`, `tuic`, `ssr`.
    pub detected_protocol: String,
    /// Why it is not supported.
    pub reason: UnsupportedReason,
    /// Another core that would be needed, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_core: Option<String>,
    /// The original representation with credentials removed, safe to display.
    pub redacted_original: String,
    /// The original representation verbatim, so re-export is lossless.
    ///
    /// Treated as a secret: it usually is a full share link.
    pub original: Secret,
}

/// Why a node could not be normalised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UnsupportedReason {
    /// The URI scheme is not one xraytui implements.
    UnknownScheme {
        /// The scheme that was seen.
        scheme: String,
    },
    /// The protocol needs a core other than Xray.
    ForeignCore {
        /// Core name.
        core: String,
    },
    /// The pinned Xray release does not implement the protocol.
    CoreTooOld {
        /// Minimum version that would work.
        minimum: String,
    },
    /// The entry parsed but a required field was missing or invalid.
    Malformed {
        /// Human-readable detail. Must not contain credentials.
        detail: String,
    },
}

impl UnsupportedReason {
    /// One-line description for the TUI.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::UnknownScheme { scheme } => format!("unknown scheme '{scheme}'"),
            Self::ForeignCore { core } => format!("requires {core}"),
            Self::CoreTooOld { minimum } => format!("needs Xray >= {minimum}"),
            Self::Malformed { detail } => format!("malformed: {detail}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Node {
        Node::new(
            NodeId::new("hk-01").expect("valid"),
            "香港 01",
            NodeSource::Manual,
            Endpoint::new("example.com", 443),
            ProtocolSettings::Vless(VlessSettings {
                id: Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: "xtls-rprx-vision".into(),
                encryption: "none".into(),
                level: None,
            }),
        )
    }

    #[test]
    fn ipv6_authority_is_bracketed() {
        assert_eq!(Endpoint::new("2001:db8::1", 443).authority(), "[2001:db8::1]:443");
        assert_eq!(Endpoint::new("1.2.3.4", 443).authority(), "1.2.3.4:443");
    }

    #[test]
    fn canonical_identity_ignores_display_name() {
        let a = sample();
        let mut b = sample();
        b.name = "different".into();
        b.tags = vec!["x".into()];
        assert_eq!(a.canonical_identity(), b.canonical_identity());
    }

    #[test]
    fn canonical_identity_separates_credentials() {
        let a = sample();
        let mut b = sample();
        b.protocol = ProtocolSettings::Vless(VlessSettings {
            id: Secret::new("99999999-2222-3333-4444-555555555555"),
            flow: "xtls-rprx-vision".into(),
            encryption: "none".into(),
            level: None,
        });
        assert_ne!(a.canonical_identity(), b.canonical_identity());
    }

    #[test]
    fn canonical_identity_leaks_no_secret() {
        let node = sample();
        let identity = node.canonical_identity();
        assert!(!identity.contains("11111111"), "{identity}");
    }

    #[test]
    fn node_round_trips_through_json() {
        let node = sample();
        let json = serde_json::to_string(&node).expect("serialise");
        let back: Node = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(node, back);
    }

    #[test]
    fn unsupported_reason_descriptions_are_short() {
        let reason = UnsupportedReason::ForeignCore { core: "sing-box".into() };
        assert_eq!(reason.describe(), "requires sing-box");
    }

    #[test]
    fn http_outbound_cannot_carry_udp() {
        let http = ProtocolSettings::Http(HttpProxySettings { username: None, password: None });
        assert!(!http.supports_udp());
        let socks = ProtocolSettings::Socks(SocksSettings {
            username: None,
            password: None,
            udp: true,
        });
        assert!(socks.supports_udp());
    }

    #[test]
    fn wireguard_rejects_stream_settings() {
        let wg = ProtocolSettings::Wireguard(Box::new(WireguardSettings {
            secret_key: Secret::new("k"),
            address: vec!["10.0.0.2/32".into()],
            peers: vec![],
            mtu: None,
            reserved: vec![],
            domain_strategy: None,
        }));
        assert!(!wg.accepts_stream_settings());
    }

    #[test]
    fn debug_of_node_does_not_reveal_uuid() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("11111111"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
