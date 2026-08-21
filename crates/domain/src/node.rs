//! Normalized outbound endpoints.
//!
//! A [`Node`] is xraytui's own representation of "somewhere traffic can leave
//! through". It is deliberately *not* Xray JSON: it is versioned, it separates
//! secrets from display data, and it preserves fields it does not understand so
//! that import → export round trips do not destroy information.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
        Self {
            address: address.into(),
            port,
        }
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
    /// WireGuard carries its own transport and cannot accept `streamSettings`.
    /// Xray-native Hysteria instead requires its QUIC configuration there.
    #[must_use]
    pub fn accepts_stream_settings(&self) -> bool {
        !matches!(self, Self::Wireguard(_))
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
    /// UDP port hopping list, e.g. `20000-30000,40000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_hopping: Option<String>,
}

impl HysteriaSettings {
    /// Return only Finalmask fields that are not already represented by the
    /// typed Hysteria obfuscation and port-hopping settings.
    ///
    /// Xray JSON places both features under `streamSettings.finalmask`, while
    /// ecosystem links carry `obfs-password` and `mport`. Treating both copies
    /// as independent would make an import/export round trip change node
    /// identity even though the compiled connection is identical.
    #[must_use]
    pub fn unrepresented_finalmask(
        &self,
        finalmask: Option<&serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let finalmask = finalmask?;
        let Some(mut root) = finalmask.as_object().cloned() else {
            return Some(finalmask.clone());
        };

        if let Some(obfs) = &self.obfs
            && let Some(masks) = root
                .get_mut("udp")
                .and_then(serde_json::Value::as_array_mut)
        {
            masks.retain(|mask| {
                !(mask.get("type").and_then(serde_json::Value::as_str) == Some("salamander")
                    && mask
                        .pointer("/settings/password")
                        .and_then(serde_json::Value::as_str)
                        == Some(obfs.expose()))
            });
            if masks.is_empty() {
                root.remove("udp");
            }
        }

        if let Some(ports) = &self.port_hopping
            && let Some(quic) = root
                .get_mut("quicParams")
                .and_then(serde_json::Value::as_object_mut)
        {
            let mut remove_hop = false;
            if let Some(hop) = quic
                .get_mut("udpHop")
                .and_then(serde_json::Value::as_object_mut)
                && hop.get("ports").and_then(serde_json::Value::as_str)
                    == Some(ports.replace(':', "-").as_str())
            {
                hop.remove("ports");
                remove_hop = hop.is_empty();
            }
            if remove_hop {
                quic.remove("udpHop");
            }
            if quic.is_empty() {
                root.remove("quicParams");
            }
        }

        (!root.is_empty()).then_some(serde_json::Value::Object(root))
    }
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
    /// Maximum transmission unit. Omitted to use the core default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Transmission time interval in milliseconds. Omitted to use the core
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tti: Option<u32>,
}

/// Transport-layer security.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "security", rename_all = "lowercase")]
#[derive(Default)]
pub enum TransportSecurity {
    /// No TLS.
    #[default]
    None,
    /// Standard TLS.
    Tls(TlsSettings),
    /// REALITY.
    Reality(RealitySettings),
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
    /// ECH config list, as accepted by Xray's `echConfigList`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech_config_list: Option<String>,
    /// Xray's ECH enforcement mode (`none`, `half` or `full`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech_force_query: Option<String>,
    /// Comma-separated SHA-256 certificate pins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_peer_cert_sha256: Option<String>,
    /// Comma-separated certificate names checked by Xray.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_peer_cert_by_name: Option<String>,
    /// Explicit TLS cipher suites. There is not yet a settled standard share
    /// parameter for this field, so standard-link export reports it as lossy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_suites: Option<String>,
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
    /// Xray Finalmask configuration. It remains JSON-shaped because upstream
    /// intentionally permits nested, extensible mask settings and the official
    /// `fm` share field carries this object verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalmask: Option<serde_json::Value>,
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
            finalmask: None,
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
    /// through [`Secret::fingerprint`] and then hashed as a complete canonical
    /// record, so it never embeds plaintext credentials. It remains sensitive
    /// identity material because low-entropy passwords can be guessed offline;
    /// prefer the node ID in ordinary logs.
    #[must_use]
    pub fn canonical_identity(&self) -> String {
        let protocol = match &self.protocol {
            ProtocolSettings::Vless(v) => serde_json::json!({
                "type": "vless", "id": v.id.fingerprint(), "flow": v.flow,
                "encryption": v.encryption, "level": v.level,
            }),
            ProtocolSettings::Vmess(v) => serde_json::json!({
                "type": "vmess", "id": v.id.fingerprint(), "security": v.security,
                "alter_id": v.alter_id, "level": v.level,
            }),
            ProtocolSettings::Trojan(t) => serde_json::json!({
                "type": "trojan", "password": t.password.fingerprint(), "flow": t.flow,
            }),
            ProtocolSettings::Shadowsocks(s) => serde_json::json!({
                "type": "shadowsocks", "method": s.method,
                "password": s.password.fingerprint(), "uot": s.uot,
                "uot_version": s.uot_version,
            }),
            ProtocolSettings::Http(h) => serde_json::json!({
                "type": "http", "username": h.username,
                "password": h.password.as_ref().map(Secret::fingerprint),
            }),
            ProtocolSettings::Socks(s) => serde_json::json!({
                "type": "socks", "username": s.username,
                "password": s.password.as_ref().map(Secret::fingerprint), "udp": s.udp,
            }),
            ProtocolSettings::Wireguard(w) => serde_json::json!({
                "type": "wireguard", "secret_key": w.secret_key.fingerprint(),
                "address": w.address,
                "peers": w.peers.iter().map(|peer| serde_json::json!({
                    "public_key": peer.public_key,
                    "pre_shared_key": peer.pre_shared_key.as_ref().map(Secret::fingerprint),
                    "endpoint": peer.endpoint,
                    "allowed_ips": if peer.allowed_ips.is_empty()
                        || (peer.allowed_ips.len() == 2
                            && peer.allowed_ips.iter().any(|ip| ip == "0.0.0.0/0")
                            && peer.allowed_ips.iter().any(|ip| ip == "::0/0"))
                    {
                        vec!["0.0.0.0/0", "::0/0"]
                    } else {
                        peer.allowed_ips.iter().map(String::as_str).collect::<Vec<_>>()
                    },
                    "keep_alive": peer.keep_alive.unwrap_or(0),
                })).collect::<Vec<_>>(),
                "mtu": w.mtu, "reserved": w.reserved,
                "domain_strategy": w.domain_strategy.as_deref().unwrap_or("forceip").to_ascii_lowercase(),
            }),
            ProtocolSettings::Hysteria(h) => serde_json::json!({
                "type": "hysteria", "auth": h.auth.fingerprint(),
                "obfs": h.obfs.as_ref().map(Secret::fingerprint),
                "up": h.up, "down": h.down, "port_hopping": h.port_hopping,
            }),
        };
        let transport = match &self.transport {
            Transport::Raw(raw) => serde_json::json!({
                "type": "raw", "header_type": raw.header_type, "host": raw.host,
                "path": raw.path,
            }),
            Transport::Xhttp(xhttp) => serde_json::json!({
                "type": "xhttp", "host": xhttp.host, "path": xhttp.path,
                "mode": xhttp.mode, "extra": xhttp.extra,
            }),
            Transport::Grpc(grpc) => serde_json::json!({
                "type": "grpc", "service_name": grpc.service_name,
                "multi_mode": grpc.multi_mode, "authority": grpc.authority,
            }),
            Transport::Websocket(ws) => {
                let header_host = ws
                    .headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value);
                let headers = ws
                    .headers
                    .iter()
                    .filter(|(key, _)| !key.eq_ignore_ascii_case("host"))
                    .collect::<BTreeMap<_, _>>();
                serde_json::json!({
                    "type": "websocket", "path": ws.path,
                    "host": ws.host.as_ref().or(header_host), "headers": headers,
                })
            }
            Transport::HttpUpgrade(hu) => serde_json::json!({
                "type": "httpupgrade", "path": hu.path, "host": hu.host,
            }),
            Transport::Mkcp(kcp) => serde_json::json!({
                "type": "mkcp", "header_type": kcp.header_type,
                "seed": kcp.seed.as_ref().map(Secret::fingerprint),
                "mtu": kcp.mtu, "tti": kcp.tti,
            }),
        };
        let security = match &self.security {
            TransportSecurity::None => serde_json::json!({"type": "none"}),
            TransportSecurity::Tls(tls) => serde_json::json!({
                "type": "tls", "server_name": tls.server_name, "alpn": tls.alpn,
                "fingerprint": tls.fingerprint, "allow_insecure": tls.allow_insecure,
                "ech_config_list": tls.ech_config_list,
                "ech_force_query": tls.ech_force_query,
                "pinned_peer_cert_sha256": tls.pinned_peer_cert_sha256,
                "verify_peer_cert_by_name": tls.verify_peer_cert_by_name,
                "cipher_suites": tls.cipher_suites,
            }),
            TransportSecurity::Reality(reality) => serde_json::json!({
                "type": "reality", "server_name": reality.server_name,
                "public_key": reality.public_key.fingerprint(),
                "short_id": reality.short_id.as_ref().map(Secret::fingerprint),
                "spider_x": reality.spider_x, "fingerprint": reality.fingerprint,
                "mldsa65_verify": reality.mldsa65_verify.as_ref().map(Secret::fingerprint),
            }),
        };
        let finalmask = match &self.protocol {
            ProtocolSettings::Hysteria(hysteria) => {
                hysteria.unrepresented_finalmask(self.finalmask.as_ref())
            }
            _ => self.finalmask.clone(),
        };
        let canonical = serde_json::json!({
            "protocol": protocol,
            "endpoint": if matches!(self.protocol, ProtocolSettings::Wireguard(_)) {
                serde_json::Value::Null
            } else {
                serde_json::json!({
                    "address": self.endpoint.address.to_ascii_lowercase(),
                    "port": self.endpoint.port,
                })
            },
            "transport": transport,
            "security": security,
            "finalmask": finalmask,
            "mux": self.mux,
            "sockopt": self.sockopt,
            "extra": self.extra,
        });
        let rendered = canonical.to_string();
        let digest = Sha256::digest(rendered.as_bytes());
        format!("sha256:{digest:x}")
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
        assert_eq!(
            Endpoint::new("2001:db8::1", 443).authority(),
            "[2001:db8::1]:443"
        );
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
    fn canonical_identity_separates_every_connection_layer() {
        let baseline = sample();

        let mut endpoint = baseline.clone();
        endpoint.endpoint.port = 8443;
        assert_ne!(baseline.canonical_identity(), endpoint.canonical_identity());

        let mut protocol = baseline.clone();
        let ProtocolSettings::Vless(settings) = &mut protocol.protocol else {
            panic!("sample is VLESS");
        };
        settings.flow.clear();
        assert_ne!(baseline.canonical_identity(), protocol.canonical_identity());

        let mut transport = baseline.clone();
        transport.transport = Transport::Websocket(WebsocketTransport {
            path: "/proxy".to_owned(),
            host: Some("cdn.example.com".to_owned()),
            headers: BTreeMap::new(),
        });
        assert_ne!(
            baseline.canonical_identity(),
            transport.canonical_identity()
        );

        let mut security = baseline.clone();
        security.security = TransportSecurity::Tls(TlsSettings {
            server_name: Some("server.example.com".to_owned()),
            ..TlsSettings::default()
        });
        assert_ne!(baseline.canonical_identity(), security.canonical_identity());
    }

    #[test]
    fn websocket_host_header_and_typed_host_have_the_same_identity() {
        let mut typed = sample();
        typed.transport = Transport::Websocket(WebsocketTransport {
            path: "/proxy".to_owned(),
            host: Some("cdn.example.com".to_owned()),
            headers: BTreeMap::new(),
        });
        let mut header = typed.clone();
        let Transport::Websocket(websocket) = &mut header.transport else {
            panic!("expected WebSocket");
        };
        websocket.host = None;
        websocket
            .headers
            .insert("Host".to_owned(), "cdn.example.com".to_owned());
        assert_eq!(typed.canonical_identity(), header.canonical_identity());
    }

    #[test]
    fn canonical_identity_contains_no_plaintext_credentials() {
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
        let reason = UnsupportedReason::ForeignCore {
            core: "sing-box".into(),
        };
        assert_eq!(reason.describe(), "requires sing-box");
    }

    #[test]
    fn http_outbound_cannot_carry_udp() {
        let http = ProtocolSettings::Http(HttpProxySettings {
            username: None,
            password: None,
        });
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
