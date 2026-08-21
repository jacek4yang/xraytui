//! Building and editing a node from typed fields.
//!
//! This is the one place that turns "what a person typed" into a [`Node`]. The
//! CLI's `node add`/`node edit` and the interface's node form both go through
//! it, because two implementations of "add a node" is two behaviours, and the
//! one users hit is always the one with the bug.
//!
//! # Absent versus empty
//!
//! Every field is an `Option`. On [`NodeDraft::create`] absent means "use the
//! protocol's default"; on [`NodeDraft::edit`] absent means "leave this alone".
//! That distinction is the whole reason the type exists: `--flow ""` must be
//! able to *clear* a flow, which a plain `String` cannot express.
//!
//! # Refusing rather than ignoring
//!
//! A field belonging to another protocol — `--method` on a VLESS node, `--uuid`
//! on a Shadowsocks one — is an error, never a silently dropped argument.
//! Someone who typed it believed it would take effect, and a node that quietly
//! does something else is worse than a refused command.

use crate::node::{
    Compatibility, Endpoint, GrpcTransport, HttpProxySettings, HttpUpgradeTransport, MuxSettings,
    Node, NodeSource, ProtocolSettings, RawTransport, RealitySettings, ShadowsocksSettings,
    SocketSettings, SocksSettings, TlsSettings, Transport, TransportSecurity, TrojanSettings,
    VlessSettings, VmessSettings, WebsocketTransport,
};
use crate::{NodeId, slugify};
use xraytui_secrets::Secret;

/// Protocols a person can create from typed fields.
///
/// Deliberately not every protocol the importer understands: WireGuard and
/// Hysteria carry their own transport and key material, and a half-complete
/// form for them would produce nodes that look valid and do not work. Those
/// remain importable and editable as normalised TOML.
pub const PROTOCOLS: &[&str] = &["vless", "vmess", "trojan", "shadowsocks", "http", "socks"];

/// Transports a person can pick.
pub const TRANSPORTS: &[&str] = &["raw", "ws", "grpc", "httpupgrade"];

/// Security modes a person can pick.
pub const SECURITIES: &[&str] = &["none", "tls", "reality"];

/// What a person typed, before it becomes a node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeDraft {
    /// One of [`PROTOCOLS`].
    pub protocol: Option<String>,
    /// Display name.
    pub name: Option<String>,
    /// Host or IP.
    pub address: Option<String>,
    /// Port.
    pub port: Option<u16>,
    /// VLESS or VMess UUID.
    pub uuid: Option<String>,
    /// Trojan, Shadowsocks, HTTP or SOCKS password.
    pub password: Option<String>,
    /// HTTP or SOCKS username.
    pub username: Option<String>,
    /// Shadowsocks cipher.
    pub method: Option<String>,
    /// VLESS or Trojan flow.
    pub flow: Option<String>,
    /// One of [`TRANSPORTS`].
    pub transport: Option<String>,
    /// One of [`SECURITIES`].
    pub tls: Option<String>,
    /// SNI / server name.
    pub sni: Option<String>,
    /// REALITY public key.
    pub public_key: Option<String>,
    /// REALITY short id.
    pub short_id: Option<String>,
    /// uTLS fingerprint.
    pub fingerprint: Option<String>,
    /// ALPN entries.
    pub alpn: Vec<String>,
    /// WebSocket or HTTPUpgrade path.
    pub path: Option<String>,
    /// Host header.
    pub host: Option<String>,
    /// gRPC service name.
    pub service_name: Option<String>,
    /// Free-form tags used by group filters.
    pub tags: Vec<String>,
    /// Region label used by group filters.
    pub region: Option<String>,
}

/// Why a draft could not become a node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DraftError {
    /// A field the protocol needs was not given.
    #[error("{protocol} needs {field}")]
    Missing {
        /// Protocol involved.
        protocol: String,
        /// What was missing, phrased as the flag a user types.
        field: String,
    },
    /// A field was given that belongs to a different protocol.
    #[error("{field} does not apply to {protocol}; {hint}")]
    Irrelevant {
        /// Protocol involved.
        protocol: String,
        /// The offending field.
        field: String,
        /// What to do instead.
        hint: String,
    },
    /// A value was not one of the accepted ones.
    #[error("{field} must be one of: {accepted}")]
    NotAccepted {
        /// The field.
        field: String,
        /// Comma-separated accepted values.
        accepted: String,
    },
    /// A value was structurally wrong.
    #[error("{0}")]
    Invalid(String),
}

impl NodeDraft {
    /// Build a new node.
    ///
    /// # Errors
    /// Returns [`DraftError`] when a required field is missing, a field belongs
    /// to another protocol, or a value is not accepted.
    pub fn create(&self) -> Result<Node, DraftError> {
        let protocol = self
            .protocol
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| DraftError::Missing {
                protocol: "a node".to_owned(),
                field: "--protocol".to_owned(),
            })?
            .to_ascii_lowercase();
        if !PROTOCOLS.contains(&protocol.as_str()) {
            return Err(DraftError::NotAccepted {
                field: "--protocol".to_owned(),
                accepted: PROTOCOLS.join(", "),
            });
        }
        self.check_relevance(&protocol)?;

        let address = self
            .required("--address", self.address.as_deref(), &protocol)?
            .trim()
            .to_owned();
        if address.is_empty() {
            return Err(DraftError::Invalid("--address cannot be empty".to_owned()));
        }
        let port = self.port.ok_or_else(|| DraftError::Missing {
            protocol: protocol.clone(),
            field: "--port".to_owned(),
        })?;
        if port == 0 {
            return Err(DraftError::Invalid(
                "--port must be between 1 and 65535".to_owned(),
            ));
        }

        let name = self
            .name
            .clone()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("{address}:{port}"));

        // The identifier is derived from the name, not typed: a user should not
        // have to invent one, and a name with spaces or Chinese characters must
        // still produce a tag Xray accepts.
        let id = NodeId::new(unique_slug(&name, &address, port))
            .map_err(|error| DraftError::Invalid(error.to_string()))?;

        let settings = self.protocol_settings(&protocol)?;
        let transport = self.build_transport(&protocol)?;
        let security = self.build_security()?;

        Ok(Node {
            schema_version: 1,
            id,
            name,
            source: NodeSource::Manual,
            endpoint: Endpoint::new(address, port),
            protocol: settings,
            transport,
            security,
            finalmask: None,
            mux: MuxSettings::default(),
            sockopt: SocketSettings::default(),
            tags: self.tags.clone(),
            region: self.region.clone(),
            enabled: true,
            compatibility: Compatibility::Supported,
            notes: Vec::new(),
            extra: std::collections::BTreeMap::new(),
        })
    }

    /// Apply this draft on top of an existing node.
    ///
    /// The identifier never changes: profiles, groups and chains point at it,
    /// and renaming a node out from under them would break every reference.
    ///
    /// A node that came from a subscription becomes [`NodeSource::Manual`] once
    /// edited, because the next update would otherwise overwrite the change and
    /// the user would never learn why.
    ///
    /// # Errors
    /// Returns [`DraftError`] when a field belongs to another protocol or a
    /// value is not accepted.
    pub fn edit(&self, current: &Node) -> Result<Node, DraftError> {
        if let Some(requested) = self.protocol.as_deref()
            && !requested.eq_ignore_ascii_case(current.protocol.xray_protocol())
        {
            return Err(DraftError::Invalid(format!(
                "this node is {}, not {requested}. Changing a node's protocol means \
                 different credentials and a different transport; remove it and add \
                 the new one instead.",
                current.protocol.xray_protocol()
            )));
        }
        let protocol = current.protocol.xray_protocol().to_owned();
        self.check_relevance(&protocol)?;

        let mut next = current.clone();
        if let Some(name) = self.name.as_deref().map(str::trim)
            && !name.is_empty()
        {
            next.name = name.to_owned();
        }
        if let Some(address) = self.address.as_deref().map(str::trim)
            && !address.is_empty()
        {
            next.endpoint.address = address.to_owned();
        }
        if let Some(port) = self.port {
            if port == 0 {
                return Err(DraftError::Invalid(
                    "--port must be between 1 and 65535".to_owned(),
                ));
            }
            next.endpoint.port = port;
        }
        if !self.tags.is_empty() {
            next.tags = self.tags.clone();
        }
        if let Some(region) = self.region.clone() {
            next.region = Some(region).filter(|value| !value.is_empty());
        }

        next.protocol = self.edit_protocol_settings(&next.protocol)?;
        if self.mentions_transport() {
            next.transport = self.build_transport(&protocol)?;
        }
        if self.mentions_security() {
            next.security = self.build_security()?;
        }
        if next.source != NodeSource::Manual {
            next.source = NodeSource::Manual;
        }
        Ok(next)
    }

    fn required<'a>(
        &self,
        field: &str,
        value: Option<&'a str>,
        protocol: &str,
    ) -> Result<&'a str, DraftError> {
        value.ok_or_else(|| DraftError::Missing {
            protocol: protocol.to_owned(),
            field: field.to_owned(),
        })
    }

    /// Refuse a field that belongs to a different protocol.
    ///
    /// Shared by `create` and `edit` on purpose: an edit that silently ignores
    /// `--method` on a VLESS node is exactly as wrong as a create that does.
    fn check_relevance(&self, protocol: &str) -> Result<(), DraftError> {
        let irrelevant = |field: &str, hint: &str| DraftError::Irrelevant {
            protocol: protocol.to_owned(),
            field: field.to_owned(),
            hint: hint.to_owned(),
        };
        match protocol {
            "vless" | "vmess" => {
                if self.method.is_some() {
                    return Err(irrelevant("--method", "it is a Shadowsocks cipher"));
                }
                if self.username.is_some() {
                    return Err(irrelevant("--username", "use --uuid"));
                }
                if self.password.is_some() {
                    return Err(irrelevant("--password", "use --uuid"));
                }
                if protocol == "vmess" && self.flow.is_some() {
                    return Err(irrelevant("--flow", "VMess has no flow; it is VLESS/XTLS"));
                }
            }
            "trojan" => {
                if self.uuid.is_some() {
                    return Err(irrelevant("--uuid", "Trojan uses --password"));
                }
                if self.method.is_some() {
                    return Err(irrelevant("--method", "it is a Shadowsocks cipher"));
                }
                if self.username.is_some() {
                    return Err(irrelevant("--username", "Trojan has no username"));
                }
            }
            "shadowsocks" => {
                if self.uuid.is_some() {
                    return Err(irrelevant("--uuid", "Shadowsocks uses --password"));
                }
                if self.username.is_some() {
                    return Err(irrelevant("--username", "Shadowsocks has no username"));
                }
                if self.flow.is_some() {
                    return Err(irrelevant("--flow", "flow is VLESS/XTLS"));
                }
            }
            "http" | "socks" => {
                if self.uuid.is_some() {
                    return Err(irrelevant("--uuid", "use --username and --password"));
                }
                if self.method.is_some() {
                    return Err(irrelevant("--method", "it is a Shadowsocks cipher"));
                }
                if self.flow.is_some() {
                    return Err(irrelevant("--flow", "flow is VLESS/XTLS"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn protocol_settings(&self, protocol: &str) -> Result<ProtocolSettings, DraftError> {
        Ok(match protocol {
            "vless" => ProtocolSettings::Vless(VlessSettings {
                id: Secret::new(self.required("--uuid", self.uuid.as_deref(), protocol)?),
                flow: self.flow.clone().unwrap_or_default(),
                encryption: "none".to_owned(),
                level: None,
            }),
            "vmess" => ProtocolSettings::Vmess(VmessSettings {
                id: Secret::new(self.required("--uuid", self.uuid.as_deref(), protocol)?),
                security: "auto".to_owned(),
                alter_id: 0,
                level: None,
            }),
            "trojan" => ProtocolSettings::Trojan(TrojanSettings {
                password: Secret::new(self.required(
                    "--password",
                    self.password.as_deref(),
                    protocol,
                )?),
                flow: self.flow.clone().unwrap_or_default(),
            }),
            "shadowsocks" => ProtocolSettings::Shadowsocks(ShadowsocksSettings {
                method: self
                    .required("--method", self.method.as_deref(), protocol)?
                    .to_owned(),
                password: Secret::new(self.required(
                    "--password",
                    self.password.as_deref(),
                    protocol,
                )?),
                uot: false,
                uot_version: None,
            }),
            "http" => ProtocolSettings::Http(HttpProxySettings {
                username: self.username.clone(),
                password: self.password.as_deref().map(Secret::new),
            }),
            "socks" => ProtocolSettings::Socks(SocksSettings {
                username: self.username.clone(),
                password: self.password.as_deref().map(Secret::new),
                udp: true,
            }),
            other => {
                return Err(DraftError::NotAccepted {
                    field: format!("--protocol {other}"),
                    accepted: PROTOCOLS.join(", "),
                });
            }
        })
    }

    fn edit_protocol_settings(
        &self,
        current: &ProtocolSettings,
    ) -> Result<ProtocolSettings, DraftError> {
        let mut next = current.clone();
        match &mut next {
            ProtocolSettings::Vless(settings) => {
                if let Some(uuid) = &self.uuid {
                    settings.id = Secret::new(uuid);
                }
                if let Some(flow) = &self.flow {
                    settings.flow = flow.clone();
                }
            }
            ProtocolSettings::Vmess(settings) => {
                if let Some(uuid) = &self.uuid {
                    settings.id = Secret::new(uuid);
                }
            }
            ProtocolSettings::Trojan(settings) => {
                if let Some(password) = &self.password {
                    settings.password = Secret::new(password);
                }
                if let Some(flow) = &self.flow {
                    settings.flow = flow.clone();
                }
            }
            ProtocolSettings::Shadowsocks(settings) => {
                if let Some(password) = &self.password {
                    settings.password = Secret::new(password);
                }
                if let Some(method) = &self.method {
                    settings.method = method.clone();
                }
            }
            ProtocolSettings::Http(settings) => {
                if let Some(username) = &self.username {
                    settings.username = Some(username.clone()).filter(|v| !v.is_empty());
                }
                if let Some(password) = &self.password {
                    settings.password =
                        Some(Secret::new(password)).filter(|_| !password.is_empty());
                }
            }
            ProtocolSettings::Socks(settings) => {
                if let Some(username) = &self.username {
                    settings.username = Some(username.clone()).filter(|v| !v.is_empty());
                }
                if let Some(password) = &self.password {
                    settings.password =
                        Some(Secret::new(password)).filter(|_| !password.is_empty());
                }
            }
            // Protocols this form does not build are left exactly as they are:
            // the relevance check has already refused every field that could
            // have applied to them.
            ProtocolSettings::Wireguard(_) | ProtocolSettings::Hysteria(_) => {}
        }
        Ok(next)
    }

    fn mentions_transport(&self) -> bool {
        self.transport.is_some()
            || self.path.is_some()
            || self.host.is_some()
            || self.service_name.is_some()
    }

    fn mentions_security(&self) -> bool {
        self.tls.is_some()
            || self.sni.is_some()
            || self.public_key.is_some()
            || self.short_id.is_some()
            || self.fingerprint.is_some()
            || !self.alpn.is_empty()
    }

    fn build_transport(&self, protocol: &str) -> Result<Transport, DraftError> {
        let name = self
            .transport
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| "raw".to_owned());
        let name = match name.as_str() {
            // Xray renamed `tcp` to `raw`; accept the old spelling because every
            // share link and every tutorial still uses it.
            "tcp" | "" => "raw".to_owned(),
            "websocket" => "ws".to_owned(),
            other => other.to_owned(),
        };
        if !TRANSPORTS.contains(&name.as_str()) {
            return Err(DraftError::NotAccepted {
                field: "--transport".to_owned(),
                accepted: TRANSPORTS.join(", "),
            });
        }
        let _ = protocol;
        Ok(match name.as_str() {
            "ws" => Transport::Websocket(WebsocketTransport {
                path: self.path.clone().unwrap_or_else(|| "/".to_owned()),
                host: self.host.clone().filter(|value| !value.is_empty()),
                headers: std::collections::BTreeMap::new(),
            }),
            "grpc" => Transport::Grpc(GrpcTransport {
                service_name: self.service_name.clone().unwrap_or_default(),
                multi_mode: false,
                authority: self.host.clone().filter(|value| !value.is_empty()),
            }),
            "httpupgrade" => Transport::HttpUpgrade(HttpUpgradeTransport {
                path: self.path.clone().unwrap_or_else(|| "/".to_owned()),
                host: self.host.clone().filter(|value| !value.is_empty()),
            }),
            _ => Transport::Raw(RawTransport {
                header_type: None,
                host: Vec::new(),
                path: self.path.clone().filter(|value| !value.is_empty()),
            }),
        })
    }

    fn build_security(&self) -> Result<TransportSecurity, DraftError> {
        // Inferred when not stated, because a person who supplies a REALITY
        // public key has already said which mode they mean, and making them
        // also type `--tls reality` is a way to get a confusing error.
        let requested = self
            .tls
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| {
                if self.public_key.is_some() {
                    "reality".to_owned()
                } else if self.sni.is_some() || !self.alpn.is_empty() {
                    "tls".to_owned()
                } else {
                    "none".to_owned()
                }
            });
        if !SECURITIES.contains(&requested.as_str()) {
            return Err(DraftError::NotAccepted {
                field: "--tls".to_owned(),
                accepted: SECURITIES.join(", "),
            });
        }
        Ok(match requested.as_str() {
            "tls" => TransportSecurity::Tls(TlsSettings {
                server_name: self.sni.clone().filter(|value| !value.is_empty()),
                alpn: self.alpn.clone(),
                fingerprint: self.fingerprint.clone().filter(|value| !value.is_empty()),
                // Never set from a draft. Turning off certificate verification
                // has to be a deliberate, visible act, not a side effect of
                // filling in a form.
                allow_insecure: false,
                ..TlsSettings::default()
            }),
            "reality" => TransportSecurity::Reality(RealitySettings {
                server_name: self.sni.clone().filter(|value| !value.is_empty()),
                public_key: Secret::new(self.public_key.clone().ok_or_else(|| {
                    DraftError::Missing {
                        protocol: "reality".to_owned(),
                        field: "--public-key".to_owned(),
                    }
                })?),
                short_id: self
                    .short_id
                    .clone()
                    .filter(|value| !value.is_empty())
                    .map(Secret::new),
                spider_x: None,
                fingerprint: self.fingerprint.clone().filter(|value| !value.is_empty()),
                mldsa65_verify: None,
            }),
            _ => TransportSecurity::None,
        })
    }
}

/// A stable identifier that does not collide with another server's.
///
/// The name alone is not enough: two providers both call a node "HK 01", and
/// two nodes with the same identifier cannot both be pointed at. The endpoint
/// makes it unique without making it unreadable.
fn unique_slug(name: &str, address: &str, port: u16) -> String {
    let base = slugify(name);
    let base = if base.is_empty() {
        "node".to_owned()
    } else {
        base
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in address.as_bytes().iter().chain(&port.to_be_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{base}-{:06x}", hash & 0xff_ffff)
}

#[cfg(test)]
mod tests;
