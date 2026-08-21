//! Forms: the part of the interface that changes things.
//!
//! Pure. A form takes keys and produces a new form plus an outcome; it never
//! talks to the daemon, never touches the terminal, and never does I/O. That is
//! what makes the whole editing workflow testable without a tty — every
//! assertion in `tests.rs` is a sequence of keystrokes and an expected result.
//!
//! Forms build a [`NodeDraft`], the same type `xraytui node add` builds, so the
//! interface and the command line cannot disagree about what a field means or
//! which combinations are refused.

use xraytui_domain::draft::{NodeDraft, PROTOCOLS, SECURITIES, TRANSPORTS};
use xraytui_domain::{Node, ProtocolSettings, TransportSecurity};

use crate::app::{Key, ShareFileKind};

/// One editable line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Stable key, matched against [`NodeDraft`] field names.
    pub key: &'static str,
    /// What the user sees.
    pub label: &'static str,
    /// Current text.
    pub value: String,
    /// Whether to render as dots. Credentials are not shoulder-surfing bait.
    pub secret: bool,
    /// One line of guidance shown under the form.
    pub help: String,
}

impl Field {
    fn new(key: &'static str, label: &'static str, help: impl Into<String>) -> Self {
        Self {
            key,
            label,
            value: String::new(),
            secret: false,
            help: help.into(),
        }
    }

    fn secret(mut self) -> Self {
        self.secret = true;
        self
    }

    fn with(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self
    }
}

/// What a completed form should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormKind {
    /// Create a node.
    NodeAdd,
    /// Change an existing node.
    NodeEdit {
        /// Which node.
        id: String,
    },
    /// Paste share links.
    ImportLinks,
    /// Add a subscription.
    Subscription,
    /// Create a profile.
    Profile,
    /// Assign a program to a profile.
    AppAssign {
        /// Profile the rule points at.
        profile: String,
    },
    /// Change a profile's listeners.
    Listeners {
        /// Profile being changed.
        profile: String,
    },
    /// Export one node from the sharing menu.
    ShareExport {
        /// Which node.
        id: String,
        /// Representation being written.
        kind: ShareFileKind,
    },
}

/// What happened to a keystroke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Still editing.
    Editing,
    /// The user gave up; nothing should change.
    Cancelled,
    /// The user is finished; the caller should act on the form.
    Submit,
}

/// A form on top of the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// Shown in the frame.
    pub title: String,
    /// Editable lines, in tab order.
    pub fields: Vec<Field>,
    /// Which line has focus.
    pub cursor: usize,
    /// What to do on submit.
    pub kind: FormKind,
    /// Set when a value was rejected, shown in red under the form.
    pub error: Option<String>,
}

impl Form {
    /// A form for a new node.
    ///
    /// Deliberately one screen: protocol, name, address, port, the credential,
    /// and the transport and TLS fields that most nodes actually use. Rarer
    /// settings stay editable as normalised TOML, because a form long enough to
    /// hold everything is a form nobody finishes.
    #[must_use]
    pub fn node_add() -> Self {
        Self {
            title: "Add node".to_owned(),
            fields: vec![
                Field::new("protocol", "Protocol", const_join(PROTOCOLS)).with("vless"),
                Field::new("name", "Name", "shown in lists; anything you like"),
                Field::new("address", "Address", "hostname or IP"),
                Field::new("port", "Port", "1–65535"),
                Field::new("uuid", "UUID", "VLESS and VMess credential").secret(),
                Field::new("password", "Password", "Trojan, Shadowsocks, HTTP, SOCKS").secret(),
                Field::new("method", "Method", "Shadowsocks cipher, e.g. aes-256-gcm"),
                Field::new("flow", "Flow", "VLESS/XTLS only, e.g. xtls-rprx-vision"),
                Field::new("transport", "Transport", const_join(TRANSPORTS)).with("raw"),
                Field::new(
                    "path",
                    "Path",
                    "ws / httpupgrade path, or gRPC service name",
                ),
                Field::new("host", "Host", "Host header or gRPC authority"),
                Field::new("tls", "Security", const_join(SECURITIES)).with("none"),
                Field::new("sni", "SNI", "server name for TLS or REALITY"),
                Field::new("public_key", "REALITY key", "the pbk from the share link").secret(),
                Field::new("short_id", "REALITY sid", "the sid from the share link").secret(),
            ],
            cursor: 0,
            kind: FormKind::NodeAdd,
            error: None,
        }
    }

    /// A form pre-filled from an existing node.
    ///
    /// Credentials are *not* pre-filled: leaving a field empty means "keep what
    /// is there", so a person editing a port never has to retype a UUID, and a
    /// screen-share never shows one.
    #[must_use]
    pub fn node_edit(node: &Node) -> Self {
        let mut form = Self::node_add();
        form.title = format!("Edit {}", node.name);
        form.kind = FormKind::NodeEdit {
            id: node.id.to_string(),
        };
        let protocol = node.protocol.xray_protocol().to_owned();
        for field in &mut form.fields {
            field.value = match field.key {
                "protocol" => protocol.clone(),
                "name" => node.name.clone(),
                "address" => node.endpoint.address.clone(),
                "port" => node.endpoint.port.to_string(),
                "transport" => node.transport.xray_network().to_owned(),
                "tls" => node.security.xray_security().to_owned(),
                "sni" => match &node.security {
                    TransportSecurity::Tls(tls) => tls.server_name.clone().unwrap_or_default(),
                    TransportSecurity::Reality(reality) => {
                        reality.server_name.clone().unwrap_or_default()
                    }
                    TransportSecurity::None => String::new(),
                },
                "flow" => match &node.protocol {
                    ProtocolSettings::Vless(settings) => settings.flow.clone(),
                    ProtocolSettings::Trojan(settings) => settings.flow.clone(),
                    _ => String::new(),
                },
                "method" => match &node.protocol {
                    ProtocolSettings::Shadowsocks(settings) => settings.method.clone(),
                    _ => String::new(),
                },
                // Secrets stay blank on purpose.
                _ => String::new(),
            };
            if field.secret {
                field.help = "leave blank to keep the current value".to_owned();
            }
        }
        // The protocol cannot change on an edit — different credentials, a
        // different transport — so the field is shown for context and refused
        // if altered, by the same rule the CLI applies.
        form
    }

    /// A form for pasting share links.
    #[must_use]
    pub fn import_links() -> Self {
        Self {
            title: "Import share links".to_owned(),
            fields: vec![Field::new(
                "links",
                "Links",
                "vless:// vmess:// trojan:// ss:// — separate several with spaces",
            )],
            cursor: 0,
            kind: FormKind::ImportLinks,
            error: None,
        }
    }

    /// A form for a subscription.
    #[must_use]
    pub fn subscription() -> Self {
        Self {
            title: "Add subscription".to_owned(),
            fields: vec![
                Field::new("url", "URL", "https://… — treat it as a credential").secret(),
                Field::new("name", "Name", "shown in lists"),
            ],
            cursor: 0,
            kind: FormKind::Subscription,
            error: None,
        }
    }

    /// A form for a profile.
    #[must_use]
    pub fn profile() -> Self {
        Self {
            title: "Add profile".to_owned(),
            fields: vec![
                Field::new("id", "Identifier", "lowercase letters, digits and -"),
                Field::new("name", "Name", "shown in lists"),
                Field::new("socks", "SOCKS port", "loopback only; blank for none"),
                Field::new("http", "HTTP port", "loopback only; blank for none"),
            ],
            cursor: 0,
            kind: FormKind::Profile,
            error: None,
        }
    }

    /// A form assigning a program to a profile.
    #[must_use]
    pub fn app_assign(profile: &str) -> Self {
        Self {
            title: format!("Route a program through '{profile}'"),
            fields: vec![Field::new(
                "matcher",
                "Program",
                "a name like firefox, an absolute path, or a directory ending in /",
            )],
            cursor: 0,
            kind: FormKind::AppAssign {
                profile: profile.to_owned(),
            },
            error: None,
        }
    }

    /// A form for a profile's listeners.
    #[must_use]
    pub fn listeners(profile: &str, socks: Option<u16>, http: Option<u16>) -> Self {
        Self {
            title: format!("Listeners of '{profile}'"),
            fields: vec![
                Field::new("socks", "SOCKS port", "0 removes it")
                    .with(socks.map(|p| p.to_string()).unwrap_or_default()),
                Field::new("http", "HTTP port", "0 removes it")
                    .with(http.map(|p| p.to_string()).unwrap_or_default()),
            ],
            cursor: 0,
            kind: FormKind::Listeners {
                profile: profile.to_owned(),
            },
            error: None,
        }
    }

    /// A one-field destination form for an explicit secret export.
    #[must_use]
    pub fn share_export(node: &str, kind: ShareFileKind) -> Self {
        let (title, suffix) = match kind {
            ShareFileKind::QrPng => ("Export PNG QR", "png"),
            ShareFileKind::ShareLink => ("Export share link", "txt"),
            ShareFileKind::XrayJson => ("Export Xray outbound", "json"),
        };
        Self {
            title: format!("{title}: {node}"),
            fields: vec![
                Field::new(
                    "path",
                    "Path",
                    "credential-bearing file; written atomically with mode 0600",
                )
                .with(format!("{node}.{suffix}")),
            ],
            cursor: 0,
            kind: FormKind::ShareExport {
                id: node.to_owned(),
                kind,
            },
            error: None,
        }
    }

    /// Value of a field, trimmed.
    #[must_use]
    pub fn value(&self, key: &str) -> &str {
        self.fields
            .iter()
            .find(|field| field.key == key)
            .map_or("", |field| field.value.trim())
    }

    /// Value of a field, or `None` when it was left blank.
    #[must_use]
    pub fn filled(&self, key: &str) -> Option<String> {
        let value = self.value(key);
        (!value.is_empty()).then(|| value.to_owned())
    }

    /// Handle one keystroke.
    ///
    /// `Enter` on the last field submits; `Enter` anywhere else moves down, so
    /// filling a form top to bottom works without learning anything.
    pub fn on_key(&mut self, key: Key) -> Outcome {
        self.error = None;
        match key {
            Key::Escape => Outcome::Cancelled,
            Key::Tab | Key::Down => {
                self.cursor = (self.cursor + 1) % self.fields.len().max(1);
                Outcome::Editing
            }
            Key::BackTab | Key::Up => {
                self.cursor = self
                    .cursor
                    .checked_sub(1)
                    .unwrap_or(self.fields.len().saturating_sub(1));
                Outcome::Editing
            }
            Key::Enter => {
                if self.cursor + 1 < self.fields.len() {
                    self.cursor += 1;
                    Outcome::Editing
                } else {
                    Outcome::Submit
                }
            }
            Key::Backspace => {
                if let Some(field) = self.fields.get_mut(self.cursor) {
                    field.value.pop();
                }
                Outcome::Editing
            }
            Key::Char(character) => {
                if let Some(field) = self.fields.get_mut(self.cursor) {
                    // Bounded: a pasted file into a form field should not become
                    // an unbounded allocation in a long-running process.
                    if field.value.chars().count() < 512 {
                        field.value.push(character);
                    }
                }
                Outcome::Editing
            }
            _ => Outcome::Editing,
        }
    }

    /// Build the draft this form describes.
    ///
    /// The same [`NodeDraft`] the CLI builds, so the two cannot disagree about
    /// which fields belong to which protocol.
    #[must_use]
    pub fn draft(&self) -> NodeDraft {
        let editing = matches!(self.kind, FormKind::NodeEdit { .. });
        // On an edit, a blank field means "leave it alone" — that is why the
        // secrets are not pre-filled. On a create, blank means unset.
        let take = |key: &str| -> Option<String> {
            if editing {
                self.filled(key)
            } else {
                let value = self.value(key);
                (!value.is_empty()).then(|| value.to_owned())
            }
        };
        NodeDraft {
            protocol: take("protocol"),
            name: take("name"),
            address: take("address"),
            port: self.value("port").parse().ok(),
            uuid: take("uuid"),
            password: take("password"),
            username: None,
            method: take("method"),
            flow: take("flow"),
            transport: take("transport"),
            tls: take("tls"),
            sni: take("sni"),
            public_key: take("public_key"),
            short_id: take("short_id"),
            fingerprint: None,
            alpn: Vec::new(),
            path: take("path"),
            host: take("host"),
            service_name: if self.value("transport") == "grpc" {
                take("path")
            } else {
                None
            },
            tags: Vec::new(),
            region: None,
        }
    }
}

/// `"a, b, c"` from a static list, for help text.
fn const_join(values: &[&str]) -> String {
    values.join(", ")
}

#[cfg(test)]
mod tests;
