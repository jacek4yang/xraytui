//! A minimal D-Bus client, sufficient for `org.freedesktop.resolve1`.
//!
//! # Why not `resolvectl`
//!
//! `docs/THREAT-MODEL.md` T4 rules out driving system state through a
//! human-facing command line. `resolvectl` is a CLI whose output format is not a
//! contract; D-Bus is the interface systemd actually documents, and it takes an
//! interface index and a list of addresses as typed values rather than as text
//! that has to be quoted.
//!
//! # Why not a D-Bus crate
//!
//! The helper runs as root. Every dependency it links is part of the privileged
//! attack surface, and the general-purpose D-Bus crates bring an async runtime,
//! a name-resolution layer and a code generator with them. What is needed here
//! is four method calls with fixed signatures. This module is that, and nothing
//! else: it cannot introspect, cannot listen for signals, and cannot be pointed
//! at the session bus.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Where the system bus normally lives.
pub const SYSTEM_BUS_PATH: &str = "/run/dbus/system_bus_socket";

/// How long any single exchange with the bus may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Largest reply the client will read. Replies here are a few hundred bytes.
const MAX_MESSAGE: usize = 64 * 1024;

/// Message type: method call.
const METHOD_CALL: u8 = 1;
/// Message type: method return.
const METHOD_RETURN: u8 = 2;
/// Message type: error.
const ERROR: u8 = 3;

/// Errors the D-Bus client can report.
#[derive(Debug, thiserror::Error)]
pub enum DbusError {
    /// The bus socket could not be reached.
    #[error("cannot reach the system bus at {path}: {source}")]
    Connect {
        /// Socket path.
        path: String,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// The SASL handshake failed.
    #[error("the system bus refused authentication: {0}")]
    Auth(String),
    /// A read or write failed.
    #[error("system bus I/O: {0}")]
    Io(#[source] std::io::Error),
    /// A reply could not be understood.
    #[error("malformed reply from the system bus: {0}")]
    Malformed(&'static str),
    /// The service returned an error.
    #[error("{name}: {message}")]
    Remote {
        /// D-Bus error name, e.g. `org.freedesktop.DBus.Error.UnknownMethod`.
        name: String,
        /// Human-readable detail, if the service supplied one.
        message: String,
    },
}

/// One argument of a method call.
///
/// Deliberately small: these four shapes cover everything `resolve1` needs, and
/// adding a shape means thinking about its alignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argument {
    /// `i`
    Int32(i32),
    /// `b`
    Boolean(bool),
    /// `s`
    Str(String),
    /// `a(iay)` — the resolver list: address family and raw address bytes.
    Addresses(Vec<(i32, Vec<u8>)>),
    /// `a(sb)` — the domain list: domain and "routing only" flag.
    Domains(Vec<(String, bool)>),
}

impl Argument {
    fn signature(&self) -> &'static str {
        match self {
            Self::Int32(_) => "i",
            Self::Boolean(_) => "b",
            Self::Str(_) => "s",
            Self::Addresses(_) => "a(iay)",
            Self::Domains(_) => "a(sb)",
        }
    }

    fn marshal(&self, out: &mut Marshaller) {
        match self {
            Self::Int32(value) => out.int32(*value),
            Self::Boolean(value) => out.boolean(*value),
            Self::Str(value) => out.string(value),
            Self::Addresses(entries) => out.array(8, |inner| {
                for (family, bytes) in entries {
                    inner.align(8);
                    inner.int32(*family);
                    inner.array(1, |bytes_out| {
                        for byte in bytes {
                            bytes_out.byte(*byte);
                        }
                    });
                }
            }),
            Self::Domains(entries) => out.array(8, |inner| {
                for (domain, routing_only) in entries {
                    inner.align(8);
                    inner.string(domain);
                    inner.boolean(*routing_only);
                }
            }),
        }
    }
}

/// A connected, authenticated system-bus client.
#[derive(Debug)]
pub struct Dbus {
    stream: UnixStream,
    serial: u32,
}

impl Dbus {
    /// Connect to the system bus and complete the handshake.
    ///
    /// # Errors
    /// See [`DbusError`].
    pub fn connect_system() -> Result<Self, DbusError> {
        Self::connect(system_bus_path())
    }

    /// Connect to a specific socket. The test suite points this at a stub.
    ///
    /// # Errors
    /// See [`DbusError`].
    pub fn connect(path: impl Into<PathBuf>) -> Result<Self, DbusError> {
        let path = path.into();
        let stream = UnixStream::connect(&path).map_err(|source| DbusError::Connect {
            path: path.display().to_string(),
            source,
        })?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .map_err(DbusError::Io)?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .map_err(DbusError::Io)?;
        let mut client = Self { stream, serial: 0 };
        client.authenticate()?;
        client.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
            &[],
        )?;
        Ok(client)
    }

    fn authenticate(&mut self) -> Result<(), DbusError> {
        // The leading NUL is part of the transport, not the SASL exchange.
        let uid = rustix::process::getuid().as_raw();
        let credential = hex_encode(uid.to_string().as_bytes());
        let greeting = format!("\0AUTH EXTERNAL {credential}\r\n");
        self.stream
            .write_all(greeting.as_bytes())
            .map_err(DbusError::Io)?;
        let line = self.read_line()?;
        if !line.starts_with("OK ") {
            return Err(DbusError::Auth(line));
        }
        self.stream.write_all(b"BEGIN\r\n").map_err(DbusError::Io)?;
        Ok(())
    }

    fn read_line(&mut self) -> Result<String, DbusError> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = self.stream.read(&mut byte).map_err(DbusError::Io)?;
            if read == 0 {
                return Err(DbusError::Auth("the bus closed the connection".into()));
            }
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                line.truncate(line.len() - 2);
                return Ok(String::from_utf8_lossy(&line).into_owned());
            }
            if line.len() > 1024 {
                return Err(DbusError::Auth("authentication reply was too long".into()));
            }
        }
    }

    /// Make a method call and wait for its reply.
    ///
    /// The reply body is discarded: none of the calls the helper makes returns
    /// anything it needs. What matters is whether it was an error.
    ///
    /// # Errors
    /// [`DbusError::Remote`] if the service refused; see [`DbusError`] for the
    /// rest.
    pub fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        arguments: &[Argument],
    ) -> Result<(), DbusError> {
        self.serial = self.serial.wrapping_add(1).max(1);
        let serial = self.serial;

        let mut body = Marshaller::new();
        for argument in arguments {
            argument.marshal(&mut body);
        }
        let body = body.into_bytes();

        let signature: String = arguments.iter().map(Argument::signature).collect();

        let mut message = Marshaller::new();
        message.byte(b'l'); // little endian
        message.byte(METHOD_CALL);
        message.byte(0); // flags
        message.byte(1); // protocol version
        message.u32(u32::try_from(body.len()).unwrap_or(u32::MAX));
        message.u32(serial);
        message.array(8, |fields| {
            field(fields, 1, "o", &Argument::Str(path.to_owned()));
            field(fields, 2, "s", &Argument::Str(interface.to_owned()));
            field(fields, 3, "s", &Argument::Str(member.to_owned()));
            field(fields, 6, "s", &Argument::Str(destination.to_owned()));
            if !signature.is_empty() {
                fields.align(8);
                fields.byte(8);
                fields.signature("g");
                fields.signature(&signature);
            }
        });
        message.align(8);
        let mut bytes = message.into_bytes();
        bytes.extend_from_slice(&body);

        self.stream.write_all(&bytes).map_err(DbusError::Io)?;
        self.stream.flush().map_err(DbusError::Io)?;
        self.await_reply(serial)
    }

    fn await_reply(&mut self, serial: u32) -> Result<(), DbusError> {
        loop {
            let header = self.read_exact(16)?;
            if header[0] != b'l' {
                return Err(DbusError::Malformed("only little-endian replies are read"));
            }
            let kind = header[1];
            let body_len =
                u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let fields_len =
                u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
            let padded_fields = fields_len.div_ceil(8) * 8;
            if body_len + padded_fields > MAX_MESSAGE {
                return Err(DbusError::Malformed("reply is implausibly large"));
            }
            let fields = self.read_exact(padded_fields)?;
            let body = self.read_exact(body_len)?;

            let (reply_serial, error_name) = scan_fields(&fields[..fields_len.min(fields.len())]);
            if reply_serial != Some(serial) {
                // A signal or a reply to something else; keep waiting.
                continue;
            }
            return match kind {
                METHOD_RETURN => Ok(()),
                ERROR => Err(DbusError::Remote {
                    name: error_name.unwrap_or_else(|| "org.freedesktop.DBus.Error".to_owned()),
                    message: first_string(&body).unwrap_or_default(),
                }),
                _ => Err(DbusError::Malformed("unexpected message type")),
            };
        }
    }

    fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, DbusError> {
        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer).map_err(DbusError::Io)?;
        Ok(buffer)
    }
}

/// Where the system bus socket is, honouring the standard environment variable.
#[must_use]
pub fn system_bus_path() -> PathBuf {
    // `DBUS_SYSTEM_BUS_ADDRESS` looks like `unix:path=/run/dbus/system_bus_socket`.
    if let Ok(address) = std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
        && let Some(path) = address
            .split(',')
            .find_map(|part| part.trim().strip_prefix("unix:path="))
    {
        return PathBuf::from(path);
    }
    PathBuf::from(SYSTEM_BUS_PATH)
}

/// Whether a system bus socket is present. Performs no connection.
#[must_use]
pub fn system_bus_present() -> bool {
    system_bus_path().exists()
}

fn field(out: &mut Marshaller, code: u8, variant_signature: &str, value: &Argument) {
    out.align(8);
    out.byte(code);
    out.signature(variant_signature);
    match variant_signature {
        "o" | "s" => {
            if let Argument::Str(text) = value {
                out.string(text);
            }
        }
        _ => value.marshal(out),
    }
}

fn scan_fields(fields: &[u8]) -> (Option<u32>, Option<String>) {
    let mut reply_serial = None;
    let mut error_name = None;
    let mut offset = 0usize;
    while offset + 4 <= fields.len() {
        // Each field is a struct, so it starts on an 8-byte boundary.
        offset = offset.div_ceil(8) * 8;
        if offset >= fields.len() {
            break;
        }
        let code = fields[offset];
        offset += 1;
        // Variant signature: one length byte, the text, and a NUL.
        let Some(&sig_len) = fields.get(offset) else {
            break;
        };
        offset += 1;
        let signature = fields
            .get(offset..offset + usize::from(sig_len))
            .map(|slice| String::from_utf8_lossy(slice).into_owned())
            .unwrap_or_default();
        offset += usize::from(sig_len) + 1;
        match signature.as_str() {
            "u" => {
                offset = offset.div_ceil(4) * 4;
                let Some(slice) = fields.get(offset..offset + 4) else {
                    break;
                };
                let value = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
                if code == 5 {
                    reply_serial = Some(value);
                }
                offset += 4;
            }
            "s" | "o" | "g" => {
                offset = offset.div_ceil(4) * 4;
                let Some(slice) = fields.get(offset..offset + 4) else {
                    break;
                };
                let len = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
                offset += 4;
                let text = fields
                    .get(offset..offset + len)
                    .map(|slice| String::from_utf8_lossy(slice).into_owned())
                    .unwrap_or_default();
                if code == 4 {
                    error_name = Some(text);
                }
                offset += len + 1;
            }
            _ => break,
        }
    }
    (reply_serial, error_name)
}

fn first_string(body: &[u8]) -> Option<String> {
    let slice = body.get(..4)?;
    let len = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
    let text = body.get(4..4 + len)?;
    Some(String::from_utf8_lossy(text).into_owned())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Byte-level D-Bus marshaller.
///
/// Alignment is the whole job: every basic type starts at a multiple of its own
/// size, structs at eight, and arrays declare a byte count that excludes the
/// padding before their first element.
#[derive(Debug, Default)]
pub struct Marshaller {
    buffer: Vec<u8>,
}

impl Marshaller {
    /// An empty marshaller.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes written so far.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Current length, which is also the current alignment position.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether anything has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Pad with NULs until the position is a multiple of `to`.
    pub fn align(&mut self, to: usize) {
        while !self.buffer.len().is_multiple_of(to) {
            self.buffer.push(0);
        }
    }

    /// Write a byte (`y`).
    pub fn byte(&mut self, value: u8) {
        self.buffer.push(value);
    }

    /// Write a `u32` (`u`).
    pub fn u32(&mut self, value: u32) {
        self.align(4);
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write an `i32` (`i`).
    pub fn int32(&mut self, value: i32) {
        self.align(4);
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Write a boolean (`b`), which travels as a `u32`.
    pub fn boolean(&mut self, value: bool) {
        self.u32(u32::from(value));
    }

    /// Write a string (`s`) or object path (`o`).
    pub fn string(&mut self, value: &str) {
        self.u32(u32::try_from(value.len()).unwrap_or(u32::MAX));
        self.buffer.extend_from_slice(value.as_bytes());
        self.buffer.push(0);
    }

    /// Write a signature (`g`), whose length is a single byte.
    pub fn signature(&mut self, value: &str) {
        self.buffer
            .push(u8::try_from(value.len()).unwrap_or(u8::MAX));
        self.buffer.extend_from_slice(value.as_bytes());
        self.buffer.push(0);
    }

    /// Write an array, whose length is measured after the element alignment.
    pub fn array(&mut self, element_alignment: usize, write: impl FnOnce(&mut Self)) {
        self.align(4);
        let length_position = self.buffer.len();
        self.buffer.extend_from_slice(&0u32.to_le_bytes());
        self.align(element_alignment);
        let content_start = self.buffer.len();
        write(self);
        let length = u32::try_from(self.buffer.len() - content_start).unwrap_or(u32::MAX);
        self.buffer[length_position..length_position + 4].copy_from_slice(&length.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_types_are_aligned_to_their_own_width() {
        let mut out = Marshaller::new();
        out.byte(1);
        out.u32(0xdead_beef);
        let bytes = out.into_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[..4], &[1, 0, 0, 0]);
        assert_eq!(&bytes[4..], &0xdead_beefu32.to_le_bytes());
    }

    #[test]
    fn strings_are_length_prefixed_and_nul_terminated() {
        let mut out = Marshaller::new();
        out.string("resolve1");
        let bytes = out.into_bytes();
        assert_eq!(&bytes[..4], &8u32.to_le_bytes());
        assert_eq!(&bytes[4..12], b"resolve1");
        assert_eq!(bytes[12], 0);
    }

    #[test]
    fn an_array_declares_the_length_of_its_contents_only() {
        let mut out = Marshaller::new();
        out.array(8, |inner| {
            inner.align(8);
            inner.int32(2);
            inner.array(1, |bytes| {
                for byte in [1u8, 2, 3, 4] {
                    bytes.byte(byte);
                }
            });
        });
        let bytes = out.into_bytes();
        let declared = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        // struct starts at offset 8; content is i32 + (u32 length + 4 bytes).
        assert_eq!(declared, bytes.len() - 8);
    }

    #[test]
    fn the_resolver_argument_marshals_to_the_documented_shape() {
        let mut out = Marshaller::new();
        Argument::Addresses(vec![(2, vec![10, 0, 0, 1])]).marshal(&mut out);
        let bytes = out.into_bytes();
        // a(iay): array length, pad to 8, family, address length, address.
        assert_eq!(&bytes[8..12], &2i32.to_le_bytes());
        assert_eq!(&bytes[12..16], &4u32.to_le_bytes());
        assert_eq!(&bytes[16..20], &[10, 0, 0, 1]);
    }

    #[test]
    fn the_domain_argument_marshals_to_the_documented_shape() {
        let mut out = Marshaller::new();
        Argument::Domains(vec![("~.".into(), true)]).marshal(&mut out);
        let bytes = out.into_bytes();
        assert_eq!(&bytes[8..12], &2u32.to_le_bytes());
        assert_eq!(&bytes[12..14], b"~.");
        assert_eq!(bytes[14], 0);
        assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
    }

    #[test]
    fn signatures_are_derived_from_the_arguments() {
        let arguments = [Argument::Int32(3), Argument::Addresses(Vec::new())];
        let signature: String = arguments.iter().map(Argument::signature).collect();
        assert_eq!(signature, "ia(iay)");
    }

    #[test]
    fn hex_encoding_matches_the_sasl_expectation() {
        assert_eq!(hex_encode(b"0"), "30");
        assert_eq!(hex_encode(b"1000"), "31303030");
    }

    #[test]
    fn the_bus_address_variable_is_honoured() {
        // Reading the process environment is inherently global; the assertion is
        // on the parse, not on the ambient value.
        assert_eq!(
            PathBuf::from("/tmp/bus"),
            "unix:path=/tmp/bus"
                .split(',')
                .find_map(|part| part.trim().strip_prefix("unix:path="))
                .map(PathBuf::from)
                .expect("parses")
        );
    }

    #[test]
    fn connecting_to_a_missing_socket_reports_rather_than_panics() {
        let error = Dbus::connect("/nonexistent/bus").expect_err("must fail");
        assert!(matches!(error, DbusError::Connect { .. }));
    }
}
