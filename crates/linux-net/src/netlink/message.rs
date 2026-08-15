//! Encoding and decoding of netlink messages.
//!
//! Netlink is a length-prefixed, host-byte-order binary protocol. Nothing here
//! touches a raw pointer: a message is a `Vec<u8>` built by appending, and a
//! reply is a `&[u8]` walked with checked slicing. Every length read off the
//! wire is validated against the remaining buffer before it is used, so a
//! malformed or truncated reply produces [`NetlinkError::Malformed`] rather than
//! a panic or an over-read.

use std::net::IpAddr;

use super::NetlinkError;

/// Netlink aligns every header and attribute to four bytes.
pub const ALIGN_TO: usize = 4;

/// Size of `struct nlmsghdr`.
pub const HEADER_LEN: usize = 16;

/// Size of `struct nlattr`.
pub const ATTR_HEADER_LEN: usize = 4;

/// Round `len` up to the netlink alignment.
#[must_use]
pub const fn align(len: usize) -> usize {
    len.div_ceil(ALIGN_TO) * ALIGN_TO
}

// --- message types -------------------------------------------------------

/// `NLMSG_NOOP`
pub const NLMSG_NOOP: u16 = 1;
/// `NLMSG_ERROR`
pub const NLMSG_ERROR: u16 = 2;
/// `NLMSG_DONE`
pub const NLMSG_DONE: u16 = 3;

/// `RTM_NEWLINK`
pub const RTM_NEWLINK: u16 = 16;
/// `RTM_DELLINK`
pub const RTM_DELLINK: u16 = 17;
/// `RTM_GETLINK`
pub const RTM_GETLINK: u16 = 18;
/// `RTM_NEWADDR`
pub const RTM_NEWADDR: u16 = 20;
/// `RTM_DELADDR`
pub const RTM_DELADDR: u16 = 21;
/// `RTM_GETADDR`
pub const RTM_GETADDR: u16 = 22;
/// `RTM_NEWROUTE`
pub const RTM_NEWROUTE: u16 = 24;
/// `RTM_DELROUTE`
pub const RTM_DELROUTE: u16 = 25;
/// `RTM_GETROUTE`
pub const RTM_GETROUTE: u16 = 26;
/// `RTM_NEWRULE`
pub const RTM_NEWRULE: u16 = 32;
/// `RTM_DELRULE`
pub const RTM_DELRULE: u16 = 33;
/// `RTM_GETRULE`
pub const RTM_GETRULE: u16 = 34;

// --- message flags -------------------------------------------------------

/// `NLM_F_REQUEST`
pub const NLM_F_REQUEST: u16 = 0x0001;
/// `NLM_F_MULTI`
pub const NLM_F_MULTI: u16 = 0x0002;
/// `NLM_F_ACK`
pub const NLM_F_ACK: u16 = 0x0004;
/// `NLM_F_ROOT | NLM_F_MATCH`, the pair that means "dump".
pub const NLM_F_DUMP: u16 = 0x0100 | 0x0200;
/// `NLM_F_REPLACE`
pub const NLM_F_REPLACE: u16 = 0x0100;
/// `NLM_F_EXCL`
pub const NLM_F_EXCL: u16 = 0x0200;
/// `NLM_F_CREATE`
pub const NLM_F_CREATE: u16 = 0x0400;

// --- attribute types -----------------------------------------------------

/// `IFLA_IFNAME`
pub const IFLA_IFNAME: u16 = 3;
/// `IFLA_MTU`
pub const IFLA_MTU: u16 = 4;

/// `IFA_ADDRESS`
pub const IFA_ADDRESS: u16 = 1;
/// `IFA_LOCAL`
pub const IFA_LOCAL: u16 = 2;

/// `RTA_DST`
pub const RTA_DST: u16 = 1;
/// `RTA_OIF`
pub const RTA_OIF: u16 = 4;
/// `RTA_PRIORITY`, also `FRA_PRIORITY`.
pub const RTA_PRIORITY: u16 = 6;
/// `RTA_TABLE`, also `FRA_TABLE`.
pub const RTA_TABLE: u16 = 15;

/// `FRA_FWMARK`
pub const FRA_FWMARK: u16 = 10;
/// `FRA_SUPPRESS_PREFIXLEN`
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
/// `FRA_FWMASK`
pub const FRA_FWMASK: u16 = 16;
/// `FRA_PROTOCOL`
pub const FRA_PROTOCOL: u16 = 21;

// --- enumerations --------------------------------------------------------

/// `IFF_UP`
pub const IFF_UP: u32 = 0x1;

/// `AF_UNSPEC`
pub const AF_UNSPEC: u8 = 0;
/// `AF_INET`
pub const AF_INET: u8 = 2;
/// `AF_INET6`
pub const AF_INET6: u8 = 10;

/// `RTN_UNICAST`
pub const RTN_UNICAST: u8 = 1;
/// `RTN_BLACKHOLE`
pub const RTN_BLACKHOLE: u8 = 6;
/// `RTN_UNREACHABLE`
pub const RTN_UNREACHABLE: u8 = 7;
/// `RTN_LOCAL` — deliver to this machine.
pub const RTN_LOCAL: u8 = 2;
/// `RTN_THROW` — abandon this table and continue with the next rule.
pub const RTN_THROW: u8 = 9;

/// `RT_SCOPE_UNIVERSE`
pub const RT_SCOPE_UNIVERSE: u8 = 0;
/// `RT_SCOPE_HOST`
pub const RT_SCOPE_HOST: u8 = 254;
/// `RT_SCOPE_LINK`
pub const RT_SCOPE_LINK: u8 = 253;
/// `RT_SCOPE_NOWHERE`
pub const RT_SCOPE_NOWHERE: u8 = 255;

/// `RT_TABLE_UNSPEC`. Table ids above 255 do not fit the one-byte header field,
/// so the id always travels in `RTA_TABLE` and this placeholder goes in the
/// header — the same convention iproute2 uses.
pub const RT_TABLE_UNSPEC: u8 = 0;

/// `RTM_F_LOOKUP_TABLE`-style routing protocol identifier reserved for this
/// project.
///
/// **This is the ownership marker.** Every route and rule the helper installs
/// carries it, and the helper only ever deletes routes and rules that carry it.
/// A route added by NetworkManager, systemd-networkd, a VPN client or the
/// administrator has a different protocol number and is invisible to the
/// cleanup path. 114 is unassigned in `rtnetlink.h` and in iproute2's
/// `rt_protos` table.
pub const RTPROT_XRAYTUI: u8 = 114;

// --- building ------------------------------------------------------------

/// Incremental netlink message builder.
#[derive(Debug)]
pub struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    /// Start a message of `kind` with `flags`. `NLM_F_REQUEST` is added for you.
    #[must_use]
    pub fn new(kind: u16, flags: u16) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // length, patched by finish
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // sequence, patched by finish
        buf.extend_from_slice(&0u32.to_ne_bytes()); // port, kernel fills in
        Self { buf }
    }

    /// Append a fixed-layout family header.
    pub fn header(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self.pad();
        self
    }

    /// Append an attribute with an arbitrary payload.
    pub fn attr(&mut self, kind: u16, payload: &[u8]) -> &mut Self {
        let len = ATTR_HEADER_LEN + payload.len();
        // `nla_len` is a u16; every caller here passes a handful of bytes, and
        // the saturating conversion keeps the encoding total rather than
        // panicking on a value that cannot occur.
        let encoded = u16::try_from(len).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&encoded.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        self.pad();
        self
    }

    /// Append a `u8` attribute.
    pub fn attr_u8(&mut self, kind: u16, value: u8) -> &mut Self {
        self.attr(kind, &value.to_ne_bytes())
    }

    /// Append a `u32` attribute.
    pub fn attr_u32(&mut self, kind: u16, value: u32) -> &mut Self {
        self.attr(kind, &value.to_ne_bytes())
    }

    /// Append a NUL-terminated string attribute.
    pub fn attr_str(&mut self, kind: u16, value: &str) -> &mut Self {
        let mut payload = value.as_bytes().to_vec();
        payload.push(0);
        self.attr(kind, &payload)
    }

    /// Append an IP address attribute in its natural width.
    pub fn attr_ip(&mut self, kind: u16, value: IpAddr) -> &mut Self {
        match value {
            IpAddr::V4(v4) => self.attr(kind, &v4.octets()),
            IpAddr::V6(v6) => self.attr(kind, &v6.octets()),
        }
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(ALIGN_TO) {
            self.buf.push(0);
        }
    }

    /// Stamp the length and sequence number and hand back the bytes.
    #[must_use]
    pub fn finish(mut self, sequence: u32) -> Vec<u8> {
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&sequence.to_ne_bytes());
        self.buf
    }
}

/// Encode `struct ifinfomsg`.
#[must_use]
pub fn ifinfomsg(family: u8, index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = family;
    // out[1] is `__ifi_pad`.
    out[2..4].copy_from_slice(&0u16.to_ne_bytes()); // ifi_type
    out[4..8].copy_from_slice(&index.to_ne_bytes());
    out[8..12].copy_from_slice(&flags.to_ne_bytes());
    out[12..16].copy_from_slice(&change.to_ne_bytes());
    out
}

/// Encode `struct ifaddrmsg`.
#[must_use]
pub fn ifaddrmsg(family: u8, prefix_len: u8, scope: u8, index: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = family;
    out[1] = prefix_len;
    out[2] = 0; // ifa_flags
    out[3] = scope;
    out[4..8].copy_from_slice(&index.to_ne_bytes());
    out
}

/// Encode `struct rtmsg`, used for both routes and rules.
#[must_use]
pub fn rtmsg(family: u8, dst_len: u8, table: u8, protocol: u8, scope: u8, kind: u8) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = family;
    out[1] = dst_len;
    out[2] = 0; // rtm_src_len
    out[3] = 0; // rtm_tos
    out[4] = table;
    out[5] = protocol;
    out[6] = scope;
    out[7] = kind;
    out[8..12].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    out
}

// --- parsing -------------------------------------------------------------

/// One parsed message from a reply buffer.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    /// `nlmsg_type`
    pub kind: u16,
    /// `nlmsg_flags`
    pub flags: u16,
    /// `nlmsg_seq`
    pub sequence: u32,
    /// Everything after the 16-byte header.
    pub payload: &'a [u8],
}

/// Walk the messages in a datagram.
///
/// # Errors
/// Returns [`NetlinkError::Malformed`] if a declared length does not fit.
pub fn messages(buf: &[u8]) -> Result<Vec<Message<'_>>, NetlinkError> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let remaining = &buf[offset..];
        if remaining.len() < HEADER_LEN {
            return Err(NetlinkError::Malformed(
                "trailing bytes shorter than a netlink header",
            ));
        }
        let len =
            u32::from_ne_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as usize;
        if len < HEADER_LEN || len > remaining.len() {
            return Err(NetlinkError::Malformed(
                "netlink message length out of range",
            ));
        }
        let kind = u16::from_ne_bytes([remaining[4], remaining[5]]);
        let flags = u16::from_ne_bytes([remaining[6], remaining[7]]);
        let sequence =
            u32::from_ne_bytes([remaining[8], remaining[9], remaining[10], remaining[11]]);
        out.push(Message {
            kind,
            flags,
            sequence,
            payload: &remaining[HEADER_LEN..len],
        });
        offset += align(len);
    }
    Ok(out)
}

/// Walk the attributes in a payload that begins after `skip` header bytes.
///
/// Attributes with an implausible length end the walk rather than aborting the
/// caller: a partially understood reply is still useful, and every caller here
/// treats a missing attribute as "not present".
#[must_use]
pub fn attributes(payload: &[u8], skip: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    if payload.len() <= skip {
        return out;
    }
    let mut offset = align(skip);
    while offset + ATTR_HEADER_LEN <= payload.len() {
        let len = u16::from_ne_bytes([payload[offset], payload[offset + 1]]) as usize;
        let kind = u16::from_ne_bytes([payload[offset + 2], payload[offset + 3]]);
        if len < ATTR_HEADER_LEN || offset + len > payload.len() {
            break;
        }
        out.push((kind, &payload[offset + ATTR_HEADER_LEN..offset + len]));
        offset += align(len);
    }
    out
}

/// Read a `u32` attribute payload.
#[must_use]
pub fn as_u32(payload: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = payload.get(..4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(bytes))
}

/// Read a NUL-terminated string attribute payload.
#[must_use]
pub fn as_str(payload: &[u8]) -> Option<&str> {
    let end = payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(payload.len());
    std::str::from_utf8(payload.get(..end)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_rounds_up_to_four() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
        assert_eq!(align(16), 16);
    }

    #[test]
    fn a_built_message_declares_its_own_length_and_sequence() {
        let mut builder = Builder::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_ACK);
        builder.header(&rtmsg(
            AF_INET,
            0,
            RT_TABLE_UNSPEC,
            RTPROT_XRAYTUI,
            0,
            RTN_UNICAST,
        ));
        builder.attr_u32(RTA_TABLE, 29_281);
        builder.attr_u32(RTA_OIF, 7);
        let bytes = builder.finish(42);

        let declared = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(declared, bytes.len());

        let parsed = messages(&bytes).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, RTM_NEWROUTE);
        assert_eq!(parsed[0].sequence, 42);
        assert!(parsed[0].flags & NLM_F_REQUEST != 0);

        let attrs = attributes(parsed[0].payload, 12);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, RTA_TABLE);
        assert_eq!(as_u32(attrs[0].1), Some(29_281));
        assert_eq!(attrs[1].0, RTA_OIF);
        assert_eq!(as_u32(attrs[1].1), Some(7));
    }

    #[test]
    fn string_attributes_round_trip_without_the_terminator() {
        let mut builder = Builder::new(RTM_NEWLINK, 0);
        builder.header(&ifinfomsg(AF_UNSPEC, 0, 0, 0));
        builder.attr_str(IFLA_IFNAME, "xraytui1000");
        let bytes = builder.finish(1);
        let parsed = messages(&bytes).expect("parses");
        let attrs = attributes(parsed[0].payload, 16);
        assert_eq!(as_str(attrs[0].1), Some("xraytui1000"));
    }

    #[test]
    fn several_messages_in_one_datagram_are_all_found() {
        let first = Builder::new(RTM_NEWLINK, 0).finish(1);
        let second = Builder::new(RTM_NEWADDR, 0).finish(2);
        let mut buf = first.clone();
        buf.extend_from_slice(&second);
        let parsed = messages(&buf).expect("parses");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].sequence, 1);
        assert_eq!(parsed[1].sequence, 2);
    }

    #[test]
    fn a_truncated_message_is_rejected_rather_than_over_read() {
        let mut bytes = Builder::new(RTM_NEWLINK, 0).finish(1);
        // Claim a length far beyond the buffer.
        bytes[0..4].copy_from_slice(&4096u32.to_ne_bytes());
        assert!(messages(&bytes).is_err());
    }

    #[test]
    fn a_header_shorter_than_the_minimum_is_rejected() {
        let mut bytes = Builder::new(RTM_NEWLINK, 0).finish(1);
        bytes[0..4].copy_from_slice(&4u32.to_ne_bytes());
        assert!(messages(&bytes).is_err());
    }

    #[test]
    fn trailing_garbage_shorter_than_a_header_is_rejected() {
        let mut bytes = Builder::new(RTM_NEWLINK, 0).finish(1);
        bytes.extend_from_slice(&[0u8; 3]);
        assert!(messages(&bytes).is_err());
    }

    #[test]
    fn an_attribute_claiming_more_than_the_payload_ends_the_walk() {
        let mut builder = Builder::new(RTM_NEWLINK, 0);
        builder.header(&ifinfomsg(AF_UNSPEC, 0, 0, 0));
        builder.attr_u32(IFLA_MTU, 1500);
        let mut bytes = builder.finish(1);
        let attr_start = HEADER_LEN + 16;
        bytes[attr_start..attr_start + 2].copy_from_slice(&512u16.to_ne_bytes());
        let parsed = messages(&bytes).expect("parses");
        assert!(attributes(parsed[0].payload, 16).is_empty());
    }

    #[test]
    fn ipv6_addresses_encode_at_their_natural_width() {
        let mut builder = Builder::new(RTM_NEWADDR, 0);
        builder.header(&ifaddrmsg(AF_INET6, 64, RT_SCOPE_UNIVERSE, 3));
        builder.attr_ip(IFA_ADDRESS, "fd00::1".parse::<IpAddr>().expect("address"));
        let bytes = builder.finish(1);
        let parsed = messages(&bytes).expect("parses");
        let attrs = attributes(parsed[0].payload, 8);
        assert_eq!(attrs[0].1.len(), 16);
    }
}
