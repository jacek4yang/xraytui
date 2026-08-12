//! A small, safe rtnetlink client.
//!
//! # Why not `ip(8)`
//!
//! `docs/THREAT-MODEL.md` T4 rules out building command lines out of values
//! that came from configuration. Netlink removes the question entirely: an
//! interface name travels as a length-prefixed attribute, a prefix travels as
//! four or sixteen bytes, and there is no parser in between that could be
//! talked into doing something else. It also removes the dependency on
//! iproute2's human-readable output, which is not a stable interface.
//!
//! # What it can do
//!
//! Only what the helper needs: bring a link up, set its MTU, add an address,
//! add and delete routes inside a numbered table, and add and delete policy
//! rules. Everything it writes carries [`message::RTPROT_XRAYTUI`], and
//! everything it deletes must carry it too.

pub mod message;

use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::time::Duration;

use ipnet::IpNet;
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink::SocketAddrNetlink,
};

use message::{
    AF_INET, AF_INET6, AF_UNSPEC, Builder, FRA_FWMARK, FRA_FWMASK, FRA_PROTOCOL,
    FRA_SUPPRESS_PREFIXLEN, IFA_ADDRESS, IFA_LOCAL, IFF_UP, IFLA_IFNAME, IFLA_MTU, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP,
    RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, RT_TABLE_UNSPEC, RTA_DST, RTA_OIF,
    RTA_PRIORITY, RTA_TABLE, RTM_DELLINK, RTM_DELROUTE, RTM_DELRULE, RTM_GETLINK, RTM_GETROUTE,
    RTM_GETRULE, RTM_NEWADDR, RTM_NEWLINK, RTM_NEWROUTE, RTM_NEWRULE, RTN_BLACKHOLE, RTN_UNICAST,
    RTPROT_XRAYTUI, as_str, as_u32, attributes, ifaddrmsg, ifinfomsg, messages, rtmsg,
};

/// Largest netlink datagram the helper will accept.
const RECV_BUFFER: usize = 64 * 1024;

/// How long a single netlink exchange may take before it is abandoned.
///
/// The kernel answers rtnetlink synchronously, so this only matters if
/// something is badly wrong; without it a wedged socket would hang the helper
/// and, through it, every user's daemon.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Everything the netlink layer can report.
#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    /// The socket could not be created or bound.
    #[error("cannot open a netlink socket: {0}")]
    Open(#[source] rustix::io::Errno),
    /// A send or receive failed.
    #[error("netlink {operation} failed: {source}")]
    Io {
        /// What was being attempted.
        operation: &'static str,
        /// Underlying errno.
        #[source]
        source: rustix::io::Errno,
    },
    /// The kernel refused the request.
    #[error("the kernel refused {operation}: {source}")]
    Kernel {
        /// Human-readable description of the request.
        operation: String,
        /// The errno the kernel returned.
        #[source]
        source: rustix::io::Errno,
    },
    /// A reply could not be understood.
    #[error("malformed netlink reply: {0}")]
    Malformed(&'static str),
    /// A reply did not arrive before the five-second netlink deadline.
    #[error("netlink did not answer within {}s", TIMEOUT.as_secs())]
    Timeout,
    /// The interface named does not exist.
    #[error("interface {0} does not exist")]
    NoSuchLink(String),
}

impl NetlinkError {
    /// Whether the kernel said the object was already there.
    #[must_use]
    pub fn is_exists(&self) -> bool {
        matches!(self, Self::Kernel { source, .. } if *source == rustix::io::Errno::EXIST)
    }

    /// Whether the kernel said the object was not there.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(
            self,
            Self::Kernel { source, .. }
                if *source == rustix::io::Errno::NOENT
                    || *source == rustix::io::Errno::SRCH
                    || *source == rustix::io::Errno::NODEV
        ) || matches!(self, Self::NoSuchLink(_))
    }
}

/// A route as the helper cares about it: enough to recognise its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// Address family of the destination.
    pub family: u8,
    /// Destination prefix, or `None` for a default route.
    pub destination: Option<IpNet>,
    /// Routing table the route lives in.
    pub table: u32,
    /// Routing protocol identifier — the ownership marker.
    pub protocol: u8,
    /// Route type, e.g. [`message::RTN_BLACKHOLE`].
    pub kind: u8,
    /// Output interface index, when there is one.
    pub oif: Option<u32>,
}

/// A policy routing rule as the helper cares about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEntry {
    /// Address family.
    pub family: u8,
    /// Rule priority.
    pub priority: u32,
    /// Table the rule selects, when it selects one.
    pub table: Option<u32>,
    /// Firewall mark the rule matches, when it matches one.
    pub fwmark: Option<u32>,
    /// Routing protocol identifier — the ownership marker.
    pub protocol: u8,
}

/// A connected rtnetlink socket.
///
/// One socket per operation is cheap and avoids sharing sequence numbers across
/// threads, so the helper opens one, uses it, and drops it.
#[derive(Debug)]
pub struct Netlink {
    fd: OwnedFd,
    sequence: std::cell::Cell<u32>,
}

impl Netlink {
    /// Open and connect a netlink socket to the kernel.
    ///
    /// # Errors
    /// Returns [`NetlinkError::Open`] if the socket cannot be created, bound or
    /// connected — most often because the process lacks `CAP_NET_ADMIN` or the
    /// kernel has no netlink support.
    pub fn open() -> Result<Self, NetlinkError> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(NetlinkError::Open)?;
        // Port id 0 asks the kernel to allocate one, which keeps two helpers on
        // the same machine from colliding.
        rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(NetlinkError::Open)?;
        rustix::net::connect(&fd, &SocketAddrNetlink::new(0, 0)).map_err(NetlinkError::Open)?;
        rustix::net::sockopt::set_socket_timeout(
            &fd,
            rustix::net::sockopt::Timeout::Recv,
            Some(TIMEOUT),
        )
        .map_err(NetlinkError::Open)?;
        Ok(Self {
            fd,
            sequence: std::cell::Cell::new(1),
        })
    }

    fn next_sequence(&self) -> u32 {
        let next = self.sequence.get().wrapping_add(1).max(1);
        self.sequence.set(next);
        next
    }

    /// Send one request and collect the reply.
    ///
    /// Returns `(kind, payload)` for every non-control message that carried the
    /// request's sequence number. An acknowledged request that produced no data
    /// returns an empty vector.
    fn transact(
        &self,
        builder: Builder,
        description: impl Into<String>,
    ) -> Result<Vec<(u16, Vec<u8>)>, NetlinkError> {
        let sequence = self.next_sequence();
        let request = builder.finish(sequence);
        rustix::net::send(&self.fd, &request, SendFlags::empty()).map_err(|source| {
            NetlinkError::Io {
                operation: "send",
                source,
            }
        })?;

        let description = description.into();
        let mut collected = Vec::new();
        let mut buffer = vec![0u8; RECV_BUFFER];
        loop {
            let read = match rustix::net::recv(&self.fd, &mut buffer[..], RecvFlags::empty()) {
                // The second value is the datagram's true length; if it exceeds
                // the buffer the kernel truncated it, and parsing the remainder
                // would silently drop routes.
                Ok((_, complete)) if complete > buffer.len() => {
                    return Err(NetlinkError::Malformed(
                        "a netlink datagram was larger than the receive buffer",
                    ));
                }
                Ok((read, _)) => read,
                Err(rustix::io::Errno::AGAIN) => {
                    return Err(NetlinkError::Timeout);
                }
                Err(rustix::io::Errno::INTR) => continue,
                Err(source) => {
                    return Err(NetlinkError::Io {
                        operation: "receive",
                        source,
                    });
                }
            };
            for parsed in messages(&buffer[..read])? {
                if parsed.sequence != sequence {
                    continue;
                }
                match parsed.kind {
                    NLMSG_NOOP => {}
                    NLMSG_DONE => return Ok(collected),
                    NLMSG_ERROR => {
                        let bytes: [u8; 4] = parsed
                            .payload
                            .get(..4)
                            .and_then(|slice| slice.try_into().ok())
                            .ok_or(NetlinkError::Malformed("error message without a code"))?;
                        let code = i32::from_ne_bytes(bytes);
                        if code == 0 {
                            return Ok(collected);
                        }
                        return Err(NetlinkError::Kernel {
                            operation: description,
                            source: rustix::io::Errno::from_raw_os_error(-code),
                        });
                    }
                    kind => collected.push((kind, parsed.payload.to_vec())),
                }
            }
        }
    }

    // --- links -----------------------------------------------------------

    /// Look up an interface index by name.
    ///
    /// Uses netlink rather than `/sys/class/net`, which shows the mount
    /// namespace's view and would report the wrong devices inside a network
    /// namespace that did not remount sysfs.
    ///
    /// # Errors
    /// [`NetlinkError::NoSuchLink`] if there is no such interface.
    pub fn link_index(&self, name: &str) -> Result<u32, NetlinkError> {
        let mut builder = Builder::new(RTM_GETLINK, NLM_F_ACK);
        builder.header(&ifinfomsg(AF_UNSPEC, 0, 0, 0));
        builder.attr_str(IFLA_IFNAME, name);
        let replies = match self.transact(builder, format!("look up interface {name}")) {
            Ok(replies) => replies,
            Err(error) if error.is_missing() => {
                return Err(NetlinkError::NoSuchLink(name.to_owned()));
            }
            Err(error) => return Err(error),
        };
        for (kind, payload) in &replies {
            if *kind != RTM_NEWLINK {
                continue;
            }
            let index: [u8; 4] = payload
                .get(4..8)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(NetlinkError::Malformed("link message without an index"))?;
            return Ok(i32::from_ne_bytes(index).unsigned_abs());
        }
        Err(NetlinkError::NoSuchLink(name.to_owned()))
    }

    /// List every interface whose name starts with `prefix`.
    ///
    /// This is how recovery finds devices left behind by a previous run without
    /// having to trust a state file.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn links_with_prefix(&self, prefix: &str) -> Result<Vec<(String, u32)>, NetlinkError> {
        let mut builder = Builder::new(RTM_GETLINK, NLM_F_DUMP);
        builder.header(&ifinfomsg(AF_UNSPEC, 0, 0, 0));
        let replies = self.transact(builder, "list interfaces")?;
        let mut out = Vec::new();
        for (kind, payload) in &replies {
            if *kind != RTM_NEWLINK {
                continue;
            }
            let Some(index) = payload
                .get(4..8)
                .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
                .map(|bytes| i32::from_ne_bytes(bytes).unsigned_abs())
            else {
                continue;
            };
            for (attr, value) in attributes(payload, 16) {
                if attr == IFLA_IFNAME
                    && let Some(name) = as_str(value)
                    && name.starts_with(prefix)
                {
                    out.push((name.to_owned(), index));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Bring an interface up and set its MTU in one message.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn link_up(&self, index: u32, mtu: u32) -> Result<(), NetlinkError> {
        let index = i32::try_from(index).unwrap_or(i32::MAX);
        let mut builder = Builder::new(RTM_NEWLINK, NLM_F_ACK);
        builder.header(&ifinfomsg(AF_UNSPEC, index, IFF_UP, IFF_UP));
        builder.attr_u32(IFLA_MTU, mtu);
        self.transact(builder, format!("bring interface {index} up"))?;
        Ok(())
    }

    /// Take an interface down.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn link_down(&self, index: u32) -> Result<(), NetlinkError> {
        let index = i32::try_from(index).unwrap_or(i32::MAX);
        let mut builder = Builder::new(RTM_NEWLINK, NLM_F_ACK);
        builder.header(&ifinfomsg(AF_UNSPEC, index, 0, IFF_UP));
        self.transact(builder, format!("take interface {index} down"))?;
        Ok(())
    }

    /// Delete an interface by index.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn link_delete(&self, index: u32) -> Result<(), NetlinkError> {
        let index = i32::try_from(index).unwrap_or(i32::MAX);
        let mut builder = Builder::new(RTM_DELLINK, NLM_F_ACK);
        builder.header(&ifinfomsg(AF_UNSPEC, index, 0, 0));
        self.transact(builder, format!("delete interface {index}"))?;
        Ok(())
    }

    // --- addresses -------------------------------------------------------

    /// Assign an address to an interface.
    ///
    /// # Errors
    /// Propagates netlink failures; [`NetlinkError::is_exists`] is true if the
    /// address was already there.
    pub fn address_add(&self, index: u32, prefix: IpNet) -> Result<(), NetlinkError> {
        let family = family_of(prefix.addr());
        let scope = if prefix.addr().is_loopback() {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        };
        let mut builder = Builder::new(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        builder.header(&ifaddrmsg(family, prefix.prefix_len(), scope, index));
        // A point-to-point-style device needs both, and the kernel treats
        // IFA_LOCAL as authoritative.
        builder.attr_ip(IFA_LOCAL, prefix.addr());
        builder.attr_ip(IFA_ADDRESS, prefix.addr());
        self.transact(
            builder,
            format!("add address {prefix} to interface {index}"),
        )?;
        Ok(())
    }

    // --- routes ----------------------------------------------------------

    /// Add a route into a numbered table, through an interface.
    ///
    /// The route carries [`message::RTPROT_XRAYTUI`] so cleanup can recognise it.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn route_add(
        &self,
        table: u32,
        destination: IpNet,
        oif: u32,
        replace: bool,
    ) -> Result<(), NetlinkError> {
        let family = family_of(destination.addr());
        let flags = if replace {
            NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        } else {
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        };
        let mut builder = Builder::new(RTM_NEWROUTE, flags);
        builder.header(&rtmsg(
            family,
            destination.prefix_len(),
            RT_TABLE_UNSPEC,
            RTPROT_XRAYTUI,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
        ));
        builder.attr_u32(RTA_TABLE, table);
        if destination.prefix_len() > 0 {
            builder.attr_ip(RTA_DST, destination.addr());
        }
        builder.attr_u32(RTA_OIF, oif);
        self.transact(
            builder,
            format!("add route {destination} dev {oif} table {table}"),
        )?;
        Ok(())
    }

    /// Add a route with no next hop: `blackhole`, `unreachable` or `throw`.
    ///
    /// `throw` is the one that matters most — it ends the lookup in this table
    /// and lets the next policy rule take over, which is how a prefix escapes
    /// the tunnel without the helper having to copy the machine's real routes.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn route_add_special(
        &self,
        table: u32,
        destination: IpNet,
        kind: u8,
        replace: bool,
    ) -> Result<(), NetlinkError> {
        let family = family_of(destination.addr());
        let flags = if replace {
            NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        } else {
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        };
        let mut builder = Builder::new(RTM_NEWROUTE, flags);
        builder.header(&rtmsg(
            family,
            destination.prefix_len(),
            RT_TABLE_UNSPEC,
            RTPROT_XRAYTUI,
            RT_SCOPE_NOWHERE,
            kind,
        ));
        builder.attr_u32(RTA_TABLE, table);
        if destination.prefix_len() > 0 {
            builder.attr_ip(RTA_DST, destination.addr());
        }
        self.transact(
            builder,
            format!("add a type-{kind} route for {destination} in table {table}"),
        )?;
        Ok(())
    }

    /// Add a route that discards traffic, used by the kill switch.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn route_add_blackhole(
        &self,
        table: u32,
        destination: IpNet,
        replace: bool,
    ) -> Result<(), NetlinkError> {
        self.route_add_special(table, destination, RTN_BLACKHOLE, replace)
    }

    /// List the routes in one table.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn routes_in_table(&self, table: u32) -> Result<Vec<RouteEntry>, NetlinkError> {
        let mut builder = Builder::new(RTM_GETROUTE, NLM_F_DUMP);
        builder.header(&rtmsg(AF_UNSPEC, 0, RT_TABLE_UNSPEC, 0, 0, 0));
        let replies = self.transact(builder, "list routes")?;
        let mut out = Vec::new();
        for (kind, payload) in &replies {
            if *kind != RTM_NEWROUTE || payload.len() < 12 {
                continue;
            }
            let family = payload[0];
            let dst_len = payload[1];
            let mut entry = RouteEntry {
                family,
                destination: None,
                table: u32::from(payload[4]),
                protocol: payload[5],
                kind: payload[7],
                oif: None,
            };
            let mut destination_bytes: Option<Vec<u8>> = None;
            for (attr, value) in attributes(payload, 12) {
                match attr {
                    RTA_TABLE => {
                        if let Some(value) = as_u32(value) {
                            entry.table = value;
                        }
                    }
                    RTA_OIF => entry.oif = as_u32(value),
                    RTA_DST => destination_bytes = Some(value.to_vec()),
                    _ => {}
                }
            }
            if entry.table != table {
                continue;
            }
            entry.destination = destination_bytes
                .as_deref()
                .and_then(|bytes| decode_prefix(family, bytes, dst_len));
            out.push(entry);
        }
        Ok(out)
    }

    /// Delete one route from a table.
    ///
    /// # Errors
    /// Propagates netlink failures; [`NetlinkError::is_missing`] is true if the
    /// route had already gone.
    pub fn route_delete(
        &self,
        table: u32,
        destination: Option<IpNet>,
        family: u8,
    ) -> Result<(), NetlinkError> {
        let (family, prefix_len) = match destination {
            Some(net) => (family_of(net.addr()), net.prefix_len()),
            None => (family, 0),
        };
        let mut builder = Builder::new(RTM_DELROUTE, NLM_F_ACK);
        builder.header(&rtmsg(
            family,
            prefix_len,
            RT_TABLE_UNSPEC,
            RTPROT_XRAYTUI,
            RT_SCOPE_NOWHERE,
            0,
        ));
        builder.attr_u32(RTA_TABLE, table);
        if let Some(net) = destination
            && net.prefix_len() > 0
        {
            builder.attr_ip(RTA_DST, net.addr());
        }
        self.transact(
            builder,
            format!(
                "delete route {} from table {table}",
                destination.map_or_else(|| "default".to_owned(), |net| net.to_string())
            ),
        )?;
        Ok(())
    }

    /// Remove every route in `table` that carries the project protocol id.
    ///
    /// Routes put there by anything else are left alone, which is what makes it
    /// safe to run on a machine the helper does not exclusively own.
    ///
    /// # Errors
    /// Propagates netlink failures other than "already gone".
    pub fn flush_owned_routes(&self, table: u32) -> Result<usize, NetlinkError> {
        let routes = self.routes_in_table(table)?;
        let mut removed = 0;
        for route in routes {
            if route.protocol != RTPROT_XRAYTUI {
                continue;
            }
            match self.route_delete(table, route.destination, route.family) {
                Ok(()) => removed += 1,
                Err(error) if error.is_missing() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(removed)
    }

    // --- rules -----------------------------------------------------------

    /// Add a policy rule matching a firewall mark and selecting a table.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn rule_add_fwmark(
        &self,
        family: u8,
        priority: u32,
        fwmark: u32,
        table: u32,
    ) -> Result<(), NetlinkError> {
        let mut builder = Builder::new(RTM_NEWRULE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        builder.header(&rtmsg(
            family,
            0,
            RT_TABLE_UNSPEC,
            RTPROT_XRAYTUI,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
        ));
        builder.attr_u32(RTA_PRIORITY, priority);
        builder.attr_u32(FRA_FWMARK, fwmark);
        builder.attr_u32(FRA_FWMASK, u32::MAX);
        builder.attr_u32(RTA_TABLE, table);
        builder.attr_u8(FRA_PROTOCOL, RTPROT_XRAYTUI);
        self.transact(
            builder,
            format!("add rule fwmark {fwmark:#x} table {table} priority {priority}"),
        )?;
        Ok(())
    }

    /// Add a rule that consults the main table but ignores its default route.
    ///
    /// This is the standard way to keep on-link destinations working while a
    /// tunnel owns the default route: `suppress_prefixlength 0` makes the main
    /// table's `default` invisible to this lookup without touching it.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn rule_add_suppress_default(&self, family: u8, priority: u32) -> Result<(), NetlinkError> {
        let mut builder = Builder::new(RTM_NEWRULE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        builder.header(&rtmsg(
            family,
            0,
            254, // RT_TABLE_MAIN
            RTPROT_XRAYTUI,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
        ));
        builder.attr_u32(RTA_PRIORITY, priority);
        builder.attr_u32(FRA_SUPPRESS_PREFIXLEN, 0);
        builder.attr_u8(FRA_PROTOCOL, RTPROT_XRAYTUI);
        self.transact(
            builder,
            format!("add suppress_prefixlength rule at priority {priority}"),
        )?;
        Ok(())
    }

    /// List policy rules.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn rules(&self, family: u8) -> Result<Vec<RuleEntry>, NetlinkError> {
        let mut builder = Builder::new(RTM_GETRULE, NLM_F_DUMP);
        builder.header(&rtmsg(family, 0, RT_TABLE_UNSPEC, 0, 0, 0));
        let replies = self.transact(builder, "list rules")?;
        let mut out = Vec::new();
        for (kind, payload) in &replies {
            if *kind != RTM_NEWRULE || payload.len() < 12 {
                continue;
            }
            let mut entry = RuleEntry {
                family: payload[0],
                priority: 0,
                table: match payload[4] {
                    0 => None,
                    value => Some(u32::from(value)),
                },
                fwmark: None,
                protocol: payload[5],
            };
            for (attr, value) in attributes(payload, 12) {
                match attr {
                    RTA_PRIORITY => entry.priority = as_u32(value).unwrap_or(0),
                    FRA_FWMARK => entry.fwmark = as_u32(value),
                    RTA_TABLE => entry.table = as_u32(value),
                    _ => {}
                }
            }
            out.push(entry);
        }
        Ok(out)
    }

    /// Delete a rule at a priority.
    ///
    /// # Errors
    /// Propagates netlink failures.
    pub fn rule_delete(&self, family: u8, priority: u32) -> Result<(), NetlinkError> {
        let mut builder = Builder::new(RTM_DELRULE, NLM_F_ACK);
        builder.header(&rtmsg(family, 0, RT_TABLE_UNSPEC, RTPROT_XRAYTUI, 0, 0));
        builder.attr_u32(RTA_PRIORITY, priority);
        self.transact(builder, format!("delete rule at priority {priority}"))?;
        Ok(())
    }

    /// Remove every rule in `priorities` for both families, ignoring absences.
    ///
    /// # Errors
    /// Propagates netlink failures other than "already gone".
    pub fn flush_rules(&self, priorities: &[u32]) -> Result<usize, NetlinkError> {
        let mut removed = 0;
        for family in families() {
            for priority in priorities {
                // A rule can legitimately exist several times at one priority;
                // deleting until the kernel says there are none left is the
                // only way to be sure a repeated enable/disable cycle leaves
                // nothing behind.
                loop {
                    match self.rule_delete(family, *priority) {
                        Ok(()) => removed += 1,
                        Err(error) if error.is_missing() => break,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(removed)
    }
}

/// Whether this kernel has IPv6 at all.
///
/// A kernel booted with `ipv6.disable=1`, or built without IPv6, answers every
/// `AF_INET6` route message with `EOPNOTSUPP`. That is not a failure the user
/// can act on, so the helper checks once and simply does less: it installs no
/// IPv6 routes and no IPv6 rules, and says so rather than rolling the whole
/// operation back. Found by the namespace tests, whose kernel has no IPv6.
#[must_use]
pub fn ipv6_supported() -> bool {
    std::path::Path::new("/proc/net/if_inet6").exists()
}

/// The address families worth talking to this kernel about.
#[must_use]
pub fn families() -> Vec<u8> {
    if ipv6_supported() {
        vec![AF_INET, AF_INET6]
    } else {
        vec![AF_INET]
    }
}

/// Address family byte for an address.
#[must_use]
pub fn family_of(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

fn decode_prefix(family: u8, bytes: &[u8], prefix_len: u8) -> Option<IpNet> {
    let address = match family {
        AF_INET => IpAddr::from(<[u8; 4]>::try_from(bytes.get(..4)?).ok()?),
        AF_INET6 => IpAddr::from(<[u8; 16]>::try_from(bytes.get(..16)?).ok()?),
        _ => return None,
    };
    IpNet::new(address, prefix_len).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_family_list_follows_what_the_kernel_actually_has() {
        let list = families();
        assert!(list.contains(&AF_INET), "IPv4 is always present");
        assert_eq!(list.contains(&AF_INET6), ipv6_supported());
    }

    #[test]
    fn address_families_map_to_the_kernel_constants() {
        assert_eq!(family_of("10.0.0.1".parse().expect("v4")), AF_INET);
        assert_eq!(family_of("fd00::1".parse().expect("v6")), AF_INET6);
    }

    #[test]
    fn prefixes_decode_at_both_widths() {
        let v4 = decode_prefix(AF_INET, &[198, 18, 0, 0], 15).expect("v4 prefix");
        assert_eq!(v4.to_string(), "198.18.0.0/15");
        let v6 = decode_prefix(
            AF_INET6,
            &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            8,
        )
        .expect("v6 prefix");
        assert_eq!(v6.to_string(), "fd00::/8");
    }

    #[test]
    fn a_short_prefix_payload_is_rejected_rather_than_padded() {
        assert!(decode_prefix(AF_INET, &[198, 18], 15).is_none());
        assert!(decode_prefix(AF_INET6, &[0xfd, 0], 8).is_none());
        assert!(decode_prefix(99, &[1, 2, 3, 4], 8).is_none());
    }

    #[test]
    fn opening_a_netlink_socket_succeeds_or_reports_why() {
        // The helper runs as root, but the test suite may not, so this asserts
        // the shape of the outcome rather than success.
        match Netlink::open() {
            Ok(netlink) => {
                let links = netlink.links_with_prefix("").expect("dump interfaces");
                assert!(
                    links.iter().any(|(name, _)| name == "lo"),
                    "every namespace has a loopback interface, found {links:?}"
                );
            }
            Err(error) => {
                assert!(
                    matches!(error, NetlinkError::Open(_)),
                    "unexpected failure: {error}"
                );
            }
        }
    }
}
