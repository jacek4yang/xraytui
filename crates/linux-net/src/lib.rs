//! The privileged Linux backend behind `xraytui-netd`.
//!
//! `xraytui-netd-protocol` says *what* root may be asked to do;
//! this crate is *how*. The split is deliberate: the protocol crate has no
//! system dependencies and can be reviewed on its own, and this crate cannot
//! widen the interface, only implement it.
//!
//! # Shape
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`tun`] | create a persistent, user-owned TUN device |
//! | [`netlink`] | links, addresses, routes and policy rules |
//! | [`nft`] | the project's own nftables table, described structurally |
//! | [`cgroup`] | cgroup v2 groups and `pidfd`-based classification |
//! | [`dns`] | systemd-resolved and resolvconf, with restore |
//! | [`lease`] | who owns what, and what to do when they stop asking |
//! | [`engine`] | applies one [`xraytui_netd_protocol::Operation`] |
//!
//! # Two invariants hold everywhere below
//!
//! 1. **Nothing is deleted that this project did not create.** Routes and rules
//!    carry [`netlink::message::RTPROT_XRAYTUI`]; the nftables table has a fixed
//!    name; interfaces have a fixed prefix; cgroups live under one slice. Every
//!    cleanup path filters on those markers, so the helper is safe to run beside
//!    NetworkManager, systemd-networkd, a corporate VPN or a hand-written
//!    ruleset.
//! 2. **No string built here reaches a shell.** `nft` is executed with an argv
//!    and fed JSON on stdin; everything else is a syscall.

// `tun` needs three ioctls and is exempted at the module level with a `reason`;
// nothing else in the crate may use unsafe.
#![deny(unsafe_code)]
// Production paths must not panic; test modules are exempt so assertions stay
// readable.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(missing_docs)]

pub mod capabilities;
pub mod cgroup;
pub mod dbus;
pub mod dns;
pub mod engine;
pub mod lease;
pub mod netlink;
pub mod nft;
pub mod plan;
pub mod program;
pub mod routing;
pub mod transport;
pub mod tun;

pub use capabilities::probe;
pub use engine::{Engine, EngineOptions, Response};
pub use lease::{Lease, LeaseStore};
pub use transport::{NetdClient, TransportError, receive_message, send_message};

/// Convert any backend failure into the protocol's error type.
///
/// The protocol deliberately has a small, closed error set: a client should
/// learn whether it was refused, denied, unsupported or simply unlucky, and
/// nothing more. Messages are kept short and free of anything that could carry
/// a credential — none of these paths ever sees one, but the discipline is
/// worth keeping uniform with the rest of the project.
pub(crate) fn refuse(message: impl std::fmt::Display) -> xraytui_netd_protocol::NetdError {
    xraytui_netd_protocol::NetdError::Refused(message.to_string())
}

pub(crate) fn internal(message: impl std::fmt::Display) -> xraytui_netd_protocol::NetdError {
    xraytui_netd_protocol::NetdError::Internal(message.to_string())
}

pub(crate) fn unsupported(message: impl std::fmt::Display) -> xraytui_netd_protocol::NetdError {
    xraytui_netd_protocol::NetdError::Unsupported(message.to_string())
}
