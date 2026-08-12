//! Reusable domain fixtures.

use std::net::SocketAddr;

use xraytui_domain::{
    DesiredState, EgressProfile, Endpoint, ListenerSpec, Node, NodeId, NodeSource, ProfileId,
    ProtocolSettings, SocksSettings, Target,
};

/// A node that dials a local mock egress over plain SOCKS5.
///
/// This is the shape used by every integration test: the "remote proxy server"
/// is a [`crate::MockEgress`] on loopback, so the whole path — Xray inbound,
/// routing, outbound, remote proxy — is exercised without leaving the machine.
#[must_use]
pub fn socks_node(id: &str, name: &str, egress: SocketAddr) -> Node {
    Node::new(
        NodeId::new(id).expect("fixture identifiers are valid slugs"),
        name,
        NodeSource::Manual,
        Endpoint::new(egress.ip().to_string(), egress.port()),
        ProtocolSettings::Socks(SocksSettings {
            username: None,
            password: None,
            udp: false,
        }),
    )
}

/// A profile with a dedicated loopback SOCKS listener.
#[must_use]
pub fn profile_with_socks(id: &str, target: Target, socks_port: u16) -> EgressProfile {
    let mut profile = EgressProfile::new(
        ProfileId::new(id).expect("fixture identifiers are valid slugs"),
        id,
        target,
    );
    profile.socks = Some(ListenerSpec::loopback(socks_port));
    profile
}

/// A profile with both a SOCKS and an HTTP listener.
#[must_use]
pub fn profile_with_both(
    id: &str,
    target: Target,
    socks_port: u16,
    http_port: u16,
) -> EgressProfile {
    let mut profile = profile_with_socks(id, target, socks_port);
    profile.http = Some(ListenerSpec::loopback(http_port));
    profile
}

/// Insert a node and return its identifier.
pub fn add_node(state: &mut DesiredState, node: Node) -> NodeId {
    let id = node.id.clone();
    state.nodes.insert(id.clone(), node);
    id
}

/// Insert a profile and return its identifier.
pub fn add_profile(state: &mut DesiredState, profile: EgressProfile) -> ProfileId {
    let id = profile.id.clone();
    state.profiles.insert(id.clone(), profile);
    id
}
