//! Loading and saving the desired state across the policy files.
//!
//! One file per entity kind, so a user can hand-edit `profiles.toml` without
//! risking the node database, and so a git diff of a policy change is small.
//!
//! Secrets live in the same files as the entities that own them — splitting a
//! node's UUID into a second file would make hand-editing worse, not better —
//! and every policy file is written 0600 in a 0700 directory.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use xraytui_domain::{
    ApplicationRule, Chain, DesiredState, EgressProfile, Group, Node, ProfileId, RoutingRule,
    Subscription, SystemMode, UnsupportedNode,
};

use crate::{ConfigError, Paths, SCHEMA_VERSION, load_toml, store_toml};

/// `nodes.toml`
#[derive(Debug, Default, Serialize, Deserialize)]
struct NodesFile {
    #[serde(default = "default_version")]
    schema_version: u32,
    #[serde(default)]
    node: Vec<Node>,
    #[serde(default)]
    unsupported: Vec<UnsupportedNode>,
}

/// `profiles.toml`
#[derive(Debug, Default, Serialize, Deserialize)]
struct ProfilesFile {
    #[serde(default = "default_version")]
    schema_version: u32,
    #[serde(default)]
    mode: SystemMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_profile: Option<ProfileId>,
    #[serde(default)]
    profile: Vec<EgressProfile>,
}

/// `groups.toml`
#[derive(Debug, Default, Serialize, Deserialize)]
struct GroupsFile {
    #[serde(default = "default_version")]
    schema_version: u32,
    #[serde(default)]
    group: Vec<Group>,
}

/// `chains.toml`
#[derive(Debug, Default, Serialize, Deserialize)]
struct ChainsFile {
    #[serde(default = "default_version")]
    schema_version: u32,
    #[serde(default)]
    chain: Vec<Chain>,
}

/// `rules.toml`
#[derive(Debug, Default, Serialize, Deserialize)]
struct RulesFile {
    #[serde(default = "default_version")]
    schema_version: u32,
    #[serde(default)]
    application_rule: Vec<ApplicationRule>,
    #[serde(default)]
    routing_rule: Vec<RoutingRule>,
}

/// `subscriptions.toml`
#[derive(Debug, Default, Serialize, Deserialize)]
struct SubscriptionsFile {
    #[serde(default = "default_version")]
    schema_version: u32,
    #[serde(default)]
    subscription: Vec<Subscription>,
}

const fn default_version() -> u32 {
    SCHEMA_VERSION
}

/// Read every policy file into one desired state.
///
/// Missing files are treated as empty, so a fresh installation starts with a
/// valid, empty configuration rather than an error.
///
/// # Errors
/// Propagates parse failures and schema-version rejections.
pub fn load(paths: &Paths) -> Result<DesiredState, ConfigError> {
    let mut state = DesiredState::default();

    if let Some(file) = load_toml::<NodesFile>(&paths.policy_file("nodes"))? {
        for node in file.node {
            state.nodes.insert(node.id.clone(), node);
        }
        for node in file.unsupported {
            state.unsupported.insert(node.id.clone(), node);
        }
    }
    if let Some(file) = load_toml::<ProfilesFile>(&paths.policy_file("profiles"))? {
        state.mode = file.mode;
        state.default_profile = file.default_profile;
        for profile in file.profile {
            state.profiles.insert(profile.id.clone(), profile);
        }
    }
    if let Some(file) = load_toml::<GroupsFile>(&paths.policy_file("groups"))? {
        for group in file.group {
            state.groups.insert(group.id.clone(), group);
        }
    }
    if let Some(file) = load_toml::<ChainsFile>(&paths.policy_file("chains"))? {
        for chain in file.chain {
            state.chains.insert(chain.id.clone(), chain);
        }
    }
    if let Some(file) = load_toml::<RulesFile>(&paths.policy_file("rules"))? {
        for rule in file.application_rule {
            state.app_rules.insert(rule.id.clone(), rule);
        }
        for rule in file.routing_rule {
            state.routing_rules.insert(rule.id.clone(), rule);
        }
    }
    if let Some(file) = load_toml::<SubscriptionsFile>(&paths.policy_file("subscriptions"))? {
        for subscription in file.subscription {
            state
                .subscriptions
                .insert(subscription.id.clone(), subscription);
        }
    }

    Ok(state)
}

/// Write every policy file.
///
/// Each file is written atomically; a crash between files leaves the previous
/// contents of the remaining ones, which still parse.
///
/// # Errors
/// Propagates serialisation and I/O failures.
pub fn save(paths: &Paths, state: &DesiredState) -> Result<(), ConfigError> {
    store_toml(
        &paths.policy_file("nodes"),
        &NodesFile {
            schema_version: SCHEMA_VERSION,
            node: state.nodes.values().cloned().collect(),
            unsupported: state.unsupported.values().cloned().collect(),
        },
    )?;
    store_toml(
        &paths.policy_file("profiles"),
        &ProfilesFile {
            schema_version: SCHEMA_VERSION,
            mode: state.mode,
            default_profile: state.default_profile.clone(),
            profile: state.profiles.values().cloned().collect(),
        },
    )?;
    store_toml(
        &paths.policy_file("groups"),
        &GroupsFile {
            schema_version: SCHEMA_VERSION,
            group: state.groups.values().cloned().collect(),
        },
    )?;
    store_toml(
        &paths.policy_file("chains"),
        &ChainsFile {
            schema_version: SCHEMA_VERSION,
            chain: state.chains.values().cloned().collect(),
        },
    )?;
    store_toml(
        &paths.policy_file("rules"),
        &RulesFile {
            schema_version: SCHEMA_VERSION,
            application_rule: state.app_rules.values().cloned().collect(),
            routing_rule: state.routing_rules.values().cloned().collect(),
        },
    )?;
    store_toml(
        &paths.policy_file("subscriptions"),
        &SubscriptionsFile {
            schema_version: SCHEMA_VERSION,
            subscription: state.subscriptions.values().cloned().collect(),
        },
    )?;
    Ok(())
}

/// A starter configuration for a fresh installation.
///
/// Deliberately minimal and inert: one direct profile with a loopback SOCKS
/// listener, mode `off`, nothing proxied. Nothing here touches the network until
/// the user adds a node.
#[must_use]
pub fn starter_state() -> DesiredState {
    let mut state = DesiredState::default();
    let id = ProfileId::new("direct").unwrap_or_else(|_| ProfileId::from_text("direct"));
    let mut profile = EgressProfile::new(id.clone(), "Direct", xraytui_domain::Target::Direct);
    profile.socks = Some(xraytui_domain::ListenerSpec::loopback(11080));
    profile.http = Some(xraytui_domain::ListenerSpec::loopback(11081));
    state.profiles.insert(id.clone(), profile);
    state.default_profile = Some(id);
    state.mode = SystemMode::Off;
    state
}

/// Node identifiers grouped by the subscription that owns them.
#[must_use]
pub fn nodes_by_subscription(
    state: &DesiredState,
) -> BTreeMap<xraytui_domain::SubscriptionId, Vec<xraytui_domain::NodeId>> {
    let mut out: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (id, node) in &state.nodes {
        if let Some(subscription) = node.source.subscription() {
            out.entry(subscription.clone())
                .or_default()
                .push(id.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{
        Endpoint, ListenerSpec, NodeId, NodeSource, ProtocolSettings, Target, TrojanSettings,
    };
    use xraytui_secrets::Secret;

    fn sample_state() -> DesiredState {
        let mut state = starter_state();
        let node = Node::new(
            NodeId::new("hk-01").expect("valid"),
            "香港 01",
            NodeSource::Manual,
            Endpoint::new("hk.example.com", 443),
            ProtocolSettings::Trojan(TrojanSettings {
                password: Secret::new("pw"),
                flow: String::new(),
            }),
        );
        state.nodes.insert(node.id.clone(), node);
        let pid = ProfileId::new("web").expect("valid");
        let mut profile = EgressProfile::new(
            pid.clone(),
            "Web",
            Target::Node {
                id: NodeId::new("hk-01").expect("valid"),
            },
        );
        profile.socks = Some(ListenerSpec::loopback(12080));
        state.profiles.insert(pid, profile);
        state
    }

    #[test]
    fn an_empty_directory_loads_as_an_empty_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        paths.ensure().expect("ensure");
        let state = load(&paths).expect("load");
        assert_eq!(state, DesiredState::default());
    }

    #[test]
    fn state_round_trips_through_the_policy_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        paths.ensure().expect("ensure");
        let state = sample_state();
        save(&paths, &state).expect("save");
        let loaded = load(&paths).expect("load");
        assert_eq!(loaded, state);
    }

    #[test]
    fn every_policy_file_is_written_private() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        paths.ensure().expect("ensure");
        save(&paths, &sample_state()).expect("save");
        for name in [
            "nodes",
            "profiles",
            "groups",
            "chains",
            "rules",
            "subscriptions",
        ] {
            let path = paths.policy_file(name);
            assert!(path.is_file(), "{name}.toml was not written");
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}.toml has mode {mode:o}");
        }
    }

    #[test]
    fn unicode_names_survive_the_round_trip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        paths.ensure().expect("ensure");
        save(&paths, &sample_state()).expect("save");
        let loaded = load(&paths).expect("load");
        assert_eq!(
            loaded
                .nodes
                .get(&NodeId::new("hk-01").expect("valid"))
                .map(|n| n.name.as_str()),
            Some("香港 01")
        );
    }

    #[test]
    fn the_starter_state_is_valid_and_inert() {
        let state = starter_state();
        assert_eq!(state.mode, SystemMode::Off);
        assert!(state.nodes.is_empty());
        assert!(
            state
                .validate()
                .iter()
                .all(|d| d.severity != xraytui_domain::Severity::Error),
            "{:?}",
            state.validate()
        );
        assert!(
            state
                .profiles
                .values()
                .flat_map(|p| p.listeners())
                .all(|l| !l.is_exposed()),
            "the starter configuration must not expose anything"
        );
    }

    #[test]
    fn a_newer_policy_file_is_refused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        paths.ensure().expect("ensure");
        std::fs::write(paths.policy_file("nodes"), "schema_version = 99\n").expect("write");
        let error = load(&paths).expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::SchemaTooNew { found: 99, .. }),
            "{error:?}"
        );
    }

    #[test]
    fn subscription_ownership_is_indexable() {
        let mut state = sample_state();
        let sub = xraytui_domain::SubscriptionId::new("provider").expect("valid");
        let node = Node::new(
            NodeId::new("sub-01").expect("valid"),
            "Sub 01",
            NodeSource::Subscription { id: sub.clone() },
            Endpoint::new("s.example", 443),
            ProtocolSettings::Trojan(TrojanSettings {
                password: Secret::new("pw"),
                flow: String::new(),
            }),
        );
        state.nodes.insert(node.id.clone(), node);
        let index = nodes_by_subscription(&state);
        assert_eq!(index.get(&sub).map(Vec::len), Some(1));
    }
}
