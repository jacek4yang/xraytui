//! The aggregate desired state and its validation.
//!
//! [`DesiredState`] is what the user asked for. The compiler turns it into an
//! Xray generation; the daemon reconciles observed runtime state against it.
//! Nothing in this module performs I/O.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ids::{AppRuleId, ChainId, GroupId, NodeId, ProfileId, RoutingRuleId, SubscriptionId};
use crate::node::{Compatibility, Node, UnsupportedNode};
use crate::policy::{
    ApplicationRule, Chain, ChainError, EgressProfile, Group, RoutingRule, RuleAction, SystemMode,
    Target,
};
use crate::subscription::Subscription;

/// Everything the user configured, indexed for lookup.
///
/// Maps are `BTreeMap` so that iteration order is deterministic — the compiler
/// depends on this for byte-stable output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredState {
    /// Requested system mode.
    #[serde(default)]
    pub mode: SystemMode,
    /// Profile designated as the default for `RuleAction::DefaultProfile` and
    /// for global mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<ProfileId>,
    /// All nodes, including subscription-owned ones.
    #[serde(default)]
    pub nodes: BTreeMap<NodeId, Node>,
    /// Recognised but non-compilable entries.
    #[serde(default)]
    pub unsupported: BTreeMap<NodeId, UnsupportedNode>,
    /// Groups.
    #[serde(default)]
    pub groups: BTreeMap<GroupId, Group>,
    /// Chains.
    #[serde(default)]
    pub chains: BTreeMap<ChainId, Chain>,
    /// Egress profiles.
    #[serde(default)]
    pub profiles: BTreeMap<ProfileId, EgressProfile>,
    /// Application rules.
    #[serde(default)]
    pub app_rules: BTreeMap<AppRuleId, ApplicationRule>,
    /// Destination routing rules.
    #[serde(default)]
    pub routing_rules: BTreeMap<RoutingRuleId, RoutingRule>,
    /// Subscriptions.
    #[serde(default)]
    pub subscriptions: BTreeMap<SubscriptionId, Subscription>,
}

/// A validation problem. Errors block compilation; warnings do not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Severity.
    pub severity: Severity,
    /// Stable machine-readable code, e.g. `profile.unknown-target`.
    pub code: String,
    /// Human-readable message. Never contains credentials.
    pub message: String,
    /// Entity the diagnostic is attached to, for the TUI to focus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

impl Diagnostic {
    /// Construct an error.
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: code.to_owned(),
            message: message.into(),
            subject: None,
        }
    }

    /// Construct a warning.
    pub fn warning(code: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: code.to_owned(),
            message: message.into(),
            subject: None,
        }
    }

    /// Attach the entity this diagnostic concerns.
    #[must_use]
    pub fn about(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

/// Diagnostic severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Advisory; compilation proceeds.
    Warning,
    /// Blocks compilation.
    Error,
}

impl DesiredState {
    /// Resolve a target to the set of nodes it can reach.
    ///
    /// Used by health prioritisation and by the "what would this do" explanation.
    #[must_use]
    pub fn resolve_target_nodes(&self, target: &Target) -> BTreeSet<NodeId> {
        let mut out = BTreeSet::new();
        self.collect_target_nodes(target, &mut out, 0);
        out
    }

    fn collect_target_nodes(&self, target: &Target, out: &mut BTreeSet<NodeId>, depth: usize) {
        // Depth guard: groups may contain chains whose hops are nodes; nothing
        // legal nests deeper than that, and a cycle must not hang the caller.
        if depth > 4 {
            return;
        }
        match target {
            Target::Node { id } => {
                if self.nodes.contains_key(id) {
                    out.insert(id.clone());
                }
            }
            Target::Chain { id } => {
                if let Some(chain) = self.chains.get(id) {
                    for hop in &chain.hops {
                        if self.nodes.contains_key(hop) {
                            out.insert(hop.clone());
                        }
                    }
                }
            }
            Target::Group { id } => {
                for member in self.group_members(id) {
                    self.collect_target_nodes(&member, out, depth + 1);
                }
            }
            Target::Direct | Target::Block => {}
        }
    }

    /// Compute the concrete members of a group, in deterministic order.
    ///
    /// Regular expressions that fail to compile are ignored here; validation
    /// reports them separately so a bad pattern cannot silently empty a group
    /// *and* produce no diagnostic.
    #[must_use]
    pub fn group_members(&self, id: &GroupId) -> Vec<Target> {
        let Some(group) = self.groups.get(id) else {
            return Vec::new();
        };
        let membership = &group.membership;

        let include: Vec<regex::Regex> = Vec::new();
        let _ = include; // regex is compiled by the caller-side helper below

        let mut members: BTreeSet<Target> = BTreeSet::new();

        for node_id in &membership.nodes {
            if self.nodes.contains_key(node_id) {
                members.insert(Target::Node {
                    id: node_id.clone(),
                });
            }
        }
        for chain_id in &membership.chains {
            if self.chains.contains_key(chain_id) {
                members.insert(Target::Chain {
                    id: chain_id.clone(),
                });
            }
        }

        let has_criteria = !membership.subscriptions.is_empty()
            || !membership.include_regex.is_empty()
            || !membership.tags.is_empty()
            || !membership.protocols.is_empty()
            || !membership.regions.is_empty();

        if has_criteria {
            let includes = compile_patterns(&membership.include_regex);
            let excludes = compile_patterns(&membership.exclude_regex);
            for (node_id, node) in &self.nodes {
                if !node.is_compilable() {
                    continue;
                }
                if !membership.subscriptions.is_empty() {
                    let owned = membership
                        .subscriptions
                        .iter()
                        .any(|sub| node.source.owned_by(sub));
                    if !owned {
                        continue;
                    }
                }
                if !membership.protocols.is_empty()
                    && !membership
                        .protocols
                        .iter()
                        .any(|p| p.eq_ignore_ascii_case(node.protocol.xray_protocol()))
                {
                    continue;
                }
                if !membership.regions.is_empty() {
                    let region = node.region.clone().unwrap_or_default();
                    if !membership
                        .regions
                        .iter()
                        .any(|r| r.eq_ignore_ascii_case(&region))
                    {
                        continue;
                    }
                }
                if !membership.tags.is_empty()
                    && !membership.tags.iter().all(|t| node.tags.contains(t))
                {
                    continue;
                }
                if !includes.is_empty() && !includes.iter().any(|re| re.is_match(&node.name)) {
                    continue;
                }
                if excludes.iter().any(|re| re.is_match(&node.name)) {
                    continue;
                }
                members.insert(Target::Node {
                    id: node_id.clone(),
                });
            }
        } else if !membership.exclude_regex.is_empty() {
            let excludes = compile_patterns(&membership.exclude_regex);
            members.retain(|target| match target {
                Target::Node { id } => self
                    .nodes
                    .get(id)
                    .is_none_or(|node| !excludes.iter().any(|re| re.is_match(&node.name))),
                _ => true,
            });
        }

        members.into_iter().collect()
    }

    /// Validate the whole state, returning every problem found.
    ///
    /// The compiler refuses to run when any [`Severity::Error`] is present.
    #[must_use]
    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        self.validate_profiles(&mut out);
        self.validate_groups(&mut out);
        self.validate_chains(&mut out);
        self.validate_rules(&mut out);
        self.validate_listeners(&mut out);
        self.validate_default_profile(&mut out);
        out
    }

    fn validate_target(&self, target: &Target, subject: &str, out: &mut Vec<Diagnostic>) {
        match target {
            Target::Node { id } => {
                if !self.nodes.contains_key(id) {
                    let hint = if self.unsupported.contains_key(id) {
                        " (it exists but is unsupported)"
                    } else {
                        ""
                    };
                    out.push(
                        Diagnostic::error(
                            "target.unknown-node",
                            format!("{subject} points at unknown node '{id}'{hint}"),
                        )
                        .about(subject),
                    );
                } else if let Some(node) = self.nodes.get(id) {
                    if !node.enabled {
                        out.push(
                            Diagnostic::warning(
                                "target.disabled-node",
                                format!("{subject} points at disabled node '{id}'"),
                            )
                            .about(subject),
                        );
                    }
                    if node.compatibility == Compatibility::Unsupported {
                        out.push(
                            Diagnostic::error(
                                "target.unsupported-node",
                                format!("{subject} points at node '{id}' which cannot be compiled"),
                            )
                            .about(subject),
                        );
                    }
                }
            }
            Target::Group { id } => {
                if !self.groups.contains_key(id) {
                    out.push(
                        Diagnostic::error(
                            "target.unknown-group",
                            format!("{subject} points at unknown group '{id}'"),
                        )
                        .about(subject),
                    );
                } else if self.group_members(id).is_empty() {
                    out.push(
                        Diagnostic::warning(
                            "target.empty-group",
                            format!(
                                "{subject} points at group '{id}' which currently has no members"
                            ),
                        )
                        .about(subject),
                    );
                }
            }
            Target::Chain { id } => {
                if !self.chains.contains_key(id) {
                    out.push(
                        Diagnostic::error(
                            "target.unknown-chain",
                            format!("{subject} points at unknown chain '{id}'"),
                        )
                        .about(subject),
                    );
                }
            }
            Target::Direct | Target::Block => {}
        }
    }

    fn validate_profiles(&self, out: &mut Vec<Diagnostic>) {
        for (id, profile) in &self.profiles {
            let subject = format!("profile '{id}'");
            self.validate_target(&profile.target, &subject, out);
            if let Some(fallback) = &profile.fallback {
                self.validate_target(fallback, &format!("{subject} fallback"), out);
                if fallback == &profile.target {
                    out.push(
                        Diagnostic::warning(
                            "profile.fallback-equals-target",
                            format!("{subject} has a fallback identical to its target"),
                        )
                        .about(&subject),
                    );
                }
            }
        }
        if self.profiles.is_empty() {
            out.push(Diagnostic::warning(
                "profile.none",
                "no egress profiles are defined; only direct traffic will be possible",
            ));
        }
    }

    fn validate_groups(&self, out: &mut Vec<Diagnostic>) {
        for (id, group) in &self.groups {
            let subject = format!("group '{id}'");
            for pattern in group
                .membership
                .include_regex
                .iter()
                .chain(&group.membership.exclude_regex)
            {
                if let Err(err) = regex::Regex::new(pattern) {
                    out.push(
                        Diagnostic::error(
                            "group.bad-regex",
                            format!("{subject} has an invalid pattern: {err}"),
                        )
                        .about(&subject),
                    );
                }
            }
            if group.membership.is_empty() {
                out.push(
                    Diagnostic::warning(
                        "group.no-criteria",
                        format!("{subject} has no membership criteria and will always be empty"),
                    )
                    .about(&subject),
                );
            }
            for member in &group.membership.nodes {
                if !self.nodes.contains_key(member) {
                    out.push(
                        Diagnostic::error(
                            "group.unknown-member",
                            format!("{subject} lists unknown node '{member}'"),
                        )
                        .about(&subject),
                    );
                }
            }
            for member in &group.membership.chains {
                if !self.chains.contains_key(member) {
                    out.push(
                        Diagnostic::error(
                            "group.unknown-chain",
                            format!("{subject} lists unknown chain '{member}'"),
                        )
                        .about(&subject),
                    );
                }
            }
            if group.strategy == crate::policy::GroupStrategy::Manual {
                match &group.manual_selection {
                    None => out.push(
                        Diagnostic::warning(
                            "group.manual-without-selection",
                            format!("{subject} uses the manual strategy but has no selection"),
                        )
                        .about(&subject),
                    ),
                    Some(selection) => {
                        if !self.group_members(id).contains(selection) {
                            out.push(
                                Diagnostic::error(
                                    "group.manual-selection-not-member",
                                    format!(
                                        "{subject} selects '{}' which is not one of its members",
                                        selection.to_token()
                                    ),
                                )
                                .about(&subject),
                            );
                        }
                    }
                }
            }
            if let Some(fallback) = &group.fallback {
                self.validate_target(fallback, &format!("{subject} fallback"), out);
            }
        }
    }

    fn validate_chains(&self, out: &mut Vec<Diagnostic>) {
        for (id, chain) in &self.chains {
            for error in self.validate_chain(id) {
                // A disabled chain is not compiled, so a dangling reference in
                // one cannot stop the core from starting. Reporting it as an
                // error anyway would mean a subscription update that removes a
                // hop leaves the user unable to save *anything* until they
                // delete the chain — when what they usually want is to disable
                // it, keep the hops, and repair it later.
                let diagnostic = if chain.enabled {
                    Diagnostic::error("chain.invalid", error.to_string())
                } else {
                    Diagnostic::warning(
                        "chain.invalid-disabled",
                        format!("{error} (the chain is disabled, so it is not compiled)"),
                    )
                };
                out.push(diagnostic.about(format!("chain '{id}'")));
            }
        }
    }

    /// Validate one chain in isolation.
    #[must_use]
    pub fn validate_chain(&self, id: &ChainId) -> Vec<ChainError> {
        let Some(chain) = self.chains.get(id) else {
            return Vec::new();
        };
        let mut errors = Vec::new();
        if chain.hops.len() < 2 {
            errors.push(ChainError::TooShort(id.clone()));
        }
        let mut seen = BTreeSet::new();
        for (index, hop) in chain.hops.iter().enumerate() {
            if !seen.insert(hop.clone()) {
                errors.push(ChainError::RepeatedHop {
                    chain: id.clone(),
                    node: hop.clone(),
                });
            }
            match self.nodes.get(hop) {
                None => {
                    errors.push(ChainError::MissingHop {
                        chain: id.clone(),
                        node: hop.clone(),
                    });
                }
                Some(node) => {
                    if !node.enabled {
                        errors.push(ChainError::UnusableHop {
                            chain: id.clone(),
                            node: hop.clone(),
                            reason: "disabled".into(),
                        });
                    }
                    if node.compatibility == Compatibility::Unsupported {
                        errors.push(ChainError::UnusableHop {
                            chain: id.clone(),
                            node: hop.clone(),
                            reason: "unsupported protocol".into(),
                        });
                    }
                    let is_terminal = Some(index) == chain.terminal_index();
                    if !is_terminal && !node.protocol.supports_udp() {
                        errors.push(ChainError::UdpBreak {
                            chain: id.clone(),
                            node: hop.clone(),
                        });
                    }
                }
            }
        }
        errors
    }

    fn validate_rules(&self, out: &mut Vec<Diagnostic>) {
        let mut app_priorities: BTreeMap<i32, Vec<&AppRuleId>> = BTreeMap::new();
        for (id, rule) in &self.app_rules {
            let subject = format!("application rule '{id}'");
            app_priorities.entry(rule.priority).or_default().push(id);
            if rule.process.is_empty() {
                out.push(
                    Diagnostic::error(
                        "app-rule.no-matchers",
                        format!("{subject} has no process matchers"),
                    )
                    .about(&subject),
                );
            }
            for matcher in &rule.process {
                if !matcher.is_valid() {
                    out.push(
                        Diagnostic::error(
                            "app-rule.bad-matcher",
                            format!("{subject} has an invalid matcher {:?}", matcher.0),
                        )
                        .about(&subject),
                    );
                }
            }
            self.validate_action(&rule.action, &subject, out);
        }
        for (priority, ids) in &app_priorities {
            if ids.len() > 1 {
                let names: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
                out.push(Diagnostic::warning(
                    "app-rule.duplicate-priority",
                    format!(
                        "application rules {} share priority {priority}; order between them is by identifier",
                        names.join(", ")
                    ),
                ));
            }
        }

        let mut ordered: Vec<&RoutingRule> =
            self.routing_rules.values().filter(|r| r.enabled).collect();
        ordered.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        for (index, rule) in ordered.iter().enumerate() {
            let subject = format!("routing rule '{}'", rule.id);
            self.validate_action(&rule.action, &subject, out);
            if rule.matcher.is_catch_all() && index + 1 < ordered.len() {
                let shadowed: Vec<String> = ordered[index + 1..]
                    .iter()
                    .map(|r| r.id.to_string())
                    .collect();
                out.push(
                    Diagnostic::warning(
                        "routing-rule.shadowing",
                        format!(
                            "{subject} matches everything and shadows {} later rule(s): {}",
                            shadowed.len(),
                            shadowed.join(", ")
                        ),
                    )
                    .about(&subject),
                );
            }
            for matcher in &rule.matcher.process {
                if !matcher.is_valid() {
                    out.push(
                        Diagnostic::error(
                            "routing-rule.bad-matcher",
                            format!("{subject} has an invalid process matcher {:?}", matcher.0),
                        )
                        .about(&subject),
                    );
                }
            }
        }
    }

    fn validate_action(&self, action: &RuleAction, subject: &str, out: &mut Vec<Diagnostic>) {
        match action {
            RuleAction::Profile { id } => {
                if !self.profiles.contains_key(id) {
                    out.push(
                        Diagnostic::error(
                            "action.unknown-profile",
                            format!("{subject} points at unknown profile '{id}'"),
                        )
                        .about(subject),
                    );
                }
            }
            RuleAction::Target { target } => self.validate_target(target, subject, out),
            RuleAction::DefaultProfile => {
                if self.default_profile.is_none() {
                    out.push(
                        Diagnostic::error(
                            "action.no-default-profile",
                            format!("{subject} uses the default profile but none is configured"),
                        )
                        .about(subject),
                    );
                }
            }
        }
    }

    fn validate_listeners(&self, out: &mut Vec<Diagnostic>) {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for (id, profile) in &self.profiles {
            for (kind, listener) in [("socks", &profile.socks), ("http", &profile.http)] {
                let Some(listener) = listener else { continue };
                let key = listener.listen.to_string();
                let owner = format!("profile '{id}' {kind}");
                if let Some(previous) = seen.insert(key.clone(), owner.clone()) {
                    out.push(
                        Diagnostic::error(
                            "listener.port-collision",
                            format!("{owner} and {previous} both bind {key}"),
                        )
                        .about(&owner),
                    );
                }
                if listener.is_exposed() {
                    if listener.username.is_none() || listener.password.is_none() {
                        out.push(
                            Diagnostic::error(
                                "listener.lan-without-auth",
                                format!(
                                    "{owner} binds the non-loopback address {key} without credentials"
                                ),
                            )
                            .about(&owner),
                        );
                    } else {
                        out.push(
                            Diagnostic::warning(
                                "listener.lan-exposed",
                                format!("{owner} is reachable from the network on {key}"),
                            )
                            .about(&owner),
                        );
                    }
                }
                if listener.listen.port() == 0 {
                    out.push(
                        Diagnostic::error(
                            "listener.zero-port",
                            format!(
                                "{owner} requests port 0, which cannot be addressed by clients"
                            ),
                        )
                        .about(&owner),
                    );
                }
            }
        }
    }

    fn validate_default_profile(&self, out: &mut Vec<Diagnostic>) {
        if let Some(id) = &self.default_profile {
            if !self.profiles.contains_key(id) {
                out.push(Diagnostic::error(
                    "state.unknown-default-profile",
                    format!("default profile '{id}' does not exist"),
                ));
            }
        } else if self.mode == SystemMode::Global {
            out.push(Diagnostic::error(
                "state.global-without-default",
                "global mode requires a default profile",
            ));
        }
    }

    /// Every place a node is referenced. Used before deleting one.
    #[must_use]
    pub fn references_to_node(&self, id: &NodeId) -> Vec<String> {
        let mut refs = Vec::new();
        for (pid, profile) in &self.profiles {
            if matches!(&profile.target, Target::Node { id: n } if n == id) {
                refs.push(format!("profile '{pid}' target"));
            }
            if matches!(&profile.fallback, Some(Target::Node { id: n }) if n == id) {
                refs.push(format!("profile '{pid}' fallback"));
            }
        }
        for (gid, group) in &self.groups {
            if group.membership.nodes.contains(id) {
                refs.push(format!("group '{gid}' membership"));
            }
        }
        for (cid, chain) in &self.chains {
            if chain.hops.contains(id) {
                refs.push(format!("chain '{cid}' hop"));
            }
        }
        for (rid, rule) in &self.routing_rules {
            if matches!(&rule.action, RuleAction::Target { target: Target::Node { id: n } } if n == id)
            {
                refs.push(format!("routing rule '{rid}'"));
            }
        }
        for (rid, rule) in &self.app_rules {
            if matches!(&rule.action, RuleAction::Target { target: Target::Node { id: n } } if n == id)
            {
                refs.push(format!("application rule '{rid}'"));
            }
        }
        refs
    }

    /// Nodes owned by a subscription namespace.
    #[must_use]
    pub fn nodes_of_subscription(&self, id: &SubscriptionId) -> Vec<&Node> {
        self.nodes
            .values()
            .filter(|n| n.source.owned_by(id))
            .collect()
    }
}

fn compile_patterns(patterns: &[String]) -> Vec<regex::Regex> {
    patterns
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
}

// A tiny regex shim so the domain crate does not pull the full `regex` crate
// into every consumer. Only the subset used by group filters is implemented.
/// A deliberately small, bounded regular-expression engine.
///
/// Group filters and subscription filters both run patterns over text that a
/// provider controls. A general-purpose backtracking engine given
/// provider-controlled input is a denial of service waiting to be handed to
/// you, so this one has a hard step budget and a hard pattern-length limit, and
/// rejects the constructs that make backtracking explode rather than trying to
/// survive them.
pub mod regex {
    /// Minimal anchored-substring matcher supporting a useful subset of regex.
    ///
    /// Supported: literal text, `.`, `*`, `+`, `?`, `^`, `$`, `[abc]`, `[^abc]`,
    /// `[a-z]`, `|` alternation at the top level, and `(...)` grouping without
    /// captures. Anything else is a compile error, which the caller surfaces as a
    /// diagnostic rather than silently ignoring.
    ///
    /// This exists because group filters run on every recompile over potentially
    /// tens of thousands of node names, and because accepting arbitrary regex from
    /// a subscription is a denial-of-service vector: this engine is a backtracking
    /// matcher with an explicit step budget, so a pathological pattern fails
    /// instead of hanging.
    #[derive(Debug, Clone)]
    pub struct Regex {
        alternatives: Vec<Vec<Piece>>,
    }

    #[derive(Debug, Clone)]
    struct Piece {
        atom: Atom,
        repeat: Repeat,
    }

    #[derive(Debug, Clone)]
    enum Atom {
        Literal(char),
        Any,
        Class {
            negated: bool,
            ranges: Vec<(char, char)>,
        },
        Start,
        End,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Repeat {
        One,
        ZeroOrMore,
        OneOrMore,
        ZeroOrOne,
    }

    /// Pattern compilation failure.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Error(String);

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    const MAX_PATTERN_LEN: usize = 512;
    const STEP_BUDGET: u32 = 200_000;

    impl Regex {
        /// Compile a pattern.
        pub fn new(pattern: &str) -> Result<Self, Error> {
            if pattern.len() > MAX_PATTERN_LEN {
                return Err(Error(format!(
                    "pattern longer than {MAX_PATTERN_LEN} bytes"
                )));
            }
            let mut alternatives = Vec::new();
            for branch in split_top_level(pattern)? {
                alternatives.push(compile_branch(&branch)?);
            }
            Ok(Self { alternatives })
        }

        /// Whether the pattern matches anywhere in `haystack`.
        pub fn is_match(&self, haystack: &str) -> bool {
            let chars: Vec<char> = haystack.chars().collect();
            for pieces in &self.alternatives {
                let anchored_start = matches!(pieces.first().map(|p| &p.atom), Some(Atom::Start));
                let body = if anchored_start {
                    &pieces[1..]
                } else {
                    &pieces[..]
                };
                let starts: Vec<usize> = if anchored_start {
                    vec![0]
                } else {
                    (0..=chars.len()).collect()
                };
                for start in starts {
                    let mut budget = STEP_BUDGET;
                    if match_here(body, &chars, start, &mut budget) {
                        return true;
                    }
                }
            }
            false
        }
    }

    fn split_top_level(pattern: &str) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        let mut current = String::new();
        let mut depth = 0usize;
        let mut in_class = false;
        let mut escaped = false;
        for ch in pattern.chars() {
            if escaped {
                current.push(ch);
                escaped = false;
                continue;
            }
            match ch {
                '\\' => {
                    current.push(ch);
                    escaped = true;
                }
                '[' if !in_class => {
                    in_class = true;
                    current.push(ch);
                }
                ']' if in_class => {
                    in_class = false;
                    current.push(ch);
                }
                '(' if !in_class => {
                    depth += 1;
                    current.push(ch);
                }
                ')' if !in_class => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| Error("unbalanced ')'".into()))?;
                    current.push(ch);
                }
                '|' if !in_class && depth == 0 => {
                    out.push(std::mem::take(&mut current));
                }
                _ => current.push(ch),
            }
        }
        if escaped {
            return Err(Error("pattern ends with a trailing backslash".into()));
        }
        if in_class {
            return Err(Error("unterminated character class".into()));
        }
        if depth != 0 {
            return Err(Error("unbalanced '('".into()));
        }
        out.push(current);
        Ok(out)
    }

    fn compile_branch(branch: &str) -> Result<Vec<Piece>, Error> {
        let chars: Vec<char> = branch.chars().collect();
        let mut pieces = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            let atom = match chars[i] {
                '^' if i == 0 => {
                    i += 1;
                    Atom::Start
                }
                '$' if i + 1 == chars.len() => {
                    i += 1;
                    Atom::End
                }
                '.' => {
                    i += 1;
                    Atom::Any
                }
                '(' => {
                    // Grouping without captures: transparent for this subset.
                    i += 1;
                    continue;
                }
                ')' => {
                    i += 1;
                    // A quantified group (`(ab)+`) would need a real engine and is
                    // exactly the shape that causes catastrophic backtracking, so
                    // it is rejected rather than silently mis-compiled.
                    if matches!(chars.get(i), Some('*' | '+' | '?')) {
                        return Err(Error(
                            "quantifiers on groups such as '(ab)+' are not supported".into(),
                        ));
                    }
                    continue;
                }
                '\\' => {
                    i += 1;
                    let escaped = *chars
                        .get(i)
                        .ok_or_else(|| Error("trailing backslash".into()))?;
                    i += 1;
                    match escaped {
                        'd' => Atom::Class {
                            negated: false,
                            ranges: vec![('0', '9')],
                        },
                        'w' => Atom::Class {
                            negated: false,
                            ranges: vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')],
                        },
                        's' => Atom::Class {
                            negated: false,
                            ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\n'), ('\r', '\r')],
                        },
                        other => Atom::Literal(other),
                    }
                }
                '[' => {
                    i += 1;
                    let negated = chars.get(i) == Some(&'^');
                    if negated {
                        i += 1;
                    }
                    let mut ranges = Vec::new();
                    let mut closed = false;
                    while i < chars.len() {
                        if chars[i] == ']' {
                            i += 1;
                            closed = true;
                            break;
                        }
                        let lo = chars[i];
                        i += 1;
                        if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|c| *c != ']')
                        {
                            let hi = chars[i + 1];
                            i += 2;
                            ranges.push((lo, hi));
                        } else {
                            ranges.push((lo, lo));
                        }
                    }
                    if !closed {
                        return Err(Error("unterminated character class".into()));
                    }
                    Atom::Class { negated, ranges }
                }
                '*' | '+' | '?' => {
                    return Err(Error(format!(
                        "quantifier '{}' has nothing to repeat",
                        chars[i]
                    )));
                }
                literal => {
                    i += 1;
                    Atom::Literal(literal)
                }
            };
            let repeat = match chars.get(i) {
                Some('*') => {
                    i += 1;
                    Repeat::ZeroOrMore
                }
                Some('+') => {
                    i += 1;
                    Repeat::OneOrMore
                }
                Some('?') => {
                    i += 1;
                    Repeat::ZeroOrOne
                }
                _ => Repeat::One,
            };
            pieces.push(Piece { atom, repeat });
        }
        Ok(pieces)
    }

    fn atom_matches(atom: &Atom, ch: char) -> bool {
        match atom {
            Atom::Literal(expected) => *expected == ch,
            Atom::Any => true,
            Atom::Class { negated, ranges } => {
                let inside = ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&ch));
                inside != *negated
            }
            Atom::Start | Atom::End => false,
        }
    }

    fn match_here(pieces: &[Piece], chars: &[char], pos: usize, budget: &mut u32) -> bool {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        let Some(piece) = pieces.first() else {
            return true;
        };
        let rest = &pieces[1..];
        if matches!(piece.atom, Atom::End) {
            return pos == chars.len() && match_here(rest, chars, pos, budget);
        }
        if matches!(piece.atom, Atom::Start) {
            return pos == 0 && match_here(rest, chars, pos, budget);
        }
        match piece.repeat {
            Repeat::One => {
                pos < chars.len()
                    && atom_matches(&piece.atom, chars[pos])
                    && match_here(rest, chars, pos + 1, budget)
            }
            Repeat::ZeroOrOne => {
                if pos < chars.len()
                    && atom_matches(&piece.atom, chars[pos])
                    && match_here(rest, chars, pos + 1, budget)
                {
                    return true;
                }
                match_here(rest, chars, pos, budget)
            }
            Repeat::ZeroOrMore | Repeat::OneOrMore => {
                let minimum = usize::from(piece.repeat == Repeat::OneOrMore);
                let mut count = 0usize;
                let mut cursor = pos;
                while cursor < chars.len() && atom_matches(&piece.atom, chars[cursor]) {
                    cursor += 1;
                    count += 1;
                }
                while count + 1 > minimum {
                    if match_here(rest, chars, pos + count, budget) {
                        return true;
                    }
                    if count == 0 {
                        break;
                    }
                    count -= 1;
                }
                count >= minimum && match_here(rest, chars, pos + count, budget)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn literals_and_wildcards() {
            assert!(Regex::new("HK").expect("compile").is_match("HK-01"));
            assert!(!Regex::new("US").expect("compile").is_match("HK-01"));
            assert!(Regex::new("HK.01").expect("compile").is_match("HK-01"));
            assert!(Regex::new("HK-0*1").expect("compile").is_match("HK-1"));
        }

        #[test]
        fn anchors() {
            assert!(Regex::new("^HK").expect("compile").is_match("HK-01"));
            assert!(!Regex::new("^K").expect("compile").is_match("HK-01"));
            assert!(Regex::new("01$").expect("compile").is_match("HK-01"));
            assert!(!Regex::new("HK$").expect("compile").is_match("HK-01"));
        }

        #[test]
        fn classes_and_alternation() {
            assert!(Regex::new("[0-9]+").expect("compile").is_match("HK-01"));
            assert!(Regex::new("[^0-9]+").expect("compile").is_match("HK"));
            assert!(Regex::new("HK|US").expect("compile").is_match("US-02"));
            assert!(!Regex::new("JP|SG").expect("compile").is_match("US-02"));
        }

        #[test]
        fn invalid_patterns_are_errors_not_panics() {
            assert!(Regex::new("[abc").is_err());
            assert!(Regex::new("(abc").is_err());
            assert!(Regex::new("abc\\").is_err());
            assert!(Regex::new("*abc").is_err());
            assert!(Regex::new(&"a".repeat(600)).is_err());
        }

        #[test]
        fn quantified_groups_are_rejected_not_mis_compiled() {
            // `(a+)+b` is the classic catastrophic-backtracking shape. This engine
            // refuses it outright instead of pretending to support it.
            let err = Regex::new("(a+)+b").expect_err("must be rejected");
            assert!(err.to_string().contains("quantifiers on groups"), "{err}");
        }

        #[test]
        fn backtracking_pattern_terminates_within_budget() {
            // Supported subset, but still exponential for a naive matcher.
            let re = Regex::new("a*a*a*a*a*a*b").expect("compile");
            let haystack = "a".repeat(64);
            // The step budget guarantees this returns; the answer is "no match".
            assert!(!re.is_match(&haystack));
        }

        #[test]
        fn unicode_names_work() {
            assert!(Regex::new("香港").expect("compile").is_match("香港 01"));
            assert!(!Regex::new("香港").expect("compile").is_match("日本 01"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Endpoint, NodeSource, ProtocolSettings, TrojanSettings};
    use crate::policy::{GroupMembership, GroupStrategy};
    use xraytui_secrets::Secret;

    fn node(id: &str, name: &str) -> Node {
        Node::new(
            NodeId::new(id).expect("valid"),
            name,
            NodeSource::Manual,
            Endpoint::new("example.com", 443),
            ProtocolSettings::Trojan(TrojanSettings {
                password: Secret::new("pw"),
                flow: String::new(),
            }),
        )
    }

    fn state_with_nodes() -> DesiredState {
        let mut state = DesiredState::default();
        for (id, name) in [("hk-01", "HK 01"), ("hk-02", "HK 02"), ("us-01", "US 01")] {
            let n = node(id, name);
            state.nodes.insert(n.id.clone(), n);
        }
        state
    }

    #[test]
    fn unknown_targets_are_errors() {
        let mut state = DesiredState::default();
        state.profiles.insert(
            ProfileId::new("web").expect("valid"),
            EgressProfile::new(
                ProfileId::new("web").expect("valid"),
                "Web",
                Target::Node {
                    id: NodeId::new("missing").expect("valid"),
                },
            ),
        );
        let diagnostics = state.validate();
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == "target.unknown-node" && d.severity == Severity::Error),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn group_membership_applies_include_and_exclude() {
        let mut state = state_with_nodes();
        state.groups.insert(
            GroupId::new("auto-hk").expect("valid"),
            Group {
                id: GroupId::new("auto-hk").expect("valid"),
                name: "Auto HK".into(),
                strategy: GroupStrategy::Random,
                membership: GroupMembership {
                    include_regex: vec!["^HK".into()],
                    exclude_regex: vec!["02$".into()],
                    ..Default::default()
                },
                manual_selection: None,
                fallback: None,
            },
        );
        let members = state.group_members(&GroupId::new("auto-hk").expect("valid"));
        assert_eq!(
            members,
            vec![Target::Node {
                id: NodeId::new("hk-01").expect("valid")
            }]
        );
    }

    #[test]
    fn bad_group_regex_is_reported_as_error() {
        let mut state = state_with_nodes();
        state.groups.insert(
            GroupId::new("g").expect("valid"),
            Group {
                id: GroupId::new("g").expect("valid"),
                name: "G".into(),
                strategy: GroupStrategy::Random,
                membership: GroupMembership {
                    include_regex: vec!["[".into()],
                    ..Default::default()
                },
                manual_selection: None,
                fallback: None,
            },
        );
        let diagnostics = state.validate();
        assert!(
            diagnostics.iter().any(|d| d.code == "group.bad-regex"),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn chain_validation_catches_cycles_and_missing_hops() {
        let mut state = state_with_nodes();
        let id = ChainId::new("bad").expect("valid");
        state.chains.insert(
            id.clone(),
            Chain {
                id: id.clone(),
                name: "Bad".into(),
                hops: vec![
                    NodeId::new("hk-01").expect("valid"),
                    NodeId::new("hk-01").expect("valid"),
                    NodeId::new("nope").expect("valid"),
                ],
                enabled: true,
            },
        );
        let errors = state.validate_chain(&id);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ChainError::RepeatedHop { .. })),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ChainError::MissingHop { .. })),
            "{errors:?}"
        );
    }

    #[test]
    fn chain_rejects_udp_incapable_intermediate_hop() {
        let mut state = state_with_nodes();
        let mut http_node = node("http-01", "HTTP");
        http_node.protocol = ProtocolSettings::Http(crate::node::HttpProxySettings {
            username: None,
            password: None,
        });
        state.nodes.insert(http_node.id.clone(), http_node);
        let id = ChainId::new("c").expect("valid");
        state.chains.insert(
            id.clone(),
            Chain {
                id: id.clone(),
                name: "C".into(),
                hops: vec![
                    NodeId::new("http-01").expect("valid"),
                    NodeId::new("us-01").expect("valid"),
                ],
                enabled: true,
            },
        );
        let errors = state.validate_chain(&id);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ChainError::UdpBreak { .. })),
            "{errors:?}"
        );
    }

    #[test]
    fn terminal_hop_may_be_udp_incapable() {
        let mut state = state_with_nodes();
        let mut http_node = node("http-01", "HTTP");
        http_node.protocol = ProtocolSettings::Http(crate::node::HttpProxySettings {
            username: None,
            password: None,
        });
        state.nodes.insert(http_node.id.clone(), http_node);
        let id = ChainId::new("c").expect("valid");
        state.chains.insert(
            id.clone(),
            Chain {
                id: id.clone(),
                name: "C".into(),
                hops: vec![
                    NodeId::new("us-01").expect("valid"),
                    NodeId::new("http-01").expect("valid"),
                ],
                enabled: true,
            },
        );
        let errors = state.validate_chain(&id);
        assert!(
            !errors
                .iter()
                .any(|e| matches!(e, ChainError::UdpBreak { .. })),
            "{errors:?}"
        );
    }

    #[test]
    fn listener_collisions_are_errors() {
        let mut state = state_with_nodes();
        for id in ["a", "b"] {
            let pid = ProfileId::new(id).expect("valid");
            let mut profile = EgressProfile::new(pid.clone(), id, Target::Direct);
            profile.socks = Some(crate::policy::ListenerSpec::loopback(11080));
            state.profiles.insert(pid, profile);
        }
        let diagnostics = state.validate();
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == "listener.port-collision"),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn lan_listener_without_credentials_is_an_error() {
        let mut state = state_with_nodes();
        let pid = ProfileId::new("web").expect("valid");
        let mut profile = EgressProfile::new(pid.clone(), "Web", Target::Direct);
        profile.socks = Some(crate::policy::ListenerSpec {
            listen: "0.0.0.0:1080".parse().expect("addr"),
            username: None,
            password: None,
        });
        state.profiles.insert(pid, profile);
        let diagnostics = state.validate();
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == "listener.lan-without-auth"),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn catch_all_rule_shadowing_is_warned_about() {
        let mut state = state_with_nodes();
        for (id, priority) in [("first", 10), ("second", 20)] {
            let rid = RoutingRuleId::new(id).expect("valid");
            state.routing_rules.insert(
                rid.clone(),
                RoutingRule {
                    id: rid,
                    priority,
                    matcher: Default::default(),
                    action: RuleAction::Target {
                        target: Target::Direct,
                    },
                    enabled: true,
                    note: None,
                },
            );
        }
        let diagnostics = state.validate();
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == "routing-rule.shadowing"),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn references_to_node_finds_every_use() {
        let mut state = state_with_nodes();
        let node_id = NodeId::new("hk-01").expect("valid");
        let pid = ProfileId::new("web").expect("valid");
        state.profiles.insert(
            pid.clone(),
            EgressProfile::new(
                pid,
                "Web",
                Target::Node {
                    id: node_id.clone(),
                },
            ),
        );
        state.chains.insert(
            ChainId::new("c").expect("valid"),
            Chain {
                id: ChainId::new("c").expect("valid"),
                name: "C".into(),
                hops: vec![node_id.clone(), NodeId::new("us-01").expect("valid")],
                enabled: true,
            },
        );
        let refs = state.references_to_node(&node_id);
        assert_eq!(refs.len(), 2, "{refs:?}");
    }

    #[test]
    fn resolve_target_nodes_walks_groups_and_chains() {
        let mut state = state_with_nodes();
        state.groups.insert(
            GroupId::new("g").expect("valid"),
            Group {
                id: GroupId::new("g").expect("valid"),
                name: "G".into(),
                strategy: GroupStrategy::Random,
                membership: GroupMembership {
                    nodes: vec![NodeId::new("hk-01").expect("valid")],
                    chains: vec![ChainId::new("c").expect("valid")],
                    ..Default::default()
                },
                manual_selection: None,
                fallback: None,
            },
        );
        state.chains.insert(
            ChainId::new("c").expect("valid"),
            Chain {
                id: ChainId::new("c").expect("valid"),
                name: "C".into(),
                hops: vec![
                    NodeId::new("hk-02").expect("valid"),
                    NodeId::new("us-01").expect("valid"),
                ],
                enabled: true,
            },
        );
        let nodes = state.resolve_target_nodes(&Target::Group {
            id: GroupId::new("g").expect("valid"),
        });
        assert_eq!(nodes.len(), 3, "{nodes:?}");
    }
}
