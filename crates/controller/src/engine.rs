//! The reconciliation engine.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use xraytui_domain::{
    CoreStatus, DesiredState, GenerationId, GroupId, ProfileId, ProfileRuntime, RuntimeState,
    SystemMode, Target, TrafficCounters,
};
use xraytui_xray_api::{ApiClient, ApiEndpoint};
use xraytui_xray_compiler::{CompileOptions, Compiled, compile, tags};

use crate::ControllerError;
#[cfg(test)]
use crate::core::Version;
use crate::core::{self, CoreInfo, HealthGate, LaunchSpec, RestartPolicy, RunningCore, unix_now};

/// Static settings the engine needs that are not part of the routing model.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Compiler options, minus the pieces the engine fills in per generation.
    pub compile: CompileOptions,
    /// Where the commander should listen.
    pub api_endpoint: ApiEndpoint,
    /// Path for the configuration currently being applied.
    pub generated_config: PathBuf,
    /// Path for the last configuration that passed its health gate.
    pub last_good_config: PathBuf,
    /// Where to append core log output.
    pub core_log: Option<PathBuf>,
    /// Restart backoff.
    pub restart: RestartPolicy,
    /// Deadline for the API to answer after a start.
    pub api_deadline: Duration,
    /// Deadline for each listener check.
    pub listener_timeout: Duration,
    /// How long to give the core to exit on SIGTERM.
    pub shutdown_grace: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            compile: CompileOptions::default(),
            api_endpoint: ApiEndpoint::loopback(0),
            generated_config: PathBuf::from("generated-xray.json"),
            last_good_config: PathBuf::from("last-good-xray.json"),
            core_log: None,
            restart: RestartPolicy {
                min: Duration::from_millis(500),
                max: Duration::from_secs(60),
                budget: 8,
            },
            api_deadline: Duration::from_secs(15),
            listener_timeout: Duration::from_millis(750),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// How a desired-state change can be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangePlan {
    /// Nothing to do.
    NoChange,
    /// Apply through the API: a list of `(balancer tag, target outbound tag)`.
    ///
    /// This is the fast path. It changes where new connections go without
    /// touching the core's configuration, so unrelated profiles keep running and
    /// existing connections drain naturally.
    Selectors(Vec<(String, String)>),
    /// The topology changed; the core has to be restarted.
    Restart {
        /// Human-readable reason, shown in the UI and the log.
        reason: String,
    },
}

impl ChangePlan {
    /// Whether applying this plan interrupts traffic.
    #[must_use]
    pub fn is_disruptive(&self) -> bool {
        matches!(self, Self::Restart { .. })
    }
}

/// What actually happened when a plan was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Nothing needed doing.
    Unchanged,
    /// Selector overrides were applied without a restart.
    SwitchedSelectors {
        /// Balancer tags that were repointed.
        balancers: Vec<String>,
    },
    /// The core was restarted onto a new generation.
    Restarted {
        /// The generation now running.
        generation: GenerationId,
    },
    /// The new generation failed and the previous one was restored.
    RolledBack {
        /// The generation that failed.
        failed: GenerationId,
        /// The generation now running.
        restored: GenerationId,
    },
}

/// The reconciliation engine.
pub struct Engine {
    config: EngineConfig,
    info: CoreInfo,
    desired: DesiredState,
    compiled: Option<Compiled>,
    running: Option<RunningCore>,
    client: Option<ApiClient>,
    runtime: RuntimeState,
    generation: GenerationId,
    last_good: Option<(GenerationId, String)>,
    consecutive_failures: u32,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("generation", &self.generation)
            .field("core", &self.runtime.core.label())
            .field("profiles", &self.desired.profiles.len())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Create an engine for a validated core binary.
    ///
    /// # Errors
    /// Returns [`ControllerError::CoreTooOld`] when the binary predates the
    /// routing API xraytui depends on.
    pub fn new(config: EngineConfig, info: CoreInfo) -> Result<Self, ControllerError> {
        if !info.is_supported() {
            return Err(ControllerError::CoreTooOld {
                found: info.version,
                minimum: core::MINIMUM_XRAY_VERSION,
            });
        }
        Ok(Self {
            config,
            info,
            desired: DesiredState::default(),
            compiled: None,
            running: None,
            client: None,
            runtime: RuntimeState::default(),
            generation: GenerationId::ZERO,
            last_good: None,
            consecutive_failures: 0,
        })
    }

    /// The desired state currently held.
    #[must_use]
    pub fn desired(&self) -> &DesiredState {
        &self.desired
    }

    /// Install the initial desired state without starting anything.
    ///
    /// Used once at daemon start-up, after the configuration has been loaded but
    /// before the first [`Engine::rebuild_and_start`]. Calling it while a core is
    /// running would leave the running generation describing something else, so
    /// it refuses in that case and the caller must use [`Engine::apply`].
    ///
    /// # Errors
    /// Returns [`ControllerError::Invalid`] if a core is already running.
    pub fn seed(&mut self, state: DesiredState) -> Result<(), ControllerError> {
        if self.running.is_some() {
            return Err(ControllerError::Invalid(
                "cannot seed desired state while a core is running; use apply()".to_owned(),
            ));
        }
        self.desired = state;
        Ok(())
    }

    /// The observed state.
    #[must_use]
    pub fn runtime(&self) -> &RuntimeState {
        &self.runtime
    }

    /// Information about the core binary in use.
    #[must_use]
    pub fn core_info(&self) -> &CoreInfo {
        &self.info
    }

    /// The most recent successful compilation, if any.
    #[must_use]
    pub fn compiled(&self) -> Option<&Compiled> {
        self.compiled.as_ref()
    }

    /// Decide how to get from the current desired state to `next`.
    ///
    /// A change is API-applicable only when *nothing but* profile targets and
    /// manual group selections differ. Anything that alters the set of
    /// outbounds, inbounds, balancers or rules needs a restart, because those
    /// are fixed at load time.
    #[must_use]
    pub fn plan(&self, next: &DesiredState) -> ChangePlan {
        if &self.desired == next {
            return ChangePlan::NoChange;
        }

        // Structural comparison: everything except the mutable selections.
        let mut current_shape = self.desired.clone();
        let mut next_shape = next.clone();
        let mut selectors: Vec<(String, String)> = Vec::new();

        for (id, profile) in &mut next_shape.profiles {
            let Some(current) = current_shape.profiles.get_mut(id) else {
                return ChangePlan::Restart {
                    reason: format!("profile '{id}' was added"),
                };
            };
            if current.target != profile.target {
                // A target change is only cheap when the new target already has
                // a compiled outbound; a brand-new node needs the core reloaded.
                let tag = xraytui_xray_compiler::tag_for_target(&profile.target);
                if !self.tag_exists(&tag) {
                    return ChangePlan::Restart {
                        reason: format!(
                            "profile '{id}' now points at '{}', which has no compiled outbound yet",
                            profile.target.to_token()
                        ),
                    };
                }
                selectors.push((tags::profile_selector(id), tag));
            }
            // Normalise so the structural comparison ignores the target.
            current.target = profile.target.clone();
        }

        for (id, group) in &mut next_shape.groups {
            let Some(current) = current_shape.groups.get_mut(id) else {
                return ChangePlan::Restart {
                    reason: format!("group '{id}' was added"),
                };
            };
            if current.manual_selection != group.manual_selection {
                if let Some(selection) = &group.manual_selection {
                    let tag = xraytui_xray_compiler::tag_for_target(selection);
                    if !self.tag_exists(&tag) {
                        return ChangePlan::Restart {
                            reason: format!("group '{id}' selected an uncompiled target"),
                        };
                    }
                    selectors.push((tags::group_balancer(id), tag));
                }
                current.manual_selection = group.manual_selection.clone();
            }
        }

        if current_shape != next_shape {
            return ChangePlan::Restart {
                reason: describe_structural_change(&current_shape, &next_shape),
            };
        }
        if selectors.is_empty() {
            ChangePlan::NoChange
        } else {
            ChangePlan::Selectors(selectors)
        }
    }

    fn tag_exists(&self, tag: &str) -> bool {
        self.compiled
            .as_ref()
            .is_some_and(|c| c.owned_tags.contains(tag))
    }

    /// Replace the desired state, applying it in the cheapest correct way.
    ///
    /// # Errors
    /// Propagates compilation, validation and start failures. On a failed
    /// restart the previous generation is restored and
    /// [`ApplyOutcome::RolledBack`] is returned rather than an error, unless the
    /// rollback itself fails.
    pub async fn apply(&mut self, next: DesiredState) -> Result<ApplyOutcome, ControllerError> {
        match self.plan(&next) {
            ChangePlan::NoChange => {
                self.desired = next;
                Ok(ApplyOutcome::Unchanged)
            }
            ChangePlan::Selectors(selectors) => {
                let client = self
                    .client
                    .as_mut()
                    .ok_or(ControllerError::CoreNotRunning)?;
                let mut applied = Vec::new();
                for (balancer, target) in &selectors {
                    client.override_balancer(balancer, target).await?;
                    applied.push(balancer.clone());
                }
                self.desired = next;
                // Keep the compiled generation's override list in step, so a
                // later restart replays the *current* selection rather than the
                // one that was compiled in.
                if let Some(compiled) = self.compiled.as_mut() {
                    for (balancer, target) in selectors {
                        match compiled
                            .selector_overrides
                            .iter_mut()
                            .find(|(b, _)| b == &balancer)
                        {
                            Some(entry) => entry.1 = target,
                            None => compiled.selector_overrides.push((balancer, target)),
                        }
                    }
                }
                self.refresh_profile_runtime();
                Ok(ApplyOutcome::SwitchedSelectors { balancers: applied })
            }
            ChangePlan::Restart { reason } => {
                tracing::info!(reason = %reason, "restarting core to apply a structural change");
                let previous = self.desired.clone();
                self.desired = next;
                match self.rebuild_and_start().await {
                    Ok(generation) => {
                        self.consecutive_failures = 0;
                        Ok(ApplyOutcome::Restarted { generation })
                    }
                    Err(error) => {
                        tracing::warn!(%error, "new generation failed; rolling back");
                        let failed = self.generation;
                        self.desired = previous;
                        let restored = self.rebuild_and_start().await.map_err(|rollback| {
                            ControllerError::RollbackFailed {
                                generation: failed,
                                detail: rollback.to_string(),
                            }
                        })?;
                        Ok(ApplyOutcome::RolledBack { failed, restored })
                    }
                }
            }
        }
    }

    /// Compile, validate, start and health-gate the current desired state.
    ///
    /// # Errors
    /// Propagates every step's failure. The caller decides whether to roll back.
    pub async fn rebuild_and_start(&mut self) -> Result<GenerationId, ControllerError> {
        // The endpoint is the single source of truth for where the commander
        // lives. Compiling from a stale `CompileOptions::api_listen` would make
        // the core bind one address while the client dials another, which
        // presents as a start timeout rather than as a mismatch.
        let mut options = self.config.compile.clone();
        options.api_listen = self.config.api_endpoint.xray_listen();
        let compiled = compile(&self.desired, &options)?;
        let json = compiled.to_json()?;

        self.generation = self.generation.next();
        let generation = self.generation;
        self.runtime.core = CoreStatus::Starting { generation };

        // 1. Static validation. Necessary but not sufficient.
        core::validate_config(&self.info, &json, &self.config.generated_config).await?;

        // 2. Stop whatever is running before binding the same ports again.
        self.stop_core().await;

        // 3. Start.
        let spec = LaunchSpec {
            generation,
            config_path: self.config.generated_config.clone(),
            endpoint: self.config.api_endpoint.clone(),
            log_path: self.config.core_log.clone(),
        };
        let running = core::spawn(&self.info, &spec).await?;

        // 4. Health gate: API up, listeners accepting, overrides applied.
        let listeners: Vec<std::net::SocketAddr> = compiled
            .listeners
            .values()
            .flat_map(|l| l.socks.into_iter().chain(l.http))
            .collect();
        let gate = HealthGate {
            api_deadline: self.config.api_deadline,
            listeners,
            listener_timeout: self.config.listener_timeout,
            overrides: compiled.selector_overrides.clone(),
        };

        let (client, report) = match core::run_health_gate(&self.config.api_endpoint, &gate).await {
            Ok(result) => result,
            Err(error) => {
                self.running = Some(running);
                self.stop_core().await;
                self.runtime.core = CoreStatus::Failed {
                    reason: error.to_string(),
                };
                return Err(error);
            }
        };

        self.running = Some(running);
        self.client = Some(client);

        if !report.is_healthy() {
            let detail = report.describe();
            self.stop_core().await;
            self.runtime.core = CoreStatus::Failed {
                reason: detail.clone(),
            };
            return Err(ControllerError::Unhealthy { generation, detail });
        }

        // 5. Only now is the generation good enough to roll back to.
        let pid = self
            .running
            .as_ref()
            .and_then(RunningCore::pid)
            .unwrap_or_default();
        self.runtime.core = CoreStatus::Running {
            generation,
            pid,
            version: self.info.version.to_string(),
            since_unix: unix_now(),
        };
        self.runtime.generation = generation;
        self.runtime.last_known_good = Some(generation);
        self.runtime.mode = self.desired.mode;
        self.runtime.lan_exposed = self
            .desired
            .profiles
            .values()
            .flat_map(|p| p.listeners())
            .any(|l| l.is_exposed());
        self.runtime.warnings = compiled.warnings.clone();

        let _ =
            xraytui_config::write_private_atomic(&self.config.last_good_config, json.as_bytes());
        self.last_good = Some((generation, json));
        self.compiled = Some(compiled);
        self.refresh_profile_runtime();

        Ok(generation)
    }

    /// Change one profile's target through the API.
    ///
    /// This is the operation behind `xraytui profile set-target`. It touches
    /// exactly one balancer, so other profiles are provably unaffected.
    ///
    /// # Errors
    /// Returns [`ControllerError::NotFound`] for an unknown profile or target,
    /// and [`ControllerError::CoreNotRunning`] when there is no core.
    pub async fn set_profile_target(
        &mut self,
        profile: &ProfileId,
        target: Target,
    ) -> Result<ApplyOutcome, ControllerError> {
        if !self.desired.profiles.contains_key(profile) {
            return Err(ControllerError::NotFound(format!("no profile '{profile}'")));
        }
        let mut next = self.desired.clone();
        if let Some(entry) = next.profiles.get_mut(profile) {
            entry.target = target;
        }
        self.apply(next).await
    }

    /// Change a manual group's selection through the API.
    ///
    /// # Errors
    /// See [`Engine::set_profile_target`].
    pub async fn set_group_selection(
        &mut self,
        group: &GroupId,
        target: Target,
    ) -> Result<ApplyOutcome, ControllerError> {
        if !self.desired.groups.contains_key(group) {
            return Err(ControllerError::NotFound(format!("no group '{group}'")));
        }
        let mut next = self.desired.clone();
        if let Some(entry) = next.groups.get_mut(group) {
            entry.manual_selection = Some(target);
        }
        self.apply(next).await
    }

    /// Change the system mode, restarting only when the mode's topology differs.
    ///
    /// # Errors
    /// Propagates the restart failure.
    pub async fn set_mode(&mut self, mode: SystemMode) -> Result<ApplyOutcome, ControllerError> {
        let mut next = self.desired.clone();
        next.mode = mode;
        self.apply(next).await
    }

    /// Stop the core, leaving the desired state untouched.
    pub async fn stop_core(&mut self) {
        self.client = None;
        if let Some(mut running) = self.running.take() {
            let _ = running.shutdown(self.config.shutdown_grace).await;
        }
        if !matches!(self.runtime.core, CoreStatus::Failed { .. }) {
            self.runtime.core = CoreStatus::Stopped;
        }
    }

    /// Notice that the core exited and decide whether to restart it.
    ///
    /// Returns the delay before the next attempt, or `None` when the budget is
    /// exhausted and manual intervention is needed.
    pub fn note_core_exit(&mut self, reason: String) -> Option<Duration> {
        self.client = None;
        self.running = None;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if !self.config.restart.may_retry(self.consecutive_failures) {
            self.runtime.core = CoreStatus::Failed {
                reason: format!(
                    "{reason}; giving up after {} consecutive failures",
                    self.consecutive_failures
                ),
            };
            return None;
        }
        let delay = self.config.restart.delay(self.consecutive_failures);
        self.runtime.core = CoreStatus::Restarting {
            attempt: self.consecutive_failures,
            backoff_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            reason,
        };
        Some(delay)
    }

    /// Refresh traffic counters from the core.
    ///
    /// Counters are read in one `QueryStats` call and folded into the per-profile
    /// runtime, so the UI never triggers one RPC per profile.
    ///
    /// # Errors
    /// Propagates the gRPC failure.
    pub async fn refresh_statistics(&mut self) -> Result<(), ControllerError> {
        let Some(client) = self.client.as_mut() else {
            return Err(ControllerError::CoreNotRunning);
        };
        let stats = client.query_stats("", false).await?;
        let mut totals = TrafficCounters::default();
        let mut per_tag: BTreeMap<String, TrafficCounters> = BTreeMap::new();

        for (name, value) in &stats {
            let value = u64::try_from(*value).unwrap_or(0);
            let mut parts = name.split(">>>");
            let (Some(kind), Some(tag), Some(_), Some(direction)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if kind != "outbound" {
                continue;
            }
            let entry = per_tag.entry(tag.to_owned()).or_default();
            match direction {
                "uplink" => {
                    entry.uplink_bytes = value;
                    totals.uplink_bytes = totals.uplink_bytes.saturating_add(value);
                }
                "downlink" => {
                    entry.downlink_bytes = value;
                    totals.downlink_bytes = totals.downlink_bytes.saturating_add(value);
                }
                _ => {}
            }
        }

        self.runtime.total_traffic = totals;
        for profile in &mut self.runtime.profiles {
            if let Some(tag) = &profile.effective_outbound
                && let Some(counters) = per_tag.get(tag)
            {
                profile.traffic = *counters;
            }
        }
        Ok(())
    }

    /// Record a probe result against a node.
    pub fn record_node_health(
        &mut self,
        node: xraytui_domain::NodeId,
        result: xraytui_domain::ProbeResult,
    ) {
        self.runtime
            .node_health
            .entry(node)
            .or_default()
            .record(result);
        self.refresh_profile_runtime();
    }

    /// Install health that was observed before this process started.
    ///
    /// `or_insert` rather than overwrite: a probe that has already run in this
    /// process is newer than anything the database can offer, and restoring
    /// history must never move a node's health backwards.
    pub fn seed_node_health(
        &mut self,
        history: impl IntoIterator<Item = (xraytui_domain::NodeId, xraytui_domain::HealthRecord)>,
    ) {
        for (node, record) in history {
            self.runtime.node_health.entry(node).or_insert(record);
        }
        self.refresh_profile_runtime();
    }

    /// Rebuild the per-profile view of runtime state from desired + health.
    fn refresh_profile_runtime(&mut self) {
        let listeners = self
            .compiled
            .as_ref()
            .map(|c| c.listeners.clone())
            .unwrap_or_default();
        self.runtime.profiles = self
            .desired
            .profiles
            .iter()
            .filter(|(_, profile)| profile.enabled)
            .map(|(id, profile)| {
                let bound = listeners.get(id);
                let effective = xraytui_xray_compiler::tag_for_target(&profile.target);
                let health = self
                    .desired
                    .resolve_target_nodes(&profile.target)
                    .iter()
                    .filter_map(|node| self.runtime.node_health.get(node))
                    .max_by_key(|record| record.ema_latency_ms.unwrap_or(u32::MAX))
                    .cloned()
                    .unwrap_or_default();
                ProfileRuntime {
                    id: id.clone(),
                    target: profile.target.clone(),
                    effective_outbound: Some(effective),
                    health,
                    traffic: self
                        .runtime
                        .profiles
                        .iter()
                        .find(|p| &p.id == id)
                        .map(|p| p.traffic)
                        .unwrap_or_default(),
                    socks_listen: bound.and_then(|l| l.socks).map(|a| a.to_string()),
                    http_listen: bound.and_then(|l| l.http).map(|a| a.to_string()),
                    listeners_healthy: true,
                }
            })
            .collect();
    }

    /// A borrowed API client, for callers that need a raw RPC.
    #[must_use]
    pub fn client(&mut self) -> Option<&mut ApiClient> {
        self.client.as_mut()
    }
}

fn describe_structural_change(current: &DesiredState, next: &DesiredState) -> String {
    let mut reasons = Vec::new();
    if current.nodes.len() != next.nodes.len() {
        reasons.push(format!(
            "nodes {} -> {}",
            current.nodes.len(),
            next.nodes.len()
        ));
    }
    if current.profiles.len() != next.profiles.len() {
        reasons.push(format!(
            "profiles {} -> {}",
            current.profiles.len(),
            next.profiles.len()
        ));
    }
    if current.groups != next.groups {
        reasons.push("groups changed".to_owned());
    }
    if current.chains != next.chains {
        reasons.push("chains changed".to_owned());
    }
    if current.app_rules != next.app_rules {
        reasons.push("application rules changed".to_owned());
    }
    if current.routing_rules != next.routing_rules {
        reasons.push("routing rules changed".to_owned());
    }
    if current.mode != next.mode {
        reasons.push(format!("mode {} -> {}", current.mode, next.mode));
    }
    if reasons.is_empty() {
        reasons.push("listener or profile settings changed".to_owned());
    }
    reasons.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{
        EgressProfile, Endpoint, ListenerSpec, Node, NodeId, NodeSource, ProtocolSettings,
        SocksSettings,
    };

    fn info() -> CoreInfo {
        CoreInfo {
            binary: PathBuf::from("/usr/bin/xray"),
            version: Version {
                major: 26,
                minor: 3,
                patch: 27,
            },
            banner: "Xray 26.3.27".into(),
            asset_dir: None,
            has_geodata: false,
        }
    }

    fn node(id: &str) -> Node {
        Node::new(
            NodeId::new(id).unwrap_or_else(|_| NodeId::from_text(id)),
            id,
            NodeSource::Manual,
            Endpoint::new("127.0.0.1", 1080),
            ProtocolSettings::Socks(SocksSettings {
                username: None,
                password: None,
                udp: false,
            }),
        )
    }

    /// An engine whose "compiled" generation matches `state`, without a core.
    fn engine_with(state: DesiredState) -> Engine {
        let mut engine = Engine::new(EngineConfig::default(), info())
            .unwrap_or_else(|_| unreachable!("the fixture version is above the minimum"));
        let compiled = compile(&state, &engine.config.compile)
            .unwrap_or_else(|_| unreachable!("the fixture state is valid"));
        engine.compiled = Some(compiled);
        engine.desired = state;
        engine
    }

    fn two_profile_state() -> DesiredState {
        let mut state = DesiredState::default();
        for id in ["a", "b", "c"] {
            let n = node(id);
            state.nodes.insert(n.id.clone(), n);
        }
        for (id, target, port) in [("web", "a", 11080_u16), ("development", "b", 12080)] {
            let pid = ProfileId::new(id).unwrap_or_else(|_| ProfileId::from_text(id));
            let mut profile = EgressProfile::new(
                pid.clone(),
                id,
                Target::Node {
                    id: NodeId::new(target).unwrap_or_else(|_| NodeId::from_text(target)),
                },
            );
            profile.socks = Some(ListenerSpec::loopback(port));
            state.profiles.insert(pid, profile);
        }
        state
    }

    #[test]
    fn an_identical_state_needs_no_work() {
        let state = two_profile_state();
        let engine = engine_with(state.clone());
        assert_eq!(engine.plan(&state), ChangePlan::NoChange);
    }

    #[test]
    fn a_target_change_is_an_api_operation() {
        let state = two_profile_state();
        let engine = engine_with(state.clone());

        let mut next = state;
        if let Some(profile) = next.profiles.get_mut(&ProfileId::from_text("development")) {
            profile.target = Target::Node {
                id: NodeId::from_text("c"),
            };
        }

        match engine.plan(&next) {
            ChangePlan::Selectors(selectors) => {
                assert_eq!(
                    selectors,
                    vec![(
                        "profile/development/selector".to_owned(),
                        "node/c/out".to_owned()
                    )]
                );
            }
            other => panic!("expected an API switch, got {other:?}"),
        }
    }

    #[test]
    fn switching_one_profile_does_not_mention_the_other() {
        let state = two_profile_state();
        let engine = engine_with(state.clone());
        let mut next = state;
        if let Some(profile) = next.profiles.get_mut(&ProfileId::from_text("web")) {
            profile.target = Target::Direct;
        }
        match engine.plan(&next) {
            ChangePlan::Selectors(selectors) => {
                assert_eq!(selectors.len(), 1);
                assert!(
                    selectors.iter().all(|(b, _)| b.contains("/web/")),
                    "{selectors:?}"
                );
            }
            other => panic!("expected an API switch, got {other:?}"),
        }
    }

    #[test]
    fn pointing_at_an_uncompiled_target_forces_a_restart() {
        let state = two_profile_state();
        let engine = engine_with(state.clone());
        let mut next = state;
        let new_node = node("brand-new");
        next.nodes.insert(new_node.id.clone(), new_node);
        if let Some(profile) = next.profiles.get_mut(&ProfileId::from_text("web")) {
            profile.target = Target::Node {
                id: NodeId::from_text("brand-new"),
            };
        }
        assert!(
            engine.plan(&next).is_disruptive(),
            "{:?}",
            engine.plan(&next)
        );
    }

    #[test]
    fn structural_changes_force_a_restart_with_a_reason() {
        let state = two_profile_state();
        let engine = engine_with(state.clone());

        // Adding a listener changes the inbound set.
        let mut next = state.clone();
        if let Some(profile) = next.profiles.get_mut(&ProfileId::from_text("web")) {
            profile.http = Some(ListenerSpec::loopback(11081));
        }
        assert!(engine.plan(&next).is_disruptive());

        // Adding a profile changes the balancer set.
        let mut next = state.clone();
        let pid = ProfileId::from_text("chat");
        next.profiles
            .insert(pid.clone(), EgressProfile::new(pid, "chat", Target::Direct));
        match engine.plan(&next) {
            ChangePlan::Restart { reason } => assert!(reason.contains("chat"), "{reason}"),
            other => panic!("expected a restart, got {other:?}"),
        }

        // Changing the mode changes the fallback rule.
        let mut next = state;
        next.mode = SystemMode::Direct;
        assert!(engine.plan(&next).is_disruptive());
    }

    #[test]
    fn removing_a_node_forces_a_restart() {
        let state = two_profile_state();
        let engine = engine_with(state.clone());
        let mut next = state;
        next.nodes.remove(&NodeId::from_text("c"));
        assert!(engine.plan(&next).is_disruptive());
    }

    #[test]
    fn a_group_selection_change_is_an_api_operation() {
        let mut state = two_profile_state();
        let gid = GroupId::from_text("g");
        state.groups.insert(
            gid.clone(),
            xraytui_domain::Group {
                id: gid.clone(),
                name: "G".into(),
                strategy: xraytui_domain::GroupStrategy::Manual,
                membership: xraytui_domain::GroupMembership {
                    nodes: vec![NodeId::from_text("a"), NodeId::from_text("b")],
                    ..Default::default()
                },
                manual_selection: Some(Target::Node {
                    id: NodeId::from_text("a"),
                }),
                fallback: None,
            },
        );
        let engine = engine_with(state.clone());

        let mut next = state;
        if let Some(group) = next.groups.get_mut(&gid) {
            group.manual_selection = Some(Target::Node {
                id: NodeId::from_text("b"),
            });
        }
        match engine.plan(&next) {
            ChangePlan::Selectors(selectors) => {
                assert_eq!(
                    selectors,
                    vec![("group/g/balancer".to_owned(), "node/b/out".to_owned())]
                );
            }
            other => panic!("expected an API switch, got {other:?}"),
        }
    }

    #[test]
    fn too_old_a_core_is_refused_at_construction() {
        let mut old = info();
        old.version = Version {
            major: 1,
            minor: 7,
            patch: 0,
        };
        let error = Engine::new(EngineConfig::default(), old).expect_err("must refuse");
        assert!(
            matches!(error, ControllerError::CoreTooOld { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn restart_budget_is_enforced() {
        let mut engine = engine_with(two_profile_state());
        engine.config.restart = RestartPolicy {
            min: Duration::from_millis(10),
            max: Duration::from_millis(100),
            budget: 3,
        };
        assert!(engine.note_core_exit("crash".into()).is_some());
        assert!(engine.note_core_exit("crash".into()).is_some());
        assert!(engine.note_core_exit("crash".into()).is_none());
        assert!(matches!(engine.runtime().core, CoreStatus::Failed { .. }));
    }
}
