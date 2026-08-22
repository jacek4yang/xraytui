//! The daemon: engine plus control socket.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, broadcast};
use xraytui_config::{ConfigFile, Paths};
use xraytui_controller::{ApplyOutcome, Engine, EngineConfig};
use xraytui_domain::{DesiredState, Severity, SystemMode, Target};
use xraytui_ipc::{
    CheckStatus, DoctorCheck, DoctorReport, Event, ImportOrigin, IpcError, PeerCredentials,
    Request, Response, ServerHandler, SubscriptionFilter, TestTarget,
};
use xraytui_xray_api::ApiEndpoint;
use xraytui_xray_compiler::{DnsOptions, SniffingOptions, TunOptions};

/// The running daemon.
pub struct Daemon {
    paths: Paths,
    config: ConfigFile,
    engine: Arc<Mutex<Engine>>,
    events: broadcast::Sender<Event>,
    started: std::time::Instant,
    shutdown: Arc<tokio::sync::Notify>,
    /// The daemon's side of the privilege boundary. Present whether or not a
    /// helper is installed; asking it is how the daemon finds out.
    netd: Arc<crate::netd::Netd>,
    /// The periodic worker: health probes and subscription updates.
    sweeper: Arc<crate::sweeper::Sweeper>,
    /// Durable runtime state. `None` only when the database could not be
    /// opened, which is a warning rather than a failure: xraytui works without
    /// history, it just forgets more than it should.
    store: Option<Arc<xraytui_state_store::StateStore>>,
}

/// Probe history older than this is dropped when the daemon starts.
///
/// Thirty days: long enough to see that a provider has been unreliable for a
/// month, short enough that the database does not grow without bound on a
/// machine that is never reinstalled.
const HISTORY_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

/// How often the daemon checks whether the core is still alive.
///
/// Half a second: fast enough that a user pressing a key sees the truth, and
/// the cost is one non-blocking `waitpid` per tick, which does not wake a
/// sleeping laptop in any way tokio's timer was not already going to.
const CORE_POLL_INTERVAL: Duration = Duration::from_millis(500);

impl Daemon {
    /// Build a daemon: discover the core, construct the engine, seed the state.
    ///
    /// # Errors
    /// Fails when no usable Xray binary is present, since without one nothing
    /// the daemon offers would work.
    pub async fn new(paths: Paths, config: ConfigFile, state: DesiredState) -> Result<Self> {
        let binary = xraytui_controller::discover_binary(&config.core.binary)
            .context("cannot find an Xray-core binary")?;
        let info = xraytui_controller::probe_binary(&binary, config.core.asset_dir.as_deref())
            .await
            .context("cannot run the Xray-core binary")?;
        tracing::info!(version = %info.version, binary = %info.binary.display(), "using Xray-core");
        if !info.has_geodata {
            tracing::warn!(
                "no geoip.dat/geosite.dat found; geosite: and geoip: rules will fail to load"
            );
        }

        let engine_config = build_engine_config(&paths, &config, &state);
        let mut engine = Engine::new(engine_config, info).context("unsupported Xray-core")?;
        engine
            .seed(state)
            .context("cannot seed the desired state")?;

        // Opening the store is not allowed to stop the daemon: a corrupt or
        // unreadable history is a reason to lose history, not the proxy.
        let store = match xraytui_state_store::StateStore::open(paths.state_db()) {
            Ok(store) => {
                let cutoff = xraytui_linux_net::lease::now().saturating_sub(HISTORY_MAX_AGE_SECS);
                if let Err(error) = store.prune(cutoff) {
                    tracing::warn!(%error, "cannot prune the state database");
                }
                Some(Arc::new(store))
            }
            Err(error) => {
                tracing::warn!(%error, "continuing without durable runtime state");
                None
            }
        };

        // What the daemon knew before it restarted. Mode, targets and rules
        // came back with the policy files, which is where they belong; health
        // is the part that is observed rather than configured, so it comes from
        // here — otherwise every restart would report a failing node as untested
        // and route traffic back into it.
        if let Some(store) = &store {
            match store.node_health() {
                Ok(history) if !history.is_empty() => {
                    let count = history.len();
                    engine.seed_node_health(history);
                    tracing::info!(nodes = count, "restored health history");
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "cannot read health history"),
            }
            match store.recover() {
                Ok(recovered) => {
                    if let Some(interrupted) = &recovered.interrupted {
                        tracing::warn!(
                            operation = %interrupted.operation,
                            detail = %interrupted.detail,
                            "a previous operation did not finish"
                        );
                    }
                    tracing::debug!(
                        mode = ?recovered.mode,
                        last_known_good = ?recovered.last_known_good,
                        profiles = recovered.profile_targets.len(),
                        "recovered durable state"
                    );
                }
                Err(error) => tracing::warn!(%error, "cannot read durable state"),
            }
        }

        let (events, _) = xraytui_ipc::server::event_channel();
        Ok(Self {
            store,
            netd: Arc::new(crate::netd::Netd::new(std::path::PathBuf::from(
                xraytui_netd_protocol::DEFAULT_SOCKET,
            ))),
            sweeper: Arc::new(crate::sweeper::Sweeper::new()),
            paths,
            config,
            engine: Arc::new(Mutex::new(engine)),
            events,
            started: std::time::Instant::now(),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Serve until a shutdown signal arrives.
    ///
    /// # Errors
    /// Propagates socket binding failures.
    pub async fn run(self, start_core: bool) -> Result<()> {
        let socket = self.paths.control_socket();
        let server = xraytui_ipc::listen(&socket)
            .with_context(|| format!("cannot bind {}", socket.display()))?;
        tracing::info!(socket = %socket.display(), "control socket ready");

        if start_core && self.config.runtime.start_core_on_launch {
            let mut engine = self.engine.lock().await;
            match engine.rebuild_and_start().await {
                Ok(generation) => tracing::info!(%generation, "core started"),
                Err(error) => tracing::error!(%error, "core did not start; continuing idle"),
            }
        }

        let shutdown = Arc::clone(&self.shutdown);
        let signal = async move {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(signal) => signal,
                    Err(error) => {
                        tracing::error!(%error, "cannot install the SIGTERM handler");
                        return;
                    }
                };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
                _ = sigterm.recv() => tracing::info!("terminated"),
                () = shutdown.notified() => tracing::info!("shutdown requested"),
            }
        };

        let engine = Arc::clone(&self.engine);
        let netd = Arc::clone(&self.netd);
        let lease_ttl = self.config.runtime.netd_lease_ttl_secs;
        let handler = Arc::new(self);
        let broadcaster = Arc::clone(&handler);
        let ticker = tokio::spawn(async move { broadcaster.broadcast_state_periodically().await });
        let sweeper_task = tokio::spawn({
            let handler = Arc::clone(&handler);
            async move {
                let mut interval = tokio::time::interval(crate::sweeper::TICK);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    handler.sweep().await;
                }
            }
        });

        let heartbeat = tokio::spawn({
            let netd = Arc::clone(&netd);
            let engine = Arc::clone(&engine);
            async move {
                let mut interval =
                    tokio::time::interval(crate::netd::heartbeat_interval(lease_ttl));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    if !netd.is_active().await {
                        continue;
                    }
                    let generation = engine.lock().await.runtime().generation.0;
                    netd.heartbeat(generation).await;
                }
            }
        });

        let supervisor = tokio::spawn({
            let handler = Arc::clone(&handler);
            async move { handler.supervise_core().await }
        });

        server.serve(Arc::clone(&handler), signal).await;
        supervisor.abort();
        ticker.abort();
        heartbeat.abort();
        sweeper_task.abort();

        // Order matters on the way out: give the machine's networking back
        // before stopping the core, so there is never a window where the
        // default route points at a tunnel with nothing behind it.
        tracing::info!("releasing any system tunnel");
        netd.release().await;
        tracing::info!("stopping the core");
        engine.lock().await.stop_core().await;
        Ok(())
    }

    /// Push a runtime snapshot to subscribers, and refresh counters.
    async fn broadcast_state_periodically(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            // Skip the work entirely when nobody is listening: an idle daemon on
            // a laptop should not wake up to serialise state nobody reads.
            if self.events.receiver_count() == 0 {
                continue;
            }
            let mut engine = self.engine.lock().await;
            let _ = engine.refresh_statistics().await;
            let snapshot = engine.runtime().clone();
            drop(engine);
            let _ = self.events.send(Event::State(Box::new(snapshot)));
        }
    }

    /// Persist the desired state to the policy files.
    async fn persist(&self) -> Result<(), IpcError> {
        let engine = self.engine.lock().await;
        xraytui_config::store::save(&self.paths, engine.desired())
            .map_err(|error| IpcError::Internal(error.to_string()))
    }

    /// Notice a core that has died, and bring it back.
    ///
    /// Without this the daemon reports a healthy core forever after the OOM
    /// killer takes Xray: `running` still holds a `Child` whose process is
    /// gone, every listener is dead, and nothing says so. The engine already
    /// knew how to count failures and back off; nothing was calling it.
    ///
    /// Polling rather than awaiting the child: the engine owns the `Child`
    /// behind the same mutex that serves every request, and a task holding that
    /// lock across an await which only completes when the core dies would
    /// deadlock the daemon.
    async fn supervise_core(&self) {
        let mut interval = tokio::time::interval(CORE_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;

            let Some(reason) = self.engine.lock().await.poll_core_exit() else {
                continue;
            };
            tracing::warn!(%reason, "the core exited on its own");

            let Some(delay) = self.engine.lock().await.note_core_exit(reason) else {
                tracing::error!(
                    "not restarting the core again; run `xraytui logs`, then \
                     `xraytui restart` once the cause is fixed"
                );
                self.announce().await;
                continue;
            };
            self.announce().await;

            // The lock is deliberately not held across the backoff: somebody
            // asking for status during a restart storm should get an answer.
            tokio::time::sleep(delay).await;

            let mut engine = self.engine.lock().await;
            match engine.restart_after_exit().await {
                Ok(generation) => {
                    tracing::info!(%generation, "the core was restarted after it exited");
                    if let Some(store) = &self.store {
                        let _ = store
                            .record_last_known_good(generation, xraytui_linux_net::lease::now());
                    }
                }
                Err(error) => tracing::warn!(%error, "the core did not come back"),
            }
            drop(engine);
            self.announce().await;
        }
    }

    /// Push the current runtime to subscribers immediately.
    ///
    /// The periodic broadcast is on a one-second timer and skips when nobody is
    /// listening; a core dying is worth telling an attached interface about at
    /// the moment it happens.
    async fn announce(&self) {
        if self.events.receiver_count() == 0 {
            return;
        }
        let snapshot = self.engine.lock().await.runtime().clone();
        let _ = self.events.send(Event::State(Box::new(snapshot)));
    }

    /// Write the observed half of the state to the durable store.
    ///
    /// Policy has already gone to TOML by this point; what is recorded here is
    /// what the daemon would otherwise have to guess after a restart. Failures
    /// are logged and swallowed: a database that cannot be written is a reason
    /// to forget, not a reason to refuse a change the user asked for.
    async fn remember(&self, desired: &DesiredState) {
        let Some(store) = &self.store else {
            return;
        };
        let now = xraytui_linux_net::lease::now();
        if let Err(error) = store.record_mode(desired.mode, self.netd.is_active().await) {
            tracing::warn!(%error, "cannot record the mode");
        }
        for (id, profile) in &desired.profiles {
            if let Err(error) =
                store.record_profile_target(id.as_str(), &profile.target.to_token(), now)
            {
                tracing::warn!(%error, profile = %id, "cannot record the profile target");
            }
        }
        let engine = self.engine.lock().await;
        if let Some(generation) = engine.runtime().last_known_good {
            drop(engine);
            if let Err(error) = store.record_last_known_good(generation, now) {
                tracing::warn!(%error, "cannot record the last known good generation");
            }
        }
    }

    async fn apply(&self, state: DesiredState) -> Result<Response, IpcError> {
        // A mode that needs a system tunnel is refused up front when no helper
        // can grant one. Starting a core whose TUN inbound nothing routes to
        // would report success and carry no traffic, which is the worst of the
        // available outcomes.
        if state.mode.needs_tun() && !self.netd.available().await {
            return Err(IpcError::Invalid(format!(
                "{} mode needs the privileged helper at {}, which is not running.                  Start it with `sudo systemctl enable --now xraytui-netd.service`, or keep                  mode off and use each profile's SOCKS and HTTP listeners, which need no                  privileges.",
                state.mode.as_str(),
                self.netd.socket().display()
            )));
        }

        let mut engine = self.engine.lock().await;
        let outcome = engine
            .apply(state)
            .await
            .map_err(|error| IpcError::Internal(error.to_string()))?;
        let warnings = engine
            .compiled()
            .map(|c| c.warnings.clone())
            .unwrap_or_default();
        let desired = engine.desired().clone();
        drop(engine);
        self.persist().await?;
        self.remember(&desired).await;
        self.sweeper
            .reconcile(&self.config, &desired, xraytui_linux_net::lease::now())
            .await;
        self.reconcile_tunnel(&desired).await?;
        Ok(response_for(outcome, warnings))
    }

    /// Make the machine's networking match the mode that was just applied.
    ///
    /// Called after every desired-state change, so switching profiles or
    /// editing rules re-applies the routing that depends on them, and switching
    /// the mode off gives the tunnel back immediately rather than waiting for a
    /// lease to lapse.
    async fn reconcile_tunnel(&self, state: &DesiredState) -> Result<(), IpcError> {
        if !state.mode.needs_tun() {
            self.netd.release().await;
            return Ok(());
        }
        let request = crate::netd::plan_request(&self.config, state, self.proxy_endpoints(state))
            .map_err(|error| IpcError::Invalid(error.to_string()))?;
        match self.netd.establish(&request).await {
            Ok(interface) => {
                tracing::info!(interface, mode = state.mode.as_str(), "system tunnel is up");
                Ok(())
            }
            Err(error) => {
                // The mode is on but the tunnel is not; say so rather than
                // leaving the user to discover it from a traffic counter.
                tracing::error!(%error, "the system tunnel could not be brought up");
                Err(IpcError::Invalid(error.to_string()))
            }
        }
    }

    /// Addresses the core must be able to reach without going through itself.
    ///
    /// Only literal addresses are collected: a hostname would have to be
    /// resolved, and resolving it *here* — before the tunnel is up, with the
    /// resolver about to change — is exactly when the answer is least
    /// trustworthy. A node addressed by name is handled by the core's own
    /// `direct` outbound and the private-network bypass.
    fn proxy_endpoints(&self, state: &DesiredState) -> Vec<std::net::IpAddr> {
        let mut out: Vec<std::net::IpAddr> = state
            .nodes
            .values()
            .filter_map(|node| node.endpoint.address.parse().ok())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Run whatever the schedule says is due.
    ///
    /// Failures are recorded rather than propagated: a node that cannot be
    /// reached is exactly what a probe is for, and a provider that is down
    /// should back off rather than fill the log.
    async fn sweep(&self) {
        let now = xraytui_linux_net::lease::now();
        let done = self
            .sweeper
            .tick(now, |job: crate::sweeper::Job| async move {
                match job {
                crate::sweeper::Job::ProbeNode(id) => {
                    match self.test(TestTarget::Node(id.clone())).await {
                        Ok(_) => true,
                        Err(error) => {
                            tracing::debug!(node = %id, %error, "scheduled probe failed");
                            false
                        }
                    }
                }
                crate::sweeper::Job::UpdateSubscription(id) => {
                    match self.subscription_update(std::slice::from_ref(&id)).await {
                        Ok(_) => true,
                        Err(error) => {
                            tracing::warn!(subscription = %id, %error, "scheduled update failed");
                            false
                        }
                    }
                }
                }
            })
            .await;
        if !done.is_empty() {
            let keys: Vec<String> = done.iter().map(crate::sweeper::Job::key).collect();
            tracing::debug!(jobs = ?keys, "scheduled work finished");
        }
    }

    /// Fetch a subscription and describe what an update would do.
    ///
    /// Changes nothing. The same function produces the diff that
    /// [`Daemon::subscription_update`] applies, so a preview cannot disagree
    /// with the thing it previews.
    async fn subscription_diff(
        &self,
        id: &xraytui_domain::SubscriptionId,
    ) -> Result<xraytui_domain::SubscriptionDiff, IpcError> {
        let (subscription, state) = {
            let engine = self.engine.lock().await;
            let desired = engine.desired();
            let subscription =
                desired
                    .subscriptions
                    .get(id)
                    .cloned()
                    .ok_or_else(|| IpcError::NotFound {
                        kind: "subscription".into(),
                        id: id.to_string(),
                    })?;
            (subscription, desired.clone())
        };

        let options = self.fetch_options(&subscription).await;
        let fetched = xraytui_subscription::fetch(&subscription.url, &subscription.meta, &options)
            .await
            .map_err(|error| IpcError::Internal(error.to_string()))?;

        let (body, meta) = match fetched {
            xraytui_subscription::Fetched::Unchanged => {
                // Nothing to compare against; an empty diff is the honest answer
                // and costs the provider nothing.
                return Ok(xraytui_domain::SubscriptionDiff {
                    changes: Vec::new(),
                    meta: subscription.meta.clone(),
                    deduplicated: 0,
                    filtered_out: 0,
                });
            }
            xraytui_subscription::Fetched::Body { text, meta } => (text, meta),
        };

        let normalised = xraytui_subscription::normalise(&subscription, &body)
            .map_err(|error| IpcError::Invalid(error.to_string()))?;
        Ok(xraytui_subscription::compute(id, &state, &normalised, meta))
    }

    /// Update one or more subscriptions, each transactionally.
    ///
    /// Every subscription is applied on its own: one provider being down, or
    /// sending something that would empty a user's node list, must not stop the
    /// others from updating.
    async fn subscription_update(
        &self,
        ids: &[xraytui_domain::SubscriptionId],
    ) -> Result<Response, IpcError> {
        let mut warnings = Vec::new();
        let mut applied = 0usize;

        for id in ids {
            let diff = match self.subscription_diff(id).await {
                Ok(diff) => diff,
                Err(error) => {
                    warnings.push(format!("{id}: {error}"));
                    continue;
                }
            };
            if diff.changes.is_empty() {
                continue;
            }

            let (state, subscription) = {
                let engine = self.engine.lock().await;
                let desired = engine.desired().clone();
                let Some(subscription) = desired.subscriptions.get(id).cloned() else {
                    continue;
                };
                (desired, subscription)
            };

            match xraytui_subscription::apply(
                &state,
                &subscription,
                &diff,
                xraytui_subscription::apply::ApplyOptions::default(),
            ) {
                Ok((next, outcome)) => {
                    warnings.extend(outcome.warnings.iter().map(|w| format!("{id}: {w}")));
                    // The engine decides whether this needs a restart or a
                    // handful of API calls, exactly as any other state change
                    // does.
                    self.apply(next).await?;
                    applied += 1;
                    tracing::info!(
                        subscription = %id,
                        added = outcome.added,
                        changed = outcome.changed,
                        removed = outcome.removed,
                        "subscription updated"
                    );
                }
                Err(error) => warnings.push(format!("{id}: {error}")),
            }
        }

        Ok(Response::Applied {
            rolled_back: false,
            restarted: applied > 0,
            switched: Vec::new(),
            warnings,
        })
    }

    /// Build the fetch options for a subscription, resolving `fetch_via_profile`.
    ///
    /// Fetching through a profile is how a user reaches a provider their network
    /// blocks. The profile is resolved to its **own loopback SOCKS listener**,
    /// which is the only address that can appear here — never a remote proxy
    /// somebody could put in a configuration file.
    async fn fetch_options(
        &self,
        subscription: &xraytui_domain::Subscription,
    ) -> xraytui_subscription::FetchOptions {
        let mut options = xraytui_subscription::FetchOptions::for_subscription(subscription);
        options.timeout = Duration::from_millis(self.config.subscription.timeout_ms);
        options.max_bytes = options
            .max_bytes
            .min(self.config.subscription.max_response_bytes);

        if let Some(profile) = &subscription.fetch_via_profile {
            let engine = self.engine.lock().await;
            let listener = engine
                .runtime()
                .profiles
                .iter()
                .find(|entry| entry.id == *profile)
                .and_then(|entry| entry.socks_listen.clone());
            match listener {
                Some(address) => options.proxy = Some(format!("socks5h://{address}")),
                None => tracing::warn!(
                    %profile,
                    "this subscription asks to be fetched through a profile with no \
                     running SOCKS listener; fetching directly instead"
                ),
            }
        }
        options
    }

    async fn doctor(&self) -> DoctorReport {
        let mut checks = Vec::new();
        let engine = self.engine.lock().await;
        let info = engine.core_info().clone();
        let runtime = engine.runtime().clone();
        drop(engine);

        checks.push(DoctorCheck {
            name: "xray-binary".into(),
            status: CheckStatus::Pass,
            detail: format!("{} ({})", info.binary.display(), info.version),
            remedy: None,
        });
        checks.push(DoctorCheck {
            name: "xray-geodata".into(),
            status: if info.has_geodata {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: match &info.asset_dir {
                Some(dir) if info.has_geodata => {
                    format!("geoip.dat and geosite.dat in {}", dir.display())
                }
                Some(dir) => format!("incomplete geodata in {}", dir.display()),
                None => "no geodata directory found".into(),
            },
            remedy: (!info.has_geodata).then(|| {
                "install xray-geoip and xray-geosite, or set [core] asset_dir; without them \
                 geosite: and geoip: rules cannot load"
                    .to_owned()
            }),
        });
        checks.push(DoctorCheck {
            name: "core".into(),
            status: if runtime.core.is_usable() {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: runtime.core.label().to_owned(),
            remedy: (!runtime.core.is_usable())
                .then(|| "run `xraytui up`, then check `xraytui logs`".to_owned()),
        });
        checks.push(DoctorCheck {
            name: "control-socket".into(),
            status: CheckStatus::Pass,
            detail: self.paths.control_socket().display().to_string(),
            remedy: None,
        });

        // TUN prerequisites, reported honestly rather than assumed.
        let tun_device = std::path::Path::new("/dev/net/tun");
        let (tun_status, tun_detail) = if !tun_device.exists() {
            (CheckStatus::Fail, "/dev/net/tun does not exist".to_owned())
        } else {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(tun_device)
            {
                Ok(_) => (CheckStatus::Pass, "/dev/net/tun is openable".to_owned()),
                Err(error) => (
                    CheckStatus::Warn,
                    format!("/dev/net/tun exists but cannot be opened: {}", error.kind()),
                ),
            }
        };
        checks.push(DoctorCheck {
            name: "tun-device".into(),
            status: tun_status,
            detail: tun_detail,
            remedy: (tun_status != CheckStatus::Pass).then(|| {
                "load the `tun` module (modprobe tun) and make sure /dev/net/tun is mode 0666, \
                 which is the systemd default"
                    .to_owned()
            }),
        });

        let ipv6_tun = xraytui_linux_net::capabilities::ipv6_tun_available();
        checks.push(DoctorCheck {
            name: "kernel-ipv6".into(),
            status: if ipv6_tun {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: if ipv6_tun {
                "IPv6 is enabled for newly created TUN interfaces".into()
            } else {
                "IPv6 TUN routing is unavailable because the host kernel or this network namespace has IPv6 disabled; IPv4 remains available".into()
            },
            remedy: (!ipv6_tun).then(|| {
                "check /proc/net/if_inet6 and /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6; IPv6 stays fail-closed until enabled"
                    .to_owned()
            }),
        });

        let socket = self.netd.socket().to_path_buf();
        let reachable = self.netd.available().await;
        let held = self.netd.interface().await;
        checks.push(DoctorCheck {
            name: "netd".into(),
            status: if reachable {
                CheckStatus::Pass
            } else {
                // Not a failure: SOCKS and HTTP listeners work without it, and
                // that is the mode most people use.
                CheckStatus::Warn
            },
            detail: match (reachable, &held) {
                (true, Some(interface)) => {
                    format!("the helper is running and holds {interface}")
                }
                (true, None) => format!("the helper is running at {}", socket.display()),
                (false, _) => format!(
                    "no helper at {}; system TUN modes and `exec --transparent` are unavailable",
                    socket.display()
                ),
            },
            remedy: (!reachable)
                .then(|| "sudo systemctl enable --now xraytui-netd.service".to_owned()),
        });

        let scheduled = self.sweeper.len().await;
        let next = self.sweeper.next_due().await;
        checks.push(DoctorCheck {
            name: "scheduler".into(),
            status: CheckStatus::Pass,
            detail: match (scheduled, next) {
                (0, _) => "nothing is scheduled; probes and subscription updates run on \
                           demand only"
                    .to_owned(),
                (count, Some(at)) => {
                    let now = xraytui_linux_net::lease::now();
                    format!("{count} scheduled; next in {}s", at.saturating_sub(now))
                }
                (count, None) => format!("{count} scheduled"),
            },
            remedy: None,
        });

        checks.push(DoctorCheck {
            name: "cgroup-v2".into(),
            status: if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: "required by `xraytui exec --transparent`".into(),
            remedy: None,
        });

        checks.push(DoctorCheck {
            name: "lan-exposure".into(),
            status: if runtime.lan_exposed {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            detail: if runtime.lan_exposed {
                "a proxy listener is bound to a non-loopback address".into()
            } else {
                "all listeners are loopback-only".into()
            },
            remedy: runtime
                .lan_exposed
                .then(|| "set [core] lan_access = false unless this is deliberate".to_owned()),
        });

        DoctorReport { checks }
    }
}

fn response_for(outcome: ApplyOutcome, warnings: Vec<String>) -> Response {
    let rolled_back = matches!(outcome, ApplyOutcome::RolledBack { .. });
    match outcome {
        ApplyOutcome::Unchanged => {
            Response::Applied { rolled_back, restarted: false, switched: Vec::new(), warnings }
        }
        ApplyOutcome::SwitchedSelectors { balancers } => {
            Response::Applied { rolled_back, restarted: false, switched: balancers, warnings }
        }
        ApplyOutcome::Restarted { .. } => {
            Response::Applied { rolled_back, restarted: true, switched: Vec::new(), warnings }
        }
        ApplyOutcome::RolledBack { failed, .. } => Response::Applied {
            rolled_back,
            restarted: true,
            switched: Vec::new(),
            warnings: warnings
                .into_iter()
                .chain(std::iter::once(format!(
                    "generation {failed} failed its health checks; the previous configuration was restored"
                )))
                .collect(),
        },
    }
}

fn build_engine_config(paths: &Paths, config: &ConfigFile, state: &DesiredState) -> EngineConfig {
    let api_endpoint = if config.core.api_unix_socket {
        // Kept behind an explicit opt-in: no released Xray-core serves the
        // commander over a Unix socket (see docs/UPSTREAM-COMPATIBILITY.md).
        tracing::warn!(
            "[core] api_unix_socket is set, but Xray-core only listens on TCP for its \
             commander; the core will fail to start"
        );
        ApiEndpoint::unix(paths.xray_api_socket())
    } else {
        // Port 0 would be chosen by the kernel and could not be dialled back, so
        // a concrete free port is reserved instead.
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .ok()
            .and_then(|l| l.local_addr().ok())
            .map_or(10_085, |addr| addr.port());
        ApiEndpoint::loopback(port)
    };

    let tun = state.mode.needs_tun().then(|| TunOptions {
        name: config.tun.name.clone(),
        mtu: config.tun.mtu,
    });

    EngineConfig {
        compile: xraytui_xray_compiler::CompileOptions {
            api_listen: api_endpoint.xray_listen(),
            log_level: config.core.log_level.clone(),
            access_log: None,
            error_log: None,
            mkcp_finalmask_dialect: Default::default(),
            tun,
            dns: DnsOptions {
                enabled: config.dns.enabled,
                direct_servers: config.dns.direct_servers.clone(),
                proxy_servers: config.dns.proxy_servers.clone(),
                direct_domains: config.dns.direct_domains.clone(),
                query_strategy: config.dns.query_strategy.clone(),
                listen: config.dns.listen,
                non_ip_query: config.dns.non_ip_query.clone(),
            },
            bypass_private_networks: config.tun.bypass_private_networks,
            stats: config.core.stats,
            observatory_probe_url: config.health.test_url.clone(),
            observatory_probe_interval: "5m".to_owned(),
            sniffing: SniffingOptions {
                enabled: config.core.sniffing,
                dest_override: vec!["http".into(), "tls".into(), "quic".into()],
                route_only: true,
            },
        },
        api_endpoint,
        generated_config: paths.generated_config(),
        last_good_config: paths.last_good_config(),
        core_log: Some(paths.core_log()),
        restart: xraytui_controller::RestartPolicy {
            min: Duration::from_millis(config.runtime.restart_backoff_min_ms),
            max: Duration::from_millis(config.runtime.restart_backoff_max_ms),
            budget: config.runtime.max_consecutive_restarts,
        },
        api_deadline: Duration::from_millis(config.runtime.start_health_deadline_ms),
        listener_timeout: Duration::from_millis(750),
        shutdown_grace: Duration::from_secs(5),
    }
}

// The explicit `impl Future + Send` return is what makes the future spawnable;
// `async fn` in a trait does not promise `Send`.
#[allow(clippy::manual_async_fn)]
impl ServerHandler for Daemon {
    fn handle(
        &self,
        peer: PeerCredentials,
        request: Request,
    ) -> impl std::future::Future<Output = Result<Response, IpcError>> + Send {
        async move {
            tracing::debug!(uid = peer.uid, pid = peer.pid, "request");
            match request {
                Request::Ping => Ok(Response::Pong {
                    daemon: format!("xraytuid/{}", env!("CARGO_PKG_VERSION")),
                    uptime_secs: self.started.elapsed().as_secs(),
                }),

                Request::GetState => {
                    let engine = self.engine.lock().await;
                    Ok(Response::State {
                        desired: Box::new(engine.desired().clone()),
                        runtime: Box::new(engine.runtime().clone()),
                    })
                }

                Request::GetRuntime => {
                    let engine = self.engine.lock().await;
                    Ok(Response::Runtime(Box::new(engine.runtime().clone())))
                }

                Request::Validate(state) => {
                    let diagnostics = state.validate();
                    Ok(Response::Diagnostics(diagnostics))
                }

                Request::SetDesired(state) => {
                    let diagnostics = state.validate();
                    if diagnostics.iter().any(|d| d.severity == Severity::Error) {
                        return Err(IpcError::Diagnostics(diagnostics));
                    }
                    self.apply(*state).await
                }

                Request::Up => {
                    let mut engine = self.engine.lock().await;
                    let generation = engine
                        .rebuild_and_start()
                        .await
                        .map_err(|error| IpcError::Internal(error.to_string()))?;
                    tracing::info!(%generation, "core started on request");
                    Ok(Response::Applied {
                        rolled_back: false,
                        restarted: true,
                        switched: Vec::new(),
                        warnings: engine
                            .compiled()
                            .map(|c| c.warnings.clone())
                            .unwrap_or_default(),
                    })
                }

                Request::Down => {
                    self.engine.lock().await.stop_core().await;
                    Ok(Response::Ack)
                }

                Request::Restart => {
                    let mut engine = self.engine.lock().await;
                    engine.stop_core().await;
                    engine
                        .rebuild_and_start()
                        .await
                        .map_err(|error| IpcError::Internal(error.to_string()))?;
                    Ok(Response::Applied {
                        rolled_back: false,
                        restarted: true,
                        switched: Vec::new(),
                        warnings: Vec::new(),
                    })
                }

                Request::GetMode => {
                    let engine = self.engine.lock().await;
                    Ok(Response::Mode(engine.desired().mode))
                }

                Request::SetMode(mode) => {
                    let mut state = self.engine.lock().await.desired().clone();
                    state.mode = mode;
                    self.apply(state).await
                }

                Request::CycleMode => {
                    let mut state = self.engine.lock().await.desired().clone();
                    state.mode = state.mode.next();
                    let response = self.apply(state).await?;
                    let _ = response;
                    let engine = self.engine.lock().await;
                    Ok(Response::Mode(engine.desired().mode))
                }

                Request::SetProfileTarget { profile, target } => {
                    self.set_target(profile, target).await
                }

                Request::SetGroupSelection { group, target } => {
                    let mut engine = self.engine.lock().await;
                    let outcome = engine
                        .set_group_selection(&group, target)
                        .await
                        .map_err(map_controller_error)?;
                    drop(engine);
                    self.persist().await?;
                    Ok(response_for(outcome, Vec::new()))
                }

                Request::Import { text, origin } => self.import(&text, origin).await,

                Request::RemoveNode(id) => {
                    let mut state = self.engine.lock().await.desired().clone();
                    if state.nodes.remove(&id).is_none() {
                        return Err(IpcError::NotFound {
                            kind: "node".into(),
                            id: id.to_string(),
                        });
                    }
                    let references = state.references_to_node(&id);
                    if !references.is_empty() {
                        return Err(IpcError::Invalid(format!(
                            "node '{id}' is still used by: {}",
                            references.join(", ")
                        )));
                    }
                    self.apply(state).await
                }

                Request::Test(target) => self.test(target).await,

                Request::ExplainRoute {
                    domain,
                    ip,
                    port,
                    network,
                    inbound_tag,
                } => {
                    let mut engine = self.engine.lock().await;
                    let client = engine.client().ok_or(IpcError::CoreNotRunning)?;
                    let decision = client
                        .test_route(xraytui_xray_api::RouteQuery {
                            inbound_tag,
                            network: Some(network),
                            domain,
                            ip,
                            port,
                            protocol: None,
                            attributes: std::collections::HashMap::new(),
                        })
                        .await
                        .map_err(|error| IpcError::Internal(error.to_string()))?;
                    Ok(Response::RouteDecision {
                        outbound: decision.outbound_tag,
                        groups: decision.outbound_group_tags,
                        rule: None,
                    })
                }

                Request::GetGeneratedConfig => {
                    let engine = self.engine.lock().await;
                    let compiled = engine
                        .compiled()
                        .ok_or_else(|| IpcError::Invalid("nothing has been compiled yet".into()))?;
                    compiled
                        .to_json()
                        .map(Response::GeneratedConfig)
                        .map_err(|error| IpcError::Internal(error.to_string()))
                }

                Request::Doctor => Ok(Response::Doctor(Box::new(self.doctor().await))),

                Request::SubscriptionDiff(id) => {
                    let diff = self.subscription_diff(&id).await?;
                    Ok(Response::Diff(Box::new(diff)))
                }

                Request::SubscriptionUpdate(id) => self.subscription_update(&[id]).await,

                Request::SubscriptionUpdateAll => {
                    let ids: Vec<xraytui_domain::SubscriptionId> = self
                        .engine
                        .lock()
                        .await
                        .desired()
                        .subscriptions
                        .values()
                        .filter(|subscription| subscription.enabled)
                        .map(|subscription| subscription.id.clone())
                        .collect();
                    self.subscription_update(&ids).await
                }

                Request::TunPlan => {
                    let state = self.engine.lock().await.desired().clone();
                    let request = crate::netd::plan_request(
                        &self.config,
                        &state,
                        self.proxy_endpoints(&state),
                    )
                    .map_err(|error| IpcError::Invalid(error.to_string()))?;
                    let (steps, firewall, from_helper) = self.netd.plan(&request).await;
                    Ok(Response::TunPlan {
                        steps,
                        firewall,
                        from_helper,
                    })
                }

                Request::Shutdown => {
                    self.shutdown.notify_waiters();
                    Ok(Response::Ack)
                }

                // Handled by the server loop before reaching a handler.
                Request::Subscribe(_) | Request::Cancel { .. } => Ok(Response::Ack),
            }
        }
    }

    fn subscribe(&self, _filter: SubscriptionFilter) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn version(&self) -> String {
        format!("xraytuid/{}", env!("CARGO_PKG_VERSION"))
    }

    fn features(&self) -> Vec<String> {
        let mut features = vec![
            "profiles".to_owned(),
            "chains".to_owned(),
            "groups".to_owned(),
        ];
        if std::path::Path::new("/run/xraytui/netd.sock").exists() {
            features.push("tun".to_owned());
        }
        features
    }
}

impl Daemon {
    async fn set_target(
        &self,
        profile: xraytui_domain::ProfileId,
        target: Target,
    ) -> Result<Response, IpcError> {
        let mut engine = self.engine.lock().await;
        let outcome = engine
            .set_profile_target(&profile, target)
            .await
            .map_err(map_controller_error)?;
        drop(engine);
        self.persist().await?;
        Ok(response_for(outcome, Vec::new()))
    }

    async fn import(&self, text: &str, origin: ImportOrigin) -> Result<Response, IpcError> {
        let source = match origin {
            ImportOrigin::Manual => xraytui_domain::NodeSource::Manual,
            ImportOrigin::File { path } => xraytui_domain::NodeSource::File { path },
            ImportOrigin::XrayJson => xraytui_domain::NodeSource::XrayJson,
        };

        let batch = if matches!(origin_kind(&source), OriginKind::XrayJson) {
            xraytui_import::parse_xray_config(text, source)
        } else {
            xraytui_import::parse_many(text, source)
        };

        let added: Vec<_> = batch.nodes.iter().map(|node| node.id.clone()).collect();
        let unsupported = batch.unsupported.len();
        let rejected: Vec<String> = batch
            .rejected
            .iter()
            .map(|entry| format!("line {}: {}", entry.index, entry.error))
            .collect();

        if !batch.nodes.is_empty() || !batch.unsupported.is_empty() {
            let mut state = self.engine.lock().await.desired().clone();
            for node in batch.nodes {
                state.nodes.insert(node.id.clone(), node);
            }
            for node in batch.unsupported {
                state.unsupported.insert(node.id.clone(), node);
            }
            // Importing nodes never changes routing on its own, so persist
            // without recompiling; the new nodes become live at the next start.
            let mut engine = self.engine.lock().await;
            let running = engine.runtime().core.is_usable();
            if running {
                drop(engine);
                self.apply(state).await?;
            } else {
                engine
                    .seed(state)
                    .map_err(|error| IpcError::Internal(error.to_string()))?;
                drop(engine);
                self.persist().await?;
            }
        }

        Ok(Response::Imported {
            added,
            unsupported,
            rejected,
        })
    }

    async fn test(&self, target: TestTarget) -> Result<Response, IpcError> {
        let engine = self.engine.lock().await;
        let desired = engine.desired().clone();
        let runtime = engine.runtime().clone();
        drop(engine);

        // Probing goes through a profile's own listener, so a profile has to own
        // one. That constraint is deliberate: it measures the path the user's
        // applications actually take.
        let profile = match &target {
            TestTarget::Profile(id) => runtime.profile(id).cloned(),
            _ => runtime.profiles.first().cloned(),
        };
        let Some(profile) = profile else {
            return Err(IpcError::Invalid(
                "no profile with a SOCKS listener is available to probe through".into(),
            ));
        };
        let Some(listen) = profile.socks_listen.as_deref() else {
            return Err(IpcError::Invalid(format!(
                "profile '{}' has no SOCKS listener, so there is nothing to probe through",
                profile.id
            )));
        };
        let address: std::net::SocketAddr = listen
            .parse()
            .map_err(|_| IpcError::Internal(format!("unparseable listener address {listen}")))?;

        let request = xraytui_controller::ProbeRequest::from_url(
            address,
            &self.config.health.test_url,
            Duration::from_millis(self.config.health.timeout_ms),
        )
        .ok_or_else(|| {
            IpcError::Invalid(format!(
                "[health] test_url {:?} is not a usable http(s) URL",
                self.config.health.test_url
            ))
        })?;

        let result = xraytui_controller::probe_through_socks(&request).await;
        let subject = match &target {
            TestTarget::Node(id) => id.to_string(),
            TestTarget::Group(id) => id.to_string(),
            TestTarget::Chain(id) => id.to_string(),
            TestTarget::Profile(id) => id.to_string(),
        };
        let _ = self.events.send(Event::Health {
            subject,
            result: Box::new(result.clone()),
        });
        if let TestTarget::Node(id) = &target
            && desired.nodes.contains_key(id)
        {
            self.engine
                .lock()
                .await
                .record_node_health(id.clone(), result.clone());
            // Also to disk, so a node that has been failing all morning is
            // still known to be failing after a restart.
            if let Some(store) = &self.store {
                let subject = xraytui_state_store::node_subject(id);
                if let Err(error) =
                    store.record_probe(&subject, xraytui_linux_net::lease::now(), &result)
                {
                    tracing::warn!(%error, "cannot record the probe");
                }
            }
        }
        Ok(Response::Probe(Box::new(result)))
    }
}

enum OriginKind {
    Links,
    XrayJson,
}

fn origin_kind(source: &xraytui_domain::NodeSource) -> OriginKind {
    match source {
        xraytui_domain::NodeSource::XrayJson => OriginKind::XrayJson,
        _ => OriginKind::Links,
    }
}

fn map_controller_error(error: xraytui_controller::ControllerError) -> IpcError {
    use xraytui_controller::ControllerError;
    match error {
        ControllerError::NotFound(message) => IpcError::NotFound {
            kind: "entity".into(),
            id: message,
        },
        ControllerError::Invalid(message) => IpcError::Invalid(message),
        ControllerError::CoreNotRunning => IpcError::CoreNotRunning,
        other => IpcError::Internal(other.to_string()),
    }
}

/// Unused today; kept so the mode type is exercised by the compiler.
#[allow(dead_code)]
fn mode_name(mode: SystemMode) -> &'static str {
    mode.as_str()
}
