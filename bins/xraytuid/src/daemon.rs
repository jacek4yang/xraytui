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
}

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
        engine.seed(state).context("cannot seed the desired state")?;

        let (events, _) = xraytui_ipc::server::event_channel();
        Ok(Self {
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
            let mut sigterm = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ) {
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
        let handler = Arc::new(self);
        let broadcaster = Arc::clone(&handler);
        let ticker = tokio::spawn(async move { broadcaster.broadcast_state_periodically().await });

        server.serve(Arc::clone(&handler), signal).await;
        ticker.abort();

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

    async fn apply(&self, state: DesiredState) -> Result<Response, IpcError> {
        let mut engine = self.engine.lock().await;
        let outcome = engine
            .apply(state)
            .await
            .map_err(|error| IpcError::Internal(error.to_string()))?;
        let warnings = engine.compiled().map(|c| c.warnings.clone()).unwrap_or_default();
        drop(engine);
        self.persist().await?;
        Ok(response_for(outcome, warnings))
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
            status: if info.has_geodata { CheckStatus::Pass } else { CheckStatus::Warn },
            detail: match &info.asset_dir {
                Some(dir) if info.has_geodata => format!("geoip.dat and geosite.dat in {}", dir.display()),
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
            status: if runtime.core.is_usable() { CheckStatus::Pass } else { CheckStatus::Warn },
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
            match std::fs::OpenOptions::new().read(true).write(true).open(tun_device) {
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

        let netd = std::path::Path::new("/run/xraytui/netd.sock");
        checks.push(DoctorCheck {
            name: "netd".into(),
            status: if netd.exists() { CheckStatus::Pass } else { CheckStatus::Warn },
            detail: if netd.exists() {
                "privileged helper socket present".into()
            } else {
                "privileged helper is not running; TUN modes are unavailable".into()
            },
            remedy: (!netd.exists())
                .then(|| "sudo systemctl enable --now xraytui-netd.service".to_owned()),
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
            status: if runtime.lan_exposed { CheckStatus::Warn } else { CheckStatus::Pass },
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
    match outcome {
        ApplyOutcome::Unchanged => {
            Response::Applied { restarted: false, switched: Vec::new(), warnings }
        }
        ApplyOutcome::SwitchedSelectors { balancers } => {
            Response::Applied { restarted: false, switched: balancers, warnings }
        }
        ApplyOutcome::Restarted { .. } => {
            Response::Applied { restarted: true, switched: Vec::new(), warnings }
        }
        ApplyOutcome::RolledBack { failed, .. } => Response::Applied {
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
                        restarted: true,
                        switched: Vec::new(),
                        warnings: engine.compiled().map(|c| c.warnings.clone()).unwrap_or_default(),
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

                Request::ExplainRoute { domain, ip, port, network, inbound_tag } => {
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

                Request::SubscriptionDiff(_)
                | Request::SubscriptionUpdate(_)
                | Request::SubscriptionUpdateAll => Err(IpcError::Invalid(
                    "subscription fetching is not wired into this daemon build; \
                     see STATUS.md for what is implemented"
                        .into(),
                )),

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
        let mut features = vec!["profiles".to_owned(), "chains".to_owned(), "groups".to_owned()];
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
        let outcome =
            engine.set_profile_target(&profile, target).await.map_err(map_controller_error)?;
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
                engine.seed(state).map_err(|error| IpcError::Internal(error.to_string()))?;
                drop(engine);
                self.persist().await?;
            }
        }

        Ok(Response::Imported { added, unsupported, rejected })
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
        if let TestTarget::Node(id) = &target {
            if desired.nodes.contains_key(id) {
                self.engine.lock().await.record_node_health(id.clone(), result.clone());
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
        ControllerError::NotFound(message) => {
            IpcError::NotFound { kind: "entity".into(), id: message }
        }
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
