//! `xraytuid` — the per-user desired-state daemon.
//!
//! Unprivileged. Owns the desired state, supervises Xray-core, serves the
//! control socket, and coordinates privileged network changes through
//! `xraytui-netd`. It never modifies host networking itself.

#![forbid(unsafe_code)]
// Production paths must not panic; test modules are exempt so assertions stay
// readable.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod daemon;
mod lock;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Command line for the daemon.
#[derive(Debug, Parser)]
#[command(
    name = "xraytuid",
    version,
    about = "xraytui per-user desired-state daemon",
    long_about = "Owns xraytui's desired state and supervises the Xray-core process.\n\
                  Runs unprivileged as an ordinary user service; privileged network\n\
                  changes are delegated to xraytui-netd."
)]
struct Cli {
    /// Use this directory instead of the XDG locations. For testing.
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,

    /// Log level filter, e.g. `info`, `xraytuid=debug`.
    #[arg(
        long,
        env = "XRAYTUI_LOG",
        default_value = "warn,xraytuid=info,xraytui=info"
    )]
    log: String,

    /// Validate the configuration and exit without starting anything.
    #[arg(long)]
    check: bool,

    /// Do not start the core at launch, whatever the configuration says.
    #[arg(long)]
    no_start: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cli.log))
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();

    // A single-threaded runtime is enough: the daemon is I/O bound and the
    // supervised core does the actual work. It also keeps memory small on the
    // lightweight workstations this is aimed at.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?;

    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let paths = match &cli.root {
        Some(root) => xraytui_config::Paths::rooted_at(root),
        None => xraytui_config::Paths::discover().context("cannot determine XDG directories")?,
    };
    paths
        .ensure()
        .context("cannot create the xraytui directories")?;

    let config = xraytui_config::load_toml::<xraytui_config::ConfigFile>(&paths.config_file())
        .context("cannot read config.toml")?
        .unwrap_or_default();
    config.validate().context("config.toml is not valid")?;

    let mut state = xraytui_config::store::load(&paths).context("cannot read the policy files")?;
    if state.profiles.is_empty() && state.nodes.is_empty() {
        // A fresh installation gets one inert direct profile with loopback
        // listeners, so `xraytui status` and `xraytui exec` have something to
        // talk about before the user has added a node.
        tracing::info!("no configuration found; writing a starter configuration");
        state = xraytui_config::store::starter_state();
        xraytui_config::store::save(&paths, &state)
            .context("cannot write the starter configuration")?;
    }

    if cli.check {
        let diagnostics = state.validate();
        for diagnostic in &diagnostics {
            let severity = match diagnostic.severity {
                xraytui_domain::Severity::Error => "error",
                xraytui_domain::Severity::Warning => "warning",
            };
            println!("{severity}: [{}] {}", diagnostic.code, diagnostic.message);
        }
        let errors = diagnostics
            .iter()
            .filter(|d| d.severity == xraytui_domain::Severity::Error)
            .count();
        if errors > 0 {
            anyhow::bail!("{errors} configuration error(s)");
        }
        println!("configuration is valid");
        return Ok(());
    }

    // One daemon per user. The lock is held for the process lifetime and
    // released by the kernel if the process dies, so a crash does not need
    // manual cleanup.
    let _lock = lock::acquire(&paths.daemon_lock())
        .context("another xraytuid is already running for this user")?;

    let daemon = daemon::Daemon::new(paths.clone(), config, state).await?;
    daemon.run(!cli.no_start).await
}
