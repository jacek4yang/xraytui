//! `xraytui-netd` — the only component of this project that runs with
//! privileges, and the smallest one.
//!
//! It accepts a closed set of operations
//! ([`xraytui_netd_protocol::Operation`]) on a Unix socket, derives every
//! resource name from the connecting process's `SO_PEERCRED` credential, and
//! applies them through [`xraytui_linux_net`]. It never parses a subscription,
//! never resolves a name, never opens a network socket and never sees a node
//! credential.
//!
//! Two things guarantee the machine is left tidy:
//!
//! * a connection that closes applies its owner's restore/block policy immediately;
//! * a lease that stops being renewed is reaped, which covers the case where
//!   the helper itself was restarted.

#![forbid(unsafe_code)]
// Production paths must not panic; test modules are exempt so assertions stay
// readable, matching every other crate in the workspace.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod notify;
mod server;

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;
use xraytui_linux_net::{Engine, EngineOptions, nft::Nft};

/// Command line for the privileged helper.
#[derive(Debug, Parser)]
#[command(
    name = "xraytui-netd",
    about = "xraytui privileged network helper",
    version,
    long_about = "Applies a closed set of network operations on behalf of local users. \
                  Every resource is named from the connecting process's credential, so one \
                  user cannot address another's tunnel, routing table, firewall chain or cgroup."
)]
struct Args {
    /// Path of the control socket.
    #[arg(long, default_value = xraytui_netd_protocol::DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Group allowed to reach the socket. Membership is the administrator's
    /// explicit decision to let a user create project-owned network state.
    #[arg(long)]
    group: Option<String>,

    /// Directory holding lease and recovery state.
    #[arg(long, default_value = xraytui_netd_protocol::RECOVERY_DIR)]
    state_dir: PathBuf,

    /// Root of the cgroup v2 hierarchy. Detected when not given.
    #[arg(long)]
    cgroup_root: Option<PathBuf>,

    /// The `nft` program to use.
    #[arg(long, default_value = "nft")]
    nft: PathBuf,

    /// Seconds between lease sweeps.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=300))]
    reap_interval: u64,

    /// Report what this kernel and userland support, then exit. Changes nothing.
    #[arg(long)]
    check_capabilities: bool,

    /// Remove project-owned state whose owner is gone, then keep running unless
    /// `--once` is given.
    #[arg(long)]
    recover: bool,

    /// With `--recover`, exit after the sweep instead of serving.
    #[arg(long)]
    once: bool,

    /// Emit machine-readable output for `--check-capabilities`.
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("XRAYTUI_NETD_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut options = EngineOptions {
        state_dir: args.state_dir.clone(),
        nft: Nft::new(&args.nft),
        ..EngineOptions::default()
    };
    if let Some(root) = &args.cgroup_root {
        options.cgroup_root = root.clone();
    }

    if args.check_capabilities {
        let report = xraytui_linux_net::probe(&options);
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).context("encode the capability report")?
            );
        } else {
            print_capabilities(&report);
        }
        return Ok(());
    }

    let engine = Engine::new(options).map_err(|error| anyhow::anyhow!(error.to_string()))?;

    if args.recover {
        let removed = engine.recover(xraytui_linux_net::lease::now());
        for item in &removed {
            println!("removed {item}");
        }
        if removed.is_empty() {
            println!("nothing to recover");
        }
        if args.once {
            return Ok(());
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("start the async runtime")?;
    runtime.block_on(server::serve(
        engine,
        server::ServerOptions {
            socket: args.socket,
            group: args.group,
            reap_interval: std::time::Duration::from_secs(args.reap_interval),
        },
    ))
}

fn print_capabilities(report: &xraytui_netd_protocol::NetdCapabilities) {
    let mark = |value: bool| if value { "yes" } else { "no " };
    println!("kernel                {}", report.kernel);
    println!("/dev/net/tun          {}", mark(report.tun));
    println!("CAP_NET_ADMIN         {}", mark(report.cap_net_admin));
    println!("nftables              {}", mark(report.nftables));
    println!("cgroup v2             {}", mark(report.cgroup_v2));
    println!("nft socket cgroupv2   {}", mark(report.nft_cgroup_match));
    println!("systemd-resolved      {}", mark(report.systemd_resolved));
    println!("resolvconf            {}", mark(report.resolvconf));
    println!();
    println!("system tun modes      {}", mark(report.supports_tun()));
    println!(
        "exec --transparent    {}",
        mark(report.supports_transparent_exec())
    );
}
