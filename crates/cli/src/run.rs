//! Command dispatch.

use std::io::{Read as _, Write as _};

use xraytui_domain::Target;
use xraytui_ipc::{Client, ImportOrigin, Request, Response, TestTarget};

use crate::args::{
    ChainCommand, Cli, Command, Format, GroupCommand, ModeCommand, NodeCommand, ProfileCommand,
    RuleCommand, RuntimeCommand, Shell, SubscriptionCommand, TargetCommand, TunCommand,
};
use crate::output::{self};
use crate::{CliError, exec};

/// Parse arguments and run, returning a process exit code.
///
/// Never panics on user input: every failure path maps to a code from the table
/// in the crate documentation.
#[must_use]
pub fn main() -> i32 {
    quiet_broken_pipe();
    let cli = <Cli as clap::Parser>::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("xraytui: cannot start the async runtime: {error}");
            return crate::EXIT_FAILURE;
        }
    };
    match runtime.block_on(dispatch(cli)) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("xraytui: {error}");
            error.exit_code()
        }
    }
}

/// Exit quietly when the reader goes away.
///
/// `xraytui target list | dmenu` and `… | head` are documented workflows, and
/// both close the pipe early. Rust ignores `SIGPIPE`, so the write fails and
/// `println!` panics with a backtrace — which looks like a crash in a tool that
/// did exactly what it was asked. Restoring the signal disposition would need
/// `unsafe`, which this workspace forbids; catching the panic is safe, costs
/// nothing, and produces the behaviour every other command-line tool has.
fn quiet_broken_pipe() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if message.contains("Broken pipe") {
            // The reader closed first. That is not a failure of this program,
            // and printing a backtrace into a closed pipe helps nobody.
            std::process::exit(0);
        }
        previous(info);
    }));
}

async fn dispatch(cli: Cli) -> Result<(), CliError> {
    let paths = match &cli.root {
        Some(root) => xraytui_config::Paths::rooted_at(root),
        None => {
            xraytui_config::Paths::discover().map_err(|error| CliError::Other(error.to_string()))?
        }
    };

    // Commands that never need the daemon are handled first, so `completion`
    // and `manpages` work during packaging with nothing running.
    match &cli.command {
        Some(Command::Completion { shell }) => return print_completion(*shell),
        Some(Command::Init { force }) => return init(&paths, *force),
        Some(Command::Manpages { directory }) => return write_manpages(directory),
        // Transparent mode is handled here, before the daemon connection,
        // because it does not need one: what it needs is the configuration on
        // disk, a listener that is actually up, and the privileged helper. A
        // daemon that is busy — or restarting — is no reason to refuse to launch
        // a command, and the daemon is not what decides where the traffic goes.
        Some(Command::Exec(args)) if args.transparent => {
            return run_exec_transparent(&paths, args).await;
        }
        _ => {}
    }

    let socket = paths.control_socket();

    // The interface opens its own connections — one for requests and one for
    // the log stream — so it is dispatched before the shared client is made.
    if matches!(cli.command, None | Some(Command::Tui)) {
        return xraytui_tui::run(socket)
            .await
            .map_err(|error| CliError::Other(error.to_string()));
    }

    let mut client = Client::connect(&socket).await?;

    match cli.command {
        // Handled above, before the client was connected.
        None | Some(Command::Tui) => Ok(()),

        Some(Command::Status) => status(&mut client, cli.format).await,
        Some(Command::Up) => simple(&mut client, Request::Up, "core started", cli.quiet).await,
        Some(Command::Down) => simple(&mut client, Request::Down, "core stopped", cli.quiet).await,
        Some(Command::Restart) => {
            simple(&mut client, Request::Restart, "core restarted", cli.quiet).await
        }
        Some(Command::Doctor) => doctor(&mut client, cli.format).await,

        Some(Command::Mode(command)) => mode(&mut client, command, cli.format, cli.quiet).await,
        Some(Command::Tun(command)) => tun(&mut client, command, cli.format).await,
        Some(Command::Profile(command)) => {
            profile(&mut client, command, cli.format, cli.quiet).await
        }
        Some(Command::Target(command)) => target(&mut client, command, cli.format).await,
        Some(Command::App(command)) => app(&mut client, command, cli.format).await,
        Some(Command::Node(command)) => node(&mut client, *command, cli.format, cli.quiet).await,
        Some(Command::Group(command)) => group(&mut client, command, cli.format).await,
        Some(Command::Chain(command)) => chain(&mut client, command, cli.format).await,
        Some(Command::Rule(command)) => rule(&mut client, command, cli.format).await,
        Some(Command::Subscription(command)) => {
            subscription(&mut client, command, cli.format).await
        }
        Some(Command::Runtime(command)) => runtime_info(&mut client, command, cli.format).await,
        Some(Command::Logs(args)) => logs(&mut client, args.follow).await,
        Some(Command::ShowConfig) => show_config(&mut client).await,

        Some(Command::Exec(args)) => run_exec(&mut client, args).await,

        // Handled before the daemon connection.
        Some(Command::Completion { .. } | Command::Manpages { .. } | Command::Init { .. }) => {
            Ok(())
        }
    }
}

/// `xraytui init` — make a usable configuration and stop.
///
/// Everything it writes is inside the caller's own XDG directories, and all of
/// it is inert: mode `off`, one direct profile with loopback listeners, no
/// tunnel, no DNS change, no service enabled, nothing installed. A first run
/// should leave the machine exactly as it found it apart from a few files the
/// user can read.
///
/// Idempotent. Run it twice and the second run reports what already existed
/// rather than replacing it, because the second run is usually somebody
/// checking whether the first one worked.
fn init(paths: &xraytui_config::Paths, force: bool) -> Result<(), CliError> {
    paths
        .ensure()
        .map_err(|error| CliError::Other(error.to_string()))?;
    println!("directories       {}", paths.config.display());

    let config_file = paths.config_file();
    if force || !config_file.exists() {
        xraytui_config::store_toml(&config_file, &xraytui_config::ConfigFile::default())
            .map_err(|error| CliError::Other(error.to_string()))?;
        println!("config.toml       written");
    } else {
        println!("config.toml       kept (pass --force to replace it)");
    }

    let state = match xraytui_config::store::load(paths) {
        Ok(state) if !state.profiles.is_empty() => {
            println!(
                "policy            kept ({} profile(s), {} node(s))",
                state.profiles.len(),
                state.nodes.len()
            );
            state
        }
        Ok(_) => {
            let state = xraytui_config::store::starter_state();
            xraytui_config::store::save(paths, &state)
                .map_err(|error| CliError::Other(error.to_string()))?;
            println!("policy            starter configuration written");
            state
        }
        // A policy file that exists but does not parse is not a fresh
        // installation. Writing the starter configuration here would delete
        // every node the user owns because one file has a typo in it — so
        // refuse, and say which file and why.
        Err(error) => {
            return Err(CliError::Other(format!(
                "{error}\n\nRefusing to write a starter configuration over policy files that \
                 already exist: fix the file above, or move it aside, and run `xraytui init` \
                 again."
            )));
        }
    };

    match xraytui_state_store::StateStore::open(paths.state_db()) {
        Ok(store) => println!("state database    {}", store.path().display()),
        Err(error) => eprintln!("xraytui: warning: {error}"),
    }

    for diagnostic in state
        .validate()
        .iter()
        .filter(|d| d.severity == xraytui_domain::Severity::Error)
    {
        eprintln!("xraytui: [{}] {}", diagnostic.code, diagnostic.message);
    }

    println!();
    println!("Next:");
    println!("  xraytui doctor                    # what this machine can and cannot do");
    println!("  systemctl --user enable --now xraytuid.service");
    println!("  xraytui node import --stdin       # paste share links, then Ctrl-D");
    println!("  xraytui                           # the interface");
    Ok(())
}

/// Set or clear a profile's listeners. A port of 0 removes one.
fn apply_listeners(
    profile: &mut xraytui_domain::EgressProfile,
    socks: Option<u16>,
    http: Option<u16>,
    transparent: Option<u16>,
) {
    // Loopback only. A listener on 0.0.0.0 is an open proxy for the network the
    // machine is on, and that is never something a flag should do by accident.
    let spec = |port: u16| (port != 0).then(|| xraytui_domain::ListenerSpec::loopback(port));
    if let Some(port) = socks {
        profile.socks = spec(port);
    }
    if let Some(port) = http {
        profile.http = spec(port);
    }
    if let Some(port) = transparent {
        profile.transparent = spec(port);
    }
}

/// Enable or disable a rule, whichever kind it is.
async fn set_rule_enabled(client: &mut Client, rule: &str, enabled: bool) -> Result<(), CliError> {
    let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    let mut next = (*desired).clone();
    let mut found = false;
    if let Ok(id) = xraytui_domain::AppRuleId::new(rule)
        && let Some(entry) = next.app_rules.get_mut(&id)
    {
        entry.enabled = enabled;
        found = true;
    }
    if let Ok(id) = xraytui_domain::RoutingRuleId::new(rule)
        && let Some(entry) = next.routing_rules.get_mut(&id)
    {
        entry.enabled = enabled;
        found = true;
    }
    if !found {
        return Err(CliError::Other(format!("no rule '{rule}'")));
    }
    let verb = if enabled { "enabled" } else { "disabled" };
    set_desired(client, next, false, &format!("rule '{rule}' {verb}")).await
}

/// Apply a typed mutation: the daemon validates it, applies it, persists it, and
/// rolls back if reconciliation fails.
///
/// Every mutating command goes through here so there is exactly one answer to
/// "is this allowed", one place that reports a rollback, and one place the
/// interface will call too.
async fn set_desired(
    client: &mut Client,
    next: xraytui_domain::DesiredState,
    quiet: bool,
    message: &str,
) -> Result<(), CliError> {
    let response = ask(client, Request::SetDesired(Box::new(next))).await?;
    report_applied(&response)?;
    if !quiet {
        println!("{message}");
    }
    Ok(())
}

/// Turn an `Applied` response into output, or into a failure.
///
/// A rolled-back change is a *failure*: the configuration it produced did not
/// pass its health checks and the previous one was restored, so reporting
/// success and exiting 0 would tell a script the opposite of what happened.
fn report_applied(response: &Response) -> Result<(), CliError> {
    if let Response::Applied {
        rolled_back,
        warnings,
        ..
    } = response
    {
        for warning in warnings {
            eprintln!("xraytui: warning: {warning}");
        }
        if *rolled_back {
            return Err(CliError::Other(
                "the change was rolled back: the configuration it produced did not pass its \
                 health checks, and the previous one was restored. Nothing was saved."
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

async fn ask(client: &mut Client, request: Request) -> Result<Response, CliError> {
    client.request(request).await.map_err(|error| match error {
        xraytui_ipc::IpcClientError::Daemon(daemon) => CliError::from(daemon),
        other => CliError::from(other),
    })
}

async fn simple(
    client: &mut Client,
    request: Request,
    message: &str,
    quiet: bool,
) -> Result<(), CliError> {
    let response = ask(client, request).await?;
    if let Response::Applied { warnings, .. } = &response {
        for warning in warnings {
            eprintln!("xraytui: warning: {warning}");
        }
    }
    if !quiet {
        println!("{message}");
    }
    Ok(())
}

async fn status(client: &mut Client, format: Format) -> Result<(), CliError> {
    let Response::State { desired, runtime } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response to GetState".into()));
    };
    match format {
        Format::Json => {
            let value = serde_json::json!({ "runtime": *runtime, "desired": *desired });
            println!(
                "{}",
                serde_json::to_string_pretty(&value)
                    .map_err(|error| CliError::Other(error.to_string()))?
            );
        }
        Format::Dwmblocks => println!("{}", output::dwmblocks_line(&runtime)),
        Format::Shell => print!("{}", output::shell_status(&runtime)),
        Format::Dmenu | Format::Plain => {
            print!("{}", output::profile_table(&runtime, &desired));
        }
    }
    Ok(())
}

async fn doctor(client: &mut Client, format: Format) -> Result<(), CliError> {
    let Response::Doctor(report) = ask(client, Request::Doctor).await? else {
        return Err(CliError::Other("unexpected response to Doctor".into()));
    };
    if format == Format::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&*report)
                .map_err(|error| CliError::Other(error.to_string()))?
        );
    } else {
        for check in &report.checks {
            println!(
                "[{}] {:<18} {}",
                check.status.label(),
                check.name,
                check.detail
            );
            if let Some(remedy) = &check.remedy {
                for line in remedy.lines() {
                    println!("            {line}");
                }
            }
        }
    }
    if report.failures() > 0 {
        return Err(CliError::Other(format!(
            "{} check(s) failed",
            report.failures()
        )));
    }
    Ok(())
}

async fn mode(
    client: &mut Client,
    command: ModeCommand,
    format: Format,
    quiet: bool,
) -> Result<(), CliError> {
    let response = match command {
        ModeCommand::Get => ask(client, Request::GetMode).await?,
        ModeCommand::Cycle => ask(client, Request::CycleMode).await?,
        ModeCommand::Set { mode } => {
            let parsed: xraytui_domain::SystemMode = mode.parse().map_err(CliError::Usage)?;
            ask(client, Request::SetMode(parsed)).await?;
            ask(client, Request::GetMode).await?
        }
    };
    if let Response::Mode(mode) = response {
        if format == Format::Json {
            println!("{{\"mode\":\"{mode}\"}}");
        } else if !quiet {
            println!("{mode}");
        }
    }
    Ok(())
}

async fn tun(client: &mut Client, command: TunCommand, format: Format) -> Result<(), CliError> {
    match command {
        TunCommand::Status => {
            let Response::Runtime(runtime) = ask(client, Request::GetRuntime).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&runtime.tun)
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                println!("{}", runtime.tun.label());
            }
            Ok(())
        }
        TunCommand::Enable => {
            ask(client, Request::SetMode(xraytui_domain::SystemMode::Rule)).await?;
            println!("mode set to rule; TUN will come up when the helper grants it");
            Ok(())
        }
        TunCommand::Disable => {
            ask(client, Request::SetMode(xraytui_domain::SystemMode::Off)).await?;
            println!("mode set to off");
            Ok(())
        }
        TunCommand::Plan => {
            let Response::TunPlan {
                steps,
                firewall,
                from_helper,
            } = ask(client, Request::TunPlan).await?
            else {
                return Err(CliError::Other("unexpected response".into()));
            };
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "steps": steps,
                        "firewall": firewall,
                        "from_helper": from_helper,
                    }))
                    .map_err(|error| CliError::Other(error.to_string()))?
                );
                return Ok(());
            }
            if from_helper {
                println!("Plan reported by the privileged helper. Nothing has been changed.");
            } else {
                println!(
                    "Plan rendered locally: no privileged helper is running, so this is what \
                     it would be asked to do. Nothing has been changed."
                );
            }
            println!();
            for (index, step) in steps.iter().enumerate() {
                println!("{:>3}. {step}", index + 1);
            }
            if !firewall.trim().is_empty() {
                println!();
                println!("nftables ruleset that would be installed:");
                for line in firewall.lines() {
                    println!("    {line}");
                }
            }
            Ok(())
        }
    }
}

async fn profile(
    client: &mut Client,
    command: ProfileCommand,
    format: Format,
    quiet: bool,
) -> Result<(), CliError> {
    let Response::State { desired, runtime } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };

    match command {
        ProfileCommand::List => {
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&desired.profiles.values().collect::<Vec<_>>())
                        .map_err(|error| CliError::Other(error.to_string()))?
                ),
                Format::Dmenu => {
                    for (id, profile) in &desired.profiles {
                        let health = runtime
                            .profile(id)
                            .map(|p| p.health.state().label())
                            .unwrap_or("--");
                        println!(
                            "{}",
                            output::dmenu_line(
                                id.as_str(),
                                &format!(
                                    "{}  →  {}  [{health}]",
                                    profile.name,
                                    profile.target.to_token()
                                )
                            )
                        );
                    }
                }
                _ => print!("{}", output::profile_table(&runtime, &desired)),
            }
            Ok(())
        }

        ProfileCommand::Show { profile } => {
            let id = parse_id::<xraytui_domain::ProfileId>(&profile, "profile")?;
            let found = desired
                .profiles
                .get(&id)
                .ok_or_else(|| CliError::NotFound(format!("profile '{profile}' does not exist")))?;
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(found)
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                println!("id:       {}", found.id);
                println!("name:     {}", found.name);
                println!("target:   {}", found.target.to_token());
                println!(
                    "fallback: {}",
                    found
                        .fallback
                        .as_ref()
                        .map_or("(none)".to_owned(), Target::to_token)
                );
                println!(
                    "socks:    {}",
                    found
                        .socks
                        .as_ref()
                        .map_or("(none)".to_owned(), |l| l.listen.to_string())
                );
                println!(
                    "http:     {}",
                    found
                        .http
                        .as_ref()
                        .map_or("(none)".to_owned(), |l| l.listen.to_string())
                );
                println!("kill switch: {:?}", found.kill_switch);
            }
            Ok(())
        }

        ProfileCommand::SetTarget {
            profile,
            target,
            stdin,
        } => {
            let id = parse_id::<xraytui_domain::ProfileId>(&profile, "profile")?;
            let token = if stdin {
                read_stdin_token()?
            } else {
                target.unwrap_or_default()
            };
            let target: Target =
                token
                    .parse()
                    .map_err(|error: xraytui_domain::TargetParseError| {
                        CliError::Usage(error.to_string())
                    })?;
            let response = ask(
                client,
                Request::SetProfileTarget {
                    profile: id,
                    target: target.clone(),
                },
            )
            .await?;
            if let Response::Applied { restarted, .. } = response
                && !quiet
            {
                println!(
                    "{profile} -> {}{}",
                    target.to_token(),
                    if restarted { " (core restarted)" } else { "" }
                );
            }
            Ok(())
        }

        ProfileCommand::Add {
            profile,
            name,
            target,
            socks,
            http,
            transparent,
        } => {
            let id = parse_id::<xraytui_domain::ProfileId>(&profile, "profile")?;
            if desired.profiles.contains_key(&id) {
                return Err(CliError::Other(format!(
                    "profile '{profile}' already exists"
                )));
            }
            let target = match target.as_deref() {
                Some(token) => {
                    token
                        .parse()
                        .map_err(|error: xraytui_domain::TargetParseError| {
                            CliError::Usage(error.to_string())
                        })?
                }
                None => Target::Direct,
            };
            let mut entry = xraytui_domain::EgressProfile::new(
                id.clone(),
                name.unwrap_or_else(|| profile.clone()),
                target,
            );
            apply_listeners(&mut entry, socks, http, transparent);
            let mut next = (*desired).clone();
            next.profiles.insert(id, entry);
            set_desired(client, next, quiet, &format!("profile '{profile}' added")).await
        }

        ProfileCommand::Remove { profile } => {
            let id = parse_id::<xraytui_domain::ProfileId>(&profile, "profile")?;
            let mut next = (*desired).clone();
            if next.profiles.remove(&id).is_none() {
                return Err(CliError::Other(format!("no profile '{profile}'")));
            }
            // A rule pointing at a profile that no longer exists would fail
            // validation, so the rules go with it and the user is told.
            let orphaned: Vec<_> = next
                .app_rules
                .iter()
                .filter(|(_, rule)| {
                    matches!(&rule.action, xraytui_domain::RuleAction::Profile { id: p } if p == &id)
                })
                .map(|(rule_id, _)| rule_id.clone())
                .collect();
            for rule in &orphaned {
                next.app_rules.remove(rule);
            }
            if next.default_profile.as_ref() == Some(&id) {
                next.default_profile = next.profiles.keys().next().cloned();
            }
            if !orphaned.is_empty() && !quiet {
                println!("also removed {} application rule(s)", orphaned.len());
            }
            set_desired(client, next, quiet, &format!("profile '{profile}' removed")).await
        }

        ProfileCommand::Listeners {
            profile,
            socks,
            http,
            transparent,
        } => {
            let id = parse_id::<xraytui_domain::ProfileId>(&profile, "profile")?;
            let mut next = (*desired).clone();
            let entry = next
                .profiles
                .get_mut(&id)
                .ok_or_else(|| CliError::Other(format!("no profile '{profile}'")))?;
            apply_listeners(entry, socks, http, transparent);
            set_desired(
                client,
                next,
                quiet,
                &format!("listeners of '{profile}' updated"),
            )
            .await
        }

        ProfileCommand::SelectFromStdin => {
            let token = read_stdin_token()?;
            let id = parse_id::<xraytui_domain::ProfileId>(&token, "profile")?;
            if !desired.profiles.contains_key(&id) {
                return Err(CliError::NotFound(format!("profile '{id}' does not exist")));
            }
            if !quiet {
                println!("{id}");
            }
            Ok(())
        }
    }
}

async fn target(
    client: &mut Client,
    command: TargetCommand,
    format: Format,
) -> Result<(), CliError> {
    let TargetCommand::List { profile } = command;
    let Response::State { desired, runtime } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    let _ = profile;

    let mut rows: Vec<(String, String)> = Vec::new();
    rows.push(("direct".into(), "Direct — no proxy".into()));
    rows.push(("block".into(), "Block — drop the connection".into()));
    for (id, node) in &desired.nodes {
        if !node.is_compilable() {
            continue;
        }
        let latency = runtime
            .node_health
            .get(id)
            .and_then(|h| h.ema_latency_ms)
            .map_or_else(|| "  --".to_owned(), |ms| format!("{ms:>4}ms"));
        rows.push((
            format!("node:{id}"),
            format!("{}  {}  {latency}", node.name, node.summary()),
        ));
    }
    for (id, group) in &desired.groups {
        rows.push((
            format!("group:{id}"),
            format!(
                "{} ({} members)",
                group.name,
                desired.group_members(id).len()
            ),
        ));
    }
    for (id, chain) in &desired.chains {
        rows.push((
            format!("chain:{id}"),
            format!("{}  {}", chain.name, chain.describe()),
        ));
    }

    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(
                &rows
                    .iter()
                    .map(|(id, label)| serde_json::json!({"target": id, "label": label}))
                    .collect::<Vec<_>>()
            )
            .map_err(|error| CliError::Other(error.to_string()))?
        ),
        Format::Dmenu => {
            for (id, label) in &rows {
                println!("{}", output::dmenu_line(id, label));
            }
        }
        _ => {
            for (id, label) in &rows {
                println!("{id:<28} {label}");
            }
        }
    }
    Ok(())
}

async fn app(
    client: &mut Client,
    command: crate::args::AppCommand,
    format: Format,
) -> Result<(), CliError> {
    let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    match command {
        crate::args::AppCommand::List => {
            let mut rules: Vec<_> = desired.app_rules.values().collect();
            rules.sort_by_key(|rule| (rule.priority, rule.id.clone()));
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rules)
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                for rule in rules {
                    let matchers: Vec<&str> = rule.process.iter().map(|m| m.0.as_str()).collect();
                    println!(
                        "{:>6}  {:<24} {:<20} {}",
                        rule.priority,
                        rule.id,
                        rule.action.to_token(),
                        matchers.join(", ")
                    );
                }
            }
            Ok(())
        }
        crate::args::AppCommand::Assign { profile, matcher } => {
            let profile_id = parse_id::<xraytui_domain::ProfileId>(&profile, "profile")?;
            if !desired.profiles.contains_key(&profile_id) {
                return Err(CliError::Other(format!("no profile '{profile}'")));
            }
            let matcher = matcher.trim();
            if matcher.is_empty() {
                return Err(CliError::Usage(
                    "a matcher is a process name, an absolute path, or a directory ending in `/`"
                        .to_owned(),
                ));
            }
            // The identifier encodes both halves, so assigning the same program
            // to a second profile is visibly a second rule rather than a silent
            // overwrite of the first.
            let id = xraytui_domain::AppRuleId::new(format!(
                "{}-{profile}",
                xraytui_domain::slugify(matcher)
            ))
            .map_err(|error| CliError::Usage(error.to_string()))?;

            let mut next = (*desired).clone();
            next.app_rules.insert(
                id.clone(),
                xraytui_domain::ApplicationRule {
                    id: id.clone(),
                    priority: 100,
                    process: vec![xraytui_domain::AppMatcher(matcher.to_owned())],
                    action: xraytui_domain::RuleAction::Profile { id: profile_id },
                    enabled: true,
                    note: None,
                },
            );
            set_desired(
                client,
                next,
                false,
                &format!("{matcher} → profile '{profile}' (rule {id})"),
            )
            .await
        }
        crate::args::AppCommand::Unassign { rule } => {
            let id = xraytui_domain::AppRuleId::new(&rule)
                .map_err(|error| CliError::Usage(error.to_string()))?;
            let mut next = (*desired).clone();
            if next.app_rules.remove(&id).is_none() {
                return Err(CliError::Other(format!("no application rule '{rule}'")));
            }
            set_desired(client, next, false, &format!("rule '{rule}' removed")).await
        }
    }
}

async fn node(
    client: &mut Client,
    command: NodeCommand,
    format: Format,
    quiet: bool,
) -> Result<(), CliError> {
    match command {
        NodeCommand::List { filter } => {
            let Response::State { desired, runtime } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let matching: Vec<_> = desired
                .nodes
                .values()
                .filter(|node| {
                    filter.as_deref().is_none_or(|needle| {
                        node.name.contains(needle) || node.id.as_str().contains(needle)
                    })
                })
                .collect();
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&matching)
                        .map_err(|error| CliError::Other(error.to_string()))?
                ),
                Format::Dmenu => {
                    for node in matching {
                        println!(
                            "{}",
                            output::dmenu_line(
                                node.id.as_str(),
                                &format!("{}  {}", node.name, node.summary())
                            )
                        );
                    }
                }
                _ => {
                    for node in matching {
                        let latency = runtime
                            .node_health
                            .get(&node.id)
                            .and_then(|h| h.ema_latency_ms)
                            .map_or_else(|| "   --".to_owned(), |ms| format!("{ms:>4}ms"));
                        println!(
                            "{:<24} {:<28} {:<34} {latency}",
                            node.id,
                            output::truncate(&node.name, 28),
                            node.summary()
                        );
                    }
                }
            }
            Ok(())
        }

        NodeCommand::Show { node } => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let id = parse_id::<xraytui_domain::NodeId>(&node, "node")?;
            let found = desired
                .nodes
                .get(&id)
                .ok_or_else(|| CliError::NotFound(format!("node '{node}' does not exist")))?;
            // `Debug` on a node prints `Secret(<redacted>)` for credentials.
            println!("{found:#?}");
            Ok(())
        }

        NodeCommand::Add(fields) => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let node = fields
                .draft()
                .create()
                .map_err(|error| CliError::Usage(error.to_string()))?;
            let id = node.id.clone();
            if desired.nodes.contains_key(&id) {
                return Err(CliError::Other(format!(
                    "node '{id}' already exists; edit it instead"
                )));
            }
            let mut next = (*desired).clone();
            next.nodes.insert(id.clone(), node);
            set_desired(client, next, quiet, &format!("node '{id}' added")).await
        }

        NodeCommand::Edit { node, fields } => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let id = parse_id::<xraytui_domain::NodeId>(&node, "node")?;
            let current = desired
                .nodes
                .get(&id)
                .ok_or_else(|| CliError::Other(format!("no node '{node}'")))?;
            let updated = fields
                .draft()
                .edit(current)
                .map_err(|error| CliError::Usage(error.to_string()))?;
            let mut next = (*desired).clone();
            next.nodes.insert(id.clone(), updated);
            set_desired(client, next, quiet, &format!("node '{id}' updated")).await
        }

        NodeCommand::Import(args) => {
            let (text, origin) = read_import_input(&args)?;
            let Response::Imported {
                added,
                unsupported,
                rejected,
            } = ask(client, Request::Import { text, origin }).await?
            else {
                return Err(CliError::Other("unexpected response".into()));
            };
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "added": added, "unsupported": unsupported, "rejected": rejected
                    }))
                    .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else if !quiet {
                println!("imported {} node(s)", added.len());
                for id in &added {
                    println!("  + {id}");
                }
                if unsupported > 0 {
                    println!("  {unsupported} entry/entries preserved as unsupported");
                }
                for reason in &rejected {
                    eprintln!("  ! {reason}");
                }
            }
            Ok(())
        }

        NodeCommand::Remove { node } => {
            let id = parse_id::<xraytui_domain::NodeId>(&node, "node")?;
            ask(client, Request::RemoveNode(id)).await?;
            if !quiet {
                println!("removed {node}");
            }
            Ok(())
        }

        NodeCommand::Test { node } => {
            let id = parse_id::<xraytui_domain::NodeId>(&node, "node")?;
            let Response::Probe(result) = ask(client, Request::Test(TestTarget::Node(id))).await?
            else {
                return Err(CliError::Other("unexpected response".into()));
            };
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&*result)
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                match (&result.outcome, result.latency_ms) {
                    (xraytui_domain::ProbeOutcome::Ok, Some(ms)) => println!("{node}: ok, {ms} ms"),
                    (outcome, _) => println!("{node}: {outcome:?}"),
                }
            }
            if !result.outcome.is_ok() {
                return Err(CliError::Other("probe failed".into()));
            }
            Ok(())
        }

        NodeCommand::Share(args) => share(client, args).await,
    }
}

async fn share(client: &mut Client, args: crate::args::ShareArgs) -> Result<(), CliError> {
    let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    let id = parse_id::<xraytui_domain::NodeId>(&args.node, "node")?;
    let node = desired
        .nodes
        .get(&id)
        .ok_or_else(|| CliError::NotFound(format!("node '{}' does not exist", args.node)))?;
    let link =
        xraytui_import::to_share_link(node).map_err(|error| CliError::Other(error.to_string()))?;

    // A share link is a credential. Say so once, on stderr, so piping the link
    // into another command still works.
    eprintln!("warning: {}", xraytui_import::qr::SECRET_WARNING);

    if let Some(path) = &args.png {
        xraytui_import::qr::render_png(link.expose(), path, 8)
            .map_err(|error| CliError::Other(error.to_string()))?;
        println!("wrote {}", path.display());
        return Ok(());
    }
    if args.qr {
        let rendered = if args.invert {
            xraytui_import::qr::render_terminal_inverted(link.expose())
        } else {
            xraytui_import::qr::render_terminal(link.expose())
        }
        .map_err(|error| CliError::Other(error.to_string()))?;
        print!("{rendered}");
        return Ok(());
    }
    println!("{}", link.expose());
    Ok(())
}

async fn group(client: &mut Client, command: GroupCommand, format: Format) -> Result<(), CliError> {
    let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    match command {
        GroupCommand::List => {
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&desired.groups.values().collect::<Vec<_>>())
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                for (id, group) in &desired.groups {
                    let members = desired.group_members(id);
                    println!(
                        "{:<20} {:<12} {} member(s): {}",
                        id,
                        format!("{:?}", group.strategy).to_lowercase(),
                        members.len(),
                        members
                            .iter()
                            .map(Target::short_label)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
            Ok(())
        }
        GroupCommand::Add {
            group,
            name,
            strategy,
            nodes,
        } => {
            let id = parse_id::<xraytui_domain::GroupId>(&group, "group")?;
            if desired.groups.contains_key(&id) {
                return Err(CliError::Other(format!("group '{group}' already exists")));
            }
            let strategy: xraytui_domain::GroupStrategy = serde_json::from_value(
                serde_json::Value::String(strategy.clone()),
            )
            .map_err(|_| {
                CliError::Usage(format!(
                    "unknown strategy '{strategy}'; expected manual, random, round-robin, \
                     least-ping or least-load"
                ))
            })?;
            let mut members = Vec::new();
            for node in &nodes {
                let node_id = parse_id::<xraytui_domain::NodeId>(node, "node")?;
                if !desired.nodes.contains_key(&node_id) {
                    return Err(CliError::Other(format!("no node '{node}'")));
                }
                members.push(node_id);
            }
            if members.is_empty() {
                return Err(CliError::Usage(
                    "a group needs at least one --node".to_owned(),
                ));
            }
            let first = members[0].clone();
            let mut next = (*desired).clone();
            next.groups.insert(
                id.clone(),
                xraytui_domain::Group {
                    id: id.clone(),
                    name: name.unwrap_or_else(|| group.clone()),
                    strategy,
                    membership: xraytui_domain::GroupMembership {
                        nodes: members,
                        ..Default::default()
                    },
                    // A manual group with nothing selected has no target at
                    // all, so the first member is chosen rather than leaving
                    // the group unusable until somebody notices.
                    manual_selection: (strategy == xraytui_domain::GroupStrategy::Manual)
                        .then_some(Target::Node { id: first }),
                    fallback: None,
                },
            );
            set_desired(client, next, false, &format!("group '{group}' added")).await
        }

        GroupCommand::Remove { group } => {
            let id = parse_id::<xraytui_domain::GroupId>(&group, "group")?;
            let mut next = (*desired).clone();
            if next.groups.remove(&id).is_none() {
                return Err(CliError::Other(format!("no group '{group}'")));
            }
            let pointing: Vec<String> = next
                .profiles
                .iter()
                .filter(
                    |(_, profile)| matches!(&profile.target, Target::Group { id: g } if g == &id),
                )
                .map(|(profile_id, _)| profile_id.to_string())
                .collect();
            if !pointing.is_empty() {
                return Err(CliError::Other(format!(
                    "profile(s) {} still point at group '{group}'; point them elsewhere first",
                    pointing.join(", ")
                )));
            }
            set_desired(client, next, false, &format!("group '{group}' removed")).await
        }

        GroupCommand::Test { group } => {
            let id = parse_id::<xraytui_domain::GroupId>(&group, "group")?;
            let Response::Probe(result) = ask(client, Request::Test(TestTarget::Group(id))).await?
            else {
                return Err(CliError::Other("unexpected response".into()));
            };
            println!("{group}: {:?}", result.outcome);
            Ok(())
        }
        GroupCommand::Select { group, target } => {
            let id = parse_id::<xraytui_domain::GroupId>(&group, "group")?;
            let target: Target =
                target
                    .parse()
                    .map_err(|error: xraytui_domain::TargetParseError| {
                        CliError::Usage(error.to_string())
                    })?;
            ask(
                client,
                Request::SetGroupSelection {
                    group: id,
                    target: target.clone(),
                },
            )
            .await?;
            println!("{group} -> {}", target.to_token());
            Ok(())
        }
    }
}

async fn chain(client: &mut Client, command: ChainCommand, format: Format) -> Result<(), CliError> {
    let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    match command {
        ChainCommand::List => {
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&desired.chains.values().collect::<Vec<_>>())
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                for (id, chain) in &desired.chains {
                    // Printed in traffic order: local first, exit last.
                    println!("{:<20} Local -> {} -> Internet", id, chain.describe());
                }
            }
            Ok(())
        }
        ChainCommand::Add { chain, name, hops } => {
            let id = parse_id::<xraytui_domain::ChainId>(&chain, "chain")?;
            if desired.chains.contains_key(&id) {
                return Err(CliError::Other(format!("chain '{chain}' already exists")));
            }
            if hops.len() < 2 {
                return Err(CliError::Usage(
                    "a chain needs at least two --hop values: one hop is just a node".to_owned(),
                ));
            }
            let mut resolved = Vec::new();
            for hop in &hops {
                let node_id = parse_id::<xraytui_domain::NodeId>(hop, "node")?;
                if !desired.nodes.contains_key(&node_id) {
                    return Err(CliError::Other(format!("no node '{hop}'")));
                }
                resolved.push(node_id);
            }
            let mut next = (*desired).clone();
            next.chains.insert(
                id.clone(),
                xraytui_domain::Chain {
                    id: id.clone(),
                    name: name.unwrap_or_else(|| chain.clone()),
                    hops: resolved,
                    enabled: true,
                },
            );
            set_desired(client, next, false, &format!("chain '{chain}' added")).await
        }

        ChainCommand::Remove { chain } => {
            let id = parse_id::<xraytui_domain::ChainId>(&chain, "chain")?;
            let mut next = (*desired).clone();
            if next.chains.remove(&id).is_none() {
                return Err(CliError::Other(format!("no chain '{chain}'")));
            }
            let pointing: Vec<String> = next
                .profiles
                .iter()
                .filter(
                    |(_, profile)| matches!(&profile.target, Target::Chain { id: c } if c == &id),
                )
                .map(|(profile_id, _)| profile_id.to_string())
                .collect();
            if !pointing.is_empty() {
                return Err(CliError::Other(format!(
                    "profile(s) {} still point at chain '{chain}'; point them elsewhere first",
                    pointing.join(", ")
                )));
            }
            set_desired(client, next, false, &format!("chain '{chain}' removed")).await
        }

        ChainCommand::Test { chain } => {
            let id = parse_id::<xraytui_domain::ChainId>(&chain, "chain")?;
            let Response::Probe(result) = ask(client, Request::Test(TestTarget::Chain(id))).await?
            else {
                return Err(CliError::Other("unexpected response".into()));
            };
            println!("{chain}: {:?}", result.outcome);
            Ok(())
        }
    }
}

async fn rule(client: &mut Client, command: RuleCommand, format: Format) -> Result<(), CliError> {
    match command {
        RuleCommand::List => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let mut rules: Vec<_> = desired.routing_rules.values().collect();
            rules.sort_by_key(|rule| (rule.priority, rule.id.clone()));
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rules)
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                for rule in rules {
                    let kinds: Vec<&str> = rule.matcher.condition_kinds().into_iter().collect();
                    println!(
                        "{:>6}  {:<24} {:<20} {}{}",
                        rule.priority,
                        rule.id,
                        rule.action.to_token(),
                        kinds.join("+"),
                        if rule.enabled { "" } else { "  (disabled)" }
                    );
                }
            }
            Ok(())
        }
        RuleCommand::Enable { rule } => set_rule_enabled(client, &rule, true).await,
        RuleCommand::Disable { rule } => set_rule_enabled(client, &rule, false).await,
        RuleCommand::Remove { rule } => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let mut next = (*desired).clone();
            let app_id = xraytui_domain::AppRuleId::new(&rule).ok();
            let routing_id = xraytui_domain::RoutingRuleId::new(&rule).ok();
            let removed = app_id
                .as_ref()
                .is_some_and(|id| next.app_rules.remove(id).is_some())
                || routing_id
                    .as_ref()
                    .is_some_and(|id| next.routing_rules.remove(id).is_some());
            if !removed {
                return Err(CliError::Other(format!("no rule '{rule}'")));
            }
            set_desired(client, next, false, &format!("rule '{rule}' removed")).await
        }

        RuleCommand::Explain { query, network } => {
            let (domain, ip, port) = split_query(&query);
            let Response::RouteDecision {
                outbound, groups, ..
            } = ask(
                client,
                Request::ExplainRoute {
                    domain,
                    ip,
                    port,
                    network,
                    inbound_tag: None,
                },
            )
            .await?
            else {
                return Err(CliError::Other("unexpected response".into()));
            };
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"outbound": outbound, "groups": groups})
                    )
                    .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                println!("{query} -> {outbound}");
                if !groups.is_empty() {
                    println!("  via balancer(s): {}", groups.join(", "));
                }
            }
            Ok(())
        }
        RuleCommand::Validate => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let Response::Diagnostics(diagnostics) =
                ask(client, Request::Validate(Box::new(*desired))).await?
            else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let mut errors = 0;
            for diagnostic in &diagnostics {
                let severity = match diagnostic.severity {
                    xraytui_domain::Severity::Error => {
                        errors += 1;
                        "error"
                    }
                    xraytui_domain::Severity::Warning => "warning",
                };
                println!("{severity}: [{}] {}", diagnostic.code, diagnostic.message);
            }
            if errors > 0 {
                return Err(CliError::Other(format!("{errors} error(s)")));
            }
            println!("configuration is valid");
            Ok(())
        }
    }
}

async fn subscription(
    client: &mut Client,
    command: SubscriptionCommand,
    format: Format,
) -> Result<(), CliError> {
    match command {
        SubscriptionCommand::List => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &desired
                            .subscriptions
                            .values()
                            // The URL is a credential, so the JSON view omits it.
                            .map(|s| serde_json::json!({
                                "id": s.id, "name": s.name, "enabled": s.enabled,
                                "nodes": s.meta.node_count
                            }))
                            .collect::<Vec<_>>()
                    )
                    .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                for (id, subscription) in &desired.subscriptions {
                    println!(
                        "{:<20} {:<28} {} node(s){}",
                        id,
                        subscription.name,
                        subscription.meta.node_count,
                        if subscription.enabled {
                            ""
                        } else {
                            "  (disabled)"
                        }
                    );
                }
            }
            Ok(())
        }
        SubscriptionCommand::Add {
            url,
            name,
            allow_plaintext,
        } => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let name = name.unwrap_or_else(|| subscription_name_from(&url));
            let id = xraytui_domain::SubscriptionId::new(xraytui_domain::slugify(&name))
                .map_err(|error| CliError::Usage(error.to_string()))?;
            if desired.subscriptions.contains_key(&id) {
                return Err(CliError::Other(format!(
                    "subscription '{id}' already exists"
                )));
            }
            let mut next = (*desired).clone();
            next.subscriptions.insert(
                id.clone(),
                xraytui_domain::Subscription {
                    id: id.clone(),
                    name,
                    url: xraytui_secrets::Secret::new(url),
                    enabled: true,
                    // Six hours: often enough that a provider's changes arrive
                    // the same day, rare enough that a laptop is not fetching
                    // on every wake.
                    update_interval_secs: Some(6 * 60 * 60),
                    fetch_via_profile: None,
                    include_regex: Vec::new(),
                    exclude_regex: Vec::new(),
                    max_response_bytes: None,
                    max_nodes: None,
                    allow_plaintext,
                    meta: xraytui_domain::SubscriptionMeta::default(),
                },
            );
            // The URL is never echoed: it carries a bearer token.
            set_desired(
                client,
                next,
                false,
                &format!("subscription '{id}' added; run `xraytui subscription update {id}`"),
            )
            .await
        }

        SubscriptionCommand::Update { id, all, yes: _ } => {
            let request = match (id, all) {
                (Some(id), _) => Request::SubscriptionUpdate(parse_id::<
                    xraytui_domain::SubscriptionId,
                >(
                    &id, "subscription"
                )?),
                (None, true) => Request::SubscriptionUpdateAll,
                (None, false) => {
                    return Err(CliError::Usage(
                        "name a subscription, or pass --all".to_owned(),
                    ));
                }
            };
            let response = ask(client, request).await?;
            print_subscription_result(&response);
            Ok(())
        }

        SubscriptionCommand::Diff { id } => {
            let response = ask(
                client,
                Request::SubscriptionDiff(parse_id::<xraytui_domain::SubscriptionId>(
                    &id,
                    "subscription",
                )?),
            )
            .await?;
            print_subscription_result(&response);
            Ok(())
        }

        SubscriptionCommand::Remove { id } => {
            let Response::State { desired, .. } = ask(client, Request::GetState).await? else {
                return Err(CliError::Other("unexpected response".into()));
            };
            let id = parse_id::<xraytui_domain::SubscriptionId>(&id, "subscription")?;
            let mut next = (*desired).clone();
            if next.subscriptions.remove(&id).is_none() {
                return Err(CliError::Other(format!("no subscription '{id}'")));
            }
            // The nodes it owns go with it: leaving them behind would leave
            // entries nobody can update and nobody remembers agreeing to.
            let owned: Vec<_> = next
                .nodes
                .iter()
                .filter(|(_, node)| node.source.subscription() == Some(&id))
                .map(|(node_id, _)| node_id.clone())
                .collect();
            for node in &owned {
                next.nodes.remove(node);
            }
            set_desired(
                client,
                next,
                false,
                &format!("subscription '{id}' removed with {} node(s)", owned.len()),
            )
            .await
        }
    }
}

/// A readable name from a URL, when the user did not give one.
///
/// The host, not the whole URL: a subscription URL carries a token, and a
/// token in a display name would end up in every listing and every log.
fn subscription_name_from(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|host| host.split('@').next_back())
        .map_or_else(|| "subscription".to_owned(), str::to_owned)
}

/// Print an update or diff result.
fn print_subscription_result(response: &Response) {
    match response {
        Response::Diff(diff) => {
            let counts = diff.counts();
            println!(
                "{} added, {} changed, {} removed, {} unsupported, {} rejected",
                counts.added, counts.changed, counts.removed, counts.unsupported, counts.rejected
            );
            for change in &diff.changes {
                match change {
                    xraytui_domain::NodeChange::Added { node } => {
                        println!("  + {}", node.name);
                    }
                    xraytui_domain::NodeChange::Changed { id, fields, .. } => {
                        println!("  ~ {id} ({})", fields.join(", "));
                    }
                    other => println!("  · {other:?}"),
                }
            }
        }
        Response::Imported { added, .. } => {
            println!("{} node(s) imported", added.len());
        }
        Response::Applied { warnings, .. } => {
            for warning in warnings {
                eprintln!("xraytui: {warning}");
            }
            if warnings.is_empty() {
                println!("up to date");
            }
        }
        other => println!("{other:?}"),
    }
}

async fn runtime_info(
    client: &mut Client,
    command: RuntimeCommand,
    format: Format,
) -> Result<(), CliError> {
    let Response::Runtime(runtime) = ask(client, Request::GetRuntime).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    match command {
        RuntimeCommand::Stats => {
            if format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&runtime.total_traffic)
                        .map_err(|error| CliError::Other(error.to_string()))?
                );
            } else {
                println!(
                    "total   ↑ {}   ↓ {}",
                    output::human_bytes(runtime.total_traffic.uplink_bytes),
                    output::human_bytes(runtime.total_traffic.downlink_bytes)
                );
                for profile in &runtime.profiles {
                    println!(
                        "{:<14} ↑ {:<12} ↓ {}",
                        profile.id,
                        output::human_bytes(profile.traffic.uplink_bytes),
                        output::human_bytes(profile.traffic.downlink_bytes)
                    );
                }
            }
            Ok(())
        }
        RuntimeCommand::Connections { follow } => {
            if follow {
                return follow_events(
                    client,
                    xraytui_ipc::SubscriptionFilter {
                        connections: true,
                        ..Default::default()
                    },
                )
                .await;
            }
            println!("no buffered connections; use --follow to watch live decisions");
            Ok(())
        }
    }
}

async fn logs(client: &mut Client, follow: bool) -> Result<(), CliError> {
    if !follow {
        println!("use --follow to stream the daemon and core logs");
        return Ok(());
    }
    follow_events(
        client,
        xraytui_ipc::SubscriptionFilter {
            logs: true,
            ..Default::default()
        },
    )
    .await
}

async fn follow_events(
    client: &mut Client,
    filter: xraytui_ipc::SubscriptionFilter,
) -> Result<(), CliError> {
    let mut stream = client.subscribe(filter).await?;
    while let Some(event) = stream.next().await {
        match event {
            xraytui_ipc::Event::Log {
                level,
                target,
                message,
                ..
            } => {
                println!("{level:<5} {target:<24} {message}");
            }
            xraytui_ipc::Event::Connection(record) => {
                println!(
                    "{:<28} -> {:<28} {}",
                    record
                        .domain
                        .clone()
                        .or(record.ip.clone())
                        .unwrap_or_default(),
                    record.outbound,
                    record.rule_tag.unwrap_or_default()
                );
            }
            xraytui_ipc::Event::Lagged { dropped } => {
                eprintln!("xraytui: dropped {dropped} event(s); the terminal cannot keep up");
            }
            _ => {}
        }
        std::io::stdout().flush().ok();
    }
    Ok(())
}

async fn show_config(client: &mut Client) -> Result<(), CliError> {
    let Response::GeneratedConfig(json) = ask(client, Request::GetGeneratedConfig).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    eprintln!(
        "warning: this configuration contains node credentials in clear text; do not paste it \
         into a bug report"
    );
    print!("{json}");
    Ok(())
}

async fn run_exec(client: &mut Client, args: crate::args::ExecArgs) -> Result<(), CliError> {
    let Response::State { desired, runtime } = ask(client, Request::GetState).await? else {
        return Err(CliError::Other("unexpected response".into()));
    };
    let id = parse_id::<xraytui_domain::ProfileId>(&args.profile, "profile")?;
    if !desired.profiles.contains_key(&id) {
        return Err(CliError::NotFound(format!(
            "profile '{}' does not exist",
            args.profile
        )));
    }
    let live = runtime.profile(&id).ok_or(CliError::CoreDown)?;
    let no_proxy = args
        .no_proxy
        .clone()
        .unwrap_or_else(|| exec::ProxyEnvironment::default_no_proxy().to_owned());
    let environment = exec::ProxyEnvironment::build(
        live.socks_listen.as_deref(),
        live.http_listen.as_deref(),
        &no_proxy,
    );
    if environment.variables.len() <= 2 {
        return Err(CliError::Usage(format!(
            "profile '{}' has no SOCKS or HTTP listener, so there is nothing to point the \
             command at. Add `socks_listen` to it in profiles.toml.",
            args.profile
        )));
    }
    exec::run_with_environment(&environment, &args.command)?;
    Ok(())
}

/// `xraytui exec --transparent` — classify this process, then become the command.
///
/// Everything is checked before anything is done, and every failure is fatal:
/// the alternative is starting the command with its traffic going somewhere the
/// user did not ask for, while reporting success.
async fn run_exec_transparent(
    paths: &xraytui_config::Paths,
    args: &crate::args::ExecArgs,
) -> Result<(), CliError> {
    if let Err(reason) = exec::check_transparent_available(&args.profile) {
        return Err(CliError::Other(reason.to_string()));
    }
    let id = parse_id::<xraytui_domain::ProfileId>(&args.profile, "profile")?;
    let desired =
        xraytui_config::store::load(paths).map_err(|error| CliError::Other(error.to_string()))?;
    let profile = desired
        .profiles
        .get(&id)
        .ok_or_else(|| CliError::NotFound(format!("profile '{}' does not exist", args.profile)))?;
    let Some(listener) = profile.transparent.as_ref().filter(|_| profile.enabled) else {
        return Err(CliError::Other(
            exec::TransparentUnavailable::NoInbound {
                profile: args.profile.clone(),
            }
            .to_string(),
        ));
    };
    // The redirect points at this address, so if nothing is listening the
    // traffic would be dropped by the kernel rather than proxied. Asking whether
    // the port can still be *bound* answers that without connecting to it —
    // which matters, because connecting to a transparent listener is exactly the
    // loop the ruleset exists to prevent.
    if std::net::TcpListener::bind(listener.listen).is_ok() {
        return Err(CliError::Other(
            exec::TransparentUnavailable::NotListening {
                profile: args.profile.clone(),
                address: listener.listen.to_string(),
            }
            .to_string(),
        ));
    }
    exec::classify_and_exec(&exec::netd_socket(), &args.profile, &args.command).await?;
    unreachable!("classify_and_exec does not return on success")
}

// ------------------------------------------------------------------ helpers

fn parse_id<T: std::str::FromStr<Err = xraytui_domain::IdError>>(
    raw: &str,
    kind: &str,
) -> Result<T, CliError> {
    raw.trim()
        .parse()
        .map_err(|error| CliError::Usage(format!("invalid {kind} identifier: {error}")))
}

fn read_stdin_token() -> Result<String, CliError> {
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|source| CliError::Io {
            context: "reading standard input".into(),
            source,
        })?;
    output::dmenu_id(&buffer).ok_or_else(|| CliError::Usage("standard input was empty".to_owned()))
}

fn read_import_input(args: &crate::args::ImportArgs) -> Result<(String, ImportOrigin), CliError> {
    if let Some(path) = &args.xray_json {
        let text = std::fs::read_to_string(path).map_err(|source| CliError::Io {
            context: format!("reading {}", path.display()),
            source,
        })?;
        return Ok((text, ImportOrigin::XrayJson));
    }
    if let Some(path) = &args.file {
        let text = std::fs::read_to_string(path).map_err(|source| CliError::Io {
            context: format!("reading {}", path.display()),
            source,
        })?;
        return Ok((
            text,
            ImportOrigin::File {
                path: path.display().to_string(),
            },
        ));
    }
    if let Some(path) = &args.qr {
        let decoded = xraytui_import::qr::decode_png(path)
            .map_err(|error| CliError::Other(error.to_string()))?;
        return Ok((decoded.join("\n"), ImportOrigin::Manual));
    }
    if args.stdin {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|source| CliError::Io {
                context: "reading standard input".into(),
                source,
            })?;
        return Ok((buffer, ImportOrigin::Manual));
    }
    if args.clipboard {
        return Err(CliError::Other(
            "clipboard import needs an X11 or Wayland clipboard tool; pipe it instead:\n  \
             xclip -o -selection clipboard | xraytui node import --stdin"
                .to_owned(),
        ));
    }
    let input = args
        .input
        .clone()
        .ok_or_else(|| CliError::Usage("give a share link, or use --stdin/--file".to_owned()))?;
    Ok((input, ImportOrigin::Manual))
}

/// Split `host:port`, a bare host, or an IP into the parts `TestRoute` wants.
fn split_query(query: &str) -> (Option<String>, Option<String>, u16) {
    let (host, port) = match query.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (host, port.parse().unwrap_or(443))
        }
        _ => (query, 443),
    };
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.parse::<std::net::IpAddr>().is_ok() {
        (None, Some(host.to_owned()), port)
    } else {
        (Some(host.to_owned()), None, port)
    }
}

fn print_completion(shell: Shell) -> Result<(), CliError> {
    use clap::CommandFactory;
    let mut command = Cli::command();
    let name = command.get_name().to_owned();
    let generator: clap_complete::Shell = match shell {
        Shell::Bash => clap_complete::Shell::Bash,
        Shell::Zsh => clap_complete::Shell::Zsh,
        Shell::Fish => clap_complete::Shell::Fish,
    };
    clap_complete::generate(generator, &mut command, name, &mut std::io::stdout());
    Ok(())
}

fn write_manpages(directory: &std::path::Path) -> Result<(), CliError> {
    use clap::CommandFactory;
    std::fs::create_dir_all(directory).map_err(|source| CliError::Io {
        context: format!("creating {}", directory.display()),
        source,
    })?;
    let command = Cli::command();
    write_manpage(directory, &command, "xraytui")?;
    for sub in command.get_subcommands() {
        let name = format!("xraytui-{}", sub.get_name());
        write_manpage(directory, sub, &name)?;
    }
    Ok(())
}

fn write_manpage(
    directory: &std::path::Path,
    command: &clap::Command,
    name: &str,
) -> Result<(), CliError> {
    let man = clap_mangen::Man::new(command.clone())
        .title(name.to_uppercase())
        .section("1");
    let mut buffer = Vec::new();
    man.render(&mut buffer).map_err(|source| CliError::Io {
        context: format!("rendering {name}.1"),
        source,
    })?;
    let path = directory.join(format!("{name}.1"));
    std::fs::write(&path, buffer).map_err(|source| CliError::Io {
        context: format!("writing {}", path.display()),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_split_into_the_right_route_test_fields() {
        assert_eq!(
            split_query("example.com"),
            (Some("example.com".to_owned()), None, 443)
        );
        assert_eq!(
            split_query("example.com:80"),
            (Some("example.com".to_owned()), None, 80)
        );
        assert_eq!(
            split_query("1.2.3.4"),
            (None, Some("1.2.3.4".to_owned()), 443)
        );
        assert_eq!(
            split_query("1.2.3.4:8080"),
            (None, Some("1.2.3.4".to_owned()), 8080)
        );
        assert_eq!(
            split_query("[2001:db8::1]:443"),
            (None, Some("2001:db8::1".to_owned()), 443)
        );
    }

    #[test]
    fn identifier_parsing_reports_usage_errors() {
        let error = parse_id::<xraytui_domain::NodeId>("NOT VALID", "node").expect_err("must fail");
        assert!(matches!(error, CliError::Usage(_)), "{error:?}");
        assert_eq!(error.exit_code(), crate::EXIT_FAILURE);
    }

    #[test]
    fn valid_identifiers_parse() {
        let id: xraytui_domain::NodeId = parse_id("hk-01", "node").expect("valid");
        assert_eq!(id.as_str(), "hk-01");
    }

    #[test]
    fn completion_scripts_are_generated_for_every_shell() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            print_completion(shell).expect("generate");
        }
    }

    #[test]
    fn man_pages_are_written_for_every_subcommand() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_manpages(dir.path()).expect("write");
        assert!(dir.path().join("xraytui.1").is_file());
        assert!(dir.path().join("xraytui-profile.1").is_file());
        assert!(dir.path().join("xraytui-node.1").is_file());
        let contents = std::fs::read_to_string(dir.path().join("xraytui.1")).expect("read");
        assert!(contents.contains("XRAYTUI"), "{contents:.200}");
    }

    #[test]
    fn rule_action_tokens_are_understood_by_the_cli_layer() {
        // Guards against the CLI and the domain drifting apart on token syntax.
        for token in ["profile:web", "node:hk-01", "direct", "block", "default"] {
            assert!(
                token.parse::<xraytui_domain::RuleAction>().is_ok(),
                "{token}"
            );
        }
    }
}
