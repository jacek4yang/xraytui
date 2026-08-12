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
        Some(Command::Manpages { directory }) => return write_manpages(directory),
        Some(Command::Exec(args)) if args.transparent => {
            if let Err(reason) = exec::check_transparent_available(&args.profile) {
                return Err(CliError::Other(reason.to_string()));
            }
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
        Some(Command::Node(command)) => node(&mut client, command, cli.format, cli.quiet).await,
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
        Some(Command::Completion { .. } | Command::Manpages { .. }) => Ok(()),
    }
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
        crate::args::AppCommand::Assign { profile, matcher } => Err(CliError::Other(format!(
            "editing application rules is not wired into this build; \
             add them to rules.toml instead:\n\n\
             [[application_rule]]\n\
             id = \"{}-rule\"\n\
             priority = 100\n\
             process = [\"{matcher}\"]\n\
             action = {{ kind = \"profile\", id = \"{profile}\" }}\n",
            xraytui_domain::slugify(&matcher)
        ))),
        crate::args::AppCommand::Unassign { rule } => Err(CliError::Other(format!(
            "remove the `[[application_rule]]` entry with id = \"{rule}\" from rules.toml"
        ))),
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
        SubscriptionCommand::Add { .. }
        | SubscriptionCommand::Update { .. }
        | SubscriptionCommand::Diff { .. } => Err(CliError::Other(
            "subscription fetching is not part of this build; see STATUS.md for what \
             is implemented. Nodes can still be imported with `xraytui node import`."
                .to_owned(),
        )),
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
