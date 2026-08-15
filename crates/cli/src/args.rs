//! The clap command surface.
//!
//! Shaped for scripting first: every read-only command takes `--format`, every
//! state-changing command is a single verb, and exit codes are stable so shell
//! conditionals work. See `docs/DWM-INTEGRATION.md` for the dmenu recipes.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Top-level command line.
#[derive(Debug, Parser)]
#[command(
    name = "xraytui",
    version,
    about = "Terminal client for Xray-core with multiple concurrent egress profiles",
    long_about = "xraytui manages several independent egress profiles through one supervised\n\
                  Xray-core process. Different applications can use different proxies at the\n\
                  same time, and each profile's target can be switched without restarting the\n\
                  core.\n\n\
                  Running with no subcommand opens the interactive interface.",
    propagate_version = true,
    disable_help_subcommand = false
)]
pub struct Cli {
    /// Use this directory instead of the XDG locations.
    #[arg(long, global = true, value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Output format for read-only commands.
    #[arg(long, short, global = true, value_enum, default_value_t = Format::Plain)]
    pub format: Format,

    /// Suppress informational output; errors still go to stderr.
    #[arg(long, short, global = true)]
    pub quiet: bool,

    /// Increase log verbosity. Repeat for more.
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// What to do.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable columns.
    Plain,
    /// Machine-readable JSON.
    Json,
    /// `id<TAB>label` lines for piping into dmenu.
    Dmenu,
    /// A single short line for a status bar.
    Dwmblocks,
    /// `KEY=value` lines for `eval` in a shell.
    Shell,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Open the interactive interface.
    Tui,
    /// Show a one-line summary of the current state.
    Status,
    /// Start the Xray core.
    Up,
    /// Stop the Xray core.
    Down,
    /// Restart the Xray core.
    Restart,
    /// Check the environment and report problems.
    Doctor,
    /// Read or change the system mode.
    #[command(subcommand)]
    Mode(ModeCommand),
    /// Inspect or change the system TUN.
    #[command(subcommand)]
    Tun(TunCommand),
    /// Manage egress profiles.
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// List selectable targets.
    #[command(subcommand)]
    Target(TargetCommand),
    /// Manage per-application rules.
    #[command(subcommand)]
    App(AppCommand),
    /// Run a command with its traffic sent through a profile.
    Exec(ExecArgs),
    /// Create the directories, configuration and state database, then stop.
    ///
    /// Touches nothing outside your own XDG directories: no routes, no DNS, no
    /// services, no packages.
    Init {
        /// Overwrite an existing config.toml with the defaults.
        #[arg(long)]
        force: bool,
    },
    /// Manage nodes.
    #[command(subcommand)]
    Node(NodeCommand),
    /// Manage groups.
    #[command(subcommand)]
    Group(GroupCommand),
    /// Manage chains.
    #[command(subcommand)]
    Chain(ChainCommand),
    /// Inspect routing rules.
    #[command(subcommand)]
    Rule(RuleCommand),
    /// Manage subscriptions.
    #[command(subcommand, alias = "sub")]
    Subscription(SubscriptionCommand),
    /// Follow the daemon and core logs.
    Logs(LogsArgs),
    /// Inspect live runtime information.
    #[command(subcommand)]
    Runtime(RuntimeCommand),
    /// Print the generated Xray configuration.
    ShowConfig,
    /// Print a shell completion script.
    Completion {
        /// Which shell.
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Write man pages to a directory.
    Manpages {
        /// Output directory.
        #[arg(value_name = "DIR")]
        directory: PathBuf,
    },
}

/// Shells with completion support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// GNU Bash.
    Bash,
    /// Z shell.
    Zsh,
    /// Fish.
    Fish,
}

/// `xraytui mode …`
#[derive(Debug, Subcommand)]
pub enum ModeCommand {
    /// Print the current mode.
    Get,
    /// Set the mode.
    Set {
        /// `off`, `direct`, `global` or `rule`.
        mode: String,
    },
    /// Advance to the next mode.
    Cycle,
}

/// `xraytui tun …`
#[derive(Debug, Subcommand)]
pub enum TunCommand {
    /// Show TUN status.
    Status,
    /// Enable the system TUN by switching to rule mode.
    Enable,
    /// Disable the system TUN.
    Disable,
    /// Print the network changes enabling TUN would make, without making them.
    Plan,
}

/// `xraytui profile …`
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List profiles.
    List,
    /// Show one profile in detail.
    Show {
        /// Profile identifier.
        profile: String,
    },
    /// Point a profile at a target.
    SetTarget {
        /// Profile identifier.
        profile: String,
        /// `node:ID`, `group:ID`, `chain:ID`, `direct` or `block`.
        #[arg(required_unless_present = "stdin")]
        target: Option<String>,
        /// Read the target from standard input instead.
        #[arg(long)]
        stdin: bool,
    },
    /// Read `id<TAB>label` from standard input and select that profile.
    ///
    /// The counterpart to `profile list --format dmenu`.
    SelectFromStdin,
}

/// `xraytui target …`
#[derive(Debug, Subcommand)]
pub enum TargetCommand {
    /// List every selectable target.
    List {
        /// Restrict to targets usable by this profile.
        #[arg(long)]
        profile: Option<String>,
    },
}

/// `xraytui app …`
#[derive(Debug, Subcommand)]
pub enum AppCommand {
    /// List application rules.
    List,
    /// Assign a process matcher to a profile.
    Assign {
        /// Profile identifier.
        profile: String,
        /// Process name, absolute path, or directory ending in `/`.
        matcher: String,
    },
    /// Remove an application rule.
    Unassign {
        /// Rule identifier.
        rule: String,
    },
}

/// `xraytui exec …`
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Profile whose egress the command should use.
    #[arg(long, short)]
    pub profile: String,
    /// Use the cgroup v2 transparent backend instead of proxy environment
    /// variables. Requires the privileged helper and kernel support.
    #[arg(long)]
    pub transparent: bool,
    /// Hosts and CIDRs that bypass the proxy.
    #[arg(long, value_name = "LIST")]
    pub no_proxy: Option<String>,
    /// The command and its arguments.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// `xraytui node …`
#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// List nodes.
    List {
        /// Only nodes whose name matches this substring.
        #[arg(long)]
        filter: Option<String>,
    },
    /// Show one node in detail, with credentials redacted.
    Show {
        /// Node identifier.
        node: String,
    },
    /// Import nodes from a share link, a file, standard input or the clipboard.
    Import(ImportArgs),
    /// Remove a node.
    Remove {
        /// Node identifier.
        node: String,
    },
    /// Probe a node.
    Test {
        /// Node identifier.
        node: String,
    },
    /// Print a node's share link.
    Share(ShareArgs),
}

/// `xraytui node import …`
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// A share link. Omit when using another input.
    pub input: Option<String>,
    /// Read links from standard input.
    #[arg(long)]
    pub stdin: bool,
    /// Read links from a file.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
    /// Read links from the clipboard.
    #[arg(long)]
    pub clipboard: bool,
    /// Read an Xray configuration and import its outbounds.
    #[arg(long, value_name = "PATH")]
    pub xray_json: Option<PathBuf>,
    /// Decode a QR code image.
    #[arg(long, value_name = "PATH")]
    pub qr: Option<PathBuf>,
}

/// `xraytui node share …`
#[derive(Debug, Args)]
pub struct ShareArgs {
    /// Node identifier.
    pub node: String,
    /// Render the link as a terminal QR code.
    #[arg(long)]
    pub qr: bool,
    /// Invert the QR code, for dark terminals.
    #[arg(long, requires = "qr")]
    pub invert: bool,
    /// Write the QR code to a PNG file.
    #[arg(long, value_name = "FILE")]
    pub png: Option<PathBuf>,
    /// Copy the link to the clipboard instead of printing it.
    #[arg(long)]
    pub clipboard: bool,
}

/// `xraytui group …`
#[derive(Debug, Subcommand)]
pub enum GroupCommand {
    /// List groups and their members.
    List,
    /// Probe every member of a group.
    Test {
        /// Group identifier.
        group: String,
    },
    /// Choose a member of a manual group.
    Select {
        /// Group identifier.
        group: String,
        /// Target token.
        target: String,
    },
}

/// `xraytui chain …`
#[derive(Debug, Subcommand)]
pub enum ChainCommand {
    /// List chains in traffic order.
    List,
    /// Probe a chain end to end.
    Test {
        /// Chain identifier.
        chain: String,
    },
}

/// `xraytui rule …`
#[derive(Debug, Subcommand)]
pub enum RuleCommand {
    /// List rules in evaluation order.
    List,
    /// Ask the core which outbound a destination would take.
    Explain {
        /// A domain, an IP, or `host:port`.
        query: String,
        /// `tcp` or `udp`.
        #[arg(long, default_value = "tcp")]
        network: String,
    },
    /// Validate the rule set without applying it.
    Validate,
}

/// `xraytui subscription …`
#[derive(Debug, Subcommand)]
pub enum SubscriptionCommand {
    /// List subscriptions.
    List,
    /// Add a subscription.
    Add {
        /// Subscription URL.
        url: String,
        /// Display name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Update one subscription, or every enabled one with `--all`.
    Update {
        /// Subscription identifier.
        id: Option<String>,
        /// Update every enabled subscription.
        #[arg(long)]
        all: bool,
        /// Do not ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Show what an update would change, without committing it.
    Diff {
        /// Subscription identifier.
        id: String,
    },
}

/// `xraytui logs …`
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Keep following new lines.
    #[arg(long)]
    pub follow: bool,
    /// Show at most this many buffered lines first.
    #[arg(long, short = 'n', default_value_t = 50)]
    pub lines: usize,
}

/// `xraytui runtime …`
#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// Show recent routing decisions.
    Connections {
        /// Keep following.
        #[arg(long)]
        follow: bool,
    },
    /// Show traffic counters.
    Stats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_subcommand_means_the_interactive_interface() {
        let cli = Cli::try_parse_from(["xraytui"]).expect("parse");
        assert!(cli.command.is_none());
    }

    #[test]
    fn the_specified_command_surface_parses() {
        // Every invocation listed in the project specification.
        let invocations: Vec<Vec<&str>> = vec![
            vec!["xraytui", "tui"],
            vec!["xraytui", "status"],
            vec!["xraytui", "up"],
            vec!["xraytui", "down"],
            vec!["xraytui", "restart"],
            vec!["xraytui", "doctor"],
            vec!["xraytui", "mode", "get"],
            vec!["xraytui", "mode", "set", "direct"],
            vec!["xraytui", "mode", "set", "global"],
            vec!["xraytui", "mode", "set", "rule"],
            vec!["xraytui", "mode", "set", "off"],
            vec!["xraytui", "mode", "cycle"],
            vec!["xraytui", "tun", "status"],
            vec!["xraytui", "tun", "enable"],
            vec!["xraytui", "tun", "disable"],
            vec!["xraytui", "tun", "plan"],
            vec!["xraytui", "profile", "list"],
            vec!["xraytui", "profile", "show", "web"],
            vec!["xraytui", "profile", "set-target", "web", "node:hk-01"],
            vec!["xraytui", "app", "list"],
            vec!["xraytui", "app", "assign", "web", "firefox"],
            vec!["xraytui", "app", "unassign", "firefox-web"],
            vec![
                "xraytui",
                "exec",
                "--profile",
                "web",
                "--",
                "curl",
                "-s",
                "example.com",
            ],
            vec![
                "xraytui",
                "exec",
                "--transparent",
                "--profile",
                "web",
                "--",
                "curl",
                "x",
            ],
            vec!["xraytui", "node", "list"],
            vec!["xraytui", "node", "show", "hk-01"],
            vec!["xraytui", "node", "import", "vless://x@h:443"],
            vec!["xraytui", "node", "import", "--stdin"],
            vec!["xraytui", "node", "import", "--file", "/tmp/links.txt"],
            vec!["xraytui", "node", "import", "--clipboard"],
            vec![
                "xraytui",
                "node",
                "import",
                "--xray-json",
                "/tmp/config.json",
            ],
            vec!["xraytui", "node", "remove", "hk-01"],
            vec!["xraytui", "node", "test", "hk-01"],
            vec!["xraytui", "node", "share", "hk-01"],
            vec!["xraytui", "node", "share", "hk-01", "--qr"],
            vec!["xraytui", "node", "share", "hk-01", "--png", "/tmp/n.png"],
            vec!["xraytui", "group", "list"],
            vec!["xraytui", "group", "test", "auto-hk"],
            vec!["xraytui", "chain", "list"],
            vec!["xraytui", "chain", "test", "hk-us"],
            vec!["xraytui", "rule", "list"],
            vec!["xraytui", "rule", "explain", "example.com"],
            vec!["xraytui", "rule", "validate"],
            vec!["xraytui", "subscription", "list"],
            vec!["xraytui", "subscription", "add", "https://example.com/sub"],
            vec!["xraytui", "subscription", "update", "provider"],
            vec!["xraytui", "subscription", "update", "--all"],
            vec!["xraytui", "subscription", "diff", "provider"],
            vec!["xraytui", "logs"],
            vec!["xraytui", "runtime", "connections"],
            vec!["xraytui", "runtime", "stats"],
            vec!["xraytui", "completion", "bash"],
        ];
        for invocation in invocations {
            Cli::try_parse_from(&invocation)
                .unwrap_or_else(|error| panic!("{invocation:?} failed to parse: {error}"));
        }
    }

    #[test]
    fn the_dmenu_pipeline_from_the_specification_parses() {
        Cli::try_parse_from(["xraytui", "profile", "list", "--format", "dmenu"]).expect("list");
        Cli::try_parse_from(["xraytui", "profile", "select-from-stdin"]).expect("select");
        Cli::try_parse_from([
            "xraytui",
            "target",
            "list",
            "--profile",
            "development",
            "--format",
            "dmenu",
        ])
        .expect("targets");
        Cli::try_parse_from(["xraytui", "profile", "set-target", "development", "--stdin"])
            .expect("set from stdin");
        Cli::try_parse_from(["xraytui", "status", "--format", "dwmblocks"]).expect("status");
    }

    #[test]
    fn exec_requires_a_command_after_the_separator() {
        assert!(Cli::try_parse_from(["xraytui", "exec", "--profile", "web"]).is_err());
        let cli =
            Cli::try_parse_from(["xraytui", "exec", "--profile", "web", "--", "sh", "-c", "x"])
                .expect("parse");
        match cli.command {
            Some(Command::Exec(args)) => {
                // The argument vector is preserved verbatim; nothing is passed
                // through a shell unless the user spelled one out themselves.
                assert_eq!(args.command, vec!["sh", "-c", "x"]);
                assert_eq!(args.profile, "web");
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn set_target_requires_a_target_or_stdin() {
        assert!(Cli::try_parse_from(["xraytui", "profile", "set-target", "web"]).is_err());
        assert!(
            Cli::try_parse_from(["xraytui", "profile", "set-target", "web", "--stdin"]).is_ok()
        );
    }

    #[test]
    fn invert_only_applies_to_qr_output() {
        assert!(
            Cli::try_parse_from(["xraytui", "node", "share", "n", "--invert"]).is_err(),
            "--invert without --qr must be refused"
        );
        assert!(Cli::try_parse_from(["xraytui", "node", "share", "n", "--qr", "--invert"]).is_ok());
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli = Cli::try_parse_from(["xraytui", "node", "list", "--format", "json", "--quiet"])
            .expect("parse");
        assert_eq!(cli.format, Format::Json);
        assert!(cli.quiet);
    }
}
