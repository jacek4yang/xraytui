//! Build, install and maintenance tasks.
//!
//! A typed installer rather than a shell script: every destination is computed
//! from a prefix and a `DESTDIR`, `--dry-run` prints exactly what would happen,
//! and nothing is ever installed setuid.
//!
//! ```text
//! cargo xtask install --prefix /usr --dry-run
//! sudo cargo xtask install --prefix /usr
//! cargo xtask uninstall --prefix /usr --dry-run
//! cargo xtask upstream-check
//! ```

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "xraytui build and install tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Install the built binaries and support files.
    Install(InstallArgs),
    /// Remove what `install` placed, leaving user configuration alone.
    Uninstall(InstallArgs),
    /// Run every quality gate.
    Ci,
    /// Re-check the pinned upstream Xray release and protobuf closure.
    UpstreamCheck,
    /// Print the file manifest an installation would produce.
    Manifest(InstallArgs),
}

#[derive(Debug, clap::Args)]
struct InstallArgs {
    /// Installation prefix.
    #[arg(long, default_value = "/usr/local")]
    prefix: PathBuf,
    /// Staging root, for package builds.
    #[arg(long, env = "DESTDIR")]
    destdir: Option<PathBuf>,
    /// Print what would happen without touching the filesystem.
    #[arg(long)]
    dry_run: bool,
    /// Install the systemd units as well.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    systemd: bool,
}

/// One file to place.
struct Entry {
    source: Source,
    destination: PathBuf,
    mode: u32,
}

enum Source {
    /// Copy this repository file.
    File(PathBuf),
    /// Run `xraytui <args>` and capture stdout.
    Generated(Vec<String>),
    /// Run `xraytui manpages <dir>`, which writes many files at once.
    ManPages,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Task::Install(args) => install(&args),
        Task::Uninstall(args) => uninstall(&args),
        Task::Ci => ci(),
        Task::UpstreamCheck => upstream_check(),
        Task::Manifest(args) => {
            for entry in manifest(&args)? {
                println!("{:>4o}  {}", entry.mode, entry.destination.display());
            }
            Ok(())
        }
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .context("xtask must live one level below the workspace root")
}

fn release_binary(name: &str) -> Result<PathBuf> {
    let path = workspace_root()?.join("target/release").join(name);
    if !path.is_file() {
        bail!(
            "{} is missing; run `cargo build --release --workspace` first",
            path.display()
        );
    }
    Ok(path)
}

fn manifest(args: &InstallArgs) -> Result<Vec<Entry>> {
    let root = workspace_root()?;
    let prefix = &args.prefix;
    let mut entries = Vec::new();

    for name in ["xraytui", "xraytuid", "xraytui-netd"] {
        entries.push(Entry {
            source: Source::File(root.join("target/release").join(name)),
            destination: prefix.join("bin").join(name),
            // 0755, never setuid: the privileged helper gets its capabilities
            // from systemd, not from the filesystem.
            mode: 0o755,
        });
    }

    if args.systemd {
        entries.push(Entry {
            source: Source::File(root.join("packaging/systemd/xraytuid.service")),
            destination: prefix.join("lib/systemd/user/xraytuid.service"),
            mode: 0o644,
        });
        entries.push(Entry {
            source: Source::File(root.join("packaging/systemd/xraytui-netd.service")),
            destination: prefix.join("lib/systemd/system/xraytui-netd.service"),
            mode: 0o644,
        });
        entries.push(Entry {
            source: Source::File(root.join("packaging/systemd/xraytui-tmpfiles.conf")),
            destination: prefix.join("lib/tmpfiles.d/xraytui.conf"),
            mode: 0o644,
        });
        entries.push(Entry {
            source: Source::File(root.join("packaging/systemd/xraytui-sysusers.conf")),
            destination: prefix.join("lib/sysusers.d/xraytui.conf"),
            mode: 0o644,
        });
    }

    entries.push(Entry {
        source: Source::Generated(vec!["completion".into(), "bash".into()]),
        destination: prefix.join("share/bash-completion/completions/xraytui"),
        mode: 0o644,
    });
    entries.push(Entry {
        source: Source::Generated(vec!["completion".into(), "zsh".into()]),
        destination: prefix.join("share/zsh/site-functions/_xraytui"),
        mode: 0o644,
    });
    entries.push(Entry {
        source: Source::Generated(vec!["completion".into(), "fish".into()]),
        destination: prefix.join("share/fish/vendor_completions.d/xraytui.fish"),
        mode: 0o644,
    });
    entries.push(Entry {
        source: Source::ManPages,
        destination: prefix.join("share/man/man1"),
        mode: 0o644,
    });

    for doc in [
        "README.md",
        "STATUS.md",
        "DECISIONS.md",
        "PLAN.md",
        "SECURITY.md",
    ] {
        let path = root.join(doc);
        if path.is_file() {
            entries.push(Entry {
                source: Source::File(path),
                destination: prefix.join("share/doc/xraytui").join(doc),
                mode: 0o644,
            });
        }
    }
    if let Ok(read) = std::fs::read_dir(root.join("docs")) {
        for file in read.flatten() {
            let path = file.path();
            if path.extension().is_some_and(|e| e == "md") {
                let name = path.file_name().unwrap_or_default().to_owned();
                entries.push(Entry {
                    source: Source::File(path),
                    destination: prefix.join("share/doc/xraytui/docs").join(name),
                    mode: 0o644,
                });
            }
        }
    }

    Ok(entries)
}

fn staged(args: &InstallArgs, destination: &Path) -> PathBuf {
    match &args.destdir {
        Some(destdir) => {
            let relative = destination.strip_prefix("/").unwrap_or(destination);
            destdir.join(relative)
        }
        None => destination.to_path_buf(),
    }
}

fn install(args: &InstallArgs) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let entries = manifest(args)?;
    for entry in &entries {
        let destination = staged(args, &entry.destination);
        match &entry.source {
            Source::File(source) => {
                if args.dry_run {
                    println!(
                        "install -m{:o} {} {}",
                        entry.mode,
                        source.display(),
                        destination.display()
                    );
                    continue;
                }
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                std::fs::copy(source, &destination)
                    .with_context(|| format!("copying to {}", destination.display()))?;
                std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(entry.mode))
                    .with_context(|| format!("setting mode on {}", destination.display()))?;
                println!("installed {}", destination.display());
            }
            Source::Generated(arguments) => {
                let binary = release_binary("xraytui")?;
                if args.dry_run {
                    println!(
                        "{} {} > {}",
                        binary.display(),
                        arguments.join(" "),
                        destination.display()
                    );
                    continue;
                }
                let output = Command::new(&binary)
                    .args(arguments)
                    .output()
                    .with_context(|| format!("running {}", binary.display()))?;
                if !output.status.success() {
                    bail!("xraytui {} failed", arguments.join(" "));
                }
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&destination, output.stdout)?;
                std::fs::set_permissions(
                    &destination,
                    std::fs::Permissions::from_mode(entry.mode),
                )?;
                println!("generated {}", destination.display());
            }
            Source::ManPages => {
                let binary = release_binary("xraytui")?;
                if args.dry_run {
                    println!("{} manpages {}", binary.display(), destination.display());
                    continue;
                }
                std::fs::create_dir_all(&destination)?;
                let status = Command::new(&binary)
                    .arg("manpages")
                    .arg(&destination)
                    .status()
                    .with_context(|| format!("running {}", binary.display()))?;
                if !status.success() {
                    bail!("xraytui manpages failed");
                }
                println!("generated man pages in {}", destination.display());
            }
        }
    }

    if !args.dry_run {
        println!();
        println!("Next steps:");
        println!("  systemctl --user enable --now xraytuid.service");
        println!("  sudo systemctl enable --now xraytui-netd.service   # only for the system TUN");
        println!(
            "  sudo usermod -aG xraytui \"$USER\"                   # only for the system TUN"
        );
        println!("  xraytui doctor");
    }
    Ok(())
}

fn uninstall(args: &InstallArgs) -> Result<()> {
    let entries = manifest(args)?;
    for entry in &entries {
        if matches!(entry.source, Source::ManPages) {
            // Man pages are removed individually below.
            continue;
        }
        let destination = staged(args, &entry.destination);
        if args.dry_run {
            println!("rm {}", destination.display());
            continue;
        }
        match std::fs::remove_file(&destination) {
            Ok(()) => println!("removed {}", destination.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => println!("could not remove {}: {error}", destination.display()),
        }
    }

    let man_dir = staged(args, &args.prefix.join("share/man/man1"));
    if let Ok(read) = std::fs::read_dir(&man_dir) {
        for file in read.flatten() {
            let name = file.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("xraytui") && name.ends_with(".1") {
                if args.dry_run {
                    println!("rm {}", file.path().display());
                } else if std::fs::remove_file(file.path()).is_ok() {
                    println!("removed {}", file.path().display());
                }
            }
        }
    }

    println!();
    println!("User configuration in ~/.config/xraytui has been left in place.");
    println!("Remove it by hand if you want it gone.");
    Ok(())
}

fn ci() -> Result<()> {
    let root = workspace_root()?;
    let gates: &[(&str, &[&str])] = &[
        ("cargo fmt", &["fmt", "--all", "--check"]),
        ("cargo check", &["check", "--workspace", "--all-targets"]),
        (
            "cargo clippy",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("cargo test", &["test", "--workspace"]),
        ("cargo doc", &["doc", "--workspace", "--no-deps"]),
    ];
    let mut failures = Vec::new();
    for (name, arguments) in gates {
        println!("=== {name} ===");
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(&root)
            .args(*arguments)
            .status()
            .with_context(|| format!("running {name}"))?;
        if !status.success() {
            failures.push(*name);
        }
    }
    if failures.is_empty() {
        println!("all quality gates passed");
        Ok(())
    } else {
        bail!("failed: {}", failures.join(", "))
    }
}

fn upstream_check() -> Result<()> {
    let root = workspace_root()?;
    let vendor = root.join("vendor/xray-proto");
    println!("Pinned protobuf files:");
    let mut count = 0;
    for entry in walk(&vendor)? {
        if entry.extension().is_some_and(|e| e == "proto") {
            let relative = entry.strip_prefix(&vendor).unwrap_or(&entry);
            println!("  {}", relative.display());
            count += 1;
        }
    }
    println!("{count} file(s)");
    println!();
    println!(
        "Compare against https://github.com/XTLS/Xray-core/releases and update\n\
         docs/UPSTREAM-COMPATIBILITY.md if the pinned tag has moved.\n\
         This task performs no network I/O."
    );
    Ok(())
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
