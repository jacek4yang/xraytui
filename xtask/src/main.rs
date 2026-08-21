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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use sha2::{Digest, Sha256};

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
    /// Export a self-contained, downloadable recovery checkpoint.
    Checkpoint(CheckpointArgs),
    /// Build the distributable binary archive and its checksum.
    Dist,
}

#[derive(Debug, clap::Args)]
struct CheckpointArgs {
    /// Short label, e.g. `durable-state`. Lowercase letters, digits and `-`.
    #[arg(long)]
    label: String,
    /// Where to write the checkpoint. Defaults to the recorded delivery
    /// directory, or `../xraytui-deliverables` if none is recorded.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Milestone this checkpoint completes, for the manifest.
    #[arg(long, default_value = "")]
    completed: String,
    /// The next milestone, for the manifest.
    #[arg(long, default_value = "")]
    next: String,
    /// The exact command a resuming session should run first.
    #[arg(long, default_value = "cargo xtask checkpoint --label resumed")]
    resume_command: String,
    /// Path to a test summary to embed. Optional but strongly preferred.
    #[arg(long)]
    tests: Option<PathBuf>,
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
        Task::Checkpoint(args) => checkpoint(&args),
        Task::Dist => dist(),
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
        (
            "cargo check",
            &["check", "--workspace", "--all-targets", "--all-features"],
        ),
        (
            "cargo clippy",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("cargo build", &["build", "--workspace"]),
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

#[derive(Debug, Deserialize)]
struct UpstreamManifest {
    core: CoreSnapshot,
    #[serde(default)]
    ecosystem: Vec<EcosystemSnapshot>,
}

#[derive(Debug, Deserialize)]
struct CoreSnapshot {
    repository: String,
    stable_tag: String,
    stable_commit: String,
    preview_tag: String,
    preview_commit: String,
    stable_files: BTreeMap<String, String>,
    preview_files: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct EcosystemSnapshot {
    name: String,
    repository: String,
    reference: String,
    snapshot_commit: String,
    files: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct GithubCommit {
    sha: String,
}

fn upstream_check() -> Result<()> {
    let root = workspace_root()?;
    let manifest_path = root.join("upstream-compat.toml");
    let manifest: UpstreamManifest = toml::from_str(
        &std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parsing {}", manifest_path.display()))?;
    let mut failures = Vec::new();

    println!("Xray release channels");
    let release_url = format!(
        "https://api.github.com/repos/{}/releases?per_page=30",
        manifest.core.repository
    );
    let releases: Vec<GithubRelease> = fetch_json(&release_url)?;
    let latest_stable = latest_release(&releases, false).context("no stable Xray release found")?;
    let latest_preview =
        latest_release(&releases, true).context("no preview Xray release found")?;
    compare(
        "latest stable release",
        &manifest.core.stable_tag,
        &latest_stable.tag_name,
        &mut failures,
    );
    compare(
        "latest preview release",
        &manifest.core.preview_tag,
        &latest_preview.tag_name,
        &mut failures,
    );

    let stable_commit = github_commit(&manifest.core.repository, &manifest.core.stable_tag)?;
    compare(
        "stable tag commit",
        &manifest.core.stable_commit,
        &stable_commit,
        &mut failures,
    );
    let preview_commit = github_commit(&manifest.core.repository, &manifest.core.preview_tag)?;
    compare(
        "preview tag commit",
        &manifest.core.preview_commit,
        &preview_commit,
        &mut failures,
    );

    println!("\nXray connection-schema watch");
    check_remote_files(
        "stable",
        &manifest.core.repository,
        &stable_commit,
        &manifest.core.stable_files,
        &mut failures,
    )?;
    check_remote_files(
        "preview",
        &manifest.core.repository,
        &preview_commit,
        &manifest.core.preview_files,
        &mut failures,
    )?;

    println!("\nVendored protobuf closure");
    let vendor = root.join("vendor/xray-proto");
    let mut proto_count = 0usize;
    for entry in walk(&vendor)? {
        if entry
            .extension()
            .is_none_or(|extension| extension != "proto")
        {
            continue;
        }
        let relative = entry.strip_prefix(&vendor).unwrap_or(&entry);
        let path = relative.to_string_lossy();
        let upstream = fetch_bytes(&raw_url(&manifest.core.repository, &stable_commit, &path))?;
        let local = std::fs::read(&entry)
            .with_context(|| format!("reading vendored {}", relative.display()))?;
        if local == upstream {
            println!("  PASS {}", relative.display());
        } else {
            let message = format!(
                "vendored {} differs from {}",
                relative.display(),
                manifest.core.stable_tag
            );
            println!("  FAIL {message}");
            failures.push(message);
        }
        proto_count += 1;
    }
    if proto_count == 0 {
        failures.push("vendored protobuf closure is empty".to_owned());
    }

    println!("\nEcosystem share-serializer watch");
    for ecosystem in &manifest.ecosystem {
        let head = github_commit(&ecosystem.repository, &ecosystem.reference)?;
        if head == ecosystem.snapshot_commit {
            println!("  INFO {} remains at {}", ecosystem.name, short_sha(&head));
        } else {
            println!(
                "  INFO {} advanced {} -> {}; checking watched paths",
                ecosystem.name,
                short_sha(&ecosystem.snapshot_commit),
                short_sha(&head)
            );
        }
        check_remote_files(
            &ecosystem.name,
            &ecosystem.repository,
            &head,
            &ecosystem.files,
            &mut failures,
        )?;
    }

    if failures.is_empty() {
        println!(
            "\nPASS: releases, tag commits, {} Xray schema snapshots, {proto_count} protobuf files, and {} ecosystem serializer sets match the reviewed manifest",
            manifest.core.stable_files.len() + manifest.core.preview_files.len(),
            manifest.ecosystem.len()
        );
        Ok(())
    } else {
        eprintln!(
            "\nUpstream compatibility review required. Inspect primary-source changes, update the typed model/import/export/compiler and round-trip fixtures as needed, then update upstream-compat.toml and docs/UPSTREAM-COMPATIBILITY.md."
        );
        for failure in &failures {
            eprintln!("  - {failure}");
        }
        bail!("{} upstream compatibility check(s) failed", failures.len())
    }
}

fn latest_release(releases: &[GithubRelease], prerelease: bool) -> Option<&GithubRelease> {
    releases
        .iter()
        .filter(|release| !release.draft && release.prerelease == prerelease)
        .filter_map(|release| version_key(&release.tag_name).map(|key| (key, release)))
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, release)| release)
}

fn version_key(tag: &str) -> Option<Vec<u64>> {
    let numbers = tag
        .trim_start_matches(['v', 'V'])
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()
        .ok()?;
    (!numbers.is_empty()).then_some(numbers)
}

fn github_commit(repository: &str, reference: &str) -> Result<String> {
    let url = format!("https://api.github.com/repos/{repository}/commits/{reference}");
    let commit: GithubCommit = fetch_json(&url)?;
    Ok(commit.sha)
}

fn fetch_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T> {
    serde_json::from_slice(&fetch_bytes(url)?).with_context(|| format!("parsing {url}"))
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    const MAX_RESPONSE: usize = 8 * 1024 * 1024;
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "30",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
            "--user-agent",
            "xraytui-upstream-check",
            url,
        ])
        .output()
        .with_context(|| format!("running curl for {url}"))?;
    if !output.status.success() {
        bail!(
            "fetching {url} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.len() > MAX_RESPONSE {
        bail!("response from {url} exceeds {MAX_RESPONSE} bytes");
    }
    Ok(output.stdout)
}

fn raw_url(repository: &str, reference: &str, path: &str) -> String {
    format!("https://raw.githubusercontent.com/{repository}/{reference}/{path}")
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn check_remote_files(
    label: &str,
    repository: &str,
    reference: &str,
    files: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) -> Result<()> {
    for (path, expected) in files {
        let actual = sha256(&fetch_bytes(&raw_url(repository, reference, path))?);
        if &actual == expected {
            println!("  PASS {label}: {path}");
        } else {
            let message =
                format!("{label}: {path} changed (expected {expected}, observed {actual})");
            println!("  FAIL {message}");
            failures.push(message);
        }
    }
    Ok(())
}

fn compare(label: &str, expected: &str, actual: &str, failures: &mut Vec<String>) {
    if expected == actual {
        println!("  PASS {label}: {actual}");
    } else {
        println!("  FAIL {label}: expected {expected}, observed {actual}");
        failures.push(format!("{label}: expected {expected}, observed {actual}"));
    }
}

fn short_sha(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
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

/// Build a portable binary archive from a staged installation tree.
///
/// The tree comes from the same manifest `install` uses, so the archive cannot
/// drift from what a package would place. Deterministic: sorted, root-owned,
/// fixed mtime, `gzip -n`.
fn dist() -> Result<()> {
    let root = workspace_root()?;
    let version = env!("CARGO_PKG_VERSION");
    let tree_name = format!("xraytui-{version}");
    let artifact_name = format!("{tree_name}-linux-x86_64");
    let out = root.join("target/dist");
    let staging = out.join(&tree_name);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;

    let args = InstallArgs {
        prefix: PathBuf::from("usr"),
        destdir: Some(staging.clone()),
        dry_run: false,
        systemd: true,
    };
    install(&args)?;

    // The packaging sources travel with the archive so somebody can rebuild a
    // package from it without the repository.
    let packaging = staging.join("packaging");
    std::fs::create_dir_all(&packaging)?;
    for entry in ["arch", "systemd", "completions", "man"] {
        let from = root.join("packaging").join(entry);
        if from.is_dir() {
            copy_tree(&from, &packaging.join(entry))?;
        }
    }

    let archive = out.join(format!("{artifact_name}.tar.gz"));
    tar_directory(&out, &tree_name, &archive)?;
    let sum = sha256_of(&archive)?;
    std::fs::write(
        out.join(format!("{artifact_name}.tar.gz.sha256")),
        format!("{sum}  {artifact_name}.tar.gz\n"),
    )?;
    println!("{}", archive.display());
    println!("{sum}  {artifact_name}.tar.gz");
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

// ------------------------------------------------------------- checkpointing

/// Where checkpoints go when `--out` is not given.
const DELIVERY_RECORD: &str = "DELIVERY-LOCATION.txt";

/// Export a checkpoint: a single compressed file holding complete Git history,
/// a clean source snapshot, the continuation documents and the test evidence.
///
/// # Why this exists
///
/// This environment has destroyed committed work three times. A local commit is
/// not durable here; the only thing that survives is a file the user has
/// downloaded. So the unit of progress is not the commit — it is the checkpoint
/// archive, and a slice is not finished until one has been exported and handed
/// over.
///
/// Everything below runs with fixed argument vectors and no shell, so a branch
/// name or a label cannot become a command.
fn checkpoint(args: &CheckpointArgs) -> Result<()> {
    let root = workspace_root()?;

    if args.label.is_empty()
        || !args
            .label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!(
            "--label must be lowercase letters, digits and '-': got {:?}",
            args.label
        );
    }

    // A checkpoint of an unclean tree records a state that cannot be restored,
    // because the source archive comes from HEAD and the difference would be
    // lost silently. Refuse rather than mislead.
    let dirty = capture(&root, "git", &["status", "--porcelain"])?;
    if !dirty.trim().is_empty() {
        bail!(
            "the worktree is not clean; commit first.\n{}\nA checkpoint archives HEAD, so \
             uncommitted work would be silently dropped.",
            dirty.trim()
        );
    }

    let head = capture(&root, "git", &["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    let short = head.get(..7).unwrap_or(&head).to_owned();
    let branch = capture(&root, "git", &["rev-parse", "--abbrev-ref", "HEAD"])?
        .trim()
        .to_owned();
    let tags = capture(&root, "git", &["tag", "--list"])?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let out = match &args.out {
        Some(path) => path.clone(),
        None => default_delivery_directory(&root)?,
    };
    std::fs::create_dir_all(&out).with_context(|| format!("cannot create {}", out.display()))?;

    let sequence = next_sequence(&out)?;
    let name = format!("xraytui-checkpoint-{sequence:03}-{}-{short}", args.label);
    let staging = out.join(&name);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(staging.join("test-results"))?;

    // 1. Complete history: every branch, every tag.
    let bundle = staging.join("xraytui-history.bundle");
    run(
        &root,
        "git",
        &["bundle", "create", path_arg(&bundle)?, "--all"],
    )?;

    // 2. The committed tree, not the working directory. `gzip -n` omits the
    //    timestamp, so the same commit produces the same bytes.
    let source = staging.join("xraytui-source.tar.gz");
    archive_head(&root, &source)?;

    // 3. Verify the bundle by actually cloning it, because a bundle that cannot
    //    be cloned is not a backup, and this is the one check that proves it.
    let probe = out.join(format!(".verify-{sequence:03}"));
    if probe.exists() {
        std::fs::remove_dir_all(&probe)?;
    }
    run(
        &root,
        "git",
        &["clone", "--quiet", path_arg(&bundle)?, path_arg(&probe)?],
    )?;
    let restored = capture(&probe, "git", &["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    std::fs::remove_dir_all(&probe)?;
    if restored != head {
        bail!("the bundle restored {restored}, not {head}");
    }

    // 4. The documents a resuming session reads first.
    for document in [
        "CONTINUE.md",
        "RELEASE-1.0.md",
        "STATUS.md",
        "RECOVERY.md",
        "CLAUDE.md",
    ] {
        let from = root.join(document);
        if from.is_file() {
            std::fs::copy(&from, staging.join(document))?;
        }
    }
    if let Some(tests) = &args.tests
        && tests.is_file()
    {
        std::fs::copy(tests, staging.join("test-results/summary.txt"))?;
    }
    let summary = staging.join("test-results/summary.txt");
    if !summary.exists() {
        std::fs::write(
            &summary,
            "No test summary was supplied for this checkpoint.\n\
             Treat every test as UNEXECUTED at this commit.\n",
        )?;
    }
    std::fs::write(
        staging.join("test-results/commands.txt"),
        TEST_COMMANDS.trim_start(),
    )?;

    let bundle_sum = sha256_of(&bundle)?;
    let source_sum = sha256_of(&source)?;

    let manifest = checkpoint_manifest(
        sequence,
        &head,
        &branch,
        &tags,
        args,
        &bundle_sum,
        &source_sum,
    )?;
    std::fs::write(staging.join("CHECKPOINT-MANIFEST.json"), manifest)?;
    std::fs::write(
        staging.join("README-FIRST.md"),
        readme_first(sequence, &args.label, &head, &branch, &args.resume_command),
    )?;
    if !staging.join("RECOVERY.md").exists() {
        std::fs::write(staging.join("RECOVERY.md"), RECOVERY_DOC.trim_start())?;
    }

    // 5. Checksums over everything in the checkpoint, computed last.
    let mut sums = String::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(&staging, &mut files)?;
    files.sort();
    for file in &files {
        let relative = file.strip_prefix(&staging).unwrap_or(file);
        sums.push_str(&format!("{}  {}\n", sha256_of(file)?, relative.display()));
    }
    std::fs::write(staging.join("SHA256SUMS"), &sums)?;

    // 6. One outer file.
    let outer = out.join(format!("{name}.tar.gz"));
    tar_directory(&out, &name, &outer)?;
    std::fs::remove_dir_all(&staging)?;
    let outer_sum = sha256_of(&outer)?;
    std::fs::write(
        out.join(format!("{name}.tar.gz.sha256")),
        format!("{outer_sum}  {name}.tar.gz\n"),
    )?;

    println!("checkpoint {sequence:03} — {}", args.label);
    println!("  commit   {head}");
    println!("  branch   {branch}");
    println!("  archive  {}", outer.display());
    println!("  sha256   {outer_sum}");
    println!("  bundle   {bundle_sum}");
    println!("  source   {source_sum}");
    println!("\nSend {name}.tar.gz to the user. A checkpoint nobody has downloaded");
    println!("is not a backup.");
    Ok(())
}

/// The delivery directory, recorded so every later checkpoint lands beside the
/// earlier ones even across a restart.
fn default_delivery_directory(root: &Path) -> Result<PathBuf> {
    let record = root.join(DELIVERY_RECORD);
    if let Ok(text) = std::fs::read_to_string(&record) {
        let line = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'));
        if let Some(path) = line {
            return Ok(PathBuf::from(path));
        }
    }
    // Preference order, most durable first. `/mnt/user-data/working` is the
    // directory Cowork surfaces to the user; a temporary directory is not a
    // delivery location, because it is exactly what the resets destroy.
    for candidate in ["/mnt/user-data/outputs", "/mnt/user-data/working"] {
        if Path::new(candidate).is_dir() {
            return Ok(PathBuf::from(candidate).join("xraytui-deliverables"));
        }
    }
    Ok(root.parent().unwrap_or(root).join("xraytui-deliverables"))
}

/// One past the highest checkpoint already present, so numbering survives a
/// restart without being remembered.
fn next_sequence(out: &Path) -> Result<u32> {
    let mut highest: Option<u32> = None;
    if let Ok(entries) = std::fs::read_dir(out) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(rest) = name.strip_prefix("xraytui-checkpoint-") else {
                continue;
            };
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(value) = digits.parse::<u32>() {
                highest = Some(highest.map_or(value, |current: u32| current.max(value)));
            }
        }
    }
    Ok(highest.map_or(0, |value| value + 1))
}

/// `git archive HEAD | gzip -n`, without a shell.
fn archive_head(root: &Path, destination: &Path) -> Result<()> {
    let tar = Command::new("git")
        .current_dir(root)
        .args(["archive", "--format=tar", "--prefix=xraytui/", "HEAD"])
        .output()
        .context("git archive")?;
    if !tar.status.success() {
        bail!(
            "git archive failed: {}",
            String::from_utf8_lossy(&tar.stderr)
        );
    }
    let file = std::fs::File::create(destination)?;
    let mut gzip = Command::new("gzip")
        .arg("-n")
        .arg("-9")
        .stdin(std::process::Stdio::piped())
        .stdout(file)
        .spawn()
        .context("gzip")?;
    {
        use std::io::Write;
        let stdin = gzip.stdin.as_mut().context("gzip stdin")?;
        stdin.write_all(&tar.stdout)?;
    }
    let status = gzip.wait()?;
    if !status.success() {
        bail!("gzip failed with {status}");
    }
    Ok(())
}

/// Deterministic tar of one directory: sorted, owned by root, fixed mtime.
fn tar_directory(parent: &Path, name: &str, destination: &Path) -> Result<()> {
    let tar = Command::new("tar")
        .current_dir(parent)
        .args([
            "--sort=name",
            "--owner=root:0",
            "--group=root:0",
            "--mtime=UTC 2020-01-01",
            "--numeric-owner",
            "-cf",
            "-",
            name,
        ])
        .output()
        .context("tar")?;
    if !tar.status.success() {
        bail!("tar failed: {}", String::from_utf8_lossy(&tar.stderr));
    }
    let file = std::fs::File::create(destination)?;
    let mut gzip = Command::new("gzip")
        .arg("-n")
        .arg("-9")
        .stdin(std::process::Stdio::piped())
        .stdout(file)
        .spawn()
        .context("gzip")?;
    {
        use std::io::Write;
        gzip.stdin
            .as_mut()
            .context("gzip stdin")?
            .write_all(&tar.stdout)?;
    }
    if !gzip.wait()?.success() {
        bail!("gzip failed");
    }
    Ok(())
}

fn collect_files(directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

fn sha256_of(path: &Path) -> Result<String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .context("sha256sum")?;
    if !output.status.success() {
        bail!("sha256sum failed for {}", path.display());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned())
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

fn run(directory: &Path, program: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .current_dir(directory)
        .args(arguments)
        .status()
        .with_context(|| format!("cannot run {program}"))?;
    if !status.success() {
        bail!("{program} {arguments:?} failed with {status}");
    }
    Ok(())
}

fn capture(directory: &Path, program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .current_dir(directory)
        .args(arguments)
        .output()
        .with_context(|| format!("cannot run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_manifest(
    sequence: u32,
    head: &str,
    branch: &str,
    tags: &[String],
    args: &CheckpointArgs,
    bundle_sum: &str,
    source_sum: &str,
) -> Result<String> {
    let now = capture(Path::new("."), "date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])?
        .trim()
        .to_owned();
    let rust = capture(Path::new("."), "rustc", &["--version"])
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_owned();
    let kernel = capture(Path::new("."), "uname", &["-sr"])
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_owned();
    let xray = Command::new("xray")
        .arg("version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .unwrap_or_else(|| "not present".into());
    let tag_list = tags
        .iter()
        .map(|tag| format!("\"{}\"", json_escape(tag)))
        .collect::<Vec<_>>()
        .join(", ");
    let summary = args
        .tests
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let counts = parse_test_counts(&summary);

    Ok(format!(
        r#"{{
  "manifest_schema_version": 1,
  "checkpoint_sequence": {sequence},
  "created_utc": "{now}",
  "project_version": "{version}",
  "branch": "{branch}",
  "head_commit": "{head}",
  "local_tags": [{tag_list}],
  "worktree_clean": true,
  "completed_milestone": "{completed}",
  "next_milestone": "{next}",
  "first_resume_command": "{resume}",
  "tests_run": {run},
  "tests_passed": {passed},
  "tests_failed": {failed},
  "tests_unexecuted": "{unexecuted}",
  "environment_limitations": "{limitations}",
  "git_bundle": {{ "file": "xraytui-history.bundle", "sha256": "{bundle_sum}" }},
  "source_archive": {{ "file": "xraytui-source.tar.gz", "sha256": "{source_sum}" }},
  "xray_version": "{xray}",
  "rust_version": "{rust}",
  "kernel": "{kernel}",
  "disposable_network_resources_may_remain": false
}}
"#,
        version = env!("CARGO_PKG_VERSION"),
        completed = json_escape(&args.completed),
        next = json_escape(&args.next),
        resume = json_escape(&args.resume_command),
        run = counts.0,
        passed = counts.1,
        failed = counts.2,
        unexecuted = json_escape(&counts.3),
        limitations = json_escape(&environment_limitations()),
        xray = json_escape(&xray),
        rust = json_escape(&rust),
        kernel = json_escape(&kernel),
    ))
}

/// Read `RUN=`, `PASSED=`, `FAILED=` and `UNEXECUTED=` out of a summary file.
///
/// A summary that does not say is recorded as zero tests run, never as zero
/// tests failed: "nothing ran" and "nothing broke" are different facts.
fn parse_test_counts(summary: &str) -> (u64, u64, u64, String) {
    let mut run = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut unexecuted = String::from("unknown");
    for line in summary.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("RUN=") {
            run = value.trim().parse().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("PASSED=") {
            passed = value.trim().parse().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("FAILED=") {
            failed = value.trim().parse().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("UNEXECUTED=") {
            unexecuted = value.trim().to_owned();
        }
    }
    (run, passed, failed, unexecuted)
}

/// What this machine demonstrably cannot do, probed rather than assumed.
fn environment_limitations() -> String {
    let mut problems = Vec::new();
    if !Path::new("/run/dbus/system_bus_socket").exists() {
        problems.push("no D-Bus system bus: systemd-resolved cannot be tested");
    }
    if !Path::new("/proc/net/if_inet6").exists() {
        problems.push("no IPv6 in this kernel");
    }
    if which("podman").is_none() && which("docker").is_none() {
        problems.push("no container runtime: no clean Arch package build");
    }
    if problems.is_empty() {
        "none detected".to_owned()
    } else {
        problems.join("; ")
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(program))
            .find(|candidate| candidate.is_file())
    })
}

fn readme_first(sequence: u32, label: &str, head: &str, branch: &str, resume: &str) -> String {
    format!(
        r#"# Checkpoint {sequence:03} — {label}

This is a complete, self-contained copy of the xraytui project. Everything
needed to inspect, build, continue or hand it to somebody else is inside.

## Restore it

```sh
tar xzf xraytui-checkpoint-{sequence:03}-{label}-*.tar.gz
cd xraytui-checkpoint-{sequence:03}-{label}-*/
sha256sum -c SHA256SUMS

git clone xraytui-history.bundle xraytui
cd xraytui
git switch {branch}
git rev-parse HEAD    # must print {head}
```

`xraytui-source.tar.gz` is the same tree without history, as an independent
check: extract it and diff it against the clone if you want to be sure.

## Continue it

Open a new session, attach this archive, and say `continue`. The instructions
for resuming are in `CLAUDE.md` and the current state is in `CONTINUE.md`.
The first command to run is:

```sh
{resume}
```

## What the numbers mean

`CHECKPOINT-MANIFEST.json` records what was actually executed at this commit.
A test that did not run is recorded as unexecuted, never as passing. If
`tests_run` is 0 the checkpoint is a preservation snapshot, not a claim that
anything works.
"#
    )
}

const TEST_COMMANDS: &str = r#"
Commands that produce the evidence in summary.txt.

  cargo fmt --all --check
  cargo check --workspace --all-targets
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace
  sudo ./scripts/netns-test.sh          # privileged; disposable namespace only
  ./scripts/release-smoke.sh            # whole user workflow, real binaries
  cargo audit
  cargo deny check

summary.txt uses these keys, read by `cargo xtask checkpoint`:

  RUN=<total tests executed>
  PASSED=<total passed>
  FAILED=<total failed>
  UNEXECUTED=<comma-separated names of gates that did not run>
"#;

const RECOVERY_DOC: &str = r#"
# Recovering this project

## From a checkpoint archive

```sh
tar xzf xraytui-checkpoint-NNN-LABEL-SHORT.tar.gz
cd xraytui-checkpoint-NNN-LABEL-SHORT
sha256sum -c SHA256SUMS
git clone xraytui-history.bundle xraytui
cd xraytui && git switch release/v1
```

The bundle carries every local branch and tag. Nothing was ever pushed to a
remote, by explicit instruction, so the bundle is the only copy of the history.

## If the bundle will not clone

Use `xraytui-source.tar.gz`. It is the committed tree at the recorded HEAD,
without history:

```sh
tar xzf xraytui-source.tar.gz
cd xraytui && git init && git add -A && git commit -m "restored from source snapshot"
```

You lose history, not code.

## After restoring

```sh
cargo check --workspace --all-targets
cargo test --workspace
```

Then read `CONTINUE.md` for the exact next action.

## Cleaning up a machine that ran the privileged tests

Every privileged test runs inside a disposable network namespace that the
kernel destroys with the namespace, so an interrupted run leaves nothing
behind. If a daemon or fixture was left running:

```sh
pkill -f 'xraytuid --root /tmp'
pkill -f smoke-fixtures.py
```
"#;

#[cfg(test)]
mod upstream_tests {
    use super::*;

    #[test]
    fn release_selection_is_numeric_and_keeps_channels_separate() {
        let releases = vec![
            GithubRelease {
                tag_name: "v26.3.9".into(),
                draft: false,
                prerelease: false,
            },
            GithubRelease {
                tag_name: "v26.3.27".into(),
                draft: false,
                prerelease: false,
            },
            GithubRelease {
                tag_name: "v26.7.28".into(),
                draft: false,
                prerelease: true,
            },
            GithubRelease {
                tag_name: "v99.0.0".into(),
                draft: true,
                prerelease: false,
            },
        ];
        assert_eq!(
            latest_release(&releases, false).map(|release| release.tag_name.as_str()),
            Some("v26.3.27")
        );
        assert_eq!(
            latest_release(&releases, true).map(|release| release.tag_name.as_str()),
            Some("v26.7.28")
        );
    }

    #[test]
    fn version_keys_do_not_sort_27_below_9_lexically() {
        assert!(version_key("v26.3.27") > version_key("v26.3.9"));
        assert_eq!(version_key("not-a-version"), None);
    }
}
