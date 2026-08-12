//! XDG directory layout and safe directory creation.
//!
//! ```text
//! ~/.config/xraytui/          config.toml, profiles.toml, …, secrets.toml   0700
//! ~/.local/state/xraytui/     state.sqlite3, history/, logs/                0700
//! ~/.cache/xraytui/           subscriptions/, geodata/, downloads/          0700
//! $XDG_RUNTIME_DIR/xraytui/   control.sock, xray-api.json, generated-*.json 0700
//! ```
//!
//! Every directory is created with mode 0700 and verified afterwards: if a path
//! already exists but is a symlink, is not a directory, or is not owned by the
//! current user, setup fails rather than proceeding into someone else's tree.

use std::path::{Path, PathBuf};

use crate::ConfigError;

/// Project directory name used under every XDG root.
pub const PROJECT_DIR: &str = "xraytui";

/// Resolved locations for one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `~/.config/xraytui`
    pub config: PathBuf,
    /// `~/.local/state/xraytui`
    pub state: PathBuf,
    /// `~/.cache/xraytui`
    pub cache: PathBuf,
    /// `$XDG_RUNTIME_DIR/xraytui`
    pub runtime: PathBuf,
}

impl Paths {
    /// Resolve from the environment.
    ///
    /// `XDG_RUNTIME_DIR` has no portable fallback that is both private and
    /// tmpfs-backed. When it is unset, `/run/user/<uid>` is tried, and failing
    /// that a `0700` directory under the system temporary directory is used and
    /// the caller is expected to warn.
    ///
    /// # Errors
    /// Returns [`ConfigError::NoHome`] when no home directory can be determined.
    pub fn discover() -> Result<Self, ConfigError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(ConfigError::NoHome)?;

        let config = xdg_dir("XDG_CONFIG_HOME", home.join(".config")).join(PROJECT_DIR);
        let state = xdg_dir("XDG_STATE_HOME", home.join(".local/state")).join(PROJECT_DIR);
        let cache = xdg_dir("XDG_CACHE_HOME", home.join(".cache")).join(PROJECT_DIR);
        let runtime = runtime_root().join(PROJECT_DIR);

        Ok(Self {
            config,
            state,
            cache,
            runtime,
        })
    }

    /// Build an explicit layout, used by tests and by `--config-dir`.
    #[must_use]
    pub fn rooted_at(root: &Path) -> Self {
        Self {
            config: root.join("config"),
            state: root.join("state"),
            cache: root.join("cache"),
            runtime: root.join("run"),
        }
    }

    /// Create every directory with mode 0700, verifying ownership.
    ///
    /// # Errors
    /// Returns [`ConfigError::UnsafeDirectory`] when a path exists but is not a
    /// private directory owned by the caller.
    pub fn ensure(&self) -> Result<(), ConfigError> {
        for dir in [&self.config, &self.state, &self.cache, &self.runtime] {
            ensure_private_dir(dir)?;
        }
        for dir in [
            self.config.join("nodes.d"),
            self.config.join("routes.d"),
            self.state.join("history"),
            self.state.join("logs"),
            self.cache.join("subscriptions"),
            self.cache.join("geodata"),
            self.cache.join("downloads"),
        ] {
            ensure_private_dir(&dir)?;
        }
        Ok(())
    }

    /// Main configuration file.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    /// Secrets file, kept separate from display configuration.
    #[must_use]
    pub fn secrets_file(&self) -> PathBuf {
        self.config.join("secrets.toml")
    }

    /// Per-entity policy files.
    #[must_use]
    pub fn policy_file(&self, name: &str) -> PathBuf {
        self.config.join(format!("{name}.toml"))
    }

    /// SQLite runtime store.
    #[must_use]
    pub fn state_db(&self) -> PathBuf {
        self.state.join("state.sqlite3")
    }

    /// Daemon control socket.
    #[must_use]
    pub fn control_socket(&self) -> PathBuf {
        self.runtime.join("control.sock")
    }

    /// Daemon lock file, preventing two daemons for one user.
    #[must_use]
    pub fn daemon_lock(&self) -> PathBuf {
        self.runtime.join("daemon.lock")
    }

    /// Recorded Xray API endpoint.
    #[must_use]
    pub fn api_endpoint_file(&self) -> PathBuf {
        self.runtime.join("xray-api.json")
    }

    /// Xray commander Unix socket, when the Unix transport is used.
    #[must_use]
    pub fn xray_api_socket(&self) -> PathBuf {
        self.runtime.join("xray-api.sock")
    }

    /// Currently applied generated configuration.
    #[must_use]
    pub fn generated_config(&self) -> PathBuf {
        self.runtime.join("generated-xray.json")
    }

    /// Last generation that passed every health gate.
    #[must_use]
    pub fn last_good_config(&self) -> PathBuf {
        self.runtime.join("last-good-xray.json")
    }

    /// Serialised runtime state, for crash recovery and for read-only clients.
    #[must_use]
    pub fn runtime_state(&self) -> PathBuf {
        self.runtime.join("runtime-state.json")
    }

    /// Daemon log file.
    #[must_use]
    pub fn daemon_log(&self) -> PathBuf {
        self.state.join("logs/xraytuid.log")
    }

    /// Xray error log file.
    #[must_use]
    pub fn core_log(&self) -> PathBuf {
        self.state.join("logs/xray.log")
    }
}

fn xdg_dir(variable: &str, fallback: PathBuf) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or(fallback)
}

fn runtime_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        && dir.is_absolute()
    {
        return dir;
    }
    let uid = rustix::process::getuid().as_raw();
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    if run_user.is_dir() {
        return run_user;
    }
    std::env::temp_dir().join(format!("xraytui-{uid}"))
}

/// Create `dir` (and parents) with mode 0700, or verify an existing one.
///
/// # Errors
/// Returns [`ConfigError::UnsafeDirectory`] when the path exists but is a
/// symlink, is not a directory, or is owned by another user.
pub fn ensure_private_dir(dir: &Path) -> Result<(), ConfigError> {
    if let Some(parent) = dir.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(ConfigError::UnsafeDirectory {
                    path: dir.to_path_buf(),
                    reason: "path is a symlink".into(),
                });
            }
            if !metadata.is_dir() {
                return Err(ConfigError::UnsafeDirectory {
                    path: dir.to_path_buf(),
                    reason: "path exists but is not a directory".into(),
                });
            }
            verify_owner(dir, &metadata)?;
            tighten_permissions(dir, &metadata)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_dir(dir)?;
        }
        Err(source) => {
            return Err(ConfigError::Io {
                path: dir.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|source| ConfigError::Io {
            path: dir.to_path_buf(),
            source,
        })
}

fn verify_owner(dir: &Path, metadata: &std::fs::Metadata) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let uid = rustix::process::getuid().as_raw();
    if metadata.uid() != uid {
        return Err(ConfigError::UnsafeDirectory {
            path: dir.to_path_buf(),
            reason: format!(
                "owned by uid {} but this process runs as uid {uid}",
                metadata.uid()
            ),
        });
    }
    Ok(())
}

fn tighten_permissions(dir: &Path, metadata: &std::fs::Metadata) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| ConfigError::Io {
                path: dir.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
}

/// Write a file atomically with mode 0600.
///
/// Writes to a sibling temporary file, `fsync`s it, renames it into place and
/// then `fsync`s the directory, so a crash leaves either the old contents or the
/// new ones — never a truncated file.
///
/// # Errors
/// Propagates I/O failures.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<(), ConfigError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().unwrap_or(Path::new("."));
    ensure_private_dir(parent)?;

    let temp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        rustix::process::getpid().as_raw_nonzero()
    ));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|source| ConfigError::Io {
            path: temp.clone(),
            source,
        })?;
    file.write_all(contents).map_err(|source| ConfigError::Io {
        path: temp.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| ConfigError::Io {
        path: temp.clone(),
        source,
    })?;
    drop(file);

    std::fs::rename(&temp, path).map_err(|source| {
        let _ = std::fs::remove_file(&temp);
        ConfigError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;

    // Durably record the rename itself.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn directories_are_created_private() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        paths.ensure().expect("ensure");
        for dir in [&paths.config, &paths.state, &paths.cache, &paths.runtime] {
            let mode = std::fs::metadata(dir)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
        assert!(paths.config.join("nodes.d").is_dir());
        assert!(paths.state.join("logs").is_dir());
    }

    #[test]
    fn ensure_is_idempotent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        paths.ensure().expect("first");
        paths.ensure().expect("second");
    }

    #[test]
    fn loose_permissions_are_tightened() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("loose");
        std::fs::create_dir(&dir).expect("create");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        ensure_private_dir(&dir).expect("ensure");
        let mode = std::fs::metadata(&dir)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_symlink_is_refused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("real");
        std::fs::create_dir(&target).expect("create");
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let error = ensure_private_dir(&link).expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::UnsafeDirectory { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_file_in_place_of_a_directory_is_refused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("file");
        std::fs::write(&path, b"x").expect("write");
        let error = ensure_private_dir(&path).expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::UnsafeDirectory { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn atomic_write_produces_a_0600_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("sub").join("secrets.toml");
        write_private_atomic(&path, b"schema_version = 1\n").expect("write");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "schema_version = 1\n"
        );
    }

    #[test]
    fn atomic_write_replaces_contents_and_leaves_no_temp_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("f.toml");
        write_private_atomic(&path, b"first").expect("write");
        write_private_atomic(&path, b"second").expect("rewrite");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "second");
        let leftovers: Vec<_> = std::fs::read_dir(temp.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left behind");
    }

    #[test]
    fn runtime_paths_are_all_under_the_runtime_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted_at(temp.path());
        for path in [
            paths.control_socket(),
            paths.api_endpoint_file(),
            paths.generated_config(),
            paths.last_good_config(),
            paths.runtime_state(),
            paths.daemon_lock(),
        ] {
            assert!(path.starts_with(&paths.runtime), "{}", path.display());
        }
    }
}
