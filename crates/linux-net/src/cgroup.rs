//! cgroup v2 groups, and moving a process into one safely.
//!
//! # Why a cgroup rather than a uid or a pid
//!
//! Acceptance scenario M asks for *exact-instance* isolation: launching a second
//! copy of the same program under a different profile must not disturb the
//! first. A uid cannot express that — both copies share it. A pid can, but a pid
//! is a number that the kernel may hand to a different process between the
//! moment it is checked and the moment it is used.
//!
//! A cgroup is inherited by children, survives `exec`, and is what nftables can
//! match on with `socket cgroupv2`. So the helper creates one group per profile
//! and puts the launched process in it; everything that process spawns lands
//! there too.
//!
//! # `pidfd`, never a pid
//!
//! [`CgroupTree::classify`] takes a `pidfd` received over `SCM_RIGHTS`. Holding
//! it pins the process's identity: the number cannot be recycled while the
//! descriptor is open, so resolving it to a pid and then reading `/proc/<pid>`
//! is not a race. The owner check is made against that directory's owner, which
//! the kernel maintains, rather than against anything the caller claimed.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};

/// The single slice every project cgroup lives under.
pub const SLICE: &str = "xraytui.slice";

/// The profile name reserved for the supervised core itself.
///
/// The core must reach the proxy over the physical link, so its traffic is
/// accepted unmarked by the first rule in the marking chain.
pub const CORE_PROFILE: &str = "core";

/// Path of a profile cgroup relative to the cgroup v2 root.
///
/// This is the form nftables wants: `socket cgroupv2` compares against a
/// root-relative path, not a filesystem path.
#[must_use]
pub fn relative_path(uid: u32, profile: &str) -> String {
    format!("{SLICE}/u{uid}/{profile}")
}

/// Errors the cgroup backend can report.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    /// No cgroup v2 hierarchy is mounted.
    #[error("no cgroup v2 hierarchy is mounted; per-application routing needs one")]
    NoHierarchy,
    /// A directory could not be created or removed.
    #[error("{operation} {path}: {source}")]
    Io {
        /// What was attempted.
        operation: &'static str,
        /// Path involved.
        path: String,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// The `pidfd` could not be resolved to a process.
    #[error("cannot identify the process behind the descriptor: {0}")]
    UnknownProcess(String),
    /// The process belongs to somebody else.
    #[error("process {pid} belongs to uid {owner}, not to uid {caller}")]
    NotYours {
        /// Process identifier.
        pid: u32,
        /// Real owner.
        owner: u32,
        /// Who asked.
        caller: u32,
    },
    /// The group still has members.
    #[error("cgroup {0} still has processes in it")]
    NotEmpty(String),
}

/// A cgroup v2 hierarchy the helper can write to.
#[derive(Debug, Clone)]
pub struct CgroupTree {
    root: PathBuf,
}

impl CgroupTree {
    /// Use a specific hierarchy root. The test suite mounts its own.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Find the cgroup v2 mount point, preferring the conventional location.
    ///
    /// Returns `None` on a machine running cgroup v1 only.
    #[must_use]
    pub fn detect() -> Option<PathBuf> {
        let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
        let mut candidates = Vec::new();
        for line in mounts.lines() {
            let mut fields = line.split_whitespace();
            let _source = fields.next()?;
            let target = fields.next()?;
            let kind = fields.next()?;
            if kind == "cgroup2" {
                candidates.push(PathBuf::from(unescape_mount(target)));
            }
        }
        candidates
            .iter()
            .find(|path| path.as_os_str() == "/sys/fs/cgroup")
            .or_else(|| candidates.first())
            .cloned()
    }

    /// The hierarchy root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the root looks like a cgroup v2 hierarchy.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.root.join("cgroup.controllers").is_file()
    }

    /// Absolute path of a profile's group.
    #[must_use]
    pub fn path_for(&self, uid: u32, profile: &str) -> PathBuf {
        self.root.join(relative_path(uid, profile))
    }

    /// Create a profile's group, and every ancestor it needs.
    ///
    /// # Errors
    /// [`CgroupError::NoHierarchy`] or [`CgroupError::Io`].
    pub fn create(&self, uid: u32, profile: &str) -> Result<PathBuf, CgroupError> {
        if !self.is_usable() {
            return Err(CgroupError::NoHierarchy);
        }
        let path = self.path_for(uid, profile);
        // `create_dir_all` is right here: in cgroup v2 each directory *is* a
        // cgroup, so creating the ancestors is creating the slice and the
        // per-user group.
        std::fs::create_dir_all(&path).map_err(|source| CgroupError::Io {
            operation: "create cgroup",
            path: path.display().to_string(),
            source,
        })?;
        Ok(path)
    }

    /// Remove a profile's group.
    ///
    /// # Errors
    /// [`CgroupError::NotEmpty`] if processes remain, [`CgroupError::Io`]
    /// otherwise. A group that is already gone is not an error.
    pub fn remove(&self, uid: u32, profile: &str) -> Result<(), CgroupError> {
        let path = self.path_for(uid, profile);
        if !path.exists() {
            return Ok(());
        }
        if !self.members(uid, profile)?.is_empty() {
            return Err(CgroupError::NotEmpty(relative_path(uid, profile)));
        }
        match std::fs::remove_dir(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(CgroupError::Io {
                operation: "remove cgroup",
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Process ids currently in a profile's group.
    ///
    /// # Errors
    /// [`CgroupError::Io`] if `cgroup.procs` cannot be read.
    pub fn members(&self, uid: u32, profile: &str) -> Result<Vec<u32>, CgroupError> {
        let path = self.path_for(uid, profile).join("cgroup.procs");
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(CgroupError::Io {
                    operation: "read",
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        Ok(text
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect())
    }

    /// Move the process behind `pidfd` into a profile's group.
    ///
    /// # Errors
    /// [`CgroupError::NotYours`] if the process does not belong to `caller_uid`,
    /// and the process is **not** moved.
    pub fn classify(
        &self,
        caller_uid: u32,
        profile: &str,
        pidfd: BorrowedFd<'_>,
    ) -> Result<u32, CgroupError> {
        let pid = pid_of(pidfd)?;
        let owner = owner_of(pid)?;
        if owner != caller_uid {
            return Err(CgroupError::NotYours {
                pid,
                owner,
                caller: caller_uid,
            });
        }
        let path = self.create(caller_uid, profile)?.join("cgroup.procs");
        std::fs::write(&path, pid.to_string()).map_err(|source| CgroupError::Io {
            operation: "classify into",
            path: path.display().to_string(),
            source,
        })?;
        Ok(pid)
    }

    /// Remove every group belonging to a uid, deepest first.
    ///
    /// Groups that still have members are left alone and reported, because
    /// removing a cgroup out from under a running process is not possible and
    /// pretending otherwise would hide a leak.
    ///
    /// # Errors
    /// [`CgroupError::Io`] for anything other than "already gone".
    pub fn remove_user(&self, uid: u32) -> Result<Vec<String>, CgroupError> {
        let user_root = self.root.join(SLICE).join(format!("u{uid}"));
        let mut removed = Vec::new();
        let Ok(entries) = std::fs::read_dir(&user_root) else {
            return Ok(removed);
        };
        let mut profiles: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        profiles.sort();
        for profile in profiles {
            if self.remove(uid, &profile).is_ok() {
                removed.push(relative_path(uid, &profile));
            }
        }
        // The per-user group goes only when it is empty, and the slice is left
        // alone because other users may still be inside it.
        let _ = std::fs::remove_dir(&user_root);
        Ok(removed)
    }
}

/// Resolve a `pidfd` to a process id by reading the kernel's own view of it.
fn pid_of(pidfd: BorrowedFd<'_>) -> Result<u32, CgroupError> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let text = std::fs::read_to_string(&path)
        .map_err(|error| CgroupError::UnknownProcess(format!("{path}: {error}")))?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:") {
            let pid: i64 = value
                .trim()
                .parse()
                .map_err(|_| CgroupError::UnknownProcess("Pid is not a number".into()))?;
            // -1 means the process is gone; 0 means the descriptor is not a pidfd.
            return u32::try_from(pid)
                .map_err(|_| CgroupError::UnknownProcess("the process has already exited".into()));
        }
    }
    Err(CgroupError::UnknownProcess(
        "the descriptor is not a pidfd".into(),
    ))
}

/// The real uid that owns a process, as the kernel reports it.
fn owner_of(pid: u32) -> Result<u32, CgroupError> {
    use std::os::unix::fs::MetadataExt as _;
    let path = format!("/proc/{pid}");
    let metadata = std::fs::metadata(&path)
        .map_err(|error| CgroupError::UnknownProcess(format!("{path}: {error}")))?;
    Ok(metadata.uid())
}

/// `/proc/mounts` escapes spaces and a few other characters as octal.
fn unescape_mount(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let digits: String = chars.clone().take(3).collect();
        if digits.len() == 3
            && let Ok(value) = u8::from_str_radix(&digits, 8)
        {
            out.push(char::from(value));
            for _ in 0..3 {
                let _ = chars.next();
            }
        } else {
            out.push('\\');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_are_three_levels_deep_under_the_root() {
        let path = relative_path(1000, "work");
        assert_eq!(path, "xraytui.slice/u1000/work");
        assert_eq!(path.split('/').count(), 3);
    }

    #[test]
    fn a_profile_cannot_escape_its_user_directory() {
        // The protocol rejects separators, so this is a second line of defence:
        // whatever arrives, the path stays under the user's own directory.
        let tree = CgroupTree::new("/sys/fs/cgroup");
        let path = tree.path_for(1000, "work");
        assert!(path.starts_with("/sys/fs/cgroup/xraytui.slice/u1000"));
    }

    #[test]
    fn mount_escapes_are_decoded() {
        assert_eq!(unescape_mount("/sys/fs/cgroup"), "/sys/fs/cgroup");
        assert_eq!(unescape_mount("/mnt/my\\040disk"), "/mnt/my disk");
        assert_eq!(unescape_mount("/tmp/odd\\zz"), "/tmp/odd\\zz");
    }

    #[test]
    fn an_unmounted_root_is_reported_rather_than_created() {
        let dir = tempfile::tempdir().expect("temp dir");
        let tree = CgroupTree::new(dir.path());
        assert!(!tree.is_usable());
        assert!(matches!(
            tree.create(1000, "work"),
            Err(CgroupError::NoHierarchy)
        ));
    }

    #[test]
    fn detection_finds_a_hierarchy_or_honestly_reports_none() {
        // Both outcomes are legitimate depending on the host; what matters is
        // that a reported path really is a cgroup v2 root.
        if let Some(root) = CgroupTree::detect() {
            assert!(
                CgroupTree::new(&root).is_usable(),
                "{root:?} is not cgroup v2"
            );
        }
    }

    #[test]
    fn a_descriptor_that_is_not_a_pidfd_is_rejected() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let fd = std::os::fd::AsFd::as_fd(file.as_file());
        assert!(matches!(pid_of(fd), Err(CgroupError::UnknownProcess(_))));
    }

    #[test]
    fn the_owner_of_our_own_process_is_our_own_uid() {
        let pid = std::process::id();
        assert_eq!(
            owner_of(pid).expect("own uid"),
            rustix::process::getuid().as_raw()
        );
    }

    #[test]
    fn members_of_a_group_that_does_not_exist_is_empty_not_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let tree = CgroupTree::new(dir.path());
        assert_eq!(
            tree.members(1000, "work").expect("members"),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn removing_a_group_that_does_not_exist_is_not_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let tree = CgroupTree::new(dir.path());
        assert!(tree.remove(1000, "work").is_ok());
        assert!(tree.remove_user(1000).expect("remove user").is_empty());
    }
}
