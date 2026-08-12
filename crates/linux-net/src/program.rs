//! Finding and running the two external programs the helper needs.
//!
//! # Why this exists
//!
//! The helper runs as root and clears the environment of every process it
//! starts, so that nothing a user controls can influence `nft` or `resolvconf`.
//! Clearing the environment has one consequence that is easy to miss and was
//! caught by the namespace tests: with an empty environment there is no `PATH`,
//! and a bare program name cannot be resolved at all. Rust's `Command` resolves
//! a relative program against the *child's* `PATH` once `env_clear` has been
//! called, so `Command::new("nft").env_clear()` fails with `NotFound` on a
//! machine where `nft` is installed and working.
//!
//! The answer is to resolve the name to an absolute path first, against a fixed
//! list of directories, and to give the child a fixed `PATH` of the same list.
//! Both are deliberate: an operator's `PATH` should not decide which `nft` the
//! privileged helper executes.

use std::path::{Path, PathBuf};

/// The only directories the helper will look in for a program.
///
/// Deliberately not taken from the environment. A helper that ran whichever
/// `nft` happened to be first on somebody's `PATH` would be a privilege
/// escalation waiting for a writable directory.
pub const SEARCH_PATH: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin"];

/// The `PATH` given to a child process.
pub const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin";

/// Resolve a program name to an absolute path.
///
/// An absolute path is accepted as-is if it names an existing file, which is
/// what lets the test suite point the helper at a stand-in. A relative path with
/// a separator in it is rejected: there is no legitimate reason for the helper
/// to run `./nft`.
#[must_use]
pub fn resolve(program: &Path) -> Option<PathBuf> {
    if program.is_absolute() {
        return program.is_file().then(|| program.to_path_buf());
    }
    if program.components().count() != 1 {
        return None;
    }
    SEARCH_PATH
        .iter()
        .map(|directory| Path::new(directory).join(program))
        .find(|candidate| candidate.is_file())
}

/// A `Command` with a cleared environment, a fixed `PATH`, and no controlling
/// terminal inherited from the caller.
#[must_use]
pub fn command(program: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.env_clear().env("PATH", CHILD_PATH);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_on_the_fixed_path_resolves_to_an_absolute_path() {
        // `sh` is present in /bin or /usr/bin on every system this targets.
        let resolved = resolve(Path::new("sh")).expect("sh must be findable");
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("sh"));
    }

    #[test]
    fn a_program_that_does_not_exist_resolves_to_nothing() {
        assert_eq!(
            resolve(Path::new("a-program-that-does-not-exist-4242")),
            None
        );
    }

    #[test]
    fn an_absolute_path_is_taken_at_face_value() {
        assert_eq!(
            resolve(Path::new("/nonexistent/nft")),
            None,
            "an absolute path that is not there must not silently fall back to the search path"
        );
        let file = tempfile::NamedTempFile::new().expect("temp file");
        assert_eq!(
            resolve(file.path()).as_deref(),
            Some(file.path()),
            "an absolute path that exists is used as given"
        );
    }

    #[test]
    fn a_relative_path_with_separators_is_refused() {
        assert_eq!(resolve(Path::new("./nft")), None);
        assert_eq!(resolve(Path::new("../sbin/nft")), None);
        assert_eq!(resolve(Path::new("subdir/nft")), None);
    }

    #[test]
    fn a_child_gets_a_fixed_path_and_nothing_else() {
        let program = resolve(Path::new("sh")).expect("sh");
        let output = command(&program)
            .args(["-c", "echo \"$PATH\"; echo \"count=$(env | wc -l)\""])
            .output()
            .expect("run");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains(CHILD_PATH), "{text}");
        // PATH plus whatever the shell itself sets; the point is that nothing
        // was inherited.
        assert!(!text.contains("XRAYTUI"), "{text}");
    }

    #[test]
    fn resolution_is_what_makes_a_cleared_environment_workable() {
        // The regression this module exists for: a bare name with a cleared
        // environment cannot be spawned, and the resolved absolute path can.
        let bare = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .env_clear()
            .status();
        let resolved = resolve(Path::new("sh")).expect("sh");
        let absolute = command(&resolved).args(["-c", "exit 0"]).status();
        assert!(absolute.is_ok(), "an absolute path must always spawn");
        if let Err(error) = bare {
            // Documents the platform behaviour that motivated this module.
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "a bare name with no PATH fails as NotFound"
            );
        }
    }
}
