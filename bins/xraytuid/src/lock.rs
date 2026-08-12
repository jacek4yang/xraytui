//! Single-instance locking.
//!
//! An advisory `flock` on a file in `XDG_RUNTIME_DIR`. The kernel releases it
//! when the process exits — including on `SIGKILL` — so a crashed daemon never
//! leaves a lock that has to be cleared by hand.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};

/// A held lock. Dropping it, or exiting, releases the lock.
#[derive(Debug)]
pub struct DaemonLock {
    _file: File,
}

/// Take the daemon lock, failing if another daemon holds it.
///
/// # Errors
/// Returns an error naming the holding process when the lock is taken.
pub fn acquire(path: &Path) -> Result<DaemonLock> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        xraytui_config::ensure_private_dir(parent)
            .with_context(|| format!("cannot prepare {}", parent.display()))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;

    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            let holder = std::fs::read_to_string(path).unwrap_or_default();
            let holder = holder.trim();
            anyhow::bail!(
                "{} is locked by another xraytuid{}",
                path.display(),
                if holder.is_empty() {
                    String::new()
                } else {
                    format!(" (pid {holder})")
                }
            );
        }
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot lock {}", path.display()));
        }
    }

    // Record the pid for a human reading the file, after taking the lock so the
    // contents always describe the current holder.
    let pid = rustix::process::getpid().as_raw_nonzero();
    file.set_len(0).ok();
    let _ = write!(file, "{pid}");
    let _ = file.flush();

    Ok(DaemonLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_can_be_taken_and_released() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("daemon.lock");
        let lock = acquire(&path).expect("first acquire");
        assert!(path.is_file());
        drop(lock);
        // Releasing must make it available again.
        let _second = acquire(&path).expect("second acquire after release");
    }

    #[test]
    fn a_held_lock_blocks_a_second_daemon() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("daemon.lock");
        let _held = acquire(&path).expect("first acquire");
        let error = acquire(&path).expect_err("second acquire must fail");
        assert!(error.to_string().contains("locked by another xraytuid"), "{error}");
    }

    #[test]
    fn the_lock_file_records_the_holding_pid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("daemon.lock");
        let _held = acquire(&path).expect("acquire");
        let contents = std::fs::read_to_string(&path).expect("read");
        let recorded: i32 = contents.trim().parse().expect("a pid");
        assert_eq!(recorded, rustix::process::getpid().as_raw_nonzero().get());
    }

    #[test]
    fn the_lock_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("daemon.lock");
        let _held = acquire(&path).expect("acquire");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
