//! Atomic writes for credential-bearing exports.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

/// Failure while atomically writing a private export file.
#[derive(Debug, thiserror::Error)]
#[error("{operation} {path}: {source}")]
pub struct PrivateFileError {
    /// Operation that failed, without secret data.
    pub operation: &'static str,
    /// Requested destination, never its secret contents.
    pub path: String,
    /// Underlying filesystem error.
    #[source]
    pub source: std::io::Error,
}

/// Atomically replace `path` with `bytes` and force the resulting mode to 0600.
///
/// A uniquely named sibling is opened with `create_new`, written, synced, and
/// renamed over the destination. This prevents partial exports after a crash and
/// prevents an existing permissive file from retaining its old mode.
///
/// # Errors
/// Returns [`PrivateFileError`] when creation, writing, syncing, permission
/// setting, or replacement fails.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), PrivateFileError> {
    let shown = path.display().to_string();
    // `Path::parent("node.txt")` is `Some("")`, not `None`. Treat that empty
    // path as the current directory or the final directory fsync fails *after*
    // the credential was successfully renamed into place.
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| PrivateFileError {
        operation: "validating destination",
        path: shown.clone(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination has no file name",
        ),
    })?;

    let mut last_collision = None;
    for _ in 0..128 {
        let nonce = rand::random::<u64>();
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".xraytui.{}.{nonce:016x}.tmp", std::process::id()));
        let temporary = parent.join(temporary_name);
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary);
        let mut file = match opened {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(source);
                continue;
            }
            Err(source) => {
                return Err(PrivateFileError {
                    operation: "creating private temporary file for",
                    path: shown,
                    source,
                });
            }
        };

        let result = (|| {
            file.write_all(bytes).map_err(|error| ("writing", error))?;
            file.sync_all()
                .map_err(|error| ("syncing temporary file for", error))?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| ("setting private permissions on", error))?;
            drop(file);
            std::fs::rename(&temporary, path).map_err(|error| ("replacing", error))?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| ("syncing parent directory for", error))?;
            Ok::<(), (&'static str, std::io::Error)>(())
        })();
        if let Err((operation, source)) = result {
            let _ = std::fs::remove_file(&temporary);
            return Err(PrivateFileError {
                operation,
                path: shown,
                source,
            });
        }
        return Ok(());
    }

    Err(PrivateFileError {
        operation: "allocating private temporary file for",
        path: shown,
        source: last_collision.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate a temporary export file",
            )
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_is_complete_and_private_even_when_target_was_public() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"old").expect("seed file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("public mode");

        write_private_atomic(&path, b"new credential").expect("replace");

        assert_eq!(std::fs::read(&path).expect("read"), b"new credential");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let entries = std::fs::read_dir(dir.path())
            .expect("read dir")
            .collect::<Result<Vec<_>, _>>()
            .expect("entries");
        assert_eq!(entries.len(), 1, "temporary file was left behind");
    }

    #[test]
    fn a_bare_relative_filename_uses_the_current_directory_for_the_sync() {
        let path = Path::new("node.txt");
        let parent = path
            .parent()
            .filter(|candidate| !candidate.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        assert_eq!(parent, Path::new("."));
    }
}
