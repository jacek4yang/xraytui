//! Versioned TOML configuration, XDG paths and migrations.
//!
//! The user-editable source of truth is a small set of TOML files under
//! `~/.config/xraytui`. They are hand-editable, diffable, and carry an explicit
//! `schema_version`; a file written by a *newer* xraytui is a hard error rather
//! than a best-effort parse, so a downgrade cannot silently mangle policy.
//!
//! Generated Xray JSON is never read back as configuration. It is a build
//! artifact of the compiler.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod migrate;
pub mod paths;
mod schema;
pub mod store;

use std::path::{Path, PathBuf};

pub use paths::{Paths, ensure_private_dir, write_private_atomic};
pub use schema::{
    ConfigFile, CoreSection, DisabledFamilyPolicy, DnsManager, DnsSection, FailurePolicy,
    HealthSection, ReleaseChannel, RuntimeSection, SubscriptionSection, TunSection, UiSection,
    is_valid_interface_name,
};

/// Current schema version of `config.toml` and the policy files.
pub const SCHEMA_VERSION: u32 = 1;

/// Configuration failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `HOME` is unset or empty.
    #[error("cannot determine the home directory; set HOME or pass --config-dir")]
    NoHome,
    /// A filesystem operation failed.
    #[error("{path}: {source}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A directory was not a private directory owned by this user.
    #[error("refusing to use {path}: {reason}")]
    UnsafeDirectory {
        /// Path involved.
        path: PathBuf,
        /// Why it was refused.
        reason: String,
    },
    /// TOML could not be parsed.
    #[error("{path}: {source}")]
    Parse {
        /// Path involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// Serialisation failed.
    #[error("failed to serialise configuration: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// The file was written by a newer version of xraytui.
    #[error(
        "{path} declares schema_version {found}, but this build understands at most {supported}; \
         upgrade xraytui or restore the previous file"
    )]
    SchemaTooNew {
        /// Path involved.
        path: PathBuf,
        /// Version found in the file.
        found: u32,
        /// Highest version this build understands.
        supported: u32,
    },
    /// The configuration was structurally valid but semantically wrong.
    #[error("{0}")]
    Invalid(String),
}

/// Read a TOML file into `T`, enforcing the schema version.
///
/// # Errors
/// Propagates I/O and parse failures, and rejects newer schema versions.
pub fn load_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    check_schema_version(path, &text)?;
    let value = toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    Ok(Some(value))
}

/// Serialise `value` and write it atomically with mode 0600.
///
/// # Errors
/// Propagates serialisation and I/O failures.
pub fn store_toml<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), ConfigError> {
    let text = toml::to_string_pretty(value)?;
    write_private_atomic(path, text.as_bytes())
}

/// Peek at `schema_version` without deserialising the whole document.
fn check_schema_version(path: &Path, text: &str) -> Result<(), ConfigError> {
    #[derive(serde::Deserialize)]
    struct Peek {
        #[serde(default)]
        schema_version: Option<u32>,
    }
    let peek: Peek = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if let Some(found) = peek.schema_version
        && found > SCHEMA_VERSION
    {
        return Err(ConfigError::SchemaTooNew {
            path: path.to_path_buf(),
            found,
            supported: SCHEMA_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Sample {
        schema_version: u32,
        value: String,
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let loaded: Option<Sample> = load_toml(&temp.path().join("absent.toml")).expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn round_trip_preserves_values() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("s.toml");
        let sample = Sample {
            schema_version: 1,
            value: "x".into(),
        };
        store_toml(&path, &sample).expect("store");
        let loaded: Sample = load_toml(&path).expect("load").expect("present");
        assert_eq!(loaded, sample);
    }

    #[test]
    fn newer_schema_is_a_hard_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("s.toml");
        std::fs::write(&path, "schema_version = 99\nvalue = \"x\"\n").expect("write");
        let error = load_toml::<Sample>(&path).expect_err("must refuse");
        assert!(
            matches!(
                error,
                ConfigError::SchemaTooNew {
                    found: 99,
                    supported: 1,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn malformed_toml_reports_the_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("s.toml");
        std::fs::write(&path, "this is not = = toml").expect("write");
        let error = load_toml::<Sample>(&path).expect_err("must refuse");
        assert!(error.to_string().contains("s.toml"), "{error}");
    }
}
