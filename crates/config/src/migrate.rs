//! Versioned configuration migrations.
//!
//! Rules that keep migrations trustworthy:
//!
//! * every migration is a named function from version `n` to `n + 1`;
//! * a timestamped backup of the whole configuration directory is taken before
//!   anything is written;
//! * `--dry-run` reports what would change without touching the filesystem;
//! * unknown fields are preserved, never dropped, so a field added by a newer
//!   build survives a round trip through an older one.

use std::path::{Path, PathBuf};

use crate::{ConfigError, SCHEMA_VERSION, paths::write_private_atomic};

/// One step of the migration ladder.
pub struct Migration {
    /// Version this migration reads.
    pub from: u32,
    /// Version this migration produces.
    pub to: u32,
    /// Short description shown in the plan.
    pub description: &'static str,
    /// The transformation, operating on a parsed TOML document.
    pub apply: fn(&mut toml::Table) -> Result<(), String>,
}

/// Every known migration, in order.
///
/// Empty at schema version 1: there is nothing older to migrate from. The
/// machinery exists now so that the first real migration is a data change rather
/// than an infrastructure change.
pub const MIGRATIONS: &[Migration] = &[];

/// What migrating a directory would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    /// Files that would be rewritten, with their version transitions.
    pub steps: Vec<PlannedStep>,
    /// Where the backup would be written.
    pub backup_dir: PathBuf,
}

/// One planned file rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    /// File involved.
    pub path: PathBuf,
    /// Version found.
    pub from: u32,
    /// Version it would be brought to.
    pub to: u32,
    /// Human-readable descriptions of the migrations applied.
    pub descriptions: Vec<String>,
}

impl MigrationPlan {
    /// Whether anything would change.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// One line per planned change.
    #[must_use]
    pub fn render(&self) -> String {
        if self.steps.is_empty() {
            return "configuration is already at the current schema version".to_owned();
        }
        let mut out = format!("backup: {}\n", self.backup_dir.display());
        for step in &self.steps {
            out.push_str(&format!(
                "{}: schema {} -> {} ({})\n",
                step.path.display(),
                step.from,
                step.to,
                step.descriptions.join("; ")
            ));
        }
        out
    }
}

/// Work out what migrating `dir` would do, without writing anything.
///
/// # Errors
/// Propagates I/O and parse failures.
pub fn plan(dir: &Path) -> Result<MigrationPlan, ConfigError> {
    let mut steps = Vec::new();
    for entry in toml_files(dir)? {
        let text = std::fs::read_to_string(&entry).map_err(|source| ConfigError::Io {
            path: entry.clone(),
            source,
        })?;
        let table: toml::Table = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: entry.clone(),
            source: Box::new(source),
        })?;
        let found = table
            .get("schema_version")
            .and_then(toml::Value::as_integer)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(SCHEMA_VERSION);
        if found > SCHEMA_VERSION {
            return Err(ConfigError::SchemaTooNew {
                path: entry,
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == SCHEMA_VERSION {
            continue;
        }
        let descriptions: Vec<String> = MIGRATIONS
            .iter()
            .filter(|m| m.from >= found)
            .map(|m| m.description.to_owned())
            .collect();
        steps.push(PlannedStep {
            path: entry,
            from: found,
            to: SCHEMA_VERSION,
            descriptions,
        });
    }
    Ok(MigrationPlan {
        steps,
        backup_dir: backup_path(dir),
    })
}

/// Apply every pending migration, after taking a backup.
///
/// # Errors
/// Propagates I/O, parse and migration failures. On a migration failure nothing
/// has been written, because each file is rewritten only after every step for it
/// has succeeded in memory.
pub fn run(dir: &Path) -> Result<MigrationPlan, ConfigError> {
    let plan = plan(dir)?;
    if plan.is_empty() {
        return Ok(plan);
    }
    backup(dir, &plan.backup_dir)?;

    for step in &plan.steps {
        let text = std::fs::read_to_string(&step.path).map_err(|source| ConfigError::Io {
            path: step.path.clone(),
            source,
        })?;
        let mut table: toml::Table =
            toml::from_str(&text).map_err(|source| ConfigError::Parse {
                path: step.path.clone(),
                source: Box::new(source),
            })?;
        let mut version = step.from;
        for migration in MIGRATIONS.iter().filter(|m| m.from >= step.from) {
            (migration.apply)(&mut table).map_err(|reason| {
                ConfigError::Invalid(format!(
                    "migration {} -> {} failed for {}: {reason}",
                    migration.from,
                    migration.to,
                    step.path.display()
                ))
            })?;
            version = migration.to;
        }
        table.insert(
            "schema_version".to_owned(),
            toml::Value::Integer(i64::from(version.max(SCHEMA_VERSION))),
        );
        let rendered = toml::to_string_pretty(&table)?;
        write_private_atomic(&step.path, rendered.as_bytes())?;
    }
    Ok(plan)
}

fn toml_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(source) => {
            return Err(ConfigError::Io {
                path: dir.to_path_buf(),
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| ConfigError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        // `symlink_metadata` rather than `metadata`: a symlink in the config
        // directory must not redirect a migration write outside the tree.
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ConfigError::UnsafeDirectory {
                path,
                reason: "symlinks are not followed during migration".into(),
            });
        }
        if metadata.is_file() && path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn backup_path(dir: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    dir.with_file_name(format!(
        "{}.backup.{stamp}",
        dir.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("xraytui")
    ))
}

fn backup(dir: &Path, destination: &Path) -> Result<(), ConfigError> {
    crate::paths::ensure_private_dir(destination)?;
    for file in toml_files(dir)? {
        let Some(name) = file.file_name() else {
            continue;
        };
        let contents = std::fs::read(&file).map_err(|source| ConfigError::Io {
            path: file.clone(),
            source,
        })?;
        write_private_atomic(&destination.join(name), &contents)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_files_need_no_migration() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("config.toml"), "schema_version = 1\n").expect("write");
        let plan = plan(temp.path()).expect("plan");
        assert!(plan.is_empty());
        assert!(
            plan.render()
                .contains("already at the current schema version")
        );
    }

    #[test]
    fn a_newer_file_is_refused_rather_than_downgraded() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("config.toml"), "schema_version = 42\n").expect("write");
        let error = plan(temp.path()).expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::SchemaTooNew { found: 42, .. }),
            "{error:?}"
        );
    }

    #[test]
    fn an_absent_directory_is_not_an_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let plan = plan(&temp.path().join("nope")).expect("plan");
        assert!(plan.is_empty());
    }

    #[test]
    fn symlinks_in_the_config_directory_are_refused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let outside = temp.path().join("outside.toml");
        std::fs::write(&outside, "schema_version = 1\n").expect("write");
        let dir = temp.path().join("config");
        std::fs::create_dir(&dir).expect("mkdir");
        std::os::unix::fs::symlink(&outside, dir.join("linked.toml")).expect("symlink");
        let error = plan(&dir).expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::UnsafeDirectory { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn migration_run_is_a_no_op_at_the_current_version() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "schema_version = 1\nvalue = 3\n").expect("write");
        let plan = run(temp.path()).expect("run");
        assert!(plan.is_empty());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "schema_version = 1\nvalue = 3\n"
        );
    }

    #[test]
    fn migration_ladder_is_contiguous() {
        // Guards against someone adding a 3 -> 4 migration without a 2 -> 3.
        for pair in MIGRATIONS.windows(2) {
            assert_eq!(pair[0].to, pair[1].from, "migration ladder has a gap");
        }
        if let Some(last) = MIGRATIONS.last() {
            assert_eq!(
                last.to, SCHEMA_VERSION,
                "ladder does not reach the current version"
            );
        }
    }
}
