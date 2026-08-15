//! Durable runtime state: the small set of facts that must survive a restart.
//!
//! # What belongs here, and what does not
//!
//! Policy — nodes, groups, chains, profiles, rules, subscriptions — is TOML on
//! disk, editable by hand, and stays that way. This database is for the things
//! that are *observed* rather than configured, and that a daemon coming back up
//! would otherwise have to pretend it never knew:
//!
//! * which mode and tunnel state were running, so a restart resumes rather than
//!   reverting to off;
//! * where each profile was pointed, so a selector can be replayed after the
//!   core restarts;
//! * which generation was last known good, so a rollback target survives a
//!   crash;
//! * when each subscription was last fetched and what its `ETag` was, so a
//!   restart does not re-download everything at once;
//! * a bounded health history, so a node that has been failing all morning is
//!   still known to be failing after `systemctl --user restart`.
//!
//! Live traffic counters are deliberately *not* stored. They change every few
//! seconds, they are meaningless after a restart, and writing them would turn
//! an idle laptop into a disk-writing laptop.
//!
//! # Why SQLite rather than a file
//!
//! Two writers are possible — the daemon, and a CLI command that ran while the
//! daemon was busy — and a half-written JSON file is a worse failure than a
//! locked one. Transactions also make "record the probe and trim the history"
//! one operation rather than two, which is what keeps the history actually
//! bounded rather than bounded-on-average.
//!
//! # Privacy
//!
//! Nothing here contains a credential. Subscription URLs are secret because
//! they carry tokens, so the store keeps a subscription's *identifier* and
//! never its URL. Health records are counts, latencies and bounded reasons.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use xraytui_domain::{
    GenerationId, HealthRecord, NodeId, ProbeKind, ProbeOutcome, ProbeResult, SubscriptionId,
    SystemMode,
};

/// Schema version this build writes. Bumping it means adding a migration.
pub const SCHEMA_VERSION: i64 = 1;

/// How many probe results are kept per subject.
///
/// Enough to see a pattern over an afternoon, small enough that a hundred nodes
/// probed every five minutes is a database of a few megabytes rather than an
/// unbounded one.
pub const HISTORY_LIMIT: usize = 200;

/// Errors the store can report.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database could not be opened, read or written.
    #[error("state database {path}: {source}")]
    Database {
        /// Which database.
        path: String,
        /// Underlying failure.
        #[source]
        source: rusqlite::Error,
    },
    /// The directory could not be created with the right permissions.
    #[error("cannot prepare {path}: {source}")]
    Directory {
        /// Which directory.
        path: String,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// The file on disk was written by a newer build.
    #[error(
        "state database {path} has schema version {found}, but this build understands \
         {SCHEMA_VERSION}. A newer xraytui wrote it; upgrade, or move the file aside."
    )]
    TooNew {
        /// Which database.
        path: String,
        /// What was found.
        found: i64,
    },
}

/// What the daemon needs back after a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovered {
    /// Mode the daemon was last running in, if it recorded one.
    pub mode: Option<SystemMode>,
    /// Whether the system tunnel was up.
    pub tun_enabled: bool,
    /// Generation that last started and passed its health gate.
    pub last_known_good: Option<GenerationId>,
    /// When that generation was recorded, in Unix seconds.
    pub last_known_good_at: Option<u64>,
    /// Profile targets as they were last applied, rendered the way `Target`'s
    /// `Display` renders them.
    pub profile_targets: Vec<(String, String)>,
    /// A migration or multi-step change that began and never finished.
    pub interrupted: Option<Interrupted>,
}

/// A transaction that started and did not record its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interrupted {
    /// What was being attempted, e.g. `migrate` or `subscription-update`.
    pub operation: String,
    /// Free-form detail: which file, which subscription, which generation.
    pub detail: String,
    /// When it started, Unix seconds.
    pub started_at: u64,
}

/// Fetch metadata for one subscription.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionState {
    /// Unix seconds of the last successful fetch.
    pub last_success: Option<u64>,
    /// Unix seconds of the last attempt, successful or not.
    pub last_attempt: Option<u64>,
    /// `ETag` from the last successful fetch.
    pub etag: Option<String>,
    /// Consecutive failures since the last success.
    pub failures: u32,
    /// Bounded description of the last failure.
    pub last_error: Option<String>,
}

/// The durable store.
///
/// `rusqlite::Connection` is `Send` but not `Sync`, and the daemon shares one
/// store across tasks, so the connection lives behind a mutex rather than being
/// opened per call: an open-per-call design would multiply the WAL files and
/// lose the transaction guarantees that are the reason for using SQLite.
pub struct StateStore {
    connection: std::sync::Mutex<Connection>,
    path: PathBuf,
}

impl std::fmt::Debug for StateStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl StateStore {
    /// Open — creating if absent — and migrate to [`SCHEMA_VERSION`].
    ///
    /// The parent directory is created 0700 and the database 0600, because the
    /// history reveals which servers a person uses even though it holds no
    /// credential.
    ///
    /// # Errors
    /// Propagates directory, permission and SQLite failures, and refuses a
    /// database written by a newer build.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            Self::private_directory(parent)?;
        }
        let connection = Connection::open(&path).map_err(|source| StoreError::Database {
            path: path.display().to_string(),
            source,
        })?;
        let store = Self {
            connection: std::sync::Mutex::new(connection),
            path,
        };
        store.harden()?;
        store.migrate()?;
        store.restrict_file_mode()?;
        Ok(store)
    }

    /// An in-memory store, for tests and for a daemon whose database could not
    /// be opened: losing history is better than losing the proxy.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn in_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory().map_err(|source| StoreError::Database {
            path: ":memory:".to_owned(),
            source,
        })?;
        let store = Self {
            connection: std::sync::Mutex::new(connection),
            path: PathBuf::from(":memory:"),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Where this store lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run `body` with the connection.
    ///
    /// A poisoned lock is recovered rather than propagated: the mutex guards a
    /// connection, not an invariant, and a panic in one query does not make the
    /// database unusable — refusing every later write because of it would turn
    /// one failed probe into a dead daemon.
    fn with<T>(
        &self,
        body: impl FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    ) -> Result<T, StoreError> {
        let guard = match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        body(&guard).map_err(|source| self.error(source))
    }

    fn error(&self, source: rusqlite::Error) -> StoreError {
        StoreError::Database {
            path: self.path.display().to_string(),
            source,
        }
    }

    fn private_directory(directory: &Path) -> Result<(), StoreError> {
        use std::os::unix::fs::DirBuilderExt;
        if !directory.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .map_err(|source| StoreError::Directory {
                    path: directory.display().to_string(),
                    source,
                })?;
        }
        Ok(())
    }

    fn restrict_file_mode(&self) -> Result<(), StoreError> {
        use std::os::unix::fs::PermissionsExt;
        // WAL and shared-memory siblings carry the same rows as the database,
        // so restricting only the database would be theatre.
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.path.clone().into_os_string();
            path.push(suffix);
            let path = PathBuf::from(path);
            if path.exists() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                    |source| StoreError::Directory {
                        path: path.display().to_string(),
                        source,
                    },
                )?;
            }
        }
        Ok(())
    }

    fn harden(&self) -> Result<(), StoreError> {
        self.with(|connection| {
            // WAL so a reader never blocks the daemon's writer; NORMAL because
            // losing the last few probe results to a power cut is acceptable
            // and FULL would fsync on a laptop every probe.
            connection.pragma_update(None, "journal_mode", "WAL")?;
            connection.pragma_update(None, "synchronous", "NORMAL")?;
            connection.pragma_update(None, "foreign_keys", "ON")
        })
    }

    /// Create or upgrade the schema.
    ///
    /// The ladder is keyed on `PRAGMA user_version`, applied in one transaction
    /// per step, so an interrupted upgrade either happened or did not.
    fn migrate(&self) -> Result<(), StoreError> {
        let found: i64 = self
            .with(|connection| connection.query_row("PRAGMA user_version", [], |row| row.get(0)))?;
        if found > SCHEMA_VERSION {
            return Err(StoreError::TooNew {
                path: self.path.display().to_string(),
                found,
            });
        }
        if found < 1 {
            self.with(|connection| {
                connection.execute_batch(
                    "BEGIN;
                     CREATE TABLE IF NOT EXISTS meta (
                         key   TEXT PRIMARY KEY,
                         value TEXT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS profile_target (
                         profile TEXT PRIMARY KEY,
                         target  TEXT NOT NULL,
                         at      INTEGER NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS subscription (
                         id           TEXT PRIMARY KEY,
                         last_success INTEGER,
                         last_attempt INTEGER,
                         etag         TEXT,
                         failures     INTEGER NOT NULL DEFAULT 0,
                         last_error   TEXT
                     );
                     CREATE TABLE IF NOT EXISTS probe (
                         subject    TEXT NOT NULL,
                         at         INTEGER NOT NULL,
                         ok         INTEGER NOT NULL,
                         latency_ms INTEGER,
                         detail     TEXT
                     );
                     CREATE INDEX IF NOT EXISTS probe_subject_at ON probe (subject, at DESC);
                     CREATE TABLE IF NOT EXISTS transaction_log (
                         id        INTEGER PRIMARY KEY AUTOINCREMENT,
                         operation TEXT NOT NULL,
                         detail    TEXT NOT NULL,
                         started   INTEGER NOT NULL,
                         finished  INTEGER
                     );
                     PRAGMA user_version = 1;
                     COMMIT;",
                )
            })?;
        }
        Ok(())
    }

    // --- meta ---------------------------------------------------------------

    fn put_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.with(|connection| {
            connection.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
        })
        .map(|_| ())
    }

    fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    params![key],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
    }

    /// Record the mode and tunnel state the daemon is running in.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn record_mode(&self, mode: SystemMode, tun_enabled: bool) -> Result<(), StoreError> {
        self.put_meta("mode", mode.as_str())?;
        self.put_meta("tun_enabled", if tun_enabled { "1" } else { "0" })
    }

    /// Record a generation that started and passed its health gate.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn record_last_known_good(
        &self,
        generation: GenerationId,
        at: u64,
    ) -> Result<(), StoreError> {
        self.put_meta("last_known_good", &generation.0.to_string())?;
        self.put_meta("last_known_good_at", &at.to_string())
    }

    /// Record where a profile is pointed.
    ///
    /// The target is stored as the string a user would type, so the store does
    /// not have to know the target grammar and a change in the domain model does
    /// not invalidate the database.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn record_profile_target(
        &self,
        profile: &str,
        target: &str,
        at: u64,
    ) -> Result<(), StoreError> {
        self.with(|connection| {
            connection.execute(
                "INSERT INTO profile_target (profile, target, at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(profile) DO UPDATE SET
                     target = excluded.target,
                     at     = excluded.at",
                params![profile, target, at as i64],
            )
        })
        .map(|_| ())
    }

    /// Forget a profile that no longer exists.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn forget_profile(&self, profile: &str) -> Result<(), StoreError> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM profile_target WHERE profile = ?1",
                params![profile],
            )
        })
        .map(|_| ())
    }

    /// Everything the daemon needs back after a restart, in one read.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn recover(&self) -> Result<Recovered, StoreError> {
        let mode = self
            .meta("mode")?
            .and_then(|text| text.parse::<SystemMode>().ok());
        let tun_enabled = self.meta("tun_enabled")?.as_deref() == Some("1");
        let last_known_good = self
            .meta("last_known_good")?
            .and_then(|text| text.parse::<u64>().ok())
            .map(GenerationId);
        let last_known_good_at = self
            .meta("last_known_good_at")?
            .and_then(|text| text.parse::<u64>().ok());
        let profile_targets = self.with(|connection| {
            let mut statement = connection
                .prepare("SELECT profile, target FROM profile_target ORDER BY profile")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })?;
        Ok(Recovered {
            mode,
            tun_enabled,
            last_known_good,
            last_known_good_at,
            profile_targets,
            interrupted: self.interrupted()?,
        })
    }

    // --- transactions -------------------------------------------------------

    /// Note that a multi-step operation has begun.
    ///
    /// Returns a token to pass to [`StateStore::finish_transaction`]. An entry
    /// that is never finished is what [`StateStore::recover`] reports as
    /// interrupted, which is how a migration killed halfway is noticed on the
    /// next start rather than silently half-applied.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn begin_transaction(
        &self,
        operation: &str,
        detail: &str,
        at: u64,
    ) -> Result<i64, StoreError> {
        self.with(|connection| {
            connection.execute(
                "INSERT INTO transaction_log (operation, detail, started) VALUES (?1, ?2, ?3)",
                params![operation, detail, at as i64],
            )?;
            Ok(connection.last_insert_rowid())
        })
    }

    /// Note that the operation completed.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn finish_transaction(&self, token: i64, at: u64) -> Result<(), StoreError> {
        self.with(|connection| {
            connection.execute(
                "UPDATE transaction_log SET finished = ?2 WHERE id = ?1",
                params![token, at as i64],
            )
        })
        .map(|_| ())
    }

    /// The oldest operation that began and never finished.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn interrupted(&self) -> Result<Option<Interrupted>, StoreError> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT operation, detail, started FROM transaction_log
                     WHERE finished IS NULL ORDER BY id LIMIT 1",
                    [],
                    |row| {
                        Ok(Interrupted {
                            operation: row.get(0)?,
                            detail: row.get(1)?,
                            started_at: row.get::<_, i64>(2)?.unsigned_abs(),
                        })
                    },
                )
                .optional()
        })
    }

    /// Forget every unfinished operation, after recovering from them.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn clear_interrupted(&self) -> Result<(), StoreError> {
        self.with(|connection| {
            connection.execute("DELETE FROM transaction_log WHERE finished IS NULL", [])
        })
        .map(|_| ())
    }

    // --- subscriptions ------------------------------------------------------

    /// Record a successful subscription fetch.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn record_subscription_success(
        &self,
        id: &SubscriptionId,
        at: u64,
        etag: Option<&str>,
    ) -> Result<(), StoreError> {
        self.with(|connection| {
            connection.execute(
                "INSERT INTO subscription (id, last_success, last_attempt, etag, failures, last_error)
                 VALUES (?1, ?2, ?2, ?3, 0, NULL)
                 ON CONFLICT(id) DO UPDATE SET
                     last_success = excluded.last_success,
                     last_attempt = excluded.last_attempt,
                     etag         = excluded.etag,
                     failures     = 0,
                     last_error   = NULL",
                params![id.as_str(), at as i64, etag],
            )
        })
        .map(|_| ())
    }

    /// Record a failed subscription fetch.
    ///
    /// `detail` must already be redacted: a subscription URL carries a token.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn record_subscription_failure(
        &self,
        id: &SubscriptionId,
        at: u64,
        detail: &str,
    ) -> Result<(), StoreError> {
        let detail = bounded(detail, 400);
        self.with(|connection| {
            connection.execute(
                "INSERT INTO subscription (id, last_attempt, failures, last_error)
                 VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                     last_attempt = excluded.last_attempt,
                     failures     = subscription.failures + 1,
                     last_error   = excluded.last_error",
                params![id.as_str(), at as i64, detail],
            )
        })
        .map(|_| ())
    }

    /// What is known about a subscription's updates.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn subscription(&self, id: &SubscriptionId) -> Result<SubscriptionState, StoreError> {
        let found = self.with(|connection| {
            connection
                .query_row(
                    "SELECT last_success, last_attempt, etag, failures, last_error
                     FROM subscription WHERE id = ?1",
                    params![id.as_str()],
                    |row| {
                        Ok(SubscriptionState {
                            last_success: row.get::<_, Option<i64>>(0)?.map(i64::unsigned_abs),
                            last_attempt: row.get::<_, Option<i64>>(1)?.map(i64::unsigned_abs),
                            etag: row.get(2)?,
                            failures: row.get::<_, i64>(3)?.try_into().unwrap_or(u32::MAX),
                            last_error: row.get(4)?,
                        })
                    },
                )
                .optional()
        })?;
        Ok(found.unwrap_or_default())
    }

    // --- health -------------------------------------------------------------

    /// Record one probe and trim that subject's history in the same
    /// transaction, so the history is bounded rather than bounded-on-average.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn record_probe(
        &self,
        subject: &str,
        at: u64,
        result: &ProbeResult,
    ) -> Result<(), StoreError> {
        let ok = matches!(result.outcome, ProbeOutcome::Ok);
        self.with(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute(
                "INSERT INTO probe (subject, at, ok, latency_ms, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    subject,
                    at as i64,
                    i64::from(ok),
                    result.latency_ms.map(i64::from),
                    outcome_detail(&result.outcome),
                ],
            )?;
            transaction.execute(
                "DELETE FROM probe
                 WHERE subject = ?1 AND rowid NOT IN (
                     SELECT rowid FROM probe WHERE subject = ?1 ORDER BY at DESC LIMIT ?2
                 )",
                params![subject, HISTORY_LIMIT as i64],
            )?;
            transaction.commit()
        })
    }

    /// The health of one subject, folded from its stored history.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn health(&self, subject: &str) -> Result<HealthRecord, StoreError> {
        let rows: Vec<(i64, bool, Option<i64>, Option<String>)> = self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT at, ok, latency_ms, detail FROM probe
                 WHERE subject = ?1 ORDER BY at DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![subject, HISTORY_LIMIT as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })?;
        Ok(fold_health(&rows))
    }

    /// Health for every node that has a history, keyed by node identifier.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn node_health(&self) -> Result<Vec<(NodeId, HealthRecord)>, StoreError> {
        let subjects: Vec<String> = self.with(|connection| {
            let mut statement = connection
                .prepare("SELECT DISTINCT subject FROM probe WHERE subject LIKE 'node:%'")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()
        })?;
        let mut out = Vec::with_capacity(subjects.len());
        for subject in subjects {
            let Some(raw) = subject.strip_prefix("node:") else {
                continue;
            };
            let Ok(id) = NodeId::new(raw) else {
                continue;
            };
            out.push((id, self.health(&subject)?));
        }
        Ok(out)
    }

    /// Drop probe history older than `cutoff`, in Unix seconds.
    ///
    /// # Errors
    /// Propagates SQLite failures.
    pub fn prune(&self, cutoff: u64) -> Result<usize, StoreError> {
        self.with(|connection| {
            connection.execute("DELETE FROM probe WHERE at < ?1", params![cutoff as i64])
        })
    }
}

/// The key a node's probes are stored under.
#[must_use]
pub fn node_subject(id: &NodeId) -> String {
    format!("node:{id}")
}

/// The key a profile's probes are stored under.
#[must_use]
pub fn profile_subject(id: &str) -> String {
    format!("profile:{id}")
}

/// A bounded, credential-free description of why a probe failed.
fn outcome_detail(outcome: &ProbeOutcome) -> Option<String> {
    let text = match outcome {
        ProbeOutcome::Ok => return None,
        ProbeOutcome::ConnectFailed { detail } => format!("connect: {detail}"),
        ProbeOutcome::TlsFailed { detail } => format!("tls: {detail}"),
        ProbeOutcome::Timeout => "timeout".to_owned(),
        ProbeOutcome::Cancelled => "cancelled".to_owned(),
        ProbeOutcome::NotRun { reason } => format!("not run: {reason}"),
    };
    Some(bounded(&text, 200))
}

/// Truncate on a character boundary, so a multi-byte name cannot be split.
fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Fold newest-first rows into the summary the runtime carries.
fn fold_health(rows: &[(i64, bool, Option<i64>, Option<String>)]) -> HealthRecord {
    let mut record = HealthRecord {
        attempts: rows.len().try_into().unwrap_or(u32::MAX),
        successes: rows
            .iter()
            .filter(|(_, ok, _, _)| *ok)
            .count()
            .try_into()
            .unwrap_or(u32::MAX),
        // Newest first, so the leading run of failures is the current streak.
        consecutive_failures: rows
            .iter()
            .take_while(|(_, ok, _, _)| !*ok)
            .count()
            .try_into()
            .unwrap_or(u32::MAX),
        ..HealthRecord::default()
    };

    // Oldest-to-newest EMA, so the most recent probe weighs most. 0.3 is a
    // compromise: fast enough to notice a server going bad within a few probes,
    // slow enough that one timeout on a train does not condemn it.
    let mut ema: Option<f32> = None;
    for (_, ok, latency, _) in rows.iter().rev() {
        if !*ok {
            continue;
        }
        if let Some(value) = latency {
            let sample = *value as f32;
            ema = Some(match ema {
                Some(previous) => previous.mul_add(0.7, sample * 0.3),
                None => sample,
            });
        }
    }
    record.ema_latency_ms = ema.map(|value| value.round().max(0.0) as u32);

    if let Some((at, ok, latency, detail)) = rows.first() {
        record.last = Some(ProbeResult {
            at_unix_ms: at.saturating_mul(1000),
            latency_ms: (*latency).and_then(|value| u32::try_from(value).ok()),
            outcome: if *ok {
                ProbeOutcome::Ok
            } else {
                ProbeOutcome::ConnectFailed {
                    detail: detail.clone().unwrap_or_else(|| "failed".to_owned()),
                }
            },
            kind: ProbeKind::TcpConnect,
        });
    }
    record
}

#[cfg(test)]
mod tests;
