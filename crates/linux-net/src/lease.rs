//! Who owns what, and what happens when they stop asking.
//!
//! A lease is the answer to one question: *if the daemon that asked for this
//! goes away, what should the machine look like?* Without it, a crashed daemon
//! leaves a TUN device holding the default route and every connection on the
//! host silently broken — the failure mode that makes people distrust VPN
//! clients.
//!
//! Two mechanisms cover two different failures:
//!
//! * **The connection.** The helper holds the daemon's socket. A crashed daemon
//!   closes it, and teardown happens immediately.
//! * **The lease file.** If the *helper* dies — or is killed, or the machine
//!   loses power mid-session — the file left in [`RECOVERY_DIR`] records the
//!   deadline. A later helper reads it and cleans up.
//!
//! [`RECOVERY_DIR`]: xraytui_netd_protocol::RECOVERY_DIR
//!
//! The file records interface names, table ids and marks. It never records a
//! node, an endpoint, a credential or anything about traffic.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use xraytui_netd_protocol::{DnsBackend, FailurePolicy};

/// The recorded state of one user's claim on the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// Owner, taken from `SO_PEERCRED` and never from a message.
    pub uid: u32,
    /// The interface created for this user.
    pub interface: String,
    /// Routing table reserved for this user.
    pub table: u32,
    /// Firewall mark reserved for this user.
    pub fwmark: u32,
    /// Whether the current TUN was configured to carry IPv4.
    #[serde(default)]
    pub ipv4: Option<bool>,
    /// Whether the current TUN was configured to carry IPv6.
    #[serde(default)]
    pub ipv6: Option<bool>,
    /// What to do when the lease expires.
    pub failure_policy: FailurePolicy,
    /// Unix time, in seconds, after which the lease is stale.
    pub expires_at: u64,
    /// The TTL that produced `expires_at`, so a heartbeat can renew it.
    pub ttl_secs: u64,
    /// Generation the owning daemon last reported, for diagnostics.
    pub generation: u64,
    /// Whether policy routing is currently installed.
    pub routing: bool,
    /// Whether the firewall chains are currently installed.
    pub firewall: bool,
    /// Which resolver backend was driven, if any.
    pub dns: DnsBackend,
    /// Profiles that have a cgroup.
    pub cgroups: BTreeSet<String>,
}

impl Lease {
    /// A fresh lease for `uid`, expiring `ttl_secs` from `now`.
    #[must_use]
    pub fn new(
        uid: u32,
        interface: String,
        ttl_secs: u64,
        failure_policy: FailurePolicy,
        now: u64,
    ) -> Self {
        Self {
            uid,
            interface,
            table: xraytui_netd_protocol::table_for_uid(uid),
            fwmark: xraytui_netd_protocol::fwmark_for_uid(uid),
            ipv4: None,
            ipv6: None,
            failure_policy,
            expires_at: now.saturating_add(ttl_secs),
            ttl_secs,
            generation: 0,
            routing: false,
            firewall: false,
            dns: DnsBackend::None,
            cgroups: BTreeSet::new(),
        }
    }

    /// Whether the lease is stale at `now`.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Push the deadline out by the lease's own TTL.
    pub fn renew(&mut self, now: u64) {
        self.expires_at = now.saturating_add(self.ttl_secs);
    }
}

/// Errors the lease store can report.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    /// The directory could not be created or is not usable.
    #[error("lease directory {path}: {source}")]
    Directory {
        /// Directory involved.
        path: String,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A lease file could not be written.
    #[error("cannot record the lease for uid {uid}: {source}")]
    Write {
        /// Owner.
        uid: u32,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A lease file could not be encoded.
    #[error("cannot encode the lease for uid {uid}: {source}")]
    Encode {
        /// Owner.
        uid: u32,
        /// Underlying failure.
        #[source]
        source: serde_json::Error,
    },
}

/// Durable record of every active lease.
///
/// Files are named `u<uid>.json`, so the filename itself cannot be influenced by
/// anything a client sends.
#[derive(Debug, Clone)]
pub struct LeaseStore {
    directory: PathBuf,
}

impl LeaseStore {
    /// Open — creating if necessary — the directory leases live in.
    ///
    /// # Errors
    /// [`LeaseError::Directory`] if the path cannot be created or is not a
    /// directory.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, LeaseError> {
        let directory = directory.as_ref().to_path_buf();
        std::fs::create_dir_all(&directory).map_err(|source| LeaseError::Directory {
            path: directory.display().to_string(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // The directory is root-owned and names only resources, but there is
            // no reason for it to be world-readable.
            let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { directory })
    }

    fn path_for(&self, uid: u32) -> PathBuf {
        self.directory.join(format!("u{uid}.json"))
    }

    /// Read one user's lease, if it exists and parses.
    ///
    /// A file that cannot be parsed is treated as absent: it is state this
    /// helper wrote and no longer understands, and refusing to start because of
    /// it would be worse than ignoring it.
    #[must_use]
    pub fn get(&self, uid: u32) -> Option<Lease> {
        let bytes = std::fs::read(self.path_for(uid)).ok()?;
        let lease: Lease = serde_json::from_slice(&bytes).ok()?;
        // A file whose contents disagree with its name is not trustworthy.
        (lease.uid == uid).then_some(lease)
    }

    /// Write a lease, replacing any previous one.
    ///
    /// # Errors
    /// [`LeaseError::Write`] or [`LeaseError::Encode`].
    pub fn put(&self, lease: &Lease) -> Result<(), LeaseError> {
        let encoded = serde_json::to_vec_pretty(lease).map_err(|source| LeaseError::Encode {
            uid: lease.uid,
            source,
        })?;
        let final_path = self.path_for(lease.uid);
        let temporary = final_path.with_extension("json.new");
        let mut file = std::fs::File::create(&temporary).map_err(|source| LeaseError::Write {
            uid: lease.uid,
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|source| LeaseError::Write {
                uid: lease.uid,
                source,
            })?;
        std::fs::rename(&temporary, &final_path).map_err(|source| LeaseError::Write {
            uid: lease.uid,
            source,
        })
    }

    /// Forget a lease. Absent files are not an error.
    ///
    /// # Errors
    /// [`LeaseError::Write`] if the file exists and cannot be removed.
    pub fn remove(&self, uid: u32) -> Result<(), LeaseError> {
        match std::fs::remove_file(self.path_for(uid)) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LeaseError::Write { uid, source }),
        }
    }

    /// Every lease currently recorded, sorted by uid.
    #[must_use]
    pub fn all(&self) -> Vec<Lease> {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return Vec::new();
        };
        let mut out: Vec<Lease> = entries
            .flatten()
            .filter_map(|entry| {
                let bytes = std::fs::read(entry.path()).ok()?;
                serde_json::from_slice::<Lease>(&bytes).ok()
            })
            .collect();
        out.sort_by_key(|lease| lease.uid);
        out
    }

    /// Every lease that is stale at `now`.
    #[must_use]
    pub fn expired(&self, now: u64) -> Vec<Lease> {
        self.all()
            .into_iter()
            .filter(|lease| lease.is_expired(now))
            .collect()
    }
}

/// Seconds since the Unix epoch.
///
/// Leases are compared against wall time rather than a monotonic clock because
/// they must survive the helper restarting, and `Instant` cannot be written to
/// a file. A backwards step in wall time can only make a lease look *younger*,
/// which delays cleanup rather than causing a surprise teardown.
#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, LeaseStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = LeaseStore::open(dir.path()).expect("store opens");
        (dir, store)
    }

    #[test]
    fn a_lease_round_trips_through_the_store() {
        let (_guard, store) = store();
        let lease = Lease::new(1000, "xraytui1000".into(), 30, FailurePolicy::Restore, 100);
        store.put(&lease).expect("put");
        assert_eq!(store.get(1000), Some(lease));
    }

    #[test]
    fn a_pre_family_flag_lease_keeps_the_families_unknown_for_live_recovery() {
        let lease = Lease::new(1000, "xraytui1000".into(), 30, FailurePolicy::Restore, 100);
        let mut encoded = serde_json::to_value(lease).expect("encode legacy fixture");
        let object = encoded.as_object_mut().expect("lease object");
        object.remove("ipv4");
        object.remove("ipv6");

        let decoded: Lease = serde_json::from_value(encoded).expect("decode legacy lease");
        assert_eq!(decoded.ipv4, None);
        assert_eq!(decoded.ipv6, None);
    }

    #[test]
    fn resource_ids_are_derived_from_the_uid_not_supplied() {
        let lease = Lease::new(1000, "xraytui1000".into(), 30, FailurePolicy::Restore, 0);
        assert_eq!(lease.table, xraytui_netd_protocol::table_for_uid(1000));
        assert_eq!(lease.fwmark, xraytui_netd_protocol::fwmark_for_uid(1000));
    }

    #[test]
    fn expiry_is_exclusive_of_the_deadline_and_renew_moves_it() {
        let mut lease = Lease::new(1000, "xraytui1000".into(), 30, FailurePolicy::Restore, 100);
        assert!(!lease.is_expired(129));
        assert!(lease.is_expired(130));
        lease.renew(200);
        assert!(!lease.is_expired(229));
        assert!(lease.is_expired(230));
    }

    #[test]
    fn expired_leases_are_listed_and_others_are_not() {
        let (_guard, store) = store();
        store
            .put(&Lease::new(
                1,
                "xraytui1".into(),
                10,
                FailurePolicy::Restore,
                0,
            ))
            .expect("put");
        store
            .put(&Lease::new(
                2,
                "xraytui2".into(),
                1000,
                FailurePolicy::Restore,
                0,
            ))
            .expect("put");
        let expired = store.expired(50);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].uid, 1);
    }

    #[test]
    fn a_lease_file_that_disagrees_with_its_name_is_ignored() {
        let (guard, store) = store();
        let mut lease = Lease::new(1000, "xraytui1000".into(), 30, FailurePolicy::Restore, 0);
        lease.uid = 4242;
        let encoded = serde_json::to_vec(&lease).expect("encode");
        std::fs::write(guard.path().join("u1000.json"), encoded).expect("write");
        assert_eq!(store.get(1000), None);
    }

    #[test]
    fn unparseable_files_are_ignored_rather_than_fatal() {
        let (guard, store) = store();
        std::fs::write(guard.path().join("u7.json"), b"not json").expect("write");
        assert_eq!(store.get(7), None);
        assert!(store.all().is_empty());
    }

    #[test]
    fn removing_an_absent_lease_is_not_an_error() {
        let (_guard, store) = store();
        assert!(store.remove(9999).is_ok());
    }

    #[test]
    fn saturating_arithmetic_keeps_a_huge_ttl_from_wrapping() {
        let lease = Lease::new(1, "xraytui1".into(), u64::MAX, FailurePolicy::Restore, 10);
        assert_eq!(lease.expires_at, u64::MAX);
        assert!(!lease.is_expired(u64::MAX - 1));
    }

    #[test]
    fn the_lease_directory_is_private() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let (guard, _store) = store();
            let mode = std::fs::metadata(guard.path())
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
}
