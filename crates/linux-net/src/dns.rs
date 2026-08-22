//! Pointing the system resolver at the tunnel, and putting it back.
//!
//! # The rule this module exists to keep
//!
//! Resolver configuration is shared state that other software also edits. The
//! helper therefore never writes `/etc/resolv.conf` itself. It asks whichever
//! component owns that file — systemd-resolved or resolvconf — to associate
//! resolvers *with an interface*. When the interface goes away, so does the
//! association, which means the worst case after a crash is a stale interface
//! entry rather than a machine that cannot resolve anything.
//!
//! `RevertLink` and `resolvconf -d` are the documented undo for each backend, so
//! [`DnsManager::revert`] restores the previous state without the helper having
//! to remember what it was.

use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use xraytui_netd_protocol::{DnsBackend, DnsRequest};

use crate::dbus::{Argument, Dbus, DbusError};
use crate::program;

/// D-Bus destination for systemd-resolved.
const RESOLVE1: &str = "org.freedesktop.resolve1";
/// Its manager object.
const RESOLVE1_PATH: &str = "/org/freedesktop/resolve1";
/// Its manager interface.
const RESOLVE1_MANAGER: &str = "org.freedesktop.resolve1.Manager";

/// `AF_INET` as resolve1 expects it.
const AF_INET: i32 = 2;
/// `AF_INET6` as resolve1 expects it.
const AF_INET6: i32 = 10;

/// Errors the DNS backends can report.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The chosen backend is not present on this system.
    #[error("{0} is not available on this system")]
    Unavailable(&'static str),
    /// systemd-resolved refused or could not be reached.
    #[error("systemd-resolved: {0}")]
    Resolved(#[from] DbusError),
    /// `resolvconf` could not be run.
    #[error("cannot run {program}: {source}")]
    Spawn {
        /// Program attempted.
        program: String,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// `resolvconf` exited non-zero.
    #[error("resolvconf refused the update ({code}): {message}")]
    Refused {
        /// Exit status.
        code: i32,
        /// First line of standard error.
        message: String,
    },
    /// Talking to the child process failed.
    #[error("cannot send the resolver list to resolvconf: {0}")]
    Pipe(#[source] std::io::Error),
}

/// Drives whichever resolver manager the system has.
#[derive(Debug, Clone)]
pub struct DnsManager {
    bus: PathBuf,
    resolvconf: PathBuf,
    #[cfg(test)]
    resolvconf_prefix: Vec<PathBuf>,
}

impl Default for DnsManager {
    fn default() -> Self {
        Self {
            bus: crate::dbus::system_bus_path(),
            resolvconf: PathBuf::from("resolvconf"),
            #[cfg(test)]
            resolvconf_prefix: Vec::new(),
        }
    }
}

impl DnsManager {
    /// Override both backends' locations. The test suite uses this.
    #[must_use]
    pub fn new(bus: impl Into<PathBuf>, resolvconf: impl Into<PathBuf>) -> Self {
        Self {
            bus: bus.into(),
            resolvconf: resolvconf.into(),
            #[cfg(test)]
            resolvconf_prefix: Vec::new(),
        }
    }

    /// Path of the `resolvconf` program this manager would run.
    #[must_use]
    pub fn resolvconf_program(&self) -> &Path {
        &self.resolvconf
    }

    /// Whether systemd-resolved looks reachable. Performs no change.
    #[must_use]
    pub fn resolved_available(&self) -> bool {
        self.bus.exists() && Dbus::connect(&self.bus).is_ok()
    }

    /// Whether `resolvconf` looks runnable. Performs no change.
    #[must_use]
    pub fn resolvconf_available(&self) -> bool {
        program::resolve(&self.resolvconf).is_some()
    }

    /// Install resolvers for an interface.
    ///
    /// # Errors
    /// See [`DnsError`].
    pub fn apply(&self, interface: &str, index: u32, request: &DnsRequest) -> Result<(), DnsError> {
        match request.backend {
            DnsBackend::None => Ok(()),
            DnsBackend::SystemdResolved => self.apply_resolved(index, request),
            DnsBackend::Resolvconf => self.apply_resolvconf(interface, request),
        }
    }

    /// Undo whatever [`DnsManager::apply`] did for this interface.
    ///
    /// Absence is success: reverting a link that resolve1 has already forgotten,
    /// or removing a resolvconf entry that is not there, is the state the caller
    /// wanted.
    ///
    /// # Errors
    /// See [`DnsError`].
    pub fn revert(&self, interface: &str, index: u32, backend: DnsBackend) -> Result<(), DnsError> {
        match backend {
            DnsBackend::None => Ok(()),
            DnsBackend::SystemdResolved => {
                let mut bus = Dbus::connect(&self.bus)?;
                match bus.call(
                    RESOLVE1,
                    RESOLVE1_PATH,
                    RESOLVE1_MANAGER,
                    "RevertLink",
                    &[Argument::Int32(index_as_i32(index))],
                ) {
                    Ok(()) => Ok(()),
                    // resolve1 reports an unknown link as an error; that is the
                    // state we were aiming for.
                    Err(DbusError::Remote { ref name, .. })
                        if name.contains("NoSuchLink") || name.contains("LinkNotManaged") =>
                    {
                        Ok(())
                    }
                    Err(error) => Err(error.into()),
                }
            }
            DnsBackend::Resolvconf => {
                match self.run_resolvconf(&["-d", interface], None) {
                    Ok(()) => Ok(()),
                    // resolvconf exits non-zero when the record is absent.
                    Err(DnsError::Refused { .. }) => Ok(()),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn apply_resolved(&self, index: u32, request: &DnsRequest) -> Result<(), DnsError> {
        let mut bus = Dbus::connect(&self.bus)?;
        let index = index_as_i32(index);

        let addresses: Vec<(i32, Vec<u8>)> = request
            .servers
            .iter()
            .map(|address| match address {
                IpAddr::V4(v4) => (AF_INET, v4.octets().to_vec()),
                IpAddr::V6(v6) => (AF_INET6, v6.octets().to_vec()),
            })
            .collect();
        bus.call(
            RESOLVE1,
            RESOLVE1_PATH,
            RESOLVE1_MANAGER,
            "SetLinkDNS",
            &[Argument::Int32(index), Argument::Addresses(addresses)],
        )?;

        // `~.` is systemd-resolved's marker for "send everything here". It is
        // recorded as routing-only so the domain does not become a search
        // suffix, which would rewrite unqualified names.
        let domains: Vec<(String, bool)> = request
            .domains
            .iter()
            .map(|domain| (domain.clone(), domain == "~."))
            .collect();
        bus.call(
            RESOLVE1,
            RESOLVE1_PATH,
            RESOLVE1_MANAGER,
            "SetLinkDomains",
            &[Argument::Int32(index), Argument::Domains(domains)],
        )?;

        // Only claim the default route for queries when the caller asked for
        // everything; otherwise the tunnel would capture names it has no
        // business answering.
        let default_route = request.domains.iter().any(|domain| domain == "~.");
        bus.call(
            RESOLVE1,
            RESOLVE1_PATH,
            RESOLVE1_MANAGER,
            "SetLinkDefaultRoute",
            &[Argument::Int32(index), Argument::Boolean(default_route)],
        )?;
        Ok(())
    }

    fn apply_resolvconf(&self, interface: &str, request: &DnsRequest) -> Result<(), DnsError> {
        let mut payload = String::new();
        for server in &request.servers {
            payload.push_str("nameserver ");
            payload.push_str(&server.to_string());
            payload.push('\n');
        }
        for domain in &request.domains {
            if domain == "~." {
                continue;
            }
            payload.push_str("search ");
            payload.push_str(domain);
            payload.push('\n');
        }
        self.run_resolvconf(&["-a", interface], Some(&payload))
    }

    fn run_resolvconf(&self, args: &[&str], stdin: Option<&str>) -> Result<(), DnsError> {
        let Some(resolved) = program::resolve(&self.resolvconf) else {
            return Err(DnsError::Unavailable("resolvconf"));
        };
        let mut command = program::command(&resolved);
        #[cfg(test)]
        command.args(&self.resolvconf_prefix);
        command
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|source| DnsError::Spawn {
            program: self.resolvconf.display().to_string(),
            source,
        })?;
        if let Some(payload) = stdin {
            let mut handle = child
                .stdin
                .take()
                .ok_or_else(|| DnsError::Pipe(std::io::Error::other("stdin was not piped")))?;
            handle
                .write_all(payload.as_bytes())
                .map_err(DnsError::Pipe)?;
            drop(handle);
        }
        let output = child.wait_with_output().map_err(DnsError::Pipe)?;
        if output.status.success() {
            return Ok(());
        }
        Err(DnsError::Refused {
            code: output.status.code().unwrap_or(-1),
            message: String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("no message")
                .to_owned(),
        })
    }
}

fn index_as_i32(index: u32) -> i32 {
    i32::try_from(index).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(backend: DnsBackend) -> DnsRequest {
        DnsRequest {
            backend,
            servers: vec!["10.0.0.53".parse().expect("address")],
            domains: vec!["~.".into()],
        }
    }

    #[test]
    fn the_none_backend_changes_nothing_and_needs_nothing() {
        let manager = DnsManager::new("/nonexistent/bus", "/nonexistent/resolvconf");
        let spec = DnsRequest {
            backend: DnsBackend::None,
            servers: Vec::new(),
            domains: Vec::new(),
        };
        assert!(manager.apply("xraytui1000", 3, &spec).is_ok());
        assert!(manager.revert("xraytui1000", 3, DnsBackend::None).is_ok());
    }

    #[test]
    fn a_missing_backend_is_reported_not_ignored() {
        let manager = DnsManager::new("/nonexistent/bus", "/nonexistent/resolvconf");
        assert!(!manager.resolved_available());
        assert!(!manager.resolvconf_available());
        assert!(matches!(
            manager.apply("xraytui1000", 3, &request(DnsBackend::Resolvconf)),
            Err(DnsError::Unavailable("resolvconf"))
        ));
        assert!(matches!(
            manager.apply("xraytui1000", 3, &request(DnsBackend::SystemdResolved)),
            Err(DnsError::Resolved(DbusError::Connect { .. }))
        ));
    }

    #[test]
    fn resolvconf_receives_one_nameserver_line_per_server() {
        let fixture = FakeResolvconf::new();
        let manager = fixture.manager();
        let spec = DnsRequest {
            backend: DnsBackend::Resolvconf,
            servers: vec![
                "10.0.0.53".parse().expect("address"),
                "fd00::53".parse().expect("address"),
            ],
            domains: vec!["example.test".into(), "~.".into()],
        };
        manager.apply("xraytui1000", 3, &spec).expect("apply");
        let recorded = std::fs::read_to_string(&fixture.log).expect("log");
        assert!(recorded.contains("argv: -a xraytui1000"), "{recorded}");
        assert!(recorded.contains("nameserver 10.0.0.53"), "{recorded}");
        assert!(recorded.contains("nameserver fd00::53"), "{recorded}");
        assert!(recorded.contains("search example.test"), "{recorded}");
        // `~.` is a systemd-resolved marker and is not a search domain.
        assert!(!recorded.contains("search ~."), "{recorded}");
    }

    #[test]
    fn reverting_resolvconf_deletes_the_interface_record() {
        let fixture = FakeResolvconf::new();
        let manager = fixture.manager();
        manager
            .revert("xraytui1000", 3, DnsBackend::Resolvconf)
            .expect("revert");
        let recorded = std::fs::read_to_string(&fixture.log).expect("log");
        assert!(recorded.contains("argv: -d xraytui1000"), "{recorded}");
    }

    #[test]
    fn an_index_that_cannot_be_signed_is_clamped_not_wrapped() {
        assert_eq!(index_as_i32(7), 7);
        assert_eq!(index_as_i32(u32::MAX), i32::MAX);
    }

    /// A stand-in for `resolvconf` that records its argv and stdin.
    ///
    /// Each fixture owns a unique directory for its entire lifetime. The
    /// generated file is deliberately *input* to the stable system shell, not a
    /// newly written executable: GitHub-hosted filesystems have intermittently
    /// returned `ETXTBSY` even after a generated script was closed and renamed.
    /// This test-only prefix does not exist in production builds.
    struct FakeResolvconf {
        _directory: tempfile::TempDir,
        program: PathBuf,
        log: PathBuf,
    }

    impl FakeResolvconf {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temp dir");
            let log = directory.path().join("log");
            let program = directory.path().join("resolvconf.fixture");
            let body = format!(
                "#!/bin/sh\nexec >>'{}' 2>&1\necho \"argv: $*\"\ncat\n",
                log.display()
            );
            std::fs::write(&program, body).expect("write script");
            std::fs::write(&log, "").expect("create log");

            Self {
                _directory: directory,
                program,
                log,
            }
        }

        fn manager(&self) -> DnsManager {
            DnsManager {
                bus: PathBuf::from("/nonexistent/bus"),
                resolvconf: PathBuf::from("/bin/sh"),
                resolvconf_prefix: vec![self.program.clone()],
            }
        }
    }
}
