//! `xraytui exec` — run a command through a profile's egress.
//!
//! Two backends:
//!
//! * **environment** (default, unprivileged): sets `ALL_PROXY`, `HTTP_PROXY`,
//!   `HTTPS_PROXY`, their lowercase spellings and `NO_PROXY`, then executes the
//!   command. Exact for proxy-aware programs, invisible to everything else.
//! * **transparent** (`--transparent`): classifies the process into a
//!   project-owned cgroup so its traffic is policy-routed. Requires the
//!   privileged helper and kernel support, and reports honestly when either is
//!   missing instead of quietly falling back.
//!
//! The command is always spawned as an argument vector. Nothing is passed to a
//! shell unless the user typed a shell themselves.

use std::collections::BTreeMap;
use std::ffi::OsString;

use crate::CliError;

/// Proxy environment for one profile's listeners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEnvironment {
    /// The variables to set, in a deterministic order.
    pub variables: BTreeMap<String, String>,
}

impl ProxyEnvironment {
    /// Build the environment for the given listeners.
    ///
    /// `socks` is preferred for `ALL_PROXY` because it carries UDP and, with the
    /// `socks5h` scheme, leaves name resolution to the proxy — which is what
    /// stops a DNS leak from betraying the destination.
    #[must_use]
    pub fn build(socks: Option<&str>, http: Option<&str>, no_proxy: &str) -> Self {
        let mut variables = BTreeMap::new();

        if let Some(socks) = socks {
            // `socks5h` rather than `socks5`: the `h` asks the client library to
            // send the hostname to the proxy instead of resolving it locally.
            let url = format!("socks5h://{socks}");
            variables.insert("ALL_PROXY".to_owned(), url.clone());
            variables.insert("all_proxy".to_owned(), url);
        }

        let http_url = http.map(|address| format!("http://{address}")).or_else(|| {
            // Many programs understand only HTTP_PROXY. A SOCKS URL in it is
            // accepted by curl and libproxy-style clients, so it is better than
            // leaving the variable unset.
            socks.map(|address| format!("socks5h://{address}"))
        });
        if let Some(url) = http_url {
            for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
                variables.insert(key.to_owned(), url.clone());
            }
        }

        variables.insert("NO_PROXY".to_owned(), no_proxy.to_owned());
        variables.insert("no_proxy".to_owned(), no_proxy.to_owned());

        Self { variables }
    }

    /// The default `NO_PROXY` list: loopback and the private ranges.
    #[must_use]
    pub fn default_no_proxy() -> &'static str {
        "localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local"
    }

    /// Render as `KEY=value` lines, for `--format shell` and for documentation.
    #[must_use]
    pub fn to_shell(&self) -> String {
        self.variables
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Replace this process with `command`, carrying the proxy environment.
///
/// Uses `exec` semantics: the child inherits the terminal, signals and exit
/// status directly, so `xraytui exec -- vim` behaves exactly like `vim`.
///
/// # Errors
/// Returns [`CliError::Io`] when the command cannot be executed. On success this
/// function does not return.
pub fn run_with_environment(
    environment: &ProxyEnvironment,
    command: &[String],
) -> Result<std::convert::Infallible, CliError> {
    use std::os::unix::process::CommandExt;

    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| CliError::Usage("no command was given after `--`".to_owned()))?;

    let mut child = std::process::Command::new(program);
    child.args(arguments);
    for (key, value) in &environment.variables {
        child.env(OsString::from(key), OsString::from(value));
    }

    // `exec` never returns on success.
    let error = child.exec();
    Err(CliError::Io {
        context: format!("cannot execute {program}"),
        source: error,
    })
}

/// Why the transparent backend could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransparentUnavailable {
    /// The privileged helper is not running.
    #[error(
        "the privileged helper is not running, so transparent mode is unavailable.\n\
         Start it with: sudo systemctl enable --now xraytui-netd.service\n\
         Or drop --transparent to use proxy environment variables instead."
    )]
    NoHelper,
    /// cgroup v2 is not mounted.
    #[error(
        "cgroup v2 is not available on this system, so transparent mode is unavailable.\n\
         Drop --transparent to use proxy environment variables instead."
    )]
    NoCgroupV2,
    /// The profile has no transparent listener configured.
    #[error(
        "profile '{profile}' has no transparent listener, so there is nowhere for \
         its traffic to go.\n\
         Give it one — `transparent` with a loopback port of its own — and restart \
         the core."
    )]
    NoInbound {
        /// Profile that was asked for.
        profile: String,
    },
    /// The profile has a transparent listener configured, but nothing is on it.
    #[error(
        "profile '{profile}' has a transparent listener at {address}, but nothing \
         is listening there.\n\
         Its traffic would be redirected to a closed port and dropped, so the \
         command was not started. Start the core with `xraytui up`."
    )]
    NotListening {
        /// Profile that was asked for.
        profile: String,
        /// Where the listener should have been.
        address: String,
    },
    /// The helper refused to classify this process.
    #[error(
        "the privileged helper refused to place this process in profile \
         '{profile}': {reason}\n\
         The command was not started: running it now would send its traffic \
         somewhere other than where you asked."
    )]
    Refused {
        /// Profile that was asked for.
        profile: String,
        /// The helper's own words.
        reason: String,
    },
    /// The helper said yes, but the kernel does not agree.
    #[error(
        "this process was not actually placed in profile '{profile}' \
         (own cgroup: {actual}).\n\
         The command was not started."
    )]
    NotClassified {
        /// Profile that was asked for.
        profile: String,
        /// What `/proc/self/cgroup` says instead.
        actual: String,
    },
}

/// Where the helper listens, unless overridden.
pub const NETD_SOCKET: &str = "/run/xraytui/netd.sock";

/// The helper socket to use.
///
/// The environment variable exists so a test — or an unusual installation — can
/// point the client at a helper somewhere else. It changes only which helper
/// *this* process talks to, and the helper still decides everything that
/// matters from the connecting credential, so it grants nothing.
#[must_use]
pub fn netd_socket() -> std::path::PathBuf {
    std::env::var_os("XRAYTUI_NETD_SOCKET")
        .map_or_else(|| std::path::PathBuf::from(NETD_SOCKET), Into::into)
}

/// Put **this** process in a profile's cgroup, then become `command`.
///
/// # Why there is no child to race
///
/// The obvious implementation spawns the command, then classifies it, and has to
/// keep it from opening a socket in between — a barrier, a pipe, a released
/// child, and a window that has to be argued about. This does not have that
/// window at all: the process that will *become* the application classifies
/// itself first and calls `execve` afterwards.
///
/// That works because of two kernel properties:
///
/// * cgroup membership is a property of the thread group and survives `execve`,
///   so the program that replaces this image is already classified before its
///   first instruction;
/// * a socket's cgroup is recorded when the socket is *created*, so this
///   process's existing connections — to the daemon and to the helper — keep the
///   cgroup they were made in and are not redirected. They are also
///   close-on-exec, so they are gone by the time the command runs.
///
/// The application therefore cannot create a connection before classification,
/// because it does not exist before classification.
///
/// # Failure policy
///
/// Refusal is fatal, deliberately. If the helper says no, or says yes and the
/// kernel disagrees, the command is **not** started: silently running it
/// unclassified would send traffic out of the machine by a path the user did not
/// choose, while the tool reported success. Both failures are reported with the
/// profile named.
///
/// # Errors
/// [`CliError::Other`] carrying a [`TransparentUnavailable`] when the helper
/// refuses or the classification does not take effect, and [`CliError::Io`] when
/// the command itself cannot be executed. On success this function does not
/// return.
pub async fn classify_and_exec(
    socket: &std::path::Path,
    profile: &str,
    command: &[String],
) -> Result<std::convert::Infallible, CliError> {
    use std::os::unix::process::CommandExt as _;

    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| CliError::Usage("no command was given after `--`".to_owned()))?;

    let mut client = xraytui_linux_net::transport::NetdClient::connect(socket)
        .await
        .map_err(|error| refusal(profile, &error))?;
    classify_here(&mut client, profile)
        .await
        .map_err(|reason| CliError::Other(reason.to_string()))?;

    let mut child = std::process::Command::new(program);
    child.args(arguments);
    let error = child.exec();
    Err(CliError::Io {
        context: format!("cannot execute {program}"),
        source: error,
    })
}

/// Ask the helper to classify this process, and check that it worked.
///
/// Separate from [`classify_and_exec`] because everything interesting happens
/// here and nothing here replaces the process image, so it can be tested.
///
/// # Errors
/// [`TransparentUnavailable::Refused`] when the helper says no, and
/// [`TransparentUnavailable::NotClassified`] when it says yes but the kernel
/// disagrees — which is checked rather than assumed, because the helper's answer
/// is not what decides where the traffic goes.
pub async fn classify_here(
    client: &mut xraytui_linux_net::transport::NetdClient,
    profile: &str,
) -> Result<(), TransparentUnavailable> {
    use std::os::fd::AsFd as _;

    let uid = rustix::process::getuid().as_raw();
    let pidfd = rustix::process::pidfd_open(
        rustix::process::getpid(),
        rustix::process::PidfdFlags::empty(),
    )
    .map_err(|error| TransparentUnavailable::Refused {
        profile: profile.to_owned(),
        reason: format!("cannot open a descriptor for this process: {error}"),
    })?;

    client
        .call_with(
            xraytui_netd_protocol::Operation::ClassifyProcess {
                profile: profile.to_owned(),
            },
            &[pidfd.as_fd()],
        )
        .await
        .map_err(|error| TransparentUnavailable::Refused {
            profile: profile.to_owned(),
            reason: error.to_string(),
        })?;

    let expected = xraytui_linux_net::cgroup::relative_path(uid, profile);
    let actual = own_cgroup().unwrap_or_default();
    if actual.trim_end_matches('/').ends_with(&expected) {
        Ok(())
    } else {
        Err(TransparentUnavailable::NotClassified {
            profile: profile.to_owned(),
            actual,
        })
    }
}

fn refusal(profile: &str, error: &impl std::fmt::Display) -> CliError {
    CliError::Other(
        TransparentUnavailable::Refused {
            profile: profile.to_owned(),
            reason: error.to_string(),
        }
        .to_string(),
    )
}

/// This process's cgroup v2 path, as the kernel sees it.
///
/// The unified hierarchy is the line with an empty controller list, which is the
/// `0::` prefix.
fn own_cgroup() -> Option<String> {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        })
}

/// Check whether the transparent backend can be used, without using it.
///
/// Returning a typed reason rather than a boolean is deliberate: the caller must
/// tell the user *why* it is unavailable rather than silently doing something
/// weaker than they asked for.
///
/// # Errors
/// Returns the specific reason it is unavailable.
pub fn check_transparent_available(profile: &str) -> Result<(), TransparentUnavailable> {
    if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err(TransparentUnavailable::NoCgroupV2);
    }
    if !netd_socket().exists() {
        return Err(TransparentUnavailable::NoHelper);
    }
    let _ = profile;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_becomes_socks5h_so_dns_is_resolved_remotely() {
        let env = ProxyEnvironment::build(
            Some("127.0.0.1:11080"),
            None,
            ProxyEnvironment::default_no_proxy(),
        );
        assert_eq!(
            env.variables.get("ALL_PROXY").map(String::as_str),
            Some("socks5h://127.0.0.1:11080")
        );
        assert_eq!(
            env.variables.get("all_proxy").map(String::as_str),
            Some("socks5h://127.0.0.1:11080")
        );
    }

    #[test]
    fn an_http_listener_is_preferred_for_the_http_variables() {
        let env = ProxyEnvironment::build(
            Some("127.0.0.1:11080"),
            Some("127.0.0.1:11081"),
            ProxyEnvironment::default_no_proxy(),
        );
        assert_eq!(
            env.variables.get("HTTP_PROXY").map(String::as_str),
            Some("http://127.0.0.1:11081")
        );
        assert_eq!(
            env.variables.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:11081")
        );
        // ALL_PROXY still points at SOCKS, which is the more capable listener.
        assert!(
            env.variables
                .get("ALL_PROXY")
                .is_some_and(|value| value.starts_with("socks5h://"))
        );
    }

    #[test]
    fn socks_alone_still_populates_the_http_variables() {
        let env = ProxyEnvironment::build(
            Some("127.0.0.1:11080"),
            None,
            ProxyEnvironment::default_no_proxy(),
        );
        assert_eq!(
            env.variables.get("HTTP_PROXY").map(String::as_str),
            Some("socks5h://127.0.0.1:11080")
        );
    }

    #[test]
    fn no_proxy_is_always_set_in_both_spellings() {
        let env = ProxyEnvironment::build(None, None, "example.com");
        assert_eq!(
            env.variables.get("NO_PROXY").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            env.variables.get("no_proxy").map(String::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn the_default_bypass_list_covers_loopback_and_private_ranges() {
        let list = ProxyEnvironment::default_no_proxy();
        for expected in [
            "localhost",
            "127.0.0.0/8",
            "::1",
            "10.0.0.0/8",
            "192.168.0.0/16",
        ] {
            assert!(list.contains(expected), "{expected} missing from {list}");
        }
    }

    #[test]
    fn shell_rendering_is_stable_and_sorted() {
        let env = ProxyEnvironment::build(Some("127.0.0.1:1"), None, "x");
        let first = env.to_shell();
        let second = env.to_shell();
        assert_eq!(first, second);
        let keys: Vec<&str> = first.lines().filter_map(|l| l.split('=').next()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "output must be deterministic");
    }

    #[test]
    fn an_empty_command_is_a_usage_error_not_a_panic() {
        let env = ProxyEnvironment::build(None, None, "");
        let error = run_with_environment(&env, &[]).expect_err("must refuse");
        assert!(matches!(error, CliError::Usage(_)), "{error:?}");
    }

    // --- the launch barrier ------------------------------------------------

    /// A helper that answers whatever it is told to, so the *client's* half of
    /// the contract can be tested without root.
    async fn fake_helper(
        reply: Result<xraytui_netd_protocol::Outcome, xraytui_netd_protocol::NetdError>,
    ) -> xraytui_linux_net::transport::NetdClient {
        let (ours, theirs) = tokio::net::UnixStream::pair().expect("socketpair");
        tokio::spawn(async move {
            let received: Result<
                (
                    xraytui_netd_protocol::NetdRequest,
                    Vec<std::os::fd::OwnedFd>,
                ),
                _,
            > = xraytui_linux_net::transport::receive_message(&theirs).await;
            let Ok((request, descriptors)) = received else {
                return;
            };
            // The pidfd is the whole point of the operation; a helper that got
            // none could not act, so the test asserts the client sent one.
            assert_eq!(descriptors.len(), 1, "a pidfd must be attached");
            let response = xraytui_netd_protocol::NetdReply {
                id: request.id,
                result: reply,
            };
            let _ = xraytui_linux_net::transport::send_message(&theirs, &response, &[]).await;
        });
        xraytui_linux_net::transport::NetdClient::from_stream(ours)
    }

    #[tokio::test]
    async fn a_helper_that_says_yes_without_classifying_is_not_believed() {
        // The helper's answer is not what decides where traffic goes, so a bare
        // acknowledgement is checked against the kernel — and this test process
        // is certainly not in a profile cgroup.
        let mut client = fake_helper(Ok(xraytui_netd_protocol::Outcome::Ack)).await;
        let error = classify_here(&mut client, "work")
            .await
            .expect_err("must not be believed");
        assert!(
            matches!(error, TransparentUnavailable::NotClassified { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("was not started"));
    }

    #[tokio::test]
    async fn a_refusal_names_the_profile_and_says_nothing_was_started() {
        let mut client = fake_helper(Err(xraytui_netd_protocol::NetdError::Denied(
            "that process is not yours".into(),
        )))
        .await;
        let error = classify_here(&mut client, "work")
            .await
            .expect_err("must refuse");
        assert!(
            matches!(error, TransparentUnavailable::Refused { .. }),
            "{error:?}"
        );
        let rendered = error.to_string();
        assert!(rendered.contains("work"), "{rendered}");
        assert!(rendered.contains("not started"), "{rendered}");
    }

    #[tokio::test]
    async fn a_command_is_never_run_when_classification_fails() {
        // The failure policy, proven by side effect rather than asserted: the
        // command would create a file, and the file must not appear.
        let directory = std::env::temp_dir().join(format!(
            "xraytui-exec-barrier-{}",
            rustix::process::getpid().as_raw_nonzero()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("temp dir");
        let witness = directory.join("the-command-ran");

        let missing = directory.join("no-helper-here.sock");
        let error = classify_and_exec(
            &missing,
            "work",
            &["touch".to_owned(), witness.display().to_string()],
        )
        .await
        .expect_err("must refuse");

        assert!(error.to_string().contains("work"), "{error}");
        assert!(
            !witness.exists(),
            "the command ran even though classification failed"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_transparent_backend_never_reads_the_proxy_environment() {
        // Scenario M's whole point: the distinction between two instances comes
        // from the cgroup, not from variables an application might honour. If
        // this file ever starts building a `ProxyEnvironment` for the
        // transparent path, this test should be the thing that notices.
        let source = include_str!("exec.rs");
        let transparent = source
            .split("pub async fn classify_and_exec")
            .nth(1)
            .expect("the transparent entry point");
        let body = transparent.split("\n}\n").next().expect("its body");
        assert!(
            !body.contains("ProxyEnvironment"),
            "the transparent path must not depend on proxy variables"
        );
    }

    #[test]
    fn transparent_unavailability_always_explains_the_alternative() {
        for error in [
            TransparentUnavailable::NoHelper,
            TransparentUnavailable::NoCgroupV2,
            TransparentUnavailable::NoInbound {
                profile: "web".into(),
            },
        ] {
            let rendered = error.to_string();
            assert!(
                rendered.contains("transparent") || rendered.contains("--transparent"),
                "{rendered}"
            );
            assert!(rendered.len() > 40, "{rendered} is not actionable enough");
        }
    }
}
