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
    /// The profile has no transparent inbound configured.
    #[error(
        "profile '{profile}' has no transparent inbound.\n\
         Set `transparent_inbound = true` on it and restart the core."
    )]
    NoInbound {
        /// Profile that was asked for.
        profile: String,
    },
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
    if !std::path::Path::new("/run/xraytui/netd.sock").exists() {
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
