//! The project's own nftables table, described structurally.
//!
//! # Why the ruleset is text, and why that is still safe
//!
//! The first implementation built libnftables JSON, so that no ruleset syntax
//! existed anywhere in the project. That does not work: **nftables 1.0.9's JSON
//! parser cannot express `socket cgroupv2` at all.** It emits the expression
//! when dumping a ruleset — and emits it *lossily*, dropping the `level` — but
//! rejects it on input with "Invalid socket key value". Since matching a cgroup
//! is the entire mechanism behind per-application routing, JSON is not an
//! option. This was found by the namespace tests; see
//! `docs/UPSTREAM-COMPATIBILITY.md`.
//!
//! So the ruleset is generated as nftables' own syntax and fed to `nft` on
//! standard input with an argv of exactly `["-f", "-"]`. **There is no shell.**
//! What replaces "no syntax anywhere" is a narrower guarantee that is checked
//! rather than assumed:
//!
//! * every value that reaches the text is either an integer, or a string that
//!   [`Script`]'s constructor has verified against [`SAFE_WORD`] — lowercase
//!   letters, digits, and `-`, `_`, `.`, `/` only;
//! * that character set contains nothing nftables treats as syntax: no quote,
//!   brace, semicolon, backslash, newline or space;
//! * the only strings involved are an interface name (already constrained to
//!   `^xraytui[0-9a-z]{0,8}$` by the protocol), a cgroup path built from the
//!   credential UID and a validated slug, and the project's own fixed names.
//!
//! A value that fails the check is refused with [`NftError::Unsafe`] and no
//! ruleset is produced, so the failure mode is "nothing happened", not "the
//! wrong rule was installed".
//!
//! # Only one table is ever touched
//!
//! Everything lives in `table inet xraytui`. Chains are named `u<uid>-…`, so one
//! user's teardown cannot remove another's, and nothing outside that table is
//! read, written or flushed. A machine with its own firewall keeps it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::Value;
use xraytui_netd_protocol::{FirewallRequest, NFT_FAMILY, NFT_TABLE};

use crate::{cgroup, program};

/// Priority of the marking chain: before the routing decision, so that a mark
/// set here causes the packet to be re-routed.
const PRIORITY_MANGLE: i32 = -150;

/// Priority of the kill-switch chain: after re-routing, so that `oifname` is the
/// interface the packet will really leave by.
const PRIORITY_FILTER: i32 = 0;

/// Priority of the redirect chain, on the way back *in*.
///
/// Marked traffic is put back onto loopback by a `local` route, re-enters
/// through prerouting, and is handed to the profile's own listener here.
const PRIORITY_PREROUTING: i32 = -150;

/// Depth of a profile cgroup below the cgroup v2 root: `xraytui.slice/u<uid>/<profile>`.
const CGROUP_LEVEL: u32 = 3;

/// How long `nft` may take before the helper gives up on it.
const NFT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The only characters allowed in a value that becomes part of a ruleset.
///
/// Deliberately smaller than "what nftables would accept": the point is that
/// nothing in this set can end a token, open a block, start a comment or
/// introduce a new statement.
pub const SAFE_WORD: fn(char) -> bool =
    |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '/');

/// Errors the nftables backend can report.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// `nft` is not installed or not executable.
    #[error("cannot run {program}: {source}")]
    Spawn {
        /// Program that was attempted.
        program: String,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// `nft` exited non-zero.
    #[error("nft refused the ruleset ({code}): {message}")]
    Refused {
        /// Exit status, or -1 if it was signalled.
        code: i32,
        /// First line of standard error.
        message: String,
    },
    /// `nft` produced output that could not be parsed as JSON.
    #[error("nft produced output that is not JSON: {0}")]
    Output(String),
    /// The helper could not talk to the child process.
    #[error("cannot exchange data with nft: {0}")]
    Pipe(#[source] std::io::Error),
    /// A value would have become nftables syntax. Nothing was generated.
    #[error("refusing to put {value:?} in a ruleset: {reason}")]
    Unsafe {
        /// The offending value, as received.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },
}

/// An nftables script, built only from values that passed the safety check.
///
/// The type exists so that "this text is safe" is a property of the
/// constructor rather than of every call site: there is no way to obtain a
/// `Script` containing a word that was not checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    text: String,
}

impl Script {
    /// An empty script.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the script would do nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The number of commands.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.lines().filter(|line| !line.is_empty()).count()
    }

    /// The script as nftables would read it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Append a literal fragment. Only ever called with compile-time text.
    fn push_literal(&mut self, fragment: &str) -> &mut Self {
        self.text.push_str(fragment);
        self
    }

    /// Append a checked word.
    ///
    /// # Errors
    /// [`NftError::Unsafe`] if the value contains anything outside
    /// [`SAFE_WORD`], or is empty, or is implausibly long.
    fn push_word(&mut self, value: &str) -> Result<&mut Self, NftError> {
        if value.is_empty() {
            return Err(NftError::Unsafe {
                value: value.to_owned(),
                reason: "an empty value cannot be a ruleset token",
            });
        }
        if value.len() > 128 {
            return Err(NftError::Unsafe {
                value: value.chars().take(32).collect(),
                reason: "longer than any name this project generates",
            });
        }
        if !value.chars().all(SAFE_WORD) {
            return Err(NftError::Unsafe {
                value: value.to_owned(),
                reason: "contains a character that nftables could read as syntax",
            });
        }
        self.text.push_str(value);
        Ok(self)
    }

    /// Append a quoted, checked string.
    fn push_quoted(&mut self, value: &str) -> Result<&mut Self, NftError> {
        self.text.push('"');
        self.push_word(value)?;
        self.text.push('"');
        Ok(self)
    }

    /// Append an unsigned integer in hexadecimal.
    fn push_hex(&mut self, value: u32) -> &mut Self {
        use std::fmt::Write as _;
        let _ = write!(self.text, "{value:#x}");
        self
    }

    fn newline(&mut self) -> &mut Self {
        self.text.push('\n');
        self
    }
}

/// Name of the marking chain for a uid.
#[must_use]
pub fn mark_chain(uid: u32) -> String {
    format!("u{uid}-mark")
}

/// Name of the kill-switch chain for a uid.
#[must_use]
pub fn guard_chain(uid: u32) -> String {
    format!("u{uid}-guard")
}

/// Name of the transparent-redirect chain for a uid.
#[must_use]
pub fn redirect_chain(uid: u32) -> String {
    format!("u{uid}-redirect")
}

/// Build the complete ruleset for one user.
///
/// The script is *declarative*: it creates the table and the two chains if they
/// are missing, flushes the chains, and adds exactly the rules the request asks
/// for. `nft -f` applies the whole file in one transaction, so applying it twice
/// leaves the same state and a rejected script changes nothing — which is what
/// acceptance scenario K needs.
///
/// # Errors
/// [`NftError::Unsafe`] if any value would have become syntax. In that case no
/// script is produced at all.
pub fn user_ruleset(
    uid: u32,
    interface: &str,
    fwmark: u32,
    request: &FirewallRequest,
) -> Result<Script, NftError> {
    let mark = mark_chain(uid);
    let guard = guard_chain(uid);
    let redirect = redirect_chain(uid);
    let mut script = Script::new();

    script.push_literal("add table ");
    script.push_word(NFT_FAMILY)?.push_literal(" ");
    script.push_word(NFT_TABLE)?.newline();

    for (chain, kind, hook, priority) in [
        (&mark, "route", "output", PRIORITY_MANGLE),
        (&guard, "filter", "output", PRIORITY_FILTER),
        (&redirect, "filter", "prerouting", PRIORITY_PREROUTING),
    ] {
        script.push_literal("add chain ");
        script.push_word(NFT_FAMILY)?.push_literal(" ");
        script.push_word(NFT_TABLE)?.push_literal(" ");
        script.push_word(chain)?;
        script.push_literal(" { type ");
        script.push_word(kind)?;
        script.push_literal(" hook ");
        script.push_word(hook)?;
        script.push_literal(" priority ");
        script.push_literal(&priority.to_string());
        script.push_literal("; policy accept; }").newline();

        script.push_literal("flush chain ");
        script.push_word(NFT_FAMILY)?.push_literal(" ");
        script.push_word(NFT_TABLE)?.push_literal(" ");
        script.push_word(chain)?.newline();
    }

    // The core's own uplink must never be marked, or its connection to the
    // proxy would be routed into the tunnel it is providing. This rule comes
    // first so it wins.
    if request.bypass_uid {
        rule_prologue(&mut script, &mark)?;
        cgroup_match(&mut script, uid, cgroup::CORE_PROFILE)?;
        script.push_literal(" accept").newline();
    }

    // Nor is anything a process says to its own machine. Two reasons, and the
    // second is the serious one:
    //
    //   * a classified application must still reach the database, the display
    //     server or the package cache on localhost;
    //   * without this, a connection to `127.0.0.1:anything` would be marked,
    //     re-routed and handed to the profile's own transparent listener, which
    //     would read its own address as the original destination and dial
    //     itself through the proxy — a loop that ends in exhausted descriptors.
    //
    // Fixed text, so `push_literal`: `::1` contains a character `push_word`
    // refuses, and rightly — that check is for values from outside.
    for match_expression in ["ip daddr 127.0.0.0/8", "ip6 daddr ::1"] {
        rule_prologue(&mut script, &mark)?;
        script.push_literal(match_expression);
        script.push_literal(" accept").newline();
    }

    // A profile with a transparent listener of its own gets its own mark,
    // derived from the uid and the profile's position; slot 0 is the tunnel, so
    // these start at one. A profile without one is carried by the shared tunnel
    // and therefore wears the tunnel's mark, which is what the routing rules and
    // the kill switch below are written against — without that fallback,
    // per-application routing through the tunnel would stop working the moment
    // per-profile transparent egress arrived.
    //
    // The mark is the only thing that survives to prerouting. A socket lookup
    // there finds nothing for an outbound SYN — there is no listener for the
    // destination — so the cgroup cannot be matched a second time. That is why
    // the decision has to be taken here, where the cgroup *is* visible, and
    // carried onward as a number. It also makes the mark a capability: an
    // arriving packet cannot forge one, because `skb->mark` starts at zero for
    // anything this machine did not itself emit.
    for (index, entry) in request.cgroup_marks.iter().enumerate() {
        let Some(port) = entry.tproxy_port else {
            rule_prologue(&mut script, &mark)?;
            cgroup_match(&mut script, uid, &entry.profile)?;
            script.push_literal(" meta mark set ");
            script.push_hex(fwmark).newline();
            continue;
        };
        let profile_mark = xraytui_netd_protocol::transparent_mark(uid, index + 1);
        rule_prologue(&mut script, &mark)?;
        cgroup_match(&mut script, uid, &entry.profile)?;
        script.push_literal(" meta mark set ");
        script.push_hex(profile_mark).newline();

        // Three details here are not decoration, and each was established
        // against a running kernel rather than from documentation:
        //
        //   * `tproxy` refuses a rule with no transport-protocol match
        //     ("Transparent proxy support requires transport protocol match");
        //   * naming an address in an `inet` table requires the family to be
        //     stated ("specify `tproxy ip' or `tproxy ip6' ... to
        //     disambiguate"), so the rule is IPv4 and says so;
        //   * naming `127.0.0.1` rather than leaving the address implicit is
        //     what allows the listener to bind loopback instead of every address
        //     on the machine, which is the difference between a listener only
        //     this host can reach and one the network can.
        rule_prologue(&mut script, &redirect)?;
        script.push_literal("meta nfproto ipv4 meta l4proto { tcp, udp } meta mark ");
        script.push_hex(profile_mark);
        script.push_literal(" tproxy ip to 127.0.0.1:");
        script.push_literal(&port.to_string());
        script.push_literal(" accept").newline();
    }

    // The kill switch drops anything carrying this user's mark that did not end
    // up on this user's tunnel. Without it, a tunnel that goes away turns into
    // a silent direct connection.
    if request.kill_switch {
        rule_prologue(&mut script, &guard)?;
        script.push_literal("meta mark ");
        script.push_hex(fwmark);
        script.push_literal(" oifname != ");
        script.push_quoted(interface)?;
        // The counter makes a triggered kill switch observable without packet
        // capture or logging any destination. The privileged namespace suite
        // uses it to prove that a broken route was stopped.
        script.push_literal(" counter drop").newline();
    }

    Ok(script)
}

/// Build the script that removes one user's chains, given what exists.
///
/// `existing` is the chain-name list read back from the live ruleset, so the
/// script never asks nftables to delete something that is not there — which
/// would abort the whole transaction and leave the rest in place.
///
/// # Errors
/// [`NftError::Unsafe`] if a chain name read back from the ruleset is not one
/// this project could have written.
pub fn clear_user(uid: u32, existing: &[String]) -> Result<Script, NftError> {
    let mut script = Script::new();
    for name in [mark_chain(uid), guard_chain(uid), redirect_chain(uid)] {
        if !existing.contains(&name) {
            continue;
        }
        for verb in ["flush chain ", "delete chain "] {
            script.push_literal(verb);
            script.push_word(NFT_FAMILY)?.push_literal(" ");
            script.push_word(NFT_TABLE)?.push_literal(" ");
            script.push_word(&name)?.newline();
        }
    }
    Ok(script)
}

fn rule_prologue(script: &mut Script, chain: &str) -> Result<(), NftError> {
    script.push_literal("add rule ");
    script.push_word(NFT_FAMILY)?.push_literal(" ");
    script.push_word(NFT_TABLE)?.push_literal(" ");
    script.push_word(chain)?.push_literal(" ");
    Ok(())
}

fn cgroup_match(script: &mut Script, uid: u32, profile: &str) -> Result<(), NftError> {
    script.push_literal("socket cgroupv2 level ");
    script.push_literal(&CGROUP_LEVEL.to_string());
    script.push_literal(" ");
    script.push_quoted(&cgroup::relative_path(uid, profile))?;
    Ok(())
}

/// A handle on the `nft` program.
#[derive(Debug, Clone)]
pub struct Nft {
    program: PathBuf,
}

impl Default for Nft {
    fn default() -> Self {
        Self::new("nft")
    }
}

impl Nft {
    /// Use a specific `nft`, which the test suite overrides.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// The program this handle will run.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Whether `nft` can be executed at all.
    #[must_use]
    pub fn available(&self) -> bool {
        self.version().is_ok()
    }

    /// The version string `nft --version` reports.
    ///
    /// # Errors
    /// [`NftError::Spawn`] if the program is missing.
    pub fn version(&self) -> Result<String, NftError> {
        let output = self.execute(&["--version"], None)?;
        Ok(output.trim().to_owned())
    }

    /// Apply a script, after checking it.
    ///
    /// The check is a second pass with `-c`, which parses and validates without
    /// committing. `nft -f` is already transactional, so the check is not what
    /// makes the apply safe — it is what makes a *rejection* cost nothing and
    /// report the same message it would have reported at apply time.
    /// `docs/THREAT-MODEL.md` T4 names this pair explicitly.
    ///
    /// # Errors
    /// [`NftError::Refused`] if nftables rejected it; nothing will have changed.
    pub fn apply(&self, script: &Script) -> Result<(), NftError> {
        if script.is_empty() {
            return Ok(());
        }
        self.check(script)?;
        self.execute(&["-f", "-"], Some(script.as_str()))?;
        Ok(())
    }

    /// Check a script without applying it.
    ///
    /// # Errors
    /// [`NftError::Refused`] if nftables would reject it.
    pub fn check(&self, script: &Script) -> Result<(), NftError> {
        if script.is_empty() {
            return Ok(());
        }
        self.execute(&["-c", "-f", "-"], Some(script.as_str()))?;
        Ok(())
    }

    /// The chain names currently present in the project table.
    ///
    /// Returns an empty vector if the table does not exist, which is the normal
    /// state on a machine that has never used the helper.
    ///
    /// # Errors
    /// [`NftError::Spawn`] if `nft` is missing.
    pub fn chains(&self) -> Result<Vec<String>, NftError> {
        let output = match self.execute(&["-j", "list", "table", NFT_FAMILY, NFT_TABLE], None) {
            Ok(output) => output,
            // A missing table is reported as a non-zero exit; that is not an
            // error for our purposes.
            Err(NftError::Refused { .. }) => return Ok(Vec::new()),
            Err(other) => return Err(other),
        };
        let parsed: Value =
            serde_json::from_str(&output).map_err(|error| NftError::Output(error.to_string()))?;
        let mut out = Vec::new();
        if let Some(items) = parsed.get("nftables").and_then(Value::as_array) {
            for item in items {
                if let Some(name) = item
                    .get("chain")
                    .and_then(|chain| chain.get("name"))
                    .and_then(Value::as_str)
                {
                    out.push(name.to_owned());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Whether this nftables understands `socket cgroupv2`, tested against a
    /// cgroup that is known to exist.
    ///
    /// Returns `false` rather than an error when it cannot be determined, so a
    /// capability report is never a failure.
    #[must_use]
    pub fn supports_cgroup_match(&self, existing_cgroup: &str) -> bool {
        if existing_cgroup.is_empty() {
            return false;
        }
        let level = existing_cgroup
            .split('/')
            .filter(|part| !part.is_empty())
            .count();
        let mut script = Script::new();
        script.push_literal("add table ");
        if script.push_word(NFT_FAMILY).is_err() {
            return false;
        }
        script.push_literal(" ");
        if script.push_word(NFT_TABLE).is_err() {
            return false;
        }
        script.newline();
        script.push_literal("add chain ");
        let built = (|| -> Result<(), NftError> {
            script.push_word(NFT_FAMILY)?.push_literal(" ");
            script
                .push_word(NFT_TABLE)?
                .push_literal(" probe")
                .newline();
            script.push_literal("add rule ");
            script.push_word(NFT_FAMILY)?.push_literal(" ");
            script.push_word(NFT_TABLE)?.push_literal(" probe ");
            script.push_literal("socket cgroupv2 level ");
            script.push_literal(&level.to_string());
            script.push_literal(" ");
            script.push_quoted(existing_cgroup)?;
            script.push_literal(" accept").newline();
            Ok(())
        })();
        built.is_ok() && self.check(&script).is_ok()
    }

    fn execute(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftError> {
        // Resolved against a fixed search path, never the ambient one: which
        // `nft` the privileged helper runs is not an operator's `PATH` to
        // decide, and a cleared environment cannot resolve a bare name at all.
        let resolved = program::resolve(&self.program).ok_or_else(|| NftError::Spawn {
            program: self.program.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found in /usr/sbin, /usr/bin, /sbin, /bin or /usr/local/sbin",
            ),
        })?;
        let mut command = program::command(&resolved);
        command
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|source| NftError::Spawn {
            program: self.program.display().to_string(),
            source,
        })?;

        if let Some(payload) = stdin {
            let mut handle = child
                .stdin
                .take()
                .ok_or_else(|| NftError::Pipe(std::io::Error::other("stdin was not piped")))?;
            handle
                .write_all(payload.as_bytes())
                .map_err(NftError::Pipe)?;
            // Dropping closes the pipe, which is what tells nft the batch ended.
            drop(handle);
        }

        let deadline = std::time::Instant::now() + NFT_TIMEOUT;
        loop {
            match child.try_wait().map_err(NftError::Pipe)? {
                Some(_) => break,
                None if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(NftError::Pipe(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "nft did not finish in time",
                    )));
                }
                None => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }

        let output = child.wait_with_output().map_err(NftError::Pipe)?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(NftError::Refused {
            code: output.status.code().unwrap_or(-1),
            message: stderr.lines().next().unwrap_or("no message").to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_netd_protocol::CgroupMark;

    fn request() -> FirewallRequest {
        FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "work".into(),
                tproxy_port: Some(19001),
            }],
            kill_switch: true,
            bypass_uid: true,
        }
    }

    fn rendered(uid: u32) -> String {
        user_ruleset(uid, "xraytui1000", 0x7261_0000, &request())
            .expect("ruleset")
            .as_str()
            .to_owned()
    }

    #[test]
    fn every_command_names_the_project_table_and_nothing_else() {
        let text = rendered(1000);
        assert!(!text.is_empty());
        for line in text.lines() {
            assert!(
                line.contains(&format!("{NFT_FAMILY} {NFT_TABLE}")),
                "a command touched something outside the project table: {line}"
            );
        }
    }

    #[test]
    fn chain_names_carry_the_owning_uid() {
        assert_eq!(mark_chain(1000), "u1000-mark");
        assert_eq!(guard_chain(1000), "u1000-guard");
        let text = rendered(1000);
        assert!(text.contains("u1000-mark"));
        assert!(text.contains("u1000-guard"));
        assert!(!text.contains("u1001"));
    }

    #[test]
    fn the_core_bypass_rule_comes_before_any_marking_rule() {
        let text = rendered(1000);
        let bypass = text.find("u1000/core").expect("bypass rule present");
        let marking = text.find("u1000/work").expect("marking rule present");
        assert!(
            bypass < marking,
            "the core's own traffic must be accepted before anything is marked"
        );
    }

    #[test]
    fn the_cgroup_match_carries_the_level_that_json_cannot() {
        // The reason this module generates text at all: nftables 1.0.9's JSON
        // parser rejects `socket cgroupv2`, and its dump drops the level.
        let text = rendered(1000);
        assert!(
            text.contains("socket cgroupv2 level 3 \"xraytui.slice/u1000/work\""),
            "{text}"
        );
    }

    #[test]
    fn without_a_kill_switch_no_drop_rule_is_emitted() {
        let mut spec = request();
        spec.kill_switch = false;
        let text = user_ruleset(1000, "xraytui1000", 1, &spec)
            .expect("ruleset")
            .as_str()
            .to_owned();
        assert!(!text.contains("drop"), "{text}");
    }

    #[test]
    fn the_kill_switch_drops_marked_traffic_leaving_by_any_other_interface() {
        let text = rendered(1000);
        let line = text
            .lines()
            .find(|line| line.contains("u1000-guard") && line.starts_with("add rule"))
            .expect("a guard rule");
        assert!(line.contains("meta mark 0x72610000"), "{line}");
        assert!(line.contains("oifname != \"xraytui1000\""), "{line}");
        assert!(line.ends_with("counter drop"), "{line}");
    }

    #[test]
    fn each_profile_gets_the_mark_the_helper_derived_for_it() {
        // The caller cannot choose a mark, so the assertion is that the one the
        // protocol derives is the one that reaches the ruleset.
        let spec = FirewallRequest {
            cgroup_marks: vec![
                CgroupMark {
                    profile: "media".into(),
                    tproxy_port: Some(19_007),
                },
                CgroupMark {
                    profile: "work".into(),
                    tproxy_port: Some(19_008),
                },
            ],
            kill_switch: false,
            bypass_uid: false,
        };
        let text = user_ruleset(42, "xraytui42", 0, &spec)
            .expect("ruleset")
            .as_str()
            .to_owned();
        for (index, profile) in ["media", "work"].iter().enumerate() {
            let mark = xraytui_netd_protocol::transparent_mark(42, index + 1);
            assert!(
                text.contains(&format!("meta mark set {mark:#x}")),
                "{profile} did not get {mark:#x}: {text}"
            );
        }
        // Two profiles, two different marks.
        assert_ne!(
            xraytui_netd_protocol::transparent_mark(42, 1),
            xraytui_netd_protocol::transparent_mark(42, 2)
        );
    }

    #[test]
    fn a_profile_with_a_listener_gets_a_tproxy_rule_and_one_without_does_not() {
        let spec = FirewallRequest {
            cgroup_marks: vec![
                CgroupMark {
                    profile: "media".into(),
                    tproxy_port: Some(19_007),
                },
                CgroupMark {
                    profile: "tunnelled".into(),
                    tproxy_port: None,
                },
            ],
            kill_switch: false,
            bypass_uid: false,
        };
        let text = user_ruleset(42, "xraytui42", 0, &spec)
            .expect("ruleset")
            .as_str()
            .to_owned();
        assert!(text.contains("tproxy ip to 127.0.0.1:19007"), "{text}");
        assert_eq!(text.matches("tproxy ip to").count(), 1, "{text}");
        // Both are still marked; only one is redirected.
        assert_eq!(text.matches("meta mark set").count(), 2, "{text}");
    }

    #[test]
    fn a_profile_without_a_listener_wears_the_tunnel_mark_so_the_tunnel_carries_it() {
        // Otherwise it would get a mark of its own that nothing routes, and
        // per-application routing through the shared tunnel — scenario K — would
        // quietly stop working the moment scenario M arrived.
        let fwmark = xraytui_netd_protocol::fwmark_for_uid(42);
        let spec = FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "tunnelled".into(),
                tproxy_port: None,
            }],
            kill_switch: false,
            bypass_uid: false,
        };
        let text = user_ruleset(42, "xraytui42", fwmark, &spec)
            .expect("ruleset")
            .as_str()
            .to_owned();
        assert!(
            text.contains(&format!("meta mark set {fwmark:#x}")),
            "{text}"
        );
        assert!(!text.contains("tproxy"), "{text}");
    }

    #[test]
    fn the_redirect_names_loopback_and_its_family() {
        // Both were established against a running kernel: nftables refuses
        // `tproxy to <address>` in an `inet` table without a family, and naming
        // 127.0.0.1 is what lets the listener bind loopback instead of every
        // address on the machine.
        let spec = FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "media".into(),
                tproxy_port: Some(19_007),
            }],
            kill_switch: false,
            bypass_uid: false,
        };
        let text = user_ruleset(42, "xraytui42", 0, &spec)
            .expect("ruleset")
            .as_str()
            .to_owned();
        let rule = text
            .lines()
            .find(|line| line.contains("tproxy"))
            .expect("a tproxy rule");
        assert!(rule.contains("meta nfproto ipv4"), "{rule}");
        assert!(rule.contains("tproxy ip to 127.0.0.1:19007"), "{rule}");
    }

    #[test]
    fn traffic_to_this_machine_is_never_marked_so_the_listener_cannot_dial_itself() {
        let spec = FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "media".into(),
                tproxy_port: Some(19_007),
            }],
            kill_switch: false,
            bypass_uid: true,
        };
        let text = user_ruleset(42, "xraytui42", 0, &spec)
            .expect("ruleset")
            .as_str()
            .to_owned();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("u42-mark") && line.starts_with("add rule"))
            .collect();
        let loopback = lines
            .iter()
            .position(|line| line.contains("ip daddr 127.0.0.0/8 accept"))
            .expect("an IPv4 loopback exemption");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("ip6 daddr ::1 accept")),
            "{text}"
        );
        let marking = lines
            .iter()
            .position(|line| line.contains("meta mark set"))
            .expect("a marking rule");
        assert!(
            loopback < marking,
            "the exemption must come before the marking rule, or it never runs: {text}"
        );
    }

    #[test]
    fn a_tproxy_rule_carries_the_transport_match_nftables_insists_on() {
        // Without `meta l4proto` nftables refuses the rule outright:
        // "Transparent proxy support requires transport protocol match".
        let spec = FirewallRequest {
            cgroup_marks: vec![CgroupMark {
                profile: "media".into(),
                tproxy_port: Some(19_007),
            }],
            kill_switch: false,
            bypass_uid: false,
        };
        let text = user_ruleset(42, "xraytui42", 0, &spec)
            .expect("ruleset")
            .as_str()
            .to_owned();
        let rule = text
            .lines()
            .find(|line| line.contains("tproxy"))
            .expect("a tproxy rule");
        assert!(rule.contains("meta l4proto"), "{rule}");
        assert!(rule.contains("u42-redirect"), "{rule}");
    }

    #[test]
    fn clearing_only_deletes_chains_that_exist() {
        let existing = vec!["u1000-mark".to_owned()];
        let text = clear_user(1000, &existing)
            .expect("script")
            .as_str()
            .to_owned();
        assert!(text.contains("u1000-mark"));
        assert!(!text.contains("u1000-guard"));
        assert!(clear_user(1000, &[]).expect("script").is_empty());
    }

    // --- the safety gate ---------------------------------------------------

    #[test]
    fn a_value_that_could_become_syntax_is_refused_and_nothing_is_generated() {
        for hostile in [
            "work; add rule inet xraytui u0-mark accept",
            "work\nadd table inet other",
            "work\"",
            "work}",
            "work{",
            "work\\",
            "work ",
            "WORK",
            "work$(id)",
            "work`id`",
        ] {
            let spec = FirewallRequest {
                cgroup_marks: vec![CgroupMark {
                    profile: hostile.into(),
                    tproxy_port: Some(19000),
                }],
                kill_switch: false,
                bypass_uid: false,
            };
            let result = user_ruleset(1000, "xraytui1000", 1, &spec);
            assert!(
                matches!(result, Err(NftError::Unsafe { .. })),
                "{hostile:?} was not refused: {result:?}"
            );
        }
    }

    #[test]
    fn a_hostile_interface_name_is_refused_too() {
        let result = user_ruleset(1000, "xraytui1000\" accept #", 1, &request());
        assert!(matches!(result, Err(NftError::Unsafe { .. })), "{result:?}");
    }

    #[test]
    fn an_empty_or_overlong_value_is_refused() {
        let mut script = Script::new();
        assert!(matches!(script.push_word(""), Err(NftError::Unsafe { .. })));
        assert!(matches!(
            script.push_word(&"a".repeat(129)),
            Err(NftError::Unsafe { .. })
        ));
        assert!(script.is_empty(), "a refused word must leave no residue");
    }

    #[test]
    fn the_safe_character_set_excludes_everything_nftables_treats_as_syntax() {
        for c in [
            '"', '\'', '{', '}', ';', '\\', '\n', '\r', ' ', '\t', '#', '$', '`', '*', ',',
        ] {
            assert!(!SAFE_WORD(c), "{c:?} must not be allowed in a ruleset word");
        }
        for c in ['a', 'z', '0', '9', '-', '_', '.', '/'] {
            assert!(SAFE_WORD(c), "{c:?} must be allowed");
        }
    }

    #[test]
    fn every_profile_the_protocol_accepts_is_also_safe_here() {
        // The two validators must not disagree: anything `netd-protocol` lets
        // through has to be renderable, or a legitimate profile would fail at
        // the last moment.
        for profile in ["work", "media-2", "a_b", "x", &"a".repeat(64)] {
            let operation = xraytui_netd_protocol::Operation::CreateCgroup {
                profile: profile.to_owned(),
            };
            if operation.validate(1000).is_err() {
                continue;
            }
            let spec = FirewallRequest {
                cgroup_marks: vec![CgroupMark {
                    profile: profile.to_owned(),
                    tproxy_port: Some(19000),
                }],
                kill_switch: false,
                bypass_uid: false,
            };
            assert!(
                user_ruleset(1000, "xraytui1000", 1, &spec).is_ok(),
                "{profile:?} passed the protocol but was refused by the renderer"
            );
        }
    }

    // --- running -----------------------------------------------------------

    #[test]
    fn applying_an_empty_script_never_runs_the_program() {
        // A program name that cannot exist proves nothing was spawned.
        let nft = Nft::new("/nonexistent/nft");
        assert!(nft.apply(&Script::new()).is_ok());
        assert!(nft.check(&Script::new()).is_ok());
    }

    #[test]
    fn a_missing_program_is_reported_rather_than_panicking() {
        let nft = Nft::new("/nonexistent/nft");
        assert!(!nft.available());
        let script = user_ruleset(1000, "xraytui1000", 1, &request()).expect("ruleset");
        assert!(matches!(nft.apply(&script), Err(NftError::Spawn { .. })));
    }

    #[test]
    fn a_relative_program_name_with_a_separator_is_not_run() {
        let nft = Nft::new("./nft");
        assert!(!nft.available());
    }
}
