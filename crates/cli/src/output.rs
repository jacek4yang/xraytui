//! Rendering for the five output formats.
//!
//! `dmenu` output is the one with a contract worth stating: each line is
//! `id<TAB>human label`. dmenu shows the whole line, and
//! `profile select-from-stdin` reads the first tab-separated field back, so the
//! identifier survives a round trip through a menu the user can read.

use std::fmt::Write as _;

use xraytui_domain::{DesiredState, HealthState, RuntimeState, Target};

use crate::args::Format;

/// Format a byte count for a status bar: `1.2 MiB`.
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("B");
    if unit == 0 {
        format!("{bytes} {name}")
    } else {
        format!("{value:.1} {name}")
    }
}

/// Format a rate: `8.4 MiB/s`.
#[must_use]
pub fn human_rate(bytes_per_second: u64) -> String {
    format!("{}/s", human_bytes(bytes_per_second))
}

/// The dashboard's profile table, as the specification lays it out.
#[must_use]
pub fn profile_table(runtime: &RuntimeState, desired: &DesiredState) -> String {
    let mut out = String::new();
    out.push_str("Profiles\n");
    out.push_str(&"-".repeat(64));
    out.push('\n');
    for profile in &runtime.profiles {
        let name = desired
            .profiles
            .get(&profile.id)
            .map(|p| p.name.as_str())
            .unwrap_or_else(|| profile.id.as_str());
        let effective = effective_label(&profile.target, desired);
        let latency = profile
            .health
            .ema_latency_ms
            .map_or_else(|| "  --".to_owned(), |ms| format!("{ms:>4} ms"));
        let _ = writeln!(
            out,
            "{:<12} {:<17} {:<12} {:>7}   {}",
            truncate(profile.id.as_str(), 12),
            truncate(&profile.target.short_label(), 17),
            truncate(&effective, 12),
            latency,
            profile.health.state().label()
        );
        let _ = name;
    }
    out.push_str(&"-".repeat(64));
    out.push('\n');
    let _ = writeln!(
        out,
        "TUN: {}   Mode: {}   DNS: {}   Xray API: {}",
        runtime.tun.label(),
        runtime.mode,
        runtime.dns.label(),
        if runtime.core.is_usable() { "healthy" } else { runtime.core.label() }
    );
    let _ = writeln!(
        out,
        "Upload: {}   Download: {}",
        human_rate(runtime.total_traffic.uplink_bps),
        human_rate(runtime.total_traffic.downlink_bps)
    );
    out
}

fn effective_label(target: &Target, desired: &DesiredState) -> String {
    match target {
        Target::Chain { id } => desired
            .chains
            .get(id)
            .map(|chain| {
                chain
                    .hops
                    .iter()
                    .map(|hop| hop.as_str().to_uppercase())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            })
            .unwrap_or_else(|| id.to_string()),
        Target::Group { id } => desired
            .group_members(id)
            .first()
            .map(Target::short_label)
            .unwrap_or_else(|| "(empty)".to_owned()),
        other => other.short_label(),
    }
}

/// Truncate to a display width, appending an ellipsis when it does not fit.
///
/// Width is counted in characters rather than bytes so CJK names do not get cut
/// mid-codepoint. Exact column alignment for double-width glyphs is the TUI's
/// job; here the goal is only that nothing is corrupted.
#[must_use]
pub fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let keep = width.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('…');
    out
}

/// One `id<TAB>label` line.
#[must_use]
pub fn dmenu_line(id: &str, label: &str) -> String {
    format!("{id}\t{label}")
}

/// Recover the identifier from a dmenu line the user selected.
///
/// Accepts a bare identifier too, so a hand-typed answer also works.
#[must_use]
pub fn dmenu_id(selected: &str) -> Option<String> {
    let line = selected.trim();
    if line.is_empty() {
        return None;
    }
    Some(line.split('\t').next().unwrap_or(line).trim().to_owned())
}

/// The one-line status bar summary.
#[must_use]
pub fn dwmblocks_line(runtime: &RuntimeState) -> String {
    if !runtime.core.is_usable() {
        return format!("xray {}", runtime.core.label());
    }
    let down = runtime.profiles.iter().filter(|p| p.health.state() == HealthState::Down).count();
    let mode = runtime.mode.as_str();
    let tun = if runtime.tun.label() == "on" { "tun" } else { "—" };
    let health = if down == 0 { String::new() } else { format!(" !{down}") };
    format!(
        "{mode} {tun} ↑{} ↓{}{health}",
        human_rate(runtime.total_traffic.uplink_bps),
        human_rate(runtime.total_traffic.downlink_bps)
    )
}

/// `KEY=value` lines for `eval "$(xraytui status --format shell)"`.
#[must_use]
pub fn shell_status(runtime: &RuntimeState) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "XRAYTUI_CORE={}", runtime.core.label());
    let _ = writeln!(out, "XRAYTUI_MODE={}", runtime.mode);
    let _ = writeln!(out, "XRAYTUI_TUN={}", runtime.tun.label());
    let _ = writeln!(out, "XRAYTUI_DNS={}", runtime.dns.label());
    let _ = writeln!(out, "XRAYTUI_PROFILES={}", runtime.profiles.len());
    let _ = writeln!(out, "XRAYTUI_UPLINK_BYTES={}", runtime.total_traffic.uplink_bytes);
    let _ = writeln!(out, "XRAYTUI_DOWNLINK_BYTES={}", runtime.total_traffic.downlink_bytes);
    for profile in &runtime.profiles {
        let key = profile.id.as_str().to_uppercase().replace('-', "_");
        let _ = writeln!(out, "XRAYTUI_PROFILE_{key}={}", profile.target.to_token());
    }
    out
}

/// Render a value in the requested format, using `plain` for the human case.
///
/// # Errors
/// Propagates JSON serialisation failures.
pub fn render<T: serde::Serialize>(
    format: Format,
    value: &T,
    plain: impl FnOnce() -> String,
) -> Result<String, serde_json::Error> {
    match format {
        Format::Json => serde_json::to_string_pretty(value).map(|mut s| {
            s.push('\n');
            s
        }),
        _ => Ok(plain()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{
        EgressProfile, HealthRecord, ProbeKind, ProbeOutcome, ProbeResult, ProfileId,
        ProfileRuntime, TrafficCounters,
    };

    fn runtime() -> RuntimeState {
        let mut health = HealthRecord::default();
        health.record(ProbeResult {
            at_unix_ms: 0,
            latency_ms: Some(42),
            outcome: ProbeOutcome::Ok,
            kind: ProbeKind::TcpConnect,
        });
        RuntimeState {
            mode: xraytui_domain::SystemMode::Rule,
            core: xraytui_domain::CoreStatus::Running {
                generation: xraytui_domain::GenerationId(1),
                pid: 1,
                version: "26.3.27".into(),
                since_unix: 0,
            },
            profiles: vec![ProfileRuntime {
                id: ProfileId::new("web").expect("valid"),
                target: Target::Direct,
                effective_outbound: Some("control/direct".into()),
                health,
                traffic: TrafficCounters::default(),
                socks_listen: Some("127.0.0.1:11080".into()),
                http_listen: None,
                listeners_healthy: true,
            }],
            total_traffic: TrafficCounters {
                uplink_bytes: 1_258_291,
                downlink_bytes: 8_808_038,
                uplink_bps: 1_258_291,
                downlink_bps: 8_808_038,
            },
            ..Default::default()
        }
    }

    #[test]
    fn byte_formatting_matches_the_dashboard_example() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_rate(1_258_291), "1.2 MiB/s");
        assert_eq!(human_rate(8_808_038), "8.4 MiB/s");
    }

    #[test]
    fn the_profile_table_has_the_specified_shape() {
        let mut desired = DesiredState::default();
        let id = ProfileId::new("web").expect("valid");
        desired.profiles.insert(id.clone(), EgressProfile::new(id, "Web", Target::Direct));
        let table = profile_table(&runtime(), &desired);
        assert!(table.starts_with("Profiles\n"), "{table}");
        assert!(table.contains("web"), "{table}");
        assert!(table.contains("42 ms"), "{table}");
        assert!(table.contains("up"), "{table}");
        assert!(table.contains("TUN: off"), "{table}");
        assert!(table.contains("Mode: rule"), "{table}");
        assert!(table.contains("Upload: 1.2 MiB/s"), "{table}");
        assert!(table.contains("Download: 8.4 MiB/s"), "{table}");
    }

    #[test]
    fn dmenu_lines_round_trip_through_a_menu() {
        let line = dmenu_line("hk-01", "HK 01  vless/ws+tls  42 ms");
        assert_eq!(dmenu_id(&line).as_deref(), Some("hk-01"));
        // A user who typed the identifier by hand is also understood.
        assert_eq!(dmenu_id("hk-01").as_deref(), Some("hk-01"));
        assert_eq!(dmenu_id("  hk-01  \n").as_deref(), Some("hk-01"));
        assert_eq!(dmenu_id(""), None);
        assert_eq!(dmenu_id("   \n "), None);
    }

    #[test]
    fn dmenu_labels_may_contain_spaces_but_never_tabs_in_the_id() {
        let line = dmenu_line("auto-hk", "Auto HK (3 members)");
        let mut fields = line.split('\t');
        assert_eq!(fields.next(), Some("auto-hk"));
        assert_eq!(fields.next(), Some("Auto HK (3 members)"));
        assert_eq!(fields.next(), None);
    }

    #[test]
    fn the_status_bar_line_is_short_and_informative() {
        let line = dwmblocks_line(&runtime());
        // Byte length, not character count: the arrows are multi-byte.
        assert!(line.chars().count() < 48, "{line} is too long for a status bar");
        assert!(line.contains("rule"), "{line}");
        assert!(line.contains("1.2 MiB/s"), "{line}");
    }

    #[test]
    fn the_status_bar_reports_a_stopped_core_plainly() {
        let mut state = runtime();
        state.core = xraytui_domain::CoreStatus::Stopped;
        assert_eq!(dwmblocks_line(&state), "xray stopped");
    }

    #[test]
    fn shell_output_is_evaluable() {
        let output = shell_status(&runtime());
        for line in output.lines() {
            assert!(line.starts_with("XRAYTUI_"), "{line}");
            let (key, value) = line.split_once('=').unwrap_or_else(|| panic!("{line}"));
            assert!(!key.contains(' '), "{line}");
            assert!(!value.contains('\n'), "{line}");
            assert!(!value.contains(';'), "{line} could break an eval");
            assert!(!value.contains('`'), "{line} could break an eval");
            assert!(!value.contains('$'), "{line} could break an eval");
        }
        assert!(output.contains("XRAYTUI_PROFILE_WEB=direct"), "{output}");
    }

    #[test]
    fn truncation_never_splits_a_character() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("香港节点名称很长", 4), "香港节…");
        assert_eq!(truncate("abcdef", 3), "ab…");
    }

    #[test]
    fn json_rendering_is_pretty_and_newline_terminated() {
        let value = serde_json::json!({"a": 1});
        let rendered = render(Format::Json, &value, || "unused".into()).expect("render");
        assert!(rendered.ends_with("}\n"), "{rendered:?}");
        assert!(rendered.contains("\n  \"a\""), "{rendered:?}");
    }
}
