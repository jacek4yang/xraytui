//! Rendering, asserted against a real buffer.
//!
//! `TestBackend` gives ratatui a fixed-size grid with no terminal behind it, so
//! "usable at 80x24" becomes something a test can check: draw at that size, then
//! assert that the panes are there, that nothing was written outside the grid,
//! and that no line was cut in a way that loses the information it carried.

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use super::*;
use crate::app::{App, Key, Overlay, View};
use xraytui_domain::{DesiredState, EgressProfile, RuntimeState, Target};

fn app() -> App {
    let mut desired = DesiredState::default();
    for (id, name) in [
        ("web", "Web browsing"),
        ("media", "Media"),
        ("work", "Work"),
    ] {
        let profile = EgressProfile::new(
            xraytui_domain::ProfileId::from_text(id),
            name,
            Target::Direct,
        );
        desired.profiles.insert(profile.id.clone(), profile);
    }
    App::new(desired, RuntimeState::default())
}

/// Draw into a grid of the given size and return it as lines of text.
fn screen(app: &App, width: u16, height: u16) -> Vec<String> {
    let mut terminal =
        Terminal::new(TestBackend::new(width, height)).expect("a test terminal always builds");
    terminal
        .draw(|frame| draw(frame, app))
        .expect("drawing must not fail");
    let buffer = terminal.backend().buffer().clone();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol().to_owned())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect()
}

#[test]
fn the_interface_fits_the_size_the_specification_names() {
    let lines = screen(&app(), 80, 24);
    assert_eq!(lines.len(), 24);
    for line in &lines {
        assert!(
            line.chars().count() <= 80,
            "a line overflowed 80 columns: {line:?}"
        );
    }
    let text = lines.join("\n");
    assert!(text.contains("xraytui"), "{text}");
    assert!(text.contains("Profiles"), "{text}");
    assert!(text.contains("Web browsing"), "{text}");
}

#[test]
fn the_header_the_tabs_the_list_and_the_footer_are_all_present() {
    let lines = screen(&app(), 80, 24);
    assert!(lines[0].contains("mode"), "header: {:?}", lines[0]);
    assert!(lines[1].contains("1:Profiles"), "tabs: {:?}", lines[1]);
    assert!(
        lines.iter().any(|line| line.contains("Media")),
        "the list is missing"
    );
    assert!(
        lines.last().expect("a last line").contains("quit"),
        "footer: {:?}",
        lines.last()
    );
}

#[test]
fn every_pane_draws_at_the_minimum_size() {
    let mut app = app();
    for view in View::ALL {
        app.view = view;
        let lines = screen(&app, 80, 24);
        assert_eq!(lines.len(), 24, "{view:?}");
        assert!(
            lines[1].contains(view.title()),
            "{view:?} is not marked active: {:?}",
            lines[1]
        );
    }
}

#[test]
fn an_empty_pane_says_what_is_missing_rather_than_showing_nothing() {
    let app = App {
        view: View::Nodes,
        ..App::default()
    };
    let text = screen(&app, 80, 24).join("\n");
    assert!(text.contains("nothing in nodes"), "{text}");
}

#[test]
fn a_filter_that_matches_nothing_says_which_filter() {
    let mut app = app();
    app.filter = "zzz".to_owned();
    let text = screen(&app, 80, 24).join("\n");
    assert!(text.contains("nothing matches"), "{text}");
    assert!(text.contains("zzz"), "{text}");
}

#[test]
fn the_help_overlay_lists_every_documented_key() {
    let mut app = app();
    app.on_key(Key::Char('?'));
    let text = screen(&app, 80, 24).join("\n");
    for (key, _) in crate::app::KEYS {
        // Long labels are truncated by the popup width; the first token is
        // enough to prove the row is there.
        let token = key.split_whitespace().next().unwrap_or(key);
        assert!(
            text.contains(token),
            "the help overlay is missing {key:?}: {text}"
        );
    }
}

#[test]
fn the_target_picker_shows_the_profile_it_would_change() {
    let mut app = app();
    app.on_key(Key::Enter);
    let text = screen(&app, 80, 24).join("\n");
    assert!(text.contains("point media at"), "{text}");
    assert!(text.contains("direct"), "{text}");
}

#[test]
fn the_filter_overlay_shows_what_has_been_typed() {
    let mut app = app();
    app.overlay = Overlay::Filter {
        query: "med".to_owned(),
    };
    let text = screen(&app, 80, 24).join("\n");
    assert!(text.contains("med"), "{text}");
    assert!(text.contains("Enter applies"), "{text}");
}

#[test]
fn a_confirmation_shows_its_question_and_the_two_answers() {
    let mut app = app();
    app.overlay = Overlay::Confirm {
        prompt: "stop the core?".to_owned(),
        action: Box::new(crate::app::Action::Down),
    };
    let text = screen(&app, 80, 24).join("\n");
    assert!(text.contains("stop the core?"), "{text}");
    assert!(text.contains("y / n"), "{text}");
}

#[test]
fn the_share_menu_is_complete_and_fits_at_eighty_by_twenty_four() {
    let mut app = app();
    app.overlay = Overlay::ShareMenu {
        node: "hk-01".to_owned(),
        selected: 0,
    };
    let text = screen(&app, 80, 24).join("\n");
    for choice in [
        "Show QR",
        "Show share link",
        "Export PNG QR",
        "Export share link",
        "Export Xray JSON",
    ] {
        assert!(text.contains(choice), "missing {choice:?}: {text}");
    }
    assert!(text.contains("Share hk-01"), "{text}");
}

#[test]
fn a_share_link_is_only_rendered_in_the_explicit_secret_overlay() {
    let credential = "vless://11111111-2222-3333-4444-555555555555@example.test:443";
    let mut app = app();
    assert!(!screen(&app, 80, 24).join("\n").contains(credential));
    app.overlay = Overlay::SecretText {
        title: "Share link for hk-01".to_owned(),
        content: xraytui_secrets::Secret::new(credential),
    };
    let text = screen(&app, 80, 24).join("\n");
    assert!(text.contains("credential visible"), "{text}");
    assert!(text.contains("vless://11111111"), "{text}");
}

#[test]
fn a_terminal_smaller_than_the_design_still_draws_something_useful() {
    // Nothing overlaps, nothing panics, and the list survives even when the
    // decoration does not.
    for (width, height) in [(80, 24), (60, 20), (40, 10), (30, 6), (20, 4), (10, 3)] {
        let lines = screen(&app(), width, height);
        assert_eq!(lines.len(), usize::from(height), "{width}x{height}");
        for line in &lines {
            assert!(
                line.chars().count() <= usize::from(width),
                "{width}x{height}: line overflowed: {line:?}"
            );
        }
        assert!(
            lines.iter().any(|line| !line.trim().is_empty()),
            "{width}x{height}: the screen is blank"
        );
    }
}

#[test]
fn a_degenerate_terminal_does_not_panic() {
    for (width, height) in [(1, 1), (1, 24), (80, 1), (2, 2)] {
        let lines = screen(&app(), width, height);
        assert_eq!(lines.len(), usize::from(height));
    }
}

#[test]
fn overlays_stay_inside_a_terminal_too_small_to_hold_them() {
    let mut app = app();
    app.on_key(Key::Char('?'));
    for (width, height) in [(80, 24), (40, 8), (20, 5)] {
        let lines = screen(&app, width, height);
        for line in &lines {
            assert!(
                line.chars().count() <= usize::from(width),
                "{width}x{height}: the help overlay overflowed: {line:?}"
            );
        }
    }
}

/// The row index the highlight is on, found by its background colour.
///
/// Selection is a style rather than a character, so a test that compares text
/// alone would pass whatever the cursor did.
fn highlighted(app: &App, width: u16, height: u16) -> Option<usize> {
    let mut terminal =
        Terminal::new(TestBackend::new(width, height)).expect("a test terminal always builds");
    terminal
        .draw(|frame| draw(frame, app))
        .expect("drawing must not fail");
    let buffer = terminal.backend().buffer().clone();
    (0..height).position(|y| buffer[(0, y)].style().bg == Some(theme::ACCENT))
}

#[test]
fn the_highlight_is_on_the_row_the_cursor_is_on() {
    let mut app = app();
    let first = highlighted(&app, 80, 24).expect("a row must be highlighted");
    app.on_key(Key::Char('j'));
    let second = highlighted(&app, 80, 24).expect("a row must be highlighted");
    assert_eq!(second, first + 1, "j must move the highlight down one row");
    app.on_key(Key::Char('k'));
    assert_eq!(highlighted(&app, 80, 24), Some(first));
}

#[test]
fn an_empty_pane_highlights_nothing() {
    let app = App::default();
    assert_eq!(highlighted(&app, 80, 24), None);
}

#[test]
fn wide_characters_are_counted_by_the_width_they_draw() {
    // A name in CJK is two columns per character. Cutting by `char` count would
    // overflow the line; cutting by display width does not.
    let mut app = App::default();
    let profile = EgressProfile::new(
        xraytui_domain::ProfileId::from_text("wide"),
        "日本語のプロファイル名がとても長い場合",
        Target::Direct,
    );
    app.desired.profiles.insert(profile.id.clone(), profile);

    let lines = screen(&app, 40, 10);
    for line in &lines {
        let width: usize = line
            .chars()
            .map(|c| unicode_width::UnicodeWidthChar::width(c).unwrap_or(0))
            .sum();
        assert!(width <= 40, "line drew {width} columns: {line:?}");
    }
}

#[test]
fn padding_produces_exactly_the_requested_display_width() {
    use unicode_width::UnicodeWidthStr as _;
    for (text, width) in [("abc", 8), ("", 4), ("abcdefghij", 4), ("日本", 6)] {
        assert_eq!(pad(text, width).width(), width, "{text:?} at {width}");
    }
}

#[test]
fn truncation_never_exceeds_the_budget() {
    use unicode_width::UnicodeWidthStr as _;
    for width in 0u16..12 {
        assert!(truncate("日本語abc", width).width() <= usize::from(width));
    }
}

#[test]
fn a_health_state_gets_a_colour_and_an_unknown_one_is_muted() {
    assert_eq!(health_colour("up"), theme::GOOD);
    assert_eq!(health_colour("down"), theme::BAD);
    assert_eq!(health_colour("degraded"), theme::WARN);
    assert_eq!(health_colour("--"), theme::MUTED);
    assert_eq!(health_colour("something new"), theme::MUTED);
}

#[test]
fn a_centred_popup_never_leaves_the_screen() {
    let area = Rect {
        x: 0,
        y: 0,
        width: 20,
        height: 6,
    };
    let popup = centred(area, 80, 40);
    assert!(popup.x + popup.width <= area.width);
    assert!(popup.y + popup.height <= area.height);
}
