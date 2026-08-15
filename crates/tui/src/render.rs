//! Turning [`App`] into cells.
//!
//! Pure: takes a state and a frame, writes characters. No I/O, no clock, no
//! randomness — so a test can render into a `TestBackend` of any size and assert
//! on the resulting buffer, which is what makes "usable at 80x24" a checkable
//! claim rather than an aspiration.
//!
//! # What happens when the terminal is small
//!
//! Nothing overlaps and nothing panics. Below the designed size, panes are
//! dropped in order of how much they can be done without: the footer first, then
//! the header detail, then the tab bar. The list always keeps at least one row.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, KEYS, Overlay, Row, View};

/// Colours, kept in one place and deliberately few.
///
/// Terminal users have their own palettes. Using the sixteen ANSI colours means
/// the interface matches whatever `st`, `alacritty` or `tmux` was configured
/// with, instead of fighting it with a hard-coded theme.
mod theme {
    use ratatui::style::Color;

    /// Selected row, active tab.
    pub const ACCENT: Color = Color::Cyan;
    /// Healthy.
    pub const GOOD: Color = Color::Green;
    /// Degraded.
    pub const WARN: Color = Color::Yellow;
    /// Failed.
    pub const BAD: Color = Color::Red;
    /// Secondary text.
    pub const MUTED: Color = Color::DarkGray;
}

/// Draw the whole interface.
pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    if area.width == 0 || area.height == 0 {
        return;
    }

    // Header and footer are one line each; the tab bar is one more. On a very
    // short terminal they are given up rather than squeezing the list to
    // nothing, because a list with no rows shows nothing at all.
    let show_footer = area.height >= 6;
    let show_tabs = area.height >= 5;
    let mut constraints = vec![Constraint::Length(1)];
    if show_tabs {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Min(1));
    if show_footer {
        constraints.push(Constraint::Length(1));
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut index = 0;
    draw_header(frame, chunks[index], app);
    index += 1;
    if show_tabs {
        draw_tabs(frame, chunks[index], app);
        index += 1;
    }
    draw_list(frame, chunks[index], app);
    index += 1;
    if show_footer {
        draw_footer(frame, chunks[index], app);
    }

    match &app.overlay {
        Overlay::None => {}
        Overlay::Help => draw_help(frame, area),
        Overlay::Filter { query } => draw_filter(frame, area, query),
        Overlay::TargetPicker {
            profile,
            candidates,
            selected,
        } => draw_picker(frame, area, profile, candidates, *selected),
        Overlay::Confirm { prompt, .. } => draw_confirm(frame, area, prompt),
        Overlay::Form(form) => draw_form(frame, area, form),
        Overlay::Qr { art, node } => draw_qr(frame, area, art, node),
    }
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let style = if app.connected {
        Style::default()
    } else {
        Style::default().fg(theme::BAD)
    };
    let text = truncate(&format!(" xraytui  {}", app.headline()), area.width);
    frame.render_widget(Paragraph::new(Line::from(Span::styled(text, style))), area);
}

fn draw_tabs(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut spans = Vec::new();
    for view in View::ALL {
        let active = view == app.view;
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::MUTED)
        };
        spans.push(Span::styled(
            format!(" {}:{} ", view.digit(), view.title()),
            style,
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_list(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.rows();
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme::MUTED));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if rows.is_empty() {
        let message = if app.active_filter().is_empty() {
            format!("nothing in {}", app.view.title().to_lowercase())
        } else {
            format!("nothing matches {:?}", app.active_filter())
        };
        frame.render_widget(
            Paragraph::new(Span::styled(message, Style::default().fg(theme::MUTED))),
            inner,
        );
        return;
    }

    let items: Vec<ListItem<'_>> = rows
        .iter()
        .map(|row| ListItem::new(Line::from(columns(row, inner.width, app.view))))
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.cursor.min(rows.len().saturating_sub(1))));
    frame.render_stateful_widget(
        List::new(items).highlight_style(
            Style::default()
                .bg(theme::ACCENT)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        inner,
        &mut state,
    );
}

/// Lay a row out in columns that fit the available width.
///
/// The width budget is spent left to right on the columns that carry the most
/// information: identity, then what it points at, then detail, then health. A
/// narrow terminal loses the rightmost columns rather than wrapping.
fn columns(row: &Row, width: u16, view: View) -> Vec<Span<'static>> {
    if view == View::Logs {
        return vec![Span::raw(truncate(&row.primary, width))];
    }

    let width = usize::from(width);
    let state_width = 6usize.min(width / 6);
    let detail_width = 18usize.min(width / 4);
    let secondary_width = 24usize.min(width / 3);
    let primary_width = width
        .saturating_sub(state_width + detail_width + secondary_width + 3)
        .max(4);

    let mut spans = vec![Span::raw(pad(&row.primary, primary_width))];
    if secondary_width > 0 {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            pad(&row.secondary, secondary_width),
            Style::default().fg(theme::ACCENT),
        ));
    }
    if detail_width > 0 {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            pad(&row.detail, detail_width),
            Style::default().fg(theme::MUTED),
        ));
    }
    if state_width > 0 {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            pad(&row.state, state_width),
            Style::default().fg(health_colour(&row.state)),
        ));
    }
    spans
}

fn health_colour(state: &str) -> Color {
    match state {
        "up" | "ok" | "healthy" | "on" => theme::GOOD,
        "degraded" | "slow" | "unknown" => theme::WARN,
        "down" | "failed" | "off" => theme::BAD,
        _ => theme::MUTED,
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let hint = if app.status.is_empty() {
        "? keys   / filter   Enter target   m mode   r refresh   q quit".to_owned()
    } else {
        app.status.clone()
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            truncate(&format!(" {hint}"), area.width),
            Style::default().fg(theme::MUTED),
        )),
        area,
    );
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    // Two columns. The key list outgrew a single column the moment editing
    // arrived, and a help overlay that silently drops the half of the keys it
    // cannot fit is worse than no help overlay: the user concludes the feature
    // does not exist.
    let rows = KEYS.len().div_ceil(2);
    let popup = centred(area, 76, (rows as u16 + 2).min(area.height));
    frame.render_widget(Clear, popup);

    let inner_width = popup.width.saturating_sub(2) as usize;
    let column = inner_width / 2;
    let mut lines: Vec<Line<'_>> = Vec::new();
    for index in 0..rows {
        let mut text = String::new();
        for offset in [0, rows] {
            if let Some((key, description)) = KEYS.get(index + offset) {
                let cell = format!("{key:<16} {description}");
                let cell: String = cell.chars().take(column.saturating_sub(1)).collect();
                text.push_str(&format!("{cell:<width$}", width = column));
            }
        }
        lines.push(Line::from(text.trim_end().to_owned()));
    }

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" keys — any key closes ")
                .border_style(Style::default().fg(theme::ACCENT)),
        ),
        popup,
    );
}

fn draw_filter(frame: &mut Frame<'_>, area: Rect, query: &str) {
    let popup = centred(area, 48, 3);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(query.to_owned()),
            Span::styled("_", Style::default().fg(theme::ACCENT)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" filter — Enter applies, Esc cancels ")
                .border_style(Style::default().fg(theme::ACCENT)),
        ),
        popup,
    );
}

fn draw_picker(
    frame: &mut Frame<'_>,
    area: Rect,
    profile: &str,
    candidates: &[xraytui_domain::Target],
    selected: usize,
) {
    let items: Vec<ListItem<'_>> = candidates
        .iter()
        .map(|target| ListItem::new(target.to_token()))
        .collect();
    let height = u16::try_from(items.len().clamp(1, 12) + 2).unwrap_or(14);
    let popup = centred(area, 48, height);
    frame.render_widget(Clear, popup);

    let mut state = ListState::default();
    state.select(Some(selected.min(candidates.len().saturating_sub(1))));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" point {profile} at — Enter selects, Esc cancels "))
                    .border_style(Style::default().fg(theme::ACCENT)),
            )
            .highlight_style(
                Style::default()
                    .bg(theme::ACCENT)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            ),
        popup,
        &mut state,
    );
}

fn draw_confirm(frame: &mut Frame<'_>, area: Rect, prompt: &str) {
    let popup = centred(area, 52, 4);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(prompt.to_owned()),
            Line::from(Span::styled("y / n", Style::default().fg(theme::ACCENT))),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" confirm ")
                .border_style(Style::default().fg(theme::WARN)),
        )
        .wrap(Wrap { trim: true }),
        popup,
    );
}

/// An editing form.
///
/// Sized to fit whatever terminal it is given: at 80x24 a fifteen-field node
/// form does not fit at once, so the list scrolls around the focused line
/// rather than being clipped at the bottom, which would hide the field the
/// person is typing into.
fn draw_form(frame: &mut Frame<'_>, area: Rect, form: &crate::edit::Form) {
    let popup = centred(area, 66, area.height.saturating_sub(2).min(20));
    frame.render_widget(Clear, popup);

    let body_height = popup.height.saturating_sub(4) as usize;
    let first = form.cursor.saturating_sub(body_height.saturating_sub(1));
    let mut lines: Vec<Line<'_>> = Vec::new();
    for (index, field) in form.fields.iter().enumerate().skip(first).take(body_height) {
        let focused = index == form.cursor;
        let shown = if field.secret && !field.value.is_empty() {
            // Never render a credential, even to the person who typed it: a
            // terminal is often on a screen somebody else can see.
            "•".repeat(field.value.chars().count().min(24))
        } else {
            field.value.clone()
        };
        let marker = if focused { "▸" } else { " " };
        let style = if focused {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{marker} {:<14}", field.label), style),
            Span::raw(truncate(&shown, popup.width.saturating_sub(20))),
        ]));
    }

    let hint = form
        .fields
        .get(form.cursor)
        .map(|field| field.help.clone())
        .unwrap_or_default();
    lines.push(Line::from(Span::styled(
        format!("  {hint}"),
        Style::default().fg(theme::MUTED),
    )));
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("  {error}"),
            Style::default().fg(theme::BAD),
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} — enter next, esc cancel ", form.title))
                    .border_style(Style::default().fg(theme::ACCENT)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// A QR code, with the warning that it is a credential.
fn draw_qr(frame: &mut Frame<'_>, area: Rect, art: &str, node: &str) {
    let width = art.lines().map(str::len).max().unwrap_or(0) as u16 + 4;
    let height = art.lines().count() as u16 + 4;
    let popup = centred(area, width.min(area.width), height.min(area.height));
    frame.render_widget(Clear, popup);
    let mut lines: Vec<Line<'_>> = art
        .lines()
        .map(|line| Line::from(line.to_owned()))
        .collect();
    lines.push(Line::from(Span::styled(
        "this code is the credential — anyone who scans it can use the server",
        Style::default().fg(theme::WARN),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {node} — any key closes "))
                .border_style(Style::default().fg(theme::WARN)),
        ),
        popup,
    );
}

/// A centred rectangle that never leaves the screen, whatever the size asked
/// for.
fn centred(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

/// Cut a string to a display width, counting what a terminal actually draws.
fn truncate(text: &str, width: u16) -> String {
    use unicode_width::UnicodeWidthChar as _;
    let limit = usize::from(width);
    let mut out = String::new();
    let mut used = 0usize;
    for c in text.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > limit {
            break;
        }
        out.push(c);
        used += w;
    }
    out
}

/// Cut or pad to exactly `width` display columns.
fn pad(text: &str, width: usize) -> String {
    use unicode_width::UnicodeWidthStr as _;
    let mut out = truncate(text, u16::try_from(width).unwrap_or(u16::MAX));
    let used = out.width();
    if used < width {
        out.push_str(&" ".repeat(width - used));
    }
    out
}

#[cfg(test)]
mod tests;
