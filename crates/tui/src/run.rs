//! The loop that joins the state machine to a terminal and a socket.
//!
//! Deliberately thin, because it is the one part that cannot be tested without
//! both. Everything with a decision in it lives in [`crate::app`]; everything
//! with a character in it lives in [`crate::render`]. What is left here is
//! plumbing: read an event, hand it to the state machine, do what it asks, draw.
//!
//! # Two connections, not one
//!
//! A subscription occupies its client until it ends, so the interface opens a
//! second connection for the log stream. Without that, asking a question while
//! logs were arriving would deadlock — and logs arrive exactly when something is
//! going wrong, which is when the interface most needs to work.
//!
//! Keys are read on a dedicated thread rather than polled in the loop, so the
//! loop can wait on a keystroke and a log line at the same time and redraw for
//! whichever arrives.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use xraytui_domain::Target;
use xraytui_ipc::{Client, Request, Response, SubscriptionFilter};

use crate::app::{Action, App, Key};
use crate::terminal::{TerminalError, TerminalGuard};

/// How long the key thread waits before checking whether it should stop.
const POLL: Duration = Duration::from_millis(200);

/// How often the interface refreshes on its own.
///
/// A second is short enough that traffic counters look live and long enough that
/// an idle interface does not keep a laptop awake.
const TICK: Duration = Duration::from_secs(1);

/// Everything the runner can report.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The terminal could not be taken over or given back.
    #[error(transparent)]
    Terminal(#[from] TerminalError),
    /// The daemon could not be reached at all.
    #[error(
        "cannot reach the daemon at {socket}: {detail}. Start it with \
         `systemctl --user start xraytuid`, or run `xraytuid` in another terminal."
    )]
    NoDaemon {
        /// Where the client looked.
        socket: String,
        /// Why it failed.
        detail: String,
    },
    /// Reading events or drawing failed.
    #[error("terminal I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Run the interface until the user quits.
///
/// # Errors
/// See [`RunError`]. The terminal is restored before any of them is returned,
/// because the guard's `Drop` runs on the way out.
pub async fn run(socket: std::path::PathBuf) -> Result<(), RunError> {
    let mut client = Client::connect(&socket)
        .await
        .map_err(|error| RunError::NoDaemon {
            socket: socket.display().to_string(),
            detail: error.to_string(),
        })?;

    let mut app = App::default();
    refresh(&mut client, &mut app).await;
    app.status = "? for keys, q to quit".to_owned();

    let mut streamer = Client::connect(&socket).await.ok();
    let mut stream = match streamer.as_mut() {
        Some(streamer) => streamer.subscribe(SubscriptionFilter::default()).await.ok(),
        None => None,
    };
    if stream.is_none() {
        app.push_log("(log stream unavailable; the daemon may be busy)");
    }

    let guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    terminal.clear()?;

    let running = Arc::new(AtomicBool::new(true));
    let (keys_tx, mut keys) = tokio::sync::mpsc::unbounded_channel();
    let reader = std::thread::spawn({
        let running = Arc::clone(&running);
        move || read_keys(&running, &keys_tx)
    });

    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let outcome = loop {
        if let Err(error) = terminal.draw(|frame| crate::render::draw(frame, &app)) {
            break Err(RunError::Io(error));
        }

        let action = tokio::select! {
            key = keys.recv() => match key {
                Some(key) => app.on_key(key),
                // The reader thread ended, which only happens when the terminal
                // went away. Leaving is the only sensible response.
                None => Action::Quit,
            },
            event = next_event(stream.as_mut()) => {
                if let Some(event) = event {
                    record(&mut app, event);
                }
                Action::None
            }
            _ = ticker.tick() => Action::Refresh,
        };

        match action {
            Action::None => {}
            Action::Quit => break Ok(()),
            Action::Refresh => refresh(&mut client, &mut app).await,
            Action::CycleMode => {
                perform(&mut client, &mut app, Request::CycleMode, "mode changed").await;
            }
            Action::Up => perform(&mut client, &mut app, Request::Up, "core started").await,
            Action::Down => perform(&mut client, &mut app, Request::Down, "core stopped").await,
            Action::SetTarget { profile, target } => {
                let request = set_target_request(&profile, target);
                perform(&mut client, &mut app, request, "target set").await;
            }
            Action::TestNode { node } => {
                let request = Request::Test(xraytui_ipc::TestTarget::Node(
                    xraytui_domain::NodeId::from_text(&node),
                ));
                perform(&mut client, &mut app, request, "probe finished").await;
            }
            Action::Notice(message) => app.status = message,
        }
    };

    running.store(false, Ordering::Relaxed);
    // Dropping the guard restores the terminal; joining the reader first keeps
    // it from reading a keystroke after the terminal has been handed back.
    let _ = reader.join();
    drop(guard);
    outcome
}

/// Wait for the next event, or never when there is no stream.
///
/// `select!` needs every branch to be a future; a missing subscription becomes a
/// future that never completes rather than a special case in the loop.
async fn next_event(
    stream: Option<&mut xraytui_ipc::client::EventStream<'_>>,
) -> Option<xraytui_ipc::Event> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

fn record(app: &mut App, event: xraytui_ipc::Event) {
    match event {
        xraytui_ipc::Event::Log {
            level,
            target,
            message,
            ..
        } => app.push_log(format!("{level:>5} {target}: {message}")),
        xraytui_ipc::Event::Lagged { dropped } => {
            app.push_log(format!("(missed {dropped} log lines)"));
        }
        xraytui_ipc::Event::State(runtime) => app.runtime = *runtime,
        other => app.push_log(format!("{other:?}")),
    }
}

/// Read keys until asked to stop.
///
/// Runs on its own thread because crossterm's `poll` blocks, and a blocking read
/// inside the async loop would stop log lines from being drawn.
fn read_keys(running: &AtomicBool, sender: &tokio::sync::mpsc::UnboundedSender<Key>) {
    while running.load(Ordering::Relaxed) {
        match crossterm::event::poll(POLL) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(_) => return,
        }
        match crossterm::event::read() {
            // Key *releases* are reported by some terminals; acting on them
            // would make every keystroke happen twice.
            Ok(Event::Key(KeyEvent {
                kind: KeyEventKind::Release,
                ..
            })) => {}
            Ok(Event::Key(event)) => {
                if sender.send(translate(event)).is_err() {
                    return;
                }
            }
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

fn set_target_request(profile: &str, target: Target) -> Request {
    Request::SetProfileTarget {
        profile: xraytui_domain::ProfileId::from_text(profile),
        target,
    }
}

async fn refresh(client: &mut Client, app: &mut App) {
    match client.request(Request::GetState).await {
        Ok(Response::State { desired, runtime }) => app.update(*desired, *runtime),
        Ok(_) => app.status = "the daemon answered with something unexpected".to_owned(),
        Err(error) => {
            // Keep showing the last known state and say it is stale, rather than
            // blanking the screen: a daemon restart should not lose the user's
            // place.
            app.connected = false;
            app.status = format!("daemon unreachable: {error}");
        }
    }
}

async fn perform(client: &mut Client, app: &mut App, request: Request, success: &str) {
    match client.request(request).await {
        Ok(_) => {
            app.status = success.to_owned();
            refresh(client, app).await;
        }
        Err(error) => app.status = format!("refused: {error}"),
    }
}

/// Map a crossterm key to the backend-independent one the state machine uses.
#[must_use]
pub fn translate(event: KeyEvent) -> Key {
    // Ctrl-C is the terminal's quit convention and must work even though `q`
    // also does, because that is what people's fingers do.
    if event.modifiers.contains(KeyModifiers::CONTROL) && matches!(event.code, KeyCode::Char('c')) {
        return Key::Char('q');
    }
    match event.code {
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Escape,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        _ => Key::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_c_quits_like_q() {
        let event = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(translate(event), Key::Char('q'));
    }

    #[test]
    fn a_plain_c_is_not_a_quit() {
        let event = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(translate(event), Key::Char('c'));
    }

    #[test]
    fn every_navigation_key_maps_to_something_the_state_machine_knows() {
        let cases = [
            (KeyCode::Enter, Key::Enter),
            (KeyCode::Esc, Key::Escape),
            (KeyCode::Tab, Key::Tab),
            (KeyCode::BackTab, Key::BackTab),
            (KeyCode::Backspace, Key::Backspace),
            (KeyCode::Up, Key::Up),
            (KeyCode::Down, Key::Down),
            (KeyCode::PageUp, Key::PageUp),
            (KeyCode::PageDown, Key::PageDown),
            (KeyCode::Home, Key::Home),
            (KeyCode::End, Key::End),
            (KeyCode::F(5), Key::Other),
        ];
        for (code, expected) in cases {
            assert_eq!(
                translate(KeyEvent::new(code, KeyModifiers::NONE)),
                expected,
                "{code:?}"
            );
        }
    }

    #[test]
    fn a_target_request_names_the_profile_it_was_given() {
        match set_target_request("web", Target::Direct) {
            Request::SetProfileTarget { profile, target } => {
                assert_eq!(profile.as_str(), "web");
                assert_eq!(target, Target::Direct);
            }
            other => panic!("unexpected request {other:?}"),
        }
    }

    #[test]
    fn a_lag_notice_reaches_the_log_pane_rather_than_being_dropped() {
        // Silently dropping "you missed some lines" is worse than the gap.
        let mut app = App::default();
        record(&mut app, xraytui_ipc::Event::Lagged { dropped: 12 });
        assert_eq!(app.logs.len(), 1);
        assert!(app.logs[0].contains("12"), "{:?}", app.logs);
    }

    #[test]
    fn a_log_event_keeps_its_level_and_source() {
        let mut app = App::default();
        record(
            &mut app,
            xraytui_ipc::Event::Log {
                at_unix_ms: 0,
                level: "info".to_owned(),
                target: "core".to_owned(),
                message: "started".to_owned(),
            },
        );
        assert_eq!(app.logs.len(), 1);
        assert!(app.logs[0].contains("info"), "{:?}", app.logs);
        assert!(app.logs[0].contains("core"), "{:?}", app.logs);
        assert!(app.logs[0].contains("started"), "{:?}", app.logs);
    }

    #[tokio::test]
    async fn a_missing_daemon_says_how_to_start_one() {
        let dir = tempfile::tempdir().expect("temp dir");
        let error = run(dir.path().join("absent.sock"))
            .await
            .expect_err("must fail");
        let text = error.to_string();
        assert!(text.contains("cannot reach the daemon"), "{text}");
        assert!(text.contains("xraytuid"), "{text}");
    }

    #[tokio::test]
    async fn a_stream_that_is_not_there_never_produces_an_event() {
        // The `select!` branch for logs must not fire when there is no
        // subscription; a future that completes immediately would spin the loop.
        let result = tokio::time::timeout(Duration::from_millis(50), next_event(None)).await;
        assert!(result.is_err(), "next_event(None) must never complete");
    }
}
