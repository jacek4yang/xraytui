//! Owning the terminal, and giving it back.
//!
//! # The requirement this module exists for
//!
//! Acceptance scenario L asks that the terminal be left usable — cooked mode,
//! main screen, cursor visible — **however the program ends**: a clean quit, an
//! error, a panic, or a signal. A proxy tool that leaves someone with an
//! invisible cursor and no line editing has failed at something more basic than
//! proxying.
//!
//! Three mechanisms cover the three ways out:
//!
//! * `Drop` on [`TerminalGuard`] covers a normal return and an error return;
//! * a panic hook installed by [`TerminalGuard::enter`] covers a panic, and runs
//!   *before* the default hook so the backtrace is printed to a terminal that is
//!   already cooked and readable;
//! * `SIGINT` and `SIGTERM` are turned into ordinary quit events by the runner,
//!   so they take the `Drop` path rather than killing the process outright.
//!
//! The restore sequence is written by [`restore_into`], which takes a writer, so
//! a test can assert exactly what would be sent without needing a terminal.

use std::io::Write;

use crossterm::ExecutableCommand as _;
use crossterm::cursor::Show;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

/// The smallest terminal the interface is designed for.
///
/// 80x24 is the size the specification names, and the size an `st` window opens
/// at. Below it the layout still draws, but panes are dropped rather than
/// overlapping; see [`crate::render`].
pub const MINIMUM_WIDTH: u16 = 80;
/// Minimum rows, as above.
pub const MINIMUM_HEIGHT: u16 = 24;

/// Errors setting up or tearing down the terminal.
#[derive(Debug, thiserror::Error)]
pub enum TerminalError {
    /// The terminal could not be put into raw mode or the alternate screen.
    #[error("cannot take over the terminal: {0}")]
    Enter(#[source] std::io::Error),
    /// Drawing failed.
    #[error("cannot draw: {0}")]
    Draw(#[source] std::io::Error),
}

/// Holds the terminal's altered state and restores it on drop.
#[derive(Debug)]
pub struct TerminalGuard {
    restored: bool,
}

impl TerminalGuard {
    /// Take over the terminal and arrange for it to be given back.
    ///
    /// # Errors
    /// [`TerminalError::Enter`] if raw mode or the alternate screen is refused,
    /// which is normal when standard output is not a terminal.
    pub fn enter() -> Result<Self, TerminalError> {
        enable_raw_mode().map_err(TerminalError::Enter)?;
        let mut out = std::io::stdout();
        out.execute(EnterAlternateScreen)
            .map_err(TerminalError::Enter)?;
        out.execute(EnableMouseCapture)
            .map_err(TerminalError::Enter)?;

        // Chain rather than replace: the default hook prints the panic message
        // and backtrace, and it should print them to a terminal that is already
        // back in cooked mode.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = restore_into(&mut std::io::stdout());
            let _ = disable_raw_mode();
            previous(info);
        }));

        Ok(Self { restored: false })
    }

    /// Give the terminal back now, rather than at the end of the scope.
    ///
    /// # Errors
    /// [`TerminalError::Draw`] if the escape sequences cannot be written.
    pub fn restore(&mut self) -> Result<(), TerminalError> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        restore_into(&mut std::io::stdout()).map_err(TerminalError::Draw)?;
        disable_raw_mode().map_err(TerminalError::Draw)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // A failure here cannot be reported anywhere useful — the terminal is
        // the thing that is broken — so it is deliberately ignored.
        let _ = self.restore();
    }
}

/// Write the sequences that put a terminal back the way it was.
///
/// Order matters: leave the alternate screen last, so anything the application
/// printed on its way out lands on the alternate screen and disappears with it
/// rather than on the user's scrollback.
///
/// # Errors
/// Propagates write failures.
pub fn restore_into(out: &mut impl Write) -> std::io::Result<()> {
    out.execute(DisableMouseCapture)?;
    out.execute(Show)?;
    out.execute(LeaveAlternateScreen)?;
    out.flush()
}

/// Whether a terminal of this size can show the interface as designed.
#[must_use]
pub fn is_large_enough(width: u16, height: u16) -> bool {
    width >= MINIMUM_WIDTH && height >= MINIMUM_HEIGHT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_restore_sequence_leaves_the_alternate_screen_last() {
        let mut buffer = Vec::new();
        restore_into(&mut buffer).expect("write");
        let text = String::from_utf8_lossy(&buffer);

        // Cursor visible: DECTCEM set.
        assert!(
            text.contains("\u{1b}[?25h"),
            "cursor was not shown: {text:?}"
        );
        // Alternate screen off: 1049 reset.
        let leave = text
            .find("\u{1b}[?1049l")
            .expect("the alternate screen must be left");
        let show = text.find("\u{1b}[?25h").expect("the cursor must be shown");
        assert!(
            show < leave,
            "showing the cursor must happen on the alternate screen, before leaving it"
        );
        // Mouse reporting off.
        assert!(
            text.contains("\u{1b}[?1000l") || text.contains("\u{1b}[?1003l"),
            "{text:?}"
        );
    }

    #[test]
    fn restoring_twice_writes_the_sequence_twice_and_does_not_fail() {
        let mut first = Vec::new();
        let mut second = Vec::new();
        restore_into(&mut first).expect("write");
        restore_into(&mut second).expect("write");
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[test]
    fn the_minimum_size_is_the_one_the_specification_names() {
        assert_eq!((MINIMUM_WIDTH, MINIMUM_HEIGHT), (80, 24));
        assert!(is_large_enough(80, 24));
        assert!(is_large_enough(200, 60));
        assert!(!is_large_enough(79, 24));
        assert!(!is_large_enough(80, 23));
    }

    #[test]
    fn a_guard_that_never_entered_still_restores_without_panicking() {
        // `enter` fails when stdout is not a terminal, which is exactly the case
        // under `cargo test`. What matters is that the failure is reported and
        // nothing is left half-done.
        match TerminalGuard::enter() {
            Ok(mut guard) => {
                guard.restore().expect("restore");
                // Restoring again is a no-op, not an error.
                guard.restore().expect("restore again");
            }
            Err(error) => {
                assert!(matches!(error, TerminalError::Enter(_)), "{error}");
            }
        }
    }
}
