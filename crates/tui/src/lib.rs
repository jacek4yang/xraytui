//! The keyboard-first terminal interface.
//!
//! # Shape
//!
//! Three modules, split so that the two interesting ones can be tested without a
//! terminal or a daemon:
//!
//! | Module | Responsibility | Tested by |
//! |---|---|---|
//! | [`app`] | keys in, [`app::Action`] out; no I/O at all | pressing keys and asserting |
//! | [`render`] | state in, cells out; no I/O at all | rendering into a `TestBackend` |
//! | [`terminal`] | taking the terminal over and giving it back | asserting the escape sequences |
//! | [`mod@run`] | the loop that joins them to a socket | the end-to-end suite |
//!
//! # What it is for
//!
//! The specification names dwm, `st` and `tmux` users. That shapes three
//! decisions: every action has a key and none requires a mouse; the sixteen ANSI
//! colours are used so the interface inherits the terminal's palette instead of
//! fighting it; and the layout is designed for 80x24 and degrades by dropping
//! panes rather than by wrapping.
//!
//! Nothing here is authoritative. The daemon holds the state; this is a view of
//! it and a way to ask for changes, and it stays usable — showing the last state
//! it had, and saying so — when the daemon is not there.

#![forbid(unsafe_code)]
// Production paths must not panic; test modules are exempt so assertions stay
// readable.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(missing_docs)]

pub mod app;
pub mod edit;
pub mod render;
pub mod run;
pub mod terminal;

pub use app::{Action, App, Key, Overlay, Row, View};
pub use render::draw;
pub use run::{RunError, run};
pub use terminal::{MINIMUM_HEIGHT, MINIMUM_WIDTH, TerminalGuard, is_large_enough};
