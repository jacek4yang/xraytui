//! Fetching a subscription, understanding it, and applying it transactionally.
//!
//! # The property that matters
//!
//! A subscription update either happens completely or not at all. A provider
//! that returns a truncated body, a proxy that mangles it, or a filter that
//! matches nothing must never leave a user with half their nodes gone and their
//! profiles pointing at identifiers that no longer exist.
//!
//! That is why the shape here is *fetch, understand, diff, apply* rather than
//! *fetch and write*:
//!
//! | Stage | Module | Can it change anything? |
//! |---|---|---|
//! | fetch | [`mod@fetch`] | no — bytes in, text out |
//! | understand | [`mod@normalise`] | no — text in, nodes out |
//! | diff | [`diff`] | no — nodes and current state in, a description out |
//! | apply | [`mod@apply`] | yes, and only this one |
//!
//! Everything before the last stage is pure, so `xraytui subscription diff`
//! shows exactly what `xraytui subscription update` would do, computed by the
//! same code.
//!
//! # A subscription is data, never code
//!
//! Nothing in a body is executed, resolved as a path, or passed to a shell. The
//! parser treats every line as untrusted text and files it into "understood",
//! "recognised but not compilable" or "rejected".

#![forbid(unsafe_code)]
// Production paths must not panic; test modules are exempt so assertions stay
// readable.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(missing_docs)]

pub mod apply;
pub mod diff;
pub mod fetch;
pub mod normalise;

pub use apply::{ApplyError, ApplyOutcome, apply};
pub use diff::compute;
pub use fetch::{FetchError, FetchOptions, Fetched, fetch};
pub use normalise::{NormaliseError, Normalised, normalise};
