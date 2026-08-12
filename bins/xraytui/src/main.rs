//! `xraytui` — the terminal client.
//!
//! Unprivileged, and deliberately incapable of touching the network directly:
//! everything it does goes through `xraytuid` over the control socket.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let code = xraytui_cli::main();
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
