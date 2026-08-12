//! The three lines of `sd_notify` this service needs.
//!
//! The unit is `Type=notify`, so systemd waits for `READY=1` before considering
//! the helper started and before letting `xraytuid` instances depend on it.
//! Linking libsystemd for one datagram would add a C dependency to the only
//! privileged binary in the project; writing the datagram directly does not.
//!
//! Everything here is a no-op when `NOTIFY_SOCKET` is unset, which is the case
//! when the helper is run by hand or under the test suite.

use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::net::UnixDatagram;

/// Tell the service manager the helper is ready to accept connections.
pub fn ready(status: &str) {
    send(&format!("READY=1\nSTATUS={status}\n"));
}

/// Update the one-line status systemd shows in `systemctl status`.
pub fn status(status: &str) {
    send(&format!("STATUS={status}\n"));
}

/// Tell the service manager the helper is shutting down on purpose.
pub fn stopping() {
    send("STOPPING=1\n");
}

fn send(payload: &str) {
    let Some(address) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if let Err(error) = send_to(&address, payload) {
        // A service manager that is not listening is not a reason to fail.
        tracing::debug!(%error, "could not notify the service manager");
    }
}

/// Send one datagram to an explicit address.
///
/// Split out from [`send`] so it can be tested without mutating the process
/// environment, which is shared by every test in the binary.
fn send_to(address: &OsStr, payload: &str) -> std::io::Result<usize> {
    let socket = UnixDatagram::unbound()?;
    // An address beginning with `@` names the abstract namespace.
    if let Some(name) = address.to_str().and_then(|text| text.strip_prefix('@')) {
        let target = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        return socket.send_to_addr(payload.as_bytes(), &target);
    }
    socket.send_to(payload.as_bytes(), std::path::Path::new(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_are_silent_when_there_is_no_service_manager() {
        // The absence of NOTIFY_SOCKET is the normal case outside systemd; the
        // point is that it is not an error path.
        send("READY=1\n");
        ready("test");
        status("test");
        stopping();
    }

    #[test]
    fn a_datagram_reaches_a_listening_service_manager() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&path).expect("bind");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");

        send_to(path.as_os_str(), "READY=1\nSTATUS=serving\n").expect("send");

        let mut buffer = [0u8; 128];
        let read = listener.recv(&mut buffer).expect("receive");
        let text = String::from_utf8_lossy(&buffer[..read]).into_owned();
        assert!(text.contains("READY=1"), "{text}");
        assert!(text.contains("STATUS=serving"), "{text}");
    }

    #[test]
    fn an_address_nobody_is_listening_on_is_an_ordinary_error() {
        let error = send_to(OsStr::new("/nonexistent/notify.sock"), "READY=1\n");
        assert!(error.is_err());
    }
}
