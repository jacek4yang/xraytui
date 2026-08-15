//! The DNS path against a real `org.freedesktop.resolve1`.
//!
//! Everything else about DNS is unit-tested — the D-Bus encoding byte for byte,
//! the argument shapes, the "absent is success" behaviour of `RevertLink`. What
//! no unit test can establish is whether `systemd-resolved` accepts the message
//! this project sends it, and whether reverting really gives the link back.
//! That needs a running `systemd-resolved`, which the container this project is
//! developed in does not have: PID 1 is not systemd and there is no
//! `/run/dbus/system_bus_socket`.
//!
//! So the harness lives here, guarded, ready to run on a machine that has one.
//!
//! # Why it does not run by default
//!
//! `systemd-resolved` is a *host* service. It is not namespaced, so a link
//! created inside a disposable network namespace is invisible to it, and the
//! only way to talk to a real resolved is to talk to the real one on the
//! machine running the test. That is a change to the host, which this project's
//! testing rules forbid by default.
//!
//! The compromise, which is why the opt-in exists:
//!
//! * the test creates its own TUN device, and touches no other link;
//! * it sets DNS only on that link's index, never a global setting;
//! * it reverts, and then checks the link no longer carries the servers;
//! * the device is removed, which removes the link from resolved regardless;
//! * and none of it happens unless `XRAYTUI_TEST_RESOLVED=1` is set by hand.
//!
//! Run it, on a systemd machine you own, with:
//!
//! ```sh
//! sudo XRAYTUI_TEST_RESOLVED=1 cargo test -p xraytui-linux-net --test resolved
//! ```
//!
//! Anywhere else it prints why it skipped and passes, so a release gate can
//! tell "not run here" from "ran and failed" — `STATUS.md` records it as
//! unexecuted rather than as passing.

use std::net::{IpAddr, Ipv4Addr};

use xraytui_linux_net::dns::DnsManager;
use xraytui_netd_protocol::{DnsBackend, DnsRequest};

/// The device this test creates. Distinct from the one the daemon uses, so a
/// mistake here cannot disturb a real tunnel on the same machine.
const TEST_INTERFACE: &str = "xraytui-t0";

fn skip(reason: &str) {
    eprintln!("SKIPPED resolved: {reason}");
}

#[test]
fn systemd_resolved_accepts_what_this_project_sends_it() {
    if std::env::var_os("XRAYTUI_TEST_RESOLVED").is_none_or(|value| value != "1") {
        skip(
            "set XRAYTUI_TEST_RESOLVED=1 to run this; it talks to the machine's own \
             systemd-resolved, on a link it creates and then removes",
        );
        return;
    }

    let manager = DnsManager::new(
        xraytui_linux_net::dbus::SYSTEM_BUS_PATH,
        std::path::PathBuf::from("resolvconf"),
    );
    if !manager.resolved_available() {
        skip("no reachable org.freedesktop.resolve1 on the system bus");
        return;
    }
    if !rustix::process::getuid().is_root() {
        skip("creating a TUN device needs root");
        return;
    }

    let device = Tun::create(TEST_INTERFACE).expect("create the test TUN device");

    let request = DnsRequest {
        backend: DnsBackend::SystemdResolved,
        // RFC 5737 TEST-NET-1: routable nowhere, so a query that somehow
        // escaped this link would fail rather than leak.
        servers: vec![
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54)),
        ],
        domains: vec!["~.".to_owned(), "example.invalid".to_owned()],
    };

    manager
        .apply(TEST_INTERFACE, device.index, &request)
        .expect("resolved must accept SetLinkDNS and SetLinkDomains for our own link");

    // resolved's own account of the link, rather than this project's.
    let reported = resolvectl_status(TEST_INTERFACE);
    assert!(
        reported.contains("192.0.2.53"),
        "resolved does not report the server that was just set:\n{reported}"
    );

    manager
        .revert(TEST_INTERFACE, device.index, DnsBackend::SystemdResolved)
        .expect("revert must succeed");

    let after = resolvectl_status(TEST_INTERFACE);
    assert!(
        !after.contains("192.0.2.53"),
        "the link kept its resolvers after a revert:\n{after}"
    );

    // Reverting twice must also be fine: recovery paths call it on a link that
    // may already have been forgotten.
    manager
        .revert(TEST_INTERFACE, device.index, DnsBackend::SystemdResolved)
        .expect("a second revert must be a no-op, not an error");

    drop(device);
}

/// Ask resolved, through its own command line, what it thinks the link has.
///
/// `resolvectl` is the wrong tool for *setting* anything — its output is not a
/// stable interface, which is why this project speaks D-Bus — but as an
/// independent second opinion in a test it is exactly right: it is not the code
/// under test.
fn resolvectl_status(interface: &str) -> String {
    match std::process::Command::new("resolvectl")
        .args(["status", interface])
        .output()
    {
        Ok(output) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text
        }
        Err(error) => format!("resolvectl could not be run: {error}"),
    }
}

/// A TUN device that removes itself.
struct Tun {
    index: u32,
    _handle: std::os::fd::OwnedFd,
}

impl Tun {
    fn create(name: &str) -> Result<Self, String> {
        let netlink = xraytui_linux_net::netlink::Netlink::open().map_err(|e| e.to_string())?;
        // A device left by an interrupted run is cleared first, so a rerun does
        // not adopt a link whose state nobody knows.
        if let Ok(stale) = netlink.link_index(name) {
            let _ = netlink.link_delete(stale);
        }
        let device = xraytui_linux_net::tun::create(name, rustix::process::getuid().as_raw())
            .map_err(|e| e.to_string())?;
        let index = netlink.link_index(name).map_err(|e| e.to_string())?;
        Ok(Self {
            index,
            _handle: device.handle,
        })
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        if let Ok(netlink) = xraytui_linux_net::netlink::Netlink::open() {
            let _ = netlink.link_delete(self.index);
        }
    }
}
