//! What this kernel and userland can actually do.
//!
//! The probe changes nothing. It exists so that `xraytui doctor` and
//! `xraytui-netd --check-capabilities` can tell a user *why* a mode is
//! unavailable instead of failing later with a syscall error, and so the daemon
//! can refuse a mode up front rather than starting a core that cannot work.

use xraytui_netd_protocol::NetdCapabilities;

use crate::cgroup::CgroupTree;
use crate::engine::EngineOptions;
use crate::{dns::DnsManager, tun};

/// `CAP_NET_ADMIN` is capability number 12.
const CAP_NET_ADMIN_BIT: u64 = 1 << 12;
/// `CAP_NET_BIND_SERVICE` is capability number 10.
const CAP_NET_BIND_SERVICE_BIT: u64 = 1 << 10;

/// Probe the system. Performs no change.
#[must_use]
pub fn probe(options: &EngineOptions) -> NetdCapabilities {
    let tree = CgroupTree::new(options.cgroup_root.clone());
    let cgroup_v2 = tree.is_usable();
    let dns = DnsManager::new(options.dbus_socket.clone(), options.resolvconf.clone());

    NetdCapabilities {
        tun: tun::device_usable(),
        cap_net_admin: has_net_admin(),
        ipv6_tun: ipv6_tun_available(),
        nftables: options.nft.available(),
        cgroup_v2,
        nft_cgroup_match: cgroup_v2 && options.nft.supports_cgroup_match(&own_cgroup()),
        systemd_resolved: dns.resolved_available(),
        resolvconf: dns.resolvconf_available(),
        kernel: kernel_release(),
    }
}

/// Whether a newly created TUN may be configured with an IPv6 address.
///
/// Linux keeps `/proc/net/if_inet6` present when IPv6 is disabled with sysctl,
/// so checking for that file alone is insufficient. New interfaces inherit
/// `conf/default/disable_ipv6`, while `conf/all/disable_ipv6` can disable the
/// namespace globally; both must permit IPv6.
#[must_use]
pub fn ipv6_tun_available() -> bool {
    ipv6_tun_available_under(std::path::Path::new("/proc"))
}

fn ipv6_tun_available_under(proc_root: &std::path::Path) -> bool {
    if !proc_root.join("net/if_inet6").exists() {
        return false;
    }
    ["all", "default"].iter().all(|scope| {
        std::fs::read_to_string(proc_root.join(format!("sys/net/ipv6/conf/{scope}/disable_ipv6")))
            .is_ok_and(|value| value.trim() == "0")
    })
}

/// Whether the current process holds `CAP_NET_ADMIN` in its effective set.
///
/// Read from `/proc/self/status` rather than by attempting a privileged
/// operation, because the point of the probe is to be side-effect free.
#[must_use]
pub fn has_net_admin() -> bool {
    has_effective_at(std::path::Path::new("/proc/self/status"), CAP_NET_ADMIN_BIT)
}

/// Whether the current process can bind a TCP/UDP port below 1024.
#[must_use]
pub fn has_net_bind_service() -> bool {
    has_effective_at(
        std::path::Path::new("/proc/self/status"),
        CAP_NET_BIND_SERVICE_BIT,
    )
}

/// Whether another live process actually holds `CAP_NET_ADMIN`.
#[must_use]
pub fn process_has_net_admin(pid: u32) -> bool {
    has_effective_at(
        &std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("status"),
        CAP_NET_ADMIN_BIT,
    )
}

/// Whether another live process can bind a TCP/UDP port below 1024.
#[must_use]
pub fn process_has_net_bind_service(pid: u32) -> bool {
    has_effective_at(
        &std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("status"),
        CAP_NET_BIND_SERVICE_BIT,
    )
}

fn has_effective_at(status_path: &std::path::Path, bit: u64) -> bool {
    let Ok(status) = std::fs::read_to_string(status_path) else {
        return false;
    };
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("CapEff:")
            && let Ok(mask) = u64::from_str_radix(value.trim(), 16)
        {
            return mask & bit != 0;
        }
    }
    false
}

/// The kernel release string, for diagnostics.
#[must_use]
pub fn kernel_release() -> String {
    rustix::system::uname()
        .release()
        .to_str()
        .unwrap_or("unknown")
        .to_owned()
}

/// This process's own cgroup v2 path, relative to the hierarchy root.
///
/// Used as a known-to-exist path for the `socket cgroupv2` probe: nftables
/// resolves the path to a cgroup id when the rule is parsed, so probing with a
/// path that does not exist would report "unsupported" on a system that
/// supports it perfectly well.
#[must_use]
pub fn own_cgroup() -> String {
    let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") else {
        return String::new();
    };
    for line in text.lines() {
        // The unified hierarchy is the entry with an empty controller list.
        if let Some(path) = line.strip_prefix("0::") {
            return path.trim().trim_start_matches('/').to_owned();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_release_is_not_empty() {
        let release = kernel_release();
        assert!(!release.is_empty());
        assert_ne!(release, "unknown");
    }

    #[test]
    fn the_capability_bit_is_the_documented_one() {
        // CAP_NET_ADMIN == 12, so the mask is 0x1000.
        assert_eq!(CAP_NET_ADMIN_BIT, 0x1000);
        // CAP_NET_BIND_SERVICE == 10, so the mask is 0x400.
        assert_eq!(CAP_NET_BIND_SERVICE_BIT, 0x400);
    }

    #[test]
    fn effective_capabilities_are_read_from_the_effective_not_permitted_set() {
        let directory = tempfile::tempdir().expect("status fixture");
        let status = directory.path().join("status");
        std::fs::write(
            &status,
            "CapPrm:\t0000000000001000\nCapEff:\t0000000000000400\n",
        )
        .expect("write status fixture");
        assert!(has_effective_at(&status, CAP_NET_BIND_SERVICE_BIT));
        assert!(!has_effective_at(&status, CAP_NET_ADMIN_BIT));
    }

    #[test]
    fn the_own_cgroup_path_is_root_relative_or_empty() {
        let path = own_cgroup();
        assert!(
            !path.starts_with('/'),
            "must be root-relative, got {path:?}"
        );
    }

    #[test]
    fn a_probe_reports_a_consistent_picture() {
        let options = EngineOptions::for_test();
        let report = probe(&options);
        // Whatever the host can do, the derived answers must not contradict the
        // primitives they are derived from.
        if report.supports_tun() {
            assert!(report.tun && report.cap_net_admin);
        }
        if report.supports_transparent_exec() {
            assert!(report.cgroup_v2 && report.nft_cgroup_match);
        }
        assert!(!report.kernel.is_empty());
    }

    #[test]
    fn ipv6_tun_detection_checks_both_namespace_switches() {
        let root = tempfile::tempdir().expect("temporary proc tree");
        for scope in ["all", "default"] {
            let directory = root.path().join(format!("sys/net/ipv6/conf/{scope}"));
            std::fs::create_dir_all(&directory).expect("sysctl directory");
            std::fs::write(directory.join("disable_ipv6"), "0\n").expect("sysctl fixture");
        }
        std::fs::create_dir_all(root.path().join("net")).expect("net fixture");
        std::fs::write(root.path().join("net/if_inet6"), "").expect("if_inet6 fixture");
        assert!(ipv6_tun_available_under(root.path()));

        std::fs::write(
            root.path().join("sys/net/ipv6/conf/default/disable_ipv6"),
            "1\n",
        )
        .expect("disable fixture");
        assert!(!ipv6_tun_available_under(root.path()));
    }
}
