//! Persistent TUN device creation.
//!
//! # The only `unsafe` in the project
//!
//! Every other crate carries `#![forbid(unsafe_code)]`. This module cannot:
//! creating a TUN device is three `ioctl` calls on `/dev/net/tun` and Linux
//! offers no other interface for it — `RTM_NEWLINK` can delete a tun device but
//! cannot create one with an owner. The unsafe surface is deliberately tiny:
//! one `#[repr(C)]` struct, one helper that calls `libc::ioctl`, and three
//! call sites. Everything else in the module is safe code.
//!
//! # Why the device is persistent rather than an inherited descriptor
//!
//! Upstream's Linux TUN implementation opens `/dev/net/tun` itself; the
//! `xray.tun.fd` escape hatch that would let it adopt an inherited descriptor is
//! compiled for Android and Darwin only. So the helper creates the device with
//! `TUNSETPERSIST`, hands ownership to the calling user with `TUNSETOWNER`, and
//! lets the unprivileged core open it by name. See `DECISIONS.md` D-008.
//!
//! The descriptor the helper keeps is a **liveness handle**, not a data path: it
//! is returned to the daemon over `SCM_RIGHTS` so that a daemon crash closes it,
//! and it is never read from or written to.

#![allow(
    unsafe_code,
    reason = "TUNSETIFF/TUNSETOWNER/TUNSETPERSIST have no safe wrapper; the \
              surface is confined to `ioctl_int` and the three calls below"
)]

use std::ffi::c_int;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

/// The character device that creates tun and tap interfaces.
pub const TUN_DEVICE: &str = "/dev/net/tun";

/// Longest interface name the kernel accepts, including the terminator.
const IFNAMSIZ: usize = 16;

/// Everything TUN creation can report.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// `/dev/net/tun` is missing or cannot be opened.
    #[error("cannot open {TUN_DEVICE}: {0}; the tun module may not be loaded")]
    Device(#[source] std::io::Error),
    /// The name does not fit `IFNAMSIZ`.
    #[error("interface name {0:?} does not fit in {IFNAMSIZ} bytes")]
    NameTooLong(String),
    /// The name contains a NUL, which would truncate it in the kernel.
    #[error("interface name {0:?} contains an interior NUL")]
    NameHasNul(String),
    /// An ioctl failed.
    #[error("{operation} failed for {interface}: {source}")]
    Ioctl {
        /// Which ioctl.
        operation: &'static str,
        /// Which interface.
        interface: String,
        /// Underlying errno.
        #[source]
        source: std::io::Error,
    },
    /// A device of that name exists and is not a tun the helper can adopt.
    #[error("{0} exists and is not a tun device xraytui can use")]
    Conflict(String),
}

/// A TUN device the helper created and still holds a descriptor for.
#[derive(Debug)]
pub struct PersistentTun {
    /// Interface name.
    pub interface: String,
    /// The liveness descriptor. Dropping it does **not** delete the device,
    /// because `TUNSETPERSIST` was set; it is held so that the owning process
    /// closing it is observable.
    pub handle: OwnedFd,
}

/// Create a persistent TUN device owned by `owner_uid`.
///
/// The device survives this process. It is removed by [`delete`], or by the
/// lease reaper if the owner goes away.
///
/// # Errors
/// See [`TunError`]. A pre-existing device of the same name that *is* a tun is
/// adopted rather than rejected, because that is exactly the state a crashed
/// previous run leaves behind and refusing it would strand the user.
pub fn create(interface: &str, owner_uid: u32) -> Result<PersistentTun, TunError> {
    let name = encode_name(interface)?;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(TUN_DEVICE))
        .map_err(TunError::Device)?;
    let handle = OwnedFd::from(file);

    let mut request = IfReq {
        name,
        // No packet-information header: Xray reads bare IP packets.
        flags: (libc::IFF_TUN | libc::IFF_NO_PI) as u16,
        pad: [0; 22],
    };

    // SAFETY: `request` is a live, correctly sized `ifreq` for the lifetime of
    // the call, and `handle` is an open descriptor for `/dev/net/tun`.
    let attached = unsafe { libc::ioctl(handle.as_raw_fd(), libc::TUNSETIFF, &raw mut request) };
    if attached < 0 {
        let source = std::io::Error::last_os_error();
        return Err(match source.raw_os_error() {
            Some(libc::EBUSY) | Some(libc::EINVAL) => TunError::Conflict(interface.to_owned()),
            _ => TunError::Ioctl {
                operation: "TUNSETIFF",
                interface: interface.to_owned(),
                source,
            },
        });
    }

    // Order matters: hand the device to the user *before* making it persistent,
    // so a failure between the two leaves nothing behind for that user to
    // inherit.
    ioctl_int(&handle, libc::TUNSETOWNER, owner_uid as c_int).map_err(|source| {
        TunError::Ioctl {
            operation: "TUNSETOWNER",
            interface: interface.to_owned(),
            source,
        }
    })?;
    ioctl_int(&handle, libc::TUNSETPERSIST, 1).map_err(|source| TunError::Ioctl {
        operation: "TUNSETPERSIST",
        interface: interface.to_owned(),
        source,
    })?;

    Ok(PersistentTun {
        interface: interface.to_owned(),
        handle,
    })
}

/// Clear the persist flag on a device, so closing the descriptor removes it.
///
/// Used by the teardown path as a belt-and-braces companion to `RTM_DELLINK`:
/// if the link delete fails for any reason, the device still disappears when
/// the descriptor closes.
///
/// # Errors
/// See [`TunError`].
pub fn clear_persist(interface: &str) -> Result<(), TunError> {
    let name = encode_name(interface)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(TUN_DEVICE))
        .map_err(TunError::Device)?;
    let handle = OwnedFd::from(file);

    let mut request = IfReq {
        name,
        flags: (libc::IFF_TUN | libc::IFF_NO_PI) as u16,
        pad: [0; 22],
    };
    // SAFETY: as above.
    let attached = unsafe { libc::ioctl(handle.as_raw_fd(), libc::TUNSETIFF, &raw mut request) };
    if attached < 0 {
        // Nothing to detach from; the device is already gone.
        return Ok(());
    }
    ioctl_int(&handle, libc::TUNSETPERSIST, 0).map_err(|source| TunError::Ioctl {
        operation: "TUNSETPERSIST(0)",
        interface: interface.to_owned(),
        source,
    })
}

/// Whether `/dev/net/tun` exists and can be opened for reading and writing.
///
/// Performs no change; used by the capability probe.
#[must_use]
pub fn device_usable() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(TUN_DEVICE))
        .is_ok()
}

/// `struct ifreq` as `TUNSETIFF` uses it.
///
/// The kernel's `ifreq` is a 16-byte name followed by a union of at most 24
/// bytes; `TUNSETIFF` reads only the `short` at the start of that union. The
/// explicit padding keeps the layout equal to the kernel's regardless of what
/// the compiler would otherwise do.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: u16,
    pad: [u8; 22],
}

const _: () = assert!(size_of::<IfReq>() == 40, "ifreq must match the kernel ABI");

fn encode_name(interface: &str) -> Result<[u8; IFNAMSIZ], TunError> {
    if interface.as_bytes().contains(&0) {
        return Err(TunError::NameHasNul(interface.to_owned()));
    }
    // The name must fit with room for the terminator.
    if interface.len() >= IFNAMSIZ {
        return Err(TunError::NameTooLong(interface.to_owned()));
    }
    let mut name = [0u8; IFNAMSIZ];
    name[..interface.len()].copy_from_slice(interface.as_bytes());
    Ok(name)
}

/// Issue an ioctl whose argument is a plain integer passed by value.
fn ioctl_int(fd: &OwnedFd, request: libc::Ioctl, value: c_int) -> Result<(), std::io::Error> {
    // SAFETY: `request` is one of the TUNSET* commands, each of which takes an
    // `int` by value; `fd` is an open tun descriptor.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), request, value) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ifreq_layout_matches_the_kernel() {
        assert_eq!(size_of::<IfReq>(), 40);
        assert_eq!(std::mem::offset_of!(IfReq, name), 0);
        assert_eq!(std::mem::offset_of!(IfReq, flags), 16);
    }

    #[test]
    fn the_ioctl_numbers_match_the_documented_encoding() {
        // _IOW('T', nr, int) == 0x4000_0000 | (4 << 16) | ('T' << 8) | nr
        const fn iow(nr: libc::Ioctl) -> libc::Ioctl {
            0x4000_0000 | (4 << 16) | (0x54 << 8) | nr
        }
        assert_eq!(libc::TUNSETIFF, iow(202));
        assert_eq!(libc::TUNSETPERSIST, iow(203));
        assert_eq!(libc::TUNSETOWNER, iow(204));
    }

    #[test]
    fn names_are_encoded_nul_terminated_and_length_checked() {
        let encoded = encode_name("xraytui1000").expect("valid name");
        assert_eq!(&encoded[..11], b"xraytui1000");
        assert_eq!(encoded[11], 0);

        assert!(matches!(
            encode_name("xraytui123456789"),
            Err(TunError::NameTooLong(_))
        ));
        assert!(matches!(
            encode_name("xray\0tui"),
            Err(TunError::NameHasNul(_))
        ));
    }

    #[test]
    fn a_fifteen_byte_name_is_accepted_and_a_sixteen_byte_one_is_not() {
        assert!(encode_name(&"x".repeat(15)).is_ok());
        assert!(encode_name(&"x".repeat(16)).is_err());
    }
}
