//! The [`Backend`] of the daemon: `nusb` (usbfs on Linux, IOKit on
//! macOS), blocking calls only (`MaybeFuture::wait`).
//!
//! Bulk transfers as C `USBDEVFS_BULK` (Linux) / `usb_bulk_read` and
//! `usb_bulk_write` (macOS reference build): one transfer per call, no
//! zero-length packet, cancelled at the timeout. A timeout of 0 waits
//! without limit and a negative one is taken as unsigned, as usbfs does.
//!
//! Platform differences: the bus number comes from `busnum` (Linux) or
//! the top byte of the IOKit location id (macOS, as libusb); the device
//! key is bus and address (Linux) or the IOKit registry entry id (macOS);
//! errno values for the log lines are this OS's.

use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use nusb::transfer::{Buffer, Bulk, Completion, In, Out, TransferError};
use nusb::{Device, DeviceInfo, Endpoint, Interface, MaybeFuture};

use super::UsbLink;
use super::scan::{AltSetting, Backend, Endpoints, Found, InterfaceDesc};

/// Devices through `nusb`.
pub struct Nusb;

impl Backend for Nusb {
    type Info = DeviceInfo;
    type Device = Device;
    type Link = NusbLink;

    fn list(&self) -> io::Result<Vec<Found<DeviceInfo>>> {
        Ok(nusb::list_devices().wait()?.map(found).collect())
    }

    fn open(&self, info: &DeviceInfo) -> io::Result<Device> {
        Ok(info.open().wait()?)
    }

    fn config(&self, dev: &Device) -> Option<Vec<InterfaceDesc>> {
        let config = dev.configurations().next()?;
        Some(
            config
                .interfaces()
                .map(|i| InterfaceDesc {
                    number: i.interface_number(),
                    alt_settings: i
                        .alt_settings()
                        .map(|a| AltSetting {
                            class: a.class(),
                            subclass: a.subclass(),
                            protocol: a.protocol(),
                            endpoints: a.endpoints().map(|e| e.address()).collect(),
                        })
                        .collect(),
                })
                .collect(),
        )
    }

    fn claim(&self, dev: Device, eps: Endpoints) -> io::Result<NusbLink> {
        // As C, no kernel driver is detached.
        let iface = dev.claim_interface(eps.interface).wait()?;
        Ok(NusbLink {
            rx: Mutex::new(iface.endpoint::<Bulk, In>(eps.rx)?),
            tx: Mutex::new(iface.endpoint::<Bulk, Out>(eps.tx)?),
            _iface: iface,
        })
    }
}

#[cfg(target_os = "linux")]
fn found(d: DeviceInfo) -> Found<DeviceInfo> {
    Found {
        key: (u64::from(d.busnum()) << 8) | u64::from(d.device_address()),
        vendor: d.vendor_id(),
        product: d.product_id(),
        busnum: i32::from(d.busnum()),
        devnum: i32::from(d.device_address()),
        info: d,
    }
}

#[cfg(target_os = "macos")]
fn found(d: DeviceInfo) -> Found<DeviceInfo> {
    Found {
        key: d.registry_entry_id(),
        vendor: d.vendor_id(),
        product: d.product_id(),
        busnum: i32::from((d.location_id() >> 24) as u8),
        devnum: i32::from(d.device_address()),
        info: d,
    }
}

/// The claimed novacom interface; released when the device's threads
/// drop it (C `novacom_usb_close`).
pub struct NusbLink {
    rx: Mutex<Endpoint<Bulk, In>>,
    tx: Mutex<Endpoint<Bulk, Out>>,
    _iface: Interface,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The usbfs timeout: C passes the `int` as `unsigned int` ms; 0 means
/// no limit (here the longest timeout usbfs takes, about 49.7 days).
pub fn bulk_timeout(ms: i32) -> Duration {
    match ms as u32 {
        0 => Duration::from_millis(u64::from(u32::MAX)),
        ms => Duration::from_millis(u64::from(ms)),
    }
}

/// An IN transfer must ask for whole packets: `len` rounded up.
pub fn in_request_len(len: usize, max_packet: usize) -> usize {
    let mp = max_packet.max(1);
    len.max(1).div_ceil(mp) * mp
}

/// The errno the C transfer would have left for a `nusb` error (only
/// printed in log lines).
pub fn transfer_errno(e: TransferError) -> i32 {
    match e {
        TransferError::Cancelled => libc::ETIMEDOUT,
        TransferError::Stall => libc::EPIPE,
        TransferError::Disconnected => libc::ENODEV,
        TransferError::InvalidArgument => libc::EINVAL,
        #[cfg(target_os = "linux")]
        TransferError::Fault => libc::EPROTO,
        #[cfg(target_os = "linux")]
        TransferError::Unknown(errno) => i32::try_from(errno).unwrap_or(libc::EIO),
        #[cfg(not(target_os = "linux"))]
        TransferError::Fault | TransferError::Unknown(_) => libc::EIO,
    }
}

fn completed(c: &Completion) -> io::Result<usize> {
    c.status
        .map(|()| c.actual_len)
        .map_err(|e| io::Error::from_raw_os_error(transfer_errno(e)))
}

impl UsbLink for NusbLink {
    fn read(&self, buf: &mut [u8], timeout_ms: i32) -> io::Result<usize> {
        let mut ep = lock(&self.rx);
        let len = in_request_len(buf.len(), ep.max_packet_size());
        let c = ep.transfer_blocking(Buffer::new(len), bulk_timeout(timeout_ms));
        let n = completed(&c)?;
        // usbfs fails a transfer that brings more than was asked for.
        if n > buf.len() {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        buf[..n].copy_from_slice(&c.buffer[..n]);
        Ok(n)
    }

    fn write(&self, buf: &[u8], timeout_ms: i32) -> io::Result<usize> {
        let mut ep = lock(&self.tx);
        let c = ep.transfer_blocking(Buffer::from(buf), bulk_timeout(timeout_ms));
        completed(&c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_as_usbfs() {
        assert_eq!(bulk_timeout(2000), Duration::from_millis(2000));
        assert_eq!(bulk_timeout(0), bulk_timeout(-1));
        assert_eq!(bulk_timeout(-1), Duration::from_millis(u64::from(u32::MAX)));
    }

    #[test]
    fn in_lengths_are_whole_packets() {
        assert_eq!(in_request_len(16384, 512), 16384);
        assert_eq!(in_request_len(16384, 64), 16384);
        assert_eq!(in_request_len(1000, 512), 1024);
        assert_eq!(in_request_len(0, 512), 512);
        assert_eq!(in_request_len(10, 0), 10);
    }

    #[test]
    fn errno_of_transfer_errors() {
        assert_eq!(transfer_errno(TransferError::Cancelled), libc::ETIMEDOUT);
        assert_eq!(transfer_errno(TransferError::Stall), libc::EPIPE);
        assert_eq!(transfer_errno(TransferError::Disconnected), libc::ENODEV);
        assert_eq!(transfer_errno(TransferError::InvalidArgument), libc::EINVAL);
        if cfg!(target_os = "linux") {
            assert_eq!(transfer_errno(TransferError::Fault), libc::EPROTO);
            assert_eq!(transfer_errno(TransferError::Unknown(5)), 5);
        } else {
            assert_eq!(transfer_errno(TransferError::Fault), libc::EIO);
            assert_eq!(
                transfer_errno(TransferError::Unknown(0xe000_02ed)),
                libc::EIO
            );
        }
    }
}
