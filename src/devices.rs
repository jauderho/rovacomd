//! Device registry: emulation of the C `active_device` list (`main.c`:
//! `novacom_register_device`, `novacom_unregister_device`,
//! `novacom_removedup_device`, `dump_device_list`) and of the registration
//! parts of `novacom_go_online` / `novacom_go_offline` (`mux.c`).
//!
//! A device is its registry entry, its mux and its listen socket. The main
//! loop takes a [`snapshot`] (the C per-pass references), so a listen
//! socket stays open until the pass that saw it ends. Session ids come
//! only from USB SYN data, so no device here has one.

use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::{log, mux, net, server};

/// C `NOVACOM_NDUID_CHRLEN`.
pub const NDUID_CHRLEN: usize = 40;

/// One registered device (C `struct active_device`).
pub struct Device {
    pub mux: Arc<mux::Device>,
    devid: Vec<u8>,
    conntype: Vec<u8>,
    devtype: Vec<u8>,
    /// Port of `listener`; 0 if the listen socket failed (D11).
    port: i32,
    /// The per-device port; closed with the last reference.
    pub listener: Option<TcpListener>,
}

/// C `device_list`: newest first.
static DEVICES: Mutex<Vec<Arc<Device>>> = Mutex::new(Vec::new());

fn lock() -> MutexGuard<'static, Vec<Arc<Device>>> {
    DEVICES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The listed devices, newest first (C `main_loop` takes a reference to
/// each for one pass).
pub fn snapshot() -> Vec<Arc<Device>> {
    lock().clone()
}

/// C `strncasecmp(a, b, n) == 0` on C strings (a missing byte is NUL).
pub fn strncaseeq(a: &[u8], b: &[u8], n: usize) -> bool {
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0).to_ascii_lowercase();
        let y = b.get(i).copied().unwrap_or(0).to_ascii_lowercase();
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
    }
    true
}

/// One `dump_device_list` line: `"%d %s %s %s\n"`. (The session-id form
/// `"%d %s %s %s %s\n"` needs USB.)
pub fn format_line(port: i32, devid: &[u8], conntype: &[u8], devtype: &[u8]) -> Vec<u8> {
    let port = port.to_string();
    [
        port.as_bytes(),
        b" ",
        devid,
        b" ",
        conntype,
        b" ",
        devtype,
        b"\n",
    ]
    .concat()
}

/// C `novacom_go_online(nduid, conntype, devtype, NULL)`.
pub fn go_online(nduid: &[u8], conntype: &[u8], devtype: &[u8]) -> Arc<mux::Device> {
    let dev = mux::Device::new();
    log::always(&[b"novacom_go_online:", nduid, b"\n"].concat());
    register_device(&dev, nduid, conntype, devtype);
    dev
}

/// C `novacom_go_offline`.
pub fn go_offline(dev: &mux::Device) {
    log::trace(b"novacom_go_offline:762: going offline\n");
    dev.go_offline(|| unregister_device(dev.id()));
}

/// C `novacom_register_device`.
fn register_device(dev: &Arc<mux::Device>, devid: &[u8], conntype: &[u8], devtype: &[u8]) {
    log::always(
        &[
            b"dev '", devid, b"' via ", conntype, b" type ", devtype, b"\n",
        ]
        .concat(),
    );
    removedup_device(devid, conntype);
    let listener = net::create_listen_socket(0, server::listen_all()).ok();
    let port = listener
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map_or(0, |a| i32::from(a.port()));
    lock().insert(
        0,
        Arc::new(Device {
            mux: Arc::clone(dev),
            devid: devid.to_vec(),
            conntype: conntype.to_vec(),
            devtype: devtype.to_vec(),
            port,
            listener,
        }),
    );
}

/// C `novacom_removedup_device`: for `tcp` registrations, unregisters the
/// first listed device whose id (up to 40 chars) case-insensitively
/// prefixes the new id (VirtualBox workaround LTP-624).
fn removedup_device(devid: &[u8], conntype: &[u8]) {
    if !strncaseeq(conntype, b"tcp", 3) {
        return;
    }
    let dup = {
        let list = lock();
        list.iter()
            .find(|d| strncaseeq(devid, &d.devid, d.devid.len().min(NDUID_CHRLEN)))
            .map(|d| {
                let port = d.port.to_string();
                log::always(
                    &[
                        b"duplicate: '",
                        &d.devid[..],
                        b"', port ",
                        port.as_bytes(),
                        b"\n",
                    ]
                    .concat(),
                );
                d.mux.id()
            })
    };
    if let Some(h) = dup {
        unregister_device(h);
    }
}

/// C `novacom_unregister_device`.
///
/// The listen socket closes when the last [`snapshot`] holding the device
/// is dropped.
pub fn unregister_device(id: u64) {
    {
        let mut list = lock();
        if let Some(i) = list.iter().position(|d| d.mux.id() == id) {
            log::always(&[b"removing id ", &list[i].devid[..], b"\n"].concat());
            list.remove(i);
        }
    }
    server::unblock_main_loop();
}

/// C `dump_device_list`: one `send` per device, errors ignored.
pub fn dump_device_list(mut w: impl Write) {
    for d in lock().iter() {
        let _ = w.write(&format_line(d.port, &d.devid, &d.conntype, &d.devtype));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_line_format() {
        assert_eq!(
            format_line(
                50123,
                b"0123456789abcdef0123456789abcdef01234567",
                b"tcp",
                b"emulator"
            ),
            b"50123 0123456789abcdef0123456789abcdef01234567 tcp emulator\n"
        );
        assert_eq!(
            format_line(0, b"", b"tcp", b"emulator"),
            b"0  tcp emulator\n"
        );
    }

    #[test]
    fn strncasecmp_semantics() {
        assert!(strncaseeq(b"ABCdef", b"abcDEF", 6));
        assert!(strncaseeq(b"abcx", b"ABCy", 3));
        assert!(!strncaseeq(b"abcx", b"ABCy", 4));
        assert!(strncaseeq(b"abc", b"abc", 40));
        assert!(!strncaseeq(b"abc", b"abcd", 40));
        assert!(strncaseeq(b"anything", b"", 0));
        assert!(strncaseeq(b"TCP", b"tcp", 3));
        assert!(!strncaseeq(b"tc", b"tcp", 3));
    }
}
