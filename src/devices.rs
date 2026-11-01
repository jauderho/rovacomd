//! Device registry: emulation of the C `active_device` list (`main.c`:
//! `novacom_register_device`, `novacom_unregister_device`,
//! `novacom_removedup_device`, `dump_device_list`) and of the registration
//! parts of `novacom_go_online` / `novacom_go_offline` (`mux.c`).
//!
//! A device is its registry entry, its mux and its listen socket. The main
//! loop takes a [`snapshot`] (the C per-pass references), so a listen
//! socket stays open until the pass that saw it ends. Session ids come
//! only from USB SYN data; a device with one has a command service
//! ([`cmdservice::Service`]).

use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use crate::cmdservice::{self, Service};
use crate::tokens::TokenStore;
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
    /// Present if the device has a session id.
    pub service: Option<Arc<Service>>,
}

/// The session id of a device and the token store of its service.
pub struct Session {
    pub id: Vec<u8>,
    pub tokens: TokenStore,
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

/// One `dump_device_list` line: `"%d %s %s %s\n"`, or
/// `"%d %s %s %s %s\n"` with the session id.
pub fn format_line(
    port: i32,
    devid: &[u8],
    conntype: &[u8],
    devtype: &[u8],
    sessionid: Option<&[u8]>,
) -> Vec<u8> {
    let port = port.to_string();
    let mut line = [port.as_bytes(), b" ", devid, b" ", conntype, b" ", devtype].concat();
    if let Some(sid) = sessionid {
        line.extend_from_slice(b" ");
        line.extend_from_slice(sid);
    }
    line.push(b'\n');
    line
}

/// C `novacom_go_online(nduid, conntype, devtype, devdata)` with the
/// session id already taken from `devdata`. For a device with a non-empty
/// session id, also returns its init thread (C
/// `novacom_deviceinit_thread`, detached).
pub fn go_online(
    nduid: &[u8],
    conntype: &[u8],
    devtype: &[u8],
    session: Option<Session>,
) -> (Arc<mux::Device>, Option<JoinHandle<()>>) {
    let dev = mux::Device::new();
    log::always(&[b"novacom_go_online:", nduid, b"\n"].concat());
    let init = register_device(&dev, nduid, conntype, devtype, session);
    (dev, init)
}

/// C `NOVACOMD_DATATOKEN_ID`, `_MODE`, `_SESSION` with the sizes of the C
/// buffers their words are copied into (`devname[64]`, `devmode[16]`,
/// `sessionid[16]`).
const DATATOKEN_ID: (&[u8], usize) = (b"id:", 64);
const DATATOKEN_MODE: (&[u8], usize) = (b"mode:", 16);
const DATATOKEN_SESSION: (&[u8], usize) = (b"sn:", 16);

/// C `parse_devdata(devdata, token, data, size)`: in the C string
/// `devdata`, the first word (`strtok` on `" \t\n"`) after the first
/// occurrence of `token`, cut to `size - 1` bytes.
pub fn parse_devdata(devdata: &[u8], token: &[u8], size: usize) -> Option<Vec<u8>> {
    let s = server::c_str(devdata);
    let at = s.windows(token.len()).position(|w| w == token)?;
    let word = s[at + token.len()..]
        .split(|b| b" \t\n".contains(b))
        .find(|w| !w.is_empty())?;
    Some(word[..word.len().min(size - 1)].to_vec())
}

/// What C `novacom_go_online` registers from its arguments: the device
/// type, the mode (only traced) and the session id (empty if none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegInfo {
    pub devtype: Vec<u8>,
    pub devmode: Vec<u8>,
    pub sessionid: Vec<u8>,
}

/// The `devtype`/`devdata` part of C `novacom_go_online`: the device type
/// is the SYN `id:` word, else `devtype` if not empty, else `[unknown]`.
/// `trace` gets the C trace lines (mask, text).
pub fn reginfo(
    devtype: &[u8],
    devdata: Option<&[u8]>,
    trace: &mut dyn FnMut(u32, &[u8]),
) -> RegInfo {
    let mut info = RegInfo {
        devtype: if devtype.is_empty() {
            b"[unknown]".to_vec()
        } else {
            devtype.to_vec()
        },
        devmode: Vec::new(),
        sessionid: Vec::new(),
    };
    let Some(data) = devdata else {
        return info;
    };
    let (token, size) = DATATOKEN_ID;
    if let Some(name) = parse_devdata(data, token, size) {
        trace(
            log::LOG_TRACE,
            &[
                b"novacom_go_online:720: id:",
                &name[..],
                b"/(",
                devtype,
                b")\n",
            ]
            .concat(),
        );
        info.devtype = name;
    }
    let (token, size) = DATATOKEN_MODE;
    if let Some(mode) = parse_devdata(data, token, size) {
        trace(
            log::LOG_TRACE,
            &[b"novacom_go_online:724: mode:", &mode[..], b"\n"].concat(),
        );
        info.devmode = mode;
    }
    let (token, size) = DATATOKEN_SESSION;
    if let Some(sid) = parse_devdata(data, token, size) {
        trace(
            log::LOG_TRACE,
            &[b"novacom_go_online:728: sn:", &sid[..], b"\n"].concat(),
        );
        info.sessionid = sid;
    }
    info
}

/// C `novacom_go_online(nduid, "usb", devtype, devdata)` (a USB link after
/// its SYN). The command service of a device with a session id keeps its
/// tokens in `tokens`; its init thread is returned as by [`go_online`].
pub fn go_online_usb(
    nduid: &[u8],
    devtype: &[u8],
    devdata: Option<&[u8]>,
    tokens: TokenStore,
) -> (Arc<mux::Device>, Option<JoinHandle<()>>) {
    let dev = mux::Device::new();
    log::always(&[b"novacom_go_online:", nduid, b"\n"].concat());
    let info = reginfo(devtype, devdata, &mut log::log);
    let session = Session {
        id: info.sessionid,
        tokens,
    };
    let init = register_device(&dev, nduid, b"usb", &info.devtype, Some(session));
    (dev, init)
}

/// C `novacom_go_offline`.
pub fn go_offline(dev: &mux::Device) {
    log::trace(b"novacom_go_offline:762: going offline\n");
    dev.go_offline(|| unregister_device(dev.id()));
}

/// C `novacom_register_device`.
///
/// C starts the init thread before the device is listed, but the thread
/// first waits for the mux lock that `novacom_go_online` holds until the
/// registration is done; here it starts after the device is listed.
fn register_device(
    dev: &Arc<mux::Device>,
    devid: &[u8],
    conntype: &[u8],
    devtype: &[u8],
    session: Option<Session>,
) -> Option<JoinHandle<()>> {
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
    let service = session
        .filter(|s| !s.id.is_empty())
        .map(|s| Arc::new(Service::new(devid, &s.id, s.tokens)));
    lock().insert(
        0,
        Arc::new(Device {
            mux: Arc::clone(dev),
            devid: devid.to_vec(),
            conntype: conntype.to_vec(),
            devtype: devtype.to_vec(),
            port,
            listener,
            service: service.clone(),
        }),
    );
    let dev = Arc::clone(dev);
    service.map(|svc| std::thread::spawn(move || cmdservice::device_init(&dev, svc)))
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

/// The device of a control command (C `novacom_register_command`): the
/// first listed device if `path` is empty, else the first whose id
/// case-insensitively prefixes `path` (D33).
pub fn find_for_command(path: &[u8]) -> Option<Arc<Device>> {
    lock()
        .iter()
        .find(|d| path.is_empty() || strncaseeq(&d.devid, path, d.devid.len()))
        .cloned()
}

/// C `novacom_unregister_device`.
///
/// The listen socket closes when the last [`snapshot`] holding the device
/// is dropped. A device whose service awaits a reply is never released,
/// as in C: that command's client stays connected and the listen socket
/// stays open.
pub fn unregister_device(id: u64) {
    {
        let mut list = lock();
        if let Some(i) = list.iter().position(|d| d.mux.id() == id) {
            log::always(&[b"removing id ", &list[i].devid[..], b"\n"].concat());
            let d = list.remove(i);
            if d.service.as_ref().is_some_and(|svc| svc.drop_pending()) {
                std::mem::forget(d);
            }
        }
    }
    server::unblock_main_loop();
}

/// C `dump_device_list`: one `send` per device, errors ignored.
pub fn dump_device_list(mut w: impl Write) {
    for d in lock().iter() {
        let sid = d.service.as_ref().map(|svc| svc.sessionid());
        let _ = w.write(&format_line(d.port, &d.devid, &d.conntype, &d.devtype, sid));
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
                b"emulator",
                None
            ),
            b"50123 0123456789abcdef0123456789abcdef01234567 tcp emulator\n"
        );
        assert_eq!(
            format_line(0, b"", b"tcp", b"emulator", None),
            b"0  tcp emulator\n"
        );
        assert_eq!(
            format_line(4000, b"ab", b"usb", b"castle-linux", Some(b"0123456789")),
            b"4000 ab usb castle-linux 0123456789\n"
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

    #[test]
    fn devdata_words_and_size_limits() {
        let p = |d: &[u8], t: &[u8], n: usize| parse_devdata(d, t, n);
        assert_eq!(p(b"id:castle sn:1", b"id:", 64), Some(b"castle".to_vec()));
        assert_eq!(p(b"id:castle sn:1", b"sn:", 16), Some(b"1".to_vec()));
        // Cut to size - 1: id 63, sn and mode 15.
        let long = [b"id:".to_vec(), vec![b'i'; 70]].concat();
        assert_eq!(p(&long, b"id:", 64), Some(vec![b'i'; 63]));
        let sn = [b"sn:".to_vec(), vec![b'7'; 16]].concat();
        assert_eq!(p(&sn, b"sn:", 16), Some(vec![b'7'; 15]));
        // strtok: leading separators skipped; the word may be the next token.
        assert_eq!(p(b"id: \t\nx\ty", b"id:", 64), Some(b"x".to_vec()));
        assert_eq!(p(b"sn: id:foo", b"sn:", 16), Some(b"id:foo".to_vec()));
        // strstr: the token may sit inside a word; the first one counts.
        assert_eq!(p(b"uuid:abc id:def", b"id:", 64), Some(b"abc".to_vec()));
        // Missing token or word, or after the C string's end.
        assert_eq!(p(b"mode:x", b"id:", 64), None);
        assert_eq!(p(b"id:   ", b"id:", 64), None);
        assert_eq!(p(b"x\0id:y", b"id:", 64), None);
        assert_eq!(p(b"", b"id:", 64), None);
    }

    #[test]
    fn reginfo_device_type_choice_and_traces() {
        let lines = std::cell::RefCell::new(Vec::new());
        let mut rec = |m: u32, b: &[u8]| lines.borrow_mut().push((m, b.to_vec()));
        let info = reginfo(b"", None, &mut rec);
        assert_eq!(info.devtype, b"[unknown]");
        assert_eq!(
            reginfo(b"pixie-linux", None, &mut rec).devtype,
            b"pixie-linux"
        );
        let info = reginfo(b"", Some(b"nothing"), &mut rec);
        assert_eq!(
            (info.devtype, info.devmode, info.sessionid),
            (b"[unknown]".to_vec(), Vec::new(), Vec::new())
        );
        assert!(lines.borrow().is_empty());
        let info = reginfo(b"castle-linux", Some(b"mode:m id:dev sn:s"), &mut rec);
        assert_eq!(
            (info.devtype, info.devmode, info.sessionid),
            (b"dev".to_vec(), b"m".to_vec(), b"s".to_vec())
        );
        assert_eq!(
            *lines.borrow(),
            [
                (
                    log::LOG_TRACE,
                    b"novacom_go_online:720: id:dev/(castle-linux)\n".to_vec()
                ),
                (log::LOG_TRACE, b"novacom_go_online:724: mode:m\n".to_vec()),
                (log::LOG_TRACE, b"novacom_go_online:728: sn:s\n".to_vec()),
            ]
        );
    }
}
