//! Safety guards, checked before every daemon start:
//!
//! - Fixed ports: refuse to run if anything listens on, is bound to, or
//!   accepts connections on 6968, 6969, 6970, 6971, 12311 or 64022, so no
//!   test ever talks to a real daemon. The listener tables are read first
//!   (no traffic); bind and connect probes follow.
//! - Device safety: refuse to run while a Palm device is attached, because
//!   the C reference scans and claims USB devices at start. A Palm device is
//!   any device with the Palm vendor id 0x0830, or an HP 0x03F0
//!   vendor/product pair from the C `usbid_list` (`src/host/device_list.c`).
//!   Other HP devices and all Apple devices (0x05AC, also in `usbid_list`)
//!   are ignored, so hubs, printers and phones do not block tests. Every
//!   device is checked, including devices behind hubs. macOS:
//!   `ioreg -p IOUSB -l -w0`; Linux: `/sys/bus/usb/devices/*/id{Vendor,Product}`.
//!
//! Also: the listening sockets of one process (macOS `lsof`, Linux
//! `/proc`), for the bind-address checks.

use std::collections::BTreeSet;
use std::net::{TcpListener, TcpStream};
#[cfg(target_os = "macos")]
use std::process::Command;

use rovacomd::usb::scan::USBID_LIST;

/// The fixed ports of novacomd.
pub const FIXED_PORTS: [u16; 6] = [6968, 6969, 6970, 6971, 12311, 64022];
const PALM_VENDOR: u16 = 0x0830;
const HP_VENDOR: u16 = 0x03F0;

/// A USB device as (vendor id, product id).
pub type UsbId = (u16, u16);

pub fn assert_safe_to_start() {
    assert_no_palm_device();
    assert_ports_free();
}

/// True for a Palm device: Palm vendor id with any product, or an HP pair
/// from the C `usbid_list`. Apple ids are never Palm devices here.
pub fn is_palm_device((vendor, product): UsbId) -> bool {
    vendor == PALM_VENDOR
        || (vendor == HP_VENDOR
            && USBID_LIST
                .iter()
                .any(|&(v, p, _)| v == vendor && p == product))
}

/// Devices from `ioreg -p IOUSB -l -w0` output. Each `+-o` line starts a
/// device; its own `"idVendor" = 2096` and `"idProduct" = 33026` lines come
/// before the first child, in either order.
pub fn parse_ioreg_devices(text: &str) -> Vec<UsbId> {
    fn value(line: &str, key: &str) -> Option<u16> {
        let rest = &line[line.find(key)? + key.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    }
    let mut devices = Vec::new();
    let (mut vendor, mut product) = (None, None);
    for line in text.lines().chain(std::iter::once("+-o end")) {
        if line.contains("+-o ") {
            if let Some(v) = vendor.take() {
                devices.push((v, product.unwrap_or(0)));
            }
            product = None;
        } else if let Some(v) = value(line, "\"idVendor\" = ") {
            vendor = Some(v);
        } else if let Some(p) = value(line, "\"idProduct\" = ") {
            product = Some(p);
        }
    }
    devices
}

/// Id from a sysfs `idVendor` or `idProduct` file (`"0830\n"`).
pub fn parse_sysfs_id(text: &str) -> Option<u16> {
    u16::from_str_radix(text.trim(), 16).ok()
}

#[cfg(target_os = "macos")]
fn usb_devices() -> Vec<UsbId> {
    let out = Command::new("/usr/sbin/ioreg")
        .args(["-p", "IOUSB", "-l", "-w0"])
        .output()
        .unwrap_or_else(|e| panic!("cannot list USB devices with ioreg: {e}; refusing to run"));
    assert!(
        out.status.success(),
        "ioreg failed ({}); refusing to run",
        out.status
    );
    parse_ioreg_devices(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(target_os = "linux")]
fn usb_devices() -> Vec<UsbId> {
    let Ok(dir) = std::fs::read_dir("/sys/bus/usb/devices") else {
        return Vec::new(); // no USB bus
    };
    let read = |path: std::path::PathBuf| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| parse_sysfs_id(&t))
    };
    dir.filter_map(Result::ok)
        .filter_map(|e| {
            let vendor = read(e.path().join("idVendor"))?;
            // A device without a readable product id is checked as product 0:
            // a Palm vendor id still matches.
            Some((vendor, read(e.path().join("idProduct")).unwrap_or(0)))
        })
        .collect()
}

pub fn assert_no_palm_device() {
    let found: Vec<UsbId> = usb_devices()
        .into_iter()
        .filter(|&d| is_palm_device(d))
        .collect();
    assert!(
        found.is_empty(),
        "Palm device attached: unplug it before running daemon tests (USB vendor:product {found:04x?})"
    );
}

/// Local ports in LISTEN state from `netstat -an -p tcp` (macOS), e.g.
/// `tcp4 0 0 127.0.0.1.6968 *.* LISTEN`.
pub fn parse_netstat_listen_ports(text: &str) -> Vec<u16> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 || !f[0].starts_with("tcp") || f[5] != "LISTEN" {
                return None;
            }
            f[3].rsplit_once('.')?.1.parse().ok()
        })
        .collect()
}

/// One row of `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcTcpRow {
    /// Local IPv4 address (`"127.0.0.1"`), or the hex text for IPv6.
    pub addr: String,
    pub port: u16,
    pub listen: bool,
    pub inode: u64,
}

pub fn parse_proc_net_tcp(text: &str) -> Vec<ProcTcpRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let (addr_hex, port_hex) = f[1].split_once(':')?;
            let addr = if addr_hex.len() == 8 {
                let v = u32::from_str_radix(addr_hex, 16).ok()?;
                std::net::Ipv4Addr::from(v.to_le_bytes()).to_string()
            } else {
                addr_hex.to_string()
            };
            Some(ProcTcpRow {
                addr,
                port: u16::from_str_radix(port_hex, 16).ok()?,
                listen: f[3] == "0A",
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

/// Listening sockets from `lsof -nP -a -p PID -iTCP -sTCP:LISTEN -Fn`
/// (`n127.0.0.1:6968`, `n*:6968`) as (address, port); `*` is `0.0.0.0`.
pub fn parse_lsof_listeners(text: &str) -> Vec<(String, u16)> {
    text.lines()
        .filter_map(|line| {
            let (addr, port) = line.strip_prefix('n')?.rsplit_once(':')?;
            let addr = if addr == "*" { "0.0.0.0" } else { addr };
            Some((addr.to_string(), port.parse().ok()?))
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn system_listen_ports() -> Vec<u16> {
    let out = Command::new("/usr/sbin/netstat")
        .args(["-an", "-p", "tcp"])
        .output()
        .unwrap_or_else(|e| panic!("cannot run netstat: {e}; refusing to run"));
    assert!(out.status.success(), "netstat failed; refusing to run");
    parse_netstat_listen_ports(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(target_os = "linux")]
fn proc_tcp_rows() -> Vec<ProcTcpRow> {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| parse_proc_net_tcp(&t))
        .collect()
}

#[cfg(target_os = "linux")]
fn system_listen_ports() -> Vec<u16> {
    proc_tcp_rows()
        .into_iter()
        .filter(|r| r.listen)
        .map(|r| r.port)
        .collect()
}

pub fn assert_ports_free() {
    let listening = system_listen_ports();
    for port in FIXED_PORTS {
        assert!(
            !listening.contains(&port),
            "port {port} is in use (listening) — is novacomd running? refusing to run"
        );
    }
    // Bound but not listening (Linux) or a specific-address listener the
    // table missed. A wildcard probe would trip the macOS firewall prompt.
    let addrs: &[&str] = if cfg!(target_os = "linux") {
        &["127.0.0.1", "0.0.0.0"]
    } else {
        &["127.0.0.1"]
    };
    for port in FIXED_PORTS {
        for addr in addrs {
            if let Err(e) = TcpListener::bind((*addr, port)) {
                panic!(
                    "port {port} is busy on {addr} ({e}) — is novacomd running? refusing to run"
                );
            }
        }
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "port {port} accepts connections — is novacomd running? refusing to run"
        );
    }
}

/// Listening TCP sockets of process `pid` as (address, port).
#[cfg(target_os = "macos")]
pub fn pid_listeners(pid: u32) -> BTreeSet<(String, u16)> {
    let out = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fn",
        ])
        .output()
        .expect("run lsof");
    parse_lsof_listeners(&String::from_utf8_lossy(&out.stdout))
        .into_iter()
        .collect()
}

/// Listening TCP sockets of process `pid` as (address, port).
#[cfg(target_os = "linux")]
pub fn pid_listeners(pid: u32) -> BTreeSet<(String, u16)> {
    let inodes: BTreeSet<u64> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read /proc/PID/fd")
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .filter_map(|l| {
            let l = l.to_string_lossy().into_owned();
            l.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
        })
        .collect();
    proc_tcp_rows()
        .into_iter()
        .filter(|r| r.listen && inodes.contains(&r.inode))
        .map(|r| (r.addr, r.port))
        .collect()
}

#[test]
fn ioreg_parser_reads_each_device_behind_hubs() {
    // Shape of real output: nested hubs, keys in either order, a hub's
    // keys before its children, and one device without idProduct.
    let sample = "+-o Root  <class IORegistryEntry>\n\
        \x20 +-o AppleT8112USBXHCI@00000000  <class AppleT8112USBXHCI>\n\
        \x20 | +-o USB2.0 Hub@00100000  <class IOUSBHostDevice>\n\
        \x20 | | |   \"idProduct\" = 10274\n\
        \x20 | | |   \"idVendor\" = 8457\n\
        \x20 | | +-o Gaming Mouse@00111000  <class IOUSBHostDevice>\n\
        \x20 | | |     \"idVendor\" = 1133\n\
        \x20 | | |     \"idProduct\" = 49970\n\
        \x20 | | +-o USB2.0 Hub@00114000  <class IOUSBHostDevice>\n\
        \x20 | |   |   \"idProduct\" = 10258\n\
        \x20 | |   |   \"idVendor\" = 8457\n\
        \x20 | |   +-o iPhone@00114300  <class IOUSBHostDevice>\n\
        \x20 | |   |     \"idProduct\" = 4776\n\
        \x20 | |   |     \"idVendor\" = 1452\n\
        \x20 | |   +-o Pre3@00114400  <class IOUSBHostDevice>\n\
        \x20 | |         \"USB Vendor Name\" = \"Palm\"\n\
        \x20 | |         \"idVendor\" = 2096\n\
        \x20 | |         \"idProduct\" = 33026\n\
        \x20 | +-o Odd@00200000  <class IOUSBHostDevice>\n\
        \x20 |       \"idVendor\" = 1008\n";
    assert_eq!(
        parse_ioreg_devices(sample),
        vec![
            (8457, 10274),
            (1133, 49970),
            (8457, 10258),
            (0x05AC, 0x12A8),
            (0x0830, 0x8102),
            (0x03F0, 0),
        ]
    );
}

#[test]
fn palm_device_rule() {
    // Palm vendor: any product, also one not in usbid_list.
    assert!(is_palm_device((0x0830, 0x8102)));
    assert!(is_palm_device((0x0830, 0xFFFF)));
    // HP: only pairs from usbid_list.
    assert!(is_palm_device((0x03F0, 0x1128)));
    assert!(is_palm_device((0x03F0, 0x5f28)));
    assert!(!is_palm_device((0x03F0, 0x0000)));
    assert!(!is_palm_device((0x03F0, 0x1D02))); // an HP printer id
    // Apple: never, even the pairs in usbid_list.
    assert!(!is_palm_device((0x05AC, 0x12A8)));
    assert!(!is_palm_device((0x05AC, 0x8002)));
    assert!(!is_palm_device((0x05AC, 0x0101)));
    // Others.
    assert!(!is_palm_device((0x2109, 0x2812)));
}

#[test]
fn sysfs_parser_reads_hex() {
    assert_eq!(parse_sysfs_id("0830\n"), Some(0x0830));
    assert_eq!(parse_sysfs_id("1d6b\n"), Some(0x1d6b));
    assert_eq!(parse_sysfs_id("zz"), None);
}

#[test]
fn netstat_parser_keeps_listeners_only() {
    let sample = "Active Internet connections (including servers)\n\
        Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
        tcp4       0      0  127.0.0.1.6968         *.*                    LISTEN\n\
        tcp46      0      0  *.6969                 *.*                    LISTEN\n\
        tcp4       0      0  127.0.0.1.6971         127.0.0.1.50000        TIME_WAIT\n\
        tcp6       0      0  ::1.64022              *.*                    LISTEN\n";
    assert_eq!(parse_netstat_listen_ports(sample), vec![6968, 6969, 64022]);
}

#[test]
fn proc_net_tcp_parser() {
    let sample = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
        \x20  0: 0100007F:1B38 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n\
        \x20  1: 00000000:1B39 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0\n\
        \x20  2: 0100007F:1B3B 0100007F:C350 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000\n";
    assert_eq!(
        parse_proc_net_tcp(sample),
        vec![
            ProcTcpRow {
                addr: "127.0.0.1".into(),
                port: 6968,
                listen: true,
                inode: 12345
            },
            ProcTcpRow {
                addr: "0.0.0.0".into(),
                port: 6969,
                listen: true,
                inode: 12346
            },
            ProcTcpRow {
                addr: "127.0.0.1".into(),
                port: 6971,
                listen: false,
                inode: 0
            },
        ]
    );
}

#[test]
fn lsof_parser() {
    let sample = "p123\nf5\nn127.0.0.1:6968\nf6\nn*:6969\nf7\nn[::1]:7000\n";
    assert_eq!(
        parse_lsof_listeners(sample),
        vec![
            ("127.0.0.1".to_string(), 6968),
            ("0.0.0.0".to_string(), 6969),
            ("[::1]".to_string(), 7000)
        ]
    );
}

#[test]
fn port_guard_refuses_busy_port() {
    let _s = super::session();
    assert_ports_free();
    let held = TcpListener::bind(("127.0.0.1", 6971)).expect("bind 6971");
    assert!(std::panic::catch_unwind(assert_ports_free).is_err());
    drop(held);
}
