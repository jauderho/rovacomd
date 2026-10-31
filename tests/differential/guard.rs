//! Safety guards, checked before every daemon start:
//!
//! - Fixed ports: refuse to run if anything listens on, is bound to, or
//!   accepts connections on 6968, 6969, 6970, 6971, 12311 or 64022, so no
//!   test ever talks to a real daemon. The listener tables are read first
//!   (no traffic); bind and connect probes follow.
//! - Device safety: refuse to run while a USB device with a vendor id from
//!   the C `usbid_list` (`src/host/device_list.c`: Palm 0x0830, HP 0x03F0,
//!   Apple 0x05AC) is attached, because the C reference scans and claims
//!   USB devices at start. macOS: `ioreg -p IOUSB -l -w0`; Linux:
//!   `/sys/bus/usb/devices/*/idVendor`.
//!
//! Also: the listening sockets of one process (macOS `lsof`, Linux
//! `/proc`), for the bind-address checks.

use std::collections::BTreeSet;
use std::net::{TcpListener, TcpStream};
#[cfg(target_os = "macos")]
use std::process::Command;

/// The fixed ports of novacomd.
pub const FIXED_PORTS: [u16; 6] = [6968, 6969, 6970, 6971, 12311, 64022];
/// Vendor ids in the C `usbid_list`.
pub const USBID_VENDORS: [u16; 3] = [0x0830, 0x03F0, 0x05AC];

pub fn assert_safe_to_start() {
    assert_no_palm_device();
    assert_ports_free();
}

/// Vendor ids from `ioreg -p IOUSB -l -w0` output (`"idVendor" = 2096`).
pub fn parse_ioreg_vendor_ids(text: &str) -> Vec<u16> {
    const KEY: &str = "\"idVendor\" = ";
    text.lines()
        .filter_map(|line| {
            let rest = &line[line.find(KEY)? + KEY.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

/// Vendor id from a sysfs `idVendor` file (`"0830\n"`).
pub fn parse_sysfs_vendor_id(text: &str) -> Option<u16> {
    u16::from_str_radix(text.trim(), 16).ok()
}

/// Ids of `ids` that are in the C `usbid_list`.
pub fn usbid_matches(ids: &[u16]) -> Vec<u16> {
    ids.iter()
        .copied()
        .filter(|id| USBID_VENDORS.contains(id))
        .collect()
}

#[cfg(target_os = "macos")]
fn usb_vendor_ids() -> Vec<u16> {
    let out = Command::new("/usr/sbin/ioreg")
        .args(["-p", "IOUSB", "-l", "-w0"])
        .output()
        .unwrap_or_else(|e| panic!("cannot list USB devices with ioreg: {e}; refusing to run"));
    assert!(
        out.status.success(),
        "ioreg failed ({}); refusing to run",
        out.status
    );
    parse_ioreg_vendor_ids(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(target_os = "linux")]
fn usb_vendor_ids() -> Vec<u16> {
    let Ok(dir) = std::fs::read_dir("/sys/bus/usb/devices") else {
        return Vec::new(); // no USB bus
    };
    dir.filter_map(Result::ok)
        .filter_map(|e| std::fs::read_to_string(e.path().join("idVendor")).ok())
        .filter_map(|t| parse_sysfs_vendor_id(&t))
        .collect()
}

pub fn assert_no_palm_device() {
    let found = usbid_matches(&usb_vendor_ids());
    assert!(
        found.is_empty(),
        "Palm device attached: unplug it before running daemon tests (USB vendor ids {found:04x?})"
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
fn ioreg_parser_finds_vendor_ids() {
    let sample = "+-o Root  <class IORegistryEntry>\n\
        \x20   |   \"idProduct\" = 33026\n\
        \x20   |   \"idVendor\" = 2096\n\
        \x20 | |     \"idVendor\" = 1133\n\
        \x20 \"USB Vendor Name\" = \"Palm\"\n\
        \x20     \"idVendor\" = 1452\n";
    let ids = parse_ioreg_vendor_ids(sample);
    assert_eq!(ids, vec![0x0830, 1133, 0x05AC]);
    assert_eq!(usbid_matches(&ids), vec![0x0830, 0x05AC]);
    assert_eq!(
        usbid_matches(&parse_ioreg_vendor_ids("\"idVendor\" = 1008")),
        vec![0x03F0]
    );
    assert!(usbid_matches(&parse_ioreg_vendor_ids("\"idVendor\" = 8457\nno ids\n")).is_empty());
}

#[test]
fn sysfs_parser_reads_hex() {
    assert_eq!(parse_sysfs_vendor_id("0830\n"), Some(0x0830));
    assert_eq!(parse_sysfs_vendor_id("1d6b\n"), Some(0x1d6b));
    assert_eq!(parse_sysfs_vendor_id("zz"), None);
    let ids: Vec<u16> = ["03f0\n", "1d6b\n"]
        .iter()
        .filter_map(|t| parse_sysfs_vendor_id(t))
        .collect();
    assert_eq!(usbid_matches(&ids), vec![0x03F0]);
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
