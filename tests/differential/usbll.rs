//! Differential tests of the USB link layer and the recovery records
//! (`transport_usb.c`, `recovery.c`) at function level.
//!
//! USB needs hardware, so the C side is a driver (`usbll/driver.c`)
//! compiled at test time from the unmodified reference `transport_usb.c`
//! (included, so the driver can print the link state), `recovery.c`,
//! `buf_queue.c` and `mux.c` (compiled with the mux packet calls of
//! `transport_usb.c` renamed away, so the real `novacom_go_online` parses
//! the SYN data and registers the device while packet I/O goes to
//! scripted stubs), plus platform stubs (`usbll/stubs.c`). Time is
//! virtual; session ids and mux packets are scripted.
//! `__PRETTY_FUNCTION__` is compiled as `__func__` (the bare name GCC, the
//! upstream toolchain, prints; Apple clang prints the signature) and
//! `__FILE__` as the reference build's `src/...` path.
//!
//! The same script runs through [`rovacomd::usbll`] with a recording
//! [`Host`]. Compared: every result, log line, registration (nduid, device
//! type, mode, session id), go-offline, mux call and transmitted packet,
//! and the link state after `G` steps.
//!
//! The thread harness (`usbll/usbthreads.c`) adds the reference
//! `host/usb-linux.c` as built (on macOS with the build patch's libusb-0.1
//! bulk calls) and runs its rx and tx thread functions one at a time on a
//! scripted device: reads, writes, `usleep` and the mux wait advance the
//! virtual clock. It is compared with [`rovacomd::usb`]'s loops; C's
//! `__LINE__` values of the patched file are mapped back to upstream
//! (`git show HEAD:src/host/usb-linux.c`). Not covered: device
//! enumeration and claiming (slice 5), and the concurrency of the two
//! threads (unit tests in `usb.rs`).
//!
//! Not scripted here, because C has undefined behavior on them (covered
//! by unit tests of the intentional changes): SYN data with
//! `data_length == 0` or a wrapping `data_offset + data_length` (D14),
//! and a link established by a SYN shorter than 40 bytes (D34).

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use rovacomd::devices;
use rovacomd::usb::{self, Settings, UsbHandle, UsbLink};
use rovacomd::usbll::{
    self, CMD_DATA, CMD_NULL, CMD_RST, CMD_SYN, Header, Host, Link, MAGIC, Records, RecoveryToken,
    RxType, Shared, VERSION,
};

/// The host nduid of both sides.
const HOST_NDUID: &[u8; 40] = b"0123456789abcdef0123456789abcdef01234567";
const DEV_NDUID: &[u8; 40] = b"fedcba9876543210fedcba9876543210fedcba98";
/// Size of the receive and transmit buffers.
const BUF_SIZE: usize = 16384;

#[derive(Clone, Debug)]
enum Step {
    /// `g_recovery_timeout`.
    W(i32),
    /// Next session id.
    N(u32),
    /// Virtual clock (ms).
    T(u64),
    /// Create a link: devtype, max_mtu, heartbeat, timeout.
    C(&'static [u8], u32, i32, i32),
    /// Set the link uid.
    I(usize, u32),
    /// Receive: link, length, bytes.
    X(usize, usize, Vec<u8>),
    /// Next mux packet (`None`: no packet).
    M(Option<Vec<u8>>),
    /// Prepare a packet.
    S(usize),
    /// Drop offline.
    O(usize),
    /// Destroy.
    Z(usize),
    /// Print the state.
    G(usize),
    /// Park the link.
    A(usize),
    /// Find a parked link by these header bytes.
    F(Vec<u8>),
    /// Age the records.
    U(i32),
    /// Remove the records of an nduid.
    R(Vec<u8>),
}

use Step::*;

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".to_string();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Same escaping as `put_escaped` in driver.c.
fn escape(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) && c != b'\\' {
                char::from(c).to_string()
            } else {
                format!("\\x{c:02x}")
            }
        })
        .collect()
}

fn script(steps: &[Step]) -> String {
    let mut s = String::new();
    for st in steps {
        s += &match st {
            W(n) => format!("W {n}\n"),
            N(id) => format!("N {id:08x}\n"),
            T(ms) => format!("T {ms}\n"),
            C(dt, mtu, hb, to) => format!("C {} {mtu} {hb} {to}\n", hex(dt)),
            I(k, uid) => format!("I {k} {uid}\n"),
            X(k, len, b) => format!("X {k} {len} {}\n", hex(b)),
            M(p) => format!("M {}\n", p.as_deref().map_or("-".to_string(), hex)),
            S(k) => format!("S {k}\n"),
            O(k) => format!("O {k}\n"),
            Z(k) => format!("Z {k}\n"),
            G(k) => format!("G {k}\n"),
            A(k) => format!("A {k}\n"),
            F(b) => format!("F {}\n", hex(b)),
            U(n) => format!("U {n}\n"),
            R(id) => format!("R {}\n", hex(id)),
        };
    }
    s
}

fn reference_src() -> PathBuf {
    let dir = super::manifest_dir().join("reference/novacomd");
    assert!(
        dir.join("src/transport_usb.c").is_file(),
        "{} not found: the C reference sources are needed",
        dir.display()
    );
    dir
}

/// Builds the C driver once per test run, under the cargo target dir.
fn driver() -> &'static Path {
    static DRIVER: OnceLock<PathBuf> = OnceLock::new();
    DRIVER.get_or_init(|| {
        let src = reference_src();
        let here = super::manifest_dir().join("tests/differential/usbll");
        let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let out = tmp.join("usbll-driver");
        let mux_obj = tmp.join("usbll-mux.o");
        let cc = |extra: &[String]| {
            let status = Command::new("cc")
                .args([
                    "-std=gnu11",
                    "-fcommon",
                    "-O0",
                    "-w",
                    "-DPLATFORM_PTHREADS=1",
                    "-DHOST=1",
                    "-DWEBOS_TARGET_MACHINE_IMPL_HOST=1",
                    "-D__PRETTY_FUNCTION__=__func__",
                ])
                .arg(format!("-fmacro-prefix-map={}/=", src.display()))
                .arg(format!("-I{}", src.join("include").display()))
                .arg(format!("-I{}", src.join("src").display()))
                .args(extra)
                .status()
                .expect("run cc");
            assert!(status.success(), "building the C driver failed");
        };
        let mut renames: Vec<String> = [
            "novacom_process_packet",
            "novacom_get_tx_packet",
            "novacom_prepare_tx_packet",
            "novacom_go_offline",
            "novacom_retain_device_handle",
            "novacom_release_device_handle",
        ]
        .iter()
        .map(|f| format!("-D{f}=real_mux_{f}"))
        .collect();
        renames.extend([
            "-c".to_string(),
            src.join("src/novacom/mux.c").display().to_string(),
            "-o".to_string(),
            mux_obj.display().to_string(),
        ]);
        cc(&renames);
        cc(&[
            here.join("driver.c").display().to_string(),
            here.join("stubs.c").display().to_string(),
            src.join("src/host/recovery.c").display().to_string(),
            src.join("src/novacom/buf_queue.c").display().to_string(),
            mux_obj.display().to_string(),
            "-o".to_string(),
            out.display().to_string(),
        ]);
        out
    })
}

fn run_c(steps: &[Step]) -> Vec<String> {
    let mut child = Command::new(driver())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start C driver");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script(steps).as_bytes())
        .expect("write script");
    let out = child.wait_with_output().expect("C driver output");
    assert!(
        out.status.success(),
        "C driver failed: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8 transcript")
        .lines()
        .map(str::to_string)
        .collect()
}

/// A scripted read: cost (ms), then bytes or an errno.
type ScriptedRead = (u64, Result<Vec<u8>, i32>);

/// The recording host of the Rust run. Devices are numbered in
/// registration order.
struct Rec {
    /// The thread harness: sleeps are recorded, and an empty mux queue
    /// means "no packet within the timeout".
    threads: bool,
    t0: Instant,
    clock: Mutex<u64>,
    sessionids: Mutex<VecDeque<u32>>,
    mux: Mutex<VecDeque<Option<Vec<u8>>>>,
    out: Mutex<Vec<String>>,
    ndevs: Mutex<usize>,
    records: Mutex<Records<usize>>,
    /// Scripted reads: cost (ms) and bytes or errno.
    reads: Mutex<VecDeque<ScriptedRead>>,
    /// Scripted writes: `None` succeeds, `Some(errno)` fails.
    writes: Mutex<VecDeque<Option<i32>>>,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Rec {
    fn new(threads: bool) -> Self {
        Self {
            threads,
            t0: Instant::now(),
            clock: Mutex::new(0),
            sessionids: Mutex::new(VecDeque::new()),
            mux: Mutex::new(VecDeque::new()),
            out: Mutex::new(Vec::new()),
            ndevs: Mutex::new(0),
            records: Mutex::new(Records::new()),
            reads: Mutex::new(VecDeque::new()),
            writes: Mutex::new(VecDeque::new()),
        }
    }

    fn emit(&self, line: String) {
        locked(&self.out).push(line);
    }
}

impl Host for Rec {
    type Dev = usize;

    fn now(&self) -> Instant {
        self.t0 + Duration::from_millis(*locked(&self.clock))
    }

    fn sleep(&self, d: Duration) {
        if self.threads {
            self.emit(format!("SLEEP {}", d.as_millis()));
        }
        *locked(&self.clock) += d.as_millis() as u64;
    }

    fn new_sessionid(&self) -> u32 {
        locked(&self.sessionids)
            .pop_front()
            .expect("no session id left")
    }

    fn nduid(&self) -> [u8; 40] {
        *HOST_NDUID
    }

    fn log(&self, mask: u32, msg: &[u8]) {
        self.emit(format!("L {mask} {}", escape(msg)));
    }

    fn go_online(&self, nduid: &[u8], devtype: &[u8], devdata: Option<&[u8]>) -> usize {
        self.log(1, &[b"novacom_go_online:", nduid, b"\n"].concat());
        let info = devices::reginfo(devtype, devdata, &mut |m, b| self.log(m, b));
        let mut n = locked(&self.ndevs);
        let dev = *n;
        *n += 1;
        self.emit(format!(
            "REG {dev} {} usb {} {} {}",
            hex(nduid),
            hex(&info.devtype),
            hex(&info.devmode),
            hex(&info.sessionid)
        ));
        dev
    }

    fn go_offline(&self, dev: &usize) {
        self.emit(format!("OFF {dev}"));
    }

    fn process_packet(&self, dev: &usize, buf: &[u8], len: usize) {
        self.emit(format!("PMUX {dev} {len} {}", hex(&buf[..len])));
    }

    fn get_tx_packet(&self, dev: &usize, timeout: Duration, len: usize) -> Option<Vec<u8>> {
        self.emit(format!("GETTX {dev} {} {len}", timeout.as_millis()));
        let next = locked(&self.mux).pop_front();
        match next {
            Some(p) => p,
            None if self.threads => {
                *locked(&self.clock) += timeout.as_millis() as u64;
                None
            }
            None => panic!("no mux packet scripted"),
        }
    }

    fn records(&self) -> &Mutex<Records<usize>> {
        &self.records
    }
}

/// C `PACKET_TYPE_*`; the stub mux returns `PACKET_TYPE_DATA`.
fn code(t: RxType) -> i32 {
    match t {
        RxType::Null => 0,
        RxType::Err => 1,
        RxType::Mux => 3,
        RxType::Protocol => 4,
        RxType::Bad => -1,
    }
}

fn state_line(k: usize, link: &Shared<usize>) -> String {
    let s = usbll::lock(link).snapshot();
    let token = s.recovery_token.map_or("-".to_string(), |t| {
        format!("{:08x}:{:08x}", t.txid, t.rxid)
    });
    format!(
        "G {k} {} {:08x} {:08x} {} {:08x} {:08x} {} {} {} {} {} {} {} {token} {:08x}",
        s.state as i32,
        s.sessionid,
        s.remoteid,
        s.nextcommand,
        s.reset_sessionid,
        s.reset_remoteid,
        s.max_mtu,
        s.mtu,
        s.heartbeat_interval,
        s.timeout,
        i32::from(s.online),
        hex(&s.nduid),
        s.synpacket_size,
        s.uid
    )
}

fn run_rust(steps: &[Step]) -> Vec<String> {
    let host = Rec::new(false);
    let mut links: Vec<Shared<usize>> = Vec::new();
    let mut rx: Vec<Vec<u8>> = Vec::new();
    let mut tx: Vec<Vec<u8>> = Vec::new();
    let mut recovery_timeout = 5;
    let index = |links: &[Shared<usize>], l: &Shared<usize>| {
        links
            .iter()
            .position(|x| Arc::ptr_eq(x, l))
            .map_or(-1, |i| i as i64)
    };
    for st in steps {
        match st {
            W(n) => recovery_timeout = *n,
            N(id) => locked(&host.sessionids).push_back(*id),
            T(ms) => *locked(&host.clock) = *ms,
            C(dt, mtu, hb, to) => {
                let link = Link::new(dt, *mtu, *hb, *to, &host);
                links.push(Arc::new(Mutex::new(link)));
                rx.push(vec![0; BUF_SIZE]);
                tx.push(vec![0; BUF_SIZE]);
                host.emit(format!("C {}", links.len() - 1));
            }
            I(k, uid) => usbll::lock(&links[*k]).set_uid(*uid),
            X(k, len, bytes) => {
                rx[*k][..bytes.len()].copy_from_slice(bytes);
                if usbll::check_packet_header(&rx[*k], *len, &host) {
                    host.emit(format!("X {k} bad"));
                } else {
                    let t = usbll::lock(&links[*k]).process_packet(&mut rx[*k], *len, &host);
                    host.emit(format!("X {k} {}", code(t)));
                }
            }
            M(p) => locked(&host.mux).push_back(p.clone()),
            S(k) => {
                let max_len = usbll::lock(&links[*k]).mtu() as usize;
                match usbll::prepare_tx_packet(&links[*k], &mut tx[*k], max_len, &host) {
                    Ok(Some(n)) => host.emit(format!("S {k} 0 {}", hex(&tx[*k][..n]))),
                    Ok(None) => host.emit(format!("S {k} -1 -")),
                    Err(usbll::AssertFailed) => {
                        host.emit("ABORT".to_string());
                        break;
                    }
                }
            }
            O(k) => usbll::lock(&links[*k]).drop_offline(&host),
            Z(k) => usbll::destroy(&links[*k], &host),
            G(k) => host.emit(state_line(*k, &links[*k])),
            A(k) => {
                let (nduid, token) = {
                    let l = usbll::lock(&links[*k]);
                    (l.nduid().to_vec(), l.recovery_token())
                };
                let rc = match token {
                    Some(t) => {
                        locked(&host.records).add(
                            t,
                            &nduid,
                            Arc::clone(&links[*k]),
                            recovery_timeout,
                        );
                        0
                    }
                    None => {
                        usbll::destroy(&links[*k], &host);
                        -1
                    }
                };
                host.emit(format!("A {k} {rc}"));
            }
            F(bytes) => {
                let mut b = vec![0u8; 64];
                b[..bytes.len()].copy_from_slice(bytes);
                let found = locked(&host.records).find(&RecoveryToken::from_header(&b), &host);
                let i = found.map_or(-1, |l| index(&links, &l));
                host.emit(format!("F {i}"));
            }
            U(n) => locked(&host.records).update(*n, &host),
            R(id) => locked(&host.records).remove(id, &host),
        }
    }
    host.out
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Pointers printed by the "got syn" trace (`data(%p)`) differ between
/// the runs; null pointers stay.
fn normalize(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|l| match l.find("data(0x") {
            Some(at) if !l[at..].starts_with("data(0x0)") => {
                let end = l[at..].find(')').map_or(l.len(), |e| at + e);
                format!("{}data(P{}", &l[..at], &l[end..])
            }
            _ => l,
        })
        .collect()
}

/// Runs `steps` through C and Rust and compares the transcripts; returns
/// the C transcript.
fn differential(name: &str, steps: &[Step]) -> Vec<String> {
    let c = normalize(run_c(steps));
    let r = normalize(run_rust(steps));
    assert_eq!(r, c, "{name}: transcript (left: Rust, right: C)");
    c
}

// --- packets ----------------------------------------------------------------

fn header(txid: u32, rxid: u32, command: u32) -> Vec<u8> {
    Header {
        magic: MAGIC,
        version: VERSION,
        txid,
        rxid,
        command,
    }
    .encode()
    .to_vec()
}

/// A full SYN: header, syn header, then `data`.
#[allow(clippy::too_many_arguments)]
fn syn(
    txid: u32,
    nduid: &[u8; 40],
    mtu: u32,
    heartbeat: u32,
    timeout: u32,
    data_offset: u32,
    data_length: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut p = header(txid, 0, CMD_SYN);
    p.extend_from_slice(nduid);
    for v in [mtu, heartbeat, timeout, data_offset, data_length] {
        p.extend_from_slice(&v.to_ne_bytes());
    }
    p.extend_from_slice(data);
    p
}

/// A device SYN with the usual data block right after the syn header.
fn syn_data(txid: u32, data: &[u8]) -> Vec<u8> {
    syn(
        txid,
        DEV_NDUID,
        16384,
        1000,
        5000,
        60,
        data.len() as u32,
        data,
    )
}

fn rx(k: usize, p: Vec<u8>) -> Step {
    X(k, p.len(), p)
}

fn data(txid: u32, rxid: u32, payload: &[u8]) -> Vec<u8> {
    [header(txid, rxid, CMD_DATA), payload.to_vec()].concat()
}

/// A pmux-like packet of `len` bytes (bytes `seed`, `seed+1`, ...).
fn pmux(len: usize, seed: u8) -> Vec<u8> {
    Vec::from_fn(len, |i| seed.wrapping_add(i as u8))
}

const DEV: u32 = 0xd0d0_0001;
const HOSTSID: u32 = 0x1234_5678;

/// A link (0) established with a device SYN carrying `data`.
fn established(data: &[u8]) -> Vec<Step> {
    vec![
        N(HOSTSID),
        C(b"castle-linux", 16384, 0, 2000),
        I(0, 0x0001_0002),
        rx(0, syn_data(DEV, data)),
        S(0),
    ]
}

// --- tests --------------------------------------------------------------------

#[test]
fn handshake_data_heartbeat_and_null() {
    let mut s = established(b"id:castle-linux sn:a1b2c3d4e5 mode:normal\0");
    s.extend([
        G(0),
        // Data from the device goes to the mux; data to it comes from the mux.
        rx(0, data(DEV, HOSTSID, &pmux(40, 1))),
        M(Some(pmux(36, 9))),
        S(0),
        M(None),
        S(0),
        // Null packets addressed to us are ignored; one with rxid 0 is not.
        rx(0, [header(DEV, HOSTSID, CMD_NULL), vec![0; 41]].concat()),
        rx(0, [header(DEV, 0, CMD_NULL), vec![0; 41]].concat()),
        // 999 ms of silence is fine, 1000 ms is not: a null packet.
        T(999),
        M(None),
        S(0),
        T(1000),
        S(0),
        T(1999),
        M(None),
        S(0),
        T(2000),
        S(0),
        G(0),
    ]);
    let c = differential("handshake", &s);
    assert!(c.iter().any(|l| l.starts_with("REG 0 ")), "{c:?}");
    assert!(c.iter().any(|l| l.starts_with("PMUX 0 40 ")), "{c:?}");
}

#[test]
fn header_checks() {
    let good = header(1, 2, CMD_DATA);
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0xff;
    let mut old = good.clone();
    old[4..8].copy_from_slice(&0u32.to_ne_bytes());
    let mut newer = good.clone();
    newer[4..8].copy_from_slice(&2u32.to_ne_bytes());
    let mut both = bad_magic.clone();
    both[4..8].copy_from_slice(&7u32.to_ne_bytes());
    let s = vec![
        N(HOSTSID),
        C(b"", 16384, 0, 2000),
        // Short packets: the rest of the header comes from the buffer,
        // which is still zero, then holds an earlier packet.
        X(0, 0, vec![]),
        X(0, 19, good[..19].to_vec()),
        rx(0, bad_magic),
        rx(0, old),
        rx(0, newer),
        rx(0, both),
        rx(0, good.clone()),
        X(0, 4, b"zzzz".to_vec()),
        X(0, 4, good[..4].to_vec()),
        G(0),
    ];
    differential("header_checks", &s);
}

#[test]
fn out_of_sequence_before_syn_gets_rst() {
    let s = vec![
        N(HOSTSID),
        C(b"castle-linux", 16384, 0, 2000),
        I(0, 0x0003_0004),
        // Nothing to send while listening.
        S(0),
        rx(0, data(0xaaaa, 0xbbbb, b"x")),
        G(0),
        // The rst swaps the ids; its 41 bytes after the header are
        // whatever the buffer holds (still zero here).
        S(0),
        S(0),
        rx(0, [header(0xcccc, 0xdddd, CMD_NULL), vec![7; 41]].concat()),
        // rst and unknown commands before the SYN.
        rx(0, header(0, HOSTSID, CMD_RST)),
        rx(0, header(5, 6, CMD_RST)),
        rx(0, header(5, 6, 9)),
        G(0),
        S(0),
        G(0),
    ];
    differential("rst_before_syn", &s);
}

#[test]
fn established_errors_rst_and_reset() {
    let mut s = established(b"id:x sn:0123456789\0");
    s.extend([
        // A packet for another session gets an rst; its stale 41 bytes
        // are the host SYN's.
        rx(0, data(DEV, 0x5555, b"zz")),
        G(0),
        S(0),
        // rxid 0 is accepted.
        rx(0, data(DEV, 0, b"p")),
        // SYN from the same session: error; from another: bad.
        rx(0, syn_data(DEV, b"id:y\0")),
        rx(0, syn_data(DEV + 1, b"id:y\0")),
        // Unknown command and a foreign rst: error.
        rx(0, header(DEV, HOSTSID, 9)),
        rx(0, header(DEV, 0x7777, CMD_RST)),
        G(0),
        // rst for us: the device goes offline, new session id, listen.
        N(0x0bad_cafe),
        rx(0, header(DEV, HOSTSID, CMD_RST)),
        G(0),
        S(0),
        // A new SYN registers it again.
        rx(0, syn_data(DEV + 2, b"id:again\0")),
        S(0),
        G(0),
        Z(0),
    ]);
    let c = differential("established_errors", &s);
    assert!(c.contains(&"OFF 0".to_string()), "{c:?}");
    assert!(c.contains(&"OFF 1".to_string()), "{c:?}");
}

#[test]
fn syn_lengths_and_negotiation() {
    let full = syn(DEV, DEV_NDUID, 1000, 300, 1500, 0xffff, 1, b"");
    let mut s = vec![W(5)];
    // One link per SYN length: 39 (nothing taken), 40 (nduid only), 44
    // (mtu present but not taken), 45, 51 (old defaults), 52, 56, 60.
    for (k, len) in [39usize, 40, 44, 45, 51, 52, 56, 60]
        .into_iter()
        .enumerate()
    {
        s.push(N(0x100 + k as u32));
        s.push(C(b"castle-linux", 16384, 0, 2000));
        s.push(X(k, 20 + len, full[..20 + len].to_vec()));
        s.push(G(k));
        // The host SYN: 80 bytes, or as long as the device's if shorter.
        s.push(S(k));
        s.push(G(k));
    }
    differential("syn_lengths", &s);
}

#[test]
fn heartbeat_and_timeout_values() {
    let mut s = Vec::new();
    // (link heartbeat, link timeout, SYN heartbeat, SYN timeout)
    let cases: [(i32, i32, u32, u32); 6] = [
        (0, 2000, 1000, 5000),
        (0, 2000, 500, 100),
        (0, 2000, 0, 0),
        (0, 2000, u32::MAX, u32::MAX),
        (0, 8_000_000, 2000, 7_200_000),
        (1500, -3, 1200, 6000),
    ];
    for (k, (hb, to, shb, sto)) in cases.into_iter().enumerate() {
        s.push(N(0x200 + k as u32));
        s.push(T(0));
        s.push(C(b"castle-linux", 16384, hb, to));
        s.push(rx(k, syn(DEV, DEV_NDUID, 16384, shb, sto, 0xffff, 1, b"")));
        s.push(S(k));
        s.push(G(k));
        // Heartbeat 0 and -1 send a null packet on every call after the
        // SYN; -1 even without time passing.
        s.push(M(None));
        s.push(S(k));
        s.push(T(1));
        s.push(M(None));
        s.push(S(k));
    }
    differential("heartbeat_timeout", &s);
}

#[test]
fn odd_length_rule_and_stale_bytes() {
    let mut s = established(b"id:castle-linux\0");
    s.extend([
        // A long packet leaves bytes behind in the tx buffer.
        M(Some(pmux(200, 0x40))),
        S(0),
        // 20 + 44 = 64: one more byte, which is stale.
        M(Some(pmux(44, 0x80))),
        S(0),
        // 20 + 108 = 128.
        M(Some(pmux(108, 0x90))),
        S(0),
        M(Some(pmux(45, 0xa0))),
        S(0),
        // The rst after these: its 41 bytes are the stale pmux bytes.
        rx(0, data(DEV, 0x9999, b"")),
        S(0),
    ]);
    differential("odd_length", &s);
    // A small MTU: a packet of exactly the MTU gets no extra byte.
    let s = vec![
        N(HOSTSID),
        C(b"castle-linux", 16384, 0, 2000),
        rx(0, syn(DEV, DEV_NDUID, 128, 1000, 5000, 60, 4, b"id:\0")),
        G(0),
        S(0),
        M(Some(pmux(108, 1))),
        S(0),
        M(Some(pmux(44, 2))),
        S(0),
    ];
    differential("odd_length_mtu", &s);
}

#[test]
fn syn_data_tokens() {
    let long_id = [
        b"id:".to_vec(),
        vec![b'i'; 70],
        b" sn:".to_vec(),
        vec![b's'; 20],
        b" mode:".to_vec(),
        vec![b'm'; 20],
        vec![0],
    ]
    .concat();
    let cases: Vec<Vec<u8>> = vec![
        long_id,
        b"id:\t  spaced\tsn:  0123456789 mode:\n\0".to_vec(),
        b"sn: id:foo\0".to_vec(),
        b"xid:abc uuid:def\0".to_vec(),
        b"mode:recovery\0".to_vec(),
        b"nothing here\0".to_vec(),
        b"id:\0".to_vec(),
        b"id:abc\0sn:hidden\0".to_vec(),
        // No NUL: the last byte is replaced by one.
        b"id:castle sn:1234567890".to_vec(),
        b"\0".to_vec(),
        b"id:a id:b sn:1 sn:2".to_vec(),
    ];
    let mut s = Vec::new();
    for (k, d) in cases.iter().enumerate() {
        s.push(N(0x300 + k as u32));
        s.push(C(
            if k % 2 == 0 { b"pixie-linux" } else { b"" },
            16384,
            0,
            2000,
        ));
        s.push(rx(k, syn_data(DEV, d)));
        s.push(G(k));
    }
    // Data offset past the syn header, data before the end of the packet,
    // data not fitting, offset inside the syn header.
    let k = cases.len();
    let tail = b"....id:off sn:5\0";
    s.extend([
        N(0x400),
        C(b"castle-linux", 16384, 0, 2000),
        rx(k, syn(DEV, DEV_NDUID, 16384, 1000, 5000, 64, 12, tail)),
        N(0x401),
        C(b"castle-linux", 16384, 0, 2000),
        rx(
            k + 1,
            syn(DEV, DEV_NDUID, 16384, 1000, 5000, 60, 40, b"id:short\0"),
        ),
        N(0x402),
        C(b"castle-linux", 16384, 0, 2000),
        rx(k + 2, syn(DEV, DEV_NDUID, 16384, 1000, 5000, 1, 2, b"")),
    ]);
    differential("syn_data", &s);
}

#[test]
fn second_syn_and_synrecv_state() {
    let s = vec![
        N(HOSTSID),
        C(b"castle-linux", 16384, 0, 2000),
        rx(0, syn_data(DEV, b"id:first\0")),
        // Before the host answered: no second registration.
        rx(0, syn_data(DEV + 1, b"id:second\0")),
        G(0),
        // Data before the host SYN: rst.
        rx(0, data(DEV, HOSTSID, b"early")),
        S(0),
        G(0),
        S(0),
        G(0),
    ];
    differential("second_syn", &s);
}

#[test]
fn old_syn_reply_length() {
    let full = syn(DEV, DEV_NDUID, 4000, 1000, 5000, 0, 0, b"");
    let s = vec![
        N(HOSTSID),
        C(b"castle-linux", 16384, 0, 2000),
        X(0, 20 + 48, full[..68].to_vec()),
        S(0),
        G(0),
        // Retransmitted old SYN while established: same session, error.
        X(0, 20 + 48, full[..68].to_vec()),
    ];
    differential("old_syn", &s);
}

#[test]
fn mtu_below_null_packet_asserts() {
    let s = vec![
        N(HOSTSID),
        C(b"castle-linux", 16384, 0, 2000),
        rx(0, syn(DEV, DEV_NDUID, 60, 1000, 5000, 0xffff, 1, b"")),
        G(0),
        S(0),
    ];
    let c = differential("assert", &s);
    assert_eq!(c.last().map(String::as_str), Some("ABORT"));
}

#[test]
fn recovery_records() {
    let mut s = vec![W(2)];
    // Link 0: registered, parked, found by a packet with its ids.
    s.extend(established(b"id:a\0"));
    s.extend([
        A(0),
        // Wrong ids: not found.
        F(header(DEV, HOSTSID + 1, CMD_DATA)),
        F(header(DEV + 1, HOSTSID, CMD_DATA)),
        F(header(DEV, HOSTSID, CMD_NULL)),
        G(0),
        // Parked again: still there after `-t` updates of 1 s ...
        A(0),
        U(1),
        U(1),
        F(header(DEV, HOSTSID, CMD_DATA)),
        // ... and destroyed (the device goes offline) by the next one.
        A(0),
        U(1),
        U(1),
        U(1),
        F(header(DEV, HOSTSID, CMD_DATA)),
        // A link without a registered device is destroyed, not parked.
        N(0x600),
        C(b"castle-linux", 16384, 0, 2000),
        A(1),
        // Default window and explicit removal by nduid.
        W(5),
        N(0x601),
        C(b"pixie-linux", 16384, 0, 2000),
        rx(2, syn_data(0x2222, b"id:p\0")),
        A(2),
        N(0x602),
        C(b"pixie-linux", 16384, 0, 2000),
        rx(
            3,
            syn(0x3333, HOST_NDUID, 16384, 1000, 5000, 0xffff, 1, b""),
        ),
        A(3),
        U(5),
        R(b"nomatch".to_vec()),
        R(DEV_NDUID.to_vec()),
        U(1),
        F(header(0x3333, 0x602, CMD_DATA)),
    ]);
    differential("recovery", &s);
}

#[test]
fn same_nduid_syn_discards_record_on_linux() {
    // On Linux a SYN of a parked device's nduid destroys its record
    // (`novacom_usb_transport_deviceonline`); on macOS the C call is
    // compiled out and the record stays.
    let mut s = established(b"id:a\0");
    s.extend([
        A(0),
        N(0x700),
        C(b"castle-linux", 16384, 0, 2000),
        rx(1, syn_data(0x4444, b"id:b\0")),
        F(header(DEV, HOSTSID, CMD_DATA)),
    ]);
    let c = differential("deviceonline", &s);
    let removed = c.iter().any(|l| l.contains("explicit remove"));
    assert_eq!(removed, cfg!(target_os = "linux"), "{c:?}");
}

#[test]
fn drop_offline_and_destroy() {
    let mut s = established(b"id:a\0");
    s.extend([
        N(0x800),
        O(0),
        G(0),
        // Without a device: no new session id.
        O(0),
        G(0),
        S(0),
        Z(0),
    ]);
    differential("drop_offline", &s);
}

/// The harness must see a difference: a Rust run of a different script
/// (another SYN heartbeat) does not match the C transcript.
#[test]
fn harness_detects_a_difference() {
    let mut a = established(b"id:a\0");
    a.push(G(0));
    let mut b = a.clone();
    if let X(_, _, p) = &mut b[3] {
        p[64..68].copy_from_slice(&800u32.to_ne_bytes());
    }
    assert_ne!(normalize(run_rust(&b)), normalize(run_c(&a)));
}

// --- thread harness ---------------------------------------------------------

#[derive(Clone, Debug)]
enum TStep {
    /// Next session id.
    Sid(u32),
    /// `g_recovery_timeout`.
    Window(i32),
    /// `g_usbio_retry_timeout`, `g_usbio_retry_delay`.
    Retry(i32, i32),
    /// Next mux packet.
    Mux(Vec<u8>),
    /// Next read: cost (ms), bytes.
    Rd(u64, Vec<u8>),
    /// Next read fails: cost (ms), errno.
    Rf(u64, i32),
    /// Next write succeeds.
    Wo,
    /// Next write fails with this errno.
    Wf(i32),
    /// Run the rx thread: bus, device, devtype.
    Rx(i32, i32, &'static [u8]),
    /// Run the tx thread of a new link that got this SYN.
    Tx(i32, i32, &'static [u8], Vec<u8>),
    /// Number of recovery records.
    Q,
}

fn thread_script(steps: &[TStep]) -> String {
    let mut s = String::new();
    for st in steps {
        s += &match st {
            TStep::Sid(id) => format!("N {id:08x}\n"),
            TStep::Window(n) => format!("W {n}\n"),
            TStep::Retry(t, d) => format!("E {t} {d}\n"),
            TStep::Mux(p) => format!("M {}\n", hex(p)),
            TStep::Rd(c, b) => format!("RD {c} {}\n", hex(b)),
            TStep::Rf(c, e) => format!("RF {c} {e}\n"),
            TStep::Wo => "WO\n".to_string(),
            TStep::Wf(e) => format!("WF {e}\n"),
            TStep::Rx(b, d, t) => format!("RX {b} {d} {}\n", hex(t)),
            TStep::Tx(b, d, t, syn) => format!("TX {b} {d} {} {}\n", hex(t), hex(syn)),
            TStep::Q => "Q\n".to_string(),
        };
    }
    s
}

/// Builds the thread driver once per test run.
fn thread_driver() -> &'static Path {
    static DRIVER: OnceLock<PathBuf> = OnceLock::new();
    DRIVER.get_or_init(|| {
        // The mux object of the function-level driver is reused.
        driver();
        let src = reference_src();
        let deps = super::manifest_dir().join("reference/deps/prefix/include");
        assert!(
            deps.join("usb.h").is_file(),
            "{} not found: run scripts/build-reference.sh",
            deps.display()
        );
        let here = super::manifest_dir().join("tests/differential/usbll");
        let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let out = tmp.join("usbll-threads");
        let status = Command::new("cc")
            .args([
                "-std=gnu11",
                "-fcommon",
                "-O0",
                "-w",
                "-DPLATFORM_PTHREADS=1",
                "-DHOST=1",
                "-DWEBOS_TARGET_MACHINE_IMPL_HOST=1",
                "-D__PRETTY_FUNCTION__=__func__",
            ])
            .arg(format!("-fmacro-prefix-map={}/=", src.display()))
            .arg(format!("-I{}", src.join("include").display()))
            .arg(format!("-I{}", src.join("src").display()))
            .arg(format!("-I{}", deps.display()))
            .arg(here.join("usbthreads.c"))
            .arg(here.join("stubs.c"))
            .arg(src.join("src/host/recovery.c"))
            .arg(src.join("src/host/device_list.c"))
            .arg(src.join("src/novacom/buf_queue.c"))
            .arg(tmp.join("usbll-mux.o"))
            .arg("-o")
            .arg(&out)
            .status()
            .expect("run cc");
        assert!(status.success(), "building the C thread driver failed");
        out
    })
}

/// `(function, text on the line, upstream line)` of the `usb-linux.c` log
/// statements whose `__LINE__` is printed.
const LINE_MARKS: [(&str, &str, usize); 5] = [
    (
        "novacom_usb_read",
        "received bad packet, set received packet size",
        298,
    ),
    ("novacom_usb_tx_thread", "wrote tx packet len", 388),
    ("novacom_usb_rx_thread", "error: reading packet", 431),
    ("novacom_usb_rx_thread", "reading packet, reads(", 452),
    ("novacom_usb_rx_thread", "TRACEF(\"received bad packet", 494),
];

fn line_of(text: &str, mark: &str) -> usize {
    text.lines()
        .position(|l| l.contains(mark))
        .map(|i| i + 1)
        .unwrap_or_else(|| panic!("{mark} not found"))
}

/// `(patched, upstream)` line pairs: the build's working copy carries the
/// macOS build patch, which shifts the lines.
fn line_map() -> &'static Vec<(String, String)> {
    static MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let src = reference_src();
        let patched =
            std::fs::read_to_string(src.join("src/host/usb-linux.c")).expect("usb-linux.c");
        let out = Command::new("git")
            .arg("-C")
            .arg(&src)
            .args(["show", "HEAD:src/host/usb-linux.c"])
            .output()
            .expect("git show");
        assert!(out.status.success(), "git show of the upstream usb-linux.c");
        let upstream = String::from_utf8(out.stdout).expect("utf-8");
        LINE_MARKS
            .iter()
            .map(|(func, mark, line)| {
                assert_eq!(line_of(&upstream, mark), *line, "upstream line of {mark}");
                (
                    format!("{func}:{}", line_of(&patched, mark)),
                    format!("{func}:{line}"),
                )
            })
            .collect()
    })
}

fn run_c_threads(steps: &[TStep]) -> Vec<String> {
    let mut child = Command::new(thread_driver())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start C thread driver");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(thread_script(steps).as_bytes())
        .expect("write script");
    let out = child.wait_with_output().expect("C driver output");
    assert!(
        out.status.success(),
        "C thread driver failed: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8 transcript")
        .lines()
        .map(|l| {
            line_map()
                .iter()
                .fold(l.to_string(), |l, (from, to)| l.replace(from, to))
        })
        .collect()
}

/// The scripted device of the Rust run.
struct FakeLink(Arc<Rec>);

impl UsbLink for FakeLink {
    fn read(&self, buf: &mut [u8], timeout_ms: i32) -> std::io::Result<usize> {
        let host = &self.0;
        host.emit(format!("R {} {timeout_ms}", buf.len()));
        let (cost, r) = locked(&host.reads).pop_front().unwrap_or((10, Err(110)));
        *locked(&host.clock) += cost;
        match r {
            Ok(b) => {
                buf[..b.len()].copy_from_slice(&b);
                Ok(b.len())
            }
            Err(e) => Err(std::io::Error::from_raw_os_error(e)),
        }
    }

    fn write(&self, buf: &[u8], timeout_ms: i32) -> std::io::Result<usize> {
        let host = &self.0;
        host.emit(format!("WR {timeout_ms} {}", hex(buf)));
        match locked(&host.writes).pop_front().unwrap_or(Some(32)) {
            None => Ok(buf.len()),
            Some(e) => Err(std::io::Error::from_raw_os_error(e)),
        }
    }
}

fn run_rust_threads(steps: &[TStep]) -> Vec<String> {
    let host = Arc::new(Rec::new(true));
    let mut s = Settings {
        recovery_timeout: 5,
        retry_timeout: 100,
        retry_delay: 50,
        live: false,
    };
    for st in steps {
        match st {
            TStep::Sid(id) => locked(&host.sessionids).push_back(*id),
            TStep::Window(n) => s.recovery_timeout = *n,
            TStep::Retry(t, d) => (s.retry_timeout, s.retry_delay) = (*t, *d),
            TStep::Mux(p) => locked(&host.mux).push_back(Some(p.clone())),
            TStep::Rd(c, b) => locked(&host.reads).push_back((*c, Ok(b.clone()))),
            TStep::Rf(c, e) => locked(&host.reads).push_back((*c, Err(*e))),
            TStep::Wo => locked(&host.writes).push_back(None),
            TStep::Wf(e) => locked(&host.writes).push_back(Some(*e)),
            TStep::Rx(bus, dev, devtype) => {
                let h = UsbHandle::new(FakeLink(Arc::clone(&host)), devtype, *bus, *dev);
                h.tx_ended();
                usb::rx_loop(&h, &*host, s);
                host.emit("RXEND".to_string());
            }
            TStep::Tx(bus, dev, devtype, syn) => {
                let h = UsbHandle::new(FakeLink(Arc::clone(&host)), devtype, *bus, *dev);
                let link = Link::new(
                    devtype,
                    usbll::MAX_MTU as u32,
                    0,
                    usb::USBDEVFS_IOCTL_TIMEOUT,
                    &*host,
                );
                let link: Shared<usize> = Arc::new(Mutex::new(link));
                let uid = (((bus & 0xffff) << 16) | (dev & 0xffff)) as u32;
                usbll::lock(&link).set_uid(uid);
                let mut buf = vec![0u8; BUF_SIZE];
                buf[..syn.len()].copy_from_slice(syn);
                usbll::lock(&link).process_packet(&mut buf, syn.len(), &*host);
                h.set_usbll(link);
                h.start_tx();
                usb::tx_loop(&h, &*host, s);
                host.emit("TXEND".to_string());
            }
            TStep::Q => host.emit(format!("Q {}", locked(&host.records).len())),
        }
    }
    locked(&host.out).clone()
}

fn differential_threads(name: &str, steps: &[TStep]) -> Vec<String> {
    let c = normalize(run_c_threads(steps));
    let r = normalize(run_rust_threads(steps));
    assert_eq!(r, c, "{name}: transcript (left: Rust, right: C)");
    c
}

#[test]
fn rx_thread_registers_then_parks_after_retries() {
    let c = differential_threads(
        "rx_park",
        &[
            TStep::Sid(HOSTSID),
            TStep::Rd(0, syn_data(DEV, b"id:castle sn:0123456789\0")),
            // Before the host SYN: rst.
            TStep::Rd(5, data(DEV, HOSTSID, b"x")),
            TStep::Rf(7, 19),
            TStep::Rx(3, 7, b"castle-linux"),
            TStep::Q,
        ],
    );
    assert!(
        c.iter().any(|l| l.contains("novacom_usb_rx_thread:452")),
        "{c:?}"
    );
    assert_eq!(c.last().map(String::as_str), Some("Q 1"));
}

#[test]
fn rx_thread_bad_header_bad_packet_and_retry_settings() {
    let mut bad_magic = header(1, 2, CMD_DATA);
    bad_magic[0] = 0;
    differential_threads(
        "rx_bad",
        &[
            TStep::Sid(1),
            TStep::Rd(0, bad_magic),
            TStep::Rd(3, header(4, 5, 9)),
            TStep::Rx(1, 2, b""),
            TStep::Sid(2),
            TStep::Retry(120, 50),
            TStep::Rf(0, 5),
            TStep::Rf(0, 5),
            TStep::Rx(1, 2, b""),
            TStep::Sid(3),
            TStep::Retry(100, 0),
            TStep::Rx(1, 2, b""),
            TStep::Sid(4),
            TStep::Retry(-5, 50),
            TStep::Rx(0x1_0001, 0x2_0002, b"x"),
            TStep::Q,
        ],
    );
}

#[test]
fn rx_thread_recovers_a_parked_link() {
    differential_threads(
        "rx_recover",
        &[
            TStep::Window(3),
            TStep::Sid(HOSTSID),
            TStep::Rd(0, syn_data(DEV, b"id:a\0")),
            TStep::Rx(3, 7, b"castle-linux"),
            TStep::Q,
            // The device comes back on another bus/device number with
            // the same session: resumed.
            TStep::Rd(0, data(DEV, HOSTSID, b"again")),
            TStep::Rx(4, 9, b"castle-linux"),
            TStep::Q,
            // Other ids: a new link.
            TStep::Sid(0x777),
            TStep::Rd(0, data(DEV + 1, HOSTSID, b"")),
            TStep::Rx(4, 9, b"castle-linux"),
            TStep::Q,
        ],
    );
}

#[test]
fn tx_thread_syn_data_heartbeat_and_write_retries() {
    let syn = syn(DEV, DEV_NDUID, 16384, 1000, 1500, 60, 5, b"id:a\0");
    differential_threads(
        "tx",
        &[
            TStep::Sid(HOSTSID),
            TStep::Mux(pmux(44, 3)),
            TStep::Wo,
            TStep::Wo,
            TStep::Wf(5),
            TStep::Wo,
            TStep::Wo,
            TStep::Tx(3, 7, b"castle-linux", syn.clone()),
            // All writes fail.
            TStep::Sid(HOSTSID + 1),
            TStep::Retry(130, 40),
            TStep::Tx(1, 1, b"castle-linux", syn),
        ],
    );
}
