//! Differential and pairing tests: run the C reference daemon
//! (`reference/novacomd/build/novacomd`, built by
//! `scripts/build-reference.sh`) and `rovacomd` in turn with the same
//! inputs, and compare exit status, stdout and stderr byte for byte after
//! normalizing timestamps, the version string and ephemeral ports.
//!
//! Safety rules (see `guard`): every daemon start is serialized by one
//! process-wide lock and is refused unless all six fixed ports are free and
//! no Palm/HP/Apple USB device from the C `usbid_list` is attached. Every
//! spawned daemon is killed when its handle drops, also on panic.

#[path = "differential/cli.rs"]
mod cli;
#[path = "differential/cservice.rs"]
mod cservice;
#[path = "differential/daemon.rs"]
mod daemon;
#[path = "differential/guard.rs"]
mod guard;
#[path = "differential/pairing.rs"]
mod pairing;
#[path = "differential/pmux.rs"]
mod pmux;
#[path = "differential/relay.rs"]
mod relay;

use std::ffi::OsString;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// `BUILDVERSION` of the reference build.
const C_VERSION: &[u8] = b"ref-530a103";
/// Upper bound for a daemon to exit or to become ready.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Poll interval for waits.
const POLL: Duration = Duration::from_millis(10);
/// Loopback address of every fixed port.
const LOCALHOST: &str = "127.0.0.1";

/// Serializes everything that starts daemons or uses the fixed ports.
static DAEMON_LOCK: Mutex<()> = Mutex::new(());

fn session() -> MutexGuard<'static, ()> {
    // A panic in another test must not block the rest.
    DAEMON_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// `path`, or the file named by env var `var`; panics if it does not exist.
fn required_file(var: &str, default: PathBuf, hint: &str) -> PathBuf {
    let path = std::env::var_os(var).map_or(default, PathBuf::from);
    assert!(
        path.is_file(),
        "{} not found: {hint} (or set {var})",
        path.display()
    );
    path
}

fn reference() -> PathBuf {
    required_file(
        "ROVACOMD_REFERENCE",
        manifest_dir().join("reference/novacomd/build/novacomd"),
        "run scripts/build-reference.sh",
    )
}

fn rovacomd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rovacomd"))
}

/// Temporary directory with a symlink `name -> target`; removed on drop.
struct Alias(PathBuf);

impl Alias {
    fn new(target: &Path, name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rovacomd-alias-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create alias dir");
        std::os::unix::fs::symlink(target, dir.join(name)).expect("create symlink");
        Self(dir.join(name))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Alias {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A daemon binary and the `argv[0]` it is started with.
#[derive(Clone, Debug)]
struct Bin {
    path: PathBuf,
    arg0: &'static str,
    /// Output comes from the C reference (normalized to rovacomd's).
    is_c: bool,
    /// Invoked under the C name `novacomd` (getopt prefix not normalized).
    alias: bool,
}

impl Bin {
    fn c() -> Self {
        Self {
            path: reference(),
            arg0: "rovacomd",
            is_c: true,
            alias: false,
        }
    }

    fn c_alias() -> Self {
        Self {
            arg0: "novacomd",
            alias: true,
            ..Self::c()
        }
    }

    fn rust() -> Self {
        Self {
            path: rovacomd(),
            arg0: "rovacomd",
            is_c: false,
            alias: false,
        }
    }

    fn rust_alias(alias: &Alias) -> Self {
        Self {
            path: alias.path().to_path_buf(),
            arg0: "novacomd",
            is_c: false,
            alias: true,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Outcome {
    status: String,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl fmt::Debug for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outcome")
            .field("status", &self.status)
            .field("stdout", &String::from_utf8_lossy(&self.stdout))
            .field("stderr", &String::from_utf8_lossy(&self.stderr))
            .finish()
    }
}

fn spawn_reader<R: Read + Send + 'static>(mut r: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

fn status_string(s: std::process::ExitStatus) -> String {
    match (s.code(), s.signal()) {
        (Some(c), _) => format!("exit {c}"),
        (None, Some(sig)) => format!("signal {sig}"),
        (None, None) => "unknown".to_string(),
    }
}

/// A running daemon process. Dropping it kills the process.
struct Daemon {
    bin: Bin,
    child: Option<Child>,
    out: Option<JoinHandle<Vec<u8>>>,
    err: Option<JoinHandle<Vec<u8>>>,
}

impl Daemon {
    /// Checks the safety guards, then starts `bin` with `args`. The caller
    /// holds [`session`].
    fn spawn(bin: &Bin, args: &[&str]) -> Self {
        Self::spawn_with(bin, args, |_| {})
    }

    fn spawn_with(bin: &Bin, args: &[&str], tweak: impl FnOnce(&mut Command)) -> Self {
        guard::assert_safe_to_start();
        Self::spawn_unchecked(bin, args, tweak)
    }

    /// Checks the safety guards, then binds 127.0.0.1:`port` for each of
    /// `occupy` (kept bound by the returned listeners) and starts `bin`.
    fn spawn_occupied(
        bin: &Bin,
        args: &[&str],
        occupy: &[u16],
        tweak: impl FnOnce(&mut Command),
    ) -> (Self, Vec<std::net::TcpListener>) {
        guard::assert_safe_to_start();
        let held = occupy
            .iter()
            .map(|&p| std::net::TcpListener::bind((LOCALHOST, p)).expect("occupy port"))
            .collect();
        (Self::spawn_unchecked(bin, args, tweak), held)
    }

    fn spawn_unchecked(bin: &Bin, args: &[&str], tweak: impl FnOnce(&mut Command)) -> Self {
        let mut cmd = Command::new(&bin.path);
        cmd.arg0(bin.arg0)
            .args(
                args.iter()
                    .map(|a| OsString::from_vec(a.as_bytes().to_vec())),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_remove("POSIXLY_CORRECT");
        tweak(&mut cmd);
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.path.display()));
        let out = spawn_reader(child.stdout.take().expect("stdout pipe"));
        let err = spawn_reader(child.stderr.take().expect("stderr pipe"));
        Self {
            bin: bin.clone(),
            child: Some(child),
            out: Some(out),
            err: Some(err),
        }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    fn exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|c| c.try_wait().expect("try_wait").is_some())
    }

    /// Waits until port 6968 answers (or the process exits).
    fn wait_ready(&mut self) {
        let deadline = Instant::now() + TIMEOUT;
        while !self.exited() {
            if let Ok(mut s) = TcpStream::connect((LOCALHOST, 6968)) {
                let _ = s.read_to_end(&mut Vec::new());
                return;
            }
            assert!(Instant::now() < deadline, "daemon not ready");
            std::thread::sleep(POLL);
        }
    }

    /// Waits for the process to exit; returns its normalized outcome.
    fn wait_exit(mut self) -> Outcome {
        let mut child = self.child.take().expect("child");
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{} did not exit", self.bin.path.display());
            }
            std::thread::sleep(POLL);
        };
        let raw = Outcome {
            status: status_string(status),
            stdout: self
                .out
                .take()
                .map(|h| h.join().expect("stdout"))
                .unwrap_or_default(),
            stderr: self
                .err
                .take()
                .map(|h| h.join().expect("stderr"))
                .unwrap_or_default(),
        };
        normalize(raw, &self.bin)
    }

    /// Stops the daemon through the option port (`version` makes it exit
    /// with status 1 and flushes stdout).
    fn stop(self) -> Outcome {
        let _ = send_opt(b"version", None);
        self.wait_exit()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Runs `bin` with `args` until it exits by itself.
fn run(bin: &Bin, args: &[&str]) -> Outcome {
    Daemon::spawn(bin, args).wait_exit()
}

/// Replaces every C timestamp `"[%d/%d/%d %d:%02d:%02d] "` with `"[TS] "`.
fn normalize_timestamps(text: &[u8]) -> Vec<u8> {
    fn digits(t: &[u8], i: &mut usize, min: usize) -> bool {
        let n = t[*i..].iter().take_while(|b| b.is_ascii_digit()).count();
        *i += n;
        n >= min
    }
    fn lit(t: &[u8], i: &mut usize, c: u8) -> bool {
        let ok = t.get(*i) == Some(&c);
        *i += 1;
        ok
    }
    let at = |t: &[u8], start: usize| -> Option<usize> {
        let mut i = start;
        let ok = lit(t, &mut i, b'[')
            && digits(t, &mut i, 1)
            && lit(t, &mut i, b'/')
            && digits(t, &mut i, 1)
            && lit(t, &mut i, b'/')
            && digits(t, &mut i, 1)
            && lit(t, &mut i, b' ')
            && digits(t, &mut i, 1)
            && lit(t, &mut i, b':')
            && digits(t, &mut i, 2)
            && lit(t, &mut i, b':')
            && digits(t, &mut i, 2)
            && lit(t, &mut i, b']')
            && lit(t, &mut i, b' ');
        ok.then_some(i)
    };
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        match at(text, i) {
            Some(end) => {
                out.extend_from_slice(b"[TS] ");
                i = end;
            }
            None => {
                out.push(text[i]);
                i += 1;
            }
        }
    }
    out
}

/// Replaces every occurrence of `from` with `to`.
fn replace_all(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if !from.is_empty() && text[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

/// `__PRETTY_FUNCTION__` of `novacom_go_online` as Apple clang expands it
/// in C. GCC (the upstream Linux toolchain) gives the bare name, which
/// rovacomd prints on every OS.
const CLANG_GO_ONLINE: &[u8] =
    b"device_handle_t novacom_go_online(const char *, const char *, const char *, char *):";

/// Normalizes timestamps; for the C reference also the version string and,
/// on macOS, the clang `__PRETTY_FUNCTION__` text and (unless invoked as
/// `novacomd`) the executable-basename prefix of getopt diagnostics.
fn normalize(mut o: Outcome, bin: &Bin) -> Outcome {
    o.stdout = normalize_timestamps(&o.stdout);
    o.stderr = normalize_timestamps(&o.stderr);
    if bin.is_c {
        o.stdout = replace_all(&o.stdout, C_VERSION, rovacomd::cli::VERSION.as_bytes());
        if cfg!(target_os = "macos") {
            o.stdout = replace_all(&o.stdout, CLANG_GO_ONLINE, b"novacom_go_online:");
            if !bin.alias {
                o.stderr = replace_all(&o.stderr, b"novacomd: ", b"rovacomd: ");
            }
        }
    }
    o
}

/// Option-port request (64022): lengths include the NULs, as the (disabled)
/// C sender built them. Returns whatever the daemon sent back.
///
/// The request is half-closed after sending, as the C sender closed its
/// socket: the C daemon reads it with `SO_RCVLOWAT` 4096 on its main thread,
/// and if it calls `recv` before the bytes arrive, Linux wakes it only at
/// EOF. Without the half-close the C daemon then hangs until the client
/// gives up (timing dependent; seen in the `-c` test on Linux).
fn send_opt(name: &[u8], val: Option<&[u8]>) -> Vec<u8> {
    let l0 = u32::try_from(name.len() + 1).expect("len");
    let l1 = val.map_or(0, |v| u32::try_from(v.len() + 1).expect("len"));
    let mut msg = Vec::new();
    msg.extend_from_slice(&l0.to_ne_bytes());
    msg.extend_from_slice(&l1.to_ne_bytes());
    msg.extend_from_slice(name);
    msg.push(0);
    if let Some(v) = val {
        msg.extend_from_slice(v);
        msg.push(0);
    }
    send_raw(64022, &msg, true)
}

/// Connects to the fixed `port`, sends `data` (then half-closes if
/// `shutdown`), and reads until the daemon closes.
fn send_raw(port: u16, data: &[u8], shutdown: bool) -> Vec<u8> {
    let mut s = TcpStream::connect((LOCALHOST, port))
        .unwrap_or_else(|e| panic!("connect to port {port}: {e}"));
    s.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    s.write_all(data).expect("send");
    if shutdown {
        let _ = s.shutdown(Shutdown::Write);
    }
    let mut buf = Vec::new();
    match s.read_to_end(&mut buf) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
        Err(e) => panic!("read from port {port}: {e}"),
    }
    buf
}

/// Device list from port 6968.
fn devlist() -> Vec<u8> {
    send_raw(6968, b"", false)
}

/// Polls the device list until `pred` holds; returns the list.
fn wait_list(pred: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let l = devlist();
        if pred(&l) {
            return l;
        }
        assert!(
            Instant::now() < deadline,
            "device list never matched: {:?}",
            String::from_utf8_lossy(&l)
        );
        std::thread::sleep(POLL);
    }
}

/// Number of lines in a device list.
fn lines(l: &[u8]) -> usize {
    l.iter().filter(|&&b| b == b'\n').count()
}

/// Device-list lines as (port, rest-of-line).
fn split_ports(l: &[u8]) -> Vec<(u16, Vec<u8>)> {
    l.split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let sp = line.iter().position(|&b| b == b' ').expect("port field");
            let port = std::str::from_utf8(&line[..sp])
                .ok()
                .and_then(|p| p.parse().ok())
                .expect("numeric port");
            (port, line[sp..].to_vec())
        })
        .collect()
}

/// A device list with every port replaced by `<P>`.
fn mask_ports(l: &[u8]) -> Vec<u8> {
    split_ports(l)
        .into_iter()
        .flat_map(|(_, rest)| [b"<P>".to_vec(), rest, b"\n".to_vec()].concat())
        .collect()
}

/// Syn a fake device sends: `"nduid: \0"` and `id` padded with NUL to 40.
fn syn(id: &[u8]) -> Vec<u8> {
    let mut v = b"nduid: \0".to_vec();
    v.extend_from_slice(&id[..id.len().min(40)]);
    v.resize(48, 0);
    v
}

/// A fake device or emulator speaking the inet transport.
struct FakeDevice {
    s: TcpStream,
    /// The daemon's syn (`"nduid: \0"` + host nduid).
    host_syn: Vec<u8>,
}

impl FakeDevice {
    /// Connects to port 6969, retrying while it is refused (the listener
    /// thread may not be up yet).
    fn connect_raw() -> TcpStream {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            match TcpStream::connect((LOCALHOST, 6969)) {
                Ok(s) => {
                    s.set_read_timeout(Some(TIMEOUT)).expect("timeout");
                    return s;
                }
                Err(e) => {
                    assert!(Instant::now() < deadline, "port 6969: {e}");
                    std::thread::sleep(POLL);
                }
            }
        }
    }

    /// Reads the daemon's 48-byte syn from `s`.
    fn read_host_syn(s: &mut TcpStream) -> Vec<u8> {
        let mut host_syn = vec![0u8; 48];
        s.read_exact(&mut host_syn).expect("daemon syn");
        host_syn
    }

    /// Connects and completes the syn exchange with nduid `id`.
    fn connect(id: &[u8]) -> Self {
        let s = Self::connect_raw();
        Self::over(s, id)
    }

    /// Completes the syn exchange on an established stream.
    ///
    /// The syn is followed by [`LOWAT_PADDING`] keepalive frames: on Linux
    /// the C daemon reads with `SO_RCVLOWAT` 4096, and the kernel wakes a
    /// blocked reader only once 4096 bytes are queued (or at EOF), so a
    /// lone syn is never read (see `daemon::linux_rcvlowat_stall`).
    /// rovacomd reads the same bytes either way.
    fn over(mut s: TcpStream, id: &[u8]) -> Self {
        let host_syn = Self::read_host_syn(&mut s);
        let mut msg = syn(id);
        for _ in 0..LOWAT_PADDING {
            msg.extend_from_slice(&keepalive());
        }
        s.write_all(&msg).expect("send syn");
        Self { s, host_syn }
    }

    /// Reads one 12-byte frame header.
    fn read_header(&mut self) -> Vec<u8> {
        let mut h = vec![0u8; 12];
        self.s.read_exact(&mut h).expect("frame header");
        h
    }
}

/// Keepalive frames sent after the syn: 48 + 12 * 338 >= 4096 bytes.
const LOWAT_PADDING: usize = 338;

/// The keepalive frame: `"ELTSDIM\0"` and a zero length.
fn keepalive() -> Vec<u8> {
    [&b"ELTSDIM\0"[..], &0u32.to_ne_bytes()].concat()
}

/// Asserts a host syn: magic and 40 lowercase hex digits.
fn assert_host_syn(s: &[u8]) {
    assert_eq!(&s[..8], b"nduid: \0", "syn magic");
    assert!(
        s[8..].iter().all(|b| b"0123456789abcdef".contains(b)),
        "host nduid {:?}",
        String::from_utf8_lossy(&s[8..])
    );
}

#[test]
fn timestamp_normalization() {
    assert_eq!(
        normalize_timestamps(b"[2026/1/2 3:04:05] a\n[2026/12/31 23:59:59] b"),
        b"[TS] a\n[TS] b"
    );
    assert_eq!(
        normalize_timestamps(b"[1/2/3 4:5:06] x"),
        b"[1/2/3 4:5:06] x"
    );
    assert_eq!(normalize_timestamps(b"x[2026/1/2 3:04:05] y"), b"x[TS] y");
}

#[test]
fn port_masking() {
    let l = b"40001 abc tcp emulator\n40002 def tcp emulator\n";
    assert_eq!(
        mask_ports(l),
        b"<P> abc tcp emulator\n<P> def tcp emulator\n"
    );
    assert_eq!(
        split_ports(l),
        vec![
            (40001, b" abc tcp emulator".to_vec()),
            (40002, b" def tcp emulator".to_vec())
        ]
    );
}
