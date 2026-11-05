//! Device-initiated commands on the host (D1, kept as in C): a fake
//! device opens an `OPEN_COMMAND` channel on the host and sends
//! `get file://`, `put file://` or `connect tcp-port://`. Each scenario
//! runs against the C reference and then rovacomd with the same script.
//! Compared: what the device receives ([`Transcript`]), the files the
//! daemon wrote, the daemon's stdout/stderr and its log port (6970)
//! output.
//!
//! Filesystem safety: every path the fake device names is inside a
//! per-test temporary directory that is removed afterwards; each test
//! checks that the directory holds exactly the expected entries.
//! `connect` targets only listeners this test binds on loopback (on
//! macOS `localhost` resolves to `::1` first, so the test listener binds
//! the same port on `127.0.0.1` and `[::1]`).

use super::logport::LogTap;
use super::pmux::*;
use super::*;
use std::collections::BTreeSet;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

const DEV: &[u8; 40] = b"d1d1d1d1d1e2e2e2e2e2f3f3f3f3f3a4a4a4a4a4";
/// A device-side temporary channel.
const CH: u32 = 0x8000_0001;
/// C `RWSIZE`: bytes per data packet of `get`.
const RWSIZE: usize = 16384;
const FILE_OPEN_FAILED: &[u8] = b"file open failed\n\0";
const SOCKET_OPEN_FAILED: &[u8] = b"socket open failed\n\0";

fn differential<T: PartialEq + fmt::Debug>(scenario: impl Fn(&Bin) -> T) -> T {
    let _s = session();
    let c = scenario(&Bin::c());
    let r = scenario(&Bin::rust());
    assert_eq!(r, c, "rovacomd (left) differs from C (right)");
    r
}

/// A per-test temporary directory, removed (after restoring write
/// permission) on drop.
pub struct TempDir(PathBuf);

static TEMP_SEQ: AtomicUsize = AtomicUsize::new(0);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rovacomd-devcmd-{}-{tag}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create temp dir");
        // Canonical, so that the paths sent are exactly the files checked.
        Self(dir.canonicalize().expect("canonical temp dir"))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The path as a URL path for the device command.
    pub fn url(&self, name: &str) -> String {
        self.path(name).to_str().expect("utf-8 path").to_string()
    }

    /// Names of the entries in the directory.
    pub fn entries(&self) -> BTreeSet<String> {
        std::fs::read_dir(&self.0)
            .expect("read temp dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        for e in std::fs::read_dir(&self.0).into_iter().flatten().flatten() {
            let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Deterministic pseudo-random bytes (all byte values, NULs included).
fn blob(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// What one scenario observed.
#[derive(PartialEq, Eq)]
struct Run<T> {
    result: T,
    transcript: Transcript,
    out: Outcome,
    log: Vec<u8>,
}

impl<T: fmt::Debug> fmt::Debug for Run<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Run")
            .field("result", &self.result)
            .field("transcript", &self.transcript)
            .field("out", &self.out)
            .field("log", &String::from_utf8_lossy(&self.log))
            .finish()
    }
}

/// Starts `bin`, taps the log port, connects the fake device, runs
/// `script`, disconnects the device and stops the daemon.
fn run<T>(bin: &Bin, script: impl FnOnce(&Pmux) -> T) -> Run<T> {
    let mut d = Daemon::spawn(bin, &[]);
    d.wait_ready();
    let tap = LogTap::connect();
    let dev = Pmux::connect(DEV);
    wait_list(|l| lines(l) == 1);
    let result = script(&dev);
    let transcript = dev.transcript();
    drop(dev);
    wait_list(<[u8]>::is_empty);
    tap.wait_for(b"] shutting down channel 1\n");
    let out = d.stop();
    let log = tap.finish(bin, true);
    Run {
        result,
        transcript,
        out,
        log,
    }
}

/// Opens the command channel and sends `cmd`.
fn command(dev: &Pmux, cmd: &str) {
    dev.send_control(OPEN_COMMAND, CH);
    assert!(dev.send(CH, format!("{cmd}\n").as_bytes()));
}

/// The host's stream on [`CH`] once the host closed the channel.
fn until_close(dev: &Pmux) -> Vec<u8> {
    dev.wait_control(CLOSE, CH);
    dev.transcript()
        .streams
        .get(&CH)
        .cloned()
        .unwrap_or_default()
}

/// What `get` of `content` sends: `ok 0`, data packets of [`RWSIZE`]
/// bytes, stdout EOF and return code `rc`.
fn get_reply(content: &[u8], rc: i32) -> Vec<u8> {
    let mut v = b"ok 0\n".to_vec();
    for chunk in content.chunks(RWSIZE) {
        v.extend_from_slice(&stream_packet(S_DATA, chunk));
    }
    v.extend_from_slice(&oob(OOB_EOF, 1));
    v.extend_from_slice(&oob(OOB_RETURN, rc));
    v
}

/// The common log lines of one device session around `middle`.
fn session_log(middle: &[&[u8]]) -> Vec<u8> {
    let mut v: Vec<Vec<u8>> = vec![
        b"Incoming connection from 127.0.0.1/<P>".to_vec(),
        [&b"novacom_go_online:"[..], DEV].concat(),
        [&b"dev '"[..], DEV, b"' via tcp type emulator"].concat(),
    ];
    v.extend(middle.iter().map(|l| l.to_vec()));
    v.push(b"inet_rx_loop:187: invalid packet header (0/12)".to_vec());
    v.push(b"novacom_go_offline:762: going offline".to_vec());
    v.push([&b"removing id "[..], DEV].concat());
    v.push(b"shutting down channel 1".to_vec());
    v.push(format!("novacomd version {}", rovacomd::cli::VERSION).into_bytes());
    v.iter()
        .flat_map(|l| [&b"[TS] "[..], l, b"\n"].concat())
        .collect()
}

fn plain_stdout() -> Vec<u8> {
    [
        [&b"[TS] novacom_go_online:"[..], DEV, b"\n"].concat(),
        [&b"[TS] dev '"[..], DEV, b"' via tcp type emulator\n"].concat(),
        [&b"[TS] removing id "[..], DEV, b"\n"].concat(),
        format!("[TS] novacomd version {}\n", rovacomd::cli::VERSION).into_bytes(),
    ]
    .concat()
}

/// `get` of a file with `content`; returns the host stream.
fn get_file(bin: &Bin, content: &[u8]) -> Run<Vec<u8>> {
    let dir = TempDir::new("get");
    std::fs::write(dir.path("src"), content).expect("write source");
    let url = dir.url("src");
    let r = run(bin, |dev| {
        command(dev, &format!("get file://{url}"));
        until_close(dev)
    });
    assert_eq!(dir.entries(), BTreeSet::from(["src".to_string()]));
    assert_eq!(std::fs::read(dir.path("src")).expect("read"), content);
    r
}

fn check_get(content: &[u8]) {
    let r = differential(|bin| get_file(bin, content));
    assert_eq!(r.result, get_reply(content, 0));
    assert_eq!(r.transcript.controls, vec![(CLOSE, CH)]);
    assert!(r.transcript.anomalies.is_empty());
    assert_eq!(r.out.stdout, plain_stdout());
    assert_eq!(r.out.stderr, b"");
    assert_eq!(r.log, session_log(&[b"CONTROL_OPEN_COMMAND: -2147483647"]));
}

#[test]
fn get_small_file() {
    check_get(b"hello from the host\n");
}

#[test]
fn get_empty_file() {
    check_get(b"");
}

#[test]
fn get_binary_file_with_nuls() {
    let b = blob(5000, 7);
    assert!(b.contains(&0));
    check_get(&b);
}

#[test]
fn get_exact_multiple_of_rwsize() {
    check_get(&blob(2 * RWSIZE, 8));
}

#[test]
fn get_large_file() {
    check_get(&blob((1 << 20) + 4321, 9));
}

#[test]
fn get_missing_file() {
    let r = differential(|bin| {
        let dir = TempDir::new("missing");
        let url = dir.url("absent");
        let r = run(bin, |dev| {
            command(dev, &format!("get file://{url}"));
            dev.wait_stream(CH, |s| s.len() >= FILE_OPEN_FAILED.len())
        });
        assert!(dir.entries().is_empty());
        r
    });
    assert_eq!(r.result, FILE_OPEN_FAILED);
    assert!(r.transcript.controls.is_empty());
    assert_eq!(r.out.stdout, plain_stdout());
}

/// A directory opens, then `read` fails with EISDIR: EOF and return code
/// 21 (the same number on Linux and macOS).
#[test]
fn get_directory_returns_errno() {
    let r = differential(|bin| {
        let dir = TempDir::new("getdir");
        std::fs::create_dir(dir.path("sub")).expect("mkdir");
        let url = dir.url("sub");
        run(bin, |dev| {
            command(dev, &format!("get file://{url}"));
            until_close(dev)
        })
    });
    assert_eq!(r.result, get_reply(b"", 21));
}

/// `put` of `content` in data packets of `chunk` bytes, then stdin EOF.
/// Returns the host stream and the file (content and mode).
fn put_file(
    bin: &Bin,
    content: &[u8],
    chunk: usize,
    existing: bool,
) -> Run<(Vec<u8>, Vec<u8>, u32)> {
    let dir = TempDir::new("put");
    if existing {
        std::fs::write(dir.path("dst"), blob(70_000, 3)).expect("write old");
    }
    let url = dir.url("dst");
    let r = run(bin, |dev| {
        command(dev, &format!("put file://{url}"));
        assert_eq!(dev.wait_line(CH), b"ok 0\n");
        for c in content.chunks(chunk.max(1)) {
            assert!(dev.send(CH, &stream_packet(S_DATA, c)));
        }
        assert!(dev.send(CH, &oob(OOB_EOF, 0)));
        let stream = until_close(dev);
        let meta = std::fs::metadata(dir.path("dst")).expect("stat");
        (
            stream,
            std::fs::read(dir.path("dst")).expect("read"),
            meta.permissions().mode() & 0o7777,
        )
    });
    assert_eq!(dir.entries(), BTreeSet::from(["dst".to_string()]));
    r
}

/// The process umask (read without changing it for long).
fn umask() -> u32 {
    let out = Command::new("sh")
        .args(["-c", "umask"])
        .output()
        .expect("umask");
    u32::from_str_radix(String::from_utf8_lossy(&out.stdout).trim(), 8).expect("octal")
}

fn put_reply() -> Vec<u8> {
    [&b"ok 0\n"[..], &oob(OOB_EOF, 0), &oob(OOB_RETURN, 0)].concat()
}

fn check_put(content: &[u8], chunk: usize, existing: bool) {
    let r = differential(|bin| put_file(bin, content, chunk, existing));
    let (stream, file, mode) = &r.result;
    assert_eq!(stream, &put_reply());
    assert_eq!(file, content);
    if !existing {
        assert_eq!(*mode, 0o775 & !umask());
    }
    assert!(r.transcript.anomalies.is_empty());
    assert_eq!(r.out.stdout, plain_stdout());
    assert_eq!(r.out.stderr, b"");
}

#[test]
fn put_small_file() {
    check_put(b"written by the device\n", RWSIZE, false);
}

#[test]
fn put_empty_file_truncates() {
    check_put(b"", RWSIZE, true);
}

#[test]
fn put_binary_file_with_nuls() {
    let b = blob(9000, 11);
    assert!(b.contains(&0));
    check_put(&b, 1000, false);
}

#[test]
fn put_large_file() {
    check_put(&blob((1 << 20) + 777, 12), RWSIZE, true);
}

/// Targets the daemon cannot open inside the temporary directory: a
/// read-only directory and an existing directory.
#[test]
fn put_unwritable_targets() {
    let r = differential(|bin| {
        let dir = TempDir::new("ro");
        std::fs::create_dir(dir.path("ro")).expect("mkdir");
        std::fs::set_permissions(dir.path("ro"), std::fs::Permissions::from_mode(0o555))
            .expect("chmod");
        let (in_ro, as_dir) = (dir.url("ro/new"), dir.url("ro"));
        let r = run(bin, |dev| {
            command(dev, &format!("put file://{in_ro}"));
            let one = dev.wait_stream(CH, |s| s.len() >= FILE_OPEN_FAILED.len());
            const CH2: u32 = CH + 1;
            dev.send_control(OPEN_COMMAND, CH2);
            assert!(dev.send(CH2, format!("put file://{as_dir}\n").as_bytes()));
            let two = dev.wait_stream(CH2, |s| s.len() >= FILE_OPEN_FAILED.len());
            (one, two)
        });
        assert_eq!(dir.entries(), BTreeSet::from(["ro".to_string()]));
        assert_eq!(std::fs::read_dir(dir.path("ro")).expect("ls").count(), 0);
        r
    });
    assert_eq!(
        r.result,
        (FILE_OPEN_FAILED.to_vec(), FILE_OPEN_FAILED.to_vec())
    );
}

/// Bad stream packets on a `put` channel: C logs the header error on
/// stderr; the writer ends and the command completes.
#[test]
fn put_bad_packet_header() {
    let r = differential(|bin| {
        let dir = TempDir::new("bad");
        let url = dir.url("dst");
        let r = run(bin, |dev| {
            command(dev, &format!("put file://{url}"));
            assert_eq!(dev.wait_line(CH), b"ok 0\n");
            assert!(dev.send(CH, &stream_packet(S_DATA, b"kept")));
            let mut bad = stream_packet(S_DATA, b"lost");
            bad[0] ^= 0xff;
            assert!(dev.send(CH, &bad));
            let s = until_close(dev);
            (s, std::fs::read(dir.path("dst")).expect("read"))
        });
        assert_eq!(dir.entries(), BTreeSet::from(["dst".to_string()]));
        r
    });
    assert_eq!(r.result.0, put_reply());
    assert_eq!(r.out.stderr, b"[TS] Bad packet header magic\n");
}

/// A loopback listener for `connect tcp-port://`: the same port on
/// `127.0.0.1` and, where available, `[::1]`.
struct Target {
    v4: TcpListener,
    v6: Option<TcpListener>,
}

impl Target {
    fn bind() -> Self {
        for _ in 0..50 {
            let v4 = TcpListener::bind((LOCALHOST, 0)).expect("bind v4");
            let port = v4.local_addr().expect("addr").port();
            match TcpListener::bind(("::1", port)) {
                Ok(v6) => return Self { v4, v6: Some(v6) },
                Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
                Err(_) => return Self { v4, v6: None },
            }
        }
        panic!("no free port on 127.0.0.1 and ::1");
    }

    fn port(&self) -> u16 {
        self.v4.local_addr().expect("addr").port()
    }

    /// The one connection the daemon makes (on either address).
    fn accept(&self) -> TcpStream {
        let all: Vec<&TcpListener> = std::iter::once(&self.v4).chain(self.v6.as_ref()).collect();
        for l in &all {
            l.set_nonblocking(true).expect("nonblocking");
        }
        let deadline = Instant::now() + TIMEOUT;
        loop {
            for l in &all {
                match l.accept() {
                    Ok((s, _)) => {
                        s.set_nonblocking(false).expect("blocking");
                        s.set_read_timeout(Some(TIMEOUT)).expect("timeout");
                        return s;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) => panic!("accept: {e}"),
                }
            }
            assert!(Instant::now() < deadline, "daemon did not connect");
            std::thread::sleep(POLL);
        }
    }
}

#[test]
fn connect_to_test_listener() {
    let up = blob(40_000, 21);
    let down = blob(50_000, 22);
    let r = differential(|bin| {
        let target = Target::bind();
        let port = target.port();
        run(bin, |dev| {
            command(dev, &format!("connect tcp-port://{port}"));
            let mut s = target.accept();
            assert_eq!(dev.wait_line(CH), b"ok 0\n");
            assert!(dev.send(CH, &stream_packet(S_DATA, &up)));
            let mut got = vec![0u8; up.len()];
            s.read_exact(&mut got).expect("listener read");
            s.write_all(&down).expect("listener write");
            // Everything arrived (header and data of each packet) before
            // the listener closes.
            dev.wait_stream(CH, |st| {
                let mut n = 5;
                let mut data = 0;
                while st.len() >= n + 16 {
                    let size = u32::from_le_bytes(st[n + 8..n + 12].try_into().unwrap()) as usize;
                    if st.len() < n + 16 + size {
                        break;
                    }
                    data += size;
                    n += 16 + size;
                }
                data == down.len()
            });
            drop(s);
            let stream = until_close(dev);
            // The data packets as one byte stream (their sizes depend on
            // timing), then the tail.
            let mut data = Vec::new();
            let mut n = 5;
            while n + 16 <= stream.len() {
                let size = u32::from_le_bytes(stream[n + 8..n + 12].try_into().unwrap()) as usize;
                let kind = u32::from_le_bytes(stream[n + 12..n + 16].try_into().unwrap());
                if kind != S_DATA {
                    break;
                }
                data.extend_from_slice(&stream[n + 16..n + 16 + size]);
                n += 16 + size;
            }
            (got, data, stream[n..].to_vec())
        })
    });
    let (got, data, tail) = &r.result;
    assert_eq!(got, &up);
    assert_eq!(data, &down);
    assert_eq!(
        tail,
        &[&oob(OOB_EOF, 1)[..], &oob(OOB_EOF, 0), &oob(OOB_RETURN, 0)].concat()
    );
    assert_eq!(r.transcript.controls, vec![(CLOSE, CH)]);
}

/// The device ends its side first: the socket stays open (the reader's
/// copy) until the listener closes.
#[test]
fn connect_device_eof_first() {
    let r = differential(|bin| {
        let target = Target::bind();
        let port = target.port();
        run(bin, |dev| {
            command(dev, &format!("connect tcp-port://{port}"));
            let mut s = target.accept();
            assert_eq!(dev.wait_line(CH), b"ok 0\n");
            assert!(dev.send(CH, &stream_packet(S_DATA, b"ping")));
            assert!(dev.send(CH, &oob(OOB_EOF, 0)));
            let mut got = vec![0u8; 4];
            s.read_exact(&mut got).expect("listener read");
            let eof0 = [&b"ok 0\n"[..], &oob(OOB_EOF, 0)].concat();
            dev.wait_stream(CH, |st| st == eof0);
            s.write_all(b"pong").expect("listener write");
            dev.wait_stream(CH, |st| st.len() == eof0.len() + 20);
            drop(s);
            (got, until_close(dev))
        })
    });
    assert_eq!(r.result.0, b"ping");
    assert_eq!(
        r.result.1,
        [
            &b"ok 0\n"[..],
            &oob(OOB_EOF, 0),
            &stream_packet(S_DATA, b"pong"),
            &oob(OOB_EOF, 1),
            &oob(OOB_RETURN, 0)
        ]
        .concat()
    );
}

#[test]
fn connect_to_closed_port() {
    let r = differential(|bin| {
        let port = Target::bind().port();
        run(bin, |dev| {
            command(dev, &format!("connect tcp-port://{port}"));
            dev.wait_stream(CH, |s| s.len() >= SOCKET_OPEN_FAILED.len())
        })
    });
    assert_eq!(r.result, SOCKET_OPEN_FAILED);
    assert!(r.transcript.controls.is_empty());
}

/// Unknown verbs keep the command handler: each command gets
/// `unrecognized command`.
#[test]
fn unknown_device_commands() {
    let r = differential(|bin| {
        run(bin, |dev| {
            command(dev, "run file:///bin/true");
            let reply = b"unrecognized command\n\0";
            dev.wait_stream(CH, |s| s.len() == reply.len());
            assert!(dev.send(CH, b"GET nosuch://x\n"));
            dev.wait_stream(CH, |s| s.len() == 2 * reply.len())
        })
    });
    assert_eq!(r.result, b"unrecognized command\n\0".repeat(2));
}
