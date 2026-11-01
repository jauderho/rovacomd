//! Differential tests of the host command service and token storage
//! (`login`/`logout`/`logint`/`add`/`remove`, automatic token login).
//!
//! Only USB devices carry a session id, so this path cannot be driven
//! through the C daemon without USB. Instead a C driver
//! (`cservice/driver.c`) is compiled at test time from the unmodified
//! reference `main.c` (included, `main` renamed), `commands_service.c`,
//! `tokenstorage.c`, `buffer.c`, `sha1.c` and `commands.c`, plus stubs for
//! the mux, sockets, logging and platform (`cservice/stubs.c`). The stubs
//! define `getpwuid`, which takes precedence over libc at link time, so the
//! C token directory is a temp home; `connect` is stubbed too, so
//! `unblock_main_loop` stays off port 12311.
//!
//! The same script runs through the C driver and through `rovacomd`
//! in-process (device registry, command service, a mux played by the
//! test), each with its own temp home. Compared: channel opens and request
//! bytes on the service channel, bytes and close state seen by every
//! control client, and the token files.
//!
//! Isolation: the real `~/.nova` (passwd home and `$HOME`) must look the
//! same before and after; the C side must have written into its temp home.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rovacomd::devices::{self, Session};
use rovacomd::mux::{
    self, CHANNEL_CMDSERVICE, CHANNEL_CONTROL, FLAG_ACK, HEADER_LEN, Header, OP_OPEN_COMMAND,
    PMUX_MAGIC, PMUX_VERSION,
};
use rovacomd::{cmdservice, tokens};

const DEV1: &[u8] = b"0123456789abcdef0123456789abcdef01234567";
const DEV2: &[u8] = b"fedcba9876543210fedcba9876543210fedcba98";
/// A case-insensitive prefix of `DEV1`.
const DEV1_PREFIX: &[u8] = b"0123456789ABCDEF0123456789ABCDEF0123456";
const SID: &[u8] = b"a1b2c3d4e5";
const PACKET_LEN: usize = 4096;

#[derive(Clone)]
enum Step {
    /// Register a USB device with this id and session id.
    Dev(&'static [u8], &'static [u8]),
    /// A control client sends this command.
    Cmd(Vec<u8>),
    /// Device `n` replies on channel 0x50.
    Reply(usize, Vec<u8>),
    /// Device `n` goes away.
    Unregister(usize),
}

fn cmd(s: &str) -> Step {
    Step::Cmd(s.as_bytes().to_vec())
}

fn cmd_to(verb: &str, id: &[u8], rest: &str) -> Step {
    Step::Cmd([verb.as_bytes(), b" dev://", id, rest.as_bytes()].concat())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A token reply to `add`: type 75, version 0, command 70, blob.
fn token_reply(token: &[u8]) -> Vec<u8> {
    [&[75, 0, 70][..], &(token.len() as u32).to_be_bytes(), token].concat()
}

fn token(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// Token directory contents: file name to (mode, contents).
type NovaTree = BTreeMap<Vec<u8>, (u32, Vec<u8>)>;
/// A directory entry: name, size and modification time.
type DirEntryState = (Vec<u8>, u64, i64);

/// `<dir>/.nova` as a map of file name to (mode, contents); `None` if
/// there is no such directory. The directory itself is keyed by "".
fn nova_tree(home: &Path) -> Option<NovaTree> {
    let dir = home.join(".nova");
    let meta = fs::symlink_metadata(&dir).ok()?;
    let mut tree = BTreeMap::new();
    tree.insert(Vec::new(), (meta.permissions().mode(), Vec::new()));
    for e in fs::read_dir(&dir).ok()?.flatten() {
        let m = e.metadata().ok()?;
        let data = if m.is_file() {
            fs::read(e.path()).ok()?
        } else {
            Vec::new()
        };
        tree.insert(
            e.file_name().as_bytes().to_vec(),
            (m.permissions().mode(), data),
        );
    }
    Some(tree)
}

/// The real token directories (passwd home and `$HOME`): existence,
/// entries, sizes and modification times.
fn real_nova_state() -> Vec<(PathBuf, Option<Vec<DirEntryState>>)> {
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Some(h) = rovacomd::sys::home_dir() {
        homes.push(PathBuf::from(std::ffi::OsStr::from_bytes(&h)));
    }
    if let Some(h) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(h));
    }
    homes
        .into_iter()
        .map(|h| {
            let dir = h.join(".nova");
            let state = fs::symlink_metadata(&dir).ok().map(|m| {
                let mut entries = vec![(Vec::new(), m.size(), m.mtime())];
                if let Ok(rd) = fs::read_dir(&dir) {
                    for e in rd.flatten() {
                        if let Ok(m) = e.metadata() {
                            entries.push((e.file_name().as_bytes().to_vec(), m.size(), m.mtime()));
                        }
                    }
                }
                entries.sort();
                entries
            });
            (dir, state)
        })
        .collect()
}

fn reference_src() -> PathBuf {
    let dir = super::manifest_dir().join("reference/novacomd");
    assert!(
        dir.join("src/main.c").is_file(),
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
        let here = super::manifest_dir().join("tests/differential/cservice");
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cservice-driver");
        let status = Command::new("cc")
            .args([
                "-std=gnu11",
                "-fcommon",
                "-O0",
                "-w",
                "-DPLATFORM_PTHREADS=1",
                "-DHOST=1",
                "-DWEBOS_TARGET_MACHINE_IMPL_HOST=1",
                "-DBUILDVERSION=\"harness\"",
            ])
            .arg(format!("-I{}", src.join("include").display()))
            .arg(format!("-I{}", src.join("src").display()))
            .arg(here.join("driver.c"))
            .arg(here.join("stubs.c"))
            .arg(src.join("src/host/commands_service.c"))
            .arg(src.join("src/host/tokenstorage.c"))
            .arg(src.join("src/lib/buffer.c"))
            .arg(src.join("src/lib/cksum/sha1.c"))
            .arg(src.join("src/novacom/commands.c"))
            .arg("-o")
            .arg(&out)
            .status()
            .expect("run cc");
        assert!(status.success(), "building the C driver failed");
        out
    })
}

/// A fresh home directory for one run, with `seed` token files.
fn fresh_home(name: &str, side: &str, seed: &[(&[u8], Vec<u8>)]) -> PathBuf {
    let home = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cservice")
        .join(name)
        .join(side);
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).expect("create temp home");
    if !seed.is_empty() {
        let nova = home.join(".nova");
        fs::create_dir(&nova).expect("create .nova");
        fs::set_permissions(&nova, fs::Permissions::from_mode(0o700)).expect("chmod .nova");
        for (file, data) in seed {
            fs::write(nova.join(std::ffi::OsStr::from_bytes(file)), data).expect("seed token");
        }
    }
    home
}

fn run_c(home: &Path, steps: &[Step]) -> Vec<String> {
    let mut script = String::new();
    for s in steps {
        script += &match s {
            Step::Dev(id, sid) => format!("D {} {}\n", hex(id), hex(sid)),
            Step::Cmd(c) => format!("C {}\n", hex(c)),
            Step::Reply(d, data) => format!("R {d} {}\n", hex(data)),
            Step::Unregister(d) => format!("U {d}\n"),
        };
    }
    let mut child = Command::new(driver())
        .arg(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start C driver");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
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

/// A device as the Rust run plays it.
struct FakeDevice {
    mux: Arc<mux::Device>,
    rx_seq: u32,
}

/// Takes every registered test device offline when dropped, so a failed
/// run leaves the registry empty.
struct Devices(Vec<FakeDevice>);

impl Drop for Devices {
    fn drop(&mut self) {
        for d in &self.0 {
            devices::go_offline(&d.mux);
        }
    }
}

fn packet(flags: u16, channel: u32, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let h = Header {
        magic: PMUX_MAGIC,
        version: PMUX_VERSION,
        flags,
        channel,
        sequence,
        payload_len: len,
        total_len: len + HEADER_LEN as u32,
        crc: if flags == 0 { mux::adler(payload) } else { 0 },
    };
    [&h.encode()[..], payload].concat()
}

/// Records one packet from the daemon and acknowledges it.
fn record(out: &mut Vec<String>, idx: usize, dev: &mux::Device, p: &[u8]) {
    let h = Header::decode(p);
    if h.flags & FLAG_ACK != 0 {
        return;
    }
    let payload = &p[HEADER_LEN..];
    if h.channel == CHANNEL_CONTROL {
        let word = |at: usize| u32::from_ne_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
        let (op, chan) = (word(HEADER_LEN), word(HEADER_LEN + 4));
        assert_eq!(op, OP_OPEN_COMMAND, "unexpected control message");
        out.push(format!("O {idx} {chan:x} 1"));
    } else {
        out.push(format!("W {idx} {:x} {}", h.channel, hex(payload)));
    }
    let ack = packet(FLAG_ACK, h.channel, h.sequence, b"");
    dev.process_packet(&ack, ack.len());
}

/// Records and acknowledges everything the daemon has queued.
fn drain(out: &mut Vec<String>, devs: &Devices) {
    for (idx, d) in devs.0.iter().enumerate() {
        while let Some(p) = d
            .mux
            .with(|m| m.prepare_tx_packet(Instant::now(), PACKET_LEN))
        {
            record(out, idx, &d.mux, &p);
        }
    }
}

/// What a client received, and whether the daemon closed it.
fn client_state(c: &mut TcpStream) -> (Vec<u8>, bool) {
    c.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set timeout");
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match c.read(&mut buf) {
            Ok(0) => return (got, true),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => return (got, false),
        }
    }
}

fn run_rust(home: &Path, steps: &[Step]) -> Vec<String> {
    let mut out = Vec::new();
    let mut devs = Devices(Vec::new());
    let mut clients: Vec<TcpStream> = Vec::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind client listener");
    for s in steps {
        match s {
            Step::Dev(id, sid) => {
                let session = Session {
                    id: sid.to_vec(),
                    tokens: tokens::TokenStore::with_home(home),
                };
                let (dev, init) = devices::go_online(id, b"usb", b"castle-linux", Some(session));
                let idx = devs.0.len();
                devs.0.push(FakeDevice {
                    mux: Arc::clone(&dev),
                    rx_seq: 0,
                });
                if let Some(init) = init {
                    let p = dev
                        .get_tx_packet(Duration::from_secs(5), PACKET_LEN)
                        .expect("channel open request");
                    record(&mut out, idx, &dev, &p);
                    init.join().expect("init thread");
                }
                drain(&mut out, &devs);
            }
            Step::Cmd(c) => {
                let client = TcpStream::connect(listener.local_addr().expect("addr"))
                    .expect("connect client");
                let (server, _) = listener.accept().expect("accept client");
                clients.push(client);
                cmdservice::register_command(Some(server), c);
                drain(&mut out, &devs);
            }
            Step::Reply(d, data) => {
                let dev = &mut devs.0[*d];
                dev.rx_seq += 1;
                let p = packet(0, CHANNEL_CMDSERVICE, dev.rx_seq, data);
                dev.mux.process_packet(&p, p.len());
                drain(&mut out, &devs);
            }
            Step::Unregister(d) => devices::go_offline(&devs.0[*d].mux),
        }
    }
    for (k, c) in clients.iter_mut().enumerate() {
        let (data, closed) = client_state(c);
        let state = if closed { "closed" } else { "open" };
        out.push(format!("K {k} {} {state}", hex(&data)));
    }
    out
}

/// Runs `steps` through C and Rust with identical seeded homes, compares
/// the transcripts and token directories, and returns the C transcript
/// and the C home.
fn differential(name: &str, seed: &[(&[u8], Vec<u8>)], steps: &[Step]) -> (Vec<String>, PathBuf) {
    let _s = super::session();
    super::guard::assert_safe_to_start();
    let before = real_nova_state();
    let c_home = fresh_home(name, "c", seed);
    let r_home = fresh_home(name, "rust", seed);
    let c = run_c(&c_home, steps);
    let r = run_rust(&r_home, steps);
    assert_eq!(r, c, "{name}: transcript (left: Rust, right: C)");
    assert_eq!(
        nova_tree(&r_home),
        nova_tree(&c_home),
        "{name}: token directory (left: Rust, right: C)"
    );
    assert_eq!(
        real_nova_state(),
        before,
        "{name}: the real ~/.nova changed"
    );
    (c, c_home)
}

fn reply_line(k: usize, reply: &[u8], closed: bool) -> String {
    let state = if closed { "closed" } else { "open" };
    format!("K {k} {} {state}", hex(reply))
}

#[test]
fn token_lifecycle() {
    let tok = token(300, 7);
    let steps = [
        Step::Dev(DEV1, SID),
        cmd_to("add", DEV1, " pwhash"),
        Step::Reply(0, token_reply(&tok)),
        cmd_to("login", DEV1, "suffix h1"),
        Step::Reply(0, vec![52, 0, 50]),
        cmd_to("LOGINT", &DEV1.to_ascii_uppercase(), " h2"),
        Step::Reply(0, vec![51, 0, 50]),
        cmd("logout dev://"),
        Step::Reply(0, vec![52, 0, 1]),
        cmd_to("remove", DEV1, " pw"),
        Step::Reply(0, vec![52, 0, 71]),
        cmd_to("remove", DEV1, " pw"),
    ];
    let (c, home) = differential("token_lifecycle", &[], &steps);
    let hash = tokens::sha1_hex(&[&tok[..256], SID].concat());
    let remove = [&[71, 0, 0, 0, 0, 2][..], b"pw", &[0, 0, 0, 40], &hash].concat();
    assert!(c.contains(&format!("W 0 50 {}", hex(&remove))), "{c:?}");
    assert_eq!(
        &c[c.len() - 6..],
        [
            reply_line(0, cmdservice::REPLY_OK, true),
            reply_line(1, cmdservice::REPLY_OK, true),
            reply_line(2, cmdservice::REPLY_FAILED, true),
            reply_line(3, cmdservice::REPLY_OK, true),
            reply_line(4, cmdservice::REPLY_OK, true),
            reply_line(5, cmdservice::REPLY_ERR, true),
        ]
    );
    // The C side used the temp home (getpwuid override), and the token is
    // gone again after `remove`.
    assert!(home.join(".nova").is_dir());
    assert!(
        !home
            .join(".nova")
            .join(std::ffi::OsStr::from_bytes(DEV1))
            .exists()
    );
}

#[test]
fn token_is_stored_in_the_temp_home() {
    let tok = token(256, 3);
    let steps = [
        Step::Dev(DEV1, SID),
        cmd_to("add", DEV1, " pw"),
        Step::Reply(0, token_reply(&tok)),
    ];
    let (_, home) = differential("token_store", &[], &steps);
    let file = home.join(".nova").join(std::ffi::OsStr::from_bytes(DEV1));
    assert_eq!(fs::read(file).expect("C token file"), tok);
}

#[test]
fn automatic_token_login() {
    let tok = token(260, 11);
    let steps = [
        Step::Dev(DEV1, SID),
        cmd_to("add", DEV1, " pw"),
        Step::Reply(0, vec![52, 0, 50]),
        Step::Reply(0, token_reply(b"new")),
    ];
    let (c, home) = differential("auto_logint", &[(DEV1, tok.clone())], &steps);
    let hash = tokens::sha1_hex(&[&tok[..256], SID].concat());
    let logint = [&[50, 0, 0, 0, 0, 5][..], b"token", &[0, 0, 0, 40], &hash].concat();
    assert_eq!(c[0], "O 0 50 1");
    assert_eq!(c[1], format!("W 0 50 {}", hex(&logint)));
    let file = home.join(".nova").join(std::ffi::OsStr::from_bytes(DEV1));
    assert_eq!(fs::read(file).expect("C token file"), b"new");
}

#[test]
fn no_automatic_login_without_usable_token_or_session() {
    let steps = [
        // Token present, but the session id is not 10 bytes long.
        Step::Dev(DEV1, b"a1b2c3d4e"),
        // Token shorter than 256 bytes.
        Step::Dev(DEV2, SID),
        // No session id: no service.
        Step::Dev(b"nosession", b""),
        cmd("login dev:// h"),
        cmd_to("login", DEV2, " h"),
        Step::Reply(1, vec![52, 0, 50]),
        cmd_to("remove", DEV1, " pw"),
        cmd_to("remove", DEV2, " pw"),
        cmd("login dev://nomatch h"),
        cmd_to("bogus", DEV1, " h"),
        cmd("login"),
        cmd_to("login", DEV2, ""),
    ];
    let seed: [(&[u8], Vec<u8>); 2] = [(DEV1, token(256, 1)), (DEV2, token(255, 2))];
    let (c, _) = differential("no_auto_logint", &seed, &steps);
    assert!(!c.iter().any(|l| l.starts_with("W 0 ")), "{c:?}");
    assert_eq!(
        &c[c.len() - 8..],
        [
            reply_line(0, cmdservice::INVALID_COMMAND, true),
            reply_line(1, cmdservice::REPLY_OK, true),
            reply_line(2, cmdservice::REPLY_ERR, true),
            reply_line(3, cmdservice::REPLY_ERR, true),
            reply_line(4, cmdservice::INVALID_COMMAND, true),
            reply_line(5, b"", true),
            reply_line(6, b"", true),
            reply_line(7, cmdservice::REPLY_ERR, true),
        ]
    );
}

#[test]
fn device_choice_by_prefix() {
    let steps = [
        Step::Dev(DEV1, SID),
        Step::Dev(DEV1_PREFIX, b"z9y8x7w6v5"),
        // DEV1_PREFIX is listed first and prefixes DEV1 (D33).
        cmd_to("login", DEV1, " a"),
        Step::Reply(1, vec![52, 0, 50]),
        cmd("login dev:// b"),
        Step::Reply(1, vec![52, 0, 50]),
        Step::Unregister(1),
        cmd_to("login", DEV1, " c"),
        Step::Reply(0, vec![52, 0, 50]),
        cmd_to("login", &DEV1[..39], " d"),
    ];
    let (c, _) = differential("prefix", &[], &steps);
    assert!(c.contains(&"W 1 50 32000000000870617373776f72640000000161".to_string()));
    assert!(c.contains(&"W 0 50 32000000000870617373776f72640000000163".to_string()));
    assert_eq!(
        c.last(),
        Some(&reply_line(3, cmdservice::INVALID_COMMAND, true))
    );
}

#[test]
fn unregister_drops_pending_commands() {
    let steps = [
        Step::Dev(DEV1, SID),
        cmd_to("login", DEV1, " h"),
        cmd_to("logout", DEV1, ""),
        cmd_to("add", DEV1, " pw"),
        Step::Unregister(0),
        cmd_to("login", DEV1, " h"),
    ];
    let (c, _) = differential("unregister", &[], &steps);
    assert_eq!(
        &c[c.len() - 4..],
        [
            reply_line(0, b"", false),
            reply_line(1, b"", true),
            reply_line(2, b"", true),
            reply_line(3, cmdservice::INVALID_COMMAND, true),
        ]
    );
}

#[test]
fn request_size_limits() {
    let h = |n: usize| "h".repeat(n);
    let mut steps = vec![Step::Dev(DEV1, SID)];
    for (verb, max) in [("login", 82), ("logint", 85), ("add", 94), ("remove", 50)] {
        steps.push(cmd(&format!("{verb} dev:// {}", h(max))));
        steps.push(Step::Reply(0, vec![51, 0, 71]));
        steps.push(cmd(&format!("{verb} dev:// {}", h(max + 1))));
    }
    let (c, _) = differential("size_limits", &[(DEV1, token(256, 5))], &steps);
    let writes = c.iter().filter(|l| l.starts_with("W ")).count();
    // One automatic logint, then one request per verb.
    assert_eq!(writes, 5, "{c:?}");
}

#[test]
fn reply_variants() {
    let replies: Vec<Vec<u8>> = vec![
        vec![],
        vec![52, 0],
        vec![52, 0, 50],
        vec![51, 0, 50],
        vec![75, 9, 50, 1],
        vec![0, 0, 1],
        vec![51, 0, 1],
        vec![52, 0, 99],
        vec![52, 0, 70],
        vec![51, 0, 70],
        token_reply(b""),
        vec![75, 0, 70, 0, 0, 0],
        vec![75, 0, 70, 0, 0, 0, 4, 1, 2, 3],
        [token_reply(b"tok"), b"trailing".to_vec()].concat(),
        vec![75, 0, 71],
        vec![51, 0, 71],
        vec![52, 0, 71],
    ];
    // An unsolicited reply first: ignored.
    let mut steps = vec![Step::Dev(DEV1, SID), Step::Reply(0, vec![52, 0, 71])];
    for r in &replies {
        steps.push(cmd("logout dev://"));
        steps.push(Step::Reply(0, r.clone()));
    }
    let (c, _) = differential("replies", &[(DEV1, b"short".to_vec())], &steps);
    assert_eq!(
        c.iter().filter(|l| l.ends_with(" closed")).count(),
        replies.len()
    );
}
