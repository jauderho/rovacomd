//! Running daemons (ASSESSMENT 8.2): listeners, single instance, bind
//! failures, `-d`, inet devices (syn, registration, duplicates, keepalive,
//! disconnect), device list, control port, option port, `-c`, `-b`.
//!
//! Each scenario runs against the C reference, then against rovacomd, and
//! the observations must be equal. Daemons are stopped through the option
//! port (`version`), which flushes their stdout.

use super::*;
use std::collections::BTreeSet;
use std::net::TcpListener;

const A: &[u8; 40] = b"aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd";
const A_UPPER: &[u8; 40] = b"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDD";
const B: &[u8; 40] = b"0123456789abcdef0123456789abcdef01234567";

/// Runs `scenario` for C, then Rust; asserts equal results.
fn differential<T: PartialEq + fmt::Debug>(scenario: impl Fn(&Bin) -> T) -> T {
    let _s = session();
    let c = scenario(&Bin::c());
    let r = scenario(&Bin::rust());
    assert_eq!(r, c, "rovacomd (left) differs from C (right)");
    r
}

fn start(bin: &Bin, args: &[&str]) -> Daemon {
    let mut d = Daemon::spawn(bin, args);
    d.wait_ready();
    d
}

/// `[TS] <line>` for each line.
fn ts_lines(lines: &[&[u8]]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|l| [&b"[TS] "[..], l, b"\n"].concat())
        .collect()
}

fn version_line() -> Vec<u8> {
    format!("novacomd version {}", rovacomd::cli::VERSION).into_bytes()
}

/// Replaces the number after each `", port "` with `<P>`.
fn mask_dup_ports(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if text[i..].starts_with(b"', port ") {
            out.extend_from_slice(b"', port <P>");
            i += 8;
            while i < text.len() && text[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

/// Listeners of the daemon once port 6969 is up; ports other than the
/// fixed ones are shown as 0.
fn listeners(d: &Daemon) -> BTreeSet<(String, u16)> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let l = guard::pid_listeners(d.pid());
        if l.iter().any(|(_, p)| *p == 6969) {
            return l
                .into_iter()
                .map(|(a, p)| {
                    (
                        a,
                        if guard::FIXED_PORTS.contains(&p) {
                            p
                        } else {
                            0
                        },
                    )
                })
                .collect();
        }
        assert!(Instant::now() < deadline, "no listener on 6969: {l:?}");
        std::thread::sleep(POLL);
    }
}

fn set(entries: &[(&str, u16)]) -> BTreeSet<(String, u16)> {
    entries.iter().map(|&(a, p)| (a.to_string(), p)).collect()
}

/// Waits for EOF from the daemon on `s`; returns the bytes read.
fn read_until_eof(s: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    buf
}

#[test]
fn startup_listeners_empty_list_and_stop() {
    let (ls, list, ctrl, out) = differential(|bin| {
        let d = start(bin, &[]);
        let ls = listeners(&d);
        (
            ls,
            devlist(),
            send_raw(6971, b"list host://", false),
            d.stop(),
        )
    });
    let lo = "127.0.0.1";
    assert_eq!(
        ls,
        set(&[
            (lo, 6968),
            (lo, 6969),
            (lo, 6970),
            (lo, 6971),
            (lo, 12311),
            (lo, 64022)
        ])
    );
    assert_eq!((list, ctrl), (Vec::new(), Vec::new()));
    assert_eq!(out.status, "exit 1");
    assert_eq!(out.stdout, ts_lines(&[&version_line()]));
    assert_eq!(out.stderr, b"");
}

#[test]
fn devices_list_keepalive_and_disconnect() {
    let r = differential(|bin| {
        let d = start(bin, &[]);
        let mut a = FakeDevice::connect(A);
        assert_host_syn(&a.host_syn);
        let one = wait_list(|l| lines(l) == 1);
        let b = FakeDevice::connect(B);
        assert_host_syn(&b.host_syn);
        let two = wait_list(|l| lines(l) == 2);
        // Ports: distinct, listening on loopback, A's unchanged.
        let ports = split_ports(&two);
        assert_ne!(ports[0].0, ports[1].0);
        assert_eq!(split_ports(&one)[0].0, ports[1].0);
        let ls = guard::pid_listeners(d.pid());
        for (p, _) in &ports {
            assert!(ls.contains(&("127.0.0.1".to_string(), *p)), "{p} in {ls:?}");
        }
        let via_ctrl = send_raw(6971, b"list host://", false);
        assert_eq!(via_ctrl, two, "list host:// equals the 6968 list");
        // Keepalives: every 2 s while idle.
        let h1 = a.read_header();
        let t1 = Instant::now();
        let h2 = a.read_header();
        let gap = t1.elapsed();
        assert!(
            (Duration::from_millis(1500)..Duration::from_millis(3000)).contains(&gap),
            "keepalive gap {gap:?}"
        );
        drop(a); // peer EOF
        let after = wait_list(|l| lines(l) == 1);
        drop(b);
        (
            mask_ports(&one),
            mask_ports(&two),
            mask_ports(&after),
            h1,
            h2,
            d.stop(),
        )
    });
    let (one, two, after, h1, h2, out) = r;
    let line = |id: &[u8]| [&b"<P> "[..], id, b" tcp emulator\n"].concat();
    assert_eq!(one, line(A));
    assert_eq!(two, [line(B), line(A)].concat(), "newest first");
    assert_eq!(after, line(B));
    assert_eq!((h1, h2), (keepalive(), keepalive()));
    let online = |id: &[u8]| [&b"novacom_go_online:"[..], id].concat();
    let dev = |id: &[u8]| [&b"dev '"[..], id, b"' via tcp type emulator"].concat();
    assert_eq!(
        out.stdout,
        ts_lines(&[
            &online(A),
            &dev(A),
            &online(B),
            &dev(B),
            &[&b"removing id "[..], A].concat(),
            &version_line(),
        ])
    );
    assert_eq!(out.stderr, b"");
}

#[test]
fn duplicate_nduids_replace_older_devices() {
    let (lists, out) = differential(|bin| {
        let d = start(bin, &[]);
        let old = FakeDevice::connect(A);
        let l1 = wait_list(|l| lines(l) == 1);
        let _new = FakeDevice::connect(A_UPPER);
        let l2 = wait_list(|l| l.windows(40).any(|w| w == A_UPPER));
        assert_ne!(split_ports(&l1)[0].0, split_ports(&l2)[0].0);
        // A shorter listed id that prefixes the new id is a duplicate too.
        let _short = FakeDevice::connect(b"abc");
        let l3 = wait_list(|l| lines(l) == 2);
        let _long = FakeDevice::connect(b"ABCdefghijklmnopqrstuvwxyz0123456789ABCD");
        let l4 = wait_list(|l| l.windows(4).any(|w| w == b"ABCd") && lines(l) == 2);
        // The replaced link ending later removes nothing.
        drop(old);
        std::thread::sleep(Duration::from_millis(2500));
        let l5 = devlist();
        let lists = [l2, l3, l4, l5].map(|l| mask_ports(&l));
        let mut out = d.stop();
        out.stdout = mask_dup_ports(&out.stdout);
        (lists, out)
    });
    let line = |id: &[u8]| [&b"<P> "[..], id, b" tcp emulator\n"].concat();
    let long: &[u8] = b"ABCdefghijklmnopqrstuvwxyz0123456789ABCD";
    assert_eq!(lists[0], line(A_UPPER));
    assert_eq!(lists[1], [line(b"abc"), line(A_UPPER)].concat());
    assert_eq!(lists[2], [line(long), line(A_UPPER)].concat());
    assert_eq!(lists[3], lists[2]);
    let online = |id: &[u8]| [&b"novacom_go_online:"[..], id].concat();
    let dev = |id: &[u8]| [&b"dev '"[..], id, b"' via tcp type emulator"].concat();
    let dup = |id: &[u8]| [&b"duplicate: '"[..], id, b"', port <P>"].concat();
    let rm = |id: &[u8]| [&b"removing id "[..], id].concat();
    assert_eq!(
        out.stdout,
        ts_lines(&[
            &online(A),
            &dev(A),
            &online(A_UPPER),
            &dev(A_UPPER),
            &dup(A),
            &rm(A),
            &online(b"abc"),
            &dev(b"abc"),
            &online(long),
            &dev(long),
            &dup(b"abc"),
            &rm(b"abc"),
            &version_line(),
        ])
    );
}

#[test]
fn bad_syn_and_bad_frames() {
    let (lists, out) = differential(|bin| {
        let d = start(bin, &[]);
        // Wrong magic: the daemon closes, no device.
        let mut s = FakeDevice::connect_raw();
        FakeDevice::read_host_syn(&mut s);
        let mut bad = syn(B);
        bad[0] = b'N';
        s.write_all(&bad).expect("send");
        let _ = s.shutdown(Shutdown::Write); // wakes the C reader on Linux
        let a = read_until_eof(&mut s);
        // Short syn, then EOF.
        let mut s = FakeDevice::connect_raw();
        FakeDevice::read_host_syn(&mut s);
        s.write_all(&syn(B)[..10]).expect("send");
        let _ = s.shutdown(Shutdown::Write);
        let b = read_until_eof(&mut s);
        // No syn at all.
        let mut s = FakeDevice::connect_raw();
        FakeDevice::read_host_syn(&mut s);
        let _ = s.shutdown(Shutdown::Write);
        let c = read_until_eof(&mut s);
        let empty = devlist();
        // Registered devices: wrong frame magic, oversize frame, short body.
        let mut lists = vec![a, b, c, empty];
        for (id, frame) in [
            (
                b"e".as_slice(),
                [&b"ELTSDIX\0"[..], &0u32.to_ne_bytes()].concat(),
            ),
            (b"f", [&b"ELTSDIM\0"[..], &4097u32.to_ne_bytes()].concat()),
            (
                b"g",
                [&b"ELTSDIM\0"[..], &100u32.to_ne_bytes(), &[0u8; 10]].concat(),
            ),
        ] {
            let mut dev = FakeDevice::connect(id);
            wait_list(|l| lines(l) == 1);
            if id == b"g" {
                // A pmux-sized garbage packet and an empty frame are accepted.
                let ok = [&b"ELTSDIM\0"[..], &28u32.to_ne_bytes(), &[0u8; 28]].concat();
                dev.s.write_all(&ok).expect("send");
                dev.s.write_all(&keepalive()).expect("send");
                std::thread::sleep(Duration::from_millis(300));
                lists.push(mask_ports(&devlist()));
            }
            dev.s.write_all(&frame).expect("send");
            let _ = dev.s.shutdown(Shutdown::Write);
            // The device leaves after the tx thread's current 2 s wait.
            wait_list(<[u8]>::is_empty);
        }
        (lists, d.stop())
    });
    assert_eq!(
        &lists[..4],
        &[Vec::new(), Vec::new(), Vec::new(), Vec::new()]
    );
    assert_eq!(lists[4], b"<P> g tcp emulator\n");
    assert_eq!(
        out.stderr,
        ts_lines(&[
            b"invalid connection packet, read(48/48)",
            b"invalid connection packet, read(10/48)",
            b"invalid connection packet, read(0/48)",
        ])
    );
    let mut want: Vec<Vec<u8>> = Vec::new();
    for id in [&b"e"[..], b"f", b"g"] {
        want.push([&b"novacom_go_online:"[..], id].concat());
        want.push([&b"dev '"[..], id, b"' via tcp type emulator"].concat());
        want.push([&b"removing id "[..], id].concat());
    }
    want.push(version_line());
    let want: Vec<&[u8]> = want.iter().map(Vec::as_slice).collect();
    assert_eq!(out.stdout, ts_lines(&want));
}

#[test]
fn control_port_commands() {
    let a_logout = [&b"logout dev://"[..], A, b"\n"].concat();
    let a_remove = [&b"remove dev://"[..], A, b" pw"].concat();
    let cases: Vec<(&[u8], bool)> = vec![
        (b"list host://", false),
        (b"  LIST  Host://  \r\n", false),
        (b"list a b host://x y", false),
        (b"list\0 host://", false),
        (b"bogus x://", false),
        (b"list", false),
        (b"list dev://", false),
        (b"", true),
        (&[b'a'; 127], false),
        (b"login dev://x hash", false),
        (&a_logout, false),
        (b"add dev://", false),
        (&a_remove, false),
        (b"LOGINT DEV://a", false),
        (b"lo\\gin dev://x h", false),
    ];
    let replies = differential(|bin| {
        let d = start(bin, &[]);
        let _a = FakeDevice::connect(A);
        let list = wait_list(|l| lines(l) == 1);
        let port = format!("{} ", split_ports(&list)[0].0);
        let replies: Vec<Vec<u8>> = cases
            .iter()
            .map(|&(cmd, shut)| replace_all(&send_raw(6971, cmd, shut), port.as_bytes(), b"<P> "))
            .collect();
        let out = d.stop();
        (mask_ports(&list), replies, out.stderr)
    });
    let (list, replies, stderr) = replies;
    let invalid = b"invalid command\n\0".to_vec();
    let want: Vec<Vec<u8>> = vec![
        list.clone(),
        list.clone(),
        list,
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        invalid.clone(),
        invalid.clone(),
        invalid.clone(),
        invalid.clone(),
        invalid.clone(),
        invalid,
    ];
    assert_eq!(replies, want);
    assert_eq!(stderr, b"");
}

#[test]
fn option_port_requests() {
    let out = differential(|bin| {
        let d = start(bin, &[]);
        let mut raw = vec![
            send_opt(b"bogus", None),
            send_opt(b"recoverytimeout", Some(b"9")),
            send_opt(b"recoverytimeout", Some(b"3")),
            send_opt(b"connect-ip", Some(b"127.0.0.1:1")),
        ];
        let l0_zero = [&0u32.to_ne_bytes()[..], &5u32.to_ne_bytes(), b"abcd\0"].concat();
        raw.push(send_raw(64022, &l0_zero, true));
        let too_big = [&4000u32.to_ne_bytes()[..], &96u32.to_ne_bytes()].concat();
        raw.push(send_raw(64022, &too_big, true));
        // Still serving.
        let list = devlist();
        let _ = send_opt(b"help", None);
        (raw, list, d.wait_exit())
    });
    let (raw, list, o) = out;
    assert!(raw.iter().all(Vec::is_empty) && list.is_empty());
    assert_eq!(o.status, "exit 1");
    let mut want = ts_lines(&[b"Connecting to 127.0.0.1/1 via IP"]);
    for l in rovacomd::cli::USAGE_LINES {
        want.extend_from_slice(&[&b"[TS] "[..], l].concat());
    }
    assert_eq!(o.stdout, want);
    assert_eq!(
        o.stderr,
        ts_lines(&[b"Invalid timeout out of range(2~5 seconds): 9 "])
    );
}

#[test]
fn single_instance_probe() {
    let out = differential(|bin| {
        let (d, _held) = Daemon::spawn_occupied(bin, &[], &[64022], |_| {});
        d.wait_exit()
    });
    assert_eq!(out.status, "exit 0");
    assert_eq!(out.stdout, ts_lines(&[b"Cannot start novacomd twice!"]));
    assert_eq!(out.stderr, b"");
}

#[test]
fn main_listener_bind_failures() {
    for port in [6968u16, 12311, 6970, 6971] {
        let out = differential(|bin| {
            let (d, _held) = Daemon::spawn_occupied(bin, &[], &[port], |_| {});
            d.wait_exit()
        });
        assert_eq!(out.status, "exit 1", "port {port}");
        assert_eq!(out.stdout, b"");
        assert_eq!(
            out.stderr,
            ts_lines(&[format!("error creating server sockets, port {port}").as_bytes()])
        );
    }
}

#[test]
fn inet_listener_bind_failure_keeps_running() {
    let out = differential(|bin| {
        let (mut d, _held) = Daemon::spawn_occupied(bin, &[], &[6969], |_| {});
        d.wait_ready();
        std::thread::sleep(Duration::from_millis(300));
        d.stop()
    });
    let errno = if cfg!(target_os = "macos") { 48 } else { 98 };
    assert_eq!(
        out.stderr,
        ts_lines(&[format!("Unable to create socket(errno {errno})").as_bytes()])
    );
    assert_eq!(out.stdout, ts_lines(&[&version_line()]));
}

/// A pipe whose write end is inherited by spawned children (no
/// close-on-exec): its read end reports EOF once every holder has exited.
fn inheritable_pipe() -> (std::fs::File, std::os::fd::OwnedFd) {
    use std::os::fd::FromRawFd;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live array of two ints for `pipe` to fill.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe");
    // SAFETY: `pipe` succeeded, so both fds are open and owned only here.
    unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    }
}

/// Prefix of the operand that marks the processes of the `-d` test. The
/// daemons ignore operands (getopt permutes them away).
const DAEMONIZE_MARK: &str = "rovacomd-test-mark-";

/// Pids of processes whose argv has the word `DAEMONIZE_MARK` + `value`.
fn marked_pids(value: &str) -> Vec<u32> {
    let word = format!("{DAEMONIZE_MARK}{value}");
    let out = Command::new("ps")
        .args(["-A", "-ww", "-o", "pid=,args="])
        .output()
        .expect("run ps");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.split_whitespace().skip(1).any(|w| w == word))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok())
        .collect()
}

/// Kills every marked process when dropped (also on panic), before the
/// held 6968 listener is released.
struct Reaper(String);

impl Drop for Reaper {
    fn drop(&mut self) {
        for pid in marked_pids(&self.0) {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
    }
}

#[test]
fn daemonize_parent_exits_zero() {
    let out = differential(|bin| {
        // The child fails to bind 6968 (held here) and exits silently; the
        // pipe tells when it is gone, so the port is released only then.
        // Every process started here carries a marker operand; the reaper (dropped before `held`) kills any that are left.
        let mark = format!("{}-{}", std::process::id(), bin.is_c);
        let operand = format!("{DAEMONIZE_MARK}{mark}");
        let (mut reader, writer) = inheritable_pipe();
        let (d, held) = Daemon::spawn_occupied(bin, &["-d", &operand], &[6968], |_| {});
        let _reaper = Reaper(mark.clone());
        drop(writer);
        let out = d.wait_exit();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = reader.read_to_end(&mut Vec::new());
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(TIMEOUT).is_ok(),
            "daemonized child still running (killed by the reaper)"
        );
        assert_eq!(
            marked_pids(&mark),
            Vec::<u32>::new(),
            "daemonized child left"
        );
        drop(held);
        out
    });
    assert_eq!(out.status, "exit 0");
    assert_eq!(out.stdout, ts_lines(&[b"starting the daemonizing process"]));
    assert_eq!(out.stderr, b"");
}

/// Accepts one connection on `l` within [`TIMEOUT`].
fn accept_within(l: &TcpListener) -> TcpStream {
    l.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).expect("blocking");
                s.set_read_timeout(Some(TIMEOUT)).expect("timeout");
                return s;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "no connection from the daemon");
                std::thread::sleep(POLL);
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

#[test]
fn connect_option_links_out_and_reconnects() {
    let out = differential(|bin| {
        let l = TcpListener::bind((LOCALHOST, 0)).expect("bind");
        let port = l.local_addr().expect("addr").port().to_string();
        let target = format!("127.0.0.1:{port}");
        let d = start(bin, &["-c", &target]);
        let dev = FakeDevice::over(accept_within(&l), A);
        assert_host_syn(&dev.host_syn);
        let one = mask_ports(&wait_list(|l| lines(l) == 1));
        drop(dev);
        wait_list(<[u8]>::is_empty);
        // Reconnect after 1 s; hold it without a syn.
        let _again = accept_within(&l);
        let mut out = d.stop();
        out.stdout = replace_all(&out.stdout, format!("/{port} ").as_bytes(), b"/<P> ");
        (one, out)
    });
    let (one, out) = out;
    assert_eq!(one, [&b"<P> "[..], A, b" tcp emulator\n"].concat());
    assert_eq!(
        out.stdout,
        ts_lines(&[
            b"Connecting to 127.0.0.1/<P> via IP",
            &[&b"novacom_go_online:"[..], A].concat(),
            &[&b"dev '"[..], A, b"' via tcp type emulator"].concat(),
            &[&b"removing id "[..], A].concat(),
            &version_line(),
        ])
    );
}

/// `-b`: 6968, 6969, 6970 and device ports on all interfaces. Linux only:
/// on macOS a wildcard listener triggers the application firewall prompt.
#[cfg(target_os = "linux")]
#[test]
fn bind_all_interfaces() {
    let ls = differential(|bin| {
        let d = start(bin, &["-b"]);
        let _a = FakeDevice::connect(A);
        wait_list(|l| lines(l) == 1);
        let ls = listeners(&d);
        drop(d);
        ls
    });
    let (any, lo) = ("0.0.0.0", "127.0.0.1");
    assert_eq!(
        ls,
        set(&[
            (any, 0),
            (any, 6968),
            (any, 6969),
            (any, 6970),
            (lo, 6971),
            (lo, 12311),
            (lo, 64022)
        ])
    );
}

/// Linux only, a known divergence: C sets `SO_RCVLOWAT` 4096 and reads the
/// 48-byte syn with one blocking `recv`; current kernels wake that reader
/// only once 4096 bytes are queued (or at EOF), so a peer that sends just
/// its syn is never registered. rovacomd reads without the low-water mark
/// (ASSESSMENT P6) and registers it at once. Checked on Linux 7.3.
#[cfg(target_os = "linux")]
#[test]
fn linux_rcvlowat_stall() {
    let _s = session();
    for (bin, want) in [(Bin::c(), 0), (Bin::rust(), 1)] {
        let d = start(&bin, &[]);
        let mut s = FakeDevice::connect_raw();
        FakeDevice::read_host_syn(&mut s);
        s.write_all(&syn(A)).expect("send syn");
        // rovacomd: wait until it registers (a fixed sleep failed under load).
        // C: it never registers; 1 s shows that it did not.
        let wait = if want == 0 {
            Duration::from_secs(1)
        } else {
            TIMEOUT
        };
        let deadline = Instant::now() + wait;
        while lines(&devlist()) != want && Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
        assert_eq!(lines(&devlist()), want, "{}", bin.path.display());
        drop(s);
        drop(d);
    }
}

#[test]
fn reaper_kills_marked_processes() {
    let _s = session(); // no other test's inheritable fds leak in
    let mark = format!("{}-reaper-check", std::process::id());
    // `; :` keeps sh from exec-ing sleep, so the marker stays in its argv.
    let mut child = Command::new("sh")
        .args(["-c", "sleep 5; :", &format!("{DAEMONIZE_MARK}{mark}")])
        .spawn()
        .expect("spawn sh");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(marked_pids(&mark), vec![child.id()]);
    drop(Reaper(mark.clone()));
    let status = child.wait().expect("wait");
    assert_eq!(status.signal(), Some(9));
    assert_eq!(marked_pids(&mark), Vec::<u32>::new());
}

/// Options injected through the option port after startup: none of these
/// prints anything (except the range error) or stops the daemon; `-t` with
/// no value (`l1 = 0`) gets an empty string.
#[test]
fn option_port_injection_keeps_serving() {
    let out = differential(|bin| {
        let d = start(bin, &[]);
        for (name, val) in [
            (&b"daemonize"[..], None),
            (b"no-cpuaffinity", None),
            (b"ioretry_timeout", Some(&b"300"[..])),
            (b"ioretry_delay", Some(b"20")),
            (b"recoverytimeout", None),
        ] {
            assert_eq!(send_opt(name, val), b"");
        }
        let _a = FakeDevice::connect(A);
        let list = mask_ports(&wait_list(|l| lines(l) == 1));
        (list, d.stop())
    });
    let (list, o) = out;
    assert_eq!(list, [&b"<P> "[..], A, b" tcp emulator\n"].concat());
    assert_eq!(o.status, "exit 1");
    assert_eq!(
        o.stderr,
        ts_lines(&[b"Invalid timeout out of range(2~5 seconds):  "])
    );
}

/// `bind-all-interfaces` through the option port: device listen sockets
/// made afterwards bind all interfaces; the fixed ones keep their address.
/// Linux only (macOS prompts for a wildcard listener).
#[cfg(target_os = "linux")]
#[test]
fn option_port_bind_all_affects_new_devices() {
    let ls = differential(|bin| {
        let d = start(bin, &[]);
        assert_eq!(send_opt(b"bind-all-interfaces", None), b"");
        let _a = FakeDevice::connect(A);
        wait_list(|l| lines(l) == 1);
        listeners(&d)
    });
    let (any, lo) = ("0.0.0.0", "127.0.0.1");
    assert_eq!(
        ls,
        set(&[
            (any, 0),
            (lo, 6968),
            (lo, 6969),
            (lo, 6970),
            (lo, 6971),
            (lo, 12311),
            (lo, 64022)
        ])
    );
}

/// Waits until port 6968 answers (a daemonized child has no handle here).
fn wait_port_6968() {
    let deadline = Instant::now() + TIMEOUT;
    while TcpStream::connect((LOCALHOST, 6968)).is_err() {
        assert!(Instant::now() < deadline, "daemon not ready");
        std::thread::sleep(POLL);
    }
}

/// `-d`: the child sets umask 0, so a device's `put` creates mode 0775
/// whatever the caller's umask; the child serves until stopped through the
/// option port. Paths are absolute, inside a temporary directory.
#[test]
fn daemonized_child_serves_put_with_umask_zero() {
    use std::os::unix::fs::PermissionsExt;
    let mode = differential(|bin| {
        let dir = super::devcmd::TempDir::new("daemon");
        let url = dir.url("dst");
        let mark = format!("{}-put-{}", std::process::id(), bin.is_c);
        let operand = format!("{DAEMONIZE_MARK}{mark}");
        let d = Daemon::spawn(bin, &["-d", &operand]);
        let _reaper = Reaper(mark.clone());
        let parent = d.wait_exit();
        assert_eq!(parent.status, "exit 0");
        wait_port_6968();
        let dev = super::pmux::Pmux::connect(A);
        wait_list(|l| lines(l) == 1);
        const CH: u32 = 0x8000_0001;
        dev.send_control(super::pmux::OPEN_COMMAND, CH);
        assert!(dev.send(CH, format!("put file://{url}\n").as_bytes()));
        assert_eq!(dev.wait_line(CH), b"ok 0\n");
        assert!(dev.send(CH, &super::pmux::stream_packet(super::pmux::S_DATA, b"x")));
        assert!(dev.send(CH, &super::pmux::oob(super::pmux::OOB_EOF, 0)));
        dev.wait_control(super::pmux::CLOSE, CH);
        drop(dev);
        let _ = send_opt(b"version", None);
        let deadline = Instant::now() + TIMEOUT;
        while !marked_pids(&mark).is_empty() {
            assert!(Instant::now() < deadline, "daemonized child still running");
            std::thread::sleep(POLL);
        }
        let meta = std::fs::metadata(dir.path("dst")).expect("stat");
        assert_eq!(std::fs::read(dir.path("dst")).expect("read"), b"x");
        assert_eq!(dir.entries().len(), 1);
        meta.permissions().mode() & 0o7777
    });
    assert_eq!(mode, 0o775);
}
