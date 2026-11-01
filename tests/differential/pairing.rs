//! Pairing: every daemon (C novacomd, rovacomd, rovacomd invoked as
//! `novacomd`) driven by every client (C novacom, rovacom, rovacom invoked
//! as `novacom`) with one fake inet device. `-l` output and device lookup
//! (`-d <id> -c logout`: found, so the daemon answers `invalid command`;
//! unknown id: `unable to find device`) must agree across all pairings.
//!
//! Client binaries: `ROVACOMD_C_CLIENT` (default
//! `../rovacom/reference/novacom/build-novacom/novacom`) and
//! `ROVACOMD_RUST_CLIENT` (default `../rovacom/target/debug/rovacom`,
//! built with `cargo build --manifest-path ../rovacom/Cargo.toml`). A
//! missing client fails the test.

use super::*;

const DEV: &[u8; 40] = b"fedcba9876543210fedcba9876543210fedcba98";
const DEV_STR: &str = "fedcba9876543210fedcba9876543210fedcba98";

fn c_client() -> PathBuf {
    required_file(
        "ROVACOMD_C_CLIENT",
        manifest_dir().join("../rovacom/reference/novacom/build-novacom/novacom"),
        "build the C client with ../rovacom/scripts/build-reference.sh",
    )
}

fn rust_client() -> PathBuf {
    required_file(
        "ROVACOMD_RUST_CLIENT",
        manifest_dir().join("../rovacom/target/debug/rovacom"),
        "build it with `cargo build --manifest-path ../rovacom/Cargo.toml`",
    )
}

/// Runs a client to completion (at most [`TIMEOUT`]).
fn run_client(path: &Path, arg0: &str, args: &[&str]) -> Outcome {
    run_client_with(path, arg0, args, None)
}

/// Runs a client with `stdin` piped in (or no stdin).
fn run_client_with(path: &Path, arg0: &str, args: &[&str], stdin: Option<&[u8]>) -> Outcome {
    let mut child = Command::new(path)
        .arg0(arg0)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("POSIXLY_CORRECT")
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", path.display()));
    if let (Some(data), Some(mut w)) = (stdin, child.stdin.take()) {
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = w.write_all(&data);
        });
    }
    let out = spawn_reader(child.stdout.take().expect("stdout"));
    let err = spawn_reader(child.stderr.take().expect("stderr"));
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("client {} {args:?} timed out", path.display());
        }
        std::thread::sleep(POLL);
    };
    Outcome {
        status: status_string(status),
        stdout: out.join().expect("stdout"),
        stderr: err.join().expect("stderr"),
    }
}

/// What one client saw from one daemon.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    list: Outcome,
    found: Outcome,
    missing: Outcome,
}

#[test]
fn every_client_with_every_daemon() {
    let (c_client, rust_client) = (c_client(), rust_client());
    let daemon_alias = Alias::new(&rovacomd(), "novacomd");
    let client_alias = Alias::new(&rust_client, "novacom");
    let daemons = [
        ("C novacomd", Bin::c_alias()),
        ("rovacomd", Bin::rust()),
        ("rovacomd as novacomd", Bin::rust_alias(&daemon_alias)),
    ];
    let clients: [(&str, &Path, &str); 3] = [
        ("C novacom", &c_client, "novacom"),
        ("rovacom", &rust_client, "rovacom"),
        ("rovacom as novacom", client_alias.path(), "novacom"),
    ];
    let _s = session();
    let mut seen: Vec<(String, Seen)> = Vec::new();
    for (dname, bin) in &daemons {
        let mut d = Daemon::spawn(bin, &[]);
        d.wait_ready();
        let _dev = FakeDevice::connect(DEV);
        let list = wait_list(|l| lines(l) == 1);
        let port = format!("{} ", split_ports(&list)[0].0);
        for (cname, path, arg0) in &clients {
            let mask = |mut o: Outcome| {
                o.stdout = replace_all(&o.stdout, port.as_bytes(), b"<P> ");
                o
            };
            let s = Seen {
                list: mask(run_client(path, arg0, &["-l"])),
                found: mask(run_client(path, arg0, &["-d", DEV_STR, "-c", "logout"])),
                missing: mask(run_client(
                    path,
                    arg0,
                    &["-d", "nosuchdevice", "-c", "logout"],
                )),
            };
            seen.push((format!("{cname} with {dname}"), s));
        }
        let out = d.stop();
        assert_eq!(out.stderr, b"", "{dname}");
    }
    let (first_name, first) = &seen[0];
    for (name, s) in &seen[1..] {
        assert_eq!(s, first, "{name} differs from {first_name}");
    }
    assert_eq!(first.list.status, "exit 0");
    assert!(
        first.list.stdout.windows(40).any(|w| w == DEV),
        "{:?}",
        first.list
    );
    assert_eq!(first.missing.status, "exit 1");
    assert_eq!(first.missing.stderr, b"unable to find device\n");
    assert_eq!(first.found.status, "exit 1");
    assert_ne!(first.found.stderr, first.missing.stderr, "device found");
}

/// Commands run by every client against every daemon, with the stdin
/// piped in and the expected (exit, stdout, stderr).
const STDIN: &[u8] = b"line one\nline\0two\n";

/// Client arguments, piped stdin, expected outcome.
type Case = (Vec<&'static str>, Option<&'static [u8]>, Outcome);

fn command_cases() -> Vec<Case> {
    let o = |code: i32, out: &[u8], err: &[u8]| Outcome {
        status: format!("exit {code}"),
        stdout: out.to_vec(),
        stderr: err.to_vec(),
    };
    vec![
        (
            vec!["-d", DEV_STR, "--", "run", "file:///bin/echo", "hi"],
            None,
            o(0, b"hi\n", b""),
        ),
        (
            vec!["-d", DEV_STR, "run", "file:///bin/cat"],
            Some(STDIN),
            o(0, STDIN, b""),
        ),
        (
            vec!["-d", DEV_STR, "run", "file:///bin/false"],
            None,
            // The clients print this for any non-zero return code.
            o(3, b"", b"failed\nnovacom: unexpected EOF from server\n"),
        ),
    ]
}

/// Payloads of complete stream packets in `s`: (type, payload).
fn stream_packets(mut s: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut v = Vec::new();
    while s.len() >= 16 {
        let w = |i: usize| u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]);
        let (size, kind) = (w(8) as usize, w(12));
        if s.len() < 16 + size {
            break;
        }
        v.push((kind, s[16..16 + size].to_vec()));
        s = &s[16 + size..];
    }
    v
}

/// The fake device's command interpreter for one channel: `echo`, `cat`
/// (stdin echoed until the client's OOB EOF) and `false` (exit 3).
fn serve_command(dev: &pmux::Pmux, ch: u32) {
    use pmux::*;
    let line = dev.wait_line(ch);
    let cmd = String::from_utf8_lossy(&line).into_owned();
    assert!(dev.send(ch, b"ok 0\n"));
    if let Some(args) = cmd.strip_prefix("run file:///bin/echo ") {
        assert!(dev.send(ch, &stream_packet(S_DATA, args.as_bytes())));
        let _ = dev.send(ch, &oob(OOB_RETURN, 0));
    } else if cmd == "run file:///bin/cat\n" {
        let is_eof = |p: &(u32, Vec<u8>)| p.0 == S_OOB && p.1.first() == Some(&(OOB_EOF as u8));
        let s = dev.wait_stream(ch, |s| stream_packets(&s[line.len()..]).iter().any(is_eof));
        let echoed: Vec<u8> = stream_packets(&s[line.len()..])
            .into_iter()
            .take_while(|p| !is_eof(p))
            .filter(|p| p.0 == S_DATA)
            .flat_map(|p| p.1)
            .collect();
        assert!(dev.send(ch, &stream_packet(S_DATA, &echoed)));
        let _ = dev.send(ch, &oob(OOB_RETURN, 0));
    } else if cmd == "run file:///bin/false\n" {
        assert!(dev.send(ch, &stream_packet(S_ERR, b"failed\n")));
        let _ = dev.send(ch, &oob(OOB_RETURN, 3));
    } else {
        panic!("unexpected command {cmd:?}");
    }
    // The client exits after the return code; the host closes the channel.
    // That close can drop the host's ack of the return code (a C race,
    // kept), so the last send above may end without an ack.
    dev.wait_control(CLOSE, ch);
}

#[test]
fn commands_with_every_client_and_daemon() {
    let (c_client, rust_client) = (c_client(), rust_client());
    let daemon_alias = Alias::new(&rovacomd(), "novacomd");
    let client_alias = Alias::new(&rust_client, "novacom");
    let daemons = [
        ("C novacomd", Bin::c_alias()),
        ("rovacomd", Bin::rust()),
        ("rovacomd as novacomd", Bin::rust_alias(&daemon_alias)),
    ];
    let clients: [(&str, &Path, &str); 3] = [
        ("C novacom", &c_client, "novacom"),
        ("rovacom", &rust_client, "rovacom"),
        ("rovacom as novacom", client_alias.path(), "novacom"),
    ];
    let cases = command_cases();
    let _s = session();
    for (dname, bin) in &daemons {
        let mut d = Daemon::spawn(bin, &[]);
        d.wait_ready();
        let dev = std::sync::Arc::new(pmux::Pmux::connect(DEV));
        wait_list(|l| lines(l) == 1);
        let runs = clients.len() * cases.len();
        let server = {
            let dev = std::sync::Arc::clone(&dev);
            std::thread::spawn(move || {
                for n in 0..runs {
                    let ch = dev.wait_open(n);
                    serve_command(&dev, ch);
                }
            })
        };
        for (cname, path, arg0) in &clients {
            for (args, stdin, want) in &cases {
                let got = run_client_with(path, arg0, args, *stdin);
                assert_eq!(&got, want, "{cname} with {dname}: {args:?}");
            }
        }
        server
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        let t = dev.transcript();
        assert!(t.anomalies.is_empty(), "{dname}: {:?}", t.anomalies);
        let out = d.stop();
        assert_eq!(out.stderr, b"", "{dname}");
    }
}
