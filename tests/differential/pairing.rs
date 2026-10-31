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
    let mut child = Command::new(path)
        .arg0(arg0)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("POSIXLY_CORRECT")
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", path.display()));
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
