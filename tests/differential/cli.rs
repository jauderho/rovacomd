//! Command line, usage, version and early exits (ASSESSMENT 3.2, 4.13).
//! Every case ends before the daemon binds a port; a case that does not
//! would time out and fail.

use super::*;

/// Runs C and Rust with `args` and asserts identical outcomes.
fn check(args: &[&str]) -> Outcome {
    let _s = session();
    let c = run(&Bin::c(), args);
    let r = run(&Bin::rust(), args);
    assert_eq!(r, c, "args {args:?}");
    r
}

/// Usage text as the daemon prints it (normalized timestamps).
fn usage() -> Vec<u8> {
    rovacomd::cli::USAGE_LINES
        .iter()
        .flat_map(|l| [&b"[TS] "[..], l].concat())
        .collect()
}

fn version() -> Vec<u8> {
    format!("[TS] novacomd version {}\n", rovacomd::cli::VERSION).into_bytes()
}

#[test]
fn version_and_help() {
    for args in [
        &["-V"][..],
        &["--version"],
        &["--vers"],
        &["x", "y", "-V"],
        &["-V", "-Z"],
    ] {
        let o = check(args);
        assert_eq!(o.status, "exit 1");
        assert_eq!(o.stdout, version(), "{args:?}");
        assert_eq!(o.stderr, b"");
    }
    let o = check(&["-h"]);
    assert_eq!(
        (o.status.as_str(), o.stdout, o.stderr),
        ("exit 1", usage(), Vec::new())
    );
}

#[test]
fn getopt_errors() {
    for args in [
        &["-Z"][..],
        &["--bogus"],
        &["-t"],
        &["--connect-ip"],
        &["--co"],
        &["--vers=1"],
        &["--=x"],
        &["-Z", "-V"],
    ] {
        let o = check(args);
        assert_eq!(o.status, "exit 1", "{args:?}");
        assert_eq!(o.stdout, usage(), "{args:?}");
        assert!(
            o.stderr
                .ends_with(b"[TS] Invalid command line option or parameter\n"),
            "{o:?}"
        );
    }
    // glibc rejects the '-' in the cluster; macOS reads "--version".
    let o = check(&["-b-version"]);
    assert_eq!(o.status, "exit 1");
}

#[test]
fn recovery_timeout_validation() {
    for t in ["1", "6", "junk", "-3", "99999999999999999999"] {
        let o = check(&["-t", t]);
        assert_eq!(o.status, "exit 1");
        assert_eq!(o.stdout, usage());
        assert_eq!(
            o.stderr,
            format!(
                "[TS] Invalid timeout out of range(2~5 seconds): {t} \n\
                 [TS] Invalid command line option or parameter\n"
            )
            .into_bytes()
        );
    }
    // Valid values (2..5 after int truncation of atol) pass; -V ends.
    for t in ["2", "5", " +3x", "4294967298"] {
        assert_eq!(check(&["-t", t, "-V"]).stdout, version(), "-t {t:?}");
    }
    // Messages are cut to the C 256-byte buffer (no newline left).
    let long = "x".repeat(300);
    let o = check(&["-t", &long]);
    let first = o.stderr.split(|&b| b == b'[').nth(1).expect("message");
    assert!(!first.ends_with(b"\n"), "{o:?}");
}

#[test]
fn accepted_options_then_version() {
    for args in [
        &["-e", "600", "-s", "700", "-V"][..],
        &["-e", "-5", "-s", "junk", "-C", "-V"],
        &["-b", "-d", "-V"],
        &["--bind-all-interfaces", "--daemonize", "-V"],
    ] {
        assert_eq!(check(args).stdout, version(), "{args:?}");
    }
}

#[test]
fn connect_option_logs_target() {
    // Numeric hosts only: on macOS a failed lookup crashes the C daemon (D5).
    let cases = [
        ("127.0.0.1:1", "127.0.0.1/1"),
        ("127.0.0.1 1", "127.0.0.1/1"),
        ("127.0.0.1:", "127.0.0.1/6969"),
        ("127.0.0.1", "127.0.0.1/6969"),
    ];
    for (arg, shown) in cases {
        for args in [["-c", arg, "-V"], ["--connect-ip", arg, "-V"]] {
            let o = check(&args);
            let want = [
                format!("[TS] Connecting to {shown} via IP\n").into_bytes(),
                version(),
            ]
            .concat();
            assert_eq!(o.stdout, want, "{args:?}");
        }
    }
}

/// Invoked as `novacomd`, rovacomd prints the same diagnostics as C.
#[test]
fn alias_invocation() {
    let alias = Alias::new(&rovacomd(), "novacomd");
    let _s = session();
    for args in [&["-Z"][..], &["--bogus"], &["-t"], &["-V"], &["-h"]] {
        let c = run(&Bin::c_alias(), args);
        let r = run(&Bin::rust_alias(&alias), args);
        assert_eq!(r, c, "alias {args:?}");
    }
    let o = run(&Bin::rust_alias(&alias), &["-Z"]);
    assert!(o.stderr.starts_with(b"novacomd: "), "{o:?}");
}
