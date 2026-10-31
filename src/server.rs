//! Program flow: emulation of C `main`, `parse_commandline`, `handleopt`,
//! `novacomopt`, the `-d` steps, `main_loop` and the control-port part of
//! `novacom_register_command` / `novacom_service_command`.
//!
//! Main loop (C `select`, here `poll`, P5): the device-list (6968),
//! option (64022), unblock (12311), log (6970) and control (6971)
//! listeners and the accepted unblock connection. Per-device listen
//! sockets and client data sockets join it with the mux (slice 2).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::cli::{self, Getopt, NextOpt, ParseContext};
use crate::{cmdparse, devices, inet, log, net, sys};

/// C `TRANSPORT_RECOVERY_TIMEOUT`.
const RECOVERY_TIMEOUT_DEFAULT: i32 = 5;
/// C `TRANSPORT_USBIO_RETRY_TIMEOUT`.
const USBIO_RETRY_TIMEOUT_DEFAULT: i32 = 100;
/// C `g_usbio_retry_delay` default.
const USBIO_RETRY_DELAY_DEFAULT: i32 = 50;
/// C `TRANSPORT_MAX_USBIO_RETRY_TIMEOUT`: cap of `-e` and `-s`.
const USBIO_RETRY_MAX: i32 = 500;
/// Option port: requests whose lengths sum to this or more are ignored.
const OPT_MAX: u32 = 4096;
/// Control port: C `char cmd[128]`, read with `recv(..., 127)`.
const CTRL_CMD_SIZE: usize = 128;
/// Control-port reply when a device command cannot be queued (NUL included).
const INVALID_COMMAND: &[u8] = b"invalid command\n\0";

/// C globals set by `handleopt`. The USB values are used from slice 4 on.
static LISTEN_ALL: AtomicBool = AtomicBool::new(false);
static DAEMONIZE: AtomicBool = AtomicBool::new(false);
static RECOVERY_TIMEOUT: AtomicI32 = AtomicI32::new(RECOVERY_TIMEOUT_DEFAULT);
static USBIO_RETRY_TIMEOUT: AtomicI32 = AtomicI32::new(USBIO_RETRY_TIMEOUT_DEFAULT);
static USBIO_RETRY_DELAY: AtomicI32 = AtomicI32::new(USBIO_RETRY_DELAY_DEFAULT);

/// C `g_listen_all` (`-b`).
pub fn listen_all() -> bool {
    LISTEN_ALL.load(Ordering::Relaxed)
}

/// C `unblock_fd_write`.
static UNBLOCK_WRITE: Mutex<Option<TcpStream>> = Mutex::new(None);

/// C `unblock_main_loop`: one `0x00` byte to port 12311 over a lazily
/// connected socket. std cannot report a failed `socket()` apart from a
/// failed `connect()`, so both log `unable to connect`.
pub fn unblock_main_loop() {
    let mut w = UNBLOCK_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
    if w.is_none() {
        match TcpStream::connect((Ipv4Addr::LOCALHOST, net::UNBLOCKPORT)) {
            Ok(s) => *w = Some(s),
            Err(_) => {
                log::error(b"unable to connect\n");
                return;
            }
        }
    }
    if let Some(s) = w.as_ref() {
        if (&*s).write(&[0]).is_err() {
            *w = None;
        }
    }
}

/// C `usage()`.
fn usage() {
    for line in cli::USAGE_LINES {
        log::always(line);
    }
}

/// The C string at the start of `b` (up to the first NUL).
fn c_str(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// C `handleopt(opt, val)`. `Err` is the C return value -1.
fn handleopt(opt: &[u8], val: Option<&[u8]>) -> Result<(), ()> {
    let num = || cli::c_atol_int(val.unwrap_or_default());
    match (opt, val) {
        (b"connect-ip", Some(addr)) => {
            // strpbrk(addr, ": "): split at the first ':' or ' '.
            match addr.iter().position(|&b| b == b':' || b == b' ') {
                Some(i) => inet::connect_to(&addr[..i], Some(&addr[i + 1..])),
                None => inet::connect_to(addr, None),
            }
        }
        (b"version", _) => {
            log::always(format!("novacomd version {}\n", cli::VERSION).as_bytes());
            log::exit(1);
        }
        (b"bind-all-interfaces", _) => LISTEN_ALL.store(true, Ordering::Relaxed),
        (b"daemonize", _) => DAEMONIZE.store(true, Ordering::Relaxed),
        (b"recoverytimeout", _) => {
            let t = num();
            if !(2..=5).contains(&t) {
                RECOVERY_TIMEOUT.store(RECOVERY_TIMEOUT_DEFAULT, Ordering::Relaxed);
                let shown = val.unwrap_or_default();
                log::error(
                    &[
                        b"Invalid timeout out of range(2~5 seconds): ",
                        shown,
                        b" \n",
                    ]
                    .concat(),
                );
                return Err(());
            }
            RECOVERY_TIMEOUT.store(t, Ordering::Relaxed);
        }
        (b"ioretry_timeout", _) => {
            USBIO_RETRY_TIMEOUT.store(num().min(USBIO_RETRY_MAX), Ordering::Relaxed);
        }
        (b"ioretry_delay", _) => {
            USBIO_RETRY_DELAY.store(num().min(USBIO_RETRY_MAX), Ordering::Relaxed);
        }
        // g_cpuaffinity = 0: already 0, used only on the device.
        (b"no-cpuaffinity", _) => {}
        (b"help", _) => {
            usage();
            log::exit(1);
        }
        _ => return Err(()),
    }
    Ok(())
}

/// C `parse_commandline`. `Err` is the C return value -1; getopt
/// diagnostics are written to stderr as libc does.
fn parse_commandline(args: &[Vec<u8>], ctx: &ParseContext) -> Result<(), ()> {
    let mut g = Getopt::new(args, ctx);
    loop {
        match cli::getnextopt(&mut g) {
            NextOpt::Done => break,
            NextOpt::Bad(diag) => {
                let _ = sys::write_fd(sys::STDERR_FD, &diag);
                return Err(());
            }
            NextOpt::Opt(opt, val) => handleopt(opt, val.as_deref())?,
        }
    }
    let timeout = USBIO_RETRY_TIMEOUT.load(Ordering::Relaxed);
    if timeout < USBIO_RETRY_DELAY.load(Ordering::Relaxed) {
        USBIO_RETRY_DELAY.store(timeout, Ordering::Relaxed);
    }
    Ok(())
}

/// C `novacomopt`: if something accepts on 127.0.0.1:64022, another
/// daemon runs.
fn novacomopt() {
    if TcpStream::connect((Ipv4Addr::LOCALHOST, net::OPTPORT)).is_ok() {
        log::always(b"Cannot start novacomd twice!\n");
        log::exit(0);
    }
}

/// The `-d` block of C `main`.
fn daemonize() {
    log::always(b"starting the daemonizing process\n");
    match log::with_locked(sys::fork) {
        Err(_) => log::exit(1),
        Ok(sys::Forked::Parent) => log::exit(0),
        Ok(sys::Forked::Child) => {}
    }
    sys::clear_umask();
    if sys::setsid().is_err() || std::env::set_current_dir("/").is_err() {
        log::exit(1);
    }
    sys::close_std_fds();
}

/// C `create_listen_socket` in `main`, which returns 1 on failure.
fn bind_or_exit(port: u16, bind_all: bool) -> TcpListener {
    net::create_listen_socket(port, bind_all).unwrap_or_else(|_| {
        log::error(format!("error creating server sockets, port {port}\n").as_bytes());
        log::exit(1)
    })
}

/// Entry point: C `main`. Never returns; the daemon ends by `exit` or by
/// a signal.
pub fn main_entry() -> ! {
    use std::os::unix::ffi::OsStrExt;
    // SIGPIPE is already ignored by the Rust runtime, as C `main` does.
    sys::seed_rand_with_time();
    #[cfg(target_os = "linux")]
    sys::openlog(&SYSLOG_IDENT);
    inet::init_nduid();
    let args: Vec<Vec<u8>> = std::env::args_os().map(|a| a.as_bytes().to_vec()).collect();
    let argv0: &[u8] = args.first().map_or(b"", Vec::as_slice);
    let ctx = ParseContext {
        flavor: cli::FLAVOR,
        posixly_correct: std::env::var_os("POSIXLY_CORRECT").is_some(),
        diag_progname: cli::diag_progname(argv0),
    };
    if parse_commandline(&args, &ctx).is_err() {
        log::error(b"Invalid command line option or parameter\n");
        usage();
        log::exit(1);
    }
    novacomopt();
    if DAEMONIZE.load(Ordering::Relaxed) {
        daemonize();
    }
    let all = listen_all();
    let listeners = Listeners {
        devlist: bind_or_exit(net::DEVLISTPORT, all),
        unblock: bind_or_exit(net::UNBLOCKPORT, false),
        log: bind_or_exit(net::LOGPORT, all),
        opt: bind_or_exit(net::OPTPORT, false),
        ctrl: bind_or_exit(net::CTRLPORT, false),
    };
    // transport_init / transport_start: USB comes in slice 5.
    inet::start_listener();
    main_loop(&listeners)
}

/// C `openlog` ident `"novacomd(" BUILDVERSION ")"`.
#[cfg(target_os = "linux")]
static SYSLOG_IDENT: std::sync::LazyLock<std::ffi::CString> = std::sync::LazyLock::new(|| {
    std::ffi::CString::new(format!("novacomd({})", cli::VERSION)).unwrap_or_default()
});

struct Listeners {
    devlist: TcpListener,
    unblock: TcpListener,
    log: TcpListener,
    opt: TcpListener,
    ctrl: TcpListener,
}

/// C `main_loop`, without device and client sockets (slice 2).
fn main_loop(l: &Listeners) -> ! {
    // C `unblock_fd_read`; earlier connections replaced by a new accept
    // stay open (leaked in C, D10).
    let mut unblock_read: Option<TcpStream> = None;
    let mut leaked: Vec<TcpStream> = Vec::new();
    loop {
        let mut fds = vec![
            l.devlist.as_raw_fd(),
            l.opt.as_raw_fd(),
            l.unblock.as_raw_fd(),
            l.log.as_raw_fd(),
            l.ctrl.as_raw_fd(),
        ];
        if let Some(s) = &unblock_read {
            fds.push(s.as_raw_fd());
        }
        let Ok(ready) = sys::poll_readable(&fds) else {
            continue;
        };
        let [devlist, opt, unblock, log_ready, ctrl] = [0, 1, 2, 3, 4].map(|i| ready[i]);
        let mut unblock_read_ready = ready.get(5).copied().unwrap_or(false);

        if unblock {
            let new = l.unblock.accept().ok().map(|(s, _)| s);
            if let Some(old) = std::mem::replace(&mut unblock_read, new) {
                leaked.push(old);
            }
            // C then tests the new fd against the old select set: not set.
            unblock_read_ready = false;
        }
        if unblock_read_ready {
            if let Some(s) = &unblock_read {
                // recv() == 0 (EOF) keeps the socket, as in C (D10).
                if (&*s).read(&mut [0u8; 1]).is_err() {
                    unblock_read = None;
                }
            }
        }
        if opt {
            if let Ok((s, _)) = l.opt.accept() {
                handle_opt_connection(&s);
            }
        }
        if devlist {
            if let Ok((s, _)) = l.devlist.accept() {
                devices::dump_device_list(&s);
            }
        }
        if log_ready {
            if let Ok((s, _)) = l.log.accept() {
                log::add_socket(s);
            }
        }
        if ctrl {
            if let Ok((s, _)) = l.ctrl.accept() {
                register_command(&s);
            }
        }
    }
}

/// Option port (64022): two host-order `u32` lengths, then the option name
/// and value as C strings; `handleopt` runs on them. Blocking, on the main
/// loop, as in C (D7).
///
/// Intentional change (D7): when `l0 + l1` wraps so that the value would
/// start past the received bytes, C reads out of bounds; here the request
/// is ignored.
fn handle_opt_connection(s: &TcpStream) {
    let mut lengths = [0u8; 8];
    if net::read_full(s, &mut lengths) != 8 {
        return;
    }
    let l0 = u32::from_ne_bytes([lengths[0], lengths[1], lengths[2], lengths[3]]);
    let l1 = u32::from_ne_bytes([lengths[4], lengths[5], lengths[6], lengths[7]]);
    let total = l0.wrapping_add(l1);
    if l0 == 0 || total >= OPT_MAX || l0 > total {
        return;
    }
    let (l0, total) = (l0 as usize, total as usize);
    let mut buf = vec![0u8; total + 1];
    if net::read_full(s, &mut buf[..total]) > 0 {
        let _ = handleopt(c_str(&buf), Some(c_str(&buf[l0..])));
    }
}

/// Control-port verbs (C `iohandlers`): `true` for device commands.
fn lookup_handler(verb: &[u8], scheme: &[u8]) -> Option<bool> {
    const HANDLERS: [(&[u8], &[u8], bool); 6] = [
        (b"list", b"host", false),
        (b"login", b"dev", true),
        (b"logout", b"dev", true),
        (b"logint", b"dev", true),
        (b"add", b"dev", true),
        (b"remove", b"dev", true),
    ];
    HANDLERS
        .iter()
        .find(|(v, s, _)| verb.eq_ignore_ascii_case(v) && scheme.eq_ignore_ascii_case(s))
        .map(|&(_, _, remote)| remote)
}

/// C `novacom_register_command(socket, NULL)` for a control-port client:
/// one `recv` of at most 127 bytes, which must hold a NUL.
///
/// `list host://` sends the device list. A device command needs a device
/// with a session id to be queued on the service channel (slice 3); only
/// USB devices have one, so every device command gets `invalid command`.
/// Anything else gets no reply. The caller closes the socket.
fn register_command(s: &TcpStream) {
    let mut cmd = [0u8; CTRL_CMD_SIZE];
    if (&*s).read(&mut cmd[..CTRL_CMD_SIZE - 1]).is_err() {
        return;
    }
    if !cmd[..CTRL_CMD_SIZE - 1].contains(&0) {
        return;
    }
    let Some(url) = cmdparse::parse_command(c_str(&cmd)) else {
        return;
    };
    match lookup_handler(&url.verb, &url.scheme) {
        None => {}
        Some(false) => devices::dump_device_list(s),
        Some(true) => {
            let _ = (&*s).write(INVALID_COMMAND);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_table_is_case_insensitive() {
        assert_eq!(lookup_handler(b"LIST", b"Host"), Some(false));
        assert_eq!(lookup_handler(b"login", b"DEV"), Some(true));
        assert_eq!(lookup_handler(b"logint", b"dev"), Some(true));
        assert_eq!(lookup_handler(b"list", b"dev"), None);
        assert_eq!(lookup_handler(b"run", b"file"), None);
    }

    #[test]
    fn c_str_cuts_at_nul() {
        assert_eq!(c_str(b"ab\0cd"), b"ab");
        assert_eq!(c_str(b"ab"), b"ab");
    }
}
