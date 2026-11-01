//! Program flow: emulation of C `main`, `parse_commandline`, `handleopt`,
//! `novacomopt`, the `-d` steps, `main_loop` and the control-port read of
//! `novacom_register_command` (the rest is in [`crate::cmdservice`]).
//!
//! Main loop (C `select`, here `poll`, P5): the device-list (6968),
//! option (64022), unblock (12311), log (6970) and control (6971)
//! listeners, the accepted unblock connection, every per-device listen
//! socket and every client data socket that is not squelched. A client of
//! a per-device port gets a command channel on the device (C
//! `socketchan`); bytes are relayed both ways unchanged.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::cli::{self, Getopt, NextOpt, ParseContext};
use crate::{cmdservice, devices, inet, log, mux, net, sys};

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
/// C `TX_QUEUE_UPPER`: a client is squelched while its channel queues more.
const TX_QUEUE_UPPER: usize = 64 * 1024;
/// C `TX_QUEUE_LOWER`: a squelched client resumes below this.
const TX_QUEUE_LOWER: usize = 32 * 1024;
/// C `sdata[8*1024]`: client bytes read per pass.
const CLIENT_CHUNK: usize = 8 * 1024;
/// C `(uint32_t)-1`: the channel of a failed or closed socketchan.
const NO_CHANNEL: u32 = u32::MAX;

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

/// C `g_recovery_timeout` (`-t`, seconds).
pub fn recovery_timeout() -> i32 {
    RECOVERY_TIMEOUT.load(Ordering::Relaxed)
}

/// C `g_usbio_retry_timeout` (`-e`, milliseconds).
pub fn usbio_retry_timeout() -> i32 {
    USBIO_RETRY_TIMEOUT.load(Ordering::Relaxed)
}

/// C `g_usbio_retry_delay` (`-s`, milliseconds).
pub fn usbio_retry_delay() -> i32 {
    USBIO_RETRY_DELAY.load(Ordering::Relaxed)
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
pub(crate) fn c_str(b: &[u8]) -> &[u8] {
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

/// The part of C `struct socketchan` that the transport thread uses.
struct ClientChan {
    stream: TcpStream,
    close: AtomicBool,
    channel: AtomicU32,
    partial_pos: Mutex<usize>,
}

impl mux::ClientReader for ClientChan {
    /// C `socketchan_read_callback`: one non-blocking `send` to the client.
    /// A short or refused send withholds the ack, so the device
    /// retransmits; `partial_pos` remembers what was sent.
    fn read(&self, _channel: u32, data: Option<&[u8]>) -> i32 {
        let Some(buf) = data else {
            self.close.store(true, Ordering::SeqCst);
            self.channel.store(NO_CHANNEL, Ordering::SeqCst);
            unblock_main_loop();
            return 0;
        };
        if self.close.load(Ordering::SeqCst) {
            unblock_main_loop();
            return 0;
        }
        let mut pos = self
            .partial_pos
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Intentional change: a retransmission shorter than what was sent
        // already makes C pass a wrapped length to `send`; here that is a
        // send error.
        let sent = match buf.get(*pos..) {
            Some(rest) => (&self.stream).write(rest),
            None => Err(ErrorKind::InvalidInput.into()),
        };
        match sent {
            Ok(n) if n > 0 => {
                *pos += n;
                if *pos == buf.len() {
                    *pos = 0;
                    return 0;
                }
                -1
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => -1,
            _ => {
                self.close.store(true, Ordering::SeqCst);
                unblock_main_loop();
                -1
            }
        }
    }
}

/// C `struct socketchan`, owned by the main loop.
struct SocketChan {
    chan: Arc<ClientChan>,
    device: Arc<mux::Device>,
    tx_squelch: bool,
}

/// C `socketchan_write_callback`.
fn wake_main_loop() -> mux::Notify {
    Box::new(unblock_main_loop)
}

/// C `novacom_register_client`: the socketchan is listed first, then the
/// command channel is opened, blocking the main loop until the device
/// acknowledges (D9).
fn register_client(list: &mut Vec<SocketChan>, device: &Arc<mux::Device>, stream: TcpStream) {
    let chan = Arc::new(ClientChan {
        stream,
        close: AtomicBool::new(false),
        channel: AtomicU32::new(0),
        partial_pos: Mutex::new(0),
    });
    list.insert(
        0,
        SocketChan {
            chan: Arc::clone(&chan),
            device: Arc::clone(device),
            tx_squelch: false,
        },
    );
    let (num, rc) = device.open_temp_channel();
    chan.channel.store(num, Ordering::SeqCst);
    if rc < 0 {
        chan.channel.store(NO_CHANNEL, Ordering::SeqCst);
        return;
    }
    let reader: Arc<dyn mux::ClientReader> = chan.clone();
    if device
        .with(|m| m.set_reader(num, Some(mux::Reader::Client(reader))))
        .is_err()
    {
        // The device went away during the open.
        chan.channel.store(NO_CHANNEL, Ordering::SeqCst);
        chan.close.store(true, Ordering::SeqCst);
    }
}

/// C `destroy_socketchan`. As in C, a channel of `(uint32_t)-1` is also
/// "closed" (D32).
fn destroy_socketchan(sc: SocketChan) {
    let ch = sc.chan.channel.load(Ordering::SeqCst);
    if ch > 0 {
        sc.device.with(|m| {
            let _ = m.set_reader(ch, None);
            let _ = m.close_channel(ch);
        });
    }
    let _ = sc.chan.stream.shutdown(Shutdown::Both);
    // The socket closes with the last reference, which is this one.
}

/// C `main_loop`.
fn main_loop(l: &Listeners) -> ! {
    // C `unblock_fd_read`; earlier connections replaced by a new accept
    // stay open (leaked in C, D10).
    let mut unblock_read: Option<TcpStream> = None;
    let mut leaked: Vec<TcpStream> = Vec::new();
    // C `socketchan_list`: newest first.
    let mut chans: Vec<SocketChan> = Vec::new();
    let mut sdata = vec![0u8; CLIENT_CHUNK];
    loop {
        let mut i = 0;
        while i < chans.len() {
            if chans[i].chan.close.load(Ordering::SeqCst) {
                destroy_socketchan(chans.remove(i));
                continue;
            }
            let sc = &mut chans[i];
            if sc.tx_squelch {
                let ch = sc.chan.channel.load(Ordering::SeqCst);
                if sc.device.with(|m| m.tx_queue_len(ch)) < TX_QUEUE_LOWER {
                    sc.tx_squelch = false;
                }
            }
            i += 1;
        }

        let mut fds = vec![
            l.devlist.as_raw_fd(),
            l.opt.as_raw_fd(),
            l.unblock.as_raw_fd(),
            l.log.as_raw_fd(),
            l.ctrl.as_raw_fd(),
        ];
        let unblock_at = unblock_read.as_ref().map(|s| {
            fds.push(s.as_raw_fd());
            fds.len() - 1
        });
        let polled: Vec<(Arc<ClientChan>, usize)> = chans
            .iter()
            .filter(|sc| !sc.tx_squelch)
            .map(|sc| {
                fds.push(sc.chan.stream.as_raw_fd());
                (Arc::clone(&sc.chan), fds.len() - 1)
            })
            .collect();
        // Per-pass device references. Intentional change (D11): a device
        // without a listen socket is not polled (C passes fd -1 to
        // `FD_SET`).
        let devs = devices::snapshot();
        let dev_at: Vec<Option<usize>> = devs
            .iter()
            .map(|d| {
                d.listener.as_ref().map(|lst| {
                    fds.push(lst.as_raw_fd());
                    fds.len() - 1
                })
            })
            .collect();
        let Ok(ready) = sys::poll_readable(&fds) else {
            continue;
        };
        let is_ready = |at: Option<usize>| at.is_some_and(|i| ready[i]);
        let [devlist, opt, unblock, log_ready, ctrl] = [0, 1, 2, 3, 4].map(|i| ready[i]);
        let mut unblock_read_ready = is_ready(unblock_at);

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
                register_command(s);
            }
        }
        // C walks its per-pass list, which is oldest device first.
        for (d, at) in devs.iter().zip(&dev_at).rev() {
            if !is_ready(*at) {
                continue;
            }
            if let Some(Ok((s, _))) = d.listener.as_ref().map(TcpListener::accept) {
                // "Set non-blocking or novacomd will drop offline if the
                // socket fills up."
                let _ = s.set_nonblocking(true);
                register_client(&mut chans, &d.mux, s);
            }
        }
        drop(devs);

        for sc in &mut chans {
            if sc.chan.close.load(Ordering::SeqCst) {
                continue;
            }
            let Some((_, at)) = polled.iter().find(|(c, _)| Arc::ptr_eq(c, &sc.chan)) else {
                continue;
            };
            if !ready[*at] {
                continue;
            }
            relay_from_client(sc, &mut sdata);
        }
    }
}

/// Client data on a ready socket: C `recv_socket` of up to 8 KiB, queued
/// on the channel; EOF or an error closes the socketchan in the next pass.
///
/// C retries a `recv` that would block, logging each try (D29); after a
/// ready `poll` that cannot happen, so here such a pass reads nothing.
fn relay_from_client(sc: &mut SocketChan, sdata: &mut [u8]) {
    let n = match (&sc.chan.stream).read(sdata) {
        Ok(0) => {
            sc.chan.close.store(true, Ordering::SeqCst);
            return;
        }
        Ok(n) => n,
        Err(e) if e.kind() == ErrorKind::WouldBlock => return,
        Err(_) => {
            sc.chan.close.store(true, Ordering::SeqCst);
            return;
        }
    };
    let ch = sc.chan.channel.load(Ordering::SeqCst);
    let queued = sc.device.with(|m| {
        let _ = m.write(ch, &sdata[..n], Some(wake_main_loop()));
        m.tx_queue_len(ch)
    });
    if queued > TX_QUEUE_UPPER {
        sc.tx_squelch = true;
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

/// C `novacom_register_command(socket, NULL)` for a control-port client:
/// one `recv` of at most 127 bytes, which must hold a NUL; then
/// [`cmdservice::register_command`]. The socket is closed unless the
/// command is queued on a device.
fn register_command(s: TcpStream) {
    let size = cmdservice::CMD_SIZE;
    let mut cmd = vec![0u8; size];
    if (&s).read(&mut cmd[..size - 1]).is_err() {
        return;
    }
    if !cmd[..size - 1].contains(&0) {
        return;
    }
    cmdservice::register_command(Some(s), c_str(&cmd));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_str_cuts_at_nul() {
        assert_eq!(c_str(b"ab\0cd"), b"ab");
        assert_eq!(c_str(b"ab"), b"ab");
    }
}
