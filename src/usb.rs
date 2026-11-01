//! USB host threads: the platform-independent part of C
//! `host/usb-linux.c` (the rx and tx thread of a claimed device, I/O
//! retries, recovery hand-over) and the daemon's [`Host`] for the link
//! layer.
//!
//! Enumeration, claiming and bulk transfers (libusb / usbdevfs) come with
//! the platform backends in slice 5; here a device is a [`UsbLink`].
//!
//! Per device, as in C: the rx thread reads (first with the 5000 ms
//! default timeout), and its first packet decides between resuming a
//! parked link (same ids, [`Records::find`]) and a new one; it then feeds
//! the link layer. The tx thread starts after the first packet that is not
//! bad and sends whatever the link layer prepares. A failed transfer is
//! retried every `-s` ms until `-e` ms have passed; then the device's
//! threads end and the link is parked for `-t` seconds (or destroyed if no
//! device registered on it).
//!
//! The tx thread spins without pause while the link waits for the
//! device's SYN, as in C.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::devices::{self, NDUID_CHRLEN};
use crate::log::{LOG_ALWAYS, LOG_ERROR, LOG_TRACE};
use crate::mux::{self, Event};
use crate::tokens::TokenStore;
use crate::usbll::{
    self, Host, Link, MAX_MTU, Records, RecoveryToken, RxType, Shared, TIMEOUT_PACKET, delta_ms,
    lock,
};
use crate::{inet, log, server, sys};

/// C `USBDEVFS_IOCTL_TIMEOUT`: link timeout of a new link (ms).
pub const USBDEVFS_IOCTL_TIMEOUT: i32 = 2000;

/// The bulk endpoints of a claimed device (slice 5 implements this per
/// platform).
pub trait UsbLink: Send + Sync {
    /// One bulk IN transfer into `buf` (C `USBDEVFS_BULK` /
    /// `usb_bulk_read`); only the bytes read are written.
    fn read(&self, buf: &mut [u8], timeout_ms: i32) -> io::Result<usize>;
    /// One bulk OUT transfer (C `USBDEVFS_BULK` / `usb_bulk_write`).
    fn write(&self, buf: &[u8], timeout_ms: i32) -> io::Result<usize>;
}

/// The USB options (`-t`, `-e`, `-s`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// C `g_recovery_timeout` (s).
    pub recovery_timeout: i32,
    /// C `g_usbio_retry_timeout` (ms).
    pub retry_timeout: i32,
    /// C `g_usbio_retry_delay` (ms).
    pub retry_delay: i32,
}

impl Settings {
    /// The values from the command line.
    pub fn from_options() -> Self {
        Self {
            recovery_timeout: server::recovery_timeout(),
            retry_timeout: server::usbio_retry_timeout(),
            retry_delay: server::usbio_retry_delay(),
        }
    }
}

/// A claimed device (C `novacom_usb_handle_t`).
pub struct UsbHandle<K, D> {
    link: K,
    /// The `usbid_list` name of the device.
    devtype: Vec<u8>,
    busnum: i32,
    devnum: i32,
    shutdown: AtomicBool,
    tx_startup: Event,
    tx_startup_wait: AtomicBool,
    tx_shutdown: Event,
    usbll: Mutex<Option<Shared<D>>>,
    tx_timeout: AtomicI32,
}

impl<K, D> UsbHandle<K, D> {
    pub fn new(link: K, devtype: &[u8], busnum: i32, devnum: i32) -> Self {
        Self {
            link,
            devtype: devtype.to_vec(),
            busnum,
            devnum,
            shutdown: AtomicBool::new(false),
            tx_startup: Event::default(),
            tx_startup_wait: AtomicBool::new(true),
            tx_shutdown: Event::default(),
            usbll: Mutex::new(None),
            tx_timeout: AtomicI32::new(0),
        }
    }

    /// C `handle->shutdown`.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn shut_down(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// C `handle->usbll_handle`.
    pub fn usbll(&self) -> Option<Shared<D>> {
        self.usbll
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sets C `handle->usbll_handle` (the rx thread, after the first
    /// read).
    pub fn set_usbll(&self, link: Shared<D>) {
        *self.usbll.lock().unwrap_or_else(PoisonError::into_inner) = Some(link);
    }

    /// C `platform_event_signal(&handle->tx_startup_event)`: the tx thread
    /// may start.
    pub fn start_tx(&self) {
        self.tx_startup.signal();
    }

    /// C `platform_event_signal(&handle->tx_shutdown_event)`: the tx thread
    /// has ended.
    pub fn tx_ended(&self) {
        self.tx_shutdown.signal();
    }
}

/// C: the rx and tx threads of a device found by `novacom_usb_open`.
pub fn attach<K, H>(
    handle: Arc<UsbHandle<K, H::Dev>>,
    host: Arc<H>,
    s: Settings,
) -> [JoinHandle<()>; 2]
where
    K: UsbLink + 'static,
    H: Host + 'static,
    H::Dev: Sync + 'static,
{
    let rx = {
        let (handle, host) = (Arc::clone(&handle), Arc::clone(&host));
        inet::spawn(move || rx_loop(&handle, &*host, s))
    };
    let tx = inet::spawn(move || tx_loop(&handle, &*host, s));
    [rx, tx]
}

/// Sleeps before the next retry, as C does with `time_used`.
fn retry_sleep(host: &impl Host, s: Settings, time_used: &mut i32) {
    if s.retry_delay <= 0 {
        return;
    }
    let ms = if s.retry_timeout - *time_used >= s.retry_delay {
        *time_used += s.retry_delay;
        s.retry_delay
    } else {
        let rest = s.retry_timeout - *time_used;
        *time_used = s.retry_timeout;
        rest
    };
    host.sleep(Duration::from_millis(u64::try_from(ms).unwrap_or(0)));
}

/// The C result of a transfer. A failure is -1 from the usbdevfs `ioctl`
/// on Linux and `-errno` from the libusb-0.1 bulk calls of the macOS
/// reference build; `errno` keeps the error number for the log lines.
///
/// C prints `errno` also after a successful or bad read, where it is
/// whatever an earlier call left; here it is the number of the last failed
/// transfer of the thread (0 before any).
fn transfer_rc(r: io::Result<usize>, errno: &mut i32) -> i32 {
    match r {
        // At most MAX_MTU bytes.
        Ok(n) => n as i32,
        Err(e) => {
            *errno = e.raw_os_error().unwrap_or(0);
            if cfg!(target_os = "linux") || *errno <= 0 {
                -1
            } else {
                -*errno
            }
        }
    }
}

/// C `novacom_usb_read`: a read of `len` bytes; a bad usbll header turns
/// the result into 0.
fn usb_read<K: UsbLink, H: Host>(
    h: &UsbHandle<K, H::Dev>,
    buf: &mut [u8],
    len: usize,
    timeout: i32,
    host: &H,
    errno: &mut i32,
) -> i32 {
    let rc = transfer_rc(h.link.read(&mut buf[..len], timeout), errno);
    if rc > 0 && usbll::check_packet_header(buf, rc as usize, host) {
        host.log(
            LOG_ERROR,
            format!("novacom_usb_read:298 -- received bad packet, set received packet size={rc}\n")
                .as_bytes(),
        );
        return 0;
    }
    rc
}

/// C `novacom_usb_write`.
fn usb_write<K: UsbLink, D>(h: &UsbHandle<K, D>, buf: &[u8], errno: &mut i32) -> i32 {
    transfer_rc(
        h.link.write(buf, h.tx_timeout.load(Ordering::Relaxed)),
        errno,
    )
}

fn mtu_of<D: Clone>(link: Option<&Shared<D>>) -> usize {
    link.map_or(MAX_MTU, |l| lock(l).mtu() as usize)
}

fn uid_of<D: Clone>(link: Option<&Shared<D>>) -> u32 {
    link.map_or(0, |l| lock(l).uid())
}

/// C `novacom_usb_rx_thread`.
pub fn rx_loop<K: UsbLink, H: Host>(h: &UsbHandle<K, H::Dev>, host: &H, s: Settings) {
    // C: platform_calloc(MAX_MTU), reused for every read.
    let mut buf = vec![0u8; MAX_MTU];
    let mut usbll: Option<Shared<H::Dev>> = None;
    let mut rx_timeout = TIMEOUT_PACKET;
    let mut sniff = true;
    let mut errno = 0;
    while !h.is_shutdown() {
        let len = mtu_of(usbll.as_ref());
        let mut rc = usb_read(h, &mut buf, len, rx_timeout, host, &mut errno);
        let st = host.now();
        let mut time_used = 0;
        if rc <= 0 {
            let uid = uid_of(usbll.as_ref());
            host.log(
                LOG_ALWAYS,
                format!(
                    "novacom_usb_rx_thread:431 -- usbll({uid:08x}) error: reading packet, result({rc}), errno {errno}\n"
                )
                .as_bytes(),
            );
            let (count, et) = retry(
                h,
                host,
                s,
                st,
                &mut time_used,
                &mut rc,
                |rc| *rc <= 0,
                |rc| {
                    *rc = usb_read(
                        h,
                        &mut buf,
                        mtu_of(usbll.as_ref()),
                        rx_timeout,
                        host,
                        &mut errno,
                    );
                },
            );
            log_retries(
                host,
                "novacom_usb_rx_thread:452 -- ",
                uid_of(usbll.as_ref()),
                "reading packet, reads",
                count,
                delta_ms(st, et),
                rc,
                errno,
            );
        }
        if sniff {
            let link = sniff_link(h, &buf, host);
            let timeout = lock(&link).timeout();
            rx_timeout = timeout;
            h.tx_timeout.store(timeout, Ordering::Relaxed);
            h.set_usbll(Arc::clone(&link));
            usbll = Some(link);
            sniff = false;
        }
        if let (true, Some(link)) = (rc > 0, usbll.as_ref()) {
            // rc <= MAX_MTU.
            let t = lock(link).process_packet(&mut buf, rc as usize, host);
            if t == RxType::Bad {
                host.log(
                    LOG_TRACE,
                    b"novacom_usb_rx_thread:494: received bad packet\n",
                );
                if delta_ms(st, host.now()) >= s.retry_timeout {
                    h.shut_down();
                    break;
                }
                retry_sleep(host, s, &mut time_used);
            } else if h.tx_startup_wait.load(Ordering::Relaxed) {
                h.start_tx();
            }
        }
    }
    if h.tx_startup_wait.load(Ordering::Relaxed) {
        h.start_tx();
    }
    h.tx_shutdown.wait();
    if let Some(link) = usbll {
        let (nduid, token) = {
            let l = lock(&link);
            (l.nduid().to_vec(), l.recovery_token())
        };
        match token {
            Some(token) => host
                .records()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .add(token, &nduid, link, s.recovery_timeout),
            None => usbll::destroy(&link, host),
        }
    }
}

/// The C "sniff" step: the link to resume (its recovery token matches the
/// ids of the first packet, which may be a failed read's stale buffer) or
/// a new one.
fn sniff_link<K: UsbLink, H: Host>(
    h: &UsbHandle<K, H::Dev>,
    buf: &[u8],
    host: &H,
) -> Shared<H::Dev> {
    let token = RecoveryToken::from_header(buf);
    let found = host
        .records()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .find(&token, host);
    let link = match found {
        Some(link) => {
            host.log(LOG_ERROR, b"Recovered record...\n");
            link
        }
        None => Arc::new(Mutex::new(Link::new(
            &h.devtype,
            MAX_MTU as u32,
            0,
            USBDEVFS_IOCTL_TIMEOUT,
            host,
        ))),
    };
    let uid = (((h.busnum & 0xffff) << 16) | (h.devnum & 0xffff)) as u32;
    lock(&link).set_uid(uid);
    link
}

/// The C retry loop after a failed transfer: retries while `failed(rc)`
/// until `-e` ms have passed since `st` (then the device shuts down).
/// Returns the number of retries and the time of the last check (C `et`;
/// `st` if there was none, where C leaves it uninitialized, D19).
#[allow(clippy::too_many_arguments)]
fn retry<K, H: Host>(
    h: &UsbHandle<K, H::Dev>,
    host: &H,
    s: Settings,
    st: Instant,
    time_used: &mut i32,
    rc: &mut i32,
    failed: impl Fn(&i32) -> bool,
    mut again: impl FnMut(&mut i32),
) -> (u32, Instant) {
    let mut count = 0u32;
    let mut et = st;
    while failed(rc) && !h.is_shutdown() {
        et = host.now();
        if delta_ms(st, et) >= s.retry_timeout {
            h.shut_down();
            break;
        }
        retry_sleep(host, s, time_used);
        again(rc);
        count = count.wrapping_add(1);
    }
    (count, et)
}

/// The C retry statistics line.
///
/// Intentional change (D19): C passes 32-bit values for `%ld`; here the
/// values themselves are printed.
#[allow(clippy::too_many_arguments)]
fn log_retries(
    host: &impl Host,
    prefix: &str,
    uid: u32,
    what: &str,
    count: u32,
    duration: i32,
    rc: i32,
    errno: i32,
) {
    host.log(
        LOG_ALWAYS,
        format!(
            "{prefix}usbll({uid:08x}) {what}({count}), duration({duration}ms), result({rc}), last_errno {errno}\n"
        )
        .as_bytes(),
    );
}

/// C `novacom_usb_tx_thread`.
pub fn tx_loop<K: UsbLink, H: Host>(h: &UsbHandle<K, H::Dev>, host: &H, s: Settings) {
    // C: platform_calloc(MAX_MTU), reused for every packet.
    let mut buf = vec![0u8; MAX_MTU];
    h.tx_startup.wait();
    h.tx_startup_wait.store(false, Ordering::Relaxed);
    // The rx thread sets the link before it signals.
    if let Some(link) = h.usbll() {
        h.tx_timeout.store(lock(&link).timeout(), Ordering::Relaxed);
        let mut errno = 0;
        while !h.is_shutdown() {
            let max_len = lock(&link).mtu() as usize;
            let len = match usbll::prepare_tx_packet(&link, &mut buf, max_len, host) {
                Ok(Some(len)) => len,
                Ok(None) => continue,
                // C crashes in platform_abort (SIGSEGV) after the
                // ASSERT FAILED line; this aborts (SIGABRT).
                Err(usbll::AssertFailed) => std::process::abort(),
            };
            let mut rc = usb_write(h, &buf[..len], &mut errno);
            if rc < 0 {
                let uid = lock(&link).uid();
                host.log(
                    LOG_ALWAYS,
                    format!("usbll({uid:08x}) error writing packet, result({rc}), errno {errno}\n")
                        .as_bytes(),
                );
                let st = host.now();
                let mut time_used = 0;
                let (count, et) = retry(
                    h,
                    host,
                    s,
                    st,
                    &mut time_used,
                    &mut rc,
                    |rc| *rc < 0,
                    |rc| {
                        *rc = usb_write(h, &buf[..len], &mut errno);
                    },
                );
                log_retries(
                    host,
                    "",
                    uid,
                    "writing packet, writes",
                    count,
                    delta_ms(st, et),
                    rc,
                    errno,
                );
            }
            if rc >= 0 {
                let uid = lock(&link).uid();
                host.log(
                    LOG_TRACE,
                    format!(
                        "novacom_usb_tx_thread:388: usbll({uid:08x}) wrote tx packet len={rc}\n"
                    )
                    .as_bytes(),
                );
            }
        }
    }
    h.tx_ended();
}

/// The daemon's link-layer environment: wall clock, `rand()`, the host
/// nduid, console/syslog logging, the device registry and the mux.
pub struct Daemon {
    /// Token store of USB devices with a session id.
    tokens: TokenStore,
    records: Mutex<Records<Arc<mux::Device>>>,
}

impl Daemon {
    pub fn new(tokens: TokenStore) -> Self {
        Self {
            tokens,
            records: Mutex::new(Records::new()),
        }
    }
}

impl Host for Daemon {
    type Dev = Arc<mux::Device>;

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn new_sessionid(&self) -> u32 {
        // rand() is not negative.
        sys::rand() as u32
    }

    fn nduid(&self) -> [u8; NDUID_CHRLEN] {
        *inet::nduid()
    }

    fn log(&self, mask: u32, msg: &[u8]) {
        log::log(mask, msg);
    }

    fn go_online(&self, nduid: &[u8], devtype: &[u8], devdata: Option<&[u8]>) -> Self::Dev {
        devices::go_online_usb(nduid, devtype, devdata, self.tokens.clone()).0
    }

    fn go_offline(&self, dev: &Self::Dev) {
        devices::go_offline(dev);
    }

    fn process_packet(&self, dev: &Self::Dev, buf: &[u8], len: usize) {
        dev.process_packet(buf, len);
    }

    fn get_tx_packet(&self, dev: &Self::Dev, timeout: Duration, len: usize) -> Option<Vec<u8>> {
        dev.get_tx_packet(timeout, len)
    }

    fn records(&self) -> &Mutex<Records<Self::Dev>> {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usbll::tests::{
        DEV, DEV_NDUID, HOST_NDUID, SID0, TestHost, data, header, new_link, syn_data,
    };
    use crate::usbll::{CMD_DATA, CMD_NULL, CMD_SYN, Header, State};
    use std::collections::VecDeque;

    const ETIMEDOUT: i32 = 110;
    const EPIPE: i32 = 32;
    /// The C result of a failed transfer on this OS.
    fn fail(errno: i32) -> i32 {
        if cfg!(target_os = "linux") {
            -1
        } else {
            -errno
        }
    }

    const S: Settings = Settings {
        recovery_timeout: 5,
        retry_timeout: 100,
        retry_delay: 50,
    };

    /// Scripted bulk endpoints: reads return the queued packets, then fail
    /// with ETIMEDOUT; writes succeed or fail as queued, then fail with
    /// EPIPE.
    #[derive(Default)]
    struct FakeLink {
        /// Once the queued reads are used up, reads wait (real time) until
        /// this many writes happened.
        hold_until_writes: usize,
        reads: Mutex<VecDeque<Vec<u8>>>,
        read_calls: Mutex<Vec<(usize, i32)>>,
        write_results: Mutex<VecDeque<bool>>,
        writes: Mutex<Vec<(Vec<u8>, i32)>>,
    }

    impl UsbLink for FakeLink {
        fn read(&self, buf: &mut [u8], timeout_ms: i32) -> io::Result<usize> {
            self.read_calls
                .lock()
                .unwrap()
                .push((buf.len(), timeout_ms));
            let next = self.reads.lock().unwrap().pop_front();
            if next.is_none() {
                let start = Instant::now();
                while self.writes.lock().unwrap().len() < self.hold_until_writes
                    && start.elapsed() < Duration::from_secs(10)
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            match next {
                Some(p) => {
                    buf[..p.len()].copy_from_slice(&p);
                    Ok(p.len())
                }
                None => Err(io::Error::from_raw_os_error(ETIMEDOUT)),
            }
        }

        fn write(&self, buf: &[u8], timeout_ms: i32) -> io::Result<usize> {
            self.writes.lock().unwrap().push((buf.to_vec(), timeout_ms));
            match self.write_results.lock().unwrap().pop_front() {
                Some(true) => Ok(buf.len()),
                _ => Err(io::Error::from_raw_os_error(EPIPE)),
            }
        }
    }

    fn handle(reads: Vec<Vec<u8>>) -> UsbHandle<FakeLink, usize> {
        let link = FakeLink::default();
        *link.reads.lock().unwrap() = reads.into();
        UsbHandle::new(link, b"castle-linux", 3, 7)
    }

    /// Runs the rx thread alone (its tx thread counts as finished).
    fn run_rx(h: &UsbHandle<FakeLink, usize>, host: &TestHost) {
        h.tx_shutdown.signal();
        rx_loop(h, host, S);
    }

    fn always(host: &TestHost) -> Vec<String> {
        host.logs()
            .into_iter()
            .filter(|(m, _)| *m == LOG_ALWAYS)
            .map(|(_, t)| t)
            .collect()
    }

    #[test]
    fn retry_sleep_steps() {
        let host = TestHost::new();
        let s = Settings {
            recovery_timeout: 5,
            retry_timeout: 120,
            retry_delay: 50,
        };
        let mut used = 0;
        for want in [50, 100, 120, 120] {
            retry_sleep(&host, s, &mut used);
            assert_eq!((used, host.ms()), (want, want as u64));
        }
        // No delay: no sleep.
        let s = Settings {
            retry_delay: 0,
            ..s
        };
        retry_sleep(&host, s, &mut used);
        assert_eq!(host.ms(), 120);
    }

    #[test]
    fn rx_registers_then_parks_link_after_retries() {
        let host = TestHost::new();
        let h = handle(vec![syn_data(DEV, b"id:a\0"), data(DEV, SID0, b"pm")]);
        run_rx(&h, &host);
        // First read: default timeout and MTU; then the link's.
        assert_eq!(
            *h.link.read_calls.lock().unwrap(),
            [
                (16384, 5000),
                (16384, 2000),
                (16384, 2000),
                (16384, 2000),
                (16384, 2000)
            ]
        );
        assert_eq!(h.tx_timeout.load(Ordering::Relaxed), 2000);
        assert!(h.is_shutdown());
        assert_eq!(
            always(&host),
            [
                format!(
                    "novacom_usb_rx_thread:431 -- usbll(00030007) error: reading packet, result({}), errno 110\n",
                    fail(ETIMEDOUT)
                ),
                format!(
                    "novacom_usb_rx_thread:452 -- usbll(00030007) reading packet, reads(2), duration(100ms), result({}), last_errno 110\n",
                    fail(ETIMEDOUT)
                ),
            ]
        );
        assert_eq!(host.ms(), 100);
        // The link is parked, its device still online. (The data came
        // before the host SYN, so it got an rst.)
        assert_eq!(host.records_len(), 1);
        assert_eq!(host.events().len(), 1);
        assert_eq!(lock(&h.usbll().unwrap()).snapshot().reset_sessionid, SID0);
        // The first good packet started the tx thread.
        h.tx_startup.wait();
    }

    #[test]
    fn rx_bad_header_is_a_failed_read() {
        let host = TestHost::new();
        let mut bad = header(1, 2, CMD_DATA);
        bad[0] = 0;
        let h = handle(vec![bad, syn_data(DEV, b"\0")]);
        run_rx(&h, &host);
        let logs = host.log_texts();
        assert_eq!(
            logs[0],
            "Got bad USB packet. Make sure your novacomd versions match.\n"
        );
        assert_eq!(
            logs[1],
            "novacom_usb_read:298 -- received bad packet, set received packet size=20\n"
        );
        // errno is still 0: nothing failed yet.
        assert_eq!(
            logs[2],
            "novacom_usb_rx_thread:431 -- usbll(00000000) error: reading packet, result(0), errno 0\n"
        );
        assert_eq!(
            logs[3],
            "novacom_usb_rx_thread:452 -- usbll(00000000) reading packet, reads(1), duration(0ms), result(81), last_errno 0\n"
        );
        // The SYN after the retry was the first packet of the link.
        assert!(host.events()[0].starts_with("online 0 "));
    }

    #[test]
    fn rx_resumes_parked_link() {
        let host = TestHost::new();
        let link: Shared<usize> = Arc::new(Mutex::new(new_link(&host)));
        let mut buf = vec![0u8; MAX_MTU];
        let p = syn_data(DEV, b"\0");
        buf[..p.len()].copy_from_slice(&p);
        lock(&link).process_packet(&mut buf, p.len(), &host);
        usbll::prepare_tx_packet(&link, &mut buf, MAX_MTU, &host).unwrap();
        let token = lock(&link).recovery_token().unwrap();
        host.records()
            .lock()
            .unwrap()
            .add(token, DEV_NDUID, Arc::clone(&link), 5);
        let h = handle(vec![data(DEV, SID0, b"again")]);
        run_rx(&h, &host);
        let logs = host.logs();
        assert!(logs.contains(&(LOG_ERROR, "Recovered record...\n".to_string())));
        assert_eq!(lock(&link).uid(), 0x0003_0007);
        assert!(
            host.events()
                .contains(&"pmux 0 [97, 103, 97, 105, 110]".to_string())
        );
        // Parked again at the end; only one session id was used.
        assert_eq!(host.records_len(), 1);
        assert_eq!(host.new_sessionid(), SID0 + 1);
    }

    #[test]
    fn rx_link_without_device_is_destroyed() {
        let host = TestHost::new();
        let h = handle(vec![data(1, 2, b"stray")]);
        run_rx(&h, &host);
        assert_eq!(host.records_len(), 0);
        assert!(host.events().is_empty());
        let link = h.usbll().unwrap();
        assert_eq!(lock(&link).snapshot().reset_sessionid, 2);
    }

    #[test]
    fn rx_shutdown_at_once_with_negative_retry_timeout() {
        let host = TestHost::new();
        let h = handle(vec![]);
        h.tx_shutdown.signal();
        let s = Settings {
            retry_timeout: -1,
            ..S
        };
        rx_loop(&h, &host, s);
        assert_eq!(
            always(&host)[1],
            format!(
                "novacom_usb_rx_thread:452 -- usbll(00000000) reading packet, reads(0), duration(0ms), result({}), last_errno 110\n",
                fail(ETIMEDOUT)
            )
        );
        // The failed first read still made a link (from the zeroed buffer).
        assert_eq!(h.link.read_calls.lock().unwrap().len(), 1);
        assert!(h.usbll().is_some());
        assert_eq!(host.records_len(), 0);
    }

    /// A handle whose link is established up to the host SYN, with the tx
    /// thread released.
    fn tx_handle(host: &TestHost, writes: Vec<bool>) -> UsbHandle<FakeLink, usize> {
        let h = handle(vec![]);
        *h.link.write_results.lock().unwrap() = writes.into();
        let link: Shared<usize> = Arc::new(Mutex::new(new_link(host)));
        let mut buf = vec![0u8; MAX_MTU];
        let p = syn_data(DEV, b"\0");
        buf[..p.len()].copy_from_slice(&p);
        lock(&link).process_packet(&mut buf, p.len(), host);
        lock(&link).set_uid(0x0003_0007);
        *h.usbll.lock().unwrap() = Some(link);
        h.tx_startup.signal();
        h
    }

    #[test]
    fn tx_sends_syn_data_and_heartbeat_then_gives_up() {
        let host = TestHost::new();
        let h = tx_handle(&host, vec![true, true, true]);
        host.queue_mux(vec![5; 30]);
        tx_loop(&h, &host, S);
        let writes = h.link.writes.lock().unwrap().clone();
        let cmds: Vec<u32> = writes
            .iter()
            .map(|(p, _)| Header::decode(p).command)
            .collect();
        // SYN, data, a null after 1 s idle (written), another null that
        // fails, then two retries.
        assert_eq!(
            cmds,
            [CMD_SYN, CMD_DATA, CMD_NULL, CMD_NULL, CMD_NULL, CMD_NULL]
        );
        assert!(writes.iter().all(|(_, t)| *t == 2000));
        assert_eq!(&writes[2].0[20..60], HOST_NDUID);
        let always = always(&host);
        assert_eq!(
            always,
            [
                format!(
                    "usbll(00030007) error writing packet, result({}), errno 32\n",
                    fail(EPIPE)
                ),
                format!(
                    "usbll(00030007) writing packet, writes(2), duration(100ms), result({}), last_errno 32\n",
                    fail(EPIPE)
                ),
            ]
        );
        let traces: Vec<String> = host
            .logs()
            .into_iter()
            .filter(|(m, _)| *m == LOG_TRACE)
            .map(|(_, t)| t)
            .collect();
        assert_eq!(
            traces[..2],
            [
                "novacom_usb_tx_thread:388: usbll(00030007) wrote tx packet len=80\n",
                "novacom_usb_tx_thread:388: usbll(00030007) wrote tx packet len=50\n",
            ]
        );
        assert!(h.is_shutdown());
        h.tx_shutdown.wait();
    }

    #[test]
    fn tx_retry_that_succeeds_continues() {
        let host = TestHost::new();
        let h = tx_handle(&host, vec![false, false, true]);
        tx_loop(&h, &host, S);
        let always = always(&host);
        assert_eq!(
            always[1],
            "usbll(00030007) writing packet, writes(2), duration(50ms), result(80), last_errno 32\n"
        );
        assert!(host.log_texts().contains(
            &"novacom_usb_tx_thread:388: usbll(00030007) wrote tx packet len=80\n".to_string()
        ));
        // Later writes fail for good.
        assert_eq!(always.len(), 4);
    }

    #[test]
    fn rx_bad_packet_when_established() {
        let host = TestHost::new();
        let h = tx_handle(&host, vec![]);
        // Use the established link for a receive: a SYN of another session
        // is bad.
        let link = h.usbll().unwrap();
        let mut buf = vec![0u8; MAX_MTU];
        usbll::prepare_tx_packet(&link, &mut buf, MAX_MTU, &host).unwrap();
        assert_eq!(lock(&link).snapshot().state, State::Established);
        let token = lock(&link).recovery_token().unwrap();
        host.records()
            .lock()
            .unwrap()
            .add(token, DEV_NDUID, link, 5);
        let rx = handle(vec![data(DEV, SID0, b""), syn_data(DEV + 1, b"\0")]);
        run_rx(&rx, &host);
        let logs = host.log_texts();
        assert!(logs.contains(&"novacom_usb_rx_thread:494: received bad packet\n".to_string()));
        // One retry delay for the bad packet, then 100 ms of failed reads.
        assert_eq!(host.ms(), 150);
    }

    #[test]
    fn attached_device_threads_end_and_park_the_link() {
        let host = Arc::new(TestHost::new());
        let link = FakeLink {
            hold_until_writes: 1,
            ..FakeLink::default()
        };
        link.reads
            .lock()
            .unwrap()
            .push_back(syn_data(DEV, b"id:a\0"));
        *link.write_results.lock().unwrap() = vec![true; 1000].into();
        let h = Arc::new(UsbHandle::new(link, b"castle-linux", 3, 7));
        for t in attach(Arc::clone(&h), Arc::clone(&host), S) {
            t.join().unwrap();
        }
        let writes = h.link.writes.lock().unwrap();
        assert_eq!(Header::decode(&writes[0].0).command, CMD_SYN);
        assert_eq!(host.records_len(), 1);
    }

    /// A USB device with a session id goes through the real device
    /// registry: it is listed as `usb` with its session id, and its init
    /// thread logs in with the stored token (temp home, never ~/.nova).
    #[test]
    fn usb_device_with_session_id_logs_in_with_stored_token() {
        use crate::mux::{
            CHANNEL_CMDSERVICE, CHANNEL_CONTROL, FLAG_ACK, HEADER_LEN as PMUX_HEADER_LEN,
            OP_OPEN_COMMAND, PMUX_MAGIC, PMUX_VERSION, encode_control,
        };
        use crate::tokens::sha1_hex;
        use crate::tokens::tests::TempHome;

        let home = TempHome::create();
        let token: Vec<u8> = (0..256u32).map(|i| (i * 7) as u8).collect();
        std::fs::create_dir(home.nova()).unwrap();
        std::fs::write(
            home.nova().join(std::str::from_utf8(DEV_NDUID).unwrap()),
            &token,
        )
        .unwrap();
        let host = Daemon::new(home.store());
        let link: Shared<Arc<mux::Device>> = Arc::new(Mutex::new(Link::new(
            b"castle-linux",
            MAX_MTU as u32,
            0,
            USBDEVFS_IOCTL_TIMEOUT,
            &host,
        )));
        let sid = lock(&link).snapshot().sessionid;
        let mut rxb = vec![0u8; MAX_MTU];
        let mut deliver = |p: &[u8]| {
            rxb[..p.len()].copy_from_slice(p);
            lock(&link).process_packet(&mut rxb, p.len(), &host)
        };
        let syn = syn_data(DEV, b"id:castle-linux sn:0123456789\0");
        assert_eq!(deliver(&syn), RxType::Protocol);
        let mut list = Vec::new();
        devices::dump_device_list(&mut list);
        let mine: Vec<String> = String::from_utf8(list)
            .unwrap()
            .lines()
            .filter(|l| l.contains(std::str::from_utf8(DEV_NDUID).unwrap()))
            .map(str::to_string)
            .collect();
        assert_eq!(mine.len(), 1, "{mine:?}");
        assert!(
            mine[0].ends_with(" usb castle-linux 0123456789"),
            "{mine:?}"
        );
        // Host SYN, then the init thread's open of channel 0x50.
        let mut txb = vec![0u8; MAX_MTU];
        let mut next = || {
            for _ in 0..100 {
                if let Some(n) = usbll::prepare_tx_packet(&link, &mut txb, MAX_MTU, &host).unwrap()
                {
                    return txb[..n].to_vec();
                }
            }
            panic!("nothing sent");
        };
        assert_eq!(Header::decode(&next()).command, CMD_SYN);
        let open = next();
        let ph = mux::Header::decode(&open[20..]);
        assert_eq!(ph.channel, CHANNEL_CONTROL);
        assert_eq!(
            &open[20 + PMUX_HEADER_LEN..],
            &encode_control(OP_OPEN_COMMAND, CHANNEL_CMDSERVICE)
        );
        let ack = mux::Header {
            magic: PMUX_MAGIC,
            version: PMUX_VERSION,
            flags: FLAG_ACK,
            channel: CHANNEL_CONTROL,
            sequence: ph.sequence,
            payload_len: 0,
            total_len: PMUX_HEADER_LEN as u32,
            crc: 0,
        };
        assert_eq!(deliver(&data(DEV, sid, &ack.encode())), RxType::Mux);
        let logint = next();
        let lh = mux::Header::decode(&logint[20..]);
        assert_eq!(lh.channel, CHANNEL_CMDSERVICE);
        let hash = sha1_hex(&[&token[..], b"0123456789"].concat());
        let want = [&[50, 0, 0, 0, 0, 5][..], b"token", &[0, 0, 0, 40], &hash].concat();
        assert_eq!(&logint[20 + PMUX_HEADER_LEN..], &want[..]);
        // Gone from the list with the link.
        usbll::destroy(&link, &host);
        let mut list = Vec::new();
        devices::dump_device_list(&mut list);
        assert!(
            !String::from_utf8(list)
                .unwrap()
                .contains(std::str::from_utf8(DEV_NDUID).unwrap())
        );
    }
}
