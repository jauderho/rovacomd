//! USB link layer ("usbll"): emulation of C `transport_usb.c` (host build)
//! and of the recovery records of `host/recovery.c`.
//!
//! Wire format (`transport_usb_struct.h`), all integers host byte order as
//! in C: `usbll_header` (20 bytes) = `u32 magic 'usbl'`, `u32 version 1`,
//! `u32 txid`, `u32 rxid`, `u32 command` (0 null, 1 rst, 2 syn, 3 data);
//! a SYN continues with `usbll_syn_header` (60 bytes) = `u8 nduid[40]`,
//! `u32 mtu`, `u32 heartbeat_interval`, `u32 timeout`, `u32 data_offset`,
//! `u32 data_length`, then optional data (`id:… sn:… mode:…`).
//!
//! [`Link`] is the per-link state machine with the outside world (clock,
//! `rand`, host nduid, logging, mux, device registry) behind [`Host`], so
//! it runs without hardware, threads or a real clock. Like C, it reads and
//! writes the caller's reused packet buffers: bytes a packet does not
//! cover keep what an earlier packet left there, and some of them go on
//! the wire (the 41 bytes after an `rst` header, the odd-length pad byte,
//! the SYN `data_offset`/`data_length` fields and the pmux pad byte, D16).
//! These bytes are deterministic for a given packet history.
//!
//! The host never initiates a SYN: a SYN from the device registers it
//! (`novacom_go_online`), and the next transmission answers with the host
//! SYN. Recovery: when a USB link ends, its [`Link`] (and so its mux,
//! channels and device port) is parked in [`Records`] for
//! `g_recovery_timeout` seconds; a newly attached device whose first
//! packet carries the same ids resumes it.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::devices::NDUID_CHRLEN;
use crate::log::{LOG_ALWAYS, LOG_ERROR, LOG_LLTRACE, LOG_TRACE};
use crate::mux::u32_at;
use crate::server::c_str;

pub const MAGIC: u32 = 0x7573_626c;
pub const VERSION: u32 = 1;
/// `sizeof(struct usbll_header)`.
pub const HEADER_LEN: usize = 20;
/// `sizeof(struct usbll_syn_header)`.
pub const SYN_HEADER_LEN: usize = 60;

pub const CMD_NULL: u32 = 0;
pub const CMD_RST: u32 = 1;
pub const CMD_SYN: u32 = 2;
pub const CMD_DATA: u32 = 3;

/// C `HEARTBEAT_PACKET_INTERVAL` (ms): default heartbeat.
pub const HEARTBEAT_INTERVAL: i32 = 1000;
/// C `TIMEOUT_PACKET` (ms): default link timeout.
pub const TIMEOUT_PACKET: i32 = 5000;
/// C `TRANSPORT_MAX_MTU` / `MAX_MTU`: link MTU and size of the C packet
/// buffers.
pub const MAX_MTU: usize = 16384;
/// The `timeout` the USB tx thread passes to
/// `novacom_usbll_prepare_tx_packet`: how long to wait for mux data.
pub const TX_WAIT: Duration = Duration::from_millis(100);
/// Size of a null or rst packet: header and the 41-byte host nduid string.
pub const NULL_PACKET_LEN: usize = HEADER_LEN + NDUID_CHRLEN + 1;

/// Offsets in `usbll_syn_header`.
const SYN_MTU: usize = 40;
const SYN_HEARTBEAT: usize = 44;
const SYN_TIMEOUT: usize = 48;
const SYN_DATA_OFFSET: usize = 52;
const SYN_DATA_LENGTH: usize = 56;
/// Index of the pmux header pad byte, which the C mux never writes.
const PMUX_PAD: usize = 5;
/// The C nova68 workaround values.
const NOVA68_TIMEOUT: i32 = 7_200_000;
/// Heartbeat and timeout C assumes for a SYN without them.
const OLD_HEARTBEAT: i32 = 250;
const OLD_TIMEOUT: i32 = 1000;

/// A decoded `usbll_header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub magic: u32,
    pub version: u32,
    pub txid: u32,
    pub rxid: u32,
    pub command: u32,
}

impl Header {
    /// Reads the header from the start of `buf`; bytes past its end read
    /// as zero.
    pub fn decode(buf: &[u8]) -> Self {
        Self {
            magic: u32_at(buf, 0),
            version: u32_at(buf, 4),
            txid: u32_at(buf, 8),
            rxid: u32_at(buf, 12),
            command: u32_at(buf, 16),
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        for (i, v) in [self.magic, self.version, self.txid, self.rxid, self.command]
            .into_iter()
            .enumerate()
        {
            h[4 * i..4 * i + 4].copy_from_slice(&v.to_ne_bytes());
        }
        h
    }
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}

/// `u32` as C `(int)` converts it.
fn as_int(v: u32) -> i32 {
    i32::from_ne_bytes(v.to_ne_bytes())
}

/// C `platform_delta_time_msecs(a, b)`.
///
/// C uses `gettimeofday`, so a clock step changes it; this uses the
/// injected monotonic clock.
pub fn delta_ms(a: Instant, b: Instant) -> i32 {
    i32::try_from(b.saturating_duration_since(a).as_millis()).unwrap_or(i32::MAX)
}

/// Result of [`Link::process_packet`] (C `PACKET_TYPE_*`). For a data
/// packet C returns the mux's result, which the host only compares with
/// `PACKET_TYPE_BADPACKET` and which is never that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxType {
    /// `PACKET_TYPE_NULL` (0).
    Null,
    /// `PACKET_TYPE_ERR` (1).
    Err,
    /// `PACKET_TYPE_PROTOCOL` (4).
    Protocol,
    /// `PACKET_TYPE_BADPACKET` (-1).
    Bad,
    /// The payload went to the mux (`novacom_process_packet`).
    Mux,
}

/// C link states (`state_listen` ... `state_established`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Listen = 0,
    SynSent = 1,
    SynRecv = 2,
    Established = 3,
}

/// The C recovery token (`usbll_recovery_token_t`): `magic`, `version`,
/// `txid`, `rxid`. Magic and version are always [`MAGIC`] and
/// [`VERSION`], so only the ids are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryToken {
    pub txid: u32,
    pub rxid: u32,
}

impl RecoveryToken {
    /// C `novacom_usbll_generate_recovery_token`: the ids of the header at
    /// the start of `buf` (the length is not checked, as in C).
    pub fn from_header(buf: &[u8]) -> Self {
        let h = Header::decode(buf);
        Self {
            txid: h.txid,
            rxid: h.rxid,
        }
    }
}

/// The C `platform_assert` in `novacom_usbll_prepare_tx_packet` failed: the
/// packet buffer is shorter than a null packet (a device SYN with an MTU
/// below 61). The `ASSERT FAILED` line is logged; C then crashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssertFailed;

/// Everything outside the link layer.
pub trait Host: Send + Sync {
    /// The mux of a registered device (C `device_handle_t`).
    type Dev: Clone + Send;

    /// C `platform_get_time`.
    fn now(&self) -> Instant;
    /// C `usleep` (used by the USB threads).
    fn sleep(&self, d: Duration);
    /// C `novacom_get_new_sessionid` (`rand()`).
    fn new_sessionid(&self) -> u32;
    /// C `novacom_nduid()`: the host nduid (40 characters; C adds a NUL).
    fn nduid(&self) -> [u8; NDUID_CHRLEN];
    /// C `log_printf(mask, "%s", msg)`.
    fn log(&self, mask: u32, msg: &[u8]);
    /// C `novacom_go_online(nduid, "usb", devtype, devdata)`.
    fn go_online(&self, nduid: &[u8], devtype: &[u8], devdata: Option<&[u8]>) -> Self::Dev;
    /// C `novacom_go_offline`.
    fn go_offline(&self, dev: &Self::Dev);
    /// C `novacom_process_packet(dev, buf, len)`: `buf` runs to the end of
    /// the receive buffer (the mux may read past `len`, D17).
    fn process_packet(&self, dev: &Self::Dev, buf: &[u8], len: usize);
    /// C `novacom_get_tx_packet(dev, packet, timeout)` with a
    /// `len`-byte packet buffer.
    fn get_tx_packet(&self, dev: &Self::Dev, timeout: Duration, len: usize) -> Option<Vec<u8>>;
    /// The recovery records (C `t_recovery_queue`).
    fn records(&self) -> &Mutex<Records<Self::Dev>>;
}

/// A link shared by its rx and tx threads and the recovery records (C
/// `novacom_usbll_handle_t` with its mutex).
pub type Shared<D> = Arc<Mutex<Link<D>>>;

/// Locks a link (C `platform_mutex_lock(&usbll_handle->lock)`).
pub fn lock<D>(link: &Mutex<Link<D>>) -> MutexGuard<'_, Link<D>> {
    link.lock().unwrap_or_else(PoisonError::into_inner)
}

/// C `struct novacom_usbll_state` (host fields).
pub struct Link<D> {
    /// Trace id (C `uid`: bus and device number).
    uid: u32,
    state: State,
    sessionid: u32,
    remoteid: u32,
    nextcommand: u32,
    reset_sessionid: u32,
    reset_remoteid: u32,
    max_mtu: u32,
    mtu: u32,
    heartbeat_interval: i32,
    timeout: i32,
    device: Option<D>,
    /// Changes whenever `device` does (the C pointer comparison).
    device_gen: u64,
    last_tx_time: Instant,
    /// C `char remote_nduid[41]`.
    remote_nduid: [u8; NDUID_CHRLEN + 1],
    devtype: Vec<u8>,
    synpacket_size: i32,
    recovery_token: Option<RecoveryToken>,
}

/// The state of a [`Link`], for tests and traces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub uid: u32,
    pub state: State,
    pub sessionid: u32,
    pub remoteid: u32,
    pub nextcommand: u32,
    pub reset_sessionid: u32,
    pub reset_remoteid: u32,
    pub max_mtu: u32,
    pub mtu: u32,
    pub heartbeat_interval: i32,
    pub timeout: i32,
    pub online: bool,
    pub nduid: Vec<u8>,
    pub synpacket_size: i32,
    pub recovery_token: Option<RecoveryToken>,
}

/// What [`Link::begin_tx`] leaves to do.
enum TxBegin<D> {
    /// The packet is ready (its length), or there is none.
    Done(Option<usize>),
    /// A data packet: the mux of `D` (whose generation is the `u64`) is to
    /// fill the payload, without the link locked.
    Data(D, u64),
}

impl<D: Clone> Link<D> {
    /// C `novacom_usbll_create(devtype, max_mtu, heartbeat, timeout)`;
    /// heartbeat and timeout ≤ 0 mean the defaults.
    pub fn new(
        devtype: &[u8],
        max_mtu: u32,
        heartbeat_interval: i32,
        timeout: i32,
        host: &impl Host<Dev = D>,
    ) -> Self {
        Self {
            uid: 0,
            state: State::Listen,
            sessionid: host.new_sessionid(),
            remoteid: 0,
            nextcommand: CMD_DATA,
            reset_sessionid: 0,
            reset_remoteid: 0,
            max_mtu,
            mtu: max_mtu,
            heartbeat_interval: if heartbeat_interval > 0 {
                heartbeat_interval
            } else {
                HEARTBEAT_INTERVAL
            },
            timeout: if timeout > 0 { timeout } else { TIMEOUT_PACKET },
            device: None,
            device_gen: 0,
            last_tx_time: host.now(),
            remote_nduid: [0; NDUID_CHRLEN + 1],
            devtype: devtype.to_vec(),
            synpacket_size: SYN_HEADER_LEN as i32,
            recovery_token: None,
        }
    }

    /// C `novacom_usbll_destroy`: a registered device goes offline.
    pub fn destroy(&mut self, host: &impl Host<Dev = D>) {
        if let Some(dev) = self.take_device() {
            host.go_offline(&dev);
        }
    }

    fn take_device(&mut self) -> Option<D> {
        self.device_gen += 1;
        self.device.take()
    }

    /// C `novacom_usbll_get_mtu`.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// C `novacom_usbll_get_timeout`.
    pub fn timeout(&self) -> i32 {
        self.timeout
    }

    /// C `novacom_usbll_get_nduid`: the device nduid as a C string.
    pub fn nduid(&self) -> &[u8] {
        c_str(&self.remote_nduid)
    }

    /// C `novacom_usbll_getuid`.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// C `novacom_usbll_setuid`.
    pub fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
    }

    /// C `novacom_usbll_get_recovery_token`: set by the SYN that
    /// registered the device.
    pub fn recovery_token(&self) -> Option<RecoveryToken> {
        self.recovery_token
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            uid: self.uid,
            state: self.state,
            sessionid: self.sessionid,
            remoteid: self.remoteid,
            nextcommand: self.nextcommand,
            reset_sessionid: self.reset_sessionid,
            reset_remoteid: self.reset_remoteid,
            max_mtu: self.max_mtu,
            mtu: self.mtu,
            heartbeat_interval: self.heartbeat_interval,
            timeout: self.timeout,
            online: self.device.is_some(),
            nduid: self.nduid().to_vec(),
            synpacket_size: self.synpacket_size,
            recovery_token: self.recovery_token,
        }
    }

    /// C `novacom_usbll_drop_offline`: the device goes offline with a new
    /// session id; the link listens again.
    pub fn drop_offline(&mut self, host: &impl Host<Dev = D>) {
        if let Some(dev) = self.take_device() {
            host.go_offline(&dev);
            self.sessionid = host.new_sessionid();
        }
        self.state = State::Listen;
        self.remoteid = 0;
        self.mtu = self.max_mtu;
    }

    /// C `novacom_usbll_process_packet` for the `len`-byte packet at the
    /// start of the receive buffer `buf` (`len` ≥ [`HEADER_LEN`], checked
    /// by [`check_packet_header`]). Like C, a SYN may write a NUL into
    /// `buf`, and the mux gets the rest of `buf` past the header.
    pub fn process_packet(
        &mut self,
        buf: &mut [u8],
        len: usize,
        host: &impl Host<Dev = D>,
    ) -> RxType {
        let h = Header::decode(buf);
        if h.command == CMD_RST {
            host.log(
                LOG_ERROR,
                format!(
                    "Got RESET packet, process it?, rxid=0x{:08x}, sessionid=0x{:08x}\n",
                    h.rxid, self.sessionid
                )
                .as_bytes(),
            );
            if h.rxid == self.sessionid {
                host.log(LOG_ERROR, b"Got RESET packet, restart...\n");
                self.drop_offline(host);
                return RxType::Protocol;
            }
        }
        if h.command == CMD_NULL && h.rxid == self.sessionid {
            return RxType::Null;
        }
        if self.state == State::Established {
            if h.rxid != self.sessionid && h.rxid != 0 && h.command != CMD_RST {
                self.schedule_rst(&h);
                return RxType::Err;
            }
            let mut t = RxType::Err;
            if h.command == CMD_DATA {
                // Intentional change (D34): a SYN shorter than 40 bytes
                // establishes the link without registering a device; C
                // then passes a NULL mux and crashes. Here the packet is
                // dropped.
                if let Some(dev) = &self.device {
                    host.process_packet(dev, &buf[HEADER_LEN..], len - HEADER_LEN);
                    t = RxType::Mux;
                }
            }
            if h.command == CMD_SYN && h.txid != self.remoteid {
                t = RxType::Bad;
            }
            return t;
        }
        match h.command {
            CMD_NULL | CMD_DATA => {
                // Out of sequence: answer with an rst.
                self.schedule_rst(&h);
                RxType::Err
            }
            CMD_SYN => {
                if self.device.is_none() {
                    self.register(&h, buf, len, host);
                }
                match self.state {
                    State::Listen => self.state = State::SynRecv,
                    State::SynSent => self.state = State::Established,
                    State::SynRecv | State::Established => {}
                }
                RxType::Protocol
            }
            CMD_RST => RxType::Err,
            _ => RxType::Bad,
        }
    }

    fn schedule_rst(&mut self, h: &Header) {
        self.nextcommand = CMD_RST;
        self.reset_sessionid = h.rxid;
        self.reset_remoteid = h.txid;
    }

    /// The SYN branch of C `novacom_usbll_process_packet` for a link
    /// without a device: negotiation, SYN data and registration.
    fn register(&mut self, h: &Header, buf: &mut [u8], len: usize, host: &impl Host<Dev = D>) {
        let syn_len = len - HEADER_LEN;
        self.synpacket_size = syn_len as i32;
        if syn_len < SYN_MTU {
            return;
        }
        let syn = HEADER_LEN;
        self.remote_nduid[..NDUID_CHRLEN].copy_from_slice(&buf[syn..syn + NDUID_CHRLEN]);
        self.remote_nduid[NDUID_CHRLEN] = 0;
        let mtu = u32_at(buf, syn + SYN_MTU);
        if syn_len > SYN_HEARTBEAT && mtu < self.mtu {
            self.mtu = mtu;
        }
        if syn_len >= SYN_DATA_OFFSET {
            let heartbeat = as_int(u32_at(buf, syn + SYN_HEARTBEAT));
            let timeout = as_int(u32_at(buf, syn + SYN_TIMEOUT));
            self.heartbeat_interval = self.heartbeat_interval.min(heartbeat);
            self.timeout = self.timeout.min(timeout);
            // nova68 workaround.
            if self.timeout == NOVA68_TIMEOUT {
                self.timeout -= 1;
            }
            if self.heartbeat_interval == HEARTBEAT_INTERVAL {
                self.heartbeat_interval -= 1;
            }
        } else {
            self.heartbeat_interval = OLD_HEARTBEAT;
            self.timeout = OLD_TIMEOUT;
        }
        let data_offset = u32_at(buf, syn + SYN_DATA_OFFSET);
        let data_length = u32_at(buf, syn + SYN_DATA_LENGTH);
        let mut data_at = None;
        if syn_len >= SYN_HEADER_LEN + data_length as usize
            && syn_len >= data_length.wrapping_add(data_offset) as usize
        {
            // Intentional change (D14): C writes the NUL at
            // `data_offset + data_length - 1` without checking that the
            // u32 sum did not wrap or that `data_length` is not 0; both
            // write far outside the buffer. Here such data is ignored.
            if data_length > 0 && data_offset.checked_add(data_length).is_some() {
                let start = syn + data_offset as usize;
                buf[start + data_length as usize - 1] = 0;
                data_at = Some(start);
            }
        } else if syn_len > SYN_DATA_OFFSET {
            host.log(LOG_LLTRACE, b"invalid data definition within syn packet\n");
        }
        let devdata = data_at.map(|at| c_str(&buf[at..]));
        let nduid = c_str(&self.remote_nduid).to_vec();
        #[cfg(target_os = "linux")]
        device_online(&nduid, host);
        self.device = Some(host.go_online(&nduid, &self.devtype, devdata));
        self.device_gen += 1;
        self.remoteid = h.txid;
        // C prints the data pointer with %p.
        let data_ptr = match data_at {
            Some(at) => format!("{:p}", buf[at..].as_ptr()),
            None if cfg!(target_os = "linux") => "(nil)".to_string(),
            None => "0x0".to_string(),
        };
        let shown_len = if data_at.is_some() { data_length } else { 0 };
        host.log(
            LOG_LLTRACE,
            format!(
                "got syn, mtu {}, heartbeat {}, timeout {}, len({}/{}/{}), data({})\n",
                self.mtu,
                self.heartbeat_interval,
                self.timeout,
                syn_len,
                SYN_HEADER_LEN,
                shown_len,
                data_ptr
            )
            .as_bytes(),
        );
        // C builds the token from this header, then patches in the host
        // session id ("rxid is not known yet to device").
        self.recovery_token = Some(RecoveryToken {
            txid: h.txid,
            rxid: self.sessionid,
        });
    }

    /// C `novacom_usbll_prepare_tx_packet` up to the mux call, with the
    /// link locked: writes the header (and a null, rst or SYN packet) into
    /// `buf`, of which `max_len` bytes may be used.
    fn begin_tx(
        &mut self,
        buf: &mut [u8],
        max_len: usize,
        host: &impl Host<Dev = D>,
    ) -> Result<TxBegin<D>, AssertFailed> {
        if max_len < NULL_PACKET_LEN {
            host.log(
                LOG_ERROR,
                b"ASSERT FAILED at (src/transport_usb.c:316): max_packet_len >= (sizeof(struct usbll_header) + NOVACOM_NDUID_STRLEN)\n",
            );
            return Err(AssertFailed);
        }
        put_u32(buf, 0, MAGIC);
        put_u32(buf, 4, VERSION);
        // A packet at least every heartbeat interval.
        if self.nextcommand != CMD_RST
            && delta_ms(self.last_tx_time, host.now()) > self.heartbeat_interval
        {
            self.nextcommand = CMD_NULL;
        }
        if self.nextcommand == CMD_NULL {
            self.nextcommand = CMD_DATA;
            // Only sent once established; else C retries as a data packet.
            if self.state == State::Established {
                put_u32(buf, 8, self.sessionid);
                put_u32(buf, 12, self.remoteid);
                put_u32(buf, 16, CMD_NULL);
                buf[HEADER_LEN..HEADER_LEN + NDUID_CHRLEN].copy_from_slice(&host.nduid());
                buf[HEADER_LEN + NDUID_CHRLEN] = 0;
                self.last_tx_time = host.now();
                return Ok(TxBegin::Done(Some(NULL_PACKET_LEN)));
            }
        } else if self.nextcommand == CMD_RST {
            put_u32(buf, 8, self.reset_sessionid);
            put_u32(buf, 12, self.reset_remoteid);
            put_u32(buf, 16, CMD_RST);
            self.nextcommand = CMD_DATA;
            self.last_tx_time = host.now();
            host.log(
                LOG_ALWAYS,
                format!(
                    "novacom_usbll_prepare_tx_packet:359: usbll({:08x}) sending rst, txid=0x{:08x}, rxid=0x{:08x}\n",
                    self.uid, self.reset_sessionid, self.reset_remoteid
                )
                .as_bytes(),
            );
            return Ok(TxBegin::Done(Some(NULL_PACKET_LEN)));
        }
        put_u32(buf, 8, self.sessionid);
        put_u32(buf, 12, self.remoteid);
        match self.state {
            // The host does not initiate a SYN; it answers one.
            State::Listen | State::SynSent => Ok(TxBegin::Done(None)),
            State::SynRecv => {
                put_u32(buf, 16, CMD_SYN);
                let syn = HEADER_LEN;
                buf[syn..syn + NDUID_CHRLEN].copy_from_slice(&host.nduid());
                put_u32(buf, syn + SYN_MTU, self.mtu);
                put_u32(buf, syn + SYN_HEARTBEAT, self.heartbeat_interval as u32);
                put_u32(buf, syn + SYN_TIMEOUT, self.timeout as u32);
                let mut len = HEADER_LEN + SYN_HEADER_LEN;
                if self.synpacket_size < SYN_HEADER_LEN as i32 {
                    host.log(
                        LOG_ERROR,
                        b"Got old syn USB packet. Adjusting packet length\n",
                    );
                    // synpacket_size is a received length, so not negative.
                    len = HEADER_LEN + usize::try_from(self.synpacket_size).unwrap_or(0);
                }
                self.state = State::Established;
                self.last_tx_time = host.now();
                Ok(TxBegin::Done(Some(len)))
            }
            State::Established => {
                put_u32(buf, 16, CMD_DATA);
                // Intentional change (D34): without a registered device C
                // passes a NULL mux and crashes; here there is no packet.
                Ok(match &self.device {
                    Some(dev) => TxBegin::Data(dev.clone(), self.device_gen),
                    None => TxBegin::Done(None),
                })
            }
        }
    }

    /// C `novacom_usbll_prepare_tx_packet` after the mux call, with the
    /// link locked again. Like the C mux, `pmux` is written into `buf`
    /// without its pad byte, also when it is then dropped.
    fn finish_tx(
        &mut self,
        generation: u64,
        pmux: Option<Vec<u8>>,
        buf: &mut [u8],
        host: &impl Host<Dev = D>,
    ) -> Option<usize> {
        let mut len = pmux.map(|p| {
            for (i, &b) in p.iter().enumerate() {
                if i != PMUX_PAD {
                    buf[HEADER_LEN + i] = b;
                }
            }
            HEADER_LEN + p.len()
        });
        if generation != self.device_gen {
            host.log(
                LOG_TRACE,
                b"novacom_usbll_prepare_tx_packet:459: novacom device was deleted while waiting for tx\n",
            );
            len = None;
        }
        if len.is_some() {
            self.last_tx_time = host.now();
        }
        len
    }
}

/// C `novacom_usbll_prepare_tx_packet(link, packet, 100)`: builds the next
/// packet in `buf` (`max_len` = the link MTU, at most `buf.len()`) and
/// returns its length, or `None` (C `TX_NO_PACKET`). A data packet waits
/// up to [`TX_WAIT`] for the mux, with the link unlocked as in C.
///
/// A packet whose length is a multiple of 64 and below `max_len` gets one
/// more byte (whatever `buf` holds there) "so it looks like a complete
/// usb transfer".
pub fn prepare_tx_packet<H: Host>(
    link: &Mutex<Link<H::Dev>>,
    buf: &mut [u8],
    max_len: usize,
    host: &H,
) -> Result<Option<usize>, AssertFailed> {
    let begin = lock(link).begin_tx(buf, max_len, host)?;
    let len = match begin {
        TxBegin::Done(len) => len,
        TxBegin::Data(dev, generation) => {
            let pmux = host.get_tx_packet(&dev, TX_WAIT, max_len - HEADER_LEN);
            lock(link).finish_tx(generation, pmux, buf, host)
        }
    };
    Ok(len.map(|n| {
        if n != max_len && n % 64 == 0 {
            n + 1
        } else {
            n
        }
    }))
}

/// C `novacom_usbll_check_packet_header(buf, len)` for a `len`-byte packet
/// at the start of the receive buffer `buf`: `true` (C
/// `PACKET_TYPE_BADPACKET`) if it is too short or has a wrong magic or
/// version; each problem is logged. Like C, a short packet's header is
/// completed from what `buf` still holds.
pub fn check_packet_header(buf: &[u8], len: usize, host: &impl Host) -> bool {
    let h = Header::decode(buf);
    let mut bad = false;
    if len < HEADER_LEN {
        host.log(
            LOG_ERROR,
            b"Invalid USB packet length. Make sure your novacomd versions match.\n",
        );
        bad = true;
    }
    if h.magic != MAGIC {
        host.log(
            LOG_ERROR,
            b"Got bad USB packet. Make sure your novacomd versions match.\n",
        );
        bad = true;
    }
    if h.version < VERSION {
        host.log(
            LOG_ERROR,
            b"Got packet with old usb transport header, please upgrade the other end\n",
        );
        bad = true;
    } else if h.version > VERSION {
        host.log(
            LOG_ERROR,
            b"Got packet with newer usb transport header than we support, please upgrade to newer version\n",
        );
        bad = true;
    }
    bad
}

/// C `novacom_usbll_destroy` on a shared link.
pub fn destroy<H: Host>(link: &Mutex<Link<H::Dev>>, host: &H) {
    lock(link).destroy(host);
}

/// C `novacom_usb_transport_deviceonline(nduid)` (`usb-linux.c`), called
/// on Linux only when a device registers: parked links of the same nduid
/// are destroyed.
pub fn device_online<H: Host>(nduid: &[u8], host: &H) {
    let mut records = host
        .records()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    records.remove(nduid, host);
}

/// One parked link (C `recovery_entry_t` and its
/// `transport_recovery_token_t`).
struct Record<D> {
    token: RecoveryToken,
    /// C `char nduid[41]`, filled with `snprintf("%s")`.
    nduid: Vec<u8>,
    link: Shared<D>,
    /// Seconds left.
    timeout: i32,
}

/// C `t_recovery_queue` (`recovery.c`), in insertion order.
pub struct Records<D> {
    entries: Vec<Record<D>>,
}

impl<D> Default for Records<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> Records<D> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// C `usbrecords_add`: parks `link` for `timeout` seconds (C
    /// `g_recovery_timeout`).
    pub fn add(&mut self, token: RecoveryToken, nduid: &[u8], link: Shared<D>, timeout: i32) {
        let nduid = c_str(nduid);
        self.entries.push(Record {
            token,
            nduid: nduid[..nduid.len().min(NDUID_CHRLEN)].to_vec(),
            link,
            timeout,
        });
    }

    /// C `usbrecords_find`: removes and returns the first link parked with
    /// `token`.
    pub fn find<H: Host<Dev = D>>(&mut self, token: &RecoveryToken, host: &H) -> Option<Shared<D>> {
        let i = self.entries.iter().position(|r| r.token == *token)?;
        let r = self.entries.remove(i);
        host.log(
            LOG_TRACE,
            &[
                b"usbrecords_find:105: Matches, nduid(",
                &r.nduid[..],
                b")\n",
            ]
            .concat(),
        );
        Some(r.link)
    }

    /// C `usbrecords_update(elapsed)`: counts every record down; those
    /// below zero are destroyed (their devices go offline).
    pub fn update<H: Host<Dev = D>>(&mut self, elapsed: i32, host: &H) {
        let mut i = 0;
        while i < self.entries.len() {
            let r = &mut self.entries[i];
            r.timeout = r.timeout.wrapping_sub(elapsed);
            if r.timeout < 0 {
                host.log(
                    LOG_TRACE,
                    b"usbrecords_update:146: expired timeout::destroy record\n",
                );
                let r = self.entries.remove(i);
                destroy(&r.link, host);
            } else {
                i += 1;
            }
        }
    }

    /// C `usbrecords_remove(nduid)`: destroys every link parked for
    /// `nduid` (C `strncmp(..., 41)`; a stored nduid has at most 40
    /// characters).
    pub fn remove<H: Host<Dev = D>>(&mut self, nduid: &[u8], host: &H) {
        let nduid = c_str(nduid);
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].nduid == nduid {
                host.log(
                    LOG_TRACE,
                    &[
                        b"usbrecords_remove:179: explicit remove::nduid(",
                        nduid,
                        b")\n",
                    ]
                    .concat(),
                );
                let r = self.entries.remove(i);
                destroy(&r.link, host);
            } else {
                i += 1;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    pub(crate) const HOST_NDUID: &[u8; 40] = b"0123456789abcdef0123456789abcdef01234567";
    pub(crate) const DEV_NDUID: &[u8; 40] = b"fedcba9876543210fedcba9876543210fedcba98";
    pub(crate) const DEV: u32 = 0xd0d0_0001;
    /// The first session id of a [`TestHost`].
    pub(crate) const SID0: u32 = 0x5e55_0001;

    pub(crate) type Hook = Box<dyn FnOnce() + Send>;

    /// A host with a virtual clock (`sleep` advances it), counting session
    /// ids from [`SID0`], devices numbered from 0, scripted mux packets
    /// (none when the script is empty; the wait then advances the clock)
    /// and a record of everything else.
    pub(crate) struct TestHost {
        t0: Instant,
        pub(crate) clock_ms: Mutex<u64>,
        next_sid: AtomicU32,
        ndevs: AtomicUsize,
        pub(crate) logs: Mutex<Vec<(u32, String)>>,
        pub(crate) events: Mutex<Vec<String>>,
        pub(crate) mux: Mutex<VecDeque<Vec<u8>>>,
        /// Runs once inside the next `get_tx_packet`.
        pub(crate) on_get_tx: Mutex<Option<Hook>>,
        records: Mutex<Records<usize>>,
    }

    impl TestHost {
        pub(crate) fn new() -> Self {
            Self {
                t0: Instant::now(),
                clock_ms: Mutex::new(0),
                next_sid: AtomicU32::new(SID0),
                ndevs: AtomicUsize::new(0),
                logs: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
                mux: Mutex::new(VecDeque::new()),
                on_get_tx: Mutex::new(None),
                records: Mutex::new(Records::new()),
            }
        }

        pub(crate) fn set_ms(&self, ms: u64) {
            *self.clock_ms.lock().unwrap() = ms;
        }

        pub(crate) fn ms(&self) -> u64 {
            *self.clock_ms.lock().unwrap()
        }

        pub(crate) fn logs(&self) -> Vec<(u32, String)> {
            self.logs.lock().unwrap().clone()
        }

        pub(crate) fn log_texts(&self) -> Vec<String> {
            self.logs().into_iter().map(|(_, t)| t).collect()
        }

        pub(crate) fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        pub(crate) fn queue_mux(&self, p: Vec<u8>) {
            self.mux.lock().unwrap().push_back(p);
        }

        pub(crate) fn records_len(&self) -> usize {
            self.records.lock().unwrap().len()
        }
    }

    impl Host for TestHost {
        type Dev = usize;

        fn now(&self) -> Instant {
            self.t0 + Duration::from_millis(self.ms())
        }

        fn sleep(&self, d: Duration) {
            *self.clock_ms.lock().unwrap() += d.as_millis() as u64;
        }

        fn new_sessionid(&self) -> u32 {
            self.next_sid.fetch_add(1, Ordering::Relaxed)
        }

        fn nduid(&self) -> [u8; NDUID_CHRLEN] {
            *HOST_NDUID
        }

        fn log(&self, mask: u32, msg: &[u8]) {
            self.logs
                .lock()
                .unwrap()
                .push((mask, String::from_utf8_lossy(msg).into_owned()));
        }

        fn go_online(&self, nduid: &[u8], devtype: &[u8], devdata: Option<&[u8]>) -> usize {
            let n = self.ndevs.fetch_add(1, Ordering::Relaxed);
            let data = devdata.map_or("-".to_string(), |d| String::from_utf8_lossy(d).into());
            self.events.lock().unwrap().push(format!(
                "online {n} {} {} {data}",
                String::from_utf8_lossy(nduid),
                String::from_utf8_lossy(devtype)
            ));
            n
        }

        fn go_offline(&self, dev: &usize) {
            self.events.lock().unwrap().push(format!("offline {dev}"));
        }

        fn process_packet(&self, dev: &usize, buf: &[u8], len: usize) {
            self.events
                .lock()
                .unwrap()
                .push(format!("pmux {dev} {:?}", &buf[..len]));
        }

        fn get_tx_packet(&self, dev: &usize, timeout: Duration, len: usize) -> Option<Vec<u8>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("gettx {dev} {} {len}", timeout.as_millis()));
            let hook = self.on_get_tx.lock().unwrap().take();
            if let Some(h) = hook {
                h();
            }
            let p = self.mux.lock().unwrap().pop_front();
            if p.is_none() {
                self.sleep(timeout);
            }
            p
        }

        fn records(&self) -> &Mutex<Records<usize>> {
            &self.records
        }
    }

    pub(crate) fn header(txid: u32, rxid: u32, command: u32) -> Vec<u8> {
        Header {
            magic: MAGIC,
            version: VERSION,
            txid,
            rxid,
            command,
        }
        .encode()
        .to_vec()
    }

    /// A SYN with the given fields, then `data`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn syn(
        txid: u32,
        mtu: u32,
        heartbeat: u32,
        timeout: u32,
        data_offset: u32,
        data_length: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut p = header(txid, 0, CMD_SYN);
        p.extend_from_slice(DEV_NDUID);
        for v in [mtu, heartbeat, timeout, data_offset, data_length] {
            p.extend_from_slice(&v.to_ne_bytes());
        }
        p.extend_from_slice(data);
        p
    }

    /// A device SYN with `data` right after the syn header.
    pub(crate) fn syn_data(txid: u32, data: &[u8]) -> Vec<u8> {
        syn(txid, 16384, 1000, 5000, 60, data.len() as u32, data)
    }

    pub(crate) fn data(txid: u32, rxid: u32, payload: &[u8]) -> Vec<u8> {
        [header(txid, rxid, CMD_DATA), payload.to_vec()].concat()
    }

    /// A receive buffer holding `p`.
    fn rxbuf(p: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; MAX_MTU];
        b[..p.len()].copy_from_slice(p);
        b
    }

    fn feed(link: &mut Link<usize>, host: &TestHost, p: &[u8]) -> RxType {
        link.process_packet(&mut rxbuf(p), p.len(), host)
    }

    pub(crate) fn new_link(host: &TestHost) -> Link<usize> {
        Link::new(b"castle-linux", MAX_MTU as u32, 0, 2000, host)
    }

    /// Prepares one packet in `buf`; returns its bytes.
    fn tx(link: &Shared<usize>, host: &TestHost, buf: &mut [u8]) -> Option<Vec<u8>> {
        let max = lock(link).mtu() as usize;
        prepare_tx_packet(link, buf, max, host)
            .unwrap()
            .map(|n| buf[..n].to_vec())
    }

    /// A link established by a device SYN with `data`; the host SYN is
    /// sent.
    fn established(host: &TestHost, data: &[u8]) -> (Shared<usize>, Vec<u8>) {
        let link = Arc::new(Mutex::new(new_link(host)));
        assert_eq!(
            feed(&mut lock(&link), host, &syn_data(DEV, data)),
            RxType::Protocol
        );
        let mut buf = vec![0u8; MAX_MTU];
        let p = tx(&link, host, &mut buf).unwrap();
        assert_eq!(Header::decode(&p).command, CMD_SYN);
        (link, buf)
    }

    #[test]
    fn header_codec_and_constants() {
        let h = header(0x0102_0304, 0x0506_0708, CMD_DATA);
        assert_eq!(&h[..4], b"lbsu"); // 'usbl' little-endian
        let d = Header::decode(&h);
        assert_eq!((d.txid, d.rxid, d.command), (0x0102_0304, 0x0506_0708, 3));
        assert_eq!(Header::decode(&h[..10]).rxid, 0);
        assert_eq!(NULL_PACKET_LEN, 61);
        assert_eq!(
            RecoveryToken::from_header(&h),
            RecoveryToken {
                txid: 0x0102_0304,
                rxid: 0x0506_0708
            }
        );
    }

    #[test]
    fn create_defaults() {
        let host = TestHost::new();
        let l = Link::<usize>::new(b"", 16384, 0, 0, &host);
        let s = l.snapshot();
        assert_eq!(
            (s.state, s.sessionid, s.heartbeat_interval, s.timeout, s.mtu),
            (State::Listen, SID0, 1000, 5000, 16384)
        );
        assert_eq!(
            (s.nextcommand, s.synpacket_size, s.online),
            (CMD_DATA, 60, false)
        );
        let l = Link::<usize>::new(b"", 512, 300, 2000, &host);
        assert_eq!(
            (l.snapshot().heartbeat_interval, l.timeout(), l.mtu()),
            (300, 2000, 512)
        );
        assert_eq!(l.nduid(), b"");
    }

    #[test]
    fn header_check_errors_in_c_order() {
        let host = TestHost::new();
        let good = header(1, 2, CMD_DATA);
        assert!(!check_packet_header(&good, 20, &host));
        // Oversized packets are fine for the header check.
        assert!(!check_packet_header(&rxbuf(&good), MAX_MTU, &host));
        assert!(host.logs().is_empty());
        let mut v0 = good.clone();
        v0[4] = 0;
        let mut v2 = good.clone();
        v2[4] = 2;
        let mut magic = good.clone();
        magic[3] = 0;
        let cases: [(&[u8], usize, &[&str]); 5] = [
            (&good, 19, &["Invalid USB packet length"]),
            (
                &[],
                0,
                &["Invalid USB packet length", "Got bad USB packet", "old usb"],
            ),
            (&v0, 20, &["old usb transport header"]),
            (&v2, 20, &["newer usb transport header"]),
            (&magic, 20, &["Got bad USB packet"]),
        ];
        for (p, len, want) in cases {
            host.logs.lock().unwrap().clear();
            assert!(check_packet_header(p, len, &host));
            let logs = host.logs();
            assert_eq!(logs.len(), want.len(), "{logs:?}");
            for ((mask, text), w) in logs.iter().zip(want) {
                assert_eq!(*mask, LOG_ERROR);
                assert!(text.contains(w) && text.ends_with('\n'), "{text}");
            }
        }
        // A short packet is completed from the buffer.
        let mut b = rxbuf(&good);
        b[..2].copy_from_slice(b"xx");
        host.logs.lock().unwrap().clear();
        assert!(check_packet_header(&b, 2, &host));
        assert_eq!(host.logs().len(), 2);
    }

    #[test]
    fn syn_registers_and_host_answers() {
        let host = TestHost::new();
        let (link, _) = established(&host, b"id:castle sn:0123456789 mode:x\0");
        let s = lock(&link).snapshot();
        assert_eq!(s.state, State::Established);
        assert_eq!(
            (s.remoteid, s.heartbeat_interval, s.timeout),
            (DEV, 999, 2000)
        );
        assert_eq!(s.nduid, DEV_NDUID);
        assert_eq!(
            s.recovery_token,
            Some(RecoveryToken {
                txid: DEV,
                rxid: SID0
            })
        );
        assert_eq!(
            host.events()[0],
            format!(
                "online 0 {} castle-linux id:castle sn:0123456789 mode:x",
                std::str::from_utf8(DEV_NDUID).unwrap()
            )
        );
        let host_syn = syn_reply(&host);
        assert_eq!(&host_syn[..20], &header(SID0, DEV, CMD_SYN)[..]);
        assert_eq!(&host_syn[20..60], HOST_NDUID);
        assert_eq!(u32_at(&host_syn, 60), 16384);
        assert_eq!(u32_at(&host_syn, 64), 999);
        assert_eq!(u32_at(&host_syn, 68), 2000);
        assert!(host.logs().iter().any(|(m, t)| *m == LOG_LLTRACE
            && t.starts_with(
                "got syn, mtu 16384, heartbeat 999, timeout 2000, len(91/60/31), data(0x"
            )));
    }

    /// The host SYN of a fresh link answering a plain device SYN.
    fn syn_reply(host: &TestHost) -> Vec<u8> {
        let link = Arc::new(Mutex::new(new_link(host)));
        let sid = lock(&link).snapshot().sessionid;
        feed(&mut lock(&link), host, &syn_data(DEV, b"\0"));
        let mut buf = vec![0u8; MAX_MTU];
        let p = tx(&link, host, &mut buf).unwrap();
        assert_eq!(p.len(), 80);
        let mut p = p;
        p[8..12].copy_from_slice(&SID0.to_ne_bytes());
        assert_ne!(sid, 0);
        p
    }

    #[test]
    fn listen_sends_nothing_and_answers_strays_with_rst() {
        let host = TestHost::new();
        let link = Arc::new(Mutex::new(new_link(&host)));
        lock(&link).set_uid(0x0003_0004);
        let mut buf = vec![0u8; MAX_MTU];
        assert_eq!(tx(&link, &host, &mut buf), None);
        // Even after the heartbeat interval.
        host.set_ms(5000);
        assert_eq!(tx(&link, &host, &mut buf), None);
        assert_eq!(
            feed(&mut lock(&link), &host, &data(7, 8, b"x")),
            RxType::Err
        );
        let rst = tx(&link, &host, &mut buf).unwrap();
        assert_eq!(rst.len(), 61);
        assert_eq!(&rst[..20], &header(8, 7, CMD_RST)[..]);
        assert_eq!(
            host.log_texts().last().unwrap(),
            "novacom_usbll_prepare_tx_packet:359: usbll(00030004) sending rst, txid=0x00000008, rxid=0x00000007\n"
        );
        assert_eq!(tx(&link, &host, &mut buf), None);
        // Null packets (not for us) too; rst and unknown commands not.
        assert_eq!(
            feed(&mut lock(&link), &host, &header(9, 10, CMD_NULL)),
            RxType::Err
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &header(9, 10, CMD_RST)),
            RxType::Err
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &header(9, 10, 4)),
            RxType::Bad
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &header(9, SID0, CMD_NULL)),
            RxType::Null
        );
        let s = lock(&link).snapshot();
        assert_eq!(
            (s.reset_sessionid, s.reset_remoteid, s.nextcommand),
            (10, 9, CMD_RST)
        );
    }

    #[test]
    fn established_data_null_and_heartbeat() {
        let host = TestHost::new();
        let (link, mut buf) = established(&host, b"id:a\0");
        assert_eq!(
            feed(&mut lock(&link), &host, &data(DEV, SID0, b"pmux!")),
            RxType::Mux
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &data(DEV, 0, b"z")),
            RxType::Mux
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &header(DEV, SID0, CMD_NULL)),
            RxType::Null
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &header(DEV, 0, CMD_NULL)),
            RxType::Err
        );
        let ev = host.events();
        assert_eq!(ev[1], "pmux 0 [112, 109, 117, 120, 33]");
        assert_eq!(ev[2], "pmux 0 [122]");
        // Data from the mux, without its pad byte.
        host.queue_mux(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let p = tx(&link, &host, &mut buf).unwrap();
        assert_eq!(&p[..20], &header(SID0, DEV, CMD_DATA)[..]);
        assert_eq!(&p[20..], &[1, 2, 3, 4, 5, b'5', 7, 8]);
        assert_eq!(host.events().last().unwrap(), "gettx 0 100 16364");
        // Nothing from the mux: no packet (the wait took 100 ms).
        assert_eq!(tx(&link, &host, &mut buf), None);
        assert_eq!(host.ms(), 100);
        // After 999 ms since the last packet the wait still happens; after
        // more than 999 ms a null packet goes out.
        host.set_ms(999);
        host.queue_mux(vec![9; 30]);
        assert_eq!(tx(&link, &host, &mut buf).unwrap().len(), 50);
        host.set_ms(1999);
        let null = tx(&link, &host, &mut buf).unwrap();
        assert_eq!(null.len(), 61);
        assert_eq!(&null[..20], &header(SID0, DEV, CMD_NULL)[..]);
        assert_eq!(&null[20..60], HOST_NDUID);
        assert_eq!(null[60], 0);
    }

    #[test]
    fn established_rst_out_of_session_and_syns() {
        let host = TestHost::new();
        let (link, mut buf) = established(&host, b"id:a\0");
        assert_eq!(
            feed(&mut lock(&link), &host, &data(DEV, 0x55, b"")),
            RxType::Err
        );
        let rst = tx(&link, &host, &mut buf).unwrap();
        assert_eq!(&rst[..20], &header(0x55, DEV, CMD_RST)[..]);
        // The 41 bytes after the header are left from the host SYN.
        assert_eq!(&rst[20..60], HOST_NDUID);
        assert_eq!(
            feed(&mut lock(&link), &host, &syn_data(DEV, b"\0")),
            RxType::Err
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &syn_data(DEV + 1, b"\0")),
            RxType::Bad
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &header(DEV, 0x66, CMD_RST)),
            RxType::Err
        );
        assert_eq!(
            feed(&mut lock(&link), &host, &header(DEV, SID0, 7)),
            RxType::Err
        );
        assert_eq!(lock(&link).snapshot().state, State::Established);
        // An rst for us: offline, new session, listen.
        host.logs.lock().unwrap().clear();
        assert_eq!(
            feed(&mut lock(&link), &host, &header(DEV, SID0, CMD_RST)),
            RxType::Protocol
        );
        assert_eq!(
            host.log_texts(),
            [
                "Got RESET packet, process it?, rxid=0x5e550001, sessionid=0x5e550001\n",
                "Got RESET packet, restart...\n"
            ]
        );
        let s = lock(&link).snapshot();
        assert_eq!(
            (s.state, s.sessionid, s.remoteid, s.online),
            (State::Listen, SID0 + 1, 0, false)
        );
        assert_eq!(host.events().last().unwrap(), "offline 0");
        // Recovery token and remote nduid are kept.
        assert!(s.recovery_token.is_some());
        assert_eq!(s.nduid, DEV_NDUID);
    }

    #[test]
    fn odd_length_rule_uses_stale_byte() {
        let host = TestHost::new();
        let (link, mut buf) = established(&host, b"id:a\0");
        host.queue_mux(vec![0xaa; 100]);
        assert_eq!(tx(&link, &host, &mut buf).unwrap().len(), 120);
        host.queue_mux(vec![0xbb; 44]);
        let p = tx(&link, &host, &mut buf).unwrap();
        assert_eq!(p.len(), 65);
        assert_eq!(p[64], 0xaa);
        // Exactly the MTU: no extra byte.
        let host = TestHost::new();
        let link = Arc::new(Mutex::new(new_link(&host)));
        feed(
            &mut lock(&link),
            &host,
            &syn(DEV, 128, 1000, 5000, 60, 1, b"\0"),
        );
        let mut buf = vec![0u8; MAX_MTU];
        tx(&link, &host, &mut buf).unwrap();
        host.queue_mux(vec![1; 108]);
        assert_eq!(tx(&link, &host, &mut buf).unwrap().len(), 128);
        assert_eq!(host.events().last().unwrap(), "gettx 0 100 108");
    }

    #[test]
    fn syn_negotiation_and_old_formats() {
        let full = syn(DEV, 1000, 300, 1500, 0xffff, 1, b"");
        // (syn length, mtu, heartbeat, timeout, registered)
        let cases = [
            (39, 16384, 1000, 2000, false),
            (40, 16384, 250, 1000, true),
            (44, 16384, 250, 1000, true),
            (45, 1000, 250, 1000, true),
            (52, 1000, 300, 1500, true),
            (60, 1000, 300, 1500, true),
        ];
        for (len, mtu, hb, to, reg) in cases {
            let host = TestHost::new();
            let mut l = new_link(&host);
            assert_eq!(feed(&mut l, &host, &full[..20 + len]), RxType::Protocol);
            let s = l.snapshot();
            assert_eq!(
                (
                    s.mtu,
                    s.heartbeat_interval,
                    s.timeout,
                    s.online,
                    s.synpacket_size
                ),
                (mtu, hb, to, reg, len as i32),
                "syn length {len}"
            );
            assert_eq!(s.state, State::SynRecv);
        }
        // Old SYN: the answer is as long as the device's.
        let host = TestHost::new();
        let link = Arc::new(Mutex::new(new_link(&host)));
        feed(&mut lock(&link), &host, &full[..20 + 48]);
        let mut buf = vec![0u8; MAX_MTU];
        assert_eq!(tx(&link, &host, &mut buf).unwrap().len(), 68);
        assert!(
            host.log_texts()
                .contains(&"Got old syn USB packet. Adjusting packet length\n".to_string())
        );
        // nova68 workaround and values from the device as int (D15, kept).
        let host = TestHost::new();
        let mut l = Link::new(b"", 16384, 0, 8_000_000, &host);
        feed(
            &mut l,
            &host,
            &syn(DEV, 16384, 1000, 7_200_000, 0xffff, 1, b""),
        );
        assert_eq!(
            (l.snapshot().heartbeat_interval, l.timeout()),
            (999, 7_199_999)
        );
        let mut l = new_link(&host);
        feed(&mut l, &host, &syn(DEV, 0, u32::MAX, 0, 0xffff, 1, b""));
        assert_eq!(
            (l.mtu(), l.snapshot().heartbeat_interval, l.timeout()),
            (0, -1, 0)
        );
    }

    #[test]
    fn second_syn_does_not_register_again() {
        let host = TestHost::new();
        let mut l = new_link(&host);
        feed(&mut l, &host, &syn_data(DEV, b"id:a\0"));
        feed(&mut l, &host, &syn_data(DEV + 5, b"id:b\0"));
        assert_eq!(host.events().len(), 1);
        assert_eq!(l.snapshot().remoteid, DEV);
        assert_eq!(l.snapshot().state, State::SynRecv);
    }

    #[test]
    fn syn_data_bounds() {
        let host = TestHost::new();
        let online = |p: &[u8]| {
            let mut l = new_link(&host);
            host.events.lock().unwrap().clear();
            host.logs.lock().unwrap().clear();
            let mut b = rxbuf(p);
            l.process_packet(&mut b, p.len(), &host);
            (host.events()[0].clone(), b)
        };
        let id = std::str::from_utf8(DEV_NDUID).unwrap();
        // The last data byte becomes a NUL, also in the buffer.
        let (ev, b) = online(&syn_data(DEV, b"id:abcdef"));
        assert_eq!(ev, format!("online 0 {id} castle-linux id:abcde"));
        assert_eq!(b[88], 0);
        // Data not fitting the packet: ignored, traced.
        let (ev, _) = online(&syn(DEV, 16384, 1000, 5000, 60, 10, b"id:x\0"));
        assert!(ev.ends_with(" -"), "{ev}");
        assert_eq!(
            host.logs()[0],
            (
                LOG_LLTRACE,
                "invalid data definition within syn packet\n".to_string()
            )
        );
        // The packet must hold the syn header plus `data_length` bytes,
        // but the data may start inside the syn header.
        let (ev, _) = online(&syn(DEV, 16384, 1000, 5000, 56, 4, b"abcd"));
        assert!(ev.ends_with(" \u{4}"), "{ev:?}");
    }

    /// D14: C writes the terminating NUL far outside its buffer for
    /// `data_length == 0` or a wrapping `data_offset + data_length`; here
    /// the data is ignored, without the trace of misfitting data.
    #[test]
    fn d14_syn_data_that_c_writes_out_of_bounds_is_ignored() {
        for (offset, length) in [(0u32, 0u32), (60, 0), (0xffff_fff0, 0x10), (u32::MAX, 1)] {
            let host = TestHost::new();
            let mut l = new_link(&host);
            let p = syn(DEV, 16384, 1000, 5000, offset, length, &[b'x'; 16]);
            let mut b = rxbuf(&p);
            assert_eq!(l.process_packet(&mut b, p.len(), &host), RxType::Protocol);
            assert_eq!(b, rxbuf(&p), "buffer changed for {offset}/{length}");
            assert!(host.events()[0].ends_with(" -"), "{:?}", host.events());
            assert!(!host.log_texts().iter().any(|t| t.contains("invalid data")));
        }
    }

    /// D34: a SYN shorter than 40 bytes establishes the link without a
    /// device; C then passes a NULL mux and crashes.
    #[test]
    fn d34_link_without_device_drops_data() {
        let host = TestHost::new();
        let link = Arc::new(Mutex::new(new_link(&host)));
        let p = syn(DEV, 16384, 1000, 5000, 0, 0, b"");
        feed(&mut lock(&link), &host, &p[..20 + 10]);
        let mut buf = vec![0u8; MAX_MTU];
        assert_eq!(tx(&link, &host, &mut buf).unwrap().len(), 30);
        assert_eq!(lock(&link).snapshot().state, State::Established);
        assert_eq!(
            feed(&mut lock(&link), &host, &data(DEV, SID0, b"x")),
            RxType::Err
        );
        assert_eq!(tx(&link, &host, &mut buf), None);
        assert!(host.events().is_empty());
    }

    #[test]
    fn device_deleted_while_waiting_for_mux() {
        let host = Arc::new(TestHost::new());
        let (link, mut buf) = established(&host, b"id:a\0");
        let (l2, h2) = (Arc::clone(&link), Arc::clone(&host));
        *host.on_get_tx.lock().unwrap() = Some(Box::new(move || lock(&l2).drop_offline(&*h2)));
        host.queue_mux(vec![7; 10]);
        assert_eq!(tx(&link, &host, &mut buf), None);
        assert_eq!(
            host.log_texts().last().unwrap(),
            "novacom_usbll_prepare_tx_packet:459: novacom device was deleted while waiting for tx\n"
        );
        // The mux bytes still reached the buffer, as in C.
        assert_eq!(buf[20], 7);
    }

    #[test]
    fn mtu_below_null_packet_fails_the_assert() {
        let host = TestHost::new();
        let link = Arc::new(Mutex::new(new_link(&host)));
        feed(
            &mut lock(&link),
            &host,
            &syn(DEV, 60, 1000, 5000, 0xffff, 1, b""),
        );
        let mut buf = vec![0u8; MAX_MTU];
        assert_eq!(
            prepare_tx_packet(&link, &mut buf, 60, &host),
            Err(AssertFailed)
        );
        assert_eq!(
            host.logs().last().unwrap(),
            &(LOG_ERROR, "ASSERT FAILED at (src/transport_usb.c:316): max_packet_len >= (sizeof(struct usbll_header) + NOVACOM_NDUID_STRLEN)\n".to_string())
        );
        assert!(prepare_tx_packet(&link, &mut buf, 61, &host).is_ok());
    }

    #[test]
    fn drop_offline_and_destroy() {
        let host = TestHost::new();
        let (link, _) = established(&host, b"\0");
        lock(&link).drop_offline(&host);
        lock(&link).drop_offline(&host);
        assert_eq!(lock(&link).snapshot().sessionid, SID0 + 1);
        destroy(&link, &host);
        assert_eq!(
            host.events()
                .iter()
                .filter(|e| e.starts_with("offline"))
                .count(),
            1
        );
        let (link, _) = established(&host, b"\0");
        destroy(&link, &host);
        assert_eq!(host.events().last().unwrap(), "offline 1");
    }

    fn parked(host: &TestHost, txid: u32) -> Shared<usize> {
        let link = Arc::new(Mutex::new(new_link(host)));
        feed(&mut lock(&link), host, &syn_data(txid, b"\0"));
        link
    }

    #[test]
    fn records_window_find_and_remove() {
        let host = TestHost::new();
        let a = parked(&host, 0xa);
        let b = parked(&host, 0xb);
        let ta = lock(&a).recovery_token().unwrap();
        let tb = lock(&b).recovery_token().unwrap();
        let mut r = Records::new();
        r.add(ta, lock(&a).nduid(), Arc::clone(&a), 2);
        r.add(tb, b"other", Arc::clone(&b), 5);
        // Inside the window: found once, then gone.
        r.update(1, &host);
        r.update(1, &host);
        assert_eq!(r.len(), 2);
        let found = r.find(&ta, &host).unwrap();
        assert!(Arc::ptr_eq(&found, &a));
        assert!(r.find(&ta, &host).is_none());
        assert!(host.log_texts().contains(&format!(
            "usbrecords_find:105: Matches, nduid({})\n",
            std::str::from_utf8(DEV_NDUID).unwrap()
        )));
        // Outside the window: destroyed after `timeout + 1` updates.
        r.add(ta, lock(&a).nduid(), Arc::clone(&a), 2);
        r.update(2, &host);
        assert_eq!(r.len(), 2);
        r.update(1, &host);
        assert_eq!(r.len(), 1);
        assert_eq!(host.events().last().unwrap(), "offline 0");
        // Removal by nduid (C string compare).
        r.remove(b"other\0junk", &host);
        assert!(r.is_empty());
        assert_eq!(host.events().last().unwrap(), "offline 1");
        assert!(
            host.log_texts()
                .last()
                .unwrap()
                .contains("explicit remove::nduid(other)")
        );
    }

    #[test]
    fn records_keep_at_most_40_nduid_chars() {
        let host = TestHost::new();
        let a = parked(&host, 1);
        let mut r = Records::new();
        let long = [&DEV_NDUID[..], b"XYZ"].concat();
        r.add(RecoveryToken { txid: 1, rxid: 2 }, &long, a, 5);
        r.remove(&long, &host);
        assert_eq!(r.len(), 1);
        r.remove(DEV_NDUID, &host);
        assert!(r.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syn_of_parked_nduid_destroys_record_on_linux() {
        let host = TestHost::new();
        let a = parked(&host, 1);
        let t = lock(&a).recovery_token().unwrap();
        host.records().lock().unwrap().add(t, DEV_NDUID, a, 5);
        let _b = parked(&host, 2);
        assert_eq!(host.records_len(), 0);
        assert!(host.events().contains(&"offline 0".to_string()));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn syn_of_parked_nduid_keeps_record_on_macos() {
        let host = TestHost::new();
        let a = parked(&host, 1);
        let t = lock(&a).recovery_token().unwrap();
        host.records().lock().unwrap().add(t, DEV_NDUID, a, 5);
        let _b = parked(&host, 2);
        assert_eq!(host.records_len(), 1);
    }
}
