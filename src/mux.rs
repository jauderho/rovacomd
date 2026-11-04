//! Channel multiplexer: emulation of C `mux.c` (host build).
//!
//! Wire format (`mux.h`), all integers host byte order as in C:
//! `pmux_header` (28 bytes) = `u32 magic 'pmux'`, `u8 version 3`, `u8 pad`,
//! `u16 flags (1 = ACK)`, `u32 channel`, `u32 sequence`, `u32 payload_len`,
//! `u32 total_len`, `u32 crc` (Adler-32 of the payload, 0 = unchecked),
//! then the payload. Control messages on channel 1: `u32 op`,
//! `u32 channel`, `u32 len = 12`.
//!
//! [`Mux`] is the per-device state machine with time passed in, so it can
//! be tested without threads. [`Device`] wraps it the way the C
//! `mux_instance` is shared: one mutex, the transmit wake-up event, and
//! the blocking calls (`novacom_get_tx_packet`, the synchronous channel
//! open). C runs buffer-queue callbacks under the mux mutex; here they run
//! right after it is released (they only wake other threads).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use crate::bufq::BufQueue;
use crate::{cmdparse, devcmd, log};

pub const PMUX_MAGIC: u32 = 0x706d_7578;
pub const PMUX_VERSION: u8 = 3;
pub const FLAG_ACK: u16 = 1;
/// `sizeof(struct pmux_header)`.
pub const HEADER_LEN: usize = 28;
/// `sizeof(struct pmux_control_header)`.
pub const CONTROL_LEN: usize = 12;

pub const OP_NONE: u32 = 0;
pub const OP_CHANNEL_CLOSED: u32 = 1;
pub const OP_OPEN: u32 = 2;
pub const OP_OPEN_COMMAND: u32 = 3;
pub const OP_CLOSE: u32 = 4;

pub const CHANNEL_NULL: u32 = 0;
pub const CHANNEL_CONTROL: u32 = 1;
pub const CHANNEL_CMDSERVICE: u32 = 0x50;
pub const CHANNEL_MAX_FIXED: u32 = 0xfff;
pub const CHANNEL_HOST_BASE: u32 = 0x1000;
pub const CHANNEL_MAX_HOST: u32 = 0x7fff_ffff;

/// C `RETRANSMIT_WAIT_PERIOD`.
pub const RETRANSMIT_WAIT: Duration = Duration::from_millis(50);

/// Reply of the host command handler (`commands_device.c`), NUL included.
const UNRECOGNIZED: &[u8] = b"unrecognized command\n\0";

/// C `adler()` (`mux.c`): Adler-32; 1 for no data.
pub fn adler(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5550) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// The `u32` at `at` (host byte order); bytes past the end of `buf` read
/// as zero.
pub(crate) fn u32_at(buf: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    for (i, b) in w.iter_mut().enumerate() {
        *b = buf.get(at + i).copied().unwrap_or(0);
    }
    u32::from_ne_bytes(w)
}

/// `u32` as C `%d` prints it.
pub(crate) fn c_int(v: u32) -> i32 {
    i32::from_ne_bytes(v.to_ne_bytes())
}

/// A decoded `pmux_header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub magic: u32,
    pub version: u8,
    pub flags: u16,
    pub channel: u32,
    pub sequence: u32,
    pub payload_len: u32,
    pub total_len: u32,
    pub crc: u32,
}

impl Header {
    /// Reads the header from the start of `buf`; bytes past its end read
    /// as zero.
    pub fn decode(buf: &[u8]) -> Self {
        let b = |i: usize| buf.get(i).copied().unwrap_or(0);
        Self {
            magic: u32_at(buf, 0),
            version: b(4),
            flags: u16::from_ne_bytes([b(6), b(7)]),
            channel: u32_at(buf, 8),
            sequence: u32_at(buf, 12),
            payload_len: u32_at(buf, 16),
            total_len: u32_at(buf, 20),
            crc: u32_at(buf, 24),
        }
    }

    /// The 28 header bytes (`_pad` is 0, as in the zeroed C tx buffer).
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&self.magic.to_ne_bytes());
        h[4] = self.version;
        h[6..8].copy_from_slice(&self.flags.to_ne_bytes());
        for (at, v) in [
            (8, self.channel),
            (12, self.sequence),
            (16, self.payload_len),
            (20, self.total_len),
            (24, self.crc),
        ] {
            h[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        }
        h
    }
}

/// A control message payload: `op`, `channel`, `len = 12`.
pub fn encode_control(op: u32, channel: u32) -> [u8; CONTROL_LEN] {
    let mut m = [0u8; CONTROL_LEN];
    m[0..4].copy_from_slice(&op.to_ne_bytes());
    m[4..8].copy_from_slice(&channel.to_ne_bytes());
    m[8..12].copy_from_slice(&(CONTROL_LEN as u32).to_ne_bytes());
    m
}

/// Callback of a transmitted buffer (C `novacom_async_callback`), run once
/// the device acknowledged it or the channel went away.
pub type Notify = Box<dyn FnOnce() + Send>;

/// Work a channel callback starts once the mux is released (C creates the
/// thread inside the callback; it runs when the caller drops the lock).
pub type Spawn = Box<dyn FnOnce(Arc<Device>) + Send>;

/// Receiver of a client channel (C `socketchan_read_callback`). `data` is
/// `None` when the channel shuts down (C `err = -1`). A negative return
/// value withholds the ack, so the device retransmits.
pub trait ClientReader: Send + Sync {
    fn read(&self, channel: u32, data: Option<&[u8]>) -> i32;
}

/// Receiver of the service channel 0x50 (C `socketcmd_read_callback`).
/// It gets the mux so that it can queue the next request: C re-enters its
/// recursive mux lock from the callback.
pub trait ServiceReader: Send + Sync {
    fn read(&self, mux: &mut Mux, channel: u32, data: Option<&[u8]>) -> i32;
}

/// C `rx_callback` of a channel.
#[derive(Clone)]
pub enum Reader {
    /// `control_channel_rx_callback`.
    Control,
    /// `novacom_handle_command_fromclient` (a channel the device opened
    /// with `OPEN_COMMAND`, D1).
    Command,
    Client(Arc<dyn ClientReader>),
    Service(Arc<dyn ServiceReader>),
}

/// C `struct novacom_channel`.
struct Channel {
    num: u32,
    closing: bool,
    tx: BufQueue<Notify>,
    acked_tx_sequence: u32,
    last_tx_sequence: u32,
    retransmit_len: usize,
    /// Zero in C until the first transmission; only read after one.
    retransmit_time: Option<Instant>,
    rx_sequence: u32,
    reader: Option<Reader>,
    has_pending_ack: bool,
    /// C `close_callbacks`: fired when the channel shuts down.
    close_callbacks: Vec<(u64, Notify)>,
}

impl Channel {
    fn new(num: u32) -> Self {
        Self {
            num,
            closing: false,
            tx: BufQueue::new(),
            acked_tx_sequence: 0,
            last_tx_sequence: 0,
            retransmit_len: 0,
            retransmit_time: None,
            rx_sequence: 0,
            reader: None,
            has_pending_ack: false,
            close_callbacks: Vec::new(),
        }
    }
}

/// C -1 from a channel call: no such channel (or, for
/// [`Mux::close_channel`], a fixed channel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoChannel;

/// Outcome of [`Mux::open_channel`].
pub enum Open {
    /// C returns -1 at once.
    Failed,
    /// The open request is queued; C waits until its callback runs, then
    /// returns 0.
    Queued,
}

/// C `struct mux_instance` without its mutex and event.
pub struct Mux {
    online: bool,
    /// C `channel_list`: creation order.
    channels: Vec<Channel>,
    next_temp_channel: u32,
    /// C `wake_tx_event` is signalled.
    wake: bool,
    /// Callbacks due to run once the caller releases the mux.
    fired: Vec<Notify>,
    /// Work due to start once the caller releases the mux.
    spawns: Vec<Spawn>,
    /// Identity of the next close callback.
    next_close_id: u64,
}

impl Default for Mux {
    fn default() -> Self {
        Self::new()
    }
}

impl Mux {
    /// The mux part of C `novacom_go_online`: online, with the control
    /// channel.
    pub fn new() -> Self {
        let mut m = Self {
            online: true,
            channels: Vec::new(),
            next_temp_channel: CHANNEL_HOST_BASE,
            wake: false,
            fired: Vec::new(),
            spawns: Vec::new(),
            next_close_id: 0,
        };
        m.create_channel(CHANNEL_CONTROL, false, true);
        let _ = m.set_reader(CHANNEL_CONTROL, Some(Reader::Control));
        m
    }

    pub fn is_online(&self) -> bool {
        self.online
    }

    /// `true` while the transmit wake-up event is signalled.
    pub fn wake_pending(&self) -> bool {
        self.wake
    }

    /// Callbacks that became due; the caller runs them after releasing
    /// the mux.
    pub fn take_fired(&mut self) -> Vec<Notify> {
        std::mem::take(&mut self.fired)
    }

    /// Work that became due; the caller starts it after releasing the mux.
    pub fn take_spawns(&mut self) -> Vec<Spawn> {
        std::mem::take(&mut self.spawns)
    }

    /// Queues `f` to start once the caller releases the mux.
    pub(crate) fn spawn(&mut self, f: Spawn) {
        self.spawns.push(f);
    }

    fn find(&self, num: u32) -> Option<usize> {
        self.channels.iter().position(|c| c.num == num)
    }

    /// C `create_channel`. `command` installs the command handler on
    /// channels above the fixed range (D1).
    pub fn create_channel(&mut self, num: u32, command: bool, bypass_online: bool) -> bool {
        if (!bypass_online && !self.online) || self.find(num).is_some() {
            return false;
        }
        let mut c = Channel::new(num);
        if command && num > CHANNEL_MAX_FIXED {
            c.reader = Some(Reader::Command);
        }
        self.channels.push(c);
        true
    }

    /// C `novacom_write_channel_async`: queues `data` and the optional
    /// callback. `Err` is C -1 (no such channel; the callback is dropped).
    pub fn write(&mut self, chan: u32, data: &[u8], done: Option<Notify>) -> Result<(), NoChannel> {
        let i = self.find(chan).ok_or(NoChannel)?;
        self.channels[i].tx.append(data, done);
        self.wake = true;
        Ok(())
    }

    /// C `novacom_tx_queue_len` (0 for an unknown channel).
    pub fn tx_queue_len(&self, chan: u32) -> usize {
        self.find(chan).map_or(0, |i| self.channels[i].tx.len())
    }

    /// C `novacom_set_read_callback`.
    pub fn set_reader(&mut self, chan: u32, reader: Option<Reader>) -> Result<(), NoChannel> {
        let i = self.find(chan).ok_or(NoChannel)?;
        self.channels[i].reader = reader;
        Ok(())
    }

    /// C `novacom_set_closechannel_callback`: `done` fires when the channel
    /// shuts down. Returns an id for [`Mux::clear_close_callback`]. `Err`
    /// (C -1) if there is no such channel or it is closing.
    pub fn set_close_callback(&mut self, chan: u32, done: Notify) -> Result<u64, NoChannel> {
        let i = self.find(chan).ok_or(NoChannel)?;
        if self.channels[i].closing {
            return Err(NoChannel);
        }
        let id = self.next_close_id;
        self.next_close_id += 1;
        self.channels[i].close_callbacks.push((id, done));
        Ok(id)
    }

    /// C `novacom_clear_closechannel_callback`: the callback is dropped
    /// without running. `Err` (C -1) if there is no such channel or it is
    /// closing (the callback then still fires).
    pub fn clear_close_callback(&mut self, chan: u32, id: u64) -> Result<(), NoChannel> {
        let i = self.find(chan).ok_or(NoChannel)?;
        let c = &mut self.channels[i];
        if c.closing {
            return Err(NoChannel);
        }
        c.close_callbacks.retain(|(k, _)| *k != id);
        Ok(())
    }

    /// The number choice of C `novacom_open_temp_channel`: the next host
    /// channel number not in use, wrapping before `0x7fffffff`.
    pub fn alloc_temp_channel(&mut self) -> u32 {
        loop {
            let n = self.next_temp_channel;
            self.next_temp_channel += 1;
            if self.next_temp_channel == CHANNEL_MAX_HOST {
                self.next_temp_channel = CHANNEL_HOST_BASE;
            }
            if self.find(n).is_none() {
                return n;
            }
        }
    }

    /// C `novacom_open_channel` up to its wait: creates the channel and
    /// queues `OPEN_COMMAND` (or `OPEN`) on the control channel with
    /// `done` as its callback.
    pub fn open_channel(&mut self, num: u32, command: bool, done: Notify) -> Open {
        if !self.create_channel(num, false, false) {
            return Open::Failed;
        }
        if num <= CHANNEL_CONTROL {
            return Open::Failed;
        }
        let op = if command { OP_OPEN_COMMAND } else { OP_OPEN };
        match self.send_control(op, num, Some(done)) {
            Ok(()) => Open::Queued,
            Err(NoChannel) => Open::Failed,
        }
    }

    /// C `send_control_message`.
    fn send_control(&mut self, op: u32, chan: u32, done: Option<Notify>) -> Result<(), NoChannel> {
        self.write(CHANNEL_CONTROL, &encode_control(op, chan), done)
    }

    /// C `novacom_close_channel`: the channel shuts down (and `CLOSE` is
    /// sent) once its queued data is acknowledged. `Err` is C -1.
    pub fn close_channel(&mut self, chan: u32) -> Result<(), NoChannel> {
        if chan <= CHANNEL_MAX_FIXED {
            return Err(NoChannel);
        }
        let i = self.find(chan).ok_or(NoChannel)?;
        if self.channels[i].closing {
            return Ok(());
        }
        self.channels[i].closing = true;
        if self.channels[i].tx.is_empty() {
            self.shutdown_channel(i, true);
        }
        Ok(())
    }

    /// C `novacom_shutdown_channel`.
    fn shutdown_channel(&mut self, i: usize, send_notification: bool) {
        let c = self.channels.remove(i);
        if send_notification {
            let _ = self.send_control(OP_CLOSE, c.num, None);
        }
        self.fired.extend(c.tx.destroy());
        self.fired
            .extend(c.close_callbacks.into_iter().map(|(_, n)| n));
        if let Some(r) = c.reader {
            self.call_reader(&r, c.num, None);
        }
    }

    /// The channel part of C `novacom_go_offline`.
    pub fn go_offline(&mut self) {
        self.online = false;
        self.wake = true;
        while let Some(c) = self.channels.first() {
            muxtrace(&format!("shutting down channel {}\n", c_int(c.num)));
            self.shutdown_channel(0, false);
        }
    }

    /// Calls a channel's rx callback; returns its result.
    fn call_reader(&mut self, r: &Reader, chan: u32, data: Option<&[u8]>) -> i32 {
        match (r, data) {
            (Reader::Client(c), _) => c.read(chan, data),
            (Reader::Service(sv), _) => sv.read(self, chan, data),
            (_, None) => 0,
            (Reader::Control, Some(d)) => self.control_read(d),
            (Reader::Command, Some(d)) => self.command_read(chan, d),
        }
    }

    /// C `control_channel_rx_callback`.
    fn control_read(&mut self, data: &[u8]) -> i32 {
        if data.len() < CONTROL_LEN {
            return 0;
        }
        let (op, chan) = (u32_at(data, 0), u32_at(data, 4));
        let name = match op {
            OP_CHANNEL_CLOSED => "CONTROL_CHANNEL_CLOSED",
            OP_OPEN => "CONTROL_OPEN",
            OP_OPEN_COMMAND => "CONTROL_OPEN_COMMAND",
            OP_CLOSE => "CONTROL_CLOSE",
            _ => return 0,
        };
        muxtrace(&format!("{name}: {}\n", c_int(chan)));
        match op {
            OP_OPEN => {
                self.create_channel(chan, false, false);
            }
            OP_OPEN_COMMAND => {
                self.create_channel(chan, true, false);
            }
            _ => {
                if let Some(i) = self.find(chan) {
                    self.shutdown_channel(i, false);
                }
            }
        }
        0
    }

    /// C `novacom_handle_command_fromclient` on the host (no auth check):
    /// the `get file`, `put file` and `connect tcp-port` handlers of
    /// [`devcmd`] (D1, kept as in C).
    fn command_read(&mut self, chan: u32, data: &[u8]) -> i32 {
        let Some(url) = cmdparse::parse_command(data) else {
            let _ = self.write(chan, UNRECOGNIZED, None);
            return 0;
        };
        // Removed up front "so that fast clients don't overrun us".
        let _ = self.set_reader(chan, None);
        if !devcmd::start(self, chan, &url) {
            let _ = self.write(chan, UNRECOGNIZED, None);
            let _ = self.set_reader(chan, Some(Reader::Command));
        }
        0
    }

    /// C `novacom_process_packet` for the `len`-byte packet at the start of
    /// `buf`.
    ///
    /// C reads the header and the payload from its receive buffer without
    /// checking them against `len` (D17): a short packet takes the rest of
    /// its header, and a payload may run up to 28 bytes past the packet,
    /// from whatever an earlier packet left in the buffer. The inet
    /// transport passes its reused buffer the same way; bytes past the end
    /// of `buf` read as zero (intentional change: C reads past its buffer).
    pub fn process_packet(&mut self, buf: &[u8], len: usize) {
        let h = Header::decode(buf);
        if h.magic != PMUX_MAGIC
            || h.version != PMUX_VERSION
            || h.total_len as usize > len
            || h.payload_len > h.total_len
            || h.channel == CHANNEL_NULL
        {
            return;
        }
        let Some(i) = self.find(h.channel) else {
            if h.channel > CHANNEL_CONTROL {
                let _ = self.send_control(OP_CHANNEL_CLOSED, h.channel, None);
            }
            return;
        };
        if h.flags & FLAG_ACK != 0 {
            let c = &mut self.channels[i];
            if h.sequence > c.acked_tx_sequence && h.sequence <= c.last_tx_sequence {
                c.acked_tx_sequence = h.sequence;
                let fired = c.tx.consume(c.retransmit_len);
                let shutdown = c.closing && c.tx.is_empty();
                self.fired.extend(fired);
                self.wake = true;
                if shutdown {
                    self.shutdown_channel(i, true);
                }
            } else {
                log::trace(seq_line("Out of sequence ACK", c, &h).as_bytes());
            }
            return;
        }
        if h.flags != 0 {
            return;
        }
        let payload_end = HEADER_LEN + h.payload_len as usize;
        let padded;
        let data = match buf.get(HEADER_LEN..payload_end) {
            Some(d) => d,
            None => {
                let mut v = buf.get(HEADER_LEN..).unwrap_or_default().to_vec();
                v.resize(payload_end - HEADER_LEN, 0);
                padded = v;
                &padded
            }
        };
        let c = &mut self.channels[i];
        let num = c.num;
        let mut do_ack = false;
        if c.closing {
            c.rx_sequence = h.sequence;
            do_ack = true;
        } else if let Some(reader) = c.reader.clone() {
            if h.sequence == c.rx_sequence {
                log::trace(seq_line("RE-ACK", c, &h).as_bytes());
                do_ack = true;
            } else if h.sequence == c.rx_sequence.wrapping_add(1) {
                let crc = if h.crc == 0 { 0 } else { adler(data) };
                if crc != h.crc {
                    log::trace(
                        format!(
                            "novacom_process_packet:462: *** CHECKSUM MISMATCH *** (that's a bad thing): header->crc({:08x}), crc({crc:08x})\n",
                            h.crc
                        )
                        .as_bytes(),
                    );
                } else {
                    let accepted = self.call_reader(&reader, num, Some(data)) >= 0;
                    // The callback may have shut the channel down (a
                    // CLOSE for channel 1 itself). C then writes to the
                    // freed channel; here the update is skipped.
                    if let (true, Some(j)) = (accepted, self.find(num)) {
                        self.channels[j].rx_sequence = h.sequence;
                        do_ack = true;
                    }
                }
            } else {
                log::error(
                    seq_line(
                        "RX PKT OUT OF SEQUENCE (this is a very weird and bad thing)",
                        c,
                        &h,
                    )
                    .as_bytes(),
                );
            }
        }
        if let (true, Some(j)) = (do_ack, self.find(num)) {
            self.channels[j].has_pending_ack = true;
            self.wake = true;
        }
    }

    /// C `novacom_prepare_tx_packet` with a `packet_len`-byte packet
    /// buffer: a pending ack first; else the first channel whose
    /// unacknowledged packet is [`RETRANSMIT_WAIT`] old; else the last
    /// channel with queued data and nothing unacknowledged. `None` when
    /// there is nothing to send (the wake-up event is reset).
    pub fn prepare_tx_packet(&mut self, now: Instant, packet_len: usize) -> Option<Vec<u8>> {
        if let Some(c) = self.channels.iter_mut().find(|c| c.has_pending_ack) {
            c.has_pending_ack = false;
            let h = Header {
                magic: PMUX_MAGIC,
                version: PMUX_VERSION,
                flags: FLAG_ACK,
                channel: c.num,
                sequence: c.rx_sequence,
                payload_len: 0,
                total_len: HEADER_LEN as u32,
                crc: 0,
            };
            return Some(h.encode().to_vec());
        }
        let due = |c: &Channel| {
            c.retransmit_time
                .is_none_or(|t| now.saturating_duration_since(t) >= RETRANSMIT_WAIT)
        };
        let (i, retransmit) = match self
            .channels
            .iter()
            .position(|c| c.last_tx_sequence != c.acked_tx_sequence && due(c))
        {
            Some(i) => (i, true),
            None => match self
                .channels
                .iter()
                .rposition(|c| c.last_tx_sequence == c.acked_tx_sequence && !c.tx.is_empty())
            {
                Some(i) => (i, false),
                None => {
                    self.wake = false;
                    return None;
                }
            },
        };
        let c = &mut self.channels[i];
        let room = packet_len.saturating_sub(HEADER_LEN);
        if !retransmit {
            c.last_tx_sequence = c.last_tx_sequence.wrapping_add(1);
        }
        let payload = if retransmit {
            c.tx.peek(c.retransmit_len)
        } else {
            let p = if c.num > CHANNEL_MAX_FIXED {
                c.tx.peek(room)
            } else {
                c.tx.peek_onechunk(room)
            };
            c.retransmit_len = p.len();
            p
        };
        c.retransmit_time = Some(now);
        let len = payload.len() as u32;
        let h = Header {
            magic: PMUX_MAGIC,
            version: PMUX_VERSION,
            flags: 0,
            channel: c.num,
            sequence: c.last_tx_sequence,
            payload_len: len,
            total_len: len + HEADER_LEN as u32,
            crc: adler(&payload),
        };
        let mut p = h.encode().to_vec();
        p.extend_from_slice(&payload);
        Some(p)
    }
}

/// `TRACEL(LOG_MUXTRACE, ...)`.
fn muxtrace(line: &str) {
    log::log(log::LOG_MUXTRACE, line.as_bytes());
}

/// The C sequence diagnostics of `novacom_process_packet`.
fn seq_line(what: &str, c: &Channel, h: &Header) -> String {
    format!(
        "[{}] {what}: h->seq: {}, c->rx_seq: {}, h->flags: {}, h->channel: {},c->last_tx: {}, c->acked_tx: {}\n",
        c_int(c.num),
        c_int(h.sequence),
        c_int(c.rx_sequence),
        h.flags,
        c_int(h.channel),
        c_int(c.last_tx_sequence),
        c_int(c.acked_tx_sequence),
    )
}

/// One-shot event with a waiter (C `platform_event_t` used by
/// `novacom_write_channel_sync`).
#[derive(Default)]
pub(crate) struct Event {
    done: Mutex<bool>,
    cv: Condvar,
}

impl Event {
    pub(crate) fn signal(&self) {
        *self.done.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.cv.notify_all();
    }

    /// Intentional change (D25): C waits under `if`, so a spurious wake-up
    /// ends its wait early; here it waits until signalled.
    pub(crate) fn wait(&self) {
        let mut d = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        while !*d {
            d = self.cv.wait(d).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A shared mux (C `device_handle_t`).
pub struct Device {
    id: u64,
    /// This device, for work started by channel callbacks.
    me: Weak<Device>,
    mux: Mutex<Mux>,
    /// Signalled with [`Mux::wake_pending`] (C `wake_tx_event`).
    wake: Condvar,
}

impl Device {
    /// A new online mux (C `novacom_go_online` before registration).
    pub fn new() -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            me: me.clone(),
            mux: Mutex::new(Mux::new()),
            wake: Condvar::new(),
        })
    }

    /// Identity of this registration (the C pointer value).
    pub fn id(&self) -> u64 {
        self.id
    }

    fn lock(&self) -> MutexGuard<'_, Mux> {
        self.mux.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` on the locked mux, then signals the transmitter if needed,
    /// runs the callbacks that became due and starts due work.
    pub fn with<R>(&self, f: impl FnOnce(&mut Mux) -> R) -> R {
        let (r, fired, spawns) = {
            let mut m = self.lock();
            let r = f(&mut m);
            if m.wake_pending() {
                self.wake.notify_all();
            }
            (r, m.take_fired(), m.take_spawns())
        };
        for n in fired {
            n();
        }
        if let Some(me) = self.me.upgrade() {
            for s in spawns {
                s(Arc::clone(&me));
            }
        }
        r
    }

    /// C `novacom_process_packet`.
    pub fn process_packet(&self, buf: &[u8], len: usize) {
        self.with(|m| m.process_packet(buf, len));
    }

    /// C `novacom_get_tx_packet(mux, packet, timeout)`: the next packet,
    /// waiting up to `timeout`; checks for retransmits every
    /// [`RETRANSMIT_WAIT`]. `None` on timeout or when the mux goes offline.
    pub fn get_tx_packet(&self, timeout: Duration, packet_len: usize) -> Option<Vec<u8>> {
        let start = Instant::now();
        let mut m = self.lock();
        loop {
            if let Some(p) = m.prepare_tx_packet(Instant::now(), packet_len) {
                return Some(p);
            }
            if !m.wake_pending() {
                m = self
                    .wake
                    .wait_timeout(m, RETRANSMIT_WAIT)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            if !m.is_online() || start.elapsed() >= timeout {
                return None;
            }
        }
    }

    /// C `novacom_open_temp_channel(mux, &channel, 1)`: picks the channel
    /// number, opens it with `OPEN_COMMAND` and waits, without a timeout,
    /// until the device acknowledges the request or the mux goes offline
    /// (D9). Returns the number and the C result (0 or -1).
    pub fn open_temp_channel(&self) -> (u32, i32) {
        self.open_and_wait(Mux::alloc_temp_channel, true)
    }

    /// C `novacom_open_channel(mux, num, command)`: opens channel `num` and
    /// waits like [`Device::open_temp_channel`]. Returns 0 or -1.
    pub fn open_channel(&self, num: u32, command: bool) -> i32 {
        self.open_and_wait(|_| num, command).1
    }

    /// Opens the channel that `pick` chooses and waits for the device.
    fn open_and_wait(&self, pick: impl FnOnce(&mut Mux) -> u32, command: bool) -> (u32, i32) {
        let ev = Arc::new(Event::default());
        let done = {
            let ev = Arc::clone(&ev);
            Box::new(move || ev.signal())
        };
        let (num, open) = self.with(|m| {
            let num = pick(m);
            (num, m.open_channel(num, command, done))
        });
        match open {
            Open::Failed => (num, -1),
            Open::Queued => {
                ev.wait();
                (num, 0)
            }
        }
    }

    /// C `novacom_go_offline`: `unregister` (C `novacom_unregister_device`)
    /// runs with the mux locked, then every channel shuts down.
    pub fn go_offline(&self, unregister: impl FnOnce()) {
        self.with(|m| {
            m.online = false;
            unregister();
            m.go_offline();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI32;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// A packet as the device sends it.
    fn pkt(flags: u16, channel: u32, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let h = Header {
            magic: PMUX_MAGIC,
            version: PMUX_VERSION,
            flags,
            channel,
            sequence,
            payload_len: len,
            total_len: len + HEADER_LEN as u32,
            crc: if flags == 0 { adler(payload) } else { 0 },
        };
        [&h.encode()[..], payload].concat()
    }

    fn ack(channel: u32, sequence: u32) -> Vec<u8> {
        pkt(FLAG_ACK, channel, sequence, b"")
    }

    fn feed(m: &mut Mux, p: &[u8]) {
        m.process_packet(p, p.len());
    }

    /// Decodes a packet from `prepare_tx_packet`.
    fn split(p: &[u8]) -> (Header, Vec<u8>) {
        (Header::decode(p), p[HEADER_LEN..].to_vec())
    }

    /// Records what a client channel receives; returns `result` for data.
    struct Rec {
        got: Mutex<Vec<Option<Vec<u8>>>>,
        result: AtomicI32,
    }

    impl Rec {
        fn new(result: i32) -> Arc<Self> {
            Arc::new(Self {
                got: Mutex::new(Vec::new()),
                result: AtomicI32::new(result),
            })
        }
        fn got(&self) -> Vec<Option<Vec<u8>>> {
            self.got.lock().unwrap().clone()
        }
    }

    impl ClientReader for Rec {
        fn read(&self, _channel: u32, data: Option<&[u8]>) -> i32 {
            self.got.lock().unwrap().push(data.map(<[u8]>::to_vec));
            if data.is_some() {
                self.result.load(Ordering::Relaxed)
            } else {
                0
            }
        }
    }

    fn counter() -> (Arc<AtomicI32>, Notify) {
        let n = Arc::new(AtomicI32::new(0));
        let n2 = Arc::clone(&n);
        (
            n,
            Box::new(move || {
                n2.fetch_add(1, Ordering::Relaxed);
            }),
        )
    }

    fn run_fired(m: &mut Mux) {
        for n in m.take_fired() {
            n();
        }
    }

    #[test]
    fn adler_matches_reference_values() {
        assert_eq!(adler(b""), 1);
        assert_eq!(adler(b"Wikipedia"), 0x11E6_0398);
        let big = vec![0xffu8; 20_000];
        // Reference: zlib adler32 of 20000 bytes of 0xff.
        let (mut a, mut b) = (1u64, 0u64);
        for &x in &big {
            a = (a + u64::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(adler(&big), ((b << 16) | a) as u32);
    }

    #[test]
    fn header_and_control_codec() {
        let p = pkt(0, 0x1000, 7, b"xyz");
        assert_eq!(&p[0..4], b"xump"); // 'pmux' little-endian
        let (h, d) = split(&p);
        assert_eq!(
            (
                h.version,
                h.flags,
                h.channel,
                h.sequence,
                h.payload_len,
                h.total_len
            ),
            (3, 0, 0x1000, 7, 3, 31)
        );
        assert_eq!(h.crc, adler(b"xyz"));
        assert_eq!(d, b"xyz");
        assert_eq!(Header::decode(&h.encode()), h);
        let c = encode_control(OP_OPEN_COMMAND, 0x1234);
        assert_eq!(
            (u32_at(&c, 0), u32_at(&c, 4), u32_at(&c, 8)),
            (3, 0x1234, 12)
        );
        // Bytes past the end read as zero.
        assert_eq!(Header::decode(&p[..10]).sequence, 0);
    }

    #[test]
    fn open_sends_open_command_and_completes_on_ack() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        let num = m.alloc_temp_channel();
        assert_eq!(num, 0x1000);
        let (done, notify) = counter();
        assert!(matches!(m.open_channel(num, true, notify), Open::Queued));
        let (h, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!((h.channel, h.sequence, h.flags), (1, 1, 0));
        assert_eq!(d, encode_control(OP_OPEN_COMMAND, 0x1000));
        // Nothing else to send until the ack.
        assert!(m.prepare_tx_packet(t0, 4096).is_none());
        assert!(!m.wake_pending());
        feed(&mut m, &ack(1, 1));
        run_fired(&mut m);
        assert_eq!(done.load(Ordering::Relaxed), 1);
        assert!(m.wake_pending());
        assert_eq!(m.alloc_temp_channel(), 0x1001);
    }

    #[test]
    fn temp_channel_numbers_skip_live_ones_and_wrap() {
        let mut m = Mux::new();
        m.next_temp_channel = CHANNEL_MAX_HOST - 2;
        assert!(m.create_channel(CHANNEL_MAX_HOST - 1, false, false));
        assert_eq!(m.alloc_temp_channel(), CHANNEL_MAX_HOST - 2);
        // 0x7ffffffe is live, the counter wraps at 0x7fffffff.
        assert_eq!(m.alloc_temp_channel(), CHANNEL_HOST_BASE);
    }

    #[test]
    fn data_is_coalesced_and_retransmitted_after_50ms() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        assert!(m.create_channel(0x1000, false, false));
        let (done, notify) = counter();
        m.write(0x1000, b"hello ", None).unwrap();
        m.write(0x1000, b"world", Some(notify)).unwrap();
        assert_eq!(m.tx_queue_len(0x1000), 11);
        let first = m.prepare_tx_packet(t0, 4096).unwrap();
        let (h, d) = split(&first);
        assert_eq!(
            (h.channel, h.sequence, h.crc),
            (0x1000, 1, adler(b"hello world"))
        );
        assert_eq!(d, b"hello world");
        // Not yet due: nothing to send.
        assert!(m.prepare_tx_packet(t0 + ms(49), 4096).is_none());
        // Due: same sequence and bytes.
        assert_eq!(m.prepare_tx_packet(t0 + ms(50), 4096).unwrap(), first);
        assert!(m.prepare_tx_packet(t0 + ms(99), 4096).is_none());
        // A stale or future ack changes nothing.
        feed(&mut m, &ack(0x1000, 0));
        feed(&mut m, &ack(0x1000, 2));
        assert_eq!(m.tx_queue_len(0x1000), 11);
        feed(&mut m, &ack(0x1000, 1));
        run_fired(&mut m);
        assert_eq!(done.load(Ordering::Relaxed), 1);
        assert_eq!(m.tx_queue_len(0x1000), 0);
        assert!(m.prepare_tx_packet(t0 + ms(200), 4096).is_none());
    }

    #[test]
    fn payload_limit_and_control_one_chunk_per_packet() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        assert!(m.create_channel(0x1000, false, false));
        m.write(0x1000, &[7u8; 5000], None).unwrap();
        let (h, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!((h.payload_len, d.len()), (4068, 4068));
        feed(&mut m, &ack(0x1000, 1));
        let (h, _) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!((h.sequence, h.payload_len), (2, 932));
        // Control messages: one buffer per packet.
        m.write(CHANNEL_CONTROL, &encode_control(OP_CLOSE, 5), None)
            .unwrap();
        m.write(CHANNEL_CONTROL, &encode_control(OP_CLOSE, 6), None)
            .unwrap();
        let (h, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!((h.channel, d), (1, encode_control(OP_CLOSE, 5).to_vec()));
    }

    #[test]
    fn tx_priority_ack_then_retransmit_then_last_channel() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        for n in [0x1000, 0x1001, 0x1002] {
            assert!(m.create_channel(n, false, false));
        }
        let rec = Rec::new(0);
        m.set_reader(0x1000, Some(Reader::Client(rec.clone())))
            .unwrap();
        m.write(0x1000, b"a", None).unwrap();
        m.write(0x1001, b"b", None).unwrap();
        // The last channel with data goes first.
        let (h, _) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!(h.channel, 0x1001);
        let (h, _) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!(h.channel, 0x1000);
        // An ack beats everything; a due retransmit beats new data.
        feed(&mut m, &pkt(0, 0x1000, 1, b"in"));
        m.write(0x1002, b"c", None).unwrap();
        let (h, _) = split(&m.prepare_tx_packet(t0 + ms(60), 4096).unwrap());
        assert_eq!((h.flags, h.channel, h.sequence), (FLAG_ACK, 0x1000, 1));
        let (h, _) = split(&m.prepare_tx_packet(t0 + ms(60), 4096).unwrap());
        assert_eq!((h.channel, h.sequence), (0x1000, 1));
        let (h, _) = split(&m.prepare_tx_packet(t0 + ms(60), 4096).unwrap());
        assert_eq!((h.channel, h.sequence), (0x1001, 1));
        let (h, _) = split(&m.prepare_tx_packet(t0 + ms(60), 4096).unwrap());
        assert_eq!((h.channel, h.sequence), (0x1002, 1));
        assert_eq!(rec.got(), vec![Some(b"in".to_vec())]);
    }

    #[test]
    fn rx_sequence_reack_out_of_sequence_crc_and_nak() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        assert!(m.create_channel(0x1000, false, false));
        // No reader: dropped without an ack.
        feed(&mut m, &pkt(0, 0x1000, 1, b"x"));
        assert!(m.prepare_tx_packet(t0, 4096).is_none());
        let rec = Rec::new(-1);
        m.set_reader(0x1000, Some(Reader::Client(rec.clone())))
            .unwrap();
        // Reader refuses: no ack, sequence not advanced.
        feed(&mut m, &pkt(0, 0x1000, 1, b"x"));
        assert!(m.prepare_tx_packet(t0, 4096).is_none());
        rec.result.store(0, Ordering::Relaxed);
        feed(&mut m, &pkt(0, 0x1000, 1, b"x"));
        let (h, _) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!((h.flags, h.sequence), (FLAG_ACK, 1));
        // Duplicate: re-acked, not delivered again.
        feed(&mut m, &pkt(0, 0x1000, 1, b"x"));
        let (h, _) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!((h.flags, h.sequence), (FLAG_ACK, 1));
        // Bad crc: dropped. crc 0: not checked.
        let mut bad = pkt(0, 0x1000, 2, b"y");
        bad[24] ^= 1;
        feed(&mut m, &bad);
        assert!(m.prepare_tx_packet(t0, 4096).is_none());
        let mut unchecked = pkt(0, 0x1000, 2, b"y");
        unchecked[24..28].copy_from_slice(&[0; 4]);
        feed(&mut m, &unchecked);
        assert!(m.prepare_tx_packet(t0, 4096).is_some());
        // Out of sequence: dropped (and logged on stderr).
        feed(&mut m, &pkt(0, 0x1000, 9, b"z"));
        assert!(m.prepare_tx_packet(t0, 4096).is_none());
        assert_eq!(
            rec.got(),
            vec![
                Some(b"x".to_vec()),
                Some(b"x".to_vec()),
                Some(b"y".to_vec())
            ]
        );
    }

    #[test]
    fn invalid_headers_are_ignored_and_unknown_channels_answered() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        let good = pkt(0, 0x2000, 1, b"abc");
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = good.clone();
        bad_version[4] = 2;
        for p in [&bad_magic, &bad_version] {
            feed(&mut m, p);
        }
        // total_len > len, payload_len > total_len, channel 0, other flags.
        m.process_packet(&good, good.len() - 1);
        let mut p = good.clone();
        p[16..20].copy_from_slice(&40u32.to_ne_bytes());
        feed(&mut m, &p);
        feed(&mut m, &pkt(0, 0, 1, b"abc"));
        feed(
            &mut m,
            &pkt(2, CHANNEL_CONTROL, 1, &encode_control(OP_OPEN, 9)),
        );
        assert!(m.prepare_tx_packet(t0, 4096).is_none());
        // Unknown channel (data or ack): CHANNEL_CLOSED, also for 2..=0xfff.
        feed(&mut m, &good);
        feed(&mut m, &ack(2, 1));
        let (h, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!(
            (h.channel, d),
            (1, encode_control(OP_CHANNEL_CLOSED, 0x2000).to_vec())
        );
        feed(&mut m, &ack(1, 1));
        let (_, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!(d, encode_control(OP_CHANNEL_CLOSED, 2));
    }

    #[test]
    fn short_packet_uses_rest_of_buffer() {
        let mut m = Mux::new();
        // A 10-byte packet in a buffer that still holds an earlier header
        // whose total_len exceeds 10: rejected.
        let mut buf = pkt(0, 0x2000, 1, b"abc");
        buf[..4].copy_from_slice(&PMUX_MAGIC.to_ne_bytes());
        m.process_packet(&buf, 10);
        assert!(m.prepare_tx_packet(Instant::now(), 4096).is_none());
        // A payload that runs past the packet reads the stale bytes.
        let rec = Rec::new(0);
        assert!(m.create_channel(0x1000, false, false));
        m.set_reader(0x1000, Some(Reader::Client(rec.clone())))
            .unwrap();
        let mut buf = pkt(0, 0x1000, 1, b"0123456789");
        buf[16..20].copy_from_slice(&10u32.to_ne_bytes());
        buf[20..24].copy_from_slice(&30u32.to_ne_bytes());
        buf[24..28].copy_from_slice(&[0; 4]);
        m.process_packet(&buf, 30);
        assert_eq!(rec.got(), vec![Some(b"0123456789".to_vec())]);
    }

    #[test]
    fn control_messages_from_device() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        let ctl =
            |seq: u32, op: u32, ch: u32| pkt(0, CHANNEL_CONTROL, seq, &encode_control(op, ch));
        // OPEN creates a channel without a reader: its data is not acked.
        feed(&mut m, &ctl(1, OP_OPEN, 0x8000_0000));
        assert_eq!(split(&m.prepare_tx_packet(t0, 4096).unwrap()).0.sequence, 1);
        feed(&mut m, &pkt(0, 0x8000_0000, 1, b"d"));
        assert!(m.prepare_tx_packet(t0, 4096).is_none());
        // Short or unknown control messages are acked and ignored.
        feed(&mut m, &pkt(0, CHANNEL_CONTROL, 2, b"short"));
        feed(&mut m, &ctl(3, 99, 5));
        assert_eq!(split(&m.prepare_tx_packet(t0, 4096).unwrap()).0.sequence, 3);
        // CLOSE removes it silently; later data gets CHANNEL_CLOSED.
        feed(&mut m, &ctl(4, OP_CLOSE, 0x8000_0000));
        let _ = m.prepare_tx_packet(t0, 4096);
        feed(&mut m, &pkt(0, 0x8000_0000, 2, b"d"));
        let (_, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!(d, encode_control(OP_CHANNEL_CLOSED, 0x8000_0000));
    }

    #[test]
    fn command_channel_from_device_answers_unrecognized() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        feed(
            &mut m,
            &pkt(
                0,
                CHANNEL_CONTROL,
                1,
                &encode_control(OP_OPEN_COMMAND, 0x8000_0001),
            ),
        );
        let _ = m.prepare_tx_packet(t0, 4096);
        for (seq, cmd) in [(1, &b"\n"[..]), (2, b"bogus x://y\n")] {
            feed(&mut m, &pkt(0, 0x8000_0001, seq, cmd));
            let (h, _) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
            assert_eq!((h.flags, h.sequence), (FLAG_ACK, seq));
            let (h, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
            assert_eq!((h.channel, d), (0x8000_0001, UNRECOGNIZED.to_vec()));
            feed(&mut m, &ack(0x8000_0001, seq));
        }
    }

    #[test]
    fn close_waits_for_queue_then_sends_close() {
        let t0 = Instant::now();
        let mut m = Mux::new();
        assert!(m.create_channel(0x1000, false, false));
        let rec = Rec::new(0);
        m.set_reader(0x1000, Some(Reader::Client(rec.clone())))
            .unwrap();
        m.write(0x1000, b"tail", None).unwrap();
        let _ = m.prepare_tx_packet(t0, 4096);
        m.close_channel(0x1000).unwrap();
        assert_eq!(m.close_channel(0x1000), Ok(()));
        assert_eq!(m.close_channel(5), Err(NoChannel));
        // Closing: data from the device is acked and not delivered.
        feed(&mut m, &pkt(0, 0x1000, 4, b"late"));
        let (h, _) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!((h.flags, h.sequence), (FLAG_ACK, 4));
        feed(&mut m, &ack(0x1000, 1));
        let (h, d) = split(&m.prepare_tx_packet(t0, 4096).unwrap());
        assert_eq!(
            (h.channel, d),
            (1, encode_control(OP_CLOSE, 0x1000).to_vec())
        );
        assert_eq!(rec.got(), vec![None]);
        assert_eq!(m.tx_queue_len(0x1000), 0);
        // Empty queue: shut down at once.
        assert!(m.create_channel(0x1001, false, false));
        m.close_channel(0x1001).unwrap();
        assert_eq!(m.set_reader(0x1001, None), Err(NoChannel));
    }

    #[test]
    fn device_close_and_offline_notify_readers_and_fire_callbacks() {
        let mut m = Mux::new();
        assert!(m.create_channel(0x1000, false, false));
        let rec = Rec::new(0);
        m.set_reader(0x1000, Some(Reader::Client(rec.clone())))
            .unwrap();
        feed(
            &mut m,
            &pkt(0, CHANNEL_CONTROL, 1, &encode_control(OP_CLOSE, 0x1000)),
        );
        assert_eq!(rec.got(), vec![None]);
        // CLOSE from the device sends no CLOSE back (only the ack).
        let (h, _) = split(&m.prepare_tx_packet(Instant::now(), 4096).unwrap());
        assert_eq!(h.flags, FLAG_ACK);
        assert!(m.prepare_tx_packet(Instant::now(), 4096).is_none());
        // go_offline: pending callbacks fire, readers get the close.
        assert!(m.create_channel(0x1001, false, false));
        let rec2 = Rec::new(0);
        m.set_reader(0x1001, Some(Reader::Client(rec2.clone())))
            .unwrap();
        let (done, notify) = counter();
        assert!(matches!(m.open_channel(0x1002, true, notify), Open::Queued));
        m.go_offline();
        run_fired(&mut m);
        assert_eq!(done.load(Ordering::Relaxed), 1);
        assert_eq!(rec2.got(), vec![None]);
        assert!(!m.is_online());
        assert!(!m.create_channel(0x1003, false, false));
        assert_eq!(m.write(CHANNEL_CONTROL, b"x", None), Err(NoChannel));
    }

    #[test]
    fn close_callbacks_fire_on_shutdown_unless_cleared() {
        let mut m = Mux::new();
        assert!(m.create_channel(0x1000, false, false));
        let (kept, notify) = counter();
        let (cleared, notify2) = counter();
        m.set_close_callback(0x1000, notify).unwrap();
        let id = m.set_close_callback(0x1000, notify2).unwrap();
        m.clear_close_callback(0x1000, id).unwrap();
        assert!(m.set_close_callback(0x2000, Box::new(|| {})).is_err());
        m.write(0x1000, b"x", None).unwrap();
        m.close_channel(0x1000).unwrap();
        // Closing: no new callbacks, none cleared.
        assert!(m.set_close_callback(0x1000, Box::new(|| {})).is_err());
        assert!(m.clear_close_callback(0x1000, 0).is_err());
        run_fired(&mut m);
        assert_eq!(kept.load(Ordering::Relaxed), 0);
        m.go_offline();
        run_fired(&mut m);
        assert_eq!(kept.load(Ordering::Relaxed), 1);
        assert_eq!(cleared.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn device_starts_spawned_work_after_release() {
        let dev = Device::new();
        let ran = Arc::new(AtomicI32::new(0));
        let r2 = Arc::clone(&ran);
        dev.with(|m| {
            m.spawn(Box::new(move |d| {
                // The mux is free again.
                d.with(|m| assert!(m.is_online()));
                r2.store(1, Ordering::Relaxed);
            }));
            assert_eq!(ran.load(Ordering::Relaxed), 0);
        });
        assert_eq!(ran.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn close_of_control_channel_does_not_ack() {
        let mut m = Mux::new();
        feed(
            &mut m,
            &pkt(0, CHANNEL_CONTROL, 1, &encode_control(OP_CLOSE, 1)),
        );
        assert!(m.prepare_tx_packet(Instant::now(), 4096).is_none());
        // Opens now fail: no control channel.
        let (_, notify) = counter();
        assert!(matches!(m.open_channel(0x1000, true, notify), Open::Failed));
    }

    #[test]
    fn device_open_and_tx_threads() {
        let dev = Device::new();
        let d2 = Arc::clone(&dev);
        let opener = std::thread::spawn(move || d2.open_temp_channel());
        // The open request arrives at the transmitter.
        let p = dev.get_tx_packet(ms(2000), 4096).unwrap();
        let (h, d) = split(&p);
        assert_eq!(d, encode_control(OP_OPEN_COMMAND, 0x1000));
        dev.process_packet(&ack(1, h.sequence), HEADER_LEN);
        assert_eq!(opener.join().unwrap(), (0x1000, 0));
        // Idle: times out.
        let t = Instant::now();
        assert!(dev.get_tx_packet(ms(120), 4096).is_none());
        assert!(t.elapsed() >= ms(120));
        // Offline: an open fails, a pending open returns 0.
        dev.with(|m| m.create_channel(0x1001, false, false));
        let d3 = Arc::clone(&dev);
        let opener = std::thread::spawn(move || d3.open_temp_channel());
        let _ = dev.get_tx_packet(ms(2000), 4096).unwrap();
        let unregistered = AtomicI32::new(0);
        dev.go_offline(|| {
            unregistered.store(1, Ordering::Relaxed);
        });
        assert_eq!(opener.join().unwrap(), (0x1002, 0));
        assert_eq!(unregistered.load(Ordering::Relaxed), 1);
        assert!(dev.get_tx_packet(ms(2000), 4096).is_none());
        assert_eq!(dev.open_temp_channel(), (0x1003, -1));
    }
}
