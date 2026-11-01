//! A fake pmux device on the inet transport, written independently of the
//! rovacomd mux (std only): it acknowledges the host's packets, records
//! what the host sends, and sends data with stop-and-wait retransmission
//! every 50 ms as a device does. Tests script it per scenario.
//!
//! Linux low-water mark: the C daemon reads each inet frame with one
//! blocking `recv` on a socket with `SO_RCVLOWAT` 4096, and Linux wakes a
//! blocked reader only once 4096 bytes are queued (or at EOF). Every write
//! of this device is therefore followed by [`PAD_FRAMES`] empty keepalive
//! frames (>= 4096 bytes): the reader wakes, handles the real frames and
//! the keepalives (which the daemon ignores) and blocks again on an empty
//! queue. The daemon gets the same frames either way, so this changes
//! nothing that is compared. It is done on every OS and for both daemons.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar};

pub const MAGIC: u32 = 0x706d_7578;
pub const ACK: u16 = 1;
pub const HDR: usize = 28;
/// Device payload limit on inet (4096-byte packets).
pub const MAX_PAYLOAD: usize = 4096 - HDR;
pub const OPEN: u32 = 2;
pub const OPEN_COMMAND: u32 = 3;
pub const CLOSE: u32 = 4;
pub const CHANNEL_CLOSED: u32 = 1;
/// Keepalive frames after each write: 12 * 342 = 4104 >= 4096 bytes.
pub const PAD_FRAMES: usize = 342;
/// Device retransmit period.
const RETRANSMIT: Duration = Duration::from_millis(50);

/// Adler-32 (independent of `rovacomd::mux::adler`).
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// A pmux packet with explicit fields.
pub fn packet(flags: u16, channel: u32, seq: u32, payload: &[u8], crc: u32) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("len");
    let mut p = Vec::with_capacity(HDR + payload.len());
    p.extend_from_slice(&MAGIC.to_ne_bytes());
    p.extend_from_slice(&[3, 0]);
    p.extend_from_slice(&flags.to_ne_bytes());
    for v in [channel, seq, len, len + HDR as u32, crc] {
        p.extend_from_slice(&v.to_ne_bytes());
    }
    p.extend_from_slice(payload);
    p
}

pub fn data_packet(channel: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
    packet(0, channel, seq, payload, adler32(payload))
}

pub fn control(op: u32, channel: u32) -> Vec<u8> {
    [op, channel, 12]
        .iter()
        .flat_map(|v| v.to_ne_bytes())
        .collect()
}

/// End-to-end stream framing (`packet_struct.h`): header + payload.
pub fn stream_packet(kind: u32, payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len()).expect("len");
    let mut p: Vec<u8> = [0xDECA_FBADu32, 1, size, kind]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    p.extend_from_slice(payload);
    p
}

pub const S_DATA: u32 = 0;
pub const S_ERR: u32 = 1;
pub const S_OOB: u32 = 2;
pub const OOB_EOF: u32 = 0;
pub const OOB_RETURN: u32 = 2;

/// OOB message: 20-byte payload `message`, `arg`, zero padding.
pub fn oob(message: u32, arg: i32) -> Vec<u8> {
    let mut m = vec![0u8; 20];
    m[..4].copy_from_slice(&message.to_le_bytes());
    m[4..8].copy_from_slice(&arg.to_le_bytes());
    stream_packet(S_OOB, &m)
}

/// What the device saw from the host, in comparable form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transcript {
    /// New control messages from the host: (op, channel).
    pub controls: Vec<(u32, u32)>,
    /// Payload bytes the host sent per channel (each sequence once).
    pub streams: BTreeMap<u32, Vec<u8>>,
    /// Sequences of device packets the host acknowledged, per channel.
    pub acks: BTreeMap<u32, BTreeSet<u32>>,
    /// Malformed or unexpected packets.
    pub anomalies: Vec<String>,
}

#[derive(Default)]
struct State {
    t: Transcript,
    /// Last accepted host sequence per channel.
    rx_seq: BTreeMap<u32, u32>,
    /// Arrival times of host data packets per (channel, sequence).
    arrivals: BTreeMap<(u32, u32), Vec<Instant>>,
    /// Channels the device accepts data on.
    open: BTreeSet<u32>,
    /// Channels the host closed (CLOSE or CHANNEL_CLOSED).
    closed: BTreeSet<u32>,
    /// Host data packets still to ignore (no ack), per channel.
    withhold: BTreeMap<u32, usize>,
    /// Channels whose host data is not acknowledged at all.
    paused: BTreeSet<u32>,
    /// Device transmit sequence per channel.
    tx_seq: BTreeMap<u32, u32>,
    /// Device packets sent more than once.
    resends: usize,
    eof: bool,
}

struct Shared {
    st: Mutex<State>,
    cv: Condvar,
    w: Mutex<TcpStream>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes `packets` as frames, then the low-water padding.
    fn send(&self, packets: &[Vec<u8>]) {
        let mut buf = Vec::new();
        for p in packets {
            buf.extend_from_slice(b"ELTSDIM\0");
            buf.extend_from_slice(&u32::try_from(p.len()).expect("len").to_ne_bytes());
            buf.extend_from_slice(p);
        }
        for _ in 0..PAD_FRAMES {
            buf.extend_from_slice(&keepalive());
        }
        let mut w = self.w.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = w.write_all(&buf);
    }
}

/// The fake device; dropping it closes the link.
pub struct Pmux {
    sh: Arc<Shared>,
    /// Kept to shut the link down on drop.
    s: TcpStream,
}

impl Drop for Pmux {
    fn drop(&mut self) {
        let _ = self.s.shutdown(Shutdown::Both);
    }
}

impl Pmux {
    /// Connects to port 6969 as device `id` and starts the reader.
    pub fn connect(id: &[u8]) -> Self {
        let dev = FakeDevice::connect(id);
        let s = dev.s;
        let _ = s.set_nodelay(true);
        let sh = Arc::new(Shared {
            st: Mutex::new(State::default()),
            cv: Condvar::new(),
            w: Mutex::new(s.try_clone().expect("clone")),
        });
        let r = s.try_clone().expect("clone");
        let sh2 = Arc::clone(&sh);
        std::thread::spawn(move || reader(r, &sh2));
        Self { sh, s }
    }

    /// Waits until `pred` holds on the state (at most [`TIMEOUT`]).
    fn wait<T>(&self, what: &str, mut pred: impl FnMut(&State) -> Option<T>) -> T {
        let deadline = Instant::now() + TIMEOUT;
        let mut st = self.sh.lock();
        loop {
            if let Some(v) = pred(&st) {
                return v;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "fake device: timed out waiting for {what}: {:?}",
                st.t
            );
            st = self
                .sh
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Waits for the `n`th `OPEN_COMMAND` from the host; returns its channel.
    pub fn wait_open(&self, n: usize) -> u32 {
        self.wait("OPEN_COMMAND", |st| {
            st.t.controls
                .iter()
                .filter(|(op, _)| *op == OPEN_COMMAND)
                .nth(n)
                .map(|&(_, c)| c)
        })
    }

    /// Waits until the host stream on `chan` satisfies `pred`.
    pub fn wait_stream(&self, chan: u32, pred: impl Fn(&[u8]) -> bool) -> Vec<u8> {
        self.wait("stream", |st| {
            let s = st.t.streams.get(&chan).map_or(&[][..], Vec::as_slice);
            pred(s).then(|| s.to_vec())
        })
    }

    /// Waits until the host stream on `chan` holds a newline; returns the
    /// first line, newline included.
    pub fn wait_line(&self, chan: u32) -> Vec<u8> {
        let s = self.wait_stream(chan, |s| s.contains(&b'\n'));
        let end = s
            .iter()
            .position(|&b| b == b'\n')
            .map_or(s.len(), |i| i + 1);
        s[..end].to_vec()
    }

    /// Waits for a control message `(op, channel)` from the host.
    pub fn wait_control(&self, op: u32, chan: u32) {
        self.wait("control message", |st| {
            st.t.controls.contains(&(op, chan)).then_some(())
        });
    }

    /// Ignores (does not acknowledge) the next `n` host data packets on
    /// `chan`.
    pub fn withhold(&self, chan: u32, n: usize) {
        self.sh.lock().withhold.insert(chan, n);
    }

    /// Stops or resumes acknowledging host data on `chan`.
    pub fn pause(&self, chan: u32, on: bool) {
        let mut st = self.sh.lock();
        if on {
            st.paused.insert(chan);
        } else {
            st.paused.remove(&chan);
        }
    }

    /// Arrival times of host packet (`chan`, `seq`).
    pub fn arrivals(&self, chan: u32, seq: u32) -> Vec<Instant> {
        self.sh
            .lock()
            .arrivals
            .get(&(chan, seq))
            .cloned()
            .unwrap_or_default()
    }

    /// Device packets that had to be sent more than once.
    pub fn resends(&self) -> usize {
        self.sh.lock().resends
    }

    pub fn transcript(&self) -> Transcript {
        self.sh.lock().t.clone()
    }

    /// The next device sequence on `chan` (without using it).
    pub fn peek_seq(&self, chan: u32) -> u32 {
        self.sh.lock().tx_seq.get(&chan).copied().unwrap_or(0) + 1
    }

    /// Sends raw packets without waiting for anything.
    pub fn send_raw(&self, packets: &[Vec<u8>]) {
        self.sh.send(packets);
    }

    /// Sends `data` on `chan` in packets of up to [`MAX_PAYLOAD`] bytes,
    /// each retransmitted every 50 ms until acknowledged. Returns `false`
    /// if the host closed the channel first.
    pub fn send(&self, chan: u32, data: &[u8]) -> bool {
        for chunk in data.chunks(MAX_PAYLOAD) {
            let seq = {
                let mut st = self.sh.lock();
                let s = st.tx_seq.entry(chan).or_insert(0);
                *s += 1;
                *s
            };
            let p = data_packet(chan, seq, chunk);
            let deadline = Instant::now() + TIMEOUT;
            let mut first = true;
            loop {
                if !first {
                    self.sh.lock().resends += 1;
                }
                first = false;
                self.sh.send(std::slice::from_ref(&p));
                let until = Instant::now() + RETRANSMIT;
                let mut st = self.sh.lock();
                loop {
                    if st.t.acks.get(&chan).is_some_and(|a| a.contains(&seq)) {
                        break;
                    }
                    if st.closed.contains(&chan) && chan != 1 {
                        return false;
                    }
                    assert!(!st.eof, "fake device: link closed while sending");
                    let now = Instant::now();
                    if now >= until {
                        break;
                    }
                    st = self
                        .sh
                        .cv
                        .wait_timeout(st, until - now)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
                if st.t.acks.get(&chan).is_some_and(|a| a.contains(&seq)) {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "fake device: no ack for {chan:#x}/{seq}"
                );
            }
        }
        true
    }

    /// Sends a control message and waits for its ack. `OPEN` and
    /// `OPEN_COMMAND` make the device accept data on that channel.
    pub fn send_control(&self, op: u32, chan: u32) {
        if op == OPEN || op == OPEN_COMMAND {
            self.sh.lock().open.insert(chan);
        }
        assert!(self.send(1, &control(op, chan)));
    }
}

/// Reads host frames until EOF: records packets and acknowledges data.
fn reader(mut s: TcpStream, sh: &Shared) {
    let _ = s.set_read_timeout(None);
    loop {
        let mut hdr = [0u8; 12];
        if s.read_exact(&mut hdr).is_err() {
            break;
        }
        let len = u32_at(&hdr, 8) as usize;
        if &hdr[..8] != b"ELTSDIM\0" || len > 4096 {
            sh.lock().t.anomalies.push(format!("bad frame {hdr:?}"));
            break;
        }
        if len == 0 {
            continue;
        }
        let mut p = vec![0u8; len];
        if s.read_exact(&mut p).is_err() {
            break;
        }
        {
            // The ack is written before the state changes become visible,
            // so a script that reacts to them sends its next frame after
            // the ack.
            let mut st = sh.lock();
            if let Some(ack) = handle(&mut st, &p) {
                sh.send(&[ack]);
            }
        }
        sh.cv.notify_all();
    }
    sh.lock().eof = true;
    sh.cv.notify_all();
}

/// Handles one host packet; returns the ack to send, if any.
fn handle(st: &mut State, p: &[u8]) -> Option<Vec<u8>> {
    if p.len() < HDR {
        st.t.anomalies.push(format!("short packet {p:?}"));
        return None;
    }
    let flags = u16::from_ne_bytes([p[6], p[7]]);
    let (chan, seq) = (u32_at(p, 8), u32_at(p, 12));
    let (plen, tlen, crc) = (
        u32_at(p, 16) as usize,
        u32_at(p, 20) as usize,
        u32_at(p, 24),
    );
    let payload = &p[HDR..];
    let well_formed = u32_at(p, 0) == MAGIC
        && p[4] == 3
        && p[5] == 0
        && tlen == p.len()
        && plen == payload.len()
        && if flags == ACK {
            plen == 0 && crc == 0
        } else {
            flags == 0 && crc == adler32(payload)
        };
    if !well_formed {
        st.t.anomalies
            .push(format!("malformed packet {:?}", &p[..HDR]));
        return None;
    }
    if flags == ACK {
        st.t.acks.entry(chan).or_default().insert(seq);
        return None;
    }
    st.arrivals
        .entry((chan, seq))
        .or_default()
        .push(Instant::now());
    let last = st.rx_seq.get(&chan).copied().unwrap_or(0);
    if seq == last {
        // A retransmission of an acknowledged packet: ack again.
        return Some(packet(ACK, chan, seq, &[], 0));
    }
    if seq != last + 1 {
        st.t.anomalies
            .push(format!("sequence {seq} after {last} on {chan:#x}"));
        return None;
    }
    if st.paused.contains(&chan) {
        return None;
    }
    if let Some(n) = st.withhold.get_mut(&chan).filter(|n| **n > 0) {
        *n -= 1;
        return None;
    }
    if chan == 1 {
        if payload.len() != 12 {
            st.t.anomalies.push(format!("control payload {payload:?}"));
        } else {
            let (op, ch) = (u32_at(payload, 0), u32_at(payload, 4));
            st.t.controls.push((op, ch));
            match op {
                OPEN_COMMAND | OPEN => {
                    st.open.insert(ch);
                }
                CLOSE | CHANNEL_CLOSED => {
                    st.open.remove(&ch);
                    st.closed.insert(ch);
                }
                _ => {}
            }
        }
    } else if st.open.contains(&chan) {
        st.t.streams
            .entry(chan)
            .or_default()
            .extend_from_slice(payload);
    } else {
        st.t.anomalies
            .push(format!("data on unopened channel {chan:#x}"));
        return None;
    }
    st.rx_seq.insert(chan, seq);
    Some(packet(ACK, chan, seq, &[], 0))
}

#[test]
fn fake_device_codec() {
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    let p = data_packet(0x1000, 2, b"abc");
    assert_eq!(p.len(), 31);
    assert_eq!(u32_at(&p, 20), 31);
    assert_eq!(u32_at(&p, 24), adler32(b"abc"));
    assert_eq!(control(OPEN, 5).len(), 12);
    let o = oob(OOB_RETURN, -1);
    assert_eq!(o.len(), 36);
    assert_eq!(&o[16..24], &[2, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
}
