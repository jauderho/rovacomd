//! Log port (6970): the daemon sends every log line (all masks, with
//! timestamps) to its latest client. Compared byte for byte after
//! normalizing timestamps, the C version string and, on macOS, clang's
//! `__PRETTY_FUNCTION__` text (GCC, the upstream toolchain, gives the
//! bare function name, which rovacomd prints).

use super::pmux::*;
use super::*;

/// A client of the log port, read on a thread until the daemon closes it.
pub struct LogTap {
    h: JoinHandle<Vec<u8>>,
}

impl LogTap {
    /// Connects and waits until the main loop has taken the connection:
    /// two device-list requests answered after the connect mean a full
    /// pass of the loop ran after the one that saw the log listener ready.
    pub fn connect() -> Self {
        let mut s = TcpStream::connect((LOCALHOST, 6970)).expect("connect log port");
        s.set_read_timeout(Some(TIMEOUT * 6)).expect("timeout");
        let h = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        });
        devlist();
        devlist();
        Self { h }
    }

    /// Everything received, normalized; `drop_timing` removes the lines
    /// whose presence depends on retransmission timing.
    pub fn finish(self, bin: &Bin, drop_timing: bool) -> Vec<u8> {
        let raw = self.h.join().expect("log reader");
        normalize_log(&raw, bin, drop_timing)
    }
}

/// Lines that a late acknowledgment (a retransmission) adds.
const TIMING_LINES: [&[u8]; 2] = [b"] RE-ACK: ", b"] Out of sequence ACK: "];

/// clang `__PRETTY_FUNCTION__` (`type name(args)`) before `:` at the start
/// of a message, replaced by the bare name.
fn bare_function_names(line: &[u8]) -> Vec<u8> {
    let Some(close) = line.windows(2).position(|w| w == b"):") else {
        return line.to_vec();
    };
    let Some(open) = line[..close].iter().position(|&b| b == b'(') else {
        return line.to_vec();
    };
    let head = &line[..open];
    let ok = head
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b' ' || b == b'*')
        && head.contains(&b' ');
    if !ok {
        return line.to_vec();
    }
    let name_start = head
        .iter()
        .rposition(|&b| !(b.is_ascii_alphanumeric() || b == b'_'))
        .map_or(0, |i| i + 1);
    [&head[name_start..], &line[close + 1..]].concat()
}

/// The peer port of `Incoming connection from <host>/<port>` (inet
/// listener), replaced by `<P>`.
fn mask_incoming_port(line: &[u8]) -> Vec<u8> {
    const KEY: &[u8] = b"Incoming connection from ";
    let Some(at) = line.windows(KEY.len()).position(|w| w == KEY) else {
        return line.to_vec();
    };
    let Some(slash) = line[at..].iter().position(|&b| b == b'/') else {
        return line.to_vec();
    };
    let start = at + slash + 1;
    let end = start
        + line[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    [&line[..start], b"<P>", &line[end..]].concat()
}

pub fn normalize_log(raw: &[u8], bin: &Bin, drop_timing: bool) -> Vec<u8> {
    let text = normalize_timestamps(raw);
    let text = if bin.is_c {
        replace_all(&text, C_VERSION, rovacomd::cli::VERSION.as_bytes())
    } else {
        text
    };
    let mut out = Vec::new();
    for line in text.split_inclusive(|&b| b == b'\n') {
        let line = &mask_incoming_port(line);
        if drop_timing
            && TIMING_LINES
                .iter()
                .any(|t| line.windows(t.len()).any(|w| w == *t))
        {
            continue;
        }
        match line.strip_prefix(b"[TS] ") {
            Some(rest) if bin.is_c && cfg!(target_os = "macos") => {
                out.extend_from_slice(b"[TS] ");
                out.extend_from_slice(&bare_function_names(rest));
            }
            _ => out.extend_from_slice(line),
        }
    }
    out
}

#[test]
fn clang_names_are_reduced() {
    assert_eq!(
        bare_function_names(b"void *packet_thread(void *):206: tried\n"),
        b"packet_thread:206: tried\n"
    );
    assert_eq!(
        bare_function_names(b"device_handle_t novacom_go_online(const char *, char *):abc\n"),
        b"novacom_go_online:abc\n"
    );
    let gcc = b"novacom_process_packet:462: *** CHECKSUM MISMATCH *** (that's a bad thing): x\n";
    assert_eq!(bare_function_names(gcc), gcc);
}

fn differential<T: PartialEq + fmt::Debug>(scenario: impl Fn(&Bin) -> T) -> T {
    let _s = session();
    let c = scenario(&Bin::c());
    let r = scenario(&Bin::rust());
    assert_eq!(r, c, "rovacomd (left) differs from C (right)");
    r
}

const DEV: &[u8; 40] = b"10101010102020202020303030303040404040ab";

/// A second log client replaces the first, which is closed.
#[test]
fn latest_log_client_wins() {
    let (first, second) = differential(|bin| {
        let d = start(bin);
        let a = LogTap::connect();
        let b = LogTap::connect();
        let first = a.finish(bin, false);
        let dev = FakeDevice::connect(DEV);
        wait_list(|l| lines(l) == 1);
        drop(dev);
        wait_list(<[u8]>::is_empty);
        let _ = d.stop();
        (first, b.finish(bin, false))
    });
    assert_eq!(first, b"");
    let want: Vec<u8> = [
        b"[TS] Incoming connection from 127.0.0.1/<P>\n".to_vec(),
        [&b"[TS] novacom_go_online:"[..], DEV, b"\n"].concat(),
        [&b"[TS] dev '"[..], DEV, b"' via tcp type emulator\n"].concat(),
        b"[TS] inet_rx_loop:187: invalid packet header (0/12)\n".to_vec(),
        b"[TS] novacom_go_offline:762: going offline\n".to_vec(),
        [&b"[TS] removing id "[..], DEV, b"\n"].concat(),
        b"[TS] shutting down channel 1\n".to_vec(),
        format!("[TS] novacomd version {}\n", rovacomd::cli::VERSION).into_bytes(),
    ]
    .concat();
    assert_eq!(second, want);
}

fn start(bin: &Bin) -> Daemon {
    let mut d = Daemon::spawn(bin, &[]);
    d.wait_ready();
    d
}

/// Mux diagnostics: control messages, a duplicate packet (RE-ACK), a
/// stale acknowledgment, a checksum mismatch, data on a channel being
/// closed, and the channels shut down when the device goes away.
#[test]
fn mux_trace_lines() {
    let (log, full) = differential(|bin| {
        let d = start(bin);
        let tap = LogTap::connect();
        let dev = Pmux::connect(DEV);
        wait_list(|l| lines(l) == 1);
        const A: u32 = 0x8000_0010;
        const B: u32 = 0x8000_0011;
        dev.send_control(OPEN, A);
        dev.send_control(OPEN_COMMAND, B);
        assert!(dev.send(B, b"bogus x://y\n"));
        dev.wait_stream(B, |s| s.len() == 22);
        // Let the host see the device's ack of its reply.
        std::thread::sleep(Duration::from_millis(200));
        // Duplicate of sequence 1: re-acknowledged.
        dev.send_raw(&[data_packet(B, 1, b"bogus x://y\n")]);
        // Acknowledgment of a sequence the host never sent.
        dev.send_raw(&[packet(ACK, B, 7, &[], 0)]);
        // Wrong checksum: dropped.
        dev.send_raw(&[packet(0, B, 2, b"zz", 0x1234_5678)]);
        std::thread::sleep(Duration::from_millis(200));
        dev.send_control(CLOSE, A);
        dev.send_control(CHANNEL_CLOSED, 0x8000_0099);
        dev.send_control(99, 5);
        drop(dev);
        wait_list(<[u8]>::is_empty);
        let _ = d.stop();
        let raw = tap.h.join().expect("log");
        (
            normalize_log(&raw, bin, true),
            normalize_log(&raw, bin, false),
        )
    });
    let want: Vec<u8> = [
        b"[TS] Incoming connection from 127.0.0.1/<P>\n".to_vec(),
        [&b"[TS] novacom_go_online:"[..], DEV, b"\n"].concat(),
        [&b"[TS] dev '"[..], DEV, b"' via tcp type emulator\n"].concat(),
        b"[TS] CONTROL_OPEN: -2147483632\n".to_vec(),
        b"[TS] CONTROL_OPEN_COMMAND: -2147483631\n".to_vec(),
        format!(
            "[TS] novacom_process_packet:462: *** CHECKSUM MISMATCH *** (that's a bad thing): header->crc(12345678), crc({:08x})\n",
            adler32(b"zz")
        )
        .into_bytes(),
        b"[TS] CONTROL_CLOSE: -2147483632\n".to_vec(),
        b"[TS] CONTROL_CHANNEL_CLOSED: -2147483495\n".to_vec(),
        b"[TS] inet_rx_loop:187: invalid packet header (0/12)\n".to_vec(),
        b"[TS] novacom_go_offline:762: going offline\n".to_vec(),
        [&b"[TS] removing id "[..], DEV, b"\n"].concat(),
        b"[TS] shutting down channel 1\n".to_vec(),
        b"[TS] shutting down channel -2147483631\n".to_vec(),
        format!("[TS] novacomd version {}\n", rovacomd::cli::VERSION).into_bytes(),
    ]
    .concat();
    assert_eq!(
        String::from_utf8_lossy(&log),
        String::from_utf8_lossy(&want)
    );
    let has = |t: &str| {
        full.split(|&b| b == b'\n')
            .any(|l| l.starts_with(t.as_bytes()))
    };
    assert!(has(
        "[TS] [-2147483631] RE-ACK: h->seq: 1, c->rx_seq: 1, h->flags: 0, h->channel: -2147483631,c->last_tx: 1, c->acked_tx: 1"
    ));
    assert!(has(
        "[TS] [-2147483631] Out of sequence ACK: h->seq: 7, c->rx_seq: 1, h->flags: 1, h->channel: -2147483631,c->last_tx: 1, c->acked_tx: 1"
    ));
}

/// A text to mask: prefix, replacement, bytes of the masked value.
type Mask = (&'static [u8], &'static [u8], fn(u8) -> bool);

/// Normalizes what differs between processes in the relay trace lines:
/// pointers, socket fds and the stale `errno` of the EOF line.
fn mask_relay(log: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    let masks: [Mask; 5] = [
        (b"0x", b"<PTR>", |b| b.is_ascii_hexdigit()),
        (b"socket ", b"socket <FD>", |b| b.is_ascii_digit()),
        (b"sc->socket=", b"sc->socket=<FD>", |b| b.is_ascii_digit()),
        (b"sock=", b"sock=<FD>", |b| b.is_ascii_hexdigit()),
        (b"recv: errno=", b"recv: errno=<E>", |b| b.is_ascii_digit()),
    ];
    'outer: while i < log.len() {
        for (from, to, keep) in masks {
            if log[i..].starts_with(from) {
                out.extend_from_slice(to);
                i += from.len();
                while i < log.len() && keep(log[i]) {
                    i += 1;
                }
                continue 'outer;
            }
        }
        out.push(log[i]);
        i += 1;
    }
    out
}

/// The per-device relay: a client's command, data and close.
#[test]
fn relay_trace_lines() {
    let log = differential(|bin| {
        let d = start(bin);
        let tap = LogTap::connect();
        let dev = std::sync::Arc::new(Pmux::connect(DEV));
        let port = split_ports(&wait_list(|l| lines(l) == 1))[0].0;
        let mut c = TcpStream::connect((LOCALHOST, port)).expect("client");
        c.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        let ch = dev.wait_open(0);
        c.write_all(b"get file://x\0junk").expect("send");
        dev.wait_stream(ch, |s| s.len() == 17);
        assert!(dev.send(ch, b"ok 0\n"));
        let mut ok = [0u8; 5];
        c.read_exact(&mut ok).expect("read");
        drop(c);
        dev.wait_control(CLOSE, ch);
        // A client the device never answers: its close is logged on the
        // device's packet.
        drop(dev);
        wait_list(<[u8]>::is_empty);
        let _ = d.stop();
        String::from_utf8_lossy(&mask_relay(&tap.finish(bin, true))).into_owned()
    });
    let want = [
        "Incoming connection from 127.0.0.1/<P>",
        "novacom_go_online:10101010102020202020303030303040404040ab",
        "dev '10101010102020202020303030303040404040ab' via tcp type emulator",
        "data socket <FD>",
        "novacom_register_client:512: Opening temp channel, device <PTR>",
        "novacom_register_client:525: socketchan::created: <PTR>, socket <FD>, novacom 4096, device <PTR>",
        "main_loop:780: src/main.c:780: sock=<FD>, cmd/data recved: get file://x, len=17",
        "main_loop:769: src/main.c:769: recv: errno=<E>, ret=0, sc->socket=<FD>",
        "destroy_socketchan:256: socketchan::destroy: <PTR>, socket <FD>, novacom 4096, device <PTR>",
        "inet_rx_loop:187: invalid packet header (0/12)",
        "novacom_go_offline:762: going offline",
        "removing id 10101010102020202020303030303040404040ab",
        "shutting down channel 1",
    ]
    .iter()
    .map(|l| format!("[TS] {l}\n"))
    .collect::<String>()
        + &format!("[TS] novacomd version {}\n", rovacomd::cli::VERSION);
    assert_eq!(log, want);
}
