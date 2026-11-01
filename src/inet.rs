//! Inet transport: emulation of `transport_inet.c` (listen on port 6969,
//! `-c` outbound connect) and of the host nduid (`novacom_nduid_init`).
//!
//! Wire format, all integers host byte order as in C:
//! syn `"nduid: \0"` + 40-byte nduid (both sides send, then read);
//! frame `"ELTSDIM\0"` + `u32` length + one pmux packet (length 0 =
//! keepalive, sent after 2 s without traffic).
//!
//! Received packets go to the mux; the tx thread sends what the mux has
//! (an empty frame after 2 s without any). C never ends the link on a bad
//! pmux packet (`novacom_process_packet` never returns
//! `PACKET_TYPE_BADPACKET`).

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::devices::{self, NDUID_CHRLEN};
use crate::{log, mux, net, server, sys};

/// C `NDUID_MAGIC` with its NUL.
pub const NDUID_MAGIC: &[u8; 8] = b"nduid: \0";
/// C `IP_MAGIC` with its NUL.
pub const IP_MAGIC: &[u8; 8] = b"ELTSDIM\0";
/// C `IP_MAX_PACKET_SIZE`.
pub const IP_MAX_PACKET_SIZE: u32 = 4096;
/// Size of C `inet_syn_t`.
pub const SYN_LEN: usize = 48;
/// Size of C `inet_header_t`.
pub const HEADER_LEN: usize = 12;
/// `novacom_get_tx_packet(..., 2000)` timeout: idle time before a keepalive.
const KEEPALIVE: Duration = Duration::from_millis(2000);
/// Pause after a failed `accept` (C `usleep(100000)`).
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
/// Pause between outbound connection attempts (C `sleep(1)`).
const RECONNECT: Duration = Duration::from_secs(1);
/// C `NI_MAXHOST - 1` and `NI_MAXSERV - 1`: `-c` host and service limits.
const MAX_HOST: usize = 1024;
const MAX_SERV: usize = 31;

static NDUID: OnceLock<[u8; NDUID_CHRLEN]> = OnceLock::new();

/// C `novacom_nduid_init`: 40 lowercase hex digits from `rand()` (seeded
/// with `srand(time(NULL))` beforehand, as in C). Called at startup so the
/// `rand()` calls happen in the C order.
pub fn init_nduid() {
    nduid();
}

/// C `novacom_nduid()`.
pub fn nduid() -> &'static [u8; NDUID_CHRLEN] {
    NDUID.get_or_init(|| {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut id = [0u8; NDUID_CHRLEN];
        for b in &mut id {
            *b = HEX[(sys::rand() & 0xf) as usize];
        }
        id
    })
}

/// The 48-byte syn sent to a peer.
pub fn encode_syn(nduid: &[u8; NDUID_CHRLEN]) -> [u8; SYN_LEN] {
    let mut syn = [0u8; SYN_LEN];
    syn[..8].copy_from_slice(NDUID_MAGIC);
    syn[8..].copy_from_slice(nduid);
    syn
}

/// The peer nduid from a received syn (bytes up to the first NUL within
/// 40), or `None` on a wrong magic.
pub fn decode_syn(syn: &[u8; SYN_LEN]) -> Option<Vec<u8>> {
    if &syn[..8] != NDUID_MAGIC {
        return None;
    }
    let id = &syn[8..];
    Some(id[..id.iter().position(|&b| b == 0).unwrap_or(id.len())].to_vec())
}

/// A frame header for a packet of `len` bytes.
pub fn encode_header(len: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(IP_MAGIC);
    h[8..].copy_from_slice(&len.to_ne_bytes());
    h
}

/// Packet length from a frame header, or `None` on a wrong magic or a
/// length above [`IP_MAX_PACKET_SIZE`].
pub fn decode_header(h: &[u8; HEADER_LEN]) -> Option<u32> {
    let len = u32::from_ne_bytes([h[8], h[9], h[10], h[11]]);
    (&h[..8] == IP_MAGIC && len <= IP_MAX_PACKET_SIZE).then_some(len)
}

/// C `platform_create_thread`, which asserts on failure.
///
/// Intentional change: C logs `ASSERT FAILED ...` and crashes with
/// SIGSEGV; this aborts without the message.
fn spawn(f: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    std::thread::Builder::new()
        .spawn(f)
        .unwrap_or_else(|_| std::process::abort())
}

/// C `inet_rx_loop`: syn exchange, registration, frame loop, offline.
fn rx_loop(stream: TcpStream) {
    let stream = Arc::new(stream);
    let _ = stream.set_nodelay(true);
    // One send; the result is ignored, as in C.
    let _ = std::io::Write::write(&mut &*stream, &encode_syn(nduid()));
    let mut syn = [0u8; SYN_LEN];
    let n = net::read_full(&stream, &mut syn);
    let peer = if n == SYN_LEN as isize {
        decode_syn(&syn)
    } else {
        None
    };
    let Some(peer) = peer else {
        log::error(format!("invalid connection packet, read({n}/{SYN_LEN})\n").as_bytes());
        return;
    };
    let dev = devices::go_online(&peer, b"tcp", b"emulator");
    let shutdown = Arc::new(AtomicBool::new(false));
    let tx = {
        let (stream, shutdown, dev) =
            (Arc::clone(&stream), Arc::clone(&shutdown), Arc::clone(&dev));
        spawn(move || tx_loop(&stream, &shutdown, &dev))
    };
    // C reuses one uninitialized `IP_MAX_PACKET_SIZE` buffer, and the mux
    // reads stale bytes from it (D17). Intentional change: it starts
    // zeroed.
    let mut buf = vec![0u8; IP_MAX_PACKET_SIZE as usize];
    loop {
        let mut hdr = [0u8; HEADER_LEN];
        let n = net::read_full(&stream, &mut hdr);
        let len = if n == HEADER_LEN as isize {
            decode_header(&hdr)
        } else {
            None
        };
        let Some(len) = len else {
            log::trace(
                format!("inet_rx_loop:187: invalid packet header ({n}/{HEADER_LEN})\n").as_bytes(),
            );
            break;
        };
        #[cfg(target_os = "linux")]
        sys::tcp_quickack(&stream);
        if len > 0 {
            let n = net::read_full(&stream, &mut buf[..len as usize]);
            if n != len as isize {
                log::trace(
                    format!("inet_rx_loop:198: invalid data length ({n}/{len})\n").as_bytes(),
                );
                break;
            }
            dev.process_packet(&buf, len as usize);
        }
    }
    // C sets the tx shutdown flag and waits for the tx thread, which
    // finishes its current `novacom_get_tx_packet` and sends once more.
    shutdown.store(true, Ordering::Relaxed);
    let _ = tx.join();
    devices::go_offline(&dev);
}

/// C `inet_tx_loop`: one frame per `novacom_get_tx_packet` call, empty
/// when it returns no packet within 2 s.
fn tx_loop(stream: &TcpStream, shutdown: &AtomicBool, dev: &mux::Device) {
    while !shutdown.load(Ordering::Relaxed) {
        let pkt = dev
            .get_tx_packet(KEEPALIVE, IP_MAX_PACKET_SIZE as usize)
            .unwrap_or_default();
        // pkt.len() <= IP_MAX_PACKET_SIZE.
        let mut frame = encode_header(pkt.len() as u32).to_vec();
        frame.extend_from_slice(&pkt);
        // One send; the result is ignored, as in C (D27).
        let _ = std::io::Write::write(&mut &*stream, &frame);
    }
}

/// C `inetlisten_transport_start`: the port 6969 listener thread.
pub fn start_listener() {
    let _ = spawn(|| {
        let listener = match net::create_listen_socket(net::INETPORT, server::listen_all()) {
            Ok(l) => l,
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                log::error(format!("Unable to create socket(errno {errno})\n").as_bytes());
                return;
            }
        };
        loop {
            match listener.accept() {
                Ok((s, addr)) => {
                    log::trace(
                        format!("Incoming connection from {}/{}\n", addr.ip(), addr.port())
                            .as_bytes(),
                    );
                    let _ = spawn(move || rx_loop(s));
                }
                Err(_) => std::thread::sleep(ACCEPT_RETRY),
            }
        }
    });
}

/// C `inetconnect_connect_to(host, serv)` (`-c host[:port]`): logs the
/// target and starts a thread that resolves it once, then connects and
/// runs the link forever, retrying every second.
///
/// Intentional change (D5): on macOS a resolution failure makes C
/// dereference NULL; here the thread ends as on Linux.
pub fn connect_to(host: &[u8], serv: Option<&[u8]>) {
    let host = host[..host.len().min(MAX_HOST)].to_vec();
    let serv = match serv {
        Some(s) if !s.is_empty() => s[..s.len().min(MAX_SERV)].to_vec(),
        _ => net::INETPORT.to_string().into_bytes(),
    };
    log::always(&[b"Connecting to ", &host[..], b"/", &serv[..], b" via IP\n"].concat());
    let _ = spawn(move || {
        let Some(addr) = sys::resolve_first(&host, &serv) else {
            log::trace(b"inetconnect_findandattach_thread:311: Host not found\n");
            return;
        };
        loop {
            if let Ok(s) = TcpStream::connect(addr) {
                rx_loop(s);
            }
            std::thread::sleep(RECONNECT);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &[u8; 40] = b"0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn syn_round_trip() {
        let syn = encode_syn(ID);
        assert_eq!(&syn[..8], b"nduid: \0");
        assert_eq!(&syn[8..], ID);
        assert_eq!(decode_syn(&syn), Some(ID.to_vec()));
    }

    #[test]
    fn syn_nduid_stops_at_nul_and_magic_is_exact() {
        let mut syn = encode_syn(ID);
        syn[8 + 5] = 0;
        assert_eq!(decode_syn(&syn), Some(b"01234".to_vec()));
        let mut bad = encode_syn(ID);
        bad[7] = b'x';
        assert_eq!(decode_syn(&bad), None);
        let mut bad = encode_syn(ID);
        bad[0] = b'N';
        assert_eq!(decode_syn(&bad), None);
    }

    #[test]
    fn header_round_trip_and_limits() {
        let h = encode_header(0);
        assert_eq!(&h[..8], b"ELTSDIM\0");
        assert_eq!(&h[8..], &0u32.to_ne_bytes());
        assert_eq!(decode_header(&h), Some(0));
        assert_eq!(decode_header(&encode_header(4096)), Some(4096));
        assert_eq!(decode_header(&encode_header(4097)), None);
        let mut bad = encode_header(1);
        bad[7] = b' ';
        assert_eq!(decode_header(&bad), None);
    }

    #[test]
    fn nduid_is_40_lowercase_hex() {
        init_nduid();
        let id = nduid();
        assert!(id.iter().all(|b| b"0123456789abcdef".contains(b)));
    }
}
