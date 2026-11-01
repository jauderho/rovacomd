//! Per-device client relay through the mux (ASSESSMENT 8.2, slice 2).
//!
//! Each scenario runs against the C reference and then rovacomd with the
//! same fake device script ([`pmux`]) and the same raw TCP client on the
//! per-device port. Compared: the bytes the client receives, what the
//! device receives ([`Transcript`]: control messages, per-channel data,
//! acknowledged sequences, anomalies), and the daemon's stdout/stderr.

use super::pmux::*;
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const DEV: &[u8; 40] = b"5555555555666666666677777777778888888888";
const CMD: &[u8] = b"run file:///bin/echo hi\n";

fn differential<T: PartialEq + fmt::Debug>(scenario: impl Fn(&Bin) -> T) -> T {
    let _s = session();
    let c = scenario(&Bin::c());
    let r = scenario(&Bin::rust());
    assert_eq!(r, c, "rovacomd (left) differs from C (right)");
    r
}

/// A running daemon with one fake device; `port` is its per-device port.
struct Setup {
    d: Daemon,
    dev: Pmux,
    port: u16,
}

fn setup(bin: &Bin) -> Setup {
    let mut d = Daemon::spawn(bin, &[]);
    d.wait_ready();
    let dev = Pmux::connect(DEV);
    let list = wait_list(|l| lines(l) == 1);
    let port = split_ports(&list)[0].0;
    Setup { d, dev, port }
}

fn client(port: u16) -> TcpStream {
    let s = TcpStream::connect((LOCALHOST, port)).expect("connect device port");
    s.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    s
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).expect("client read");
    b
}

fn read_to_eof(s: &mut TcpStream) -> Vec<u8> {
    let mut b = Vec::new();
    match s.read_to_end(&mut b) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
        Err(e) => panic!("client read: {e}"),
    }
    b
}

/// Deterministic pseudo-random bytes (all byte values, NULs included).
fn blob(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Runs `f` on a thread; the handle panics on join if `f` did.
fn spawn<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> JoinHandle<T> {
    std::thread::spawn(f)
}

fn join<T>(h: JoinHandle<T>) -> T {
    h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// The usual reply of a `run` command: `ok 0`, stdout, stderr, return 0.
fn run_reply() -> Vec<u8> {
    [
        &b"ok 0\n"[..],
        &stream_packet(S_DATA, b"hi\n"),
        &stream_packet(S_ERR, b"warn\n"),
        &oob(OOB_RETURN, 0),
    ]
    .concat()
}

fn ts_lines(lines: &[&[u8]]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|l| [&b"[TS] "[..], l, b"\n"].concat())
        .collect()
}

/// stdout of a run with one device that stays connected.
fn plain_stdout() -> Vec<u8> {
    ts_lines(&[
        &[&b"novacom_go_online:"[..], DEV].concat(),
        &[&b"dev '"[..], DEV, b"' via tcp type emulator"].concat(),
        format!("novacomd version {}", rovacomd::cli::VERSION).as_bytes(),
    ])
}

/// Runs `script` as the device side and `client` as the client side of
/// one scenario; returns (client result, transcript, daemon outcome).
fn scenario<T>(
    bin: &Bin,
    script: impl FnOnce(Arc<Pmux>) + Send + 'static,
    client_side: impl FnOnce(u16) -> T,
) -> (T, Transcript, Outcome) {
    let Setup { d, dev, port } = setup(bin);
    let dev = Arc::new(dev);
    let script = {
        let dev = Arc::clone(&dev);
        spawn(move || script(dev))
    };
    let got = client_side(port);
    join(script);
    let t = dev.transcript();
    (got, t, d.stop())
}

#[test]
fn command_round_trip() {
    let (got, t, out) = differential(|bin| {
        // The client closes only after the device has its last ack: a
        // close right after the client read the data can shut the channel
        // down before the host sends that ack (C drops the pending ack
        // with the channel), which is a race, not a difference.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        scenario(
            bin,
            move |dev| {
                let ch = dev.wait_open(0);
                assert_eq!(dev.wait_line(ch), CMD);
                assert!(dev.send(ch, b"ok 0\n"));
                assert!(dev.send(ch, &stream_packet(S_DATA, b"hi\n")));
                assert!(dev.send(ch, &stream_packet(S_ERR, b"warn\n")));
                assert!(dev.send(ch, &oob(OOB_RETURN, 0)));
                let _ = tx.send(());
                dev.wait_control(CLOSE, ch);
            },
            move |port| {
                let mut s = client(port);
                s.write_all(CMD).expect("send");
                let got = read_n(&mut s, run_reply().len());
                rx.recv_timeout(TIMEOUT).expect("device done");
                got
            },
        )
    });
    assert_eq!(got, run_reply());
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000), (CLOSE, 0x1000)]);
    assert_eq!(t.streams, BTreeMap::from([(0x1000, CMD.to_vec())]));
    assert_eq!(t.acks[&0x1000], (1..=4).collect());
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stdout, plain_stdout());
    assert_eq!(out.stderr, b"");
}

/// `size` bytes each way, then the device closes. The client writes while
/// it reads; the device sends first (`concurrent` false) or while it
/// receives.
fn both_directions(bin: &Bin, size: usize, concurrent: bool) -> (Vec<u8>, Transcript, Outcome) {
    let (down, up) = (blob(size, 1), blob(size, 2));
    let (down2, up2) = (down.clone(), up.clone());
    scenario(
        bin,
        move |dev| {
            let ch = dev.wait_open(0);
            dev.wait_line(ch);
            assert!(dev.send(ch, b"ok 0\n"));
            let sender = {
                let dev = Arc::clone(&dev);
                spawn(move || assert!(dev.send(ch, &down2)))
            };
            if !concurrent {
                join(sender);
                dev.wait_stream(ch, |s| s.len() == CMD.len() + up2.len());
            } else {
                dev.wait_stream(ch, |s| s.len() == CMD.len() + up2.len());
                join(sender);
            }
            dev.send_control(CLOSE, ch);
        },
        move |port| {
            let mut s = client(port);
            s.write_all(CMD).expect("send");
            let ok = read_n(&mut s, 5);
            let mut w = s.try_clone().expect("clone");
            let writer = spawn(move || w.write_all(&up).expect("client send"));
            let got = read_n(&mut s, size);
            join(writer);
            let rest = read_to_eof(&mut s);
            [ok, got, rest].concat()
        },
    )
}

#[test]
fn binary_data_with_nuls_both_directions() {
    let (got, t, out) = differential(|bin| both_directions(bin, 3000, false));
    assert_eq!(got, [&b"ok 0\n"[..], &blob(3000, 1)].concat());
    assert!(blob(3000, 1).contains(&0) && blob(3000, 2).contains(&0));
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000)]);
    assert_eq!(t.streams[&0x1000], [CMD, &blob(3000, 2)].concat());
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stdout, plain_stdout());
    assert_eq!(out.stderr, b"");
}

#[test]
fn large_streams_both_directions() {
    const MIB: usize = 1 << 20;
    let (got, t, out) = differential(|bin| both_directions(bin, MIB + 12_345, true));
    assert_eq!(got, [&b"ok 0\n"[..], &blob(MIB + 12_345, 1)].concat());
    assert_eq!(t.streams[&0x1000], [CMD, &blob(MIB + 12_345, 2)].concat());
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000)]);
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stderr, b"");
}

#[test]
fn slow_reading_client() {
    const SIZE: usize = 8 << 20;
    let (got, t, out) = differential(|bin| {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        scenario(
            bin,
            move |dev| {
                let ch = dev.wait_open(0);
                dev.wait_line(ch);
                // Tells the client once the daemon refused a packet (the
                // client socket is full) and the device had to resend.
                let watcher = {
                    let dev = Arc::clone(&dev);
                    spawn(move || {
                        let deadline = Instant::now() + TIMEOUT;
                        while dev.resends() == 0 && Instant::now() < deadline {
                            std::thread::sleep(POLL);
                        }
                        if dev.resends() > 0 {
                            let _ = tx.send(());
                        }
                    })
                };
                assert!(dev.send(ch, &[&b"ok 0\n"[..], &blob(SIZE, 3)].concat()));
                join(watcher);
                dev.send_control(CLOSE, ch);
            },
            move |port| {
                let mut s = client(port);
                s.write_all(CMD).expect("send");
                let resent = rx.recv_timeout(TIMEOUT * 2).is_ok();
                let bytes = read_to_eof(&mut s) == [&b"ok 0\n"[..], &blob(SIZE, 3)].concat();
                (bytes, resent)
            },
        )
    });
    // Client bytes intact; the daemon refused data while the client socket
    // was full, so the device retransmitted.
    assert_eq!(got, (true, true));
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000)]);
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stderr, b"");
}

/// `SO_SNDBUF` on a client socket (fixes the size, no autotuning).
fn set_sndbuf(s: &TcpStream, bytes: i32) {
    use std::os::fd::AsRawFd;
    // SAFETY: `s` owns a valid socket fd; `bytes` is a live `c_int` and
    // the length passed is its size.
    let rc = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&raw const bytes).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt");
}

#[test]
fn squelch_engages_and_releases() {
    const SIZE: usize = 4 << 20;
    let (stalled, t, out) = differential(|bin| {
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        scenario(
            bin,
            move |dev| {
                let ch = dev.wait_open(0);
                dev.wait_line(ch);
                // From now on the host's data is not acknowledged.
                dev.pause(ch, true);
                assert!(dev.send(ch, b"ok 0\n"));
                go_rx.recv().expect("client stalled");
                dev.pause(ch, false);
                dev.wait_stream(ch, |s| s.len() == CMD.len() + SIZE);
                dev.send_control(CLOSE, ch);
            },
            move |port| {
                let mut s = client(port);
                set_sndbuf(&s, 64 * 1024);
                s.write_all(CMD).expect("send");
                assert_eq!(read_n(&mut s, 5), b"ok 0\n");
                let data = blob(SIZE, 4);
                s.set_nonblocking(true).expect("nonblocking");
                let mut sent = 0;
                let mut idle_since = Instant::now();
                while sent < SIZE && idle_since.elapsed() < Duration::from_millis(500) {
                    match s.write(&data[sent..]) {
                        Ok(n) => {
                            sent += n;
                            idle_since = Instant::now();
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("client send: {e}"),
                    }
                }
                // The daemon stopped reading once 64 KiB were queued.
                let stalled = sent < SIZE;
                go_tx.send(()).expect("resume");
                s.set_nonblocking(false).expect("blocking");
                s.write_all(&data[sent..]).expect("client send");
                assert_eq!(read_to_eof(&mut s), b"");
                stalled
            },
        )
    });
    assert!(stalled, "client was never squelched");
    assert_eq!(t.streams[&0x1000], [CMD, &blob(SIZE, 4)].concat());
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000)]);
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stderr, b"");
}

#[test]
fn client_half_close_closes_channel() {
    let (got, t, out) = differential(|bin| {
        scenario(
            bin,
            |dev| {
                let ch = dev.wait_open(0);
                dev.wait_line(ch);
                assert!(dev.send(ch, b"ok 0\n"));
                dev.wait_control(CLOSE, ch);
                // Data on the closed channel is answered with CHANNEL_CLOSED.
                let seq = dev.peek_seq(ch);
                dev.send_raw(&[data_packet(ch, seq, b"late")]);
                dev.wait_control(CHANNEL_CLOSED, ch);
            },
            |port| {
                let mut s = client(port);
                s.write_all(CMD).expect("send");
                let ok = read_n(&mut s, 5);
                s.write_all(b"stdin data").expect("send");
                s.shutdown(Shutdown::Write).expect("half-close");
                [ok, read_to_eof(&mut s)].concat()
            },
        )
    });
    assert_eq!(got, b"ok 0\n");
    assert_eq!(t.streams[&0x1000], [CMD, b"stdin data"].concat());
    assert_eq!(
        t.controls,
        vec![
            (OPEN_COMMAND, 0x1000),
            (CLOSE, 0x1000),
            (CHANNEL_CLOSED, 0x1000)
        ]
    );
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stderr, b"");
}

#[test]
fn device_closes_first() {
    let (got, t, out) = differential(|bin| {
        scenario(
            bin,
            |dev| {
                let ch = dev.wait_open(0);
                dev.wait_line(ch);
                assert!(dev.send(ch, b"ok 0\n"));
                assert!(dev.send(ch, &stream_packet(S_DATA, b"partial\n")));
                dev.send_control(CLOSE, ch);
            },
            |port| {
                let mut s = client(port);
                s.write_all(CMD).expect("send");
                read_to_eof(&mut s)
            },
        )
    });
    assert_eq!(
        got,
        [&b"ok 0\n"[..], &stream_packet(S_DATA, b"partial\n")].concat()
    );
    // The host closes silently: no CLOSE back.
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000)]);
    assert_eq!(t.acks[&1], BTreeSet::from([1]));
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stdout, plain_stdout());
    assert_eq!(out.stderr, b"");
}

#[test]
fn client_disconnects_mid_stream() {
    const DOWN: usize = 64 * 1024;
    const UP: usize = 512 * 1024;
    let (got, t, out) = differential(|bin| {
        scenario(
            bin,
            |dev| {
                let ch = dev.wait_open(0);
                dev.wait_line(ch);
                assert!(dev.send(ch, &[&b"ok 0\n"[..], &blob(DOWN, 5)].concat()));
                // The command is still running when the client goes away.
                dev.wait_control(CLOSE, ch);
            },
            |port| {
                let mut s = client(port);
                s.write_all(CMD).expect("send");
                let got = read_n(&mut s, 5 + DOWN);
                s.write_all(&blob(UP, 6)).expect("send");
                drop(s);
                got
            },
        )
    });
    assert_eq!(got, [&b"ok 0\n"[..], &blob(DOWN, 5)].concat());
    // Queued client data is still delivered before the CLOSE.
    assert_eq!(t.streams[&0x1000], [CMD, &blob(UP, 6)].concat());
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000), (CLOSE, 0x1000)]);
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stderr, b"");
}

#[test]
fn retransmit_when_device_withholds_ack() {
    let (got, t, out) = differential(|bin| {
        let Setup { d, dev, port } = setup(bin);
        // The OPEN_COMMAND (control channel, sequence 1) and the command
        // line (sequence 1 on the new channel) each arrive three times.
        dev.withhold(1, 2);
        dev.withhold(0x1000, 2);
        let mut s = client(port);
        s.write_all(CMD).expect("send");
        let ch = dev.wait_open(0);
        dev.wait_line(ch);
        assert!(dev.send(ch, b"ok 0\n"));
        assert!(dev.send(ch, &oob(OOB_RETURN, 0)));
        let got = read_n(&mut s, 5 + 36);
        drop(s);
        dev.wait_control(CLOSE, ch);
        let gaps = |times: Vec<Instant>| {
            let ok = times
                .windows(2)
                .all(|w| w[1] - w[0] >= Duration::from_millis(40));
            (times.len(), ok)
        };
        let r = (got, gaps(dev.arrivals(1, 1)), gaps(dev.arrivals(ch, 1)));
        (r, dev.transcript(), d.stop())
    });
    assert_eq!(got.1, (3, true), "OPEN_COMMAND retransmits");
    assert_eq!(got.2, (3, true), "data retransmits");
    assert_eq!(t.controls, vec![(OPEN_COMMAND, 0x1000), (CLOSE, 0x1000)]);
    assert_eq!(t.streams[&0x1000], CMD);
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stderr, b"");
}

#[test]
fn two_concurrent_clients_on_one_device() {
    const SIZE: usize = 256 * 1024;
    let (got, t, out) = differential(|bin| {
        let Setup { d, dev, port } = setup(bin);
        let dev = Arc::new(dev);
        let mut a = client(port);
        a.write_all(b"run file:///bin/cat a\n").expect("send");
        let cha = dev.wait_open(0);
        let mut b = client(port);
        b.write_all(b"run file:///bin/cat b\n").expect("send");
        let chb = dev.wait_open(1);
        let script = |ch: u32, seed: u32| {
            let dev = Arc::clone(&dev);
            spawn(move || {
                let line = dev.wait_line(ch);
                assert!(dev.send(ch, &[&b"ok 0\n"[..], &blob(SIZE, seed)].concat()));
                dev.wait_stream(ch, |s| s.len() == line.len() + SIZE);
                dev.send_control(CLOSE, ch);
            })
        };
        let (sa, sb) = (script(cha, 10), script(chb, 11));
        let io = |mut s: TcpStream, seed: u32| {
            spawn(move || {
                let mut w = s.try_clone().expect("clone");
                let writer = spawn(move || w.write_all(&blob(SIZE, seed)).expect("send"));
                let got = read_to_eof(&mut s);
                join(writer);
                got
            })
        };
        let (ia, ib) = (io(a, 20), io(b, 21));
        let got = (join(ia), join(ib));
        join(sa);
        join(sb);
        (got, dev.transcript(), d.stop())
    });
    assert_eq!(got.0, [&b"ok 0\n"[..], &blob(SIZE, 10)].concat());
    assert_eq!(got.1, [&b"ok 0\n"[..], &blob(SIZE, 11)].concat());
    assert_eq!(
        t.streams,
        BTreeMap::from([
            (
                0x1000,
                [&b"run file:///bin/cat a\n"[..], &blob(SIZE, 20)].concat()
            ),
            (
                0x1001,
                [&b"run file:///bin/cat b\n"[..], &blob(SIZE, 21)].concat()
            ),
        ])
    );
    assert_eq!(
        t.controls,
        vec![(OPEN_COMMAND, 0x1000), (OPEN_COMMAND, 0x1001)]
    );
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stderr, b"");
}

#[test]
fn unknown_and_garbage_pmux_frames() {
    let (t, out) = differential(|bin| {
        let Setup { d, dev, .. } = setup(bin);
        // The host answers data on an unknown channel with CHANNEL_CLOSED;
        // all frames before it have been handled by then.
        let mut pings = 0x7000;
        let mut ping = |dev: &Pmux| {
            pings += 1;
            dev.send_raw(&[data_packet(pings, 1, b"ping")]);
            dev.wait_control(CHANNEL_CLOSED, pings);
        };
        let good = data_packet(1, 1, &control(OPEN, 0x9000));
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xff;
        let mut bad_version = good.clone();
        bad_version[4] = 2;
        let mut long_total = good.clone();
        long_total[20..24].copy_from_slice(&41u32.to_ne_bytes());
        let mut long_payload = good.clone();
        long_payload[16..20].copy_from_slice(&41u32.to_ne_bytes());
        let mut other_flags = good.clone();
        other_flags[6] = 2;
        dev.send_raw(&[
            bad_magic,
            bad_version,
            long_total,
            long_payload,
            other_flags,
            data_packet(0, 1, b"null channel"),
            b"xump\x03".to_vec(),
        ]);
        ping(&dev);
        // An ack for an unknown channel, a stale ack on the control channel.
        dev.send_raw(&[packet(ACK, 2, 1, &[], 0), packet(ACK, 1, 99, &[], 0)]);
        dev.wait_control(CHANNEL_CLOSED, 2);
        // Out of sequence on the control channel: logged, not acked.
        let seq = dev.peek_seq(1);
        dev.send_raw(&[data_packet(1, seq + 5, &control(OPEN, 0x9001))]);
        ping(&dev);
        // Bad checksum: dropped; then the same sequence, correct.
        let mut bad_crc = data_packet(1, seq, &control(OPEN, 0x9000));
        bad_crc[24] ^= 1;
        dev.send_raw(&[bad_crc]);
        ping(&dev);
        dev.send_control(OPEN, 0x9000);
        // A channel without a reader: its data is not acked.
        dev.send_raw(&[data_packet(0x9000, 1, b"no reader")]);
        ping(&dev);
        // Short and unknown control messages are acked and ignored.
        assert!(dev.send(1, b"short"));
        ping(&dev);
        assert!(dev.send(1, &control(99, 5)));
        dev.send_control(CLOSE, 0x9000);
        dev.send_raw(&[data_packet(0x9000, 2, b"after close")]);
        dev.wait_control(CHANNEL_CLOSED, 0x9000);
        // OPEN_COMMAND from the device: the host command handler answers
        // unknown or unparsable commands.
        dev.send_control(OPEN_COMMAND, 0x8000_0001);
        assert!(dev.send(0x8000_0001, b"\n"));
        dev.wait_stream(0x8000_0001, |s| s.len() == 22);
        assert!(dev.send(0x8000_0001, b"bogus x://y\n"));
        dev.wait_stream(0x8000_0001, |s| s.len() == 44);
        ping(&dev);
        (dev.transcript(), d.stop())
    });
    let closed = |c: u32| (CHANNEL_CLOSED, c);
    assert_eq!(
        t.controls,
        vec![
            closed(0x7001),
            closed(2),
            closed(0x7002),
            closed(0x7003),
            closed(0x7004),
            closed(0x7005),
            closed(0x9000),
            closed(0x7006),
        ]
    );
    assert_eq!(
        t.streams[&0x8000_0001],
        b"unrecognized command\n\0unrecognized command\n\0"
    );
    assert!(!t.acks.contains_key(&0x9000));
    assert!(t.anomalies.is_empty());
    assert_eq!(out.stdout, plain_stdout());
    assert_eq!(
        out.stderr,
        ts_lines(&[b"[1] RX PKT OUT OF SEQUENCE (this is a very weird and bad thing): h->seq: 6, c->rx_seq: 0, h->flags: 0, h->channel: 1,c->last_tx: 2, c->acked_tx: 2"])
    );
}
