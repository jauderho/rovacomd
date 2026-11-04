//! Device-initiated commands on the host: emulation of the host build of
//! C `commands_device.c` (`get file`, `put file`, `connect tcp-port`,
//! `start_fds_thread`, the reader and writer workers, `callback_to_bufq`)
//! and `packet.c` (`send_packet*`, `packet_thread`).
//!
//! D1, kept as in C (ASSESSMENT Q2): a peer that opens an `OPEN_COMMAND`
//! channel on the host can read any file the daemon can read (`get`),
//! create or overwrite files with mode 0775 (`put`, less the umask) and
//! open TCP connections to `localhost` (`connect`). There is no
//! authentication on the host.
//!
//! Replies on the channel: `file open failed\n\0` or `socket open
//! failed\n\0` (the channel stays open, its data is no longer
//! acknowledged), else `ok 0\n`, then end-to-end stream packets
//! (`packet_struct.h`, host byte order): data, EOF and the return code,
//! after which the host closes the channel.
//!
//! The host build never has a child process or a stderr stream: the
//! `open tty` / `run file` handlers are device-only, so the C stderr
//! reader, the signal and resize messages and `waitpid` are not reached.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::Duration;

use crate::cmdparse::CommandUrl;
use crate::mux::{self, Device, Mux, Reader, c_int};
use crate::{inet, log, sys};

/// Reply when `get`/`put` cannot open the file, NUL included.
const FILE_OPEN_FAILED: &[u8] = b"file open failed\n\0";
/// Reply when `connect` cannot connect, NUL included.
const SOCKET_OPEN_FAILED: &[u8] = b"socket open failed\n\0";
/// C `NOVACOMDMSG_REPLY_OK`, sent without its NUL.
const REPLY_OK: &[u8] = b"ok 0\n";
/// C `QUEUE_MAX`: incoming data is not acknowledged while the input queue
/// holds more; the packet thread waits for the output queue to drain
/// above it.
const QUEUE_MAX: usize = 65536;
/// C `RWSIZE`: bytes per read or write.
const RWSIZE: usize = 16384;
/// Mode of a file created by `put` (C `S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH`).
const PUT_MODE: u32 = 0o775;
/// How long `start_fds_thread` waits for the packet thread before it
/// closes the input queue.
const PACKET_WAIT: Duration = Duration::from_secs(60);

/// `struct packet_header` (`packet_struct.h`).
const PACKET_MAGIC: u32 = 0xDECA_FBAD;
const PACKET_VERSION: u32 = 1;
const PACKET_HEADER_LEN: usize = 16;
const TYPE_DATA: u32 = 0;
const TYPE_ERR: u32 = 1;
const TYPE_OOB: u32 = 2;
/// `struct packet_oob_msg`: `u32 message` and a 16-byte union.
const OOB_LEN: usize = 20;
const OOB_EOF: u32 = 0;
const OOB_SIGNAL: u32 = 1;
const OOB_RETURN: u32 = 2;
const OOB_RESIZE: u32 = 3;
const STDIN_FILENO: i32 = 0;
const STDOUT_FILENO: i32 = 1;
const STDERR_FILENO: i32 = 2;

/// C `iohandlers` (host build): starts the handler for `url` on channel
/// `chan`; `false` if there is none. Called by the command handler with
/// the mux locked, as in C; threads start once it is released.
pub(crate) fn start(m: &mut Mux, chan: u32, url: &CommandUrl) -> bool {
    let is = |verb: &[u8], scheme: &[u8]| {
        url.verb.eq_ignore_ascii_case(verb) && url.scheme.eq_ignore_ascii_case(scheme)
    };
    if is(b"get", b"file") {
        file_send(m, chan, &url.path);
    } else if is(b"put", b"file") {
        file_receive(m, chan, &url.path);
    } else if is(b"connect", b"tcp-port") {
        tcp_connect(m, chan, &url.path);
    } else {
        return false;
    }
    true
}

fn path_of(p: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(p))
}

/// C `novacom_start_file_send`: `open(path, O_RDONLY)`.
fn file_send(m: &mut Mux, chan: u32, path: &[u8]) {
    match File::open(path_of(path)) {
        Err(_) => {
            let _ = m.write(chan, FILE_OPEN_FAILED, None);
        }
        Ok(f) => start_fds_thread(m, chan, None, Some(f), false),
    }
}

/// C `novacom_start_file_receive`:
/// `open(path, O_WRONLY|O_CREAT|O_TRUNC, 0775)`.
fn file_receive(m: &mut Mux, chan: u32, path: &[u8]) {
    let opened = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PUT_MODE)
        .open(path_of(path));
    match opened {
        Err(_) => {
            let _ = m.write(chan, FILE_OPEN_FAILED, None);
        }
        Ok(f) => start_fds_thread(m, chan, Some(f), None, false),
    }
}

/// C `novacom_start_tcp_connect`: the connection is made on its own
/// thread (`tcp_connect_thread`).
fn tcp_connect(m: &mut Mux, chan: u32, port: &[u8]) {
    let port = port.to_vec();
    m.spawn(Box::new(move |dev| {
        let _ = inet::spawn(move || tcp_connect_thread(Chan { dev, num: chan }, &port));
    }));
}

/// C `tcp_connect_thread`: `getaddrinfo("localhost", port)` with
/// `AI_ALL|AI_ADDRCONFIG`, a connection to the first address, then the
/// socket serves as both input and output (`stdout_lead`).
///
/// Intentional change: on macOS (positive `EAI_*` codes) a resolution
/// failure makes C dereference NULL; here it is a failure as on Linux.
fn tcp_connect_thread(c: Chan, port: &[u8]) {
    let sock = sys::resolve_first(b"localhost", port).and_then(|a| TcpStream::connect(a).ok());
    let Some(sock) = sock else {
        let _ = c.dev.with(|m| m.write(c.num, SOCKET_OPEN_FAILED, None));
        return;
    };
    let dup = |s: &TcpStream| s.try_clone().ok().map(|d| File::from(OwnedFd::from(d)));
    let (stdin, stdout) = (dup(&sock), dup(&sock));
    drop(sock);
    start_fds(c, stdin, stdout, true);
}

/// Starts C `start_fds_thread` once the mux is released.
fn start_fds_thread(
    m: &mut Mux,
    chan: u32,
    stdin: Option<File>,
    stdout: Option<File>,
    stdout_lead: bool,
) {
    m.spawn(Box::new(move |dev| {
        let _ = inet::spawn(move || start_fds(Chan { dev, num: chan }, stdin, stdout, stdout_lead));
    }));
}

/// A channel of a device, as the worker threads use it.
struct Chan {
    dev: Arc<Device>,
    num: u32,
}

impl Chan {
    /// C `novacom_write_channel_sync`: queues `data` and waits until the
    /// device acknowledged it or the channel went away. -1 if there is no
    /// such channel.
    fn write_sync(&self, data: &[u8]) -> i32 {
        let ev = Arc::new(mux::Event::default());
        let done = {
            let ev = Arc::clone(&ev);
            Box::new(move || ev.signal())
        };
        if self
            .dev
            .with(|m| m.write(self.num, data, Some(done)))
            .is_err()
        {
            return -1;
        }
        ev.wait();
        0
    }

    /// C `send_packet`: one stream packet, synchronously.
    fn send_packet(&self, kind: u32, payload: &[u8]) -> i32 {
        let mut p = Vec::with_capacity(PACKET_HEADER_LEN + payload.len());
        for v in [PACKET_MAGIC, PACKET_VERSION, payload.len() as u32, kind] {
            p.extend_from_slice(&v.to_ne_bytes());
        }
        p.extend_from_slice(payload);
        self.write_sync(&p)
    }

    /// C `send_packet_eof` / `send_packet_returncode`.
    fn send_oob(&self, message: u32, arg: i32) -> i32 {
        let mut m = [0u8; OOB_LEN];
        m[..4].copy_from_slice(&message.to_ne_bytes());
        m[4..8].copy_from_slice(&arg.to_ne_bytes());
        self.send_packet(TYPE_OOB, &m)
    }
}

#[derive(Default)]
struct QueueState {
    data: VecDeque<u8>,
    eof: bool,
    /// Bytes ever appended and taken out (for `bufq_wait_for_empty`).
    appended: u64,
    taken: u64,
}

/// A C `buf_queue_t` used as a pipe between threads, with the blocking
/// calls of `buf_queue.c`.
#[derive(Default)]
pub(crate) struct Queue {
    st: Mutex<QueueState>,
    cv: Condvar,
}

impl Queue {
    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, g: MutexGuard<'a, QueueState>) -> MutexGuard<'a, QueueState> {
        self.cv.wait(g).unwrap_or_else(PoisonError::into_inner)
    }

    /// C `bufq_append_data`.
    pub(crate) fn append(&self, data: &[u8]) {
        let mut st = self.lock();
        st.data.extend(data);
        st.appended += data.len() as u64;
        self.cv.notify_all();
    }

    /// C `bufq_close`: readers drain what is left (`read_sleepempty`
    /// stops at once).
    pub(crate) fn close(&self) {
        self.lock().eof = true;
        self.cv.notify_all();
    }

    /// C `bufq_len`.
    pub(crate) fn len(&self) -> usize {
        self.lock().data.len()
    }

    /// C `bufq_read_sleep`.
    pub(crate) fn read_sleep(&self, size: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(size);
        let mut st = self.lock();
        loop {
            let n = (size - out.len()).min(st.data.len());
            out.extend(st.data.drain(..n));
            st.taken += n as u64;
            if n > 0 {
                self.cv.notify_all();
            }
            if out.len() == size || st.eof {
                return out;
            }
            st = self.wait(st);
        }
    }

    /// C `bufq_consume_sleep`: like [`Queue::read_sleep`], discarding.
    pub(crate) fn consume_sleep(&self, size: usize) -> usize {
        let mut done = 0;
        let mut st = self.lock();
        loop {
            let n = (size - done).min(st.data.len());
            st.data.drain(..n);
            st.taken += n as u64;
            done += n;
            if n > 0 {
                self.cv.notify_all();
            }
            if done == size || st.eof {
                return done;
            }
            st = self.wait(st);
        }
    }

    /// C `bufq_splice_sleep(to, self, size)`.
    pub(crate) fn splice_sleep(&self, to: &Queue, size: usize) -> usize {
        let mut done = 0;
        while done < size {
            let chunk = {
                let mut st = self.lock();
                loop {
                    if !st.data.is_empty() || st.eof {
                        break;
                    }
                    st = self.wait(st);
                }
                let n = (size - done).min(st.data.len());
                st.taken += n as u64;
                let chunk: Vec<u8> = st.data.drain(..n).collect();
                if n > 0 {
                    self.cv.notify_all();
                }
                chunk
            };
            if chunk.is_empty() {
                break;
            }
            done += chunk.len();
            to.append(&chunk);
        }
        done
    }

    /// C `bufq_read_sleepempty`: waits for data, then returns up to `size`
    /// bytes; empty once the queue is closed, even if data is left.
    pub(crate) fn read_sleepempty(&self, size: usize) -> Vec<u8> {
        let mut st = self.lock();
        loop {
            if st.eof {
                return Vec::new();
            }
            if !st.data.is_empty() {
                let n = size.min(st.data.len());
                st.taken += n as u64;
                let out = st.data.drain(..n).collect();
                self.cv.notify_all();
                return out;
            }
            st = self.wait(st);
        }
    }

    /// C `bufq_wait_for_empty`: waits until every byte queued now has been
    /// taken out.
    pub(crate) fn wait_for_empty(&self) {
        let mut st = self.lock();
        let target = st.appended;
        while st.taken < target {
            st = self.wait(st);
        }
    }
}

/// C `callback_to_bufq`: the channel's data goes to the input queue,
/// unacknowledged while the queue holds more than [`QUEUE_MAX`] bytes;
/// the channel's shutdown closes the queue.
struct ToQueue(Arc<Queue>);

impl mux::ClientReader for ToQueue {
    fn read(&self, _channel: u32, data: Option<&[u8]>) -> i32 {
        match data {
            None => {
                self.0.close();
                0
            }
            Some(_) if self.0.len() > QUEUE_MAX => -1,
            Some(d) => {
                self.0.append(d);
                0
            }
        }
    }
}

/// Runs `f` on a new thread; the receiver yields its result.
fn spawn_ret<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> mpsc::Receiver<T> {
    let (tx, rx) = mpsc::channel();
    let _ = inet::spawn(move || {
        let _ = tx.send(f());
    });
    rx
}

/// One byte to a close pipe; C retries a failed write once.
fn poke(w: &UnixStream, byte: u8) {
    if (&*w).write(&[byte]).is_err() {
        let _ = (&*w).write(&[byte]);
    }
}

/// C `start_fds_thread` on the host: `stdin` is written from the
/// channel's data packets, `stdout` is read into data packets.
fn start_fds(c: Chan, stdin: Option<File>, stdout: Option<File>, stdout_lead: bool) {
    let c = Arc::new(c);
    if c.write_sync(REPLY_OK) < 0 {
        log::trace(
            format!(
                "start_fds_thread:344: unable to send reply, abort command: channel({})\n",
                c_int(c.num)
            )
            .as_bytes(),
        );
        return;
    }
    let input = Arc::new(Queue::default());
    let to_queue: Arc<dyn mux::ClientReader> = Arc::new(ToQueue(Arc::clone(&input)));
    let _ = c
        .dev
        .with(|m| m.set_reader(c.num, Some(Reader::Client(to_queue))));

    // stdout: a reader thread and a close pipe that the channel's
    // shutdown and the peer's stdout EOF write to. If `pipe` fails, C
    // leaves the stream unread (and its fd open).
    let mut stdout_pipe: Option<Arc<UnixStream>> = None;
    let mut close_cb = None;
    let mut stdout_done = None;
    if let Some(fd) = stdout {
        match UnixStream::pair() {
            Ok((pr, pw)) => {
                let pw = Arc::new(pw);
                let cb_pipe = Arc::clone(&pw);
                close_cb = c
                    .dev
                    .with(|m| m.set_close_callback(c.num, Box::new(move || poke(&cb_pipe, 0x04))))
                    .ok();
                stdout_pipe = Some(pw);
                let c2 = Arc::clone(&c);
                stdout_done = Some(spawn_ret(move || reader_worker(&c2, &fd, &pr)));
            }
            Err(_) => std::mem::forget(fd),
        }
    }
    // stdin: the packet thread feeds the writer through `out`.
    let stdin_done = stdin.map(|fd| {
        let out = Arc::new(Queue::default());
        let (c2, q) = (Arc::clone(&c), Arc::clone(&out));
        (out, spawn_ret(move || writer_worker(&c2, fd, &q)))
    });
    let packet_done = {
        let input = Arc::clone(&input);
        let out = stdin_done.as_ref().map(|(q, _)| Arc::clone(q));
        let pipe = stdout_pipe.clone();
        spawn_ret(move || packet_thread(&input, out.as_deref(), pipe.as_deref()))
    };

    let mut returncode = stdout_done.map_or(0, |rx| rx.recv().unwrap_or(0));
    // C closes both pipe ends here; the reader's end went with it.
    drop(stdout_pipe);
    if let Some(id) = close_cb {
        let _ = c.dev.with(|m| m.clear_close_callback(c.num, id));
    }
    if let Some((out, rx)) = stdin_done {
        if stdout_lead {
            out.close();
        }
        let rc = rx.recv().unwrap_or(0);
        if returncode == 0 {
            returncode = rc;
        }
    }
    let _ = c.send_oob(OOB_RETURN, returncode);
    let _ = c.dev.with(|m| m.close_channel(c.num));
    if packet_done.recv_timeout(PACKET_WAIT).is_err() {
        input.close();
        let _ = packet_done.recv();
    }
}

/// `fread(buf, 1, buf.len(), fp)` on a regular file: reads until the
/// buffer is full, at end of file (second value `true`, C `feof`) or on an
/// error (lost, as with `fread`).
fn fread(mut f: &File, buf: &mut [u8]) -> (usize, bool) {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => return (n, true),
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (n, false)
}

/// C `reader_worker_thread` for stdout: waits for data or the close pipe;
/// a regular file is read through stdio (`fread`), anything else with
/// `read`. Each read goes out as one data packet; end of input (or a read
/// error, whose errno is returned) sends the stdout EOF. A byte on the
/// close pipe or a failed send ends it without EOF.
fn reader_worker(c: &Chan, fd: &File, closepipe: &UnixStream) -> i32 {
    let regular = fd.metadata().is_ok_and(|m| m.is_file());
    let mut buf = vec![0u8; RWSIZE];
    let mut rcode = 0;
    loop {
        let Ok(ready) = sys::poll_readable(&[fd.as_raw_fd(), closepipe.as_raw_fd()]) else {
            continue;
        };
        if ready[1] {
            let _ = (&*closepipe).read(&mut buf);
            return rcode;
        }
        if !ready[0] {
            continue;
        }
        let (n, eof) = if regular {
            fread(fd, &mut buf)
        } else {
            match (&*fd).read(&mut buf) {
                Ok(n) => (n, false),
                Err(e) => {
                    rcode = e.raw_os_error().unwrap_or(0);
                    (0, false)
                }
            }
        };
        if n == 0 {
            break;
        }
        if c.send_packet(TYPE_DATA, &buf[..n]) < 0 {
            return rcode;
        }
        if eof {
            break;
        }
    }
    let _ = c.send_oob(OOB_EOF, STDOUT_FILENO);
    rcode
}

/// C `writer_worker_thread`: writes what the packet thread queues until
/// the queue is closed. A write error sends `strerror(errno)` as an error
/// packet and ends it with that errno. It always ends with the stdin EOF,
/// then closes the fd.
fn writer_worker(c: &Chan, fd: File, q: &Queue) -> i32 {
    let mut rcode = 0;
    'outer: loop {
        let data = q.read_sleepempty(RWSIZE);
        if data.is_empty() {
            break;
        }
        let mut pos = 0;
        while pos < data.len() {
            let errno = match (&fd).write(&data[pos..]) {
                Ok(k) if k > 0 => {
                    pos += k;
                    continue;
                }
                Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => {
                    continue;
                }
                Ok(_) => 0,
                Err(e) => e.raw_os_error().unwrap_or(0),
            };
            // snprintf(str, 64, "%s\n", strerror(errno)), sent with its NUL.
            let mut msg = sys::strerror(errno);
            msg.push(b'\n');
            msg.truncate(63);
            if c.send_packet(TYPE_ERR, &[&msg[..], b"\0"].concat()) < 0 {
                log::error(&[&b"Unable to send error message:("[..], &msg, b")\n"].concat());
            }
            rcode = errno;
            break 'outer;
        }
    }
    let _ = c.send_oob(OOB_EOF, STDIN_FILENO);
    drop(fd);
    rcode
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    mux::u32_at(b, at)
}

/// C `packet_thread`: parses the stream packets the peer sends on the
/// channel. Data goes to the writer (or is dropped without one); EOF for
/// stdin closes the writer's queue once it drained, EOF for stdout stops
/// the reader through its close pipe. Ends at the first short read or bad
/// header, closing the writer's queue.
fn packet_thread(input: &Queue, out: Option<&Queue>, stdout_pipe: Option<&UnixStream>) {
    let mut out_open = out;
    let mut stdout_open = stdout_pipe;
    loop {
        let h = input.read_sleep(PACKET_HEADER_LEN);
        if h.len() < PACKET_HEADER_LEN {
            break;
        }
        if u32_at(&h, 0) != PACKET_MAGIC {
            log::error(b"Bad packet header magic\n");
            break;
        }
        if u32_at(&h, 4) != PACKET_VERSION {
            log::error(b"Unsupported packet version\n");
            break;
        }
        let size = u32_at(&h, 8) as usize;
        match u32_at(&h, 12) {
            TYPE_DATA => {
                let n = match out_open {
                    Some(o) => {
                        if o.len() > QUEUE_MAX {
                            o.wait_for_empty();
                        }
                        input.splice_sleep(o, size)
                    }
                    None => input.consume_sleep(size),
                };
                if n < size {
                    break;
                }
            }
            TYPE_OOB => {
                let m = input.read_sleep(OOB_LEN);
                if m.len() < OOB_LEN {
                    break;
                }
                let arg = c_int(u32_at(&m, 4));
                match u32_at(&m, 0) {
                    OOB_EOF => match arg {
                        STDIN_FILENO => {
                            if let Some(o) = out_open.take() {
                                o.wait_for_empty();
                                o.close();
                            }
                        }
                        STDOUT_FILENO => {
                            if let Some(p) = stdout_open.take() {
                                poke(p, 0x01);
                            }
                        }
                        // No stderr stream on the host.
                        STDERR_FILENO => {}
                        _ => log::trace(
                            format!("packet_thread:206: tried to close unknown fileno {arg}\n")
                                .as_bytes(),
                        ),
                    },
                    // No child process on the host.
                    OOB_SIGNAL | OOB_RESIZE => {}
                    OOB_RETURN => log::trace(
                        b"packet_thread:243: Got a return code from the other side. no idea why.\n",
                    ),
                    other => log::trace(
                        format!(
                            "packet_thread:246: bad OOB message from other side {}\n",
                            c_int(other)
                        )
                        .as_bytes(),
                    ),
                }
                if size > OOB_LEN {
                    let rest = size - OOB_LEN;
                    if input.consume_sleep(rest) < rest {
                        break;
                    }
                }
            }
            kind => {
                if kind == TYPE_ERR {
                    log::trace(b"packet_thread:257: unexpected incoming stderr data");
                }
                if input.consume_sleep(size) < size {
                    break;
                }
            }
        }
    }
    if let Some(o) = out_open {
        o.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn queue_read_sleep_waits_for_all_or_close() {
        let q = Arc::new(Queue::default());
        q.append(b"ab");
        let q2 = Arc::clone(&q);
        let t = std::thread::spawn(move || q2.read_sleep(5));
        std::thread::sleep(ms(30));
        q.append(b"cdefg");
        assert_eq!(t.join().unwrap(), b"abcde");
        q.close();
        // After close: what is left, then nothing.
        assert_eq!(q.read_sleep(5), b"fg");
        assert_eq!(q.read_sleep(5), b"");
    }

    #[test]
    fn queue_read_sleepempty_returns_available_and_stops_at_close() {
        let q = Queue::default();
        q.append(b"xyz");
        assert_eq!(q.read_sleepempty(2), b"xy");
        assert_eq!(q.read_sleepempty(16), b"z");
        q.append(b"left");
        q.close();
        // C returns 0 at once on a closed queue, even with data left.
        assert_eq!(q.read_sleepempty(16), b"");
    }

    #[test]
    fn queue_consume_splice_and_wait_for_empty() {
        let (a, b) = (Arc::new(Queue::default()), Arc::new(Queue::default()));
        a.append(b"0123456789");
        assert_eq!(a.consume_sleep(3), 3);
        assert_eq!(a.splice_sleep(&b, 4), 4);
        assert_eq!(b.read_sleep(4), b"3456");
        a.close();
        assert_eq!(a.splice_sleep(&b, 10), 3);
        assert_eq!(a.consume_sleep(1), 0);
        // wait_for_empty returns once the bytes queued now are taken.
        b.append(b"later");
        let b2 = Arc::clone(&b);
        let t0 = Instant::now();
        let t = std::thread::spawn(move || {
            b2.wait_for_empty();
            t0.elapsed()
        });
        std::thread::sleep(ms(50));
        assert_eq!(b.read_sleep(8), b"789later");
        assert!(t.join().unwrap() >= ms(50));
        b.wait_for_empty();
    }

    #[test]
    fn to_queue_withholds_ack_above_queue_max() {
        let q = Arc::new(Queue::default());
        let r = ToQueue(Arc::clone(&q));
        let big = vec![7u8; QUEUE_MAX];
        assert_eq!(mux::ClientReader::read(&r, 5, Some(&big)), 0);
        assert_eq!(mux::ClientReader::read(&r, 5, Some(b"x")), 0);
        // Now above QUEUE_MAX: refused.
        assert_eq!(mux::ClientReader::read(&r, 5, Some(b"y")), -1);
        assert_eq!(q.len(), QUEUE_MAX + 1);
        assert_eq!(mux::ClientReader::read(&r, 5, None), 0);
        assert_eq!(q.read_sleepempty(1), b"");
    }

    fn stream(kind: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        for v in [PACKET_MAGIC, PACKET_VERSION, payload.len() as u32, kind] {
            p.extend_from_slice(&v.to_ne_bytes());
        }
        p.extend_from_slice(payload);
        p
    }

    fn oob(message: u32, arg: i32, extra: usize) -> Vec<u8> {
        let mut m = vec![0u8; OOB_LEN + extra];
        m[..4].copy_from_slice(&message.to_ne_bytes());
        m[4..8].copy_from_slice(&arg.to_ne_bytes());
        stream(TYPE_OOB, &m)
    }

    #[test]
    fn packet_thread_splices_data_and_handles_eof() {
        let (input, out) = (Queue::default(), Queue::default());
        let (pr, pw) = UnixStream::pair().unwrap();
        input.append(&stream(TYPE_DATA, b"hello "));
        input.append(&stream(TYPE_ERR, b"ignored"));
        input.append(&oob(OOB_RETURN, 3, 4));
        input.append(&stream(9, b"unknown"));
        input.append(&stream(TYPE_DATA, b"world"));
        input.append(&oob(OOB_EOF, STDOUT_FILENO, 0));
        input.append(&oob(OOB_EOF, STDOUT_FILENO, 0));
        // The stdin EOF waits until the writer took everything.
        let t = std::thread::scope(|s| {
            let h = s.spawn(|| {
                input.append(&oob(OOB_EOF, STDIN_FILENO, 0));
                input.close();
                packet_thread(&input, Some(&out), Some(&pw));
            });
            std::thread::sleep(ms(30));
            let got = out.read_sleep(11);
            h.join().unwrap();
            got
        });
        assert_eq!(t, b"hello world");
        assert_eq!(out.read_sleepempty(1), b"");
        // One poke for the first stdout EOF only.
        drop(pw);
        let mut pokes = Vec::new();
        (&pr).read_to_end(&mut pokes).unwrap();
        assert_eq!(pokes, [1]);
    }

    #[test]
    fn packet_thread_stops_at_bad_header_and_closes_output() {
        for bad in [
            [&0u32.to_ne_bytes()[..], &[0u8; 12]].concat(),
            stream(TYPE_DATA, b"")
                .iter()
                .enumerate()
                .map(|(i, &b)| if i == 4 { 2 } else { b })
                .collect(),
            stream(TYPE_DATA, b"abc")[..18].to_vec(),
        ] {
            let (input, out) = (Queue::default(), Queue::default());
            input.append(&bad);
            input.close();
            packet_thread(&input, Some(&out), None);
            assert_eq!(out.read_sleepempty(16), b"");
        }
    }
}
