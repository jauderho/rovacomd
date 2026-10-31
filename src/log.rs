//! Logging: emulation of C `log_printf` and `log_add_socket` (`log.c`)
//! with the timestamp of `platform_get_time_string`.
//!
//! Sinks and masks as in C: console `ALWAYS|ERROR` (`ERROR` to stderr,
//! the rest to stdout), syslog `ALWAYS|ERROR|TRACE` (Linux only, without
//! the timestamp), log socket (port 6970) everything.
//!
//! C writes the console with stdio: stdout is line-buffered on a terminal
//! and fully buffered otherwise (so output is lost when the daemon is
//! killed by a signal), stderr is unbuffered. [`exit`] flushes stdout like
//! C `exit()`.

use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::sys::{self, LocalTime, STDERR_FD, STDOUT_FD};

pub const LOG_ALWAYS: u32 = 1 << 0;
pub const LOG_ERROR: u32 = 1 << 1;
pub const LOG_TRACE: u32 = 1 << 2;
pub const LOG_SPEW: u32 = 1 << 3;
pub const LOG_LLTRACE: u32 = 1 << 4;
pub const LOG_MUXTRACE: u32 = 1 << 5;

const CONSOLE_MASK: u32 = LOG_ALWAYS | LOG_ERROR;
#[cfg(target_os = "linux")]
const SYSLOG_MASK: u32 = LOG_ALWAYS | LOG_ERROR | LOG_TRACE;
const SOCKET_MASK: u32 = LOG_ALWAYS | LOG_ERROR | LOG_TRACE | LOG_SPEW | LOG_MUXTRACE | LOG_LLTRACE;

/// Size of the C `msg[256]` buffer.
const MSG_SIZE: usize = 256;

/// Buffer size at which a fully buffered stdout is written out. C flushes
/// when its buffer (`st_blksize` bytes) fills; the exact chunk boundaries
/// are not emulated.
const FULL_BUFFER_LIMIT: usize = 4096;

/// C `stdout`: bytes are held until a newline (line-buffered) or until
/// [`StdioOut::flush`] or the buffer limit (fully buffered). Write errors
/// are ignored, as C ignores `fprintf` errors.
struct StdioOut {
    buf: Vec<u8>,
    line_buffered: bool,
}

impl StdioOut {
    fn write(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        if self.line_buffered {
            if let Some(last_nl) = self.buf.iter().rposition(|&b| b == b'\n') {
                self.write_out(last_nl + 1);
            }
        } else if self.buf.len() >= FULL_BUFFER_LIMIT {
            self.write_out(self.buf.len());
        }
    }

    fn flush(&mut self) {
        self.write_out(self.buf.len());
    }

    /// Writes out the first `n` buffered bytes; they are dropped even if
    /// the write fails.
    fn write_out(&mut self, n: usize) {
        write_all_fd(STDOUT_FD, &self.buf[..n]);
        self.buf.drain(..n);
    }
}

/// Writes all of `data` to `fd`, stopping at the first error.
fn write_all_fd(fd: i32, mut data: &[u8]) {
    while !data.is_empty() {
        match sys::write_fd(fd, data) {
            Ok(n) if n > 0 => data = &data[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            _ => break,
        }
    }
}

struct State {
    stdout: Option<StdioOut>,
    /// C `log_socket` (log.c): the latest client of port 6970.
    socket: Option<TcpStream>,
}

static STATE: Mutex<State> = Mutex::new(State {
    stdout: None,
    socket: None,
});

fn lock() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    /// C stdio decides the buffering mode on the first output.
    fn stdout(&mut self) -> &mut StdioOut {
        self.stdout.get_or_insert_with(|| StdioOut {
            buf: Vec::new(),
            line_buffered: sys::isatty(STDOUT_FD),
        })
    }
}

/// `"[%d/%d/%d %d:%02d:%02d] "` (`platform_get_time_string`).
pub fn timestamp(t: &LocalTime) -> Vec<u8> {
    format!(
        "[{}/{}/{} {}:{:02}:{:02}] ",
        t.year, t.mon, t.mday, t.hour, t.min, t.sec
    )
    .into_bytes()
}

/// The C `msg` buffer: timestamp, then the message cut so that the whole
/// fits `vsnprintf(msg + ts, 256 - ts - 2, ...)`.
pub fn format_message(ts: &[u8], body: &[u8]) -> Vec<u8> {
    let room = (MSG_SIZE - 3).saturating_sub(ts.len());
    [ts, &body[..body.len().min(room)]].concat()
}

/// C `log_printf(mask, "%s", body)`.
///
/// Intentional change (D12): the log socket gets the truncated message;
/// C sends the untruncated length and reads past its buffer.
pub fn log(mask: u32, body: &[u8]) {
    let ts = timestamp(&sys::local_time_now());
    let msg = format_message(&ts, body);
    let mut st = lock();
    if mask & CONSOLE_MASK != 0 {
        if mask & LOG_ERROR != 0 {
            write_all_fd(STDERR_FD, &msg);
        } else {
            st.stdout().write(&msg);
        }
    }
    #[cfg(target_os = "linux")]
    if mask & SYSLOG_MASK != 0 {
        sys::syslog_alert(&msg[ts.len()..]);
    }
    if mask & SOCKET_MASK != 0 {
        if let Some(s) = st.socket.as_ref() {
            // One non-blocking send (`MSG_DONTWAIT`); a partial send is
            // ignored, an error other than EAGAIN drops the client.
            if let Err(e) = (&*s).write(&msg) {
                if e.kind() != io::ErrorKind::WouldBlock {
                    let _ = s.shutdown(Shutdown::Both);
                    st.socket = None;
                }
            }
        }
    }
}

/// `TRACEL(LOG_ALWAYS, ...)`.
pub fn always(body: &[u8]) {
    log(LOG_ALWAYS, body);
}

/// `TRACEL(LOG_ERROR, ...)`.
pub fn error(body: &[u8]) {
    log(LOG_ERROR, body);
}

/// `TRACEL(LOG_TRACE, ...)` / `TRACEF`.
pub fn trace(body: &[u8]) {
    log(LOG_TRACE, body);
}

/// C `log_add_socket`: the new client replaces (and closes) the previous.
pub fn add_socket(s: TcpStream) {
    // C sends with MSG_DONTWAIT; a non-blocking socket gives the same.
    let _ = s.set_nonblocking(true);
    let mut st = lock();
    if let Some(old) = st.socket.replace(s) {
        let _ = old.shutdown(Shutdown::Both);
    }
}

/// Runs `f` with the logger locked (used around `fork`).
pub fn with_locked<T>(f: impl FnOnce() -> T) -> T {
    let _st = lock();
    f()
}

/// C `exit(code)`: flushes stdout, then exits.
pub fn exit(code: i32) -> ! {
    if let Some(out) = lock().stdout.as_mut() {
        out.flush();
    }
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_format() {
        let t = LocalTime {
            year: 2026,
            mon: 3,
            mday: 4,
            hour: 5,
            min: 6,
            sec: 7,
        };
        assert_eq!(timestamp(&t), b"[2026/3/4 5:06:07] ");
        let t = LocalTime {
            year: 2026,
            mon: 12,
            mday: 31,
            hour: 23,
            min: 59,
            sec: 60,
        };
        assert_eq!(timestamp(&t), b"[2026/12/31 23:59:60] ");
    }

    #[test]
    fn message_truncated_to_c_buffer() {
        let ts = b"[2026/3/4 5:06:07] ";
        assert_eq!(format_message(ts, b"hi\n"), b"[2026/3/4 5:06:07] hi\n");
        let long = vec![b'x'; 400];
        let m = format_message(ts, &long);
        assert_eq!(m.len(), 253);
        assert!(m.starts_with(ts));
        assert_eq!(m[ts.len()..], long[..253 - ts.len()]);
        let exact = vec![b'y'; 253 - ts.len()];
        assert_eq!(format_message(ts, &exact).len(), 253);
    }
}
