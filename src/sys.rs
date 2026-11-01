//! Unix calls the C daemon makes that std does not expose: `time` /
//! `localtime_r`, `srand` / `rand`, `isatty`, raw `write` on the standard
//! fds, `poll` (in place of `select`), the `-d` steps (`fork`, `umask`,
//! `setsid`, closing fds 0-2), `getpwuid_r`, `getaddrinfo`, `TCP_QUICKACK`
//! and syslog.
//!
//! This is the only module with `unsafe` code.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;

pub const STDIN_FD: RawFd = 0;
pub const STDOUT_FD: RawFd = 1;
pub const STDERR_FD: RawFd = 2;

/// Fields of `struct tm` that the C timestamp prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime {
    pub year: i32,
    pub mon: i32,
    pub mday: i32,
    pub hour: i32,
    pub min: i32,
    pub sec: i32,
}

/// C `localtime_r(time(NULL))` (`platform_get_time_string`).
///
/// Intentional change: if `localtime_r` fails, C prints an uninitialized
/// `struct tm`; here the fields are zero.
pub fn local_time_now() -> LocalTime {
    // SAFETY: `time` with a null pointer only returns the current time.
    let t = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: an all-zero `struct tm` is a valid value (integers and a
    // null `tm_zone` pointer on the platforms that have one).
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `t` and `tm` are live locals; `localtime_r` writes only `tm`.
    unsafe { libc::localtime_r(&t, &mut tm) };
    LocalTime {
        year: tm.tm_year + 1900,
        mon: tm.tm_mon + 1,
        mday: tm.tm_mday,
        hour: tm.tm_hour,
        min: tm.tm_min,
        sec: tm.tm_sec,
    }
}

/// C `srand(time(NULL))` (`platform_init`).
pub fn seed_rand_with_time() {
    // SAFETY: `time` with a null pointer only returns the current time;
    // `srand` sets the libc generator state.
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        libc::srand(t as libc::c_uint);
    }
}

/// C `rand()`.
pub fn rand() -> i32 {
    // SAFETY: `rand` has no preconditions.
    unsafe { libc::rand() }
}

/// C `isatty(fd)`.
pub fn isatty(fd: RawFd) -> bool {
    // SAFETY: `isatty` accepts any integer and only queries it.
    unsafe { libc::isatty(fd) == 1 }
}

/// One C `write(fd, buf, len)`.
pub fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid for reads of `buf.len()` bytes; an invalid or
    // closed `fd` only makes the call fail.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

/// Waits without timeout until one of `fds` is readable (or at EOF or in
/// error, which `select` also reports as readable). Returns one flag per fd.
pub fn poll_readable(fds: &[RawFd]) -> io::Result<Vec<bool>> {
    let mut pfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // SAFETY: `pfds` is a live array of `pfds.len()` initialized `pollfd`s.
    let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pfds.iter().map(|p| p.revents != 0).collect())
}

/// Result of [`fork`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forked {
    Parent,
    Child,
}

/// C `fork()`.
///
/// The caller holds the logger lock across the call, so no other thread
/// (a `-c` connect thread) holds it in the child.
pub fn fork() -> io::Result<Forked> {
    // SAFETY: the child continues with a copy of the calling thread only.
    // Allocator locks are reset by the libc fork handlers (glibc, macOS
    // libmalloc); the only lock this crate's threads take around output is
    // held by the caller (see above). The C daemon forks at the same point.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Forked::Child),
        _ => Ok(Forked::Parent),
    }
}

/// C `umask(0)`.
pub fn clear_umask() {
    // SAFETY: `umask` only changes the process file mode mask.
    unsafe { libc::umask(0) };
}

/// C `setsid()`.
pub fn setsid() -> io::Result<()> {
    // SAFETY: `setsid` has no memory-safety preconditions.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// C `close(0); close(1); close(2);` (the fds are not reopened).
pub fn close_std_fds() {
    for fd in [STDIN_FD, STDOUT_FD, STDERR_FD] {
        // SAFETY: fds 0-2 are not owned by any Rust object in this crate
        // (console output uses raw `write` on the numbers).
        unsafe { libc::close(fd) };
    }
}

/// C `getpwuid(getuid())->pw_dir` (`tokenstorage_path`), through the
/// reentrant `getpwuid_r`. `None` if there is no entry or no home
/// directory.
pub fn home_dir() -> Option<Vec<u8>> {
    let mut size = 1024;
    loop {
        let mut buf: Vec<libc::c_char> = vec![0; size];
        // SAFETY: an all-zero `struct passwd` is a valid value (integers
        // and null pointers).
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pw`, `buf` (of `buf.len()` bytes) and `found` are live
        // locals; `getpwuid_r` writes only into them.
        let rc = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut pw,
                buf.as_mut_ptr(),
                buf.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE && size < 1 << 20 {
            size *= 2;
            continue;
        }
        if rc != 0 || found.is_null() || pw.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success `pw_dir` points to a NUL-terminated string
        // inside `buf`, which is still alive.
        return Some(
            unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) }
                .to_bytes()
                .to_vec(),
        );
    }
}

/// C `getaddrinfo(host, serv, {AI_ALL|AI_ADDRCONFIG, SOCK_STREAM})` and
/// the first result (`inetconnect_findandattach_thread`). `None` on error,
/// on a non-IP first result, or if `host`/`serv` contain a NUL byte.
pub fn resolve_first(host: &[u8], serv: &[u8]) -> Option<SocketAddr> {
    let host = std::ffi::CString::new(host).ok()?;
    let serv = std::ffi::CString::new(serv).ok()?;
    // SAFETY: an all-zero `addrinfo` is a valid value (integers and null
    // pointers).
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = libc::AI_ALL | libc::AI_ADDRCONFIG;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: `host` and `serv` are NUL-terminated; `hints` and `res` are
    // live locals; on success `res` owns a list freed below.
    let r = unsafe { libc::getaddrinfo(host.as_ptr(), serv.as_ptr(), &hints, &mut res) };
    if r != 0 || res.is_null() {
        return None;
    }
    // SAFETY: `res` is the non-null head of the list from `getaddrinfo`;
    // `ai_addr` points to a socket address of `ai_family`, whose size the
    // family determines.
    let addr = unsafe {
        let ai = &*res;
        match ai.ai_family {
            libc::AF_INET if !ai.ai_addr.is_null() => {
                let sin = &*ai.ai_addr.cast::<libc::sockaddr_in>();
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 if !ai.ai_addr.is_null() => {
                let sin6 = &*ai.ai_addr.cast::<libc::sockaddr_in6>();
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    };
    // SAFETY: `res` came from a successful `getaddrinfo` and is freed once.
    unsafe { libc::freeaddrinfo(res) };
    addr
}

/// C `setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &1)`; errors ignored.
#[cfg(target_os = "linux")]
pub fn tcp_quickack(sock: &std::net::TcpStream) {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    // SAFETY: `sock` owns a valid fd; `on` is a live `c_int` and the length
    // passed is its size.
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            (&raw const on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// C `openlog(ident, 0, LOG_LOCAL7)`.
#[cfg(target_os = "linux")]
pub fn openlog(ident: &'static std::ffi::CStr) {
    // SAFETY: `ident` is NUL-terminated and lives for the rest of the
    // process, as `openlog` requires (it keeps the pointer).
    unsafe { libc::openlog(ident.as_ptr(), 0, libc::LOG_LOCAL7) };
}

/// C `syslog(1 /* LOG_ALWAYS = LOG_ALERT */, "%s", msg)`. A message with
/// a NUL byte is cut there, as the C `%s` would.
#[cfg(target_os = "linux")]
pub fn syslog_alert(msg: &[u8]) {
    let end = msg.iter().position(|&b| b == 0).unwrap_or(msg.len());
    let Ok(msg) = std::ffi::CString::new(&msg[..end]) else {
        return;
    };
    // SAFETY: the format and `msg` are NUL-terminated strings; the format
    // consumes exactly one string argument.
    unsafe { libc::syslog(libc::LOG_ALERT, c"%s".as_ptr(), msg.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_time_fields_are_in_range() {
        let t = local_time_now();
        assert!(t.year >= 2024);
        assert!((1..=12).contains(&t.mon));
        assert!((1..=31).contains(&t.mday));
        assert!((0..=23).contains(&t.hour));
        assert!((0..=59).contains(&t.min));
        assert!((0..=60).contains(&t.sec));
    }

    #[test]
    fn resolves_numeric_hosts() {
        assert_eq!(
            resolve_first(b"127.0.0.1", b"6969"),
            Some("127.0.0.1:6969".parse().unwrap())
        );
        assert_eq!(resolve_first(b"127.0.0.1", b"nosuchservice"), None);
        assert_eq!(resolve_first(b"127.0.0.1", b"69\x0069"), None);
    }

    #[test]
    fn home_dir_is_absolute() {
        // Read-only lookup; nothing below the directory is touched.
        let home = home_dir().unwrap();
        assert!(home.starts_with(b"/"), "{home:?}");
    }

    #[test]
    fn poll_reports_readable_listener() {
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        assert_eq!(poll_readable(&[l.as_raw_fd()]).unwrap(), vec![true]);
    }
}
