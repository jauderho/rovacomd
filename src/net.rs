//! TCP helpers: emulation of C `create_listen_socket` (`socket.c`) and of
//! the daemon's "one `recv` with `SO_RCVLOWAT`" reads.

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};

/// C `NOVACOM_DEVLISTPORT`.
pub const DEVLISTPORT: u16 = 6968;
/// C `NOVACOM_INETPORT`.
pub const INETPORT: u16 = 6969;
/// C `NOVACOM_LOGPORT`.
pub const LOGPORT: u16 = 6970;
/// C `NOVACOM_CTRLPORT`.
pub const CTRLPORT: u16 = 6971;
/// C `NOVACOM_UNBLOCKPORT`.
pub const UNBLOCKPORT: u16 = 12311;
/// C `NOVACOM_OPTPORT`.
pub const OPTPORT: u16 = 64022;

/// C `create_listen_socket(port, bind_all)`: IPv4 TCP listener on
/// 127.0.0.1 (or 0.0.0.0 with `bind_all`), port 0 = ephemeral.
///
/// std sets `SO_REUSEADDR` before `bind` and close-on-exec, as C does. The
/// backlog is std's (128) instead of `SOMAXCONN`.
pub fn create_listen_socket(port: u16, bind_all: bool) -> io::Result<TcpListener> {
    let ip = if bind_all {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    TcpListener::bind(SocketAddrV4::new(ip, port))
}

/// C `recv(fd, buf, len, 0)` on a socket with `SO_RCVLOWAT >= len`: waits
/// until `buf` is full or the peer closes. Returns the byte count, or -1
/// if an error came before any data, like the C return value.
///
/// C relies on the low-water mark for a full read in one call; this loops
/// instead (same bytes, see ASSESSMENT P6).
pub fn read_full(mut s: &TcpStream, buf: &mut [u8]) -> isize {
    let mut n = 0;
    while n < buf.len() {
        match s.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) if n == 0 => return -1,
            Err(_) => break,
        }
    }
    n as isize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn listen_socket_binds_loopback_ephemeral() {
        let l = create_listen_socket(0, false).unwrap();
        let a = l.local_addr().unwrap();
        assert_eq!(a.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(a.port(), 0);
    }

    #[test]
    fn read_full_waits_for_all_or_eof() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        let t = std::thread::spawn(move || {
            c.write_all(b"abc").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
            c.write_all(b"defg").unwrap();
        });
        let mut buf = [0u8; 5];
        assert_eq!(read_full(&s, &mut buf), 5);
        assert_eq!(&buf, b"abcde");
        t.join().unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(read_full(&s, &mut buf), 2);
        assert_eq!(&buf[..2], b"fg");
    }
}
