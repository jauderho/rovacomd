//! Host command service: emulation of C `host/commands_service.c` and of
//! the service parts of `main.c` (`novacom_register_command`,
//! `novacom_process_cmdqueue`, `socketcmd_read_callback`,
//! `destroy_socketcmd`, `novacom_deviceinit_thread`).
//!
//! `login`, `logout`, `logint`, `add` and `remove dev://<path>` are queued
//! on the device whose id prefixes `<path>`, if it has a session id. The
//! head of the queue is sent on channel 0x50; the device's reply decides
//! the reply to the control client, which is then closed, and the next
//! command is sent. Only USB devices have a session id.

use std::collections::VecDeque;
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::cmdparse::{self, CommandUrl};
use crate::devices;
use crate::mux::{self, CHANNEL_CMDSERVICE, Mux};
use crate::tokens::{AUTHSESSION_LEN, TokenStore};
use crate::wirebuf::{Reader, Writer};

/// C `NOVACOMDMSG_REPLY_OK`, NUL included.
pub const REPLY_OK: &[u8] = b"ok 0\n\0";
/// C `NOVACOMDMSG_REPLY_ERR`, NUL included: the request was not sent.
pub const REPLY_ERR: &[u8] = b"err -1\n\0";
/// Reply when the device reports a failure (for any verb), NUL included.
pub const REPLY_FAILED: &[u8] = b"Novacom device login failed - incorrect password provided.\0";
/// Reply when a device command cannot be queued, NUL included.
pub const INVALID_COMMAND: &[u8] = b"invalid command\n\0";
/// C `char cmd[128]` of `novacom_register_command`.
pub const CMD_SIZE: usize = 128;

/// C `auth.h` message numbers.
const MSG_DISCONNECT: u8 = 1;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_TOKENREQUEST_ADD: u8 = 70;
const MSG_TOKENREQUEST_RM: u8 = 71;
const MSG_TOKEN_REPLY: u8 = 75;
/// C `buffer_new(100)` of every request.
const REQUEST_SIZE: usize = 100;

/// Control-port verbs (C `iohandlers`): `true` for device commands.
pub fn lookup_handler(verb: &[u8], scheme: &[u8]) -> Option<bool> {
    const HANDLERS: [(&[u8], &[u8], bool); 6] = [
        (b"list", b"host", false),
        (b"login", b"dev", true),
        (b"logout", b"dev", true),
        (b"logint", b"dev", true),
        (b"add", b"dev", true),
        (b"remove", b"dev", true),
    ];
    HANDLERS
        .iter()
        .find(|(v, s, _)| verb.eq_ignore_ascii_case(v) && scheme.eq_ignore_ascii_case(s))
        .map(|&(_, _, remote)| remote)
}

/// One queued command (C `socketcmd_t`). `socket` is `None` for the
/// automatic token login (C `INVALID_SOCKET`).
struct SocketCmd {
    socket: Option<TcpStream>,
    url: CommandUrl,
}

/// C `destroy_socketcmd` after one `send` of `reply` (errors ignored):
/// the client socket is closed.
fn finish(cmd: SocketCmd, reply: &[u8]) {
    if let Some(s) = &cmd.socket {
        let _ = (&*s).write(reply);
    }
}

/// The service state of a device with a session id (C `active_device`
/// fields `devid`, `sessionid` and `cmd_queue`).
pub struct Service {
    devid: Vec<u8>,
    sessionid: Vec<u8>,
    tokens: TokenStore,
    /// Invariant: the head, if any, has been sent and awaits its reply.
    queue: Mutex<VecDeque<SocketCmd>>,
}

impl Service {
    pub fn new(devid: &[u8], sessionid: &[u8], tokens: TokenStore) -> Self {
        Self {
            devid: devid.to_vec(),
            sessionid: sessionid.to_vec(),
            tokens,
            queue: Mutex::new(VecDeque::new()),
        }
    }

    pub fn sessionid(&self) -> &[u8] {
        &self.sessionid
    }

    /// Lock order: mux, then device list, then queue.
    fn lock(&self) -> MutexGuard<'_, VecDeque<SocketCmd>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// C `novacom_hostcmd_devlogin` / `devlogout` / `devlogint` / `devadd`
    /// / `devremove` up to the write: the request bytes, or `None` where C
    /// fails before writing (missing argument, request over 100 bytes,
    /// session id not 10 bytes long or no stored token for `remove`).
    fn request(&self, url: &CommandUrl) -> Option<Vec<u8>> {
        let verb = url.verb.to_ascii_lowercase();
        let arg0 = url.args.first();
        let mut b = Writer::new(REQUEST_SIZE);
        match verb.as_slice() {
            b"login" | b"logint" => {
                let hash = arg0?;
                let method: &[u8] = if verb == b"logint" {
                    b"token"
                } else {
                    b"password"
                };
                b.put_byte(MSG_USERAUTH_REQUEST).ok()?;
                b.put_byte(0).ok()?;
                b.put_string(method).ok()?;
                b.put_string(hash).ok()?;
            }
            b"logout" => {
                b.put_byte(MSG_DISCONNECT).ok()?;
                b.put_byte(0).ok()?;
            }
            b"add" => {
                let hash = arg0?;
                b.put_byte(MSG_TOKENREQUEST_ADD).ok()?;
                b.put_byte(0).ok()?;
                b.put_string(hash).ok()?;
            }
            b"remove" => {
                if self.sessionid.len() != AUTHSESSION_LEN {
                    return None;
                }
                let hash = arg0?;
                b.put_byte(MSG_TOKENREQUEST_RM).ok()?;
                b.put_byte(0).ok()?;
                b.put_string(hash).ok()?;
                // C takes the token file name from the device list
                // (`novacom_rnduid`), which holds this id.
                let token_hash = self.tokens.read_hash(&self.devid, &self.sessionid)?;
                b.put_string(&token_hash).ok()?;
            }
            _ => return None,
        }
        Some(b.into_bytes())
    }

    /// C `novacom_service_reply`: `true` for C 0. Token replies to `add`
    /// are stored; a successful `remove` deletes the token file. The reply
    /// is matched by its command byte, not by the queued verb.
    fn handle_reply(&self, buf: &[u8]) -> bool {
        let mut r = Reader::new(buf);
        let (Some(kind), Some(_version), Some(cmd)) = (r.get_byte(), r.get_byte(), r.get_byte())
        else {
            return false;
        };
        match cmd {
            MSG_DISCONNECT | MSG_USERAUTH_REQUEST => kind != MSG_USERAUTH_FAILURE,
            MSG_TOKENREQUEST_RM => {
                if kind == MSG_USERAUTH_SUCCESS {
                    let _ = self.tokens.remove(&self.devid);
                }
                kind != MSG_USERAUTH_FAILURE
            }
            MSG_TOKENREQUEST_ADD if kind == MSG_TOKEN_REPLY => match r.get_blob() {
                None => false,
                // C returns the blob length 0: success, nothing stored.
                Some([]) => true,
                Some(token) => self.tokens.store(&self.devid, token).is_ok(),
            },
            _ => false,
        }
    }

    /// C `novacom_process_cmdqueue`: sends the head; a command that cannot
    /// be sent gets `err -1` and the next one is tried.
    fn process_queue(&self, m: &mut Mux, q: &mut VecDeque<SocketCmd>) {
        while let Some(head) = q.front() {
            let sent = self
                .request(&head.url)
                .is_some_and(|r| m.write(CHANNEL_CMDSERVICE, &r, None).is_ok());
            if sent {
                return;
            }
            if let Some(cmd) = q.pop_front() {
                finish(cmd, REPLY_ERR);
            }
        }
    }

    /// The queueing part of C `novacom_register_command`: the command is
    /// appended; if the queue was empty it is processed at once.
    fn enqueue(&self, m: &mut Mux, socket: Option<TcpStream>, url: CommandUrl) {
        let mut q = self.lock();
        let first = q.is_empty();
        q.push_back(SocketCmd { socket, url });
        if first {
            self.process_queue(m, &mut q);
        }
    }

    /// The command-queue part of C `novacom_unregister_device`: commands
    /// not sent yet are dropped and their clients closed without a reply.
    /// The one awaiting its reply stays queued for good (with its client
    /// connection and the device, as the C device reference is never
    /// released). Returns `true` if there is such a command.
    pub fn drop_pending(&self) -> bool {
        let mut q = self.lock();
        q.truncate(1);
        !q.is_empty()
    }
}

impl mux::ServiceReader for Service {
    /// C `socketcmd_read_callback`: every packet on channel 0x50 is the
    /// reply to the head of the queue. The data is always accepted.
    fn read(&self, m: &mut Mux, _channel: u32, data: Option<&[u8]>) -> i32 {
        let Some(buf) = data else {
            return 0;
        };
        let mut q = self.lock();
        let Some(head) = q.pop_front() else {
            return 0;
        };
        let reply = if self.handle_reply(buf) {
            REPLY_OK
        } else {
            REPLY_FAILED
        };
        finish(head, reply);
        self.process_queue(m, &mut q);
        0
    }
}

/// C `novacom_register_command` after the command is read: `socket` is
/// the control client (`None` for the automatic token login), which is
/// closed unless the command is queued.
///
/// `list host://` sends the device list. A device command goes to the
/// first listed device if `<path>` is empty, else to the first whose id
/// case-insensitively prefixes `<path>` (D33); without such a device, or
/// if it has no session id, the client gets `invalid command`. Anything
/// else gets no reply.
pub fn register_command(socket: Option<TcpStream>, cmd: &[u8]) {
    let Some(url) = cmdparse::parse_command(cmd) else {
        return;
    };
    match lookup_handler(&url.verb, &url.scheme) {
        None => return,
        Some(false) => {
            if let Some(s) = &socket {
                devices::dump_device_list(s);
            }
            return;
        }
        Some(true) => {}
    }
    let found = devices::find_for_command(&url.path)
        .and_then(|d| d.service.clone().map(|svc| (Arc::clone(&d.mux), svc)));
    let Some((dev, svc)) = found else {
        if let Some(s) = &socket {
            let _ = (&*s).write(INVALID_COMMAND);
        }
        return;
    };
    dev.with(|m| svc.enqueue(m, socket, url));
}

/// C `novacom_deviceinit_thread`: opens channel 0x50 (waiting for the
/// device), installs the reply handler and, if a token is stored for the
/// device, queues `logint dev://<nduid> <hash>` without a client.
pub fn device_init(dev: &mux::Device, svc: Arc<Service>) {
    if dev.open_channel(CHANNEL_CMDSERVICE, true) < 0 {
        return;
    }
    let reader: Arc<dyn mux::ServiceReader> = svc.clone();
    if dev
        .with(|m| m.set_reader(CHANNEL_CMDSERVICE, Some(mux::Reader::Service(reader))))
        .is_err()
    {
        return;
    }
    let Some(hash) = svc.tokens.read_hash(&svc.devid, &svc.sessionid) else {
        return;
    };
    let mut cmd = [&b"logint dev://"[..], &svc.devid, b" ", &hash].concat();
    cmd.truncate(CMD_SIZE - 1);
    register_command(None, &cmd);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::{FLAG_ACK, HEADER_LEN, Header, PMUX_MAGIC, PMUX_VERSION, adler};
    use crate::tokens::sha1_hex;
    use crate::tokens::tests::TempHome;
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    const DEVID: &[u8] = b"0123456789abcdef0123456789abcdef01234567";
    const SID: &[u8] = b"sess012345";

    /// A device-side packet on channel 0x50.
    fn pkt(flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let h = Header {
            magic: PMUX_MAGIC,
            version: PMUX_VERSION,
            flags,
            channel: CHANNEL_CMDSERVICE,
            sequence,
            payload_len: len,
            total_len: len + HEADER_LEN as u32,
            crc: adler(payload),
        };
        [&h.encode()[..], payload].concat()
    }

    /// A mux with an open channel 0x50 served by a [`Service`]; plays the
    /// device.
    struct Rig {
        home: TempHome,
        svc: Arc<Service>,
        mux: Mux,
        rx_seq: u32,
    }

    impl Rig {
        fn new(sessionid: &[u8]) -> Self {
            let home = TempHome::create();
            let svc = Arc::new(Service::new(DEVID, sessionid, home.store()));
            let mut mux = Mux::new();
            assert!(mux.create_channel(CHANNEL_CMDSERVICE, false, false));
            let reader: Arc<dyn mux::ServiceReader> = svc.clone();
            mux.set_reader(CHANNEL_CMDSERVICE, Some(mux::Reader::Service(reader)))
                .unwrap();
            Self {
                home,
                svc,
                mux,
                rx_seq: 0,
            }
        }

        /// A control client: our end, and the daemon's end.
        fn client() -> (TcpStream, TcpStream) {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
            let (s, _) = l.accept().unwrap();
            (c, s)
        }

        /// Queues `cmd` from a new client; returns the client's end.
        fn command(&mut self, cmd: &str) -> TcpStream {
            let (c, s) = Self::client();
            let url = cmdparse::parse_command(cmd.as_bytes()).unwrap();
            self.svc.enqueue(&mut self.mux, Some(s), url);
            c
        }

        /// The requests sent on channel 0x50 since the last call; each is
        /// acknowledged.
        fn sent(&mut self) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            while let Some(p) = self.mux.prepare_tx_packet(Instant::now(), 4096) {
                let h = Header::decode(&p);
                if h.flags & FLAG_ACK != 0 {
                    continue;
                }
                assert_eq!(h.channel, CHANNEL_CMDSERVICE);
                out.push(p[HEADER_LEN..].to_vec());
                let ack = pkt(FLAG_ACK, h.sequence, b"");
                self.mux.process_packet(&ack, ack.len());
            }
            out
        }

        /// The device replies.
        fn reply(&mut self, data: &[u8]) {
            self.rx_seq += 1;
            let p = pkt(0, self.rx_seq, data);
            self.mux.process_packet(&p, p.len());
        }

        fn token(&self) -> Option<Vec<u8>> {
            std::fs::read(self.home.nova().join(std::str::from_utf8(DEVID).unwrap())).ok()
        }
    }

    /// Everything the daemon sent to a client, and whether it closed.
    fn received(c: &mut TcpStream) -> (Vec<u8>, bool) {
        c.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match c.read(&mut buf) {
                Ok(0) => return (got, true),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(_) => return (got, false),
            }
        }
    }

    fn s(len: u32, b: &[u8]) -> Vec<u8> {
        [&len.to_be_bytes()[..], b].concat()
    }

    #[test]
    fn request_bytes_per_verb() {
        let mut r = Rig::new(SID);
        let mut token = vec![0x5au8; 256];
        token.extend_from_slice(b"ignored");
        r.svc.tokens.store(DEVID, &token).unwrap();
        let token_hash = sha1_hex(&[&token[..256], SID].concat());
        let cases: [(&str, Vec<u8>); 5] = [
            (
                "login dev://x h1",
                [&[50, 0][..], &s(8, b"password"), &s(2, b"h1")].concat(),
            ),
            (
                "LOGINT dev://x h2 extra",
                [&[50, 0][..], &s(5, b"token"), &s(2, b"h2")].concat(),
            ),
            ("logout dev://x ignored", vec![1, 0]),
            ("add dev://x pw", [&[70, 0][..], &s(2, b"pw")].concat()),
            (
                "remove dev://x pw",
                [&[71, 0][..], &s(2, b"pw"), &s(40, &token_hash)].concat(),
            ),
        ];
        for (cmd, want) in cases {
            let mut c = r.command(cmd);
            assert_eq!(r.sent(), vec![want], "{cmd}");
            r.reply(&[52, 0, 50]);
            assert_eq!(received(&mut c), (REPLY_OK.to_vec(), true), "{cmd}");
        }
    }

    #[test]
    fn request_errors_reply_err() {
        let mut r = Rig::new(SID);
        let long = |n: usize| "h".repeat(n);
        // The longest arguments that fit in 100 bytes.
        for (verb, max) in [("login", 82), ("logint", 85), ("add", 94)] {
            let mut c = r.command(&format!("{verb} dev://x {}", long(max)));
            assert_eq!(r.sent().len(), 1, "{verb}");
            r.reply(&[52, 0, 50]);
            assert_eq!(received(&mut c).0, REPLY_OK, "{verb}");
            let mut c = r.command(&format!("{verb} dev://x {}", long(max + 1)));
            assert!(r.sent().is_empty(), "{verb}");
            assert_eq!(received(&mut c), (REPLY_ERR.to_vec(), true), "{verb}");
            let mut c = r.command(&format!("{verb} dev://x"));
            assert!(r.sent().is_empty(), "{verb}");
            assert_eq!(received(&mut c), (REPLY_ERR.to_vec(), true), "{verb}");
        }
        // remove: missing argument, no token (the directory is created).
        assert!(!r.home.nova().exists());
        let mut c = r.command("remove dev://x");
        assert_eq!(received(&mut c), (REPLY_ERR.to_vec(), true));
        assert!(!r.home.nova().exists());
        let mut c = r.command("remove dev://x pw");
        assert_eq!(received(&mut c), (REPLY_ERR.to_vec(), true));
        assert!(r.home.nova().is_dir());
        // remove: 50 bytes of argument fit with the token hash, 51 do not.
        r.svc.tokens.store(DEVID, &[1u8; 256]).unwrap();
        let mut c = r.command(&format!("remove dev://x {}", long(50)));
        assert_eq!(r.sent().len(), 1);
        r.reply(&[51, 0, 71]);
        assert_eq!(received(&mut c).0, REPLY_FAILED);
        let mut c = r.command(&format!("remove dev://x {}", long(51)));
        assert_eq!(received(&mut c), (REPLY_ERR.to_vec(), true));
        assert!(r.sent().is_empty());
    }

    #[test]
    fn remove_needs_a_ten_byte_session_id() {
        for sid in [&b"sess01234"[..], b"sess0123456"] {
            let mut r = Rig::new(sid);
            r.svc.tokens.store(DEVID, &[1u8; 256]).unwrap();
            let mut c = r.command("remove dev://x pw");
            assert_eq!(received(&mut c), (REPLY_ERR.to_vec(), true));
            assert!(r.sent().is_empty());
            // Other verbs do not check it.
            let mut c = r.command("logout dev://x");
            assert_eq!(r.sent().len(), 1);
            r.reply(&[52, 0, 1]);
            assert_eq!(received(&mut c).0, REPLY_OK);
        }
    }

    #[test]
    fn reply_types() {
        let blob = |t: &[u8]| s(t.len() as u32, t);
        // (reply, success, token file afterwards)
        let cases: Vec<(Vec<u8>, bool, Option<Vec<u8>>)> = vec![
            (vec![51, 0, 50], false, None),
            (vec![52, 0, 50], true, None),
            (vec![75, 9, 50, 1], true, None),
            (vec![51, 0, 1], false, None),
            (vec![0, 0, 1], true, None),
            (vec![52, 0], false, None),
            (vec![], false, None),
            (vec![52, 0, 99], false, None),
            (vec![52, 0, 70], false, None),
            (vec![51, 0, 70], false, None),
            (
                [&[75, 0, 70][..], &blob(b"tok")].concat(),
                true,
                Some(b"tok".to_vec()),
            ),
            ([&[75, 0, 70][..], &blob(b"")].concat(), true, None),
            (vec![75, 0, 70, 0, 0, 0], false, None),
            (vec![75, 0, 70, 0, 0, 0, 4, 1, 2, 3], false, None),
            (
                [&[75, 0, 70][..], &blob(b"t"), b"trailing"].concat(),
                true,
                Some(b"t".to_vec()),
            ),
        ];
        for (reply, ok, file) in cases {
            let mut r = Rig::new(SID);
            let mut c = r.command("logout dev://x");
            assert_eq!(r.sent().len(), 1);
            r.reply(&reply);
            let want = if ok { REPLY_OK } else { REPLY_FAILED };
            assert_eq!(received(&mut c), (want.to_vec(), true), "{reply:?}");
            assert_eq!(r.token(), file, "{reply:?}");
        }
    }

    #[test]
    fn remove_reply_deletes_the_token_only_on_success() {
        for (kind, ok, kept) in [(52u8, true, false), (51, false, true), (75, true, true)] {
            let mut r = Rig::new(SID);
            r.svc.tokens.store(DEVID, b"old").unwrap();
            let mut c = r.command("logout dev://x");
            r.sent();
            r.reply(&[kind, 0, 71]);
            let want = if ok { REPLY_OK } else { REPLY_FAILED };
            assert_eq!(received(&mut c).0, want);
            assert_eq!(r.token().is_some(), kept, "{kind}");
        }
    }

    #[test]
    fn queue_order_and_unsolicited_replies() {
        let mut r = Rig::new(SID);
        // A reply with nothing queued is ignored.
        r.reply(&[52, 0, 50]);
        let mut a = r.command("login dev://x a");
        let mut b = r.command("add dev://x");
        let mut c = r.command("logout dev://x");
        // Only the head is sent.
        assert_eq!(r.sent().len(), 1);
        assert_eq!(received(&mut b), (Vec::new(), false));
        r.reply(&[51, 0, 50]);
        assert_eq!(received(&mut a), (REPLY_FAILED.to_vec(), true));
        // `add` without argument fails at once; `logout` is sent.
        assert_eq!(received(&mut b), (REPLY_ERR.to_vec(), true));
        assert_eq!(r.sent(), vec![vec![1, 0]]);
        assert_eq!(received(&mut c), (Vec::new(), false));
        r.reply(&[52, 0, 1]);
        assert_eq!(received(&mut c), (REPLY_OK.to_vec(), true));
        assert!(r.svc.lock().is_empty());
    }

    #[test]
    fn closed_channel_replies_err() {
        let mut r = Rig::new(SID);
        r.mux.go_offline();
        let mut c = r.command("logout dev://x");
        assert_eq!(received(&mut c), (REPLY_ERR.to_vec(), true));
    }

    #[test]
    fn drop_pending_keeps_the_head() {
        let mut r = Rig::new(SID);
        assert!(!r.svc.drop_pending());
        let mut a = r.command("logout dev://x");
        let mut b = r.command("logout dev://x");
        assert!(r.svc.drop_pending());
        assert_eq!(received(&mut b), (Vec::new(), true));
        assert_eq!(received(&mut a), (Vec::new(), false));
    }

    #[test]
    fn handler_table_is_case_insensitive() {
        assert_eq!(lookup_handler(b"LIST", b"Host"), Some(false));
        assert_eq!(lookup_handler(b"login", b"DEV"), Some(true));
        assert_eq!(lookup_handler(b"logint", b"dev"), Some(true));
        assert_eq!(lookup_handler(b"Remove", b"dev"), Some(true));
        assert_eq!(lookup_handler(b"list", b"dev"), None);
        assert_eq!(lookup_handler(b"run", b"file"), None);
    }
}
