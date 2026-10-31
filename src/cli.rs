//! Command-line parsing: emulation of C `getnextopt` (`getopt_long` with
//! optstring `"ht:c:e:s:bdCV"`), `usage` and `atol`.
//!
//! The getopt engine is the one of the rovacom client port with this
//! daemon's option tables. The only OS difference is the libc
//! `getopt_long` implementation: glibc ([`Flavor::Gnu`]) on Linux,
//! FreeBSD-derived ([`Flavor::Bsd`]) on macOS.

/// Short option string passed to `getopt_long` by the C daemon (non-W32).
const OPTSTRING: &[u8] = b"ht:c:e:s:bdCV";

/// One entry of the C `longopts` table.
struct LongOpt {
    name: &'static [u8],
    has_arg: bool,
    val: u8,
}

/// The C `longopts` table, in table order (order matters for
/// abbreviation matching and the glibc ambiguity list).
const LONG_OPTIONS: [LongOpt; 4] = [
    LongOpt {
        name: b"connect-ip",
        has_arg: true,
        val: b'c',
    },
    LongOpt {
        name: b"bind-all-interfaces",
        has_arg: false,
        val: b'b',
    },
    LongOpt {
        name: b"daemonize",
        has_arg: false,
        val: b'd',
    },
    LongOpt {
        name: b"version",
        has_arg: false,
        val: b'V',
    },
];

/// Version string (C `BUILDVERSION`): `BUILDVERSION` at compile time, else
/// `rovacomd-<pkg version>`.
pub const VERSION: &str = match option_env!("BUILDVERSION") {
    Some(v) => v,
    None => concat!("rovacomd-", env!("CARGO_PKG_VERSION")),
};

/// Which libc `getopt_long` implementation to emulate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    /// glibc (Linux).
    Gnu,
    /// FreeBSD-derived libc with `GNU_COMPATIBLE` (macOS).
    Bsd,
}

/// The flavor of the libc this binary would have been linked against.
#[cfg(target_os = "macos")]
pub const FLAVOR: Flavor = Flavor::Bsd;
/// The flavor of the libc this binary would have been linked against.
#[cfg(not(target_os = "macos"))]
pub const FLAVOR: Flavor = Flavor::Gnu;

/// Program name that libc puts in front of getopt diagnostics.
///
/// macOS `getprogname()` is the basename of the executable path given to
/// `execve` (symlinks are not resolved), not `argv[0]`. `current_exe()` on
/// macOS returns that same path (`_NSGetExecutablePath`).
#[cfg(target_os = "macos")]
pub fn diag_progname(argv0: &[u8]) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.as_bytes().to_vec()))
        .unwrap_or_else(|| basename(argv0).to_vec())
}

/// Program name that libc puts in front of getopt diagnostics.
///
/// glibc prints `argv[0]` verbatim.
#[cfg(not(target_os = "macos"))]
pub fn diag_progname(argv0: &[u8]) -> Vec<u8> {
    argv0.to_vec()
}

/// Bytes after the last `/` (fallback for `getprogname()`).
#[cfg(target_os = "macos")]
fn basename(path: &[u8]) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    std::path::Path::new(std::ffi::OsStr::from_bytes(path))
        .file_name()
        .map_or(path, |n| n.as_bytes())
}

/// Environment of one option-parsing run.
#[derive(Clone, Debug)]
pub struct ParseContext {
    pub flavor: Flavor,
    /// `POSIXLY_CORRECT` is set: stop at the first operand.
    pub posixly_correct: bool,
    /// Prefix of libc diagnostics (see [`diag_progname`]).
    pub diag_progname: Vec<u8>,
}

/// Lines of C `usage()`, each logged with `TRACEL(LOG_ALWAYS, ...)`.
/// Trailing spaces are in the C source.
pub const USAGE_LINES: [&[u8]; 11] = [
    b"\n",
    b"Usage:  novacomd [option]...\n",
    b"options:\n",
    b"  -b                  bind ipaddress for remote access, default is 127.0.0.1 \n",
    b"  -t <seconds>        set recovery timeout interval, valid range 2 ~ 5, default is 5\n",
    b"  -c <host>:<port>    connect to specified IP address\n",
    b"  -e <io-retry-timeout>    timeout to retry packet I/O in milliesecond\n",
    b"  -s <io-retry-delay>    delay to retry packet I/O in milliesecond\n",
    b"  -d                  run in the background\n",
    b"  -V                  print version info\n",
    b"  -h                  display this help\n",
];

/// C `isspace` in the C locale (bytes >= 0x80 are not spaces).
pub fn c_isspace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// C `atol(s)` (`strtol(s, NULL, 10)` with 64-bit `long`; saturates on
/// overflow).
pub fn c_atol(s: &[u8]) -> i64 {
    let mut i = s.iter().take_while(|&&b| c_isspace(b)).count();
    let mut negative = false;
    if let Some(&sign @ (b'+' | b'-')) = s.get(i) {
        negative = sign == b'-';
        i += 1;
    }
    let mut mag: i128 = 0;
    for &b in s[i..].iter().take_while(|b| b.is_ascii_digit()) {
        mag = (mag * 10 + i128::from(b - b'0')).min(i128::from(u64::MAX) + 1);
    }
    let v = if negative { -mag } else { mag };
    i64::try_from(v).unwrap_or(if negative { i64::MIN } else { i64::MAX })
}

/// C `(int)atol(s)`: the `long` result truncated to 32 bits.
pub fn c_atol_int(s: &[u8]) -> i32 {
    c_atol(s) as i32
}

/// One result of [`Getopt::next_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Option character and its argument.
    Opt(u8, Option<Vec<u8>>),
    /// getopt returned `'?'`; carries the libc diagnostic (may be empty).
    Error(Vec<u8>),
}

/// Emulation of `getopt_long(argc, argv, OPTSTRING, LONG_OPTIONS, NULL)`.
///
/// Operands are skipped instead of permuting argv; the observable result
/// (option order and arguments) is the same. The daemon ignores operands.
pub struct Getopt<'a> {
    args: &'a [Vec<u8>],
    ctx: &'a ParseContext,
    /// Next argv element to examine.
    idx: usize,
    /// Position of the next short option inside a cluster: (element, offset).
    cluster: Option<(usize, usize)>,
}

impl<'a> Getopt<'a> {
    /// `args` is the full argv, including `argv[0]`.
    pub fn new(args: &'a [Vec<u8>], ctx: &'a ParseContext) -> Self {
        Self {
            args,
            ctx,
            idx: 1,
            cluster: None,
        }
    }

    /// Next option, or `None` at the end of the options (getopt returned -1).
    pub fn next_event(&mut self) -> Option<Event> {
        loop {
            if let Some((elem, off)) = self.cluster {
                return Some(self.short_option(elem, off));
            }
            let arg = self.args.get(self.idx)?;
            if arg.first() != Some(&b'-') || arg.len() == 1 {
                // Non-option (including a lone "-").
                if self.ctx.posixly_correct {
                    self.idx = self.args.len();
                    return None;
                }
                self.idx += 1;
                continue;
            }
            if arg.as_slice() == b"--" {
                self.idx = self.args.len();
                return None;
            }
            self.idx += 1;
            if arg[1] == b'-' {
                return Some(self.long_option(&arg[2..]));
            }
            self.cluster = Some((self.idx - 1, 1));
        }
    }

    fn short_option(&mut self, elem: usize, off: usize) -> Event {
        let arg = &self.args[elem];
        let c = arg[off];
        let rest = &arg[off + 1..];
        if self.ctx.flavor == Flavor::Bsd && c == b'-' {
            // FreeBSD libc: a '-' inside a cluster starts a long option
            // ("-b-version" is "--version"); a trailing '-' is a silent error.
            self.cluster = None;
            if rest.is_empty() {
                return Event::Error(Vec::new());
            }
            return self.long_option(rest);
        }
        self.cluster = if rest.is_empty() {
            None
        } else {
            Some((elem, off + 1))
        };
        let pos = if c == b':' {
            None
        } else {
            OPTSTRING.iter().position(|&o| o == c)
        };
        let Some(pos) = pos else {
            return Event::Error(self.diag_invalid_short(c));
        };
        if OPTSTRING.get(pos + 1) != Some(&b':') {
            return Event::Opt(c, None);
        }
        self.cluster = None;
        if !rest.is_empty() {
            return Event::Opt(c, Some(rest.to_vec()));
        }
        match self.args.get(self.idx) {
            Some(next) => {
                self.idx += 1;
                Event::Opt(c, Some(next.clone()))
            }
            None => Event::Error(self.diag_short_missing(c)),
        }
    }

    /// `body` is the text after the `--` prefix.
    fn long_option(&mut self, body: &[u8]) -> Event {
        let (name, value) = match body.iter().position(|&b| b == b'=') {
            Some(eq) => (&body[..eq], Some(&body[eq + 1..])),
            None => (body, None),
        };
        let found = match LONG_OPTIONS.iter().position(|o| o.name == name) {
            Some(i) => Some(i),
            None => {
                let partial: Vec<usize> = (0..LONG_OPTIONS.len())
                    .filter(|&i| LONG_OPTIONS[i].name.starts_with(name))
                    .collect();
                let ambiguous: Vec<usize> = match partial.first() {
                    Some(&first) => {
                        let f = &LONG_OPTIONS[first];
                        partial
                            .iter()
                            .copied()
                            .filter(|&i| {
                                let o = &LONG_OPTIONS[i];
                                i == first || o.has_arg != f.has_arg || o.val != f.val
                            })
                            .collect()
                    }
                    None => Vec::new(),
                };
                if ambiguous.len() > 1 {
                    return Event::Error(self.diag_ambiguous(body, name, &ambiguous));
                }
                partial.first().copied()
            }
        };
        let Some(i) = found else {
            return Event::Error(self.diag(&[b"unrecognized option ", &self.quote(body)]));
        };
        let opt = &LONG_OPTIONS[i];
        match (value, opt.has_arg) {
            (Some(v), true) => Event::Opt(opt.val, Some(v.to_vec())),
            (Some(_), false) => {
                let shown = match self.ctx.flavor {
                    Flavor::Gnu => opt.name,
                    Flavor::Bsd => name,
                };
                Event::Error(self.diag(&[
                    b"option ",
                    &self.quote(shown),
                    b" doesn't allow an argument",
                ]))
            }
            (None, false) => Event::Opt(opt.val, None),
            (None, true) => match self.args.get(self.idx) {
                Some(next) => {
                    self.idx += 1;
                    Event::Opt(opt.val, Some(next.clone()))
                }
                None => {
                    let shown = match self.ctx.flavor {
                        Flavor::Gnu => opt.name,
                        Flavor::Bsd => body,
                    };
                    Event::Error(self.diag(&[
                        b"option ",
                        &self.quote(shown),
                        b" requires an argument",
                    ]))
                }
            },
        }
    }

    /// `'--text'` (glibc) or `` `--text' `` (macOS).
    fn quote(&self, text: &[u8]) -> Vec<u8> {
        let open: &[u8] = match self.ctx.flavor {
            Flavor::Gnu => b"'",
            Flavor::Bsd => b"`",
        };
        [open, b"--", text, b"'"].concat()
    }

    /// `<progname>: <parts...>\n`, as printed by libc.
    fn diag(&self, parts: &[&[u8]]) -> Vec<u8> {
        [
            &self.ctx.diag_progname,
            b": ".as_slice(),
            &parts.concat(),
            b"\n",
        ]
        .concat()
    }

    fn diag_ambiguous(&self, body: &[u8], name: &[u8], set: &[usize]) -> Vec<u8> {
        match self.ctx.flavor {
            Flavor::Gnu => {
                let mut msg = [
                    b"option ".as_slice(),
                    &self.quote(body),
                    b" is ambiguous; possibilities:",
                ]
                .concat();
                for &i in set {
                    msg.push(b' ');
                    msg.extend_from_slice(&self.quote(LONG_OPTIONS[i].name));
                }
                self.diag(&[&msg])
            }
            Flavor::Bsd => self.diag(&[b"option ", &self.quote(name), b" is ambiguous"]),
        }
    }

    fn diag_invalid_short(&self, c: u8) -> Vec<u8> {
        let text: &[u8] = match (self.ctx.flavor, self.ctx.posixly_correct) {
            (Flavor::Bsd, true) => b"illegal option -- ",
            _ => b"invalid option -- ",
        };
        self.diag_short(text, c)
    }

    fn diag_short_missing(&self, c: u8) -> Vec<u8> {
        self.diag_short(b"option requires an argument -- ", c)
    }

    fn diag_short(&self, text: &[u8], c: u8) -> Vec<u8> {
        let quoted: Vec<u8> = match self.ctx.flavor {
            Flavor::Gnu => vec![b'\'', c, b'\''],
            Flavor::Bsd => vec![c],
        };
        self.diag(&[text, &quoted])
    }
}

/// One result of C `getnextopt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextOpt {
    /// Option name as passed to `handleopt`, and `optarg`.
    Opt(&'static [u8], Option<Vec<u8>>),
    /// getopt returned -1.
    Done,
    /// getopt returned `'?'`: the libc diagnostic it printed to stderr.
    Bad(Vec<u8>),
}

/// C `getnextopt`: maps the getopt result to the `handleopt` name.
pub fn getnextopt(g: &mut Getopt<'_>) -> NextOpt {
    let (c, val) = match g.next_event() {
        None => return NextOpt::Done,
        Some(Event::Error(diag)) => return NextOpt::Bad(diag),
        Some(Event::Opt(c, val)) => (c, val),
    };
    let name: &'static [u8] = match c {
        b'c' => b"connect-ip",
        b'V' => b"version",
        b'b' => b"bind-all-interfaces",
        b'd' => b"daemonize",
        b't' => b"recoverytimeout",
        b'e' => b"ioretry_timeout",
        b's' => b"ioretry_delay",
        b'C' => b"no-cpuaffinity",
        b'h' => b"help",
        _ => return NextOpt::Bad(Vec::new()),
    };
    NextOpt::Opt(name, val)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(list: &[&str]) -> Vec<Vec<u8>> {
        std::iter::once("prog")
            .chain(list.iter().copied())
            .map(|s| s.as_bytes().to_vec())
            .collect()
    }

    fn ctx(flavor: Flavor, posix: bool) -> ParseContext {
        ParseContext {
            flavor,
            posixly_correct: posix,
            diag_progname: b"P".to_vec(),
        }
    }

    /// `getnextopt` results up to and including the first non-option one.
    fn opts(flavor: Flavor, posix: bool, list: &[&str]) -> Vec<NextOpt> {
        let args = argv(list);
        let c = ctx(flavor, posix);
        let mut g = Getopt::new(&args, &c);
        let mut out = Vec::new();
        loop {
            let n = getnextopt(&mut g);
            let stop = !matches!(n, NextOpt::Opt(..));
            out.push(n);
            if stop {
                return out;
            }
        }
    }

    fn o(name: &'static str, val: Option<&str>) -> NextOpt {
        NextOpt::Opt(name.as_bytes(), val.map(|s| s.as_bytes().to_vec()))
    }

    fn bad(s: &str) -> NextOpt {
        NextOpt::Bad(s.as_bytes().to_vec())
    }

    const BOTH: [Flavor; 2] = [Flavor::Gnu, Flavor::Bsd];

    #[test]
    fn every_option_maps_to_its_handleopt_name() {
        for f in BOTH {
            assert_eq!(
                opts(
                    f,
                    false,
                    &[
                        "-h", "-t", "3", "-c", "h:1", "-e5", "-s", "6", "-bdCV", "x", "--", "-V"
                    ]
                ),
                vec![
                    o("help", None),
                    o("recoverytimeout", Some("3")),
                    o("connect-ip", Some("h:1")),
                    o("ioretry_timeout", Some("5")),
                    o("ioretry_delay", Some("6")),
                    o("bind-all-interfaces", None),
                    o("daemonize", None),
                    o("no-cpuaffinity", None),
                    o("version", None),
                    NextOpt::Done,
                ]
            );
        }
    }

    #[test]
    fn long_options_and_abbreviations() {
        for f in BOTH {
            assert_eq!(
                opts(
                    f,
                    false,
                    &["--connect-ip=a", "--conn", "b", "--b", "--daemon", "--v"]
                ),
                vec![
                    o("connect-ip", Some("a")),
                    o("connect-ip", Some("b")),
                    o("bind-all-interfaces", None),
                    o("daemonize", None),
                    o("version", None),
                    NextOpt::Done,
                ]
            );
        }
    }

    #[test]
    fn operands_are_skipped_unless_posixly_correct() {
        for f in BOTH {
            assert_eq!(
                opts(f, false, &["x", "-V"]),
                vec![o("version", None), NextOpt::Done]
            );
            assert_eq!(opts(f, true, &["x", "-V"]), vec![NextOpt::Done]);
        }
    }

    #[test]
    fn diagnostics_per_libc() {
        let cases: [(&[&str], &str, &str); 7] = [
            (
                &["-Z"],
                "P: invalid option -- 'Z'\n",
                "P: invalid option -- Z\n",
            ),
            (
                &["-t"],
                "P: option requires an argument -- 't'\n",
                "P: option requires an argument -- t\n",
            ),
            (
                &["--bogus"],
                "P: unrecognized option '--bogus'\n",
                "P: unrecognized option `--bogus'\n",
            ),
            (
                &["--connect-ip"],
                "P: option '--connect-ip' requires an argument\n",
                "P: option `--connect-ip' requires an argument\n",
            ),
            (
                &["--co"],
                "P: option '--connect-ip' requires an argument\n",
                "P: option `--co' requires an argument\n",
            ),
            (
                &["--vers=1"],
                "P: option '--version' doesn't allow an argument\n",
                "P: option `--vers' doesn't allow an argument\n",
            ),
            (
                &["--=x"],
                "P: option '--=x' is ambiguous; possibilities: '--connect-ip' \
                 '--bind-all-interfaces' '--daemonize' '--version'\n",
                "P: option `--' is ambiguous\n",
            ),
        ];
        for (args, gnu, bsd) in cases {
            assert_eq!(opts(Flavor::Gnu, false, args), vec![bad(gnu)], "{args:?}");
            assert_eq!(opts(Flavor::Bsd, false, args), vec![bad(bsd)], "{args:?}");
        }
        assert_eq!(
            opts(Flavor::Bsd, true, &["-Z"]),
            vec![bad("P: illegal option -- Z\n")]
        );
        assert_eq!(
            opts(Flavor::Gnu, false, &["-b-version"]),
            vec![
                o("bind-all-interfaces", None),
                bad("P: invalid option -- '-'\n")
            ]
        );
        assert_eq!(
            opts(Flavor::Bsd, false, &["-b-version"]),
            vec![
                o("bind-all-interfaces", None),
                o("version", None),
                NextOpt::Done
            ]
        );
    }

    #[test]
    fn atol_semantics() {
        assert_eq!(c_atol(b"5"), 5);
        assert_eq!(c_atol(b" \t\n\x0b\x0c\r+12x"), 12);
        assert_eq!(c_atol(b"-5"), -5);
        assert_eq!(c_atol(b"junk"), 0);
        assert_eq!(c_atol(b""), 0);
        assert_eq!(c_atol(b"+-1"), 0);
        assert_eq!(c_atol(b"9223372036854775807"), i64::MAX);
        assert_eq!(c_atol(b"9223372036854775808"), i64::MAX);
        assert_eq!(c_atol(b"99999999999999999999999"), i64::MAX);
        assert_eq!(c_atol(b"-9223372036854775808"), i64::MIN);
        assert_eq!(c_atol(b"-99999999999999999999999"), i64::MIN);
        assert_eq!(c_atol_int(b"4294967298"), 2);
        assert_eq!(c_atol_int(b"99999999999999999999"), -1);
        assert_eq!(c_atol_int(b"-99999999999999999999"), 0);
    }

    #[test]
    fn usage_lines_end_with_newline() {
        assert!(USAGE_LINES.iter().all(|l| l.ends_with(b"\n")));
        assert_eq!(USAGE_LINES[1], b"Usage:  novacomd [option]...\n");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn basename_fallback() {
        assert_eq!(basename(b"/a/b/novacomd"), b"novacomd");
        assert_eq!(basename(b"novacomd"), b"novacomd");
    }
}
