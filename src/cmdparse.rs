//! Command parser: emulation of C `parse_command` with `trim` and
//! `tokenize` (`src/novacom/commands.c`).
//!
//! `<verb> [verbargs...] <scheme>://<path> [args...]`; tokens are split on
//! whitespace, `\` escapes the next byte. The C code works in place on a
//! NUL-terminated copy; this port does the same on a byte buffer.

use crate::cli::c_isspace;

/// C `DEVICE_COMMAND_ARGS_LIMIT`: tokenizing stops at this many tokens.
const TOKEN_LIMIT: usize = 4096;

/// C `struct novacom_command_url`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandUrl {
    pub verb: Vec<u8>,
    pub verbargs: Vec<Vec<u8>>,
    pub scheme: Vec<u8>,
    pub path: Vec<u8>,
    pub args: Vec<Vec<u8>>,
}

/// C `iscntrl` in the C locale.
fn c_iscntrl(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

/// The C string starting at `start` (up to the next NUL).
fn c_str_at(buf: &[u8], start: usize) -> &[u8] {
    let rest = &buf[start..];
    &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())]
}

/// C `trim`: returns the start index; trailing space and control bytes are
/// overwritten with NUL. `buf` is NUL-terminated.
fn trim(buf: &mut [u8]) -> usize {
    let start = buf.iter().take_while(|&&b| c_isspace(b)).count();
    let len = c_str_at(buf, start).len();
    for pos in (start..start + len).rev() {
        if !(c_isspace(buf[pos]) || c_iscntrl(buf[pos])) {
            break;
        }
        buf[pos] = 0;
    }
    start
}

/// C `tokenize`: returns the start index of each token; separators and
/// consumed escape bytes are overwritten in place. `buf` is NUL-terminated.
fn tokenize(buf: &mut [u8], mut pos: usize) -> Vec<usize> {
    enum State {
        Initial,
        Tok,
        InTok,
        InSpace,
        InSkip,
    }
    let mut state = State::Initial;
    let mut tokens = Vec::new();
    let mut skips = 0usize;
    while buf[pos] != 0 {
        if tokens.len() >= TOKEN_LIMIT {
            return tokens;
        }
        match state {
            State::Initial => {
                state = if c_isspace(buf[pos]) {
                    State::InSpace
                } else {
                    State::Tok
                };
            }
            State::Tok => {
                tokens.push(pos);
                skips = 0;
                state = State::InTok;
                pos += 1;
            }
            State::InTok => {
                if c_isspace(buf[pos]) {
                    state = State::InSpace;
                } else if buf[pos] == b'\\' {
                    state = State::InSkip;
                    pos += 1;
                } else {
                    if skips > 0 {
                        buf[pos - skips] = buf[pos];
                        buf[pos] = 0;
                    }
                    pos += 1;
                }
            }
            State::InSpace => {
                if c_isspace(buf[pos]) {
                    buf[pos] = 0;
                    pos += 1;
                } else {
                    state = State::Tok;
                }
            }
            State::InSkip => {
                state = State::InTok;
                skips += 1;
                buf[pos - skips] = buf[pos];
                buf[pos] = 0;
                pos += 1;
            }
        }
    }
    tokens
}

/// C `parse_command(cmd, strlen(cmd), &url)`: `None` where C fails.
/// `cmd` is cut at its first NUL, as C `strlen` does.
pub fn parse_command(cmd: &[u8]) -> Option<CommandUrl> {
    let mut buf = c_str_at(cmd, 0).to_vec();
    buf.push(0);
    let start = trim(&mut buf);
    let starts = tokenize(&mut buf, start);
    let first = *starts.first()?;
    // The scheme is the first token after the verb that contains "://".
    let sep_at = |t: &[u8]| t.windows(3).position(|w| w == b"://");
    let scheme_idx = (1..starts.len()).find(|&i| sep_at(c_str_at(&buf, starts[i])).is_some())?;
    let token = |i: usize| c_str_at(&buf, starts[i]).to_vec();
    let scheme_tok = token(scheme_idx);
    let sep = sep_at(&scheme_tok)?;
    Some(CommandUrl {
        verb: c_str_at(&buf, first).to_vec(),
        verbargs: (1..scheme_idx).map(token).collect(),
        scheme: scheme_tok[..sep].to_vec(),
        path: scheme_tok[sep + 3..].to_vec(),
        args: (scheme_idx + 1..starts.len()).map(token).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(verb: &str, verbargs: &[&str], scheme: &str, path: &str, args: &[&str]) -> CommandUrl {
        let v = |l: &[&str]| l.iter().map(|s| s.as_bytes().to_vec()).collect();
        CommandUrl {
            verb: verb.as_bytes().to_vec(),
            verbargs: v(verbargs),
            scheme: scheme.as_bytes().to_vec(),
            path: path.as_bytes().to_vec(),
            args: v(args),
        }
    }

    #[test]
    fn basic_commands() {
        assert_eq!(
            parse_command(b"list host://"),
            Some(url("list", &[], "host", "", &[]))
        );
        assert_eq!(
            parse_command(b"login dev://abc hash\n"),
            Some(url("login", &[], "dev", "abc", &["hash"]))
        );
        assert_eq!(
            parse_command(b" \t run -x  -y file:///bin/ls a  b \r\n\x01"),
            Some(url("run", &["-x", "-y"], "file", "/bin/ls", &["a", "b"]))
        );
        assert_eq!(
            parse_command(b"a b://c://d"),
            Some(url("a", &[], "b", "c://d", &[]))
        );
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse_command(b""), None);
        assert_eq!(parse_command(b"   \n"), None);
        assert_eq!(parse_command(b"list"), None);
        assert_eq!(parse_command(b"list host:/"), None);
        // The verb itself is never the scheme token.
        assert_eq!(parse_command(b"host://"), None);
        assert_eq!(parse_command(b"list\0 host://"), None);
    }

    #[test]
    fn escapes() {
        assert_eq!(
            parse_command(b"lo\\gin dev://a\\ b c\\\\d"),
            Some(url("login", &[], "dev", "a b", &["c\\d"]))
        );
        // A trailing backslash is kept (C never copies over it).
        assert_eq!(
            parse_command(b"x y://z\\"),
            Some(url("x", &[], "y", "z\\", &[]))
        );
        // An escaped "://" still separates the scheme (the check runs on
        // the unescaped token).
        assert_eq!(
            parse_command(b"x y\\://z"),
            Some(url("x", &[], "y", "z", &[]))
        );
    }

    #[test]
    fn trim_keeps_inner_control_bytes() {
        assert_eq!(
            parse_command(b"list host://a\x01b\x01"),
            Some(url("list", &[], "host", "a\x01b", &[]))
        );
        // Bytes >= 0x80 are neither space nor control.
        let u = parse_command(b"\xa0list host://\xff").unwrap();
        assert_eq!(u.verb, b"\xa0list");
        assert_eq!(u.path, b"\xff");
    }
}
