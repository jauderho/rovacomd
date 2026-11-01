//! Token storage: emulation of C `host/tokenstorage.c`.
//!
//! The directory is `<home>/.nova/` (C `snprintf` into a 128-byte path
//! buffer, created with mode 0700 on every use); a token file is
//! `<dir><nduid>`. The nduid comes from the peer and is not validated, so
//! `../` leaves the directory (D2, kept as in C).

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use sha1::{Digest, Sha1};

use crate::sys;

/// C `char path[128]`.
const PATH_SIZE: usize = 128;
/// C `NOVACOM_AUTHTOKEN_LEN`: bytes of a token file used for the hash.
pub const AUTHTOKEN_LEN: usize = 256;
/// C `NOVACOM_AUTHSESSION_LEN`.
pub const AUTHSESSION_LEN: usize = 10;
/// C `SHA1_HASH_STRSIZE`: lowercase hex SHA-1, no NUL.
pub const HASH_STRLEN: usize = 40;

/// Where token files live.
#[derive(Clone, Debug)]
pub struct TokenStore {
    /// `None`: C `getpwuid(getuid())->pw_dir`, looked up on every use.
    home: Option<Vec<u8>>,
}

impl TokenStore {
    /// The daemon's store: below the home directory of the real user id
    /// (`$HOME` is not used).
    pub fn user_home() -> Self {
        Self { home: None }
    }

    /// A store below `home` in place of the passwd home directory (for
    /// tests).
    pub fn with_home(home: &Path) -> Self {
        Self {
            home: Some(home.as_os_str().as_bytes().to_vec()),
        }
    }

    /// C `tokenstorage_path`: `<home>/.nova/`, cut to 127 bytes, created
    /// with mode 0700 unless it exists.
    fn dir(&self) -> Option<Vec<u8>> {
        let home = match &self.home {
            Some(h) => h.clone(),
            None => sys::home_dir()?,
        };
        let mut path = [&home[..], b"/.nova/"].concat();
        path.truncate(PATH_SIZE - 1);
        match DirBuilder::new()
            .mode(0o700)
            .create(OsStr::from_bytes(&path))
        {
            Err(e) if e.kind() != ErrorKind::AlreadyExists => None,
            _ => Some(path),
        }
    }

    /// `<dir><file>` cut to `max` bytes (C `strncat`).
    fn file_path(&self, file: &[u8], max: usize) -> io::Result<Vec<u8>> {
        let mut path = self.dir().ok_or(ErrorKind::NotFound)?;
        path.extend_from_slice(file);
        path.truncate(max);
        Ok(path)
    }

    /// C `tokenstorage_store`: writes the token file (C `fopen "wb"`, mode
    /// 0666 less the umask); a failed write removes it.
    pub fn store(&self, file: &[u8], data: &[u8]) -> io::Result<()> {
        let path = self.file_path(file, PATH_SIZE - 1)?;
        let path = Path::new(OsStr::from_bytes(&path));
        let written = File::create(path)?.write_all(data);
        if written.is_err() {
            let _ = fs::remove_file(path);
        }
        written
    }

    /// C `tokenstorage_remove`: C `remove`, which also removes an empty
    /// directory.
    ///
    /// Intentional change (D3): C appends with one byte too many and so
    /// writes the terminating NUL past its 128-byte buffer when the path is
    /// that long; here the 128-byte path is used without the overflow (as
    /// also for [`TokenStore::read`]).
    pub fn remove(&self, file: &[u8]) -> io::Result<()> {
        let path = self.file_path(file, PATH_SIZE)?;
        let path = Path::new(OsStr::from_bytes(&path));
        match fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() => fs::remove_dir(path),
            _ => fs::remove_file(path),
        }
    }

    /// C `tokenstorage_read`: exactly `len` bytes from the start of the
    /// token file, else `None`.
    pub fn read(&self, file: &[u8], len: usize) -> Option<Vec<u8>> {
        let path = self.file_path(file, PATH_SIZE).ok()?;
        let mut buf = Vec::with_capacity(len);
        File::open(OsStr::from_bytes(&path))
            .ok()?
            .take(len as u64)
            .read_to_end(&mut buf)
            .ok()?;
        (buf.len() == len).then_some(buf)
    }

    /// C `tokenstorage_readhash`: `hex(SHA1(token[0..256] ‖ ssid))` for a
    /// 10-byte session id, else `None`.
    pub fn read_hash(&self, file: &[u8], ssid: &[u8]) -> Option<[u8; HASH_STRLEN]> {
        if ssid.len() != AUTHSESSION_LEN {
            return None;
        }
        let token = self.read(file, AUTHTOKEN_LEN)?;
        Some(sha1_hex(&[&token[..], ssid].concat()))
    }
}

/// C `SHA1Result` `Message_Digest_Str`: lowercase hex.
pub fn sha1_hex(data: &[u8]) -> [u8; HASH_STRLEN] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; HASH_STRLEN];
    for (i, b) in Sha1::digest(data).iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0x0f)];
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fresh empty directory below the system temp dir, removed on drop.
    pub struct TempHome(pub PathBuf);

    impl TempHome {
        pub fn create() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "rovacomd-tokens-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        pub fn store(&self) -> TokenStore {
            TokenStore::with_home(&self.0)
        }
        pub fn nova(&self) -> PathBuf {
            self.0.join(".nova")
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sha1_hex_is_lowercase() {
        assert_eq!(&sha1_hex(b""), b"da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            &sha1_hex(b"abc"),
            b"a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn store_read_remove() {
        let h = TempHome::create();
        let s = h.store();
        assert!(!h.nova().exists());
        s.store(b"ABC", b"token").unwrap();
        let mode = fs::metadata(h.nova()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert_eq!(fs::read(h.nova().join("ABC")).unwrap(), b"token");
        assert_eq!(s.read(b"ABC", 5), Some(b"token".to_vec()));
        assert_eq!(s.read(b"ABC", 3), Some(b"tok".to_vec()));
        assert_eq!(s.read(b"ABC", 6), None);
        assert_eq!(s.read(b"other", 1), None);
        // Overwrite truncates.
        s.store(b"ABC", b"t2").unwrap();
        assert_eq!(fs::read(h.nova().join("ABC")).unwrap(), b"t2");
        s.remove(b"ABC").unwrap();
        assert!(!h.nova().join("ABC").exists());
        assert!(s.remove(b"ABC").is_err());
        // The directory stays.
        assert!(h.nova().is_dir());
    }

    #[test]
    fn read_creates_the_directory() {
        let h = TempHome::create();
        assert_eq!(h.store().read(b"x", 1), None);
        assert!(h.nova().is_dir());
    }

    #[test]
    fn path_traversal_is_kept() {
        // D2: the nduid is used as given.
        let h = TempHome::create();
        h.store().store(b"../escaped", b"x").unwrap();
        assert_eq!(fs::read(h.0.join("escaped")).unwrap(), b"x");
    }

    #[test]
    fn empty_name_removes_the_empty_directory() {
        // C `remove("<home>/.nova/")` is `rmdir` for a directory.
        let h = TempHome::create();
        assert_eq!(h.store().read(b"", 1), None);
        assert!(h.nova().is_dir());
        h.store().remove(b"").unwrap();
        assert!(!h.nova().exists());
    }

    #[test]
    fn read_hash() {
        let h = TempHome::create();
        let s = h.store();
        let token: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        s.store(b"dev", &token).unwrap();
        let want = sha1_hex(&[&token[..256], b"0123456789"].concat());
        assert_eq!(s.read_hash(b"dev", b"0123456789"), Some(want));
        assert_eq!(s.read_hash(b"dev", b"012345678"), None);
        assert_eq!(s.read_hash(b"dev", b"0123456789a"), None);
        assert_eq!(s.read_hash(b"other", b"0123456789"), None);
        // Fewer than 256 bytes: no hash.
        s.store(b"short", &token[..255]).unwrap();
        assert_eq!(s.read_hash(b"short", b"0123456789"), None);
    }

    #[test]
    fn wrong_session_length_does_not_create_the_directory() {
        let h = TempHome::create();
        assert_eq!(h.store().read_hash(b"x", b"short"), None);
        assert!(!h.nova().exists());
    }

    #[test]
    fn path_is_cut_like_the_c_buffer() {
        let h = TempHome::create();
        let dir_len = h.0.as_os_str().len() + "/.nova/".len();
        assert!(dir_len < PATH_SIZE - 2);
        let name = vec![b'n'; PATH_SIZE];
        // store: 127 bytes in all; read and remove: 128.
        h.store().store(&name, b"t").unwrap();
        let stored = vec![b'n'; PATH_SIZE - 1 - dir_len];
        assert_eq!(
            fs::read(h.nova().join(OsStr::from_bytes(&stored))).unwrap(),
            b"t"
        );
        let longer = [&stored[..], b"n"].concat();
        fs::write(h.nova().join(OsStr::from_bytes(&longer)), b"u").unwrap();
        assert_eq!(h.store().read(&name, 1), Some(b"u".to_vec()));
        h.store().remove(&name).unwrap();
        assert!(!h.nova().join(OsStr::from_bytes(&longer)).exists());
        assert!(h.nova().join(OsStr::from_bytes(&stored)).exists());
    }
}
