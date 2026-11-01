//! Message buffer: emulation of the parts of C `buffer_t`
//! (`src/lib/buffer.c`) that the host command service uses. Strings and
//! blobs are a big-endian `u32` length followed by the bytes.

/// A `buffer_put*` call that does not fit (C -1 from `buffer_checksize`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// C `buffer_new(cap)` filled with `buffer_put*`: nothing is written by a
/// call that does not fit.
pub struct Writer {
    data: Vec<u8>,
    cap: usize,
}

impl Writer {
    pub fn new(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
            cap,
        }
    }

    /// C `buffer_checksize`: `pos + size <= len`.
    fn check(&self, size: usize) -> Result<(), Full> {
        if self.data.len() + size <= self.cap {
            Ok(())
        } else {
            Err(Full)
        }
    }

    /// C `buffer_putbyte`.
    pub fn put_byte(&mut self, b: u8) -> Result<(), Full> {
        self.check(1)?;
        self.data.push(b);
        Ok(())
    }

    /// C `buffer_putstring`.
    pub fn put_string(&mut self, s: &[u8]) -> Result<(), Full> {
        self.check(4 + s.len())?;
        // `check` bounds the length by `cap`.
        self.data.extend_from_slice(&(s.len() as u32).to_be_bytes());
        self.data.extend_from_slice(s);
        Ok(())
    }

    /// C `b->data` up to `b->pos`.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

/// C `buffer_setdata` read with `buffer_get*`.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// C `buffer_getbyte`.
    pub fn get_byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// C `buffer_getblob`: `None` where C returns `(uint32_t)-1`. An empty
    /// blob is returned as such (C returns 0).
    pub fn get_blob(&mut self) -> Option<&'a [u8]> {
        let rest = &self.data[self.pos..];
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let blob = rest[4..].get(..len)?;
        self.pos += 4 + blob.len();
        Some(blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_layout_and_capacity() {
        let mut w = Writer::new(12);
        assert_eq!(w.put_byte(50), Ok(()));
        assert_eq!(w.put_string(b"abcdef"), Ok(()));
        // 11 bytes used: a string needs at least 4 more, a byte fits.
        assert_eq!(w.put_string(b""), Err(Full));
        assert_eq!(w.put_byte(1), Ok(()));
        assert_eq!(w.put_byte(2), Err(Full));
        assert_eq!(w.into_bytes(), b"\x32\0\0\0\x06abcdef\x01");
    }

    #[test]
    fn writer_exact_fit() {
        let mut w = Writer::new(5);
        assert_eq!(w.put_string(b"x"), Ok(()));
        assert_eq!(w.into_bytes(), b"\0\0\0\x01x");
    }

    #[test]
    fn reader_bytes_and_blobs() {
        let mut r = Reader::new(b"\x4b\x00\x46\x00\x00\x00\x03xyzrest");
        assert_eq!(r.get_byte(), Some(0x4b));
        assert_eq!(r.get_byte(), Some(0));
        assert_eq!(r.get_byte(), Some(0x46));
        assert_eq!(r.get_blob(), Some(&b"xyz"[..]));
        assert_eq!(r.get_byte(), Some(b'r'));

        assert_eq!(Reader::new(b"").get_byte(), None);
        assert_eq!(Reader::new(b"\0\0\0").get_blob(), None);
        assert_eq!(Reader::new(b"\0\0\0\x04abc").get_blob(), None);
        assert_eq!(Reader::new(b"\0\0\0\0").get_blob(), Some(&b""[..]));
        assert_eq!(Reader::new(b"\xff\xff\xff\xffa").get_blob(), None);
    }
}
