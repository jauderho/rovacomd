//! Buffer queue: emulation of the parts of C `buf_queue.c` that the host
//! mux uses (`bufq_append_chain` of data and callback entries,
//! `bufq_len`, `bufq_peek_nonblock`, `bufq_peek_onechunk_nonblock`,
//! `bufq_consume_nonblock`, `bufq_destroy`).
//!
//! A queue is a list of entries: data, or a zero-length entry that carries
//! a callback. Callbacks fire when their entry is consumed or the queue is
//! destroyed. C calls them on the spot; here they are returned to the
//! caller in firing order, so the caller can run them after it drops its
//! locks. The callback type is generic so that tests can use plain values.

use std::collections::VecDeque;

enum Entry<C> {
    /// Bytes not consumed yet (C `buf + start`, `len`).
    Data(Vec<u8>),
    /// Zero-length entry with a callback (C `bufc_append_callback`).
    Callback(C),
}

impl<C> Entry<C> {
    fn len(&self) -> usize {
        match self {
            Entry::Data(d) => d.len(),
            Entry::Callback(_) => 0,
        }
    }
}

/// C `buf_queue_t`.
pub struct BufQueue<C> {
    entries: VecDeque<Entry<C>>,
}

impl<C> Default for BufQueue<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> BufQueue<C> {
    /// C `bufq_create`.
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    /// Appends `data` and then, if given, a callback entry (the chain C
    /// `novacom_queue_tx` builds and appends with `bufq_append_chain`).
    pub fn append(&mut self, data: &[u8], callback: Option<C>) {
        self.entries.push_back(Entry::Data(data.to_vec()));
        if let Some(c) = callback {
            self.entries.push_back(Entry::Callback(c));
        }
    }

    /// C `bufq_len`: queued data bytes.
    pub fn len(&self) -> usize {
        self.entries.iter().map(Entry::len).sum()
    }

    /// `true` if no data bytes are queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// C `bufq_peek_nonblock`: up to `size` bytes from the head, without
    /// consuming them.
    pub fn peek(&self, size: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(size.min(self.len()));
        for e in &self.entries {
            if let Entry::Data(d) = e {
                let room = size - out.len();
                if d.len() > room {
                    out.extend_from_slice(&d[..room]);
                    break;
                }
                out.extend_from_slice(d);
            }
        }
        out
    }

    /// C `bufq_peek_onechunk_nonblock`: up to `size` bytes of the first
    /// entry that holds data.
    pub fn peek_onechunk(&self, size: usize) -> Vec<u8> {
        self.entries
            .iter()
            .find_map(|e| match e {
                Entry::Data(d) if !d.is_empty() => Some(d[..d.len().min(size)].to_vec()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// C `bufq_consume_nonblock`: drops `size` bytes from the head; whole
    /// entries that fit are removed, then the next one is trimmed, then the
    /// zero-length entries that follow are removed. Returns the callbacks
    /// of the removed entries, in order.
    pub fn consume(&mut self, size: usize) -> Vec<C> {
        let mut fired = Vec::new();
        let mut left = size;
        while let Some(e) = self.entries.front() {
            let len = e.len();
            if len <= left {
                left -= len;
                if let Some(Entry::Callback(c)) = self.entries.pop_front() {
                    fired.push(c);
                }
            } else {
                if left > 0
                    && let Some(Entry::Data(d)) = self.entries.front_mut()
                {
                    d.drain(..left);
                }
                break;
            }
        }
        fired
    }

    /// C `bufq_destroy`: drops everything and returns all callbacks.
    pub fn destroy(self) -> Vec<C> {
        self.entries
            .into_iter()
            .filter_map(|e| match e {
                Entry::Callback(c) => Some(c),
                Entry::Data(_) => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(parts: &[(&[u8], Option<u32>)]) -> BufQueue<u32> {
        let mut q = BufQueue::new();
        for (d, c) in parts {
            q.append(d, *c);
        }
        q
    }

    #[test]
    fn len_and_peek_span_entries() {
        let q = queue(&[(b"abc", Some(1)), (b"defg", None), (b"hi", Some(2))]);
        assert_eq!(q.len(), 9);
        assert_eq!(q.peek(100), b"abcdefghi");
        assert_eq!(q.peek(5), b"abcde");
        assert_eq!(q.peek(3), b"abc");
        assert_eq!(q.peek(0), b"");
        assert!(BufQueue::<u32>::new().is_empty());
    }

    #[test]
    fn onechunk_skips_empty_entries() {
        let q = queue(&[(b"", Some(1)), (b"abcdef", Some(2)), (b"xyz", None)]);
        assert_eq!(q.peek_onechunk(100), b"abcdef");
        assert_eq!(q.peek_onechunk(4), b"abcd");
        assert_eq!(BufQueue::<u32>::new().peek_onechunk(4), b"");
    }

    #[test]
    fn consume_fires_callbacks_of_whole_entries_and_trailing_ones() {
        let mut q = queue(&[(b"abc", Some(1)), (b"defg", Some(2)), (b"hi", Some(3))]);
        // Exactly the first entry: its callback (which follows it) fires.
        assert_eq!(q.consume(3), vec![1]);
        assert_eq!(q.peek(100), b"defghi");
        // Part of an entry: trimmed, nothing fires.
        assert_eq!(q.consume(2), Vec::<u32>::new());
        assert_eq!(q.peek(100), b"fghi");
        assert_eq!(q.len(), 4);
        // Across entries.
        assert_eq!(q.consume(3), vec![2]);
        assert_eq!(q.peek(100), b"i");
        assert_eq!(q.consume(1), vec![3]);
        assert!(q.is_empty());
        assert_eq!(q.consume(5), Vec::<u32>::new());
    }

    #[test]
    fn consume_zero_fires_leading_callbacks_only() {
        let mut q = queue(&[(b"", Some(1)), (b"ab", Some(2))]);
        assert_eq!(q.consume(0), vec![1]);
        assert_eq!(q.peek(10), b"ab");
        assert_eq!(q.destroy(), vec![2]);
    }

    #[test]
    fn destroy_returns_all_callbacks_in_order() {
        let q = queue(&[(b"a", Some(7)), (b"b", None), (b"c", Some(9))]);
        assert_eq!(q.destroy(), vec![7, 9]);
    }
}
