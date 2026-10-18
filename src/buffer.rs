//! Output buffer of a Session (PROTOCOL.md §15.11): the most recent output with its
//! kind (standard output or PTY output, error output), numbered by output offset.

// Used by the Server, which runs on Unix only for now (gate G2).
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::VecDeque;
use std::sync::Arc;

/// A piece of output: its message type (TERMINAL_DATA or TERMINAL_STDERR) and bytes.
pub type Piece = (u64, Arc<[u8]>);

/// Where the replay of an attach starts (§15.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// A fresh attach: the tail of at most this many bytes, from its first line feed.
    Fresh(usize),
    /// A resume: from this offset, or from the start of the buffer if it is older.
    Resume(u64),
}

/// A resume offset beyond the end of the output.
#[derive(Debug, PartialEq, Eq)]
pub struct BeyondEnd;

pub struct OutputBuffer {
    capacity: usize,
    /// Kept pieces with the offset of their first byte, oldest first.
    pieces: VecDeque<(u64, Piece)>,
    len: usize,
    /// Offset of the byte after the last output byte.
    end: u64,
}

impl OutputBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pieces: VecDeque::new(),
            len: 0,
            end: 0,
        }
    }

    /// Offset after the last output byte: the number of output bytes so far.
    #[cfg(test)]
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Offset of the oldest byte kept.
    fn start(&self) -> u64 {
        self.end - self.len as u64
    }

    /// Numbers a piece of output and keeps the most recent `capacity` bytes.
    pub fn push(&mut self, kind: u64, data: Arc<[u8]>) {
        let offset = self.end;
        self.end += data.len() as u64;
        self.len += data.len();
        self.pieces.push_back((offset, (kind, data)));
        while self.len > self.capacity {
            let excess = self.len - self.capacity;
            let (offset, (kind, data)) = self.pieces.pop_front().expect("len > 0");
            if data.len() > excess {
                let rest: Arc<[u8]> = data[excess..].into();
                self.pieces
                    .push_front((offset + excess as u64, (kind, rest)));
                self.len -= excess;
            } else {
                self.len -= data.len();
            }
        }
    }

    /// The replay for an attach: the offset of its first byte (key 2 of
    /// TERMINAL_ATTACHED) and its pieces.
    pub fn replay(&self, replay: Replay) -> Result<(u64, Vec<Piece>), BeyondEnd> {
        let from = match replay {
            Replay::Resume(offset) if offset > self.end => return Err(BeyondEnd),
            Replay::Resume(offset) => offset.max(self.start()),
            Replay::Fresh(limit) => {
                let tail = self.end.saturating_sub(limit as u64).max(self.start());
                // Start after the first line feed, so not inside an escape sequence;
                // the output from its very start has no such risk.
                match self.first_line_feed(tail) {
                    _ if tail == 0 => 0,
                    Some(offset) => offset + 1,
                    None => self.end,
                }
            }
        };
        Ok((from, self.from(from)))
    }

    fn first_line_feed(&self, from: u64) -> Option<u64> {
        self.pieces.iter().find_map(|(offset, (_, data))| {
            let skip = from.saturating_sub(*offset) as usize;
            let found = data.get(skip..)?.iter().position(|b| *b == b'\n')?;
            Some(offset + (skip + found) as u64)
        })
    }

    /// The kept output from `from` on.
    fn from(&self, from: u64) -> Vec<Piece> {
        self.pieces
            .iter()
            .filter(|(offset, (_, data))| offset + data.len() as u64 > from)
            .map(|(offset, (kind, data))| {
                let skip = from.saturating_sub(*offset) as usize;
                let data = if skip == 0 {
                    data.clone()
                } else {
                    data[skip..].into()
                };
                (*kind, data)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: u64 = 7;
    const ERR: u64 = 8;

    fn buffer(capacity: usize, pieces: &[(u64, &str)]) -> OutputBuffer {
        let mut buffer = OutputBuffer::new(capacity);
        for (kind, text) in pieces {
            buffer.push(*kind, text.as_bytes().into());
        }
        buffer
    }

    fn text(replay: Result<(u64, Vec<Piece>), BeyondEnd>) -> (u64, Vec<(u64, String)>) {
        let (offset, pieces) = replay.unwrap();
        let pieces = pieces
            .into_iter()
            .map(|(kind, data)| (kind, String::from_utf8(data.to_vec()).unwrap()))
            .collect();
        (offset, pieces)
    }

    #[test]
    fn keeps_the_most_recent_bytes_with_their_offsets() {
        let b = buffer(5, &[(OUT, "abc"), (ERR, "de"), (OUT, "fgh")]);
        assert_eq!(b.end(), 8);
        assert_eq!(b.start(), 3);
        assert_eq!(
            text(b.replay(Replay::Resume(0))),
            (3, vec![(ERR, "de".into()), (OUT, "fgh".into())])
        );
        assert_eq!(
            text(b.replay(Replay::Resume(6))),
            (6, vec![(OUT, "gh".into())])
        );
        assert_eq!(text(b.replay(Replay::Resume(8))), (8, vec![]));
        assert_eq!(b.replay(Replay::Resume(9)).err(), Some(BeyondEnd));
    }

    #[test]
    fn a_piece_larger_than_the_buffer() {
        let b = buffer(4, &[(OUT, "abcdefgh")]);
        assert_eq!(
            text(b.replay(Replay::Resume(0))),
            (4, vec![(OUT, "efgh".into())])
        );
    }

    #[test]
    fn no_buffer_still_counts() {
        let b = buffer(0, &[(OUT, "abc"), (OUT, "de")]);
        assert_eq!(b.end(), 5);
        assert_eq!(text(b.replay(Replay::Resume(2))), (5, vec![]));
        assert_eq!(text(b.replay(Replay::Fresh(16))), (5, vec![]));
    }

    #[test]
    fn fresh_replay_starts_after_a_line_feed_in_the_tail() {
        let b = buffer(100, &[(OUT, "one\ntwo\nth"), (ERR, "ree\nfour")]);
        // The tail of 10 bytes is "three\nfour" (offsets 8–17); its line feed is at 13.
        assert_eq!(
            text(b.replay(Replay::Fresh(10))),
            (14, vec![(ERR, "four".into())])
        );
        // All output from offset 0 is replayed whole.
        assert_eq!(
            text(b.replay(Replay::Fresh(100))),
            (
                0,
                vec![(OUT, "one\ntwo\nth".into()), (ERR, "ree\nfour".into())]
            )
        );
        let evicted = buffer(12, &[(OUT, "one\ntwo\nth"), (ERR, "ree\nfour")]);
        assert_eq!(
            text(evicted.replay(Replay::Fresh(100))),
            (8, vec![(OUT, "th".into()), (ERR, "ree\nfour".into())])
        );
        let no_line = buffer(4, &[(OUT, "abcdef")]);
        assert_eq!(text(no_line.replay(Replay::Fresh(100))), (6, vec![]));
    }
}
