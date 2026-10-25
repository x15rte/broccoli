//! The one byte-level truncation rule for capped line readers.
//!
//! Two readers drain a core child's output: the supervisor's async pump in
//! the GUI process, and the elevated helper's sync pump. Both cap one line at
//! [`MAX_LINE_BYTES`] and mark the cut with [`TRUNCATED_MARKER`]; only their
//! I/O differs (`fill_buf().await` versus `fill_buf()`). The state machine
//! they drive — how much of each buffered chunk to keep, when the cap forces
//! a skip to the next newline, and how the kept bytes become the delivered
//! string — lives here, so a change to the cap shape lands once.

use super::supervisor::{MAX_LINE_BYTES, TRUNCATED_MARKER};

/// Bytes a line may retain before the truncation marker, which is appended
/// over the cap's tail.
fn keep() -> usize {
    MAX_LINE_BYTES - TRUNCATED_MARKER.len()
}

/// One capped line under construction.
pub(crate) struct Line {
    bytes: Vec<u8>,
}

/// What the reader must do after handing its buffered chunk to
/// [`Line::take`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Consume `consume` bytes and hand the next chunk in.
    More { consume: usize },
    /// Consume `consume` bytes; the line is complete.
    Done { consume: usize },
    /// Consume `consume` bytes, then discard the rest of the line (to the
    /// next newline or EOF); the line is complete, capped.
    Cut { consume: usize },
    /// The reader is at EOF; the line is complete.
    Eof,
}

impl Line {
    /// An empty line holding at most one buffer's worth of bytes up front.
    pub(crate) fn new() -> Self {
        Line {
            bytes: Vec::with_capacity(keep().min(256)),
        }
    }

    /// Take the next buffered chunk (`available` is the reader's current
    /// buffer, not yet consumed). The line keeps up to the cap, cuts there
    /// with the shared marker, and reports how many bytes of the chunk the
    /// reader must consume.
    pub(crate) fn take(&mut self, available: &[u8]) -> Step {
        if available.is_empty() {
            return Step::Eof;
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            let take = pos.min(self.room());
            self.bytes.extend_from_slice(&available[..take]);
            if take < pos {
                // Content between the budget and the newline was cut; the
                // newline itself is consumed with the line.
                self.mark_cut();
            }
            return Step::Done { consume: pos + 1 };
        }
        let take = available.len().min(self.room());
        self.bytes.extend_from_slice(&available[..take]);
        if self.bytes.len() >= keep() {
            // The line continues past the cap: the caller skips the rest.
            self.mark_cut();
            Step::Cut { consume: take }
        } else {
            Step::More { consume: take }
        }
    }

    /// True when nothing has been kept yet (an empty line, or EOF before any
    /// byte).
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Strip a trailing `\r` (CRLF) and decode lossily — the old
    /// `BufReader::lines()` required valid UTF-8 and silently killed the pump
    /// on the first invalid byte; lossy decoding keeps the stream flowing. The
    /// decoded string is bounded by a constant factor of the cap (each invalid
    /// byte becomes a 3-byte replacement char), never unbounded.
    pub(crate) fn finish(mut self) -> String {
        if self.bytes.last() == Some(&b'\r') {
            self.bytes.pop();
        }
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// Bytes still allowed before the cap.
    fn room(&self) -> usize {
        keep().saturating_sub(self.bytes.len())
    }

    /// Cut the retained bytes at the cap and mark the cut.
    fn mark_cut(&mut self) {
        self.bytes.truncate(keep());
        self.bytes.extend_from_slice(TRUNCATED_MARKER.as_bytes());
    }
}
