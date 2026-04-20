use std::collections::HashMap;
use std::num::NonZeroUsize;

use anyhow::{anyhow, Result};
use zenoh_buffers::{
    reader::{BacktrackableReader, DidntRead, HasReader, Reader},
    ZBuf, ZSlice,
};
use zenoh_codec::{RCodec, Zenoh080};

#[derive(Debug, Clone, Copy)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}

pub type SpanMap = HashMap<String, ByteSpan>;

/// Wraps a byte slice and tracks read position for per-field span recording.
pub struct SpanCursor<'a> {
    full: &'a [u8],
    remaining: &'a [u8],
}

impl<'a> SpanCursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            full: bytes,
            remaining: bytes,
        }
    }

    /// Current byte offset from the start of the buffer.
    pub fn checkpoint(&self) -> usize {
        self.full.len() - self.remaining.len()
    }

    /// Span from `start` (a prior checkpoint) to the current position.
    pub fn span_since(&self, start: usize) -> ByteSpan {
        ByteSpan {
            start,
            end: self.checkpoint(),
        }
    }

    /// Decode a value via the zenoh codec, advancing the cursor.
    pub fn decode<T>(&mut self) -> Result<T>
    where
        for<'d> Zenoh080: RCodec<T, &'d mut Self>,
    {
        Zenoh080::new()
            .read(self)
            .map_err(|_| anyhow!("SpanCursor: codec decode failed"))
    }

    /// Skip all remaining bytes.
    pub fn skip_remaining(&mut self) {
        self.remaining = &self.remaining[self.remaining.len()..];
    }

    /// Skip `n` bytes without recording a span.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        if self.remaining.len() < n {
            return Err(anyhow!("SpanCursor: not enough bytes to skip"));
        }
        self.remaining = &self.remaining[n..];
        Ok(())
    }
}

impl Reader for SpanCursor<'_> {
    fn read(&mut self, into: &mut [u8]) -> Result<NonZeroUsize, DidntRead> {
        self.remaining.read(into)
    }

    fn read_exact(&mut self, into: &mut [u8]) -> Result<(), DidntRead> {
        self.remaining.read_exact(into)
    }

    fn remaining(&self) -> usize {
        self.remaining.remaining()
    }

    fn read_zbuf(&mut self, len: usize) -> Result<ZBuf, DidntRead> {
        self.remaining.read_zbuf(len)
    }

    fn read_zslices<F: FnMut(ZSlice)>(&mut self, len: usize, f: F) -> Result<(), DidntRead> {
        self.remaining.read_zslices(len, f)
    }

    fn read_zslice(&mut self, len: usize) -> Result<ZSlice, DidntRead> {
        self.remaining.read_zslice(len)
    }

    fn read_u8(&mut self) -> Result<u8, DidntRead> {
        self.remaining.read_u8()
    }

    fn can_read(&self) -> bool {
        self.remaining.can_read()
    }
}

impl HasReader for SpanCursor<'_> {
    type Reader = Self;
    fn reader(self) -> Self {
        self
    }
}

/// Mark for backtracking: stores the current `remaining` start offset.
pub struct SpanCursorMark(usize);

impl BacktrackableReader for SpanCursor<'_> {
    type Mark = SpanCursorMark;

    fn mark(&mut self) -> Self::Mark {
        SpanCursorMark(self.checkpoint())
    }

    fn rewind(&mut self, mark: Self::Mark) -> bool {
        self.remaining = &self.full[mark.0..];
        true
    }
}

/// A type that can walk a `SpanCursor` in wire-format order, recording per-field
/// byte spans into `map` under `prefix`.  The cursor must be positioned at the
/// first byte that belongs to this value (i.e., any header/dispatch byte has
/// already been consumed by the caller before invoking this).
pub trait RecordSpans {
    fn record_spans(
        &self,
        cursor: &mut SpanCursor<'_>,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()>;
}
