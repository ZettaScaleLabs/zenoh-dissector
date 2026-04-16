/// Per-message-type span recording: walks a SpanCursor in wire-format order,
/// recording per-field byte positions into a SpanMap.
///
/// The cursor must be positioned at the **first byte of the TransportMessage**
/// (i.e., the header byte) when `record_transport_message_spans` is called.
///
/// Wire-format details follow the zenoh-codec implementations in
/// `zenoh/commons/zenoh-codec/src/transport/`.
use anyhow::Result;

use zenoh_protocol::{
    common::imsg,
    transport::{
        init::flag as init_flag,
        join::flag as join_flag,
        open::flag as open_flag,
        Fragment, Frame, InitAck, InitSyn, Join, KeepAlive, Oam, OpenAck, OpenSyn, TransportBody,
        TransportMessage, TransportSn,
    },
};

use crate::span::{RecordSpans, SpanCursor, SpanMap};

// ---------------------------------------------------------------------------
// Helper: consume and skip the extension chain from the current cursor position.
// Each extension has a 1-byte header; the MSB (0x80) indicates more extensions follow.
// We skip without recording per-extension spans.
// ---------------------------------------------------------------------------
fn skip_extensions(cursor: &mut SpanCursor, has_ext: bool) -> Result<()> {
    let mut remaining = has_ext;
    while remaining {
        let ext_byte: u8 = cursor.decode()?;
        let ext_len: u64 = cursor.decode()?; // VLE body length
        cursor.skip(ext_len as usize)?;
        remaining = (ext_byte & 0x80) != 0;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TransportMessage
// ---------------------------------------------------------------------------

pub fn record_transport_message_spans(
    msg: &TransportMessage,
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
) -> Result<()> {
    msg.record_spans(cursor, prefix, map)
}

impl RecordSpans for TransportMessage {
    fn record_spans(&self, cursor: &mut SpanCursor, prefix: &str, map: &mut SpanMap) -> Result<()> {
        // Byte 0: header byte — determines message type and flags.
        let header: u8 = cursor.decode()?;

        let body_prefix = format!("{prefix}.body");
        match &self.body {
            TransportBody::InitSyn(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.init_syn"), map)
            }
            TransportBody::InitAck(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.init_ack"), map)
            }
            TransportBody::OpenSyn(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.open_syn"), map)
            }
            TransportBody::OpenAck(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.open_ack"), map)
            }
            TransportBody::Frame(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.frame"), map)
            }
            TransportBody::Fragment(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.fragment"), map)
            }
            TransportBody::KeepAlive(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.keep_alive"), map)
            }
            TransportBody::OAM(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.o_a_m"), map)
            }
            TransportBody::Join(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.join"), map)
            }
            TransportBody::Close(_) => {
                // reason and session are packed into the header byte — no separate fields
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InitSyn
// Wire format after header byte:
//   u8: version
//   u8: flags = (zid_size-1) << 4 | whatami
//   [u8; zid_size]: zid
//   if S: u8 resolution, [u8;2] batch_size LE
//   if Z: extensions
// ---------------------------------------------------------------------------
trait RecordSpansWithHeader {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()>;
}

impl RecordSpansWithHeader for InitSyn {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        // version
        let b = cursor.checkpoint();
        let _: u8 = cursor.decode()?;
        map.insert(format!("{prefix}.version"), cursor.span_since(b));

        // flags byte: encodes whatami (low 2 bits) + zid_size-1 (high 4 bits)
        let b = cursor.checkpoint();
        let flags: u8 = cursor.decode()?;
        map.insert(format!("{prefix}.whatami"), cursor.span_since(b));
        let zid_size = ((flags >> 4) as usize) + 1;

        // zid
        let b = cursor.checkpoint();
        cursor.skip(zid_size)?;
        map.insert(format!("{prefix}.zid"), cursor.span_since(b));

        // conditional: resolution + batch_size
        if imsg::has_flag(header, init_flag::S) {
            let b = cursor.checkpoint();
            let _: u8 = cursor.decode()?;
            map.insert(format!("{prefix}.resolution"), cursor.span_since(b));

            let b = cursor.checkpoint();
            let _: [u8; 2] = cursor.decode()?;
            map.insert(format!("{prefix}.batch_size"), cursor.span_since(b));
        }

        skip_extensions(cursor, imsg::has_flag(header, init_flag::Z))
    }
}

impl RecordSpans for InitSyn {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(()) // used only via record_spans_with_header
    }
}

// ---------------------------------------------------------------------------
// InitAck — same layout as InitSyn plus a ZSlice cookie at the end
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for InitAck {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        let b = cursor.checkpoint();
        let _: u8 = cursor.decode()?;
        map.insert(format!("{prefix}.version"), cursor.span_since(b));

        let b = cursor.checkpoint();
        let flags: u8 = cursor.decode()?;
        map.insert(format!("{prefix}.whatami"), cursor.span_since(b));
        let zid_size = ((flags >> 4) as usize) + 1;

        let b = cursor.checkpoint();
        cursor.skip(zid_size)?;
        map.insert(format!("{prefix}.zid"), cursor.span_since(b));

        if imsg::has_flag(header, init_flag::S) {
            let b = cursor.checkpoint();
            let _: u8 = cursor.decode()?;
            map.insert(format!("{prefix}.resolution"), cursor.span_since(b));

            let b = cursor.checkpoint();
            let _: [u8; 2] = cursor.decode()?;
            map.insert(format!("{prefix}.batch_size"), cursor.span_since(b));
        }

        // cookie: VLE length + data
        let b = cursor.checkpoint();
        let cookie_len: u64 = cursor.decode()?;
        cursor.skip(cookie_len as usize)?;
        map.insert(format!("{prefix}.cookie"), cursor.span_since(b));

        skip_extensions(cursor, imsg::has_flag(header, init_flag::Z))
    }
}

impl RecordSpans for InitAck {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OpenSyn: VLE lease, VLE initial_sn, ZSlice cookie, extensions
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for OpenSyn {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        let b = cursor.checkpoint();
        let _: u64 = cursor.decode()?; // lease (VLE)
        map.insert(format!("{prefix}.lease"), cursor.span_since(b));

        let b = cursor.checkpoint();
        let _: TransportSn = cursor.decode()?; // initial_sn (VLE)
        map.insert(format!("{prefix}.initial_sn"), cursor.span_since(b));

        let b = cursor.checkpoint();
        let cookie_len: u64 = cursor.decode()?; // VLE len + data
        cursor.skip(cookie_len as usize)?;
        map.insert(format!("{prefix}.cookie"), cursor.span_since(b));

        skip_extensions(cursor, imsg::has_flag(header, open_flag::Z))
    }
}

impl RecordSpans for OpenSyn {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OpenAck: VLE lease, VLE initial_sn, extensions
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for OpenAck {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        let b = cursor.checkpoint();
        let _: u64 = cursor.decode()?;
        map.insert(format!("{prefix}.lease"), cursor.span_since(b));

        let b = cursor.checkpoint();
        let _: TransportSn = cursor.decode()?;
        map.insert(format!("{prefix}.initial_sn"), cursor.span_since(b));

        skip_extensions(cursor, imsg::has_flag(header, open_flag::Z))
    }
}

impl RecordSpans for OpenAck {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Frame: VLE sn, (optional extensions), then NetworkMessages
// reliability is in the header R flag — not a separate byte field
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for Frame {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        let b = cursor.checkpoint();
        let _: TransportSn = cursor.decode()?; // sn (VLE u64)
        map.insert(format!("{prefix}.sn"), cursor.span_since(b));

        // ext_qos + payload bytes are not per-field tracked here;
        // they fall back to the parent message span in the protocol tree.
        let _ = (header, map, prefix); // suppress unused warnings
        Ok(())
    }
}

impl RecordSpans for Frame {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fragment: VLE sn, (optional extensions), then payload ZSlice
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for Fragment {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        let b = cursor.checkpoint();
        let _: TransportSn = cursor.decode()?;
        map.insert(format!("{prefix}.sn"), cursor.span_since(b));

        let _ = (header, prefix, map);
        Ok(())
    }
}

impl RecordSpans for Fragment {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// KeepAlive: no body fields (all info in header byte)
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for KeepAlive {
    fn record_spans_with_header(
        &self,
        _header: u8,
        _cursor: &mut SpanCursor,
        _prefix: &str,
        _map: &mut SpanMap,
    ) -> Result<()> {
        Ok(())
    }
}

impl RecordSpans for KeepAlive {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Oam: VLE id, then extension body
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for Oam {
    fn record_spans_with_header(
        &self,
        _header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        let b = cursor.checkpoint();
        let _: u64 = cursor.decode()?; // id (VLE)
        map.insert(format!("{prefix}.id"), cursor.span_since(b));
        Ok(())
    }
}

impl RecordSpans for Oam {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Join: similar to InitSyn but with lease and next_sn fields
// Wire format after header: version, flags(whatami+zidsize), zid,
//   if S: resolution, batch_size,
//   VLE lease, VLE next_sn (complex PrioritySn), extensions
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for Join {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        let b = cursor.checkpoint();
        let _: u8 = cursor.decode()?;
        map.insert(format!("{prefix}.version"), cursor.span_since(b));

        let b = cursor.checkpoint();
        let flags: u8 = cursor.decode()?;
        map.insert(format!("{prefix}.whatami"), cursor.span_since(b));
        let zid_size = ((flags >> 4) as usize) + 1;

        let b = cursor.checkpoint();
        cursor.skip(zid_size)?;
        map.insert(format!("{prefix}.zid"), cursor.span_since(b));

        if imsg::has_flag(header, join_flag::S) {
            let b = cursor.checkpoint();
            let _: u8 = cursor.decode()?;
            map.insert(format!("{prefix}.resolution"), cursor.span_since(b));

            let b = cursor.checkpoint();
            let _: [u8; 2] = cursor.decode()?;
            map.insert(format!("{prefix}.batch_size"), cursor.span_since(b));
        }

        let b = cursor.checkpoint();
        let _: u64 = cursor.decode()?; // lease (VLE)
        map.insert(format!("{prefix}.lease"), cursor.span_since(b));

        // next_sn (PrioritySn) is complex — skip per-field tracking
        let _ = (prefix, map);
        Ok(())
    }
}

impl RecordSpans for Join {
    fn record_spans(&self, _cursor: &mut SpanCursor, _prefix: &str, _map: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}
