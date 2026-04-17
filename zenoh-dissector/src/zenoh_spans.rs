/// Per-message-type span recording: walks a SpanCursor in wire-format order,
/// recording per-field byte positions into a SpanMap.
///
/// Wire-format details follow the zenoh-codec implementations in
/// `zenoh/commons/zenoh-codec/src/`.
use anyhow::Result;

use zenoh_protocol::{
    common::{iext, imsg},
    network::{
        declare,
        id as net_id,
        push::flag as push_flag,
        request::flag as req_flag,
        response::flag as resp_flag,
    },
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
// Extension wire format:
//   header byte: bits 7=FLAG_Z (more), bits 6:5=ENC_MASK, bits 4:0=ID
//   ENC_UNIT (0x00 in bits 6:5): 1 byte total, no body
//   ENC_Z64  (0x20 in bits 6:5): VLE u64 body
//   ENC_ZBUF (0x40 in bits 6:5): VLE-length + data bytes
// ---------------------------------------------------------------------------

/// Walk extensions, recording spans for known extension headers.
/// `hdr_to_field` maps `ext_byte & !FLAG_Z` (id + encoding bits) to field name suffix.
/// This allows disambiguation when two extensions share the same ID but differ in encoding.
/// Unknown extensions are consumed and skipped without recording.
fn record_extension_spans(
    cursor: &mut SpanCursor,
    has_ext: bool,
    prefix: &str,
    hdr_to_field: &[(u8, &str)],
    map: &mut SpanMap,
) -> Result<()> {
    let mut remaining = has_ext;
    while remaining {
        let start = cursor.checkpoint();
        let ext_byte: u8 = cursor.decode()?;
        match ext_byte & iext::ENC_MASK {
            iext::ENC_UNIT => {}
            iext::ENC_Z64 => {
                let _: u64 = cursor.decode()?;
            }
            iext::ENC_ZBUF => {
                let body_len: u64 = cursor.decode()?;
                cursor.skip(body_len as usize)?;
            }
            _ => return Err(anyhow::anyhow!("unknown extension encoding")),
        }
        // Match on (enc | id) ignoring FLAG_Z
        let key = ext_byte & !iext::FLAG_Z;
        if let Some(&(_, fname)) = hdr_to_field.iter().find(|&&(k, _)| k == key) {
            map.insert(format!("{prefix}.{fname}"), cursor.span_since(start));
        }
        remaining = (ext_byte & iext::FLAG_Z) != 0;
    }
    Ok(())
}

fn skip_extensions(cursor: &mut SpanCursor, has_ext: bool) -> Result<()> {
    record_extension_spans(cursor, has_ext, "", &[], &mut SpanMap::new())
}

// ---------------------------------------------------------------------------
// WireExpr: scope (VLE u16) + optional suffix (VLE-len u16 + string bytes)
// `has_suffix` = N flag in the message header.
// ---------------------------------------------------------------------------
/// Record spans for a WireExpr field.
/// `prefix` is the full key for the wire_expr field itself (e.g. "zenoh.body.frame.payload.body.push.wire_expr").
/// Emits:
///   `{prefix}`          — whole WireExpr byte range (scope + suffix if present)
///   `{prefix}.scope`    — just the scope VLE bytes
///   `{prefix}.suffix`   — VLE-length + string bytes (only when has_suffix)
fn record_wire_expr_spans(
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
    has_suffix: bool,
) -> Result<()> {
    let whole_start = cursor.checkpoint();

    let b = cursor.checkpoint();
    let _: u64 = cursor.decode()?; // scope (VLE-bounded u16)
    map.insert(format!("{prefix}.scope"), cursor.span_since(b));

    if has_suffix {
        let b = cursor.checkpoint();
        let str_len: u64 = cursor.decode()?; // VLE length
        cursor.skip(str_len as usize)?;
        map.insert(format!("{prefix}.suffix"), cursor.span_since(b));
    }

    // Whole-field span covers everything decoded above
    map.insert(prefix.to_string(), cursor.span_since(whole_start));
    Ok(())
}

// ---------------------------------------------------------------------------
// Transport-level public entry point
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
    fn record_spans(
        &self,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
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
                m.record_spans_with_header(
                    header,
                    cursor,
                    &format!("{body_prefix}.fragment"),
                    map,
                )
            }
            TransportBody::KeepAlive(m) => m.record_spans_with_header(
                header,
                cursor,
                &format!("{body_prefix}.keep_alive"),
                map,
            ),
            TransportBody::OAM(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.o_a_m"), map)
            }
            TransportBody::Join(m) => {
                m.record_spans_with_header(header, cursor, &format!("{body_prefix}.join"), map)
            }
            TransportBody::Close(_) => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-message helper trait
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

// ---------------------------------------------------------------------------
// InitSyn / InitAck
// After header byte:
//   u8 version, u8 flags(whatami|zid_size), [u8;zid_size] zid
//   if S: u8 resolution, [u8;2] batch_size LE
//   if InitAck: VLE cookie_len + cookie bytes
//   if Z: extensions
// ---------------------------------------------------------------------------
fn record_init_spans(
    header: u8,
    is_ack: bool,
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

    if is_ack {
        let b = cursor.checkpoint();
        let cookie_len: u64 = cursor.decode()?;
        cursor.skip(cookie_len as usize)?;
        map.insert(format!("{prefix}.cookie"), cursor.span_since(b));
    }

    // InitSyn/InitAck extensions: QoS=UNIT|0x1=0x01, QoSLink=Z64|0x1=0x21, Auth=ZBUF|0x3=0x43, MLink=ZBUF|0x4=0x44
    record_extension_spans(
        cursor,
        imsg::has_flag(header, init_flag::Z),
        prefix,
        &[
            (iext::ENC_UNIT | 0x1, "ext_qos"),
            (iext::ENC_Z64 | 0x1, "ext_qos_link"),
            (iext::ENC_ZBUF | 0x3, "ext_auth"),
            (iext::ENC_ZBUF | 0x4, "ext_mlink"),
        ],
        map,
    )
}

impl RecordSpansWithHeader for InitSyn {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        record_init_spans(header, false, cursor, prefix, map)
    }
}
impl RecordSpans for InitSyn {
    fn record_spans(
        &self,
        _c: &mut SpanCursor,
        _p: &str,
        _m: &mut SpanMap,
    ) -> Result<()> {
        Ok(())
    }
}

impl RecordSpansWithHeader for InitAck {
    fn record_spans_with_header(
        &self,
        header: u8,
        cursor: &mut SpanCursor,
        prefix: &str,
        map: &mut SpanMap,
    ) -> Result<()> {
        record_init_spans(header, true, cursor, prefix, map)
    }
}
impl RecordSpans for InitAck {
    fn record_spans(
        &self,
        _c: &mut SpanCursor,
        _p: &str,
        _m: &mut SpanMap,
    ) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OpenSyn: VLE lease, VLE initial_sn, VLE+data cookie, extensions
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
        let _: u64 = cursor.decode()?;
        map.insert(format!("{prefix}.lease"), cursor.span_since(b));

        let b = cursor.checkpoint();
        let _: TransportSn = cursor.decode()?;
        map.insert(format!("{prefix}.initial_sn"), cursor.span_since(b));

        let b = cursor.checkpoint();
        let cookie_len: u64 = cursor.decode()?;
        cursor.skip(cookie_len as usize)?;
        map.insert(format!("{prefix}.cookie"), cursor.span_since(b));

        // OpenSyn extensions: QoS=UNIT|0x1=0x01, Auth=ZBUF|0x3=0x43, MLink=ZBUF|0x4=0x44
        record_extension_spans(
            cursor,
            imsg::has_flag(header, open_flag::Z),
            prefix,
            &[
                (iext::ENC_UNIT | 0x1, "ext_qos"),
                (iext::ENC_ZBUF | 0x3, "ext_auth"),
                (iext::ENC_ZBUF | 0x4, "ext_mlink"),
            ],
            map,
        )
    }
}
impl RecordSpans for OpenSyn {
    fn record_spans(&self, _c: &mut SpanCursor, _p: &str, _m: &mut SpanMap) -> Result<()> {
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

        // OpenAck extensions: QoS=UNIT|0x1=0x01, Auth=ZBUF|0x3=0x43, MLink=UNIT|0x4=0x04
        record_extension_spans(
            cursor,
            imsg::has_flag(header, open_flag::Z),
            prefix,
            &[
                (iext::ENC_UNIT | 0x1, "ext_qos"),
                (iext::ENC_ZBUF | 0x3, "ext_auth"),
                (iext::ENC_UNIT | 0x4, "ext_mlink"),
            ],
            map,
        )
    }
}
impl RecordSpans for OpenAck {
    fn record_spans(&self, _c: &mut SpanCursor, _p: &str, _m: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Frame: VLE sn, extensions, then zero or more NetworkMessages
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
        let _: TransportSn = cursor.decode()?;
        map.insert(format!("{prefix}.sn"), cursor.span_since(b));

        // extensions (ext_qos only for Frame)
        skip_extensions(cursor, imsg::has_flag(header, 0x80))?;

        // Walk each NetworkMessage payload and record spans.
        // All messages use the same prefix key since impl_for_struct! uses the
        // field name (not an index) — in frames with multiple messages, the last
        // decoded message's spans overwrite earlier ones, which is acceptable.
        let payload_prefix = format!("{prefix}.payload");
        for nmsg in &self.payload {
            if let Err(e) = record_network_message_spans(nmsg, cursor, &payload_prefix, map) {
                log::debug!("network message span error at {payload_prefix}: {e}");
                break;
            }
        }
        Ok(())
    }
}
impl RecordSpans for Frame {
    fn record_spans(&self, _c: &mut SpanCursor, _p: &str, _m: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fragment: VLE sn, extensions, remaining bytes = payload
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

        skip_extensions(cursor, imsg::has_flag(header, 0x80))
    }
}
impl RecordSpans for Fragment {
    fn record_spans(&self, _c: &mut SpanCursor, _p: &str, _m: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// KeepAlive: no fields after header
// ---------------------------------------------------------------------------
impl RecordSpansWithHeader for KeepAlive {
    fn record_spans_with_header(
        &self,
        _h: u8,
        _c: &mut SpanCursor,
        _p: &str,
        _m: &mut SpanMap,
    ) -> Result<()> {
        Ok(())
    }
}
impl RecordSpans for KeepAlive {
    fn record_spans(&self, _c: &mut SpanCursor, _p: &str, _m: &mut SpanMap) -> Result<()> {
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
        let _: u64 = cursor.decode()?;
        map.insert(format!("{prefix}.id"), cursor.span_since(b));
        Ok(())
    }
}
impl RecordSpans for Oam {
    fn record_spans(&self, _c: &mut SpanCursor, _p: &str, _m: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Join: version, flags/whatami/zid, optional resolution+batch_size, VLE lease
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
        let _: u64 = cursor.decode()?;
        map.insert(format!("{prefix}.lease"), cursor.span_since(b));

        // next_sn (PrioritySn) is complex — omit per-field, fall back to parent
        Ok(())
    }
}
impl RecordSpans for Join {
    fn record_spans(&self, _c: &mut SpanCursor, _p: &str, _m: &mut SpanMap) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NetworkMessage span recording
// Cursor must be positioned at the header byte of the NetworkMessage.
// ---------------------------------------------------------------------------
fn record_network_message_spans(
    msg: &zenoh_protocol::network::NetworkMessage,
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
) -> Result<()> {
    use zenoh_protocol::network::NetworkBody;

    let header: u8 = cursor.decode()?;
    let mid = imsg::mid(header);

    match &msg.body {
        NetworkBody::Push(_) if mid == net_id::PUSH => {
            record_push_spans(header, cursor, &format!("{prefix}.body"), map)
        }
        NetworkBody::Request(_) if mid == net_id::REQUEST => {
            record_request_spans(header, cursor, &format!("{prefix}.body"), map)
        }
        NetworkBody::Response(_) if mid == net_id::RESPONSE => {
            record_response_spans(header, cursor, &format!("{prefix}.body"), map)
        }
        NetworkBody::ResponseFinal(_) if mid == net_id::RESPONSE_FINAL => {
            record_response_final_spans(header, cursor, &format!("{prefix}.body"), map)
        }
        NetworkBody::Declare(_) if mid == net_id::DECLARE => {
            record_declare_spans(header, cursor, &format!("{prefix}.body"), map)
        }
        _ => {
            // Unknown/OAM — skip this message's bytes; we can't know the length here
            // without re-decoding, so we just stop span recording for this message.
            Ok(())
        }
    }
}

// Extension header (enc|id, without FLAG_Z) → field name for network messages.
// Push/Request/Declare: QoS=Z64|0x1=0x21, Timestamp=ZBUF|0x2=0x42, NodeId=Z64|0x3=0x23
const NET_EXT: &[(u8, &str)] = &[
    (iext::ENC_Z64 | 0x1, "ext_qos"),
    (iext::ENC_ZBUF | 0x2, "ext_tstamp"),
    (iext::ENC_Z64 | 0x3, "ext_nodeid"),
];

// ---------------------------------------------------------------------------
// Push: WireExpr (scope + optional suffix), extensions
// ---------------------------------------------------------------------------
fn record_push_spans(
    header: u8,
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
) -> Result<()> {
    let has_suffix = imsg::has_flag(header, push_flag::N);
    record_wire_expr_spans(cursor, &format!("{prefix}.push.wire_expr"), map, has_suffix)?;
    record_extension_spans(
        cursor,
        imsg::has_flag(header, push_flag::Z),
        &format!("{prefix}.push"),
        NET_EXT,
        map,
    )
}

// ---------------------------------------------------------------------------
// Request: VLE id, WireExpr, extensions
// ---------------------------------------------------------------------------
fn record_request_spans(
    header: u8,
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
) -> Result<()> {
    let b = cursor.checkpoint();
    let _: u64 = cursor.decode()?; // request id (Zenoh080Bounded::<u32>)
    map.insert(format!("{prefix}.request.id"), cursor.span_since(b));

    let has_suffix = imsg::has_flag(header, req_flag::N);
    record_wire_expr_spans(cursor, &format!("{prefix}.request.wire_expr"), map, has_suffix)?;
    record_extension_spans(
        cursor,
        imsg::has_flag(header, req_flag::Z),
        &format!("{prefix}.request"),
        NET_EXT,
        map,
    )
}

// ---------------------------------------------------------------------------
// Response: VLE rid, WireExpr, extensions
// ---------------------------------------------------------------------------
fn record_response_spans(
    header: u8,
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
) -> Result<()> {
    let b = cursor.checkpoint();
    let _: u64 = cursor.decode()?; // request id
    map.insert(format!("{prefix}.response.rid"), cursor.span_since(b));

    let has_suffix = imsg::has_flag(header, resp_flag::N);
    record_wire_expr_spans(cursor, &format!("{prefix}.response.wire_expr"), map, has_suffix)?;
    // Response extensions: QoS=Z64|0x1, Timestamp=ZBUF|0x2 — no NodeId
    record_extension_spans(
        cursor,
        imsg::has_flag(header, resp_flag::Z),
        &format!("{prefix}.response"),
        &[(iext::ENC_Z64 | 0x1, "ext_qos"), (iext::ENC_ZBUF | 0x2, "ext_tstamp")],
        map,
    )
}

// ---------------------------------------------------------------------------
// ResponseFinal: VLE rid, extensions
// ---------------------------------------------------------------------------
fn record_response_final_spans(
    header: u8,
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
) -> Result<()> {
    let b = cursor.checkpoint();
    let _: u64 = cursor.decode()?;
    map.insert(format!("{prefix}.response_final.rid"), cursor.span_since(b));
    skip_extensions(cursor, imsg::has_flag(header, 0x80))
}

// ---------------------------------------------------------------------------
// Declare: optional interest_id (VLE), extensions, then DeclareBody
// DeclareBody: 1-byte header + body
// ---------------------------------------------------------------------------
fn record_declare_spans(
    header: u8,
    cursor: &mut SpanCursor,
    prefix: &str,
    map: &mut SpanMap,
) -> Result<()> {
    if imsg::has_flag(header, declare::flag::I) {
        let b = cursor.checkpoint();
        let _: u64 = cursor.decode()?; // interest_id (VLE)
        map.insert(format!("{prefix}.declare.interest_id"), cursor.span_since(b));
    }

    record_extension_spans(
        cursor,
        imsg::has_flag(header, declare::flag::Z),
        &format!("{prefix}.declare"),
        NET_EXT,
        map,
    )?;

    // DeclareBody header byte
    let db_header: u8 = cursor.decode()?;
    let db_mid = imsg::mid(db_header);

    use declare::id::*;
    match db_mid {
        D_KEYEXPR => {
            // VLE expr_id + WireExpr
            let b = cursor.checkpoint();
            let _: u64 = cursor.decode()?;
            map.insert(
                format!("{prefix}.declare.body.declare_key_expr.id"),
                cursor.span_since(b),
            );
            let has_suffix = imsg::has_flag(db_header, 0x20); // N flag
            record_wire_expr_spans(
                cursor,
                &format!("{prefix}.declare.body.declare_key_expr.wire_expr"),
                map,
                has_suffix,
            )?;
            skip_extensions(cursor, imsg::has_flag(db_header, 0x80))?;
        }
        D_SUBSCRIBER => {
            let b = cursor.checkpoint();
            let _: u64 = cursor.decode()?; // subscriber id
            map.insert(
                format!("{prefix}.declare.body.declare_subscriber.id"),
                cursor.span_since(b),
            );
            let has_suffix = imsg::has_flag(db_header, 0x20);
            record_wire_expr_spans(
                cursor,
                &format!("{prefix}.declare.body.declare_subscriber.wire_expr"),
                map,
                has_suffix,
            )?;
            skip_extensions(cursor, imsg::has_flag(db_header, 0x80))?;
        }
        D_QUERYABLE => {
            let b = cursor.checkpoint();
            let _: u64 = cursor.decode()?;
            map.insert(
                format!("{prefix}.declare.body.declare_queryable.id"),
                cursor.span_since(b),
            );
            let has_suffix = imsg::has_flag(db_header, 0x20);
            record_wire_expr_spans(
                cursor,
                &format!("{prefix}.declare.body.declare_queryable.wire_expr"),
                map,
                has_suffix,
            )?;
            skip_extensions(cursor, imsg::has_flag(db_header, 0x80))?;
        }
        D_TOKEN => {
            let b = cursor.checkpoint();
            let _: u64 = cursor.decode()?;
            map.insert(
                format!("{prefix}.declare.body.declare_token.id"),
                cursor.span_since(b),
            );
            let has_suffix = imsg::has_flag(db_header, 0x20);
            record_wire_expr_spans(
                cursor,
                &format!("{prefix}.declare.body.declare_token.wire_expr"),
                map,
                has_suffix,
            )?;
            skip_extensions(cursor, imsg::has_flag(db_header, 0x80))?;
        }
        _ => {} // U_* and D_FINAL: skip, fall back to parent span
    }

    Ok(())
}
