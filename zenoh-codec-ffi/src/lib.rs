mod header_field;
mod macros;
pub mod span;
pub mod zenoh_impl;
pub mod zenoh_spans;

use std::ffi::c_char;
use std::sync::OnceLock;

use header_field::{FieldKind, Registration};
use span::{SpanCursor, SpanMap};
use zenoh_impl::ZenohProtocol;
use zenoh_spans::{record_scouting_message_spans, record_transport_message_spans};

/// Maximum length of a field key or display name string in the C ABI (including null terminator).
pub const ZENOH_FFI_KEY_LEN: usize = 128;

/// A field definition returned to the C plugin at startup.
/// Both arrays are null-terminated strings.
#[repr(C)]
pub struct CFieldDef {
    pub key: [c_char; ZENOH_FFI_KEY_LEN],
    pub display_name: [c_char; ZENOH_FFI_KEY_LEN],
    /// 1 = branch/subtree node (FT_NONE), 0 = leaf field (FT_BYTES).
    pub is_branch: u8,
}

/// A single decoded field with its byte span in the original wire data.
/// The `key` is a null-terminated string matching a registered field abbrev.
/// `start` and `length` are byte offsets relative to the PDU payload (after the 2-byte TCP length prefix).
/// `display` is an optional null-terminated human-readable value string (empty string = no override).
/// `replace_display`: if non-zero, `display` replaces the whole item label; otherwise it is appended in parens.
#[repr(C)]
pub struct CSpanEntry {
    pub key: [c_char; ZENOH_FFI_KEY_LEN],
    pub start: u32,
    pub length: u32,
    pub display: [c_char; ZENOH_FFI_KEY_LEN],
    pub replace_display: u8,
}

// ---------------------------------------------------------------------------
// Static startup data (never freed)
// ---------------------------------------------------------------------------

struct StaticFields {
    fields: Vec<CFieldDef>,
}
// SAFETY: CFieldDef contains only [c_char; N] arrays (plain integers). No interior mutability.
unsafe impl Sync for StaticFields {}

struct StaticSubtrees {
    _strings: Vec<std::ffi::CString>,
    ptrs: Vec<*const c_char>,
}
// SAFETY: pointers into _strings, which outlives any use after OnceLock init.
unsafe impl Sync for StaticSubtrees {}
unsafe impl Send for StaticSubtrees {}

static FIELDS: OnceLock<StaticFields> = OnceLock::new();
static SUBTREES: OnceLock<StaticSubtrees> = OnceLock::new();

fn fill_c_str(arr: &mut [c_char; ZENOH_FFI_KEY_LEN], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(ZENOH_FFI_KEY_LEN - 1);
    for (i, &b) in bytes[..n].iter().enumerate() {
        arr[i] = b as c_char;
    }
    arr[n] = 0;
    for b in arr.iter_mut().skip(n + 1) {
        *b = 0;
    }
}

fn make_cfield(key: &str, display_name: &str, is_branch: bool) -> CFieldDef {
    let mut f = CFieldDef {
        key: [0; ZENOH_FFI_KEY_LEN],
        display_name: [0; ZENOH_FFI_KEY_LEN],
        is_branch: is_branch as u8,
    };
    fill_c_str(&mut f.key, key);
    fill_c_str(&mut f.display_name, display_name);
    f
}

/// Decode a VLE integer from `bytes`, returning (value, bytes_consumed).
fn decode_vle(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut val = 0u64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((val, i + 1));
        }
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn encoding_name(id: u64) -> &'static str {
    match id {
        0 => "ZenohBytes",
        1 => "ZenohString",
        2 => "ZenohSerialized",
        3 => "application/octet-stream",
        4 => "text/plain",
        5 => "application/json",
        6 => "text/json",
        7 => "application/cdr",
        8 => "application/cbor",
        9 => "application/yaml",
        10 => "text/yaml",
        11 => "text/json5",
        12 => "application/python-serialized-object",
        13 => "application/protobuf",
        14 => "application/java-serialized-object",
        15 => "application/openmetrics-text",
        16 => "image/png",
        17 => "image/jpeg",
        18 => "image/gif",
        19 => "image/bmp",
        20 => "image/webp",
        21 => "application/xml",
        22 => "application/x-www-form-urlencoded",
        23 => "text/html",
        24 => "text/xml",
        25 => "text/css",
        26 => "text/javascript",
        27 => "text/markdown",
        28 => "text/csv",
        29 => "application/sql",
        30 => "application/coap-payload",
        31 => "application/json-patch+json",
        32 => "application/json-seq",
        33 => "application/jsonpath",
        34 => "application/jwt",
        35 => "application/mp4",
        36 => "application/soap+xml",
        37 => "application/yang",
        38 => "audio/aac",
        39 => "audio/flac",
        40 => "audio/mp4",
        41 => "audio/ogg",
        42 => "audio/vorbis",
        43 => "video/h261",
        44 => "video/h263",
        45 => "video/h264",
        46 => "video/h265",
        47 => "video/h266",
        48 => "video/mp4",
        49 => "video/ogg",
        _ => "",
    }
}

/// Returns `(display_string, replace)`.
/// When `replace` is true the display string should replace the raw-bytes label entirely.
fn build_display(key: &str, bytes: &[u8]) -> (String, bool) {
    if bytes.is_empty() {
        return (String::new(), false);
    }
    let suffix = key.rsplit('.').next().unwrap_or("");
    let s = match suffix {
        "whatami" => {
            // Packed wire value, not a WhatAmI bitmask: the low two bits hold
            // Router=0, Peer=1, Client=2 (see the Init, Join and Hello codecs).
            match bytes[0] & 0b11 {
                0 => "Router".to_string(),
                1 => "Peer".to_string(),
                2 => "Client".to_string(),
                v => format!("0x{v:02x}"),
            }
        }
        "batch_size" => {
            // Two bytes, little-endian. Not a VLE integer.
            match bytes {
                [lo, hi] => u16::from_le_bytes([*lo, *hi]).to_string(),
                _ => String::new(),
            }
        }
        "reliability" => {
            if (bytes[0] >> 5) & 1 == 1 {
                "Reliable".to_string()
            } else {
                "BestEffort".to_string()
            }
        }
        "encoding" => {
            if let Some((enc_raw, _)) = decode_vle(bytes) {
                let id = enc_raw >> 1;
                let has_schema = enc_raw & 1 != 0;
                let name = encoding_name(id);
                if name.is_empty() {
                    format!("id={id}")
                } else if has_schema {
                    format!("{name} (with schema)")
                } else {
                    name.to_string()
                }
            } else {
                String::new()
            }
        }
        "reason" => match bytes[0] {
            0x00 => "Generic".to_string(),
            0x01 => "Unsupported".to_string(),
            0x02 => "Invalid".to_string(),
            0x03 => "MaxSessions".to_string(),
            0x04 => "MaxLinks".to_string(),
            0x05 => "Expired".to_string(),
            0x06 => "Unresponsive".to_string(),
            0x07 => "ConnectionToSelf".to_string(),
            v => format!("0x{v:02x}"),
        },
        "ext_qos" | "ext_qos_link" => {
            // ENC_UNIT (1 byte): default priority, no body.
            // ENC_Z64 (header + VLE): body value & 0b111 = Priority.
            let priority = if bytes.len() == 1 {
                5 // Priority::Data (default)
            } else {
                // skip header byte, decode VLE body
                decode_vle(&bytes[1..])
                    .map(|(v, _)| (v as u8 & 0b111) as u64)
                    .unwrap_or(5)
            };
            let name = match priority {
                1 => "RealTime",
                2 => "InteractiveHigh",
                3 => "InteractiveLow",
                4 => "DataHigh",
                5 => "Data",
                6 => "DataLow",
                7 => "Background",
                _ => "Unknown",
            };
            name.to_string()
        }
        "version" => format!("{}", bytes[0]),
        "wire_expr" => {
            // bytes: scope_VLE [+ suffix_len_VLE + suffix_bytes]
            let Some((scope, scope_sz)) = decode_vle(bytes) else {
                return (String::new(), false);
            };
            let rest = &bytes[scope_sz..];
            let decoded = if rest.is_empty() {
                if scope != 0 {
                    format!("scope={scope}")
                } else {
                    String::new()
                }
            } else {
                let Some((str_len, len_sz)) = decode_vle(rest) else {
                    return (String::new(), false);
                };
                let str_end = len_sz + str_len as usize;
                let kexpr_suffix = rest
                    .get(len_sz..str_end)
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .unwrap_or("");
                if scope == 0 {
                    kexpr_suffix.to_string()
                } else {
                    format!("{scope}/{kexpr_suffix}")
                }
            };
            return (decoded, true);
        }
        "scope" | "id" | "initial_sn" | "lease" | "sn" => {
            if let Some((v, _)) = decode_vle(bytes) {
                format!("{v}")
            } else {
                String::new()
            }
        }
        _ => String::new(),
    };
    (s, false)
}

fn make_cspan(key: &str, start: usize, length: usize, display: &str, replace: bool) -> CSpanEntry {
    let mut e = CSpanEntry {
        key: [0; ZENOH_FFI_KEY_LEN],
        start: start as u32,
        length: length as u32,
        display: [0; ZENOH_FFI_KEY_LEN],
        replace_display: replace as u8,
    };
    fill_c_str(&mut e.key, key);
    fill_c_str(&mut e.display, display);
    e
}

// ---------------------------------------------------------------------------
// Startup-time exports (static lifetime, never freed)
// ---------------------------------------------------------------------------

/// Returns a pointer to a static array of `CFieldDef`, writing the count to `*out_count`.
/// The returned pointer is valid for the lifetime of the process.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn zenoh_codec_ffi_get_fields(out_count: *mut u32) -> *const CFieldDef {
    let state = FIELDS.get_or_init(|| {
        let hf_map = ZenohProtocol::generate_hf_map("zenoh");
        let mut fields: Vec<CFieldDef> = hf_map
            .iter()
            .map(|(key, field)| {
                make_cfield(key, &field.name, matches!(field.kind, FieldKind::Branch))
            })
            .collect();
        // Sort for deterministic order (makes C-side debugging easier)
        fields.sort_by_key(|a| a.key);
        StaticFields { fields }
    });
    if !out_count.is_null() {
        unsafe { *out_count = state.fields.len() as u32 };
    }
    state.fields.as_ptr()
}

/// Returns a pointer to a static array of null-terminated subtree key strings.
/// The returned pointer and all string pointers within are valid for the lifetime of the process.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn zenoh_codec_ffi_get_subtrees(out_count: *mut u32) -> *const *const c_char {
    let state = SUBTREES.get_or_init(|| {
        let names = ZenohProtocol::generate_subtree_names("zenoh");
        let strings: Vec<std::ffi::CString> = names
            .into_iter()
            .map(|s| std::ffi::CString::new(s).unwrap())
            .collect();
        let ptrs: Vec<*const c_char> = strings.iter().map(|s| s.as_ptr()).collect();
        StaticSubtrees {
            _strings: strings,
            ptrs,
        }
    });
    if !out_count.is_null() {
        unsafe { *out_count = state.ptrs.len() as u32 };
    }
    state.ptrs.as_ptr()
}

// ---------------------------------------------------------------------------
// Per-packet decode
// ---------------------------------------------------------------------------

/// Strip `[N]` index tokens from a span key so network-message indices
/// (e.g. `frame.network[0].push.wire_expr`) map to registered field names
/// (`frame.network.push.wire_expr`).
fn strip_indices(key: &str) -> std::borrow::Cow<'_, str> {
    if !key.contains('[') {
        return std::borrow::Cow::Borrowed(key);
    }
    let mut out = String::with_capacity(key.len());
    let mut chars = key.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' {
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc == ']' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Order spans as they appear on the wire: by start offset, and an enclosing span before the
/// spans it contains. `SpanMap` is a `HashMap`, so without this the order is arbitrary and a
/// reader cannot pair a declaration's id with its own suffix.
fn sort_wire_order(entries: &mut [CSpanEntry]) {
    // Equal ranges happen when a parent holds a single child. The parent's key is the prefix of
    // the child's, so the shorter key goes first.
    let key_len = |e: &CSpanEntry| e.key.iter().position(|&c| c == 0).unwrap_or(e.key.len());
    entries.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.length.cmp(&a.length))
            .then(key_len(a).cmp(&key_len(b)))
    });
}

fn span_map_to_box(map: &SpanMap, raw: &[u8]) -> Box<[CSpanEntry]> {
    let entries: Vec<CSpanEntry> = map
        .iter()
        .map(|(key, span)| {
            let stripped = strip_indices(key);
            let span_bytes = raw.get(span.start..span.start + span.len()).unwrap_or(&[]);
            let (display, replace) = build_display(&stripped, span_bytes);
            make_cspan(&stripped, span.start, span.len(), &display, replace)
        })
        .collect();
    entries.into_boxed_slice()
}

/// Shared inner transport decode: takes a plain byte slice, returns heap-allocated spans.
fn decode_transport_bytes(bytes: &[u8], out_count: *mut u32) -> *mut CSpanEntry {
    use zenoh_codec::{RCodec, Zenoh080};
    use zenoh_protocol::transport::{TransportBody, TransportMessage};

    macro_rules! fail {
        () => {{
            if !out_count.is_null() {
                unsafe { *out_count = 0 };
            }
            return std::ptr::null_mut();
        }};
    }

    // A batch holds one or more transport messages back to back. Decode them all, so a
    // KeepAlive followed by a Frame keeps the Frame. Offsets stay relative to the batch.
    //
    // Use slice reader instead of ZBuf reader: ZBuf's reader is stricter about buffer
    // boundaries and returns DidntRead on exact-length messages where no trailing bytes
    // remain (e.g. a 4-byte empty-cookie OpenSyn from zenoh-pico).
    let mut entries: Vec<CSpanEntry> = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        let mut reader: &[u8] = &bytes[start..];
        let msg: TransportMessage = match Zenoh080::new().read(&mut reader) {
            Ok(m) => m,
            // The first message must decode, or this is not a Zenoh batch. A later failure
            // keeps what was decoded so far.
            Err(_) if start > 0 => break,
            Err(_) => fail!(),
        };
        let consumed = bytes.len() - start - reader.len();
        if consumed == 0 {
            break;
        }

        // One map per message: repeated messages record the same keys.
        let mut cursor = SpanCursor::new(bytes);
        let mut map = SpanMap::new();
        if cursor.seek(start).is_err()
            || record_transport_message_spans(&msg, &mut cursor, "zenoh", &mut map).is_err()
        {
            if start == 0 {
                fail!();
            }
            break;
        }
        entries.extend(span_map_to_box(&map, bytes).into_vec());
        // A Frame or a Fragment runs to the end of the batch. The Frame codec stops at the first
        // network message it cannot decode and reports success, so bytes can be left over. They
        // are that message's tail, not a new transport message.
        if matches!(
            msg.body,
            TransportBody::Frame(_) | TransportBody::Fragment(_)
        ) {
            break;
        }
        start += consumed;
    }
    sort_wire_order(&mut entries);

    let boxed = entries.into_boxed_slice();
    let count = boxed.len() as u32;
    if !out_count.is_null() {
        unsafe { *out_count = count };
    }
    Box::into_raw(boxed) as *mut CSpanEntry
}

/// Decode a Zenoh transport-level PDU from raw bytes.
///
/// `data` must point to the PDU payload (NOT including the 2-byte TCP length prefix).
/// `len` is the payload length in bytes.
/// On success, writes the span count to `*out_count` and returns a heap-allocated
/// `CSpanEntry[]`. The caller MUST call `zenoh_codec_ffi_free_spans(ptr, count)` when done.
/// Returns NULL on decode error; `*out_count` is set to 0.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn zenoh_codec_ffi_decode_transport(
    data: *const u8,
    len: u32,
    out_count: *mut u32,
) -> *mut CSpanEntry {
    if data.is_null() || len == 0 {
        if !out_count.is_null() {
            unsafe { *out_count = 0 };
        }
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    decode_transport_bytes(bytes, out_count)
}

/// Decompress an lz4 block holding one zenoh batch.
///
/// A batch is at most `BatchSize::MAX` bytes, so that bounds the output.
/// `get_maximum_output_size` is the compression bound and is too small here.
fn decompress_batch(compressed: &[u8]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; zenoh_protocol::transport::BatchSize::MAX as usize];
    let n = lz4_flex::block::decompress_into(compressed, &mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Decode a Zenoh transport-level PDU from an lz4-compressed payload.
///
/// `data` points to the raw lz4 block bytes (the BatchHeader byte must already be stripped).
/// Decompresses in a temporary buffer then decodes. Same ownership rules as
/// `zenoh_codec_ffi_decode_transport`. Returns NULL if decompression or decoding fails.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn zenoh_codec_ffi_decode_transport_compressed(
    data: *const u8,
    len: u32,
    out_count: *mut u32,
) -> *mut CSpanEntry {
    macro_rules! fail {
        () => {{
            if !out_count.is_null() {
                unsafe { *out_count = 0 };
            }
            return std::ptr::null_mut();
        }};
    }

    if data.is_null() || len == 0 {
        fail!();
    }
    let compressed = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let buf = match decompress_batch(compressed) {
        Some(buf) => buf,
        None => fail!(),
    };
    decode_transport_bytes(&buf, out_count)
}

/// Decompress an lz4-compressed zenoh batch payload (BatchHeader byte already stripped).
///
/// Returns a heap-allocated buffer with the decompressed bytes and writes its length to
/// `*out_len`. The caller MUST free it with `zenoh_codec_ffi_free_buf(ptr, *out_len)`.
/// Returns NULL if decompression fails; `*out_len` is set to 0.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn zenoh_codec_ffi_decompress(
    data: *const u8,
    len: u32,
    out_len: *mut u32,
) -> *mut u8 {
    if data.is_null() || len == 0 || out_len.is_null() {
        if !out_len.is_null() {
            unsafe { *out_len = 0 };
        }
        return std::ptr::null_mut();
    }
    let compressed = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let buf = match decompress_batch(compressed) {
        Some(buf) => buf,
        None => {
            unsafe { *out_len = 0 };
            return std::ptr::null_mut();
        }
    };
    unsafe { *out_len = buf.len() as u32 };
    let boxed = buf.into_boxed_slice();
    Box::into_raw(boxed) as *mut u8
}

/// Free a buffer returned by `zenoh_codec_ffi_decompress`.
/// `buf` must be the exact pointer returned and `len` must match `*out_len`.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn zenoh_codec_ffi_free_buf(buf: *mut u8, len: u32) {
    if buf.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            buf,
            len as usize,
        )));
    }
}

/// Decode a Zenoh scouting-level PDU from raw bytes (UDP, no length prefix).
///
/// Same ownership rules as `zenoh_codec_ffi_decode_transport`.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn zenoh_codec_ffi_decode_scouting(
    data: *const u8,
    len: u32,
    out_count: *mut u32,
) -> *mut CSpanEntry {
    use zenoh_buffers::reader::HasReader;
    use zenoh_codec::{RCodec, Zenoh080};
    use zenoh_protocol::scouting::ScoutingMessage;

    macro_rules! fail {
        () => {{
            if !out_count.is_null() {
                unsafe { *out_count = 0 };
            }
            return std::ptr::null_mut();
        }};
    }

    if data.is_null() || len == 0 {
        fail!();
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    // Use slice reader instead of ZBuf reader (see transport decoder comment).
    let mut reader = bytes.reader();
    let msg: ScoutingMessage = match Zenoh080::new().read(&mut reader) {
        Ok(m) => m,
        Err(_) => fail!(),
    };

    let mut cursor = SpanCursor::new(bytes);
    let mut map = SpanMap::new();
    if record_scouting_message_spans(&msg, &mut cursor, "zenoh", &mut map).is_err() {
        fail!();
    }

    let boxed = span_map_to_box(&map, bytes);
    let count = boxed.len() as u32;
    if !out_count.is_null() {
        unsafe { *out_count = count };
    }
    Box::into_raw(boxed) as *mut CSpanEntry
}

/// Free a `CSpanEntry[]` returned by a decode function.
/// `entries` must be the exact pointer returned by the decode call, and `count` must match.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn zenoh_codec_ffi_free_spans(entries: *mut CSpanEntry, count: u32) {
    if entries.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(entries, count as usize));
    }
}

// Wireshark plugin boilerplate — makes libzenoh_codec_ffi.so a valid (no-op) plugin
// so Wireshark's plugin scanner loads it silently without a "no plugin_version" warning.
// The actual dissection logic is in packet-zenoh (the C plugin).
#[no_mangle]
pub static plugin_version: [u8; 6] = *b"0.0.1\0";
#[no_mangle]
pub static plugin_want_major: i32 = 4;
#[no_mangle]
pub static plugin_want_minor: i32 = 6;
#[no_mangle]
pub extern "C" fn plugin_register() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A highly compressible batch expands far beyond lz4's compression bound
    /// for its compressed size, so the output buffer must be sized by `BatchSize::MAX`.
    #[test]
    fn decompress_batch_larger_than_compression_bound() {
        let batch = vec![0u8; zenoh_protocol::transport::BatchSize::MAX as usize];
        let compressed = lz4_flex::block::compress(&batch);
        assert!(lz4_flex::block::get_maximum_output_size(compressed.len()) < batch.len());

        let mut out_len = 0u32;
        let ptr =
            zenoh_codec_ffi_decompress(compressed.as_ptr(), compressed.len() as u32, &mut out_len);
        assert!(!ptr.is_null());
        assert_eq!(out_len as usize, batch.len());
        zenoh_codec_ffi_free_buf(ptr, out_len);
    }

    #[test]
    fn whatami_uses_the_packed_wire_values() {
        // Router=0, Peer=1, Client=2 in the low two bits; the zid size sits in bits 7:4.
        let key = "zenoh.transport.init_syn.whatami";
        assert_eq!(build_display(key, &[0x00]).0, "Router");
        assert_eq!(build_display(key, &[0x01]).0, "Peer");
        assert_eq!(build_display(key, &[0x02]).0, "Client");
        assert_eq!(build_display(key, &[0x71]).0, "Peer");
    }

    #[test]
    fn batch_size_is_two_little_endian_bytes() {
        let key = "zenoh.transport.init_syn.batch_size";
        assert_eq!(build_display(key, &[0x00, 0x04]).0, "1024");
        assert_eq!(build_display(key, &[0xff, 0xff]).0, "65535");
    }

    mod batch {
        use super::*;
        use zenoh_codec::{WCodec, Zenoh080};
        use zenoh_protocol::{
            core::{Reliability, WireExpr},
            network::{
                interest::{self, InterestMode, InterestOptions},
                push::ext as push_ext,
                Interest, NetworkBody, NetworkMessage, Push,
            },
            transport::{
                frame::ext::QoSType as FrameQoS, Frame, KeepAlive, TransportBody, TransportMessage,
            },
            zenoh::{PushBody, Put},
        };

        fn encode(msg: &TransportMessage) -> Vec<u8> {
            let mut buf = Vec::new();
            Zenoh080::new().write(&mut buf, msg).unwrap();
            buf
        }

        fn push(key: &str) -> NetworkMessage {
            NetworkMessage {
                reliability: Reliability::BestEffort,
                body: NetworkBody::Push(Push {
                    wire_expr: WireExpr::from(key).to_owned(),
                    ext_qos: push_ext::QoSType::DEFAULT,
                    ext_tstamp: None,
                    ext_nodeid: push_ext::NodeIdType::DEFAULT,
                    ext_ts_stack: None,
                    payload: PushBody::Put(Put {
                        timestamp: None,
                        encoding: zenoh_protocol::core::Encoding::default(),
                        ext_sinfo: None,
                        ext_shm: None,
                        ext_attachment: None,
                        ext_unknown: vec![],
                        payload: zenoh_buffers::ZBuf::default(),
                    }),
                }),
            }
        }

        fn interest() -> NetworkMessage {
            NetworkMessage {
                reliability: Reliability::BestEffort,
                body: NetworkBody::Interest(Interest {
                    id: 1,
                    mode: InterestMode::Current,
                    options: InterestOptions::KEYEXPRS,
                    wire_expr: None,
                    ext_qos: interest::ext::QoSType::DEFAULT,
                    ext_tstamp: None,
                    ext_nodeid: interest::ext::NodeIdType::DEFAULT,
                }),
            }
        }

        fn frame(payload: Vec<NetworkMessage>) -> TransportMessage {
            TransportMessage {
                body: TransportBody::Frame(Frame {
                    reliability: Reliability::BestEffort,
                    sn: 1,
                    ext_qos: FrameQoS::DEFAULT,
                    payload,
                }),
            }
        }

        /// Decode through the C ABI and return `(key, start, length)` in the order returned.
        fn decode(bytes: &[u8]) -> Vec<(String, u32, u32)> {
            let mut count = 0u32;
            let ptr =
                zenoh_codec_ffi_decode_transport(bytes.as_ptr(), bytes.len() as u32, &mut count);
            assert!(!ptr.is_null(), "decode failed");
            let spans = unsafe { std::slice::from_raw_parts(ptr, count as usize) };
            let out = spans
                .iter()
                .map(|s| {
                    let key = unsafe { std::ffi::CStr::from_ptr(s.key.as_ptr()) }
                        .to_str()
                        .unwrap()
                        .to_owned();
                    (key, s.start, s.length)
                })
                .collect();
            zenoh_codec_ffi_free_spans(ptr, count);
            out
        }

        fn find<'a>(spans: &'a [(String, u32, u32)], key: &str) -> &'a (String, u32, u32) {
            spans
                .iter()
                .find(|(k, _, _)| k == key)
                .unwrap_or_else(|| panic!("no span for {key}"))
        }

        /// The bytes a wire expression with scope 0 and `key` as its suffix occupies.
        fn wire_expr_bytes(key: &str) -> Vec<u8> {
            let mut v = vec![0x00, key.len() as u8];
            v.extend_from_slice(key.as_bytes());
            v
        }

        #[test]
        fn keep_alive_then_frame_keeps_both_messages() {
            let mut batch = encode(&TransportMessage {
                body: TransportBody::KeepAlive(KeepAlive),
            });
            let frame_at = batch.len() as u32;
            batch.extend(encode(&frame(vec![push("demo")])));

            let spans = decode(&batch);
            assert_eq!(find(&spans, "zenoh.transport.keep_alive").1, 0);
            assert_eq!(find(&spans, "zenoh.transport.frame").1, frame_at);
            let we = find(&spans, "zenoh.transport.frame.network.push.wire_expr");
            assert!(
                we.1 > frame_at,
                "offsets must stay relative to the whole batch"
            );
            assert_eq!(
                &batch[we.1 as usize..(we.1 + we.2) as usize],
                &wire_expr_bytes("demo")[..]
            );
        }

        #[test]
        fn interest_does_not_misalign_the_next_network_message() {
            let batch = encode(&frame(vec![interest(), push("demo")]));
            let spans = decode(&batch);
            let we = find(&spans, "zenoh.transport.frame.network.push.wire_expr");
            assert_eq!(
                &batch[we.1 as usize..(we.1 + we.2) as usize],
                &wire_expr_bytes("demo")[..],
                "the Push after an Interest must be read from its own first byte"
            );
        }

        #[test]
        fn mapping_flag_is_exposed_for_push() {
            use zenoh_protocol::network::Mapping;
            let with = |mapping: Mapping| {
                let mut msg = push("demo");
                if let NetworkBody::Push(p) = &mut msg.body {
                    p.wire_expr.mapping = mapping;
                }
                let batch = encode(&frame(vec![msg]));
                let spans = decode(&batch);
                let m = find(
                    &spans,
                    "zenoh.transport.frame.network.push.wire_expr.mapping",
                );
                assert_eq!(m.2, 1, "the mapping span is the one header byte");
                batch[m.1 as usize] & 0x40 != 0
            };
            assert!(with(Mapping::Sender), "M set means the sender's mapping");
            assert!(
                !with(Mapping::Receiver),
                "M clear means the receiver's mapping"
            );
        }

        #[test]
        fn spans_come_back_in_wire_order() {
            let batch = encode(&frame(vec![push("a"), push("b")]));
            let spans = decode(&batch);
            assert!(
                spans.windows(2).all(|w| w[0].1 <= w[1].1),
                "starts must not decrease: {spans:?}"
            );
            let pushes: Vec<_> = spans
                .iter()
                .filter(|(k, _, _)| k == "zenoh.transport.frame.network.push.wire_expr")
                .collect();
            assert_eq!(pushes.len(), 2, "one wire_expr span per Push");
            assert_eq!(
                &batch[pushes[0].1 as usize..(pushes[0].1 + pushes[0].2) as usize],
                &wire_expr_bytes("a")[..]
            );
            assert_eq!(
                &batch[pushes[1].1 as usize..(pushes[1].1 + pushes[1].2) as usize],
                &wire_expr_bytes("b")[..]
            );
        }

        // ---- network messages with a body, deletes, tails, extensions ----

        fn request_query() -> NetworkMessage {
            use zenoh_protocol::{
                network::{request::ext::QueryTarget, Request},
                zenoh::{query::ConsolidationMode, Query, RequestBody},
            };
            NetworkMessage {
                reliability: Reliability::BestEffort,
                body: NetworkBody::Request(Request {
                    id: 1,
                    wire_expr: WireExpr::from("demo/query").to_owned(),
                    ext_qos: push_ext::QoSType::DEFAULT,
                    ext_tstamp: None,
                    ext_nodeid: push_ext::NodeIdType::DEFAULT,
                    ext_ts_stack: None,
                    ext_target: QueryTarget::DEFAULT,
                    ext_budget: None,
                    ext_timeout: None,
                    payload: RequestBody::Query(Query {
                        parameters: "p=1".to_string(),
                        consolidation: ConsolidationMode::DEFAULT,
                        ext_sinfo: None,
                        ext_body: None,
                        ext_attachment: None,
                        ext_unknown: vec![],
                    }),
                }),
            }
        }

        fn response_reply() -> NetworkMessage {
            use zenoh_protocol::{
                network::Response,
                zenoh::{query::ConsolidationMode, PushBody, Put, Reply, ResponseBody},
            };
            NetworkMessage {
                reliability: Reliability::BestEffort,
                body: NetworkBody::Response(Response {
                    rid: 1,
                    wire_expr: WireExpr::from("demo/answer").to_owned(),
                    ext_qos: push_ext::QoSType::DEFAULT,
                    ext_tstamp: None,
                    ext_ts_stack: None,
                    ext_respid: None,
                    payload: ResponseBody::Reply(Reply {
                        consolidation: ConsolidationMode::DEFAULT,
                        ext_unknown: vec![],
                        payload: PushBody::Put(Put {
                            timestamp: None,
                            encoding: zenoh_protocol::core::Encoding::default(),
                            ext_sinfo: None,
                            ext_shm: None,
                            ext_attachment: None,
                            ext_unknown: vec![],
                            payload: zenoh_buffers::ZBuf::from(b"answer".to_vec()),
                        }),
                    }),
                }),
            }
        }

        fn response_final(rid: u32) -> NetworkMessage {
            NetworkMessage {
                reliability: Reliability::BestEffort,
                body: NetworkBody::ResponseFinal(zenoh_protocol::network::ResponseFinal {
                    rid,
                    ext_qos: push_ext::QoSType::DEFAULT,
                    ext_tstamp: None,
                }),
            }
        }

        fn push_del(key: &str) -> NetworkMessage {
            let mut msg = push(key);
            if let NetworkBody::Push(p) = &mut msg.body {
                p.payload = PushBody::Del(zenoh_protocol::zenoh::Del {
                    timestamp: None,
                    ext_sinfo: None,
                    ext_attachment: None,
                    ext_unknown: vec![],
                });
            }
            msg
        }

        /// The bytes of the span with this key, in the order the spans came back.
        fn bytes_of<'a>(batch: &'a [u8], spans: &[(String, u32, u32)], key: &str) -> Vec<&'a [u8]> {
            spans
                .iter()
                .filter(|(k, _, _)| k == key)
                .map(|(_, s, l)| &batch[*s as usize..(*s + *l) as usize])
                .collect()
        }

        fn ends_where_next_starts(spans: &[(String, u32, u32)], first: &str, second: &str) {
            let a = spans.iter().find(|(k, _, _)| k == first).expect(first);
            let b = spans.iter().find(|(k, _, _)| k == second).expect(second);
            assert_eq!(
                a.1 + a.2,
                b.1,
                "{first} must end where {second} starts: {spans:?}"
            );
        }

        #[test]
        fn reply_then_response_final_stay_aligned() {
            let batch = encode(&frame(vec![response_reply(), response_final(7)]));
            let spans = decode(&batch);
            let rid = find(&spans, "zenoh.transport.frame.network.response_final.rid");
            assert_eq!(
                batch[rid.1 as usize], 7,
                "rid of the ResponseFinal: {spans:?}"
            );
            ends_where_next_starts(
                &spans,
                "zenoh.transport.frame.network.response",
                "zenoh.transport.frame.network.response_final",
            );
        }

        #[test]
        fn request_then_push_stay_aligned() {
            let batch = encode(&frame(vec![request_query(), push("demo")]));
            let spans = decode(&batch);
            assert_eq!(
                bytes_of(
                    &batch,
                    &spans,
                    "zenoh.transport.frame.network.push.wire_expr"
                ),
                vec![&wire_expr_bytes("demo")[..]],
                "the Push after a Request must be read from its own first byte: {spans:?}"
            );
            ends_where_next_starts(
                &spans,
                "zenoh.transport.frame.network.request",
                "zenoh.transport.frame.network.push",
            );
        }

        #[test]
        fn delete_is_not_recorded_as_a_put_and_does_not_shift_the_next_push() {
            let mut second = push("demo");
            if let NetworkBody::Push(p) = &mut second.body {
                if let PushBody::Put(put) = &mut p.payload {
                    put.payload = zenoh_buffers::ZBuf::from(b"x".to_vec());
                }
            }
            let batch = encode(&frame(vec![push_del("gone"), second]));
            let spans = decode(&batch);
            assert_eq!(
                bytes_of(
                    &batch,
                    &spans,
                    "zenoh.transport.frame.network.push.wire_expr"
                ),
                vec![&wire_expr_bytes("gone")[..], &wire_expr_bytes("demo")[..]],
                "{spans:?}"
            );
            assert_eq!(
                spans
                    .iter()
                    .filter(|(k, _, _)| k.ends_with(".put.payload"))
                    .count(),
                1,
                "only the second Push is a Put: {spans:?}"
            );
        }

        #[test]
        fn undecodable_tail_after_a_frame_is_not_a_second_message() {
            // 0x04 is a valid transport message (KeepAlive) but not a network id, so the Frame
            // stops before it. The byte belongs to the Frame's tail, not to a new message.
            let mut batch = encode(&frame(vec![push("demo")]));
            batch.push(0x04);
            let spans = decode(&batch);
            assert!(
                !spans
                    .iter()
                    .any(|(k, _, _)| k == "zenoh.transport.keep_alive"),
                "a phantom KeepAlive was decoded from the tail: {spans:?}"
            );
        }

        #[test]
        fn frame_qos_and_node_id_extensions_are_recorded() {
            let mut msg = push("demo");
            if let NetworkBody::Push(p) = &mut msg.body {
                p.ext_nodeid = push_ext::NodeIdType { node_id: 7 };
            }
            let mut tm = frame(vec![msg]);
            if let TransportBody::Frame(f) = &mut tm.body {
                f.ext_qos = FrameQoS::new(zenoh_protocol::core::Priority::RealTime);
            }
            let batch = encode(&tm);
            let spans = decode(&batch);
            find(&spans, "zenoh.transport.frame.ext_qos");
            find(&spans, "zenoh.transport.frame.network.push.ext_nodeid");
        }

        #[test]
        fn request_extensions_are_recorded() {
            let mut msg = request_query();
            if let NetworkBody::Request(r) = &mut msg.body {
                r.ext_target = zenoh_protocol::network::request::ext::QueryTarget::All;
                r.ext_budget = Some(5u32.try_into().unwrap());
                r.ext_timeout = Some(std::time::Duration::from_millis(250));
            }
            let batch = encode(&frame(vec![msg, push("demo")]));
            let spans = decode(&batch);
            find(&spans, "zenoh.transport.frame.network.request.ext_target");
            find(&spans, "zenoh.transport.frame.network.request.ext_budget");
            find(&spans, "zenoh.transport.frame.network.request.ext_timeout");
            assert_eq!(
                bytes_of(
                    &batch,
                    &spans,
                    "zenoh.transport.frame.network.push.wire_expr"
                ),
                vec![&wire_expr_bytes("demo")[..]],
                "{spans:?}"
            );
        }

        #[test]
        fn put_with_a_shared_memory_extension_keeps_the_next_message_aligned() {
            let mut msg = push("shm");
            if let NetworkBody::Push(p) = &mut msg.body {
                if let PushBody::Put(put) = &mut p.payload {
                    put.ext_shm = Some(zenoh_protocol::zenoh::put::ext::ShmType::new());
                    put.payload = zenoh_buffers::ZBuf::from(b"bytes".to_vec());
                }
            }
            let batch = encode(&frame(vec![msg, push("demo")]));
            let spans = decode(&batch);
            assert_eq!(
                bytes_of(
                    &batch,
                    &spans,
                    "zenoh.transport.frame.network.push.wire_expr"
                ),
                vec![&wire_expr_bytes("shm")[..], &wire_expr_bytes("demo")[..]],
                "{spans:?}"
            );
        }

        #[test]
        fn declare_subscriber_exposes_its_mapping_flag() {
            use zenoh_protocol::network::{
                declare::ext as dext, Declare, DeclareBody, DeclareSubscriber, Mapping,
            };
            let with = |mapping: Mapping| {
                let mut we = WireExpr::from("demo").to_owned();
                we.scope = 1;
                we.mapping = mapping;
                let msg = NetworkMessage {
                    reliability: Reliability::BestEffort,
                    body: NetworkBody::Declare(Declare {
                        interest_id: None,
                        ext_qos: dext::QoSType::DEFAULT,
                        ext_tstamp: None,
                        ext_nodeid: dext::NodeIdType::DEFAULT,
                        body: DeclareBody::DeclareSubscriber(DeclareSubscriber {
                            id: 1,
                            wire_expr: we,
                        }),
                    }),
                };
                let batch = encode(&frame(vec![msg]));
                let spans = decode(&batch);
                let m = find(
                    &spans,
                    "zenoh.transport.frame.network.declare.declare_subscriber.wire_expr.mapping",
                );
                assert_eq!(m.2, 1, "the mapping span is the one header byte");
                batch[m.1 as usize] & 0x40 != 0
            };
            assert!(with(Mapping::Sender));
            assert!(!with(Mapping::Receiver));
        }
    }
}
