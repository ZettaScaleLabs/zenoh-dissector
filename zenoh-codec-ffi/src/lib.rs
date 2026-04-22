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
#[repr(C)]
pub struct CSpanEntry {
    pub key: [c_char; ZENOH_FFI_KEY_LEN],
    pub start: u32,
    pub length: u32,
    pub display: [c_char; ZENOH_FFI_KEY_LEN],
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

fn decode_vle(bytes: &[u8]) -> Option<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    for &b in bytes {
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(val);
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

fn build_display(key: &str, bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let suffix = key.rsplit('.').next().unwrap_or("");
    match suffix {
        "whatami" => {
            let b = bytes[0];
            match b & 0x0f {
                1 => "Router".to_string(),
                2 => "Peer".to_string(),
                4 => "Client".to_string(),
                v => format!("0x{v:02x}"),
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
            if let Some(enc_raw) = decode_vle(bytes) {
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
        "version" => format!("{}", bytes[0]),
        "scope" | "id" | "batch_size" | "initial_sn" | "lease" | "sn" => {
            if let Some(v) = decode_vle(bytes) {
                format!("{v}")
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

fn make_cspan(key: &str, start: usize, length: usize, display: &str) -> CSpanEntry {
    let mut e = CSpanEntry {
        key: [0; ZENOH_FFI_KEY_LEN],
        start: start as u32,
        length: length as u32,
        display: [0; ZENOH_FFI_KEY_LEN],
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
        fields.sort_by(|a, b| a.key.cmp(&b.key));
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

fn span_map_to_box(map: &SpanMap, raw: &[u8]) -> Box<[CSpanEntry]> {
    let entries: Vec<CSpanEntry> = map
        .iter()
        .map(|(key, span)| {
            let stripped = strip_indices(key);
            let span_bytes = raw.get(span.start..span.start + span.len()).unwrap_or(&[]);
            let display = build_display(&stripped, span_bytes);
            make_cspan(&stripped, span.start, span.len(), &display)
        })
        .collect();
    entries.into_boxed_slice()
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
    use zenoh_buffers::reader::HasReader;
    use zenoh_codec::{RCodec, Zenoh080};
    use zenoh_protocol::transport::TransportMessage;

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
    let zbuf: zenoh_buffers::ZBuf = bytes.to_vec().into();
    let mut reader = zbuf.reader();
    let msg: TransportMessage = match Zenoh080::new().read(&mut reader) {
        Ok(m) => m,
        Err(_) => fail!(),
    };

    let mut cursor = SpanCursor::new(bytes);
    let mut map = SpanMap::new();
    if record_transport_message_spans(&msg, &mut cursor, "zenoh", &mut map).is_err() {
        fail!();
    }

    let boxed = span_map_to_box(&map, bytes);
    let count = boxed.len() as u32;
    if !out_count.is_null() {
        unsafe { *out_count = count };
    }
    Box::into_raw(boxed) as *mut CSpanEntry
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
    let zbuf: zenoh_buffers::ZBuf = bytes.to_vec().into();
    let mut reader = zbuf.reader();
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
