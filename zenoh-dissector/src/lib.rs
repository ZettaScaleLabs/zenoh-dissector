//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use anyhow::Result;
use header_field::{FieldKind, Registration};
use std::{cell::RefCell, collections::HashMap, ffi::CString, slice, sync::LazyLock};
use tree::{AddToTree, TreeArgs};
use utils::{new_rbatch, transport_message_summary, SizedSummary};
use wireshark::register_header_field;
use zenoh_impl::ZenohProtocol;
use zenoh_protocol::transport::{BatchSize, TransportMessage};
use zenoh_transport::common::batch::Decode;

mod conversation;
mod header_field;
mod macros;
mod span;
mod tree;
mod utils;
mod wireshark;
mod ws_log;
mod zenoh_impl;
mod zenoh_spans;

use span::SpanMap;
use zenoh_spans::{record_transport_message_spans, record_scouting_message_spans};

use zenoh_buffers::reader::{HasReader, Reader};
use zenoh_codec::{RCodec, Zenoh080};
use zenoh_protocol::common::imsg;
use zenoh_protocol::core::ExprId;
use zenoh_protocol::network::{DeclareBody, NetworkBody};
use zenoh_protocol::scouting::{id as scouting_id, ScoutingMessage};
use zenoh_protocol::transport::TransportBody;

/// Max number of message summaries in one batch.
const MAX_BATCH_SUMMARY: usize = 5;
/// Max length of a single message summary string.
const MSG_SUMMARY_LIMIT: usize = 30;
/// Length of the batch size header prepended to each Zenoh batch in TCP streams.
const BATCH_HEADER_LEN: usize = 2;

// Thread-local table mapping expr_id → resolved key expression suffix.
// Populated when DeclareKeyExpr messages are seen.
thread_local! {
    static KEY_EXPR_TABLE: RefCell<HashMap<ExprId, String>> = RefCell::new(HashMap::new());
}

/// Walk a TransportMessage looking for DeclareKeyExpr declarations and update the table.
fn update_key_expr_table(msg: &TransportMessage) {
    if let TransportBody::Frame(frame) = &msg.body {
        for nmsg in &frame.payload {
            if let NetworkBody::Declare(decl) = &nmsg.body {
                if let DeclareBody::DeclareKeyExpr(dke) = &decl.body {
                    // Build the full resolved key expression string.
                    // If scope == 0, the suffix is the complete key.
                    // If scope != 0, look up the scope's resolved string and concatenate.
                    let resolved = if dke.wire_expr.scope == 0 {
                        dke.wire_expr.suffix.to_string()
                    } else {
                        KEY_EXPR_TABLE.with(|t| {
                            let table = t.borrow();
                            if let Some(base) = table.get(&dke.wire_expr.scope) {
                                format!("{}{}", base, dke.wire_expr.suffix)
                            } else {
                                format!("{}:{}", dke.wire_expr.scope, dke.wire_expr.suffix)
                            }
                        })
                    };
                    KEY_EXPR_TABLE.with(|t| {
                        t.borrow_mut().insert(dke.id, resolved);
                    });
                }
            }
        }
    }
}

/// Resolve a wire_expr scope+suffix to a human-readable key expression string.
pub fn resolve_wire_expr(wire_expr: &zenoh_protocol::core::WireExpr<'_>) -> String {
    if wire_expr.scope == 0 {
        wire_expr.suffix.to_string()
    } else {
        KEY_EXPR_TABLE.with(|t| {
            let table = t.borrow();
            if let Some(base) = table.get(&wire_expr.scope) {
                format!("{}{}", base, wire_expr.suffix)
            } else {
                format!("{}:{}", wire_expr.scope, wire_expr.suffix)
            }
        })
    }
}

// Version symbols are generated at build time from Cargo.toml metadata
include!(concat!(env!("OUT_DIR"), "/version.rs"));

#[derive(Default, Debug)]
struct ProtocolData {
    id: i32,
    // header field map
    hf_map: HashMap<String, std::ffi::c_int>,
    // subtree map
    st_map: HashMap<String, std::ffi::c_int>,
    handle: Option<epan_sys::dissector_handle_t>,
}

thread_local! {
    static PROTOCOL_DATA: RefCell<ProtocolData> = ProtocolData::default().into();
}

// Global variables for interacting wtih wireshark preference
static mut IS_COMPRESSION: bool = false;
static mut UDP_PORT: u32 = 7447;
static mut TCP_PORT: u32 = 7447;
static mut CURR_UDP_PORT: u32 = 7447;
static mut CURR_TCP_PORT: u32 = 7447;

#[no_mangle]
extern "C" fn plugin_register() {
    env_logger::init();
    static mut PLUG: epan_sys::proto_plugin = epan_sys::proto_plugin {
        register_protoinfo: None,
        register_handoff: None,
    };
    unsafe {
        PLUG.register_protoinfo = Some(register_protoinfo);
        PLUG.register_handoff = Some(register_handoff);
        epan_sys::proto_register_plugin(&raw const PLUG);
    }
}

#[no_mangle]
unsafe extern "C" fn prefs_callback() {
    if CURR_TCP_PORT != TCP_PORT {
        #[allow(static_mut_refs)] // Wireshark requires these references to be static mut
        {
            ws_log::message!("Update TCP Port: {CURR_TCP_PORT} -> {TCP_PORT}");
        }
        PROTOCOL_DATA.with(|data| {
            let handle = data
                .borrow()
                .handle
                .expect("Handle after registration shouldn't be empty");
            let tcp_keyword = c"tcp.port".as_ptr();
            epan_sys::dissector_delete_uint(tcp_keyword, CURR_TCP_PORT, handle);
            epan_sys::dissector_add_uint_with_preference(tcp_keyword, TCP_PORT as _, handle);
        });
        CURR_TCP_PORT = TCP_PORT;
    }

    if CURR_UDP_PORT != UDP_PORT {
        #[allow(static_mut_refs)] // Wireshark requires these references to be static mut
        {
            ws_log::message!("Update UDP Port: {CURR_UDP_PORT} -> {UDP_PORT}");
        }
        PROTOCOL_DATA.with(|data| {
            let handle = data
                .borrow()
                .handle
                .expect("Handle after registration shouldn't be empty");
            let udp_keyword = c"udp.port".as_ptr();
            epan_sys::dissector_delete_uint(udp_keyword, CURR_UDP_PORT, handle);
            epan_sys::dissector_add_uint_with_preference(udp_keyword, UDP_PORT as _, handle);
        });
        CURR_UDP_PORT = UDP_PORT;
    }
}

fn register_zenoh_protocol() -> Result<()> {
    let proto_id = unsafe {
        epan_sys::proto_register_protocol(
            c"Zenoh Protocol".as_ptr(),
            c"Zenoh".as_ptr(),
            c"zenoh".as_ptr(),
        )
    };

    // Register preferences for the zenoh protocol
    unsafe {
        let zenoh_module = epan_sys::prefs_register_protocol(proto_id, Some(prefs_callback));
        epan_sys::prefs_register_uint_preference(
            zenoh_module,
            c"tcp.port".as_ptr(),
            c"TCP Port".as_ptr(),
            c"Zenoh TCP Port to listen to".as_ptr(),
            10 as _,
            &raw mut TCP_PORT as _,
        );
        epan_sys::prefs_register_uint_preference(
            zenoh_module,
            c"udp.port".as_ptr(),
            c"UDP Port".as_ptr(),
            c"Zenoh UDP Port to listen to".as_ptr(),
            10 as _,
            &raw mut UDP_PORT as _,
        );
        epan_sys::prefs_register_bool_preference(
            zenoh_module,
            c"is_compression".as_ptr(),
            c"Is Compression".as_ptr(),
            c"Is Zenoh message compressed".as_ptr(),
            &raw mut IS_COMPRESSION as _,
        );
    }

    let hf_map = ZenohProtocol::generate_hf_map("zenoh");
    let subtree_names = ZenohProtocol::generate_subtree_names("zenoh");

    PROTOCOL_DATA.with(|data| {
        data.borrow_mut().id = proto_id;

        // Header Field
        for (key, hf) in hf_map {
            data.borrow_mut().hf_map.insert(
                key.to_string(),
                register_header_field(proto_id, &hf.name, &key, hf.kind)?,
            );
        }

        // Extra header fields
        data.borrow_mut().hf_map.insert(
            conversation::FIELD_SRCZID.to_string(),
            register_header_field(
                proto_id,
                "Source ZID",
                conversation::FIELD_SRCZID,
                FieldKind::Text,
            )?,
        );
        data.borrow_mut().hf_map.insert(
            conversation::FIELD_DSTZID.to_string(),
            register_header_field(
                proto_id,
                "Destination ZID",
                conversation::FIELD_DSTZID,
                FieldKind::Text,
            )?,
        );

        // Subtree
        for name in subtree_names {
            // Create a raw pointer to ETT (Epan Tree Type) by
            // https://doc.rust-lang.org/std/primitive.pointer.html#2-consume-a-box-boxt
            let ett_ptr = Box::into_raw(Box::new([-1, -1])) as *mut _;
            // register a ETT and assign the index
            unsafe {
                epan_sys::proto_register_subtree_array([ett_ptr].as_ptr(), 1);
            }
            // and then collect it back via from_raw
            let ett: i32 = unsafe { *Box::from_raw(ett_ptr) };
            // the value of the pointer pointing to should be the index of ETT instead of
            // uninitialized -1
            debug_assert_ne!(ett, -1);

            // Record the mapping between the ETT name and index
            data.borrow_mut().st_map.insert(name, ett);
        }

        anyhow::Ok(())
    })?;
    Ok(())
}

unsafe extern "C" fn register_protoinfo() {
    if let Err(err) = register_zenoh_protocol() {
        ws_log::critical!("failed to register zenoh protocol: {err}");
    }
}

unsafe extern "C" fn register_handoff() {
    PROTOCOL_DATA.with(|data| {
        let proto_id = data.borrow().id;

        let handle = epan_sys::create_dissector_handle(Some(dissect_zenoh), proto_id);
        epan_sys::dissector_add_uint_with_preference(c"tcp.port".as_ptr(), TCP_PORT as _, handle);
        epan_sys::dissector_add_uint_with_preference(c"udp.port".as_ptr(), UDP_PORT as _, handle);
        // UDP 7446: scouting (SCOUT / HELLO)
        epan_sys::dissector_add_uint(c"udp.port".as_ptr(), 7446, handle);
        data.borrow_mut().handle = Some(handle);

        // See https://www.wireshark.org/docs/wsar_html/group__packet.html#gac1f89fb22ed3dd53cb3aecbc7b87a528
        epan_sys::heur_dissector_add(
            c"tcp".as_ptr(),
            Some(dissect_zenoh_heur),
            c"Zenoh over TCP (heuristic)".as_ptr(),
            c"zenoh_tcp_heur".as_ptr(),
            proto_id,
            epan_sys::heuristic_enable_e_HEURISTIC_DISABLE,
        );
        epan_sys::heur_dissector_add(
            c"udp".as_ptr(),
            Some(dissect_zenoh_heur),
            c"Zenoh over UDP (heuristic)".as_ptr(),
            c"zenoh_udp_heur".as_ptr(),
            proto_id,
            epan_sys::heuristic_enable_e_HEURISTIC_DISABLE,
        );

        #[allow(static_mut_refs)] // Wireshark requires these references to be static mut
        {
            ws_log::message!(
                "Zenoh dissector is registered for TCP port {TCP_PORT} and UDP port {UDP_PORT}"
            );
        }
        ws_log::message!("Zenoh heuristic dissector is registered for TCP and UDP");
    });
}

unsafe extern "C" fn dissect_zenoh_heur(    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    data: *mut std::ffi::c_void,
) -> bool {
    dissect_zenoh(tvb, pinfo, tree, data) != 0
}

unsafe extern "C" fn dissect_zenoh(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    match (*pinfo).ptype {
        epan_sys::port_type_PT_TCP => dissect_zenoh_tcp(tvb, pinfo, tree, data),
        epan_sys::port_type_PT_UDP => dissect_zenoh_udp(tvb, pinfo, tree, data),
        _ => 0,
    }
}

/// Called by `tcp_dissect_pdus` to determine the full PDU length from the fixed-length header.
///
/// Reads the 2-byte little-endian batch size and returns `BATCH_HEADER_LEN + batch_size`.
unsafe extern "C" fn get_pdu_len_zenoh_tcp(
    _pinfo: *mut epan_sys::_packet_info,
    tvb: *mut epan_sys::tvbuff,
    offset: std::ffi::c_int,
    _data: *mut std::ffi::c_void,
) -> std::ffi::c_uint {
    let batch_size = epan_sys::tvb_get_letohs(tvb, offset) as std::ffi::c_uint;
    (BATCH_HEADER_LEN as std::ffi::c_uint) + batch_size
}

const PROTO_DATA_KEY_FRAME: u32 = 0;

/// Per-frame state shared between `dissect_zenoh_tcp` calls for the same frame.
/// Stored via `p_add_proto_data` so it survives when the TCP layer calls us
/// multiple times (e.g. reassembled PDU + remaining segment data).
#[repr(C)]
struct ZenohFrameData {
    /// The protocol item ("Zenoh Protocol, …") — used to append ZID text.
    proto_ti: *mut epan_sys::_proto_node,
    /// The protocol subtree — ZID fields are added here.
    proto_tree: *mut epan_sys::proto_tree,
    /// Whether ZID fields have already been added to the tree.
    zids_added: bool,
}

/// Top-level TCP dissector: creates a single "Zenoh Protocol" protocol tree (once per
/// frame), delegates to `tcp_dissect_pdus` for reassembly and PDU boundary detection
/// (which calls `dissect_zenoh_pdu` for each complete batch), then adds ZID fields.
unsafe extern "C" fn dissect_zenoh_tcp(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    _data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    static C_STR_ZENOH: LazyLock<CString> = LazyLock::new(|| CString::new("Zenoh").unwrap());
    epan_sys::col_set_str(
        (*pinfo).cinfo,
        epan_sys::COL_PROTOCOL as _,
        C_STR_ZENOH.as_ptr(),
    );

    let proto_id = PROTOCOL_DATA.with_borrow(|d| d.id);
    let scope = (*pinfo).pool;

    // Create the protocol tree only once per frame. The TCP layer may call us
    // multiple times for the same frame (reassembled data + remaining segment).
    let existing = epan_sys::p_get_proto_data(scope, pinfo, proto_id, PROTO_DATA_KEY_FRAME);
    let frame_data: *mut ZenohFrameData = if existing.is_null() {
        let (ti, subtree) = PROTOCOL_DATA.with(|data| {
            let borrowed = data.borrow();
            let ti = epan_sys::proto_tree_add_item(tree, borrowed.id, tvb, 0, -1, epan_sys::ENC_NA);
            let st = *borrowed
                .st_map
                .get("zenoh")
                .expect("zenoh subtree not registered");
            let subtree = epan_sys::proto_item_add_subtree(ti, st);
            (ti, subtree)
        });

        let fd = epan_sys::wmem_alloc0(scope, std::mem::size_of::<ZenohFrameData>())
            as *mut ZenohFrameData;
        (*fd).proto_ti = ti;
        (*fd).proto_tree = subtree;
        epan_sys::p_add_proto_data(scope, pinfo, proto_id, PROTO_DATA_KEY_FRAME, fd as *mut _);
        fd
    } else {
        existing as *mut ZenohFrameData
    };

    // `tcp_dissect_pdus` calls dissect_zenoh_pdu for each complete batch.
    // Batch subtrees are added as siblings of the protocol tree on the frame tree.
    epan_sys::tcp_dissect_pdus(
        tvb,
        pinfo,
        tree,
        true,
        BATCH_HEADER_LEN as std::ffi::c_uint,
        Some(get_pdu_len_zenoh_tcp),
        Some(dissect_pdu_zenoh_tcp),
        std::ptr::null_mut(),
    );

    // Add ZID fields to the protocol subtree and update the protocol item text.
    // Done after tcp_dissect_pdus so that InitSyn/InitAck in any batch have had
    // a chance to update the conversation state. Only once per frame.
    if !(*frame_data).zids_added {
        (*frame_data).zids_added = true;
        conversation::update_tree(tvb, pinfo, (*frame_data).proto_tree, (*frame_data).proto_ti);
    }

    epan_sys::tvb_reported_length(tvb) as std::ffi::c_int
}

/// Dissect a single, complete Zenoh batch PDU.
///
/// The TVB contains exactly `BATCH_HEADER_LEN + batch_payload` bytes. `tcp_dissect_pdus`
/// has already handled reassembly and framing.
///
/// Batch subtrees are added to the frame `tree` as siblings of the "Zenoh Protocol" item.
unsafe extern "C" fn dissect_pdu_zenoh_tcp(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    _data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    let tvb_len = epan_sys::tvb_reported_length(tvb) as usize;
    if tvb_len < BATCH_HEADER_LEN {
        return 0;
    }

    // Skip the 2-byte length header; the rest is the batch payload.
    let payload_len = tvb_len - BATCH_HEADER_LEN;
    let payload_ptr = epan_sys::tvb_get_ptr(tvb, BATCH_HEADER_LEN as _, payload_len as _);
    let payload_slice = slice::from_raw_parts(payload_ptr, payload_len);

    let msgs = {
        let mut rbatch = match new_rbatch(payload_slice, IS_COMPRESSION) {
            Ok(rbatch) => rbatch,
            Err(err) => {
                ws_log::message!("zenoh_tcp: {err} (no={})", (*pinfo).num);
                return 0;
            }
        };
        let mut msgs = Vec::new();

        let mut offset: usize = 0;
        while !rbatch.is_empty() {
            let Ok((msg, len)): Result<(TransportMessage, BatchSize), _> = rbatch.decode() else {
                ws_log::message!(
                    "zenoh_tcp: failed to decode transport message (no={})",
                    (*pinfo).num
                );
                return 0;
            };

            msgs.push(Message {
                msg,
                len: len as _,
                offset,
            });
            offset += len as usize;
        }

        msgs
    };

    let summary = PROTOCOL_DATA.with(|data| {
        let borrowed_data = data.borrow();

        // Add a batch subtree on the frame tree (sibling of "Zenoh Protocol").
        let batch_tree = TreeArgs {
            tree,
            tvb,
            hf_map: &borrowed_data.hf_map,
            st_map: &borrowed_data.st_map,
            start: 0,
            length: tvb_len,
            spans: None,
            local_spans: None,
        }
        .make_subtree("zenoh.batch", &format!("Batch, Len: {payload_len}"))
        .unwrap();

        // Update conversation state (ZIDs) from this batch's messages.
        for m in &msgs {
            conversation::update_state(pinfo, &m.msg);
            update_key_expr_table(&m.msg);
        }

        // Build per-field span maps for each message (payload-relative, then shifted).
        let span_maps: Vec<SpanMap> = msgs.iter().map(|m| {
            let mut span_map = SpanMap::new();
            #[allow(static_mut_refs)]
            if !IS_COMPRESSION && m.offset + m.len <= payload_slice.len() {
                let msg_bytes = &payload_slice[m.offset..m.offset + m.len];
                let mut cursor = span::SpanCursor::new(msg_bytes);
                if let Err(e) = record_transport_message_spans(&m.msg, &mut cursor, "zenoh", &mut span_map) {
                    ws_log::message!("span recording error: {e}");
                    span_map.clear();
                }
                for s in span_map.values_mut() {
                    s.start += BATCH_HEADER_LEN + m.offset;
                    s.end += BATCH_HEADER_LEN + m.offset;
                }
            }
            span_map
        }).collect();

        for (m, span_map) in msgs.iter().zip(span_maps.iter()) {
            // Message offsets are relative to the batch payload; shift by BATCH_HEADER_LEN
            // to make them relative to the TVB.
            let msg_tree = TreeArgs {
                start: BATCH_HEADER_LEN + m.offset,
                length: m.len,
                spans: if span_map.is_empty() { None } else { Some(span_map) },
                local_spans: None,
                ..batch_tree
            };
            m.msg.add_to_tree("zenoh", &msg_tree).unwrap();
        }

        let mut batch_summary = SizedSummary::new(MAX_BATCH_SUMMARY);
        for m in &msgs {
            batch_summary.append(|| {
                let mut s = transport_message_summary(&m.msg);
                if s.len() > MSG_SUMMARY_LIMIT {
                    s.truncate(MSG_SUMMARY_LIMIT);
                    s += "...]";
                }
                s
            });
        }
        batch_summary
    });

    let summary_c_str = CString::new(format!("{summary}")).unwrap();
    epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as _);
    epan_sys::col_add_str(
        (*pinfo).cinfo,
        epan_sys::COL_INFO as _,
        summary_c_str.as_ptr(),
    );

    tvb_len as std::ffi::c_int
}

/// Dissect a Zenoh UDP datagram (entire payload is a single batch, no length prefix).
unsafe extern "C" fn dissect_zenoh_udp(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    _data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    epan_sys::col_add_str(
        (*pinfo).cinfo,
        epan_sys::COL_PROTOCOL as _,
        c"Zenoh".as_ptr(),
    );

    let tvb_len = epan_sys::tvb_reported_length(tvb) as usize;
    if tvb_len == 0 {
        return 0;
    }

    let tvb_ptr = epan_sys::tvb_get_ptr(tvb, 0, tvb_len as _);
    let tvb_slice = slice::from_raw_parts(tvb_ptr, tvb_len);

    // Scouting messages (SCOUT/HELLO) have mid=1 or mid=2 in the first byte.
    // Transport messages have mid >= 4. Dispatch accordingly.
    let is_scouting = tvb_slice
        .first()
        .map(|&b| {
            let mid = imsg::mid(b);
            mid == scouting_id::SCOUT || mid == scouting_id::HELLO
        })
        .unwrap_or(false);

    if is_scouting {
        let tvb_vec = tvb_slice.to_vec();
        let summary = PROTOCOL_DATA.with(|data| {
            let borrowed_data = data.borrow();
            let ti = epan_sys::proto_tree_add_item(tree, borrowed_data.id, tvb, 0, -1, epan_sys::ENC_NA);
            let st = *borrowed_data.st_map.get("zenoh").expect("zenoh subtree not registered");
            let zenoh_tree = epan_sys::proto_item_add_subtree(ti, st);
            let mut tree_args = TreeArgs {
                tree: zenoh_tree, tvb,
                hf_map: &borrowed_data.hf_map,
                st_map: &borrowed_data.st_map,
                start: 0, length: tvb_len, spans: None, local_spans: None,
            };
            let mut scout_reader = tvb_vec.reader();
            let mut summary = SizedSummary::new(MAX_BATCH_SUMMARY);
            while scout_reader.remaining() > 0 {
                let before = scout_reader.remaining();
                let msg: ScoutingMessage = match Zenoh080::new().read(&mut scout_reader) {
                    Ok(m) => m,
                    Err(_) => break,
                };
                let msg_len = before - scout_reader.remaining();
                let mut span_map = SpanMap::new();
                if tree_args.start + msg_len <= tvb_vec.len() {
                    let msg_bytes = &tvb_vec[tree_args.start..tree_args.start + msg_len];
                    let mut cursor = span::SpanCursor::new(msg_bytes);
                    if let Err(e) = record_scouting_message_spans(&msg, &mut cursor, "zenoh", &mut span_map) {
                        ws_log::message!("scouting span error: {e}");
                        span_map.clear();
                    }
                    for s in span_map.values_mut() {
                        s.start += tree_args.start;
                        s.end += tree_args.start;
                    }
                }
                let msg_args = TreeArgs {
                    length: msg_len,
                    spans: if span_map.is_empty() { None } else { Some(&span_map) },
                    local_spans: None,
                    ..tree_args
                };
                let _ = msg.add_to_tree("zenoh", &msg_args);
                tree_args.start += msg_len;
                summary.append(|| format!("{msg:?}").split('(').next().unwrap_or("Scout").to_string());
            }
            anyhow::Ok(summary)
        });
        let s = summary.map(|s| format!("{s}")).unwrap_or_default();
        let summary_c_str = CString::new(s).unwrap();
        epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as _);
        epan_sys::col_add_str((*pinfo).cinfo, epan_sys::COL_INFO as _, summary_c_str.as_ptr());
        return tvb_len as std::ffi::c_int;
    }

    let msgs = {
        let mut rbatch = match new_rbatch(tvb_slice, IS_COMPRESSION) {
            Ok(rbatch) => rbatch,
            Err(err) => {
                ws_log::message!("zenoh_udp: {err} (no={})", (*pinfo).num);
                return 0;
            }
        };
        let mut msgs = Vec::new();

        let mut offset: usize = 0;
        while !rbatch.is_empty() {
            let Ok((msg, len)): Result<(TransportMessage, BatchSize), _> = rbatch.decode() else {
                ws_log::message!(
                    "zenoh_udp: failed to decode transport message (no={})",
                    (*pinfo).num
                );
                return 0;
            };

            msgs.push(Message {
                msg,
                len: len as _,
                offset,
            });
            offset += len as usize;
        }

        msgs
    };

    let summary = PROTOCOL_DATA.with(|data| {
        let borrowed_data = data.borrow();

        let ti =
            epan_sys::proto_tree_add_item(tree, borrowed_data.id, tvb, 0, -1, epan_sys::ENC_NA);
        let st = *borrowed_data
            .st_map
            .get("zenoh")
            .expect("zenoh subtree not registered");
        let zenoh_tree = epan_sys::proto_item_add_subtree(ti, st);

        let tree_args = TreeArgs {
            tree: zenoh_tree,
            tvb,
            hf_map: &borrowed_data.hf_map,
            st_map: &borrowed_data.st_map,
            start: 0,
            length: tvb_len,
            spans: None,
            local_spans: None,
        };

        for m in &msgs {
            conversation::update_state(pinfo, &m.msg);
        }
        conversation::update_tree(tvb, pinfo, zenoh_tree, ti);

        let span_maps: Vec<SpanMap> = msgs.iter().map(|m| {
            let mut span_map = SpanMap::new();
            #[allow(static_mut_refs)]
            if !IS_COMPRESSION && m.offset + m.len <= tvb_slice.len() {
                let msg_bytes = &tvb_slice[m.offset..m.offset + m.len];
                let mut cursor = span::SpanCursor::new(msg_bytes);
                if let Err(e) = record_transport_message_spans(&m.msg, &mut cursor, "zenoh", &mut span_map) {
                    ws_log::message!("span recording error: {e}");
                    span_map.clear();
                }
                for s in span_map.values_mut() {
                    s.start += m.offset;
                    s.end += m.offset;
                }
            }
            span_map
        }).collect();

        for (m, span_map) in msgs.iter().zip(span_maps.iter()) {
            let msg_tree = TreeArgs {
                start: m.offset,
                length: m.len,
                spans: if span_map.is_empty() { None } else { Some(span_map) },
                local_spans: None,
                ..tree_args
            };
            m.msg.add_to_tree("zenoh", &msg_tree).unwrap();
        }

        let mut batch_summary = SizedSummary::new(MAX_BATCH_SUMMARY);
        for m in &msgs {
            batch_summary.append(|| {
                let mut s = transport_message_summary(&m.msg);
                if s.len() > MSG_SUMMARY_LIMIT {
                    s.truncate(MSG_SUMMARY_LIMIT);
                    s += "...]";
                }
                s
            });
        }
        batch_summary
    });

    let summary_c_str = CString::new(format!("{summary}")).unwrap();
    epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as _);
    epan_sys::col_add_str(
        (*pinfo).cinfo,
        epan_sys::COL_INFO as _,
        summary_c_str.as_ptr(),
    );

    tvb_len as std::ffi::c_int
}

/// A single decoded transport message with its position within the batch payload.
#[derive(Debug, PartialEq)]
struct Message {
    pub msg: TransportMessage,
    /// Byte offset relative to the start of the batch payload (after the 2-byte header).
    pub offset: usize,
    pub len: usize,
}
