use std::{
    ffi::{c_char, CStr, CString},
    mem, ptr,
};

use zenoh_protocol::transport::{TransportBody, TransportMessage};

use crate::{ws_log, PROTOCOL_DATA};

pub const FIELD_SRCZID: &str = "zenoh.srczid";
pub const FIELD_DSTZID: &str = "zenoh.dstzid";

#[derive(Debug)]
#[repr(C)]
struct ConversationState {
    /// C string representing the InitSyn sender's (or "A") ZID of the conversation.
    a_zid: *const c_char,
    /// Source port number of A->B messages.
    a_port: u16,
    /// C string representing the InitSyn receiver's (or "B") ZID of the conversation.
    b_zid: *const c_char,
    /// Source port number of B->A messages.
    b_port: u16,
}

impl ConversationState {
    pub(crate) fn new() -> Self {
        ConversationState {
            a_zid: ptr::null_mut(),
            a_port: u16::default(),
            b_zid: ptr::null_mut(),
            b_port: u16::default(),
        }
    }

    pub(crate) unsafe fn with_pinfo(pinfo: *mut epan_sys::_packet_info) -> *mut ConversationState {
        // See https://github.com/wireshark/wireshark/blob/7f37406d807ac05b72118a5075a405a30de90bb4/epan/conversation.h#L188-L208
        let conv = epan_sys::find_conversation_pinfo(pinfo, 0);
        if conv.is_null() {
            return ptr::null_mut();
        }

        let proto = PROTOCOL_DATA.with_borrow(|data| data.id);

        let proto_data = epan_sys::conversation_get_proto_data(conv, proto);

        if proto_data.is_null() {
            let conv_state = epan_sys::wmem_alloc0(
                epan_sys::wmem_file_scope(),
                mem::size_of::<ConversationState>(),
            ) as *mut ConversationState;

            conv_state.write(ConversationState::new());
            epan_sys::conversation_add_proto_data(conv, proto, conv_state as *mut _);

            conv_state
        } else {
            proto_data as *mut ConversationState
        }
    }

    /// Returns the source ZID for this packet, or `None` if not yet known.
    unsafe fn source(&self, pinfo: *mut epan_sys::_packet_info) -> Option<*const c_char> {
        if !self.a_zid.is_null() && (*pinfo).srcport == self.a_port as u32 {
            Some(self.a_zid)
        } else if !self.b_zid.is_null() && (*pinfo).srcport == self.b_port as u32 {
            Some(self.b_zid)
        } else {
            None
        }
    }

    /// Returns the destination ZID for this packet, or `None` if not yet known.
    unsafe fn destination(&self, pinfo: *mut epan_sys::_packet_info) -> Option<*const c_char> {
        if !self.a_zid.is_null() && (*pinfo).srcport == self.a_port as u32 {
            if self.b_zid.is_null() {
                None
            } else {
                Some(self.b_zid)
            }
        } else if !self.b_zid.is_null() && (*pinfo).srcport == self.b_port as u32 {
            if self.a_zid.is_null() {
                None
            } else {
                Some(self.a_zid)
            }
        } else {
            None
        }
    }
}

/// Update the conversation state from a single transport message.
///
/// Extracts ZIDs from InitSyn/InitAck messages and stores them in the conversation state.
pub(crate) unsafe fn update_state(pinfo: *mut epan_sys::_packet_info, msg: &TransportMessage) {
    // https://github.com/wireshark/wireshark/blob/7f37406d807ac05b72118a5075a405a30de90bb4/epan/conversation.h#L188-L208
    let conv = epan_sys::find_conversation_pinfo(pinfo, 0);
    if conv.is_null() {
        return;
    }

    fn file_scoped_c_str(s: impl AsRef<[u8]>) -> *mut c_char {
        let s = CString::new(s.as_ref()).unwrap();
        unsafe { epan_sys::wmem_strdup(epan_sys::wmem_file_scope(), s.as_ptr()) }
    }

    match &msg.body {
        TransportBody::InitSyn(init_syn) => {
            let conv_state = ConversationState::with_pinfo(pinfo);
            if conv_state.is_null() {
                return;
            }

            if !(*conv_state).a_zid.is_null() {
                ws_log::critical!("duplicate InitSyn");
                return;
            }

            (*conv_state).a_zid = file_scoped_c_str(init_syn.zid.to_string());
            (*conv_state).a_port = (*pinfo).srcport as u16;
        }
        TransportBody::InitAck(init_ack) => {
            let conv_state = ConversationState::with_pinfo(pinfo);
            if conv_state.is_null() {
                return;
            }

            if !(*conv_state).b_zid.is_null() {
                ws_log::critical!("duplicate InitAck");
                return;
            }

            (*conv_state).b_zid = file_scoped_c_str(init_ack.zid.to_string());
            (*conv_state).b_port = (*pinfo).srcport as u16;
        }
        _ => {}
    }
}

/// Add Source/Destination ZID fields to the protocol subtree and update the
/// protocol item text to include them (e.g. "Zenoh Protocol, Src ZID: …, Dst ZID: …").
///
/// Called once per frame from `dissect_zenoh_tcp`, after all batches have been processed
/// so that InitSyn/InitAck in any batch have had a chance to update the conversation state.
pub(crate) unsafe fn update_tree(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    proto_item: *mut epan_sys::_proto_node,
) {
    let conv_state = ConversationState::with_pinfo(pinfo);
    if conv_state.is_null() {
        return;
    }

    if let Some(src) = (*conv_state).source(pinfo) {
        epan_sys::proto_tree_add_string(
            tree,
            PROTOCOL_DATA.with_borrow(|d| d.hf_map[FIELD_SRCZID]),
            tvb,
            0,
            0,
            src,
        );
        let text = CString::new(format!(
            ", Src ZID: {}",
            CStr::from_ptr(src).to_str().unwrap()
        ))
        .unwrap();
        epan_sys::proto_item_append_text(proto_item, text.as_ptr());
    }

    if let Some(dst) = (*conv_state).destination(pinfo) {
        epan_sys::proto_tree_add_string(
            tree,
            PROTOCOL_DATA.with_borrow(|d| d.hf_map[FIELD_DSTZID]),
            tvb,
            0,
            0,
            dst,
        );
        let text = CString::new(format!(
            ", Dst ZID: {}",
            CStr::from_ptr(dst).to_str().unwrap()
        ))
        .unwrap();
        epan_sys::proto_item_append_text(proto_item, text.as_ptr());
    }
}
