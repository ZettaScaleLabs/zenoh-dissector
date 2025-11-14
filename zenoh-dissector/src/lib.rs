mod header_field;
mod macros;
mod tree;
mod utils;
mod wireshark;
mod zenoh_impl;

use anyhow::Result;
use header_field::Registration;
use std::cell::RefCell;
use std::collections::HashMap;
use tree::{AddToTree, TreeArgs};
use utils::transport_message_summary;
use utils::{nul_terminated_str, SizedSummary};
use wireshark::register_header_field;
use zenoh_buffers::reader::HasReader;
use zenoh_buffers::reader::Reader;
use zenoh_impl::ZenohProtocol;

use zenoh_protocol::transport::{BatchSize, TransportMessage};
use zenoh_transport::common::batch::Decode;

// Version symbols are generated at build time from Cargo.toml metadata
include!(concat!(env!("OUT_DIR"), "/version.rs"));

// Max number of summary of batch in one packet
static MAX_PACKET_SUMMARY: usize = 5;
// Max number of summary of messages in one batch
static MAX_BATCH_SUMMARY: usize = 5;
// Max length of summary of messages
static MSG_SUMMARY_LIMIT: usize = 30;

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
            log::info!("Update TCP Port: {CURR_TCP_PORT} -> {TCP_PORT}");
        }
        PROTOCOL_DATA.with(|data| {
            let handle = data
                .borrow()
                .handle
                .expect("Handle after registration shouldn't be empty");
            let tcp_keyword = nul_terminated_str("tcp.port").unwrap();
            epan_sys::dissector_delete_uint(tcp_keyword, CURR_TCP_PORT, handle);
            epan_sys::dissector_add_uint_with_preference(tcp_keyword, TCP_PORT as _, handle);
        });
        CURR_TCP_PORT = TCP_PORT;
    }

    if CURR_UDP_PORT != UDP_PORT {
        #[allow(static_mut_refs)] // Wireshark requires these references to be static mut
        {
            log::info!("Update UDP Port: {CURR_UDP_PORT} -> {UDP_PORT}");
        }
        PROTOCOL_DATA.with(|data| {
            let handle = data
                .borrow()
                .handle
                .expect("Handle after registration shouldn't be empty");
            let udp_keyword = nul_terminated_str("udp.port").unwrap();
            epan_sys::dissector_delete_uint(udp_keyword, CURR_UDP_PORT, handle);
            epan_sys::dissector_add_uint_with_preference(udp_keyword, UDP_PORT as _, handle);
        });
        CURR_UDP_PORT = UDP_PORT;
    }
}

fn register_zenoh_protocol() -> Result<()> {
    let proto_id = unsafe {
        epan_sys::proto_register_protocol(
            nul_terminated_str("Zenoh Protocol")?,
            nul_terminated_str("Zenoh")?,
            nul_terminated_str("zenoh")?,
        )
    };

    // Register preferences for the zenoh protocol
    unsafe {
        let zenoh_module = epan_sys::prefs_register_protocol(proto_id, Some(prefs_callback));
        epan_sys::prefs_register_uint_preference(
            zenoh_module,
            nul_terminated_str("tcp.port")?,
            nul_terminated_str("TCP Port")?,
            nul_terminated_str("Zenoh TCP Port to listen to")?,
            10 as _,
            &raw mut TCP_PORT as _,
        );
        epan_sys::prefs_register_uint_preference(
            zenoh_module,
            nul_terminated_str("udp.port")?,
            nul_terminated_str("UDP Port")?,
            nul_terminated_str("Zenoh UDP Port to listen to")?,
            10 as _,
            &raw mut UDP_PORT as _,
        );
        epan_sys::prefs_register_bool_preference(
            zenoh_module,
            nul_terminated_str("is_compression")?,
            nul_terminated_str("Is Compression")?,
            nul_terminated_str("Is Zenoh message compressed")?,
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
        log::error!("{err}");
    }
}

unsafe extern "C" fn register_handoff() {
    PROTOCOL_DATA.with(|data| {
        let proto_id = data.borrow().id;

        let handle = epan_sys::create_dissector_handle(Some(dissect_main), proto_id);
        epan_sys::dissector_add_uint_with_preference(
            nul_terminated_str("tcp.port").unwrap(),
            TCP_PORT as _,
            handle,
        );
        epan_sys::dissector_add_uint_with_preference(
            nul_terminated_str("udp.port").unwrap(),
            UDP_PORT as _,
            handle,
        );
        data.borrow_mut().handle = Some(handle);

        // See https://www.wireshark.org/docs/wsar_html/group__packet.html#gac1f89fb22ed3dd53cb3aecbc7b87a528
        epan_sys::heur_dissector_add(
            nul_terminated_str("tcp").unwrap(),
            Some(dissect_heur),
            nul_terminated_str("Zenoh over TCP (heuristic)").unwrap(),
            nul_terminated_str("zenoh_tcp_heur").unwrap(),
            proto_id,
            epan_sys::heuristic_enable_e_HEURISTIC_DISABLE,
        );
        epan_sys::heur_dissector_add(
            nul_terminated_str("udp").unwrap(),
            Some(dissect_heur),
            nul_terminated_str("Zenoh over UDP (heuristic)").unwrap(),
            nul_terminated_str("zenoh_udp_heur").unwrap(),
            proto_id,
            epan_sys::heuristic_enable_e_HEURISTIC_DISABLE,
        );

        #[allow(static_mut_refs)] // Wireshark requires these references to be static mut
        {
            log::info!(
                "Zenoh dissector is registered for TCP port {TCP_PORT} and UDP port {UDP_PORT}"
            );
        }
        log::info!("Zenoh heuristic dissector is registered for TCP and UDP");
    });
}

unsafe fn try_dissect_in_zenoh(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    _data: *mut std::ffi::c_void,
) -> (anyhow::Result<SizedSummary>, usize) {
    // Update the protocol column
    epan_sys::col_set_str(
        (*pinfo).cinfo,
        epan_sys::COL_PROTOCOL as _,
        nul_terminated_str("Zenoh").unwrap(),
    );

    // Extract the tvb (Testy Virtual Buffer) represents the packet's buffer
    let tvb_len = unsafe { epan_sys::tvb_reported_length(tvb) as usize };
    let mut tvb_buf = vec![0; tvb_len];
    unsafe {
        epan_sys::tvb_memcpy(
            tvb,
            tvb_buf.as_mut_ptr() as *mut std::ffi::c_void,
            0,
            tvb_len,
        );
    }

    let mut reader = tvb_buf.reader();

    let root_key = "zenoh";
    let summary = PROTOCOL_DATA.with(|data| {
        let tree_args = TreeArgs {
            tree,
            tvb,
            hf_map: &data.borrow().hf_map,
            st_map: &data.borrow().st_map,
            start: 0,
            length: reader.len(),
        };
        let mut tree_args = tree_args.make_subtree(root_key, "Zenoh Protocol")?;

        let mut packet_summary = utils::SizedSummary::new(MAX_PACKET_SUMMARY);

        if (*pinfo).can_desegment > 0 {
            // This branch aims for TCP

            // At least containing a valid header
            assert!(reader.len() >= 2);

            // Iterate batches in a packet
            while reader.len() >= 2 {
                // Fetch the batch size
                let mut length = [0_u8; 2];
                reader.read_exact(&mut length).expect("Didn't read");
                let batch_size = BatchSize::from_le_bytes(length) as usize;

                // Need to desegment if the batch size exceeds this packet size
                if batch_size > reader.len() {
                    (*pinfo).desegment_offset = 0;
                    (*pinfo).desegment_len = epan_sys::DESEGMENT_ONE_MORE_SEGMENT;
                    log::trace!(
                        "Skip since batch_size={} >= reader.len()={}",
                        batch_size,
                        reader.len()
                    );
                    break;
                }

                let mut rbatch = utils::create_rbatch(&mut reader, batch_size, IS_COMPRESSION)?;

                // Skip two bytes for the batch_size
                tree_args.start += 2;

                // Iterate messages in a batch
                let mut batch_summary = utils::SizedSummary::new(MAX_BATCH_SUMMARY);
                while !rbatch.is_empty() {
                    // Read and decode the bytes to TransportMessage
                    let (msg, msg_len): (TransportMessage, BatchSize) = rbatch
                        .decode()
                        .map_err(|_| anyhow::anyhow!("decoding error"))?;

                    tree_args.length = msg_len as _;
                    msg.add_to_tree("zenoh", &tree_args)?;
                    tree_args.start += tree_args.length;

                    batch_summary.append(|| {
                        let mut msg_summary = transport_message_summary(&msg);
                        if msg_summary.len() > MSG_SUMMARY_LIMIT {
                            msg_summary.truncate(MSG_SUMMARY_LIMIT);
                            msg_summary += "...]";
                        }
                        msg_summary
                    });
                }

                packet_summary.append(|| format!("{batch_summary}"));
            }
        } else {
            // This branch aims for UDP

            // Fetch the batch size
            let batch_size = reader.len();

            let mut rbatch = utils::create_rbatch(&mut reader, batch_size, IS_COMPRESSION)?;

            // Iterate messages in a batch
            let mut batch_summary = utils::SizedSummary::new(MAX_BATCH_SUMMARY);
            while !rbatch.is_empty() {
                // Read and decode the bytes to TransportMessage
                let (msg, msg_len): (TransportMessage, BatchSize) = rbatch
                    .decode()
                    .map_err(|_| anyhow::anyhow!("decoding error"))?;

                tree_args.length = msg_len as _;
                msg.add_to_tree("zenoh", &tree_args)?;
                tree_args.start += tree_args.length;

                batch_summary.append(|| {
                    let mut msg_summary = msg.to_string();
                    if msg_summary.len() > MSG_SUMMARY_LIMIT {
                        msg_summary.truncate(MSG_SUMMARY_LIMIT);
                        msg_summary += "...]";
                    }
                    msg_summary
                });
            }

            packet_summary = batch_summary;

            // Update the range of the buffer to display
            tree_args.start += tree_args.length;
        }

        anyhow::Ok(packet_summary)
    });

    (summary, tvb_len)
}

unsafe extern "C" fn dissect_main(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    let (summary, tvb_len) = try_dissect_in_zenoh(tvb, pinfo, tree, data);

    match summary {
        Ok(packet_summary) => show_summary(pinfo, packet_summary),
        Err(err) => show_error(pinfo, err),
    }

    tvb_len as _
}

unsafe extern "C" fn dissect_heur(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    data: *mut std::ffi::c_void,
) -> bool {
    if let Ok(summary) = try_dissect_in_zenoh(tvb, pinfo, tree, data).0 {
        show_summary(pinfo, summary);
        true
    } else {
        false
    }
}

unsafe fn show_error(pinfo: *mut epan_sys::_packet_info, err: anyhow::Error) {
    log::error!("{err}");
    let summary = format!(
        "{} → {} {}",
        (*pinfo).srcport,
        (*pinfo).destport,
        "Failed to decode possibly due to the experimental compression preference.",
    );

    // Update the info column
    epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as std::ffi::c_int);
    epan_sys::col_set_str(
        (*pinfo).cinfo,
        epan_sys::COL_INFO as _,
        nul_terminated_str(&summary).unwrap(),
    );
}

unsafe fn show_summary(pinfo: *mut epan_sys::_packet_info, packet_summary: SizedSummary) {
    let summary = format!(
        "{} → {} {}",
        (*pinfo).srcport,
        (*pinfo).destport,
        packet_summary
    );

    // Update the info column
    epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as std::ffi::c_int);
    epan_sys::col_set_str(
        (*pinfo).cinfo,
        epan_sys::COL_INFO as _,
        nul_terminated_str(&summary).unwrap(),
    );
}
