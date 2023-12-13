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
use utils::nul_terminated_str;
use wireshark::register_header_field;
use zenoh_buffers::reader::HasReader;
use zenoh_buffers::reader::Reader;
use zenoh_impl::ZenohProtocol;

use zenoh_protocol::transport::{BatchSize, TransportMessage};
use zenoh_transport::common::batch::Decode;

#[no_mangle]
#[used]
static plugin_version: [std::ffi::c_char; 6usize] = [48i8, 46i8, 48i8, 46i8, 49i8, 0i8];
#[no_mangle]
#[used]
static plugin_want_major: std::ffi::c_int = 4;
#[no_mangle]
#[used]
static plugin_want_minor: std::ffi::c_int = 0;

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

static mut IS_COMPRESSION: i32 = 0;
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
        epan_sys::proto_register_plugin(&PLUG);
    }
}

#[no_mangle]
unsafe extern "C" fn prefs_callback() {
    if CURR_TCP_PORT != TCP_PORT {
        println!("Update TCP Port: {CURR_TCP_PORT} -> {TCP_PORT}");
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
        println!("Update UDP Port: {CURR_UDP_PORT} -> {UDP_PORT}");
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

    unsafe {
        let zenoh_module = epan_sys::prefs_register_protocol(proto_id, Some(prefs_callback));
        epan_sys::prefs_register_uint_preference(
            zenoh_module,
            nul_terminated_str("tcp.port")?,
            nul_terminated_str("TCP Port")?,
            nul_terminated_str("Zenoh TCP Port to listen to")?,
            10 as _,
            &mut TCP_PORT as _,
        );
        epan_sys::prefs_register_uint_preference(
            zenoh_module,
            nul_terminated_str("udp.port")?,
            nul_terminated_str("UDP Port")?,
            nul_terminated_str("Zenoh UDP Port to listen to")?,
            10 as _,
            &mut UDP_PORT as _,
        );
        epan_sys::prefs_register_bool_preference(
            zenoh_module,
            nul_terminated_str("is_compression")?,
            nul_terminated_str("Is Compression")?,
            nul_terminated_str("Is Zenoh message compressed")?,
            &mut IS_COMPRESSION as _,
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
        unsafe {
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
        }

        log::info!("Zenoh dissector registered at tcp.port:7447 and udp.port:7447.");
    });
}

unsafe extern "C" fn dissect_main(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::_proto_node,
    _data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
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
    let res = PROTOCOL_DATA.with(|data| {
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

                // if IS_COMPRESSION == 1 {
                //     batch_size = reader.len().min(batch_size)
                // }

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

                let mut rbatch =
                    utils::create_rbatch(&mut reader, batch_size, IS_COMPRESSION == 1, false)?;

                // Skip two bytes for the batch_size
                tree_args.start += 2;

                // Iterate messages in a batch
                let mut batch_summary = utils::SizedSummary::new(MAX_BATCH_SUMMARY);
                // let mut batch_subtree = tree_args.make_subtree("zenoh.body", "BatchMessage")?;
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

                packet_summary.append(|| format!("{batch_summary}"));
            }
        } else {
            // This branch aims for UDP

            // Fetch the batch size
            let batch_size = reader.len();

            let mut rbatch =
                utils::create_rbatch(&mut reader, batch_size, IS_COMPRESSION == 1, false)?;

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

    match res {
        Ok(packet_summary) => {
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
        Err(err) => {
            log::error!("{err}");
        }
    }

    tvb_len as _
}
