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
use zenoh_codec::{RCodec, Zenoh080};
use zenoh_impl::ZenohProtocol;

use zenoh_protocol::transport::{BatchSize, TransportMessage};

#[no_mangle]
#[used]
static plugin_version: [std::ffi::c_char; 6usize] = [48i8, 46i8, 48i8, 46i8, 49i8, 0i8];
#[no_mangle]
#[used]
static plugin_want_major: std::ffi::c_int = 4;
#[no_mangle]
#[used]
static plugin_want_minor: std::ffi::c_int = 0;

#[no_mangle]
#[used]
static MTU: usize = 65536;

#[derive(Default, Debug)]
struct ProtocolData {
    id: i32,
    // header field map
    hf_map: HashMap<String, std::ffi::c_int>,
    // subtree map
    st_map: HashMap<String, std::ffi::c_int>,
}

thread_local! {
    static PROTOCOL_DATA: RefCell<ProtocolData> = ProtocolData::default().into();
}

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

fn register_zenoh_protocol() -> Result<()> {
    let proto_id = unsafe {
        epan_sys::proto_register_protocol(
            nul_terminated_str("Zenoh Protocol")?,
            nul_terminated_str("Zenoh")?,
            nul_terminated_str("zenoh")?,
        )
    };

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
            epan_sys::dissector_add_uint(
                nul_terminated_str("tcp.port").unwrap(),
                7447 as _,
                handle,
            );
            epan_sys::dissector_add_uint(
                nul_terminated_str("udp.port").unwrap(),
                7447 as _,
                handle,
            );
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

    let codec = Zenoh080::new();
    let mut counter = 0;
    let mut reader = tvb_buf.reader();

    let root_key = "zenoh";
    let res = PROTOCOL_DATA.with(|data| {
        let tree_args = TreeArgs {
            tree,
            tvb,
            hf_map: &data.borrow().hf_map,
            st_map: &data.borrow().st_map,
            start: 0,
            length: 0,
        };

        let mut tree_args = tree_args.make_subtree(root_key, "Zenoh Protocol")?;

        // TODO: the summary of packet
        let summary_vec = vec![""];
        if (*pinfo).can_desegment > 0 {
            // Basically this branch is for TCP

            while reader.len() >= 2 {
                // Length of sliced message
                let mut length = [0_u8, 0u8];
                reader.read_exact(&mut length).unwrap();
                let n = BatchSize::from_le_bytes(length) as usize;

                if n > reader.len() {
                    (*pinfo).desegment_offset = 0;
                    (*pinfo).desegment_len = epan_sys::DESEGMENT_ONE_MORE_SEGMENT;
                    log::debug!("Skip since n={} >= reader.len()={}", n, reader.len());
                    break;
                }

                assert!(0 < n && n <= MTU, "{}", n);

                // Read sliced message into a buffer
                let mut buf = vec![0_u8; MTU];
                reader.read_exact(&mut buf[0..n]).unwrap();

                // Update the range of the buffer to display
                tree_args.length = 2 + n;

                // Read and decode the bytes to TransportMessage
                let msg = <Zenoh080 as RCodec<TransportMessage, _>>::read(codec, &mut buf.reader())
                    .map_err(|err| anyhow::anyhow!(format!("{:?}", err)))?;

                // Add the message into the tree
                msg.add_to_tree("zenoh", &tree_args)?;

                // Update the range of the buffer to display
                tree_args.start += tree_args.length;
                counter += 1;
                log::debug!("TCP message counter: {counter}");

                // TODO: Append the summary of this new message
                // summary_vec.push(msg.summary());
            }
        } else {
            // Basically this branch is for UDP

            let n = reader.len();
            assert!(0 < n && n <= MTU, "{}", n);

            // Update the range of the buffer to display
            tree_args.length = n;

            // Add the message into the tree
            let msg = <Zenoh080 as RCodec<TransportMessage, _>>::read(codec, &mut reader)
                .map_err(|err| anyhow::anyhow!(format!("{:?}", err)))?;
            log::debug!(
                "Counter: {}, remaining: {}, msg: {:?}",
                counter,
                reader.remaining(),
                &msg
            );

            // Add the message into the tree
            msg.add_to_tree("zenoh", &tree_args)?;

            // TODO: Append the summary of this new message
            // summary_vec.push(msg.summary());

            // Update the range of the buffer to display
            tree_args.start += tree_args.length;
        }

        anyhow::Ok(summary_vec)
    });

    match res {
        Ok(summary_vec) => {
            let summary = format!(
                "{} → {} [{}]",
                (*pinfo).srcport,
                (*pinfo).destport,
                summary_vec.join(", ")
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
