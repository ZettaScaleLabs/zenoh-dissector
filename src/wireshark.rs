use crate::{header_field::FieldKind, utils::nul_terminated_str};
use anyhow::Result;
use epan_sys::{field_display_e, ftenum};

impl FieldKind {
    pub fn convert(self) -> (field_display_e, ftenum) {
        match self {
            Self::Text => (
                epan_sys::field_display_e_BASE_NONE,
                epan_sys::ftenum_FT_STRING,
            ),
            Self::Branch => (
                epan_sys::field_display_e_BASE_NONE,
                epan_sys::ftenum_FT_NONE,
            ),
            // Self::Number => (
            //     epan_sys::field_display_e_BASE_DEC,
            //     epan_sys::ftenum_FT_UINT8,
            // ),
            // Self::Bytes => (
            //     epan_sys::field_display_e_SEP_SPACE,
            //     epan_sys::ftenum_FT_BYTES,
            // ),
        }
    }
}

pub fn register_header_field(
    proto_id: i32,
    field_name: &str,
    filter_name: &str,
    field_kind: FieldKind,
) -> Result<std::ffi::c_int> {
    let hf_index_ptr = Box::leak(Box::new(-1)) as *mut _;

    let (field_display, field_type) = field_kind.convert();
    let hf_register_info = epan_sys::hf_register_info {
        p_id: hf_index_ptr,
        hfinfo: epan_sys::header_field_info {
            name: nul_terminated_str(field_name)?,
            abbrev: nul_terminated_str(filter_name)?,
            type_: field_type,
            display: field_display as _,
            strings: std::ptr::null(),
            bitmask: 0,
            blurb: std::ptr::null(),
            id: -1,
            parent: 0,
            ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
            same_name_prev_id: -1,
            same_name_next: std::ptr::null_mut(),
        },
    };
    let hfs = Box::leak(Box::new([hf_register_info])) as *mut _;

    unsafe {
        epan_sys::proto_register_field_array(proto_id, hfs, 1);
    }
    debug_assert_ne!(unsafe { *hf_index_ptr }, -1);
    Ok(unsafe { *hf_index_ptr })
}
