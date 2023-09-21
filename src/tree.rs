use crate::utils::nul_terminated_str;
use anyhow::{bail, Result};
use std::collections::HashMap;

type HFPointerMap = HashMap<String, std::ffi::c_int>;

#[derive(Debug, Clone, Copy)]
pub struct TreeArgs<'a> {
    pub tree: *mut epan_sys::proto_tree,
    pub tvb: *mut epan_sys::tvbuff,
    pub hf_map: &'a HFPointerMap,
    pub start: usize,
    pub length: usize,
}

impl TreeArgs<'_> {
    pub fn get_hf(&self, key: &str) -> Result<std::ffi::c_int> {
        if let Some(hf) = self.hf_map.get(key) {
            Ok(*hf)
        } else {
            bail!("{key} not found in {:?}", &self.hf_map)
        }
    }

    pub fn make_subtree(&self, key: &str, name: &str) -> Result<Self> {
        let ett_ptr = Box::leak(Box::new(-1)) as *mut _;
        unsafe {
            epan_sys::proto_register_subtree_array([ett_ptr].as_mut_ptr(), 1);
        }
        let ett = unsafe { *ett_ptr };

        let mut new_args = *self;
        new_args.tree = unsafe {
            let ti = epan_sys::proto_tree_add_none_format(
                self.tree,
                self.get_hf(key)?,
                self.tvb,
                self.start as _,
                self.length as _,
                nul_terminated_str(name).unwrap(),
            );

            epan_sys::proto_item_add_subtree(ti, ett)
        };

        Ok(new_args)
    }
}

pub trait AddToTree {
    fn add_to_tree(&self, prefix: &str, args: &TreeArgs) -> Result<()>;
}
