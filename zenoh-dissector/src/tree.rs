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
use anyhow::{bail, Result};
use std::{collections::HashMap, ffi::CString};

// Pointer HashMap of Header Feild
type HFPointerMap = HashMap<String, std::ffi::c_int>;
// Pointer HashMap of Subtree
type STPointerMap = HashMap<String, std::ffi::c_int>;

#[derive(Debug, Clone, Copy)]
pub struct TreeArgs<'a> {
    pub tree: *mut epan_sys::proto_tree,
    pub tvb: *mut epan_sys::tvbuff,
    pub hf_map: &'a HFPointerMap,
    pub st_map: &'a STPointerMap,
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

    pub fn get_st(&self, key: &str) -> Result<std::ffi::c_int> {
        if let Some(st) = self.st_map.get(key) {
            Ok(*st)
        } else {
            bail!("{key} not found in {:?}", &self.st_map)
        }
    }

    pub fn make_subtree(&self, key: &str, name: &str) -> Result<Self> {
        let mut new_args = *self;
        let name_c_str = CString::new(name).unwrap();
        new_args.tree = unsafe {
            let ti = epan_sys::proto_tree_add_none_format(
                self.tree,
                self.get_hf(key)?,
                self.tvb,
                self.start as _,
                self.length as _,
                name_c_str.as_ptr(),
            );
            epan_sys::proto_item_add_subtree(ti, self.get_st(key)?)
        };

        Ok(new_args)
    }
}

pub trait AddToTree {
    fn add_to_tree(&self, prefix: &str, args: &TreeArgs) -> Result<()>;
}
