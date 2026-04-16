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
use crate::span::{ByteSpan, SpanMap};
use anyhow::{bail, Result};
use std::{collections::HashMap, ffi::CString};

// Pointer HashMap of Header Feild
type HFPointerMap = HashMap<String, std::ffi::c_int>;
// Pointer HashMap of Subtree
type STPointerMap = HashMap<String, std::ffi::c_int>;

pub struct TreeArgs<'a> {
    pub tree: *mut epan_sys::proto_tree,
    pub tvb: *mut epan_sys::tvbuff,
    pub hf_map: &'a HFPointerMap,
    pub st_map: &'a STPointerMap,
    pub start: usize,
    pub length: usize,
    /// Per-field byte spans shared across the whole transport message.
    pub spans: Option<&'a SpanMap>,
    /// Per-item remapped span map for `#[dissect(vec)]` rendering.
    /// Built by the vec renderer for each item index; checked before `spans`.
    pub local_spans: Option<SpanMap>,
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

    pub fn field_span(&self, field_key: &str) -> (usize, usize) {
        // local_spans (per-vec-item remapping) takes priority over shared spans
        if let Some(ref m) = self.local_spans {
            if let Some(s) = m.get(field_key) {
                return (s.start, s.len());
            }
        }
        self.spans
            .and_then(|m| m.get(field_key))
            .map(|s: &ByteSpan| (s.start, s.len()))
            .unwrap_or((self.start, 0))
    }

    pub fn make_subtree(&self, key: &str, name: &str) -> Result<Self> {
        let (sub_start, sub_len) = self.field_span(key);
        let name_c_str = CString::new(name).unwrap();
        let new_tree = unsafe {
            let ti = epan_sys::proto_tree_add_none_format(
                self.tree,
                self.get_hf(key)?,
                self.tvb,
                sub_start as _,
                sub_len as _,
                name_c_str.as_ptr(),
            );
            epan_sys::proto_item_add_subtree(ti, self.get_st(key)?)
        };

        Ok(Self {
            tree: new_tree,
            tvb: self.tvb,
            hf_map: self.hf_map,
            st_map: self.st_map,
            start: sub_start,
            length: sub_len,
            spans: self.spans,
            local_spans: self.local_spans.clone(),
        })
    }
}

pub trait AddToTree {
    fn add_to_tree(&self, prefix: &str, args: &TreeArgs) -> Result<()>;
}
