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
use std::{
    error::Error,
    ffi::{c_char, CString},
};
use zenoh_buffers::ZSlice;
use zenoh_protocol::{
    network::{DeclareBody, NetworkBody, NetworkMessage},
    transport::{BatchSize, TransportMessage},
};
use zenoh_transport::common::batch::{BatchConfig, RBatch};

pub fn leak_nul_terminated_str(s: &str) -> Result<*const c_char> {
    Ok(Box::leak(CString::new(s)?.into_boxed_c_str()).as_ptr())
}

pub struct SizedSummary {
    is_full: bool,
    data: Vec<String>,
}

impl SizedSummary {
    pub fn new(limit: usize) -> Self {
        Self {
            is_full: false,
            data: Vec::with_capacity(limit),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn append<F>(&mut self, generate_msg: F)
    where
        F: FnOnce() -> String,
    {
        if !self.is_full {
            if self.data.len() >= self.data.capacity() {
                self.is_full = true;
            } else {
                self.data.push(generate_msg());
            }
        }
    }
}

impl std::fmt::Display for SizedSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content = if self.len() > 1 {
            format!(
                "[{}]",
                self.data.join(", ") + if self.is_full { ", ..." } else { "" }
            )
        } else if self.data.is_empty() {
            "Empty".to_string()
        } else {
            self.data[0].to_owned()
        };
        write!(f, "{}", content)
    }
}

pub(crate) fn new_rbatch(batch: &[u8], compression: bool) -> Result<RBatch, Box<dyn Error>> {
    let zslice = ZSlice::from(batch.to_vec());
    let config = BatchConfig {
        mtu: BatchSize::MAX,
        is_streamed: false,
        is_compression: compression,
    };
    let mut rbatch = RBatch::new(config, zslice.clone());
    if rbatch.initialize(|| vec![0; config.mtu as usize]).is_err() {
        // In case TransportMessage like InitAck are not compressed, try to read without assuming
        // compression
        let config = BatchConfig {
            mtu: BatchSize::MAX,
            is_streamed: false,
            is_compression: false,
        };
        rbatch = RBatch::new(config, zslice);
        rbatch
            .initialize(|| vec![0; config.mtu as usize])
            .map_err(|err| err.to_string())?;
    }
    Ok(rbatch)
}

pub(crate) fn network_message_summary(msg: &NetworkMessage) -> String {
    use NetworkBody::*;
    match &msg.body {
        OAM(_) => "OAM".to_string(),
        Push(p) => {
            let key = crate::resolve_wire_expr(&p.wire_expr);
            if key.is_empty() { "Push".to_string() } else { format!("Push({key})") }
        }
        Request(r) => {
            let key = crate::resolve_wire_expr(&r.wire_expr);
            if key.is_empty() { "Request".to_string() } else { format!("Request({key})") }
        }
        Response(_) => "Response".to_string(),
        ResponseFinal(_) => "ResponseFinal".to_string(),
        Interest(_) => "Interest".to_string(),
        Declare(d) => {
            match &d.body {
                DeclareBody::DeclareKeyExpr(dke) => {
                    let key = crate::resolve_wire_expr(&dke.wire_expr);
                    format!("DeclareKeyExpr({key}→{})", dke.id)
                }
                DeclareBody::DeclareSubscriber(ds) => {
                    let key = crate::resolve_wire_expr(&ds.wire_expr);
                    if key.is_empty() { "DeclareSubscriber".to_string() } else { format!("DeclareSubscriber({key})") }
                }
                DeclareBody::DeclareQueryable(dq) => {
                    let key = crate::resolve_wire_expr(&dq.wire_expr);
                    if key.is_empty() { "DeclareQueryable".to_string() } else { format!("DeclareQueryable({key})") }
                }
                DeclareBody::DeclareToken(dt) => {
                    let key = crate::resolve_wire_expr(&dt.wire_expr);
                    if key.is_empty() { "DeclareToken".to_string() } else { format!("DeclareToken({key})") }
                }
                _ => "Declare".to_string(),
            }
        }
    }
}

pub(crate) fn transport_message_summary(msg: &TransportMessage) -> String {
    use zenoh_protocol::transport::TransportBody::*;
    match &msg.body {
        OAM(_) => "OAM".to_string(),
        InitSyn(_) => "InitSyn".to_string(),
        InitAck(_) => "InitAck".to_string(),
        OpenSyn(_) => "OpenSyn".to_string(),
        OpenAck(_) => "OpenAck".to_string(),
        Close(_) => "Close".to_string(),
        KeepAlive(_) => "KeepAlive".to_string(),
        Frame(frame) => {
            "Frame[".to_string()
                + &frame
                    .payload
                    .iter()
                    .map(network_message_summary)
                    .reduce(|acc, s| acc + "," + &s)
                    .unwrap_or_default()
                + "]"
        }
        Fragment(_) => "Fragment".to_string(),
        Join(_) => "Join".to_string(),
    }
}
