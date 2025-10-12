use std::ffi::{c_char, CString};

use anyhow::{anyhow, Result};
use zenoh_buffers::{reader::Reader, ZSlice};
use zenoh_protocol::{
    network::{NetworkBody, NetworkMessage},
    transport::{BatchSize, TransportMessage},
};
use zenoh_transport::common::batch::{BatchConfig, RBatch};

pub fn nul_terminated_str(s: &str) -> Result<*const c_char> {
    Ok(Box::leak(CString::new(s)?.into_boxed_c_str()).as_ptr())
}

pub(crate) unsafe fn nul_terminated_str2<S>(s: S) -> Result<*mut c_char>
where
    S: Into<Vec<u8>>,
{
    let s = CString::new(s)?;
    Ok(epan_sys::wmem_strdup(
        epan_sys::wmem_file_scope(),
        s.as_ptr(),
    ))
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

pub fn create_rbatch(
    reader: &mut &[u8],
    batch_size: usize,
    is_compression: bool,
) -> Result<RBatch> {
    // Read sliced message into a RBatch
    let mut batch = vec![0_u8; batch_size];
    reader
        .read_exact(&mut batch[0..batch_size])
        .expect("Failed to read the batch.");
    let zslice = ZSlice::from(batch.clone());
    let config = BatchConfig {
        mtu: BatchSize::MAX,
        is_streamed: false,
        is_compression,
    };
    let mut rbatch = RBatch::new(config, zslice.clone());
    if rbatch
        .initialize(|| zenoh_buffers::vec::uninit(config.mtu as usize).into_boxed_slice())
        .is_err()
    {
        // In case TransportMessage like InitAck are not compressed but try to decompress
        let config = BatchConfig {
            mtu: BatchSize::MAX,
            is_streamed: false,
            is_compression: false,
        };
        rbatch = RBatch::new(config, zslice);
        rbatch
            .initialize(|| zenoh_buffers::vec::uninit(config.mtu as usize).into_boxed_slice())
            .map_err(|e| anyhow!("Failed to initialize rbatch due to {e}"))?;
    }
    Ok(rbatch)
}

pub(crate) fn network_message_summary(msg: &NetworkMessage) -> String {
    use NetworkBody::*;
    match &msg.body {
        OAM(_) => "OAM".to_string(),
        Push(_) => "Push".to_string(),
        Request(_) => "Request".to_string(),
        Response(_) => "Response".to_string(),
        ResponseFinal(_) => "ResponseFinal".to_string(),
        Interest(_) => "Interest".to_string(),
        Declare(_) => "Declare".to_string(),
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
