use anyhow::Result;
use std::ffi::{c_char, CString};
use zenoh_buffers::reader::Reader;
use zenoh_protocol::transport::BatchSize;
use zenoh_transport::common::batch::{BatchConfig, RBatch};

pub fn nul_terminated_str(s: &str) -> Result<*const c_char> {
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

pub fn create_rbatch(
    reader: &mut &[u8],
    batch_size: usize,
    is_compression: bool,
    is_streamed: bool,
) -> Result<RBatch> {
    // Read sliced message into a RBatch
    let mut batch = vec![0_u8; batch_size];
    reader
        .read_exact(&mut batch[0..batch_size])
        .expect("Failed to read the batch.");
    let config = BatchConfig {
        mtu: BatchSize::MAX,
        is_streamed,
        is_compression,
    };
    let mut rbatch = RBatch::new(config, batch);
    rbatch
        .initialize(|| zenoh_buffers::vec::uninit(config.mtu as usize).into_boxed_slice())
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    Ok(rbatch)
}
