//! Integration tests that exercise the full dissector pipeline:
//! build → install → write pcap → run tshark → assert PDML output.
//!
//! These catch bugs that unit tests cannot:
//!
//! Bug 3 (field length): nested fields (e.g. `init_syn.ext_qos`) must NOT inherit
//!   the full TransportMessage byte length. Old code passed `args.length` down
//!   through every recursive `add_to_tree` call without zeroing on descent.
//!
//! Bug 4 (TCP trailing byte): when a complete batch is immediately followed by
//!   the first byte of the next batch's 2-byte length prefix in the same TCP
//!   segment, the dissector's `while reader.len() >= 2` loop exits without
//!   setting `desegment_offset`, so Wireshark never reassembles the next batch.
//!   The second batch's segment is then dissected standalone with a garbage length.
//!
//! # Field names after zids-and-trees merge
//! TODO: after rebasing onto zids-and-trees, update the field name constants below:
//!   TRANSPORT_PREFIX = "zenoh.transport"  (was "zenoh.body")
//!   FRAME_NETWORK_PREFIX = "zenoh.transport.frame.network"  (was "zenoh.body.frame.body")

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use zenoh_buffers::writer::DidntWrite;
use zenoh_codec::{WCodec, Zenoh080};
use zenoh_protocol::{
    core::{ExprId, Reliability, Resolution, WhatAmI, WireExpr, ZenohIdProto},
    network::{
        declare::{self, ext as dec_ext, DeclareKeyExpr, DeclareSubscriber},
        Declare, NetworkBody, NetworkMessage,
    },
    transport::{
        BatchSize, Frame, InitSyn, TransportBody, TransportMessage,
        frame::ext as frame_ext,
        init::ext::PatchType,
    },
};

// TODO(post-zids-and-trees-merge): change to "zenoh.transport"
const TRANSPORT_PREFIX: &str = "zenoh.body";

// ---------------------------------------------------------------------------
// Dissector install
// ---------------------------------------------------------------------------

fn install_dissector() {
    // The plugin dir contains a symlink → target/debug/libzenoh_dissector.so,
    // so a plain `cargo build` is sufficient — no copy needed.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("cargo")
        .args(["build", "-j4"])
        .env("RUSTFLAGS", "-C linker=gcc")
        .current_dir(manifest)
        .status()
        .expect("cargo build failed");
    assert!(status.success(), "cargo build failed");
}

// ---------------------------------------------------------------------------
// Minimal pcap writer
// ---------------------------------------------------------------------------

fn pcap_global_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    h.extend_from_slice(&2u16.to_le_bytes());           // major
    h.extend_from_slice(&4u16.to_le_bytes());           // minor
    h.extend_from_slice(&0i32.to_le_bytes());           // thiszone
    h.extend_from_slice(&0u32.to_le_bytes());           // sigfigs
    h.extend_from_slice(&65535u32.to_le_bytes());       // snaplen
    h.extend_from_slice(&1u32.to_le_bytes());           // link type: Ethernet
    h
}

fn ethernet_ipv4_tcp_packet(tcp_payload: &[u8], seq: u32) -> Vec<u8> {
    let tcp_len = 20 + tcp_payload.len();
    let ip_len = 20 + tcp_len;
    let mut pkt = Vec::with_capacity(14 + ip_len);

    // Ethernet header
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0x00; 6]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes)
    pkt.push(0x45); // version + IHL
    pkt.push(0x00); // DSCP
    pkt.extend_from_slice(&(ip_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]); // id
    pkt.extend_from_slice(&[0x40, 0x00]); // don't fragment
    pkt.push(64);                          // TTL
    pkt.push(6);                           // TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (Wireshark doesn't verify)
    pkt.extend_from_slice(&[127, 0, 0, 1]); // src
    pkt.extend_from_slice(&[127, 0, 0, 1]); // dst

    // TCP header (20 bytes)
    pkt.extend_from_slice(&60000u16.to_be_bytes()); // srcport
    pkt.extend_from_slice(&7447u16.to_be_bytes());  // dstport: Zenoh default
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
    pkt.push(0x50); // data offset = 5
    pkt.push(0x18); // PSH + ACK
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent

    pkt.extend_from_slice(tcp_payload);
    pkt
}

fn pcap_record(pkt: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + pkt.len());
    r.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    r.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    let len = pkt.len() as u32;
    r.extend_from_slice(&len.to_le_bytes()); // incl_len
    r.extend_from_slice(&len.to_le_bytes()); // orig_len
    r.extend_from_slice(pkt);
    r
}

fn zenoh_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(2 + payload.len());
    f.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

/// Write a pcap with a single TCP packet containing one Zenoh batch.
fn write_single_pcap(path: &Path, payload: &[u8]) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&pcap_global_header()).unwrap();
    let pkt = ethernet_ipv4_tcp_packet(&zenoh_frame(payload), 1);
    f.write_all(&pcap_record(&pkt)).unwrap();
}

/// Write a pcap that reproduces Bug 4:
///
/// The TCP stream carries two Zenoh batches back-to-back. The boundary between
/// them is split across two segments so that:
///
///   Segment 1: [frame1_len_lo, frame1_len_hi, ...batch1...,  frame2_len_lo]
///   Segment 2: [frame2_len_hi, ...batch2...]
///
/// With the old desegmentation code the `while reader.len() >= 2` loop exits
/// after decoding batch1 (only 1 byte = frame2_len_lo remains), without
/// requesting more data. Segment 2 arrives standalone; the dissector reads
/// [frame2_len_hi, batch2[0]] as a garbled length and fails to decode batch2.
fn write_bug4_pcap(path: &Path, payload1: &[u8], payload2: &[u8]) {
    let frame1 = zenoh_frame(payload1);
    let frame2 = zenoh_frame(payload2);

    // Segment 1: complete frame1 + first byte of frame2's length prefix
    let mut seg1 = frame1.clone();
    seg1.push(frame2[0]);

    // Segment 2: rest of frame2 (second length byte + payload)
    let seg2 = &frame2[1..];

    let seq2 = 1 + seg1.len() as u32; // contiguous seq numbers

    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&pcap_global_header()).unwrap();
    f.write_all(&pcap_record(&ethernet_ipv4_tcp_packet(&seg1, 1))).unwrap();
    f.write_all(&pcap_record(&ethernet_ipv4_tcp_packet(seg2, seq2))).unwrap();
}

// ---------------------------------------------------------------------------
// Zenoh message encoding
// ---------------------------------------------------------------------------

fn encode_transport<T>(msg: &T) -> Vec<u8>
where
    for<'w> Zenoh080: WCodec<&'w T, &'w mut Vec<u8>, Output = Result<(), DidntWrite>>,
{
    let mut buf = Vec::new();
    Zenoh080::new().write(&mut buf, msg).unwrap();
    buf
}

fn make_init_syn() -> TransportMessage {
    TransportMessage {
        body: TransportBody::InitSyn(InitSyn {
            version: 0x08,
            whatami: WhatAmI::Client,
            zid: ZenohIdProto::rand(),
            resolution: Resolution::default(),
            batch_size: BatchSize::default(),
            ext_qos: None,
            ext_qos_link: None,
            ext_auth: None,
            ext_mlink: None,
            ext_lowlatency: None,
            ext_compression: None,
            ext_patch: PatchType::NONE,
        }),
    }
}

// ---------------------------------------------------------------------------
// tshark runner + PDML helpers
// ---------------------------------------------------------------------------

fn run_tshark(pcap: &Path) -> String {
    let out = Command::new("tshark")
        .args([
            "-r", pcap.to_str().unwrap(),
            "-T", "pdml",
            "-d", "tcp.port==7447,zenoh",
            "-o", "tcp.desegment_tcp_streams:TRUE",
        ])
        .output()
        .expect("tshark not found");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// All (pos, size) pairs for a named field across the whole PDML.
fn field_spans(pdml: &str, name: &str) -> Vec<(usize, usize)> {
    let mut result = Vec::new();
    for line in pdml.lines() {
        if line.contains(&format!("name=\"{name}\"")) {
            let pos = attr(line, "pos");
            let size = attr(line, "size");
            if let (Some(p), Some(s)) = (pos, size) {
                result.push((p, s));
            }
        }
    }
    result
}


fn attr(line: &str, name: &str) -> Option<usize> {
    let needle = format!("{name}=\"");
    let start = line.find(&needle)? + needle.len();
    let end = line[start..].find('"')? + start;
    line[start..end].parse().ok()
}

fn tshark_available() -> bool {
    Command::new("tshark").arg("--version").output().is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Bug 3: every field inside an InitSyn — including optional extension fields
/// whose value is `None` — must have `size` < the total TransportMessage byte
/// count. Old code passed `args.length` (full message size) down through all
/// recursive `add_to_tree` calls without zeroing on descent.
///
/// The optional fields fall back to `(args.start, args.length)` when no span
/// is recorded for them, which is the variant of Bug 3 that span recording
/// alone does not fix.
#[test]
fn nested_fields_have_correct_byte_size() {
    if !tshark_available() {
        eprintln!("skipping: tshark not found");
        return;
    }
    install_dissector();

    let msg = make_init_syn();
    let payload = encode_transport(&msg);
    let total_len = payload.len();

    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("init_syn.pcap");
    write_single_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);

    // Primary fields must have their exact wire widths
    let version_spans = field_spans(&pdml, &format!("{TRANSPORT_PREFIX}.init_syn.version"));
    assert!(!version_spans.is_empty(), "version field not found in PDML:\n{pdml}");
    for (_, size) in &version_spans {
        assert_eq!(*size, 1, "version must be 1 byte, got {size}");
    }
    let whatami_spans = field_spans(&pdml, &format!("{TRANSPORT_PREFIX}.init_syn.whatami"));
    assert!(!whatami_spans.is_empty(), "whatami field not found in PDML");
    for (_, size) in &whatami_spans {
        assert_eq!(*size, 1, "whatami must be 1 byte, got {size}");
    }

    // No field — including optional None extensions — may claim the full
    // message length. That would mean the old Bug 3 behaviour is still present.
    let checked_fields = [
        "version", "whatami", "zid", "resolution", "batch_size",
        // Optional extension fields: None values must not inherit full-packet size
        "ext_qos", "ext_qos_link", "ext_auth", "ext_mlink",
    ];
    for suffix in checked_fields {
        let name = format!("{TRANSPORT_PREFIX}.init_syn.{suffix}");
        for (_, size) in field_spans(&pdml, &name) {
            assert_ne!(
                size, total_len,
                "'{name}' size={size} equals total message length — \
                 field is inheriting the full TransportMessage length (Bug 3)"
            );
        }
    }
}

/// Bug 4: when two Zenoh batches are transmitted back-to-back and the boundary
/// between them falls such that only the first byte of the second batch's
/// 2-byte length prefix is in segment 1, the old dissector exits its decode
/// loop without requesting desegmentation. Segment 2 then arrives standalone
/// and the dissector mis-reads [len2_hi, batch2[0]] as a garbage batch length,
/// losing the second batch entirely.
///
/// We use two InitSyn batches and assert that `init_syn.version` appears twice
/// in the PDML — once per successfully decoded batch. A garbled second batch
/// produces no sub-fields, so the count stays at 1 with the old code.
///
/// After the fix (`tcp_dissect_pdus`), Wireshark handles PDU framing and both
/// batches are decoded.
#[test]
fn trailing_byte_batch_boundary_triggers_reassembly() {
    if !tshark_available() {
        eprintln!("skipping: tshark not found");
        return;
    }
    install_dissector();

    // Two separate InitSyn batches. The second batch's 2-byte length prefix
    // will be split across the two TCP segments (first byte in seg1, second in seg2).
    let batch1 = encode_transport(&make_init_syn());
    let batch2 = encode_transport(&make_init_syn());

    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bug4.pcap");
    write_bug4_pcap(&pcap, &batch1, &batch2);

    let pdml = run_tshark(&pcap);

    // If both batches decode correctly, version appears twice (once per InitSyn).
    // With Bug 4, the second batch is lost → count stays at 1.
    let version_field = format!("{TRANSPORT_PREFIX}.init_syn.version");
    let count = field_spans(&pdml, &version_field).len();
    assert_eq!(
        count, 2,
        "expected init_syn.version to appear twice (one per batch), got {count}. \
         Bug 4: trailing byte at batch boundary prevented reassembly of the second batch.\n\
         PDML:\n{pdml}"
    );
}

/// Multi-message frame span collision: when a single Frame carries two Declare
/// sub-messages (e.g. DeclareKeyExpr then DeclareSubscriber), all messages share
/// the same span-map prefix key. Recording spans for all messages and letting later
/// ones overwrite means the first Declare's fields get the second Declare's byte
/// positions — the first sub-message highlights the wrong bytes in the hex panel.
///
/// We assert that:
///   1. `declare_key_expr.id` has `size=1` (1 VLE byte) at the correct position.
///   2. `declare_key_expr.id.pos` < `declare_subscriber.id.pos`
///      (the key-expr id appears before the subscriber id in the packet).
///
/// With the old "record all, last wins" behaviour both fields point to the same
/// (second message's) position so assertion 2 fails: key-expr id pos ≥ subscriber pos.
#[test]
fn first_declare_in_multi_message_frame_highlights_correct_bytes() {
    if !tshark_available() {
        eprintln!("skipping: tshark not found");
        return;
    }
    install_dissector();

    // Build a Frame carrying two Declare messages back-to-back.
    let key_expr_suffix = "demo/example";
    let subscriber_suffix = "/**";

    let decl1 = NetworkMessage {
        body: NetworkBody::Declare(Declare {
            interest_id: None,
            ext_qos: dec_ext::QoSType::DEFAULT,
            ext_tstamp: None,
            ext_nodeid: dec_ext::NodeIdType::DEFAULT,
            body: declare::DeclareBody::DeclareKeyExpr(DeclareKeyExpr {
                id: 1 as ExprId,
                wire_expr: WireExpr::from(key_expr_suffix),
            }),
        }),
        reliability: Reliability::Reliable,
    };

    let decl2 = NetworkMessage {
        body: NetworkBody::Declare(Declare {
            interest_id: None,
            ext_qos: dec_ext::QoSType::DEFAULT,
            ext_tstamp: None,
            ext_nodeid: dec_ext::NodeIdType::DEFAULT,
            body: declare::DeclareBody::DeclareSubscriber(DeclareSubscriber {
                id: 0,
                wire_expr: WireExpr::from(subscriber_suffix),
            }),
        }),
        reliability: Reliability::Reliable,
    };

    let frame_msg = TransportMessage {
        body: TransportBody::Frame(Frame {
            reliability: Reliability::Reliable,
            sn: 1,
            ext_qos: frame_ext::QoSType::DEFAULT,
            payload: vec![decl1, decl2],
        }),
    };

    let payload = encode_transport(&frame_msg);
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("multi_declare.pcap");
    write_single_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);

    // The first Declare's id field must have size=1 (exactly one VLE byte).
    let key_expr_id_field = format!("{TRANSPORT_PREFIX}.frame.payload.body.declare.body.declare_key_expr.id");
    let key_expr_spans = field_spans(&pdml, &key_expr_id_field);
    assert!(!key_expr_spans.is_empty(), "declare_key_expr.id not found in PDML:\n{pdml}");
    let (key_expr_pos, key_expr_size) = key_expr_spans[0];
    assert_eq!(
        key_expr_size, 1,
        "declare_key_expr.id must be 1 byte, got {key_expr_size}. \
         If size equals the subscriber id's size at the subscriber's position, \
         the first Declare's spans are being overwritten by the second."
    );

    // The second Declare's id field: if it was given a non-zero byte range, it must
    // be at a higher byte offset than the first Declare's id.
    // With the old "last wins" bug, key_expr.id would be given the subscriber's
    // position (key_expr_pos ≥ subscriber_pos, both pointing to the same bytes).
    let sub_id_field = format!("{TRANSPORT_PREFIX}.frame.payload.body.declare.body.declare_subscriber.id");
    let sub_spans = field_spans(&pdml, &sub_id_field);
    if let Some(&(sub_pos, sub_size)) = sub_spans.first() {
        if sub_size > 0 {
            assert!(
                key_expr_pos < sub_pos,
                "declare_key_expr.id at pos={key_expr_pos} must precede \
                 declare_subscriber.id at pos={sub_pos}. \
                 Both pointing to the same or later position means the first Declare's \
                 span was overwritten by the second (multi-message frame span collision bug)."
            );
        }
        // size=0 is acceptable — only the first message gets recorded spans in the
        // current design; subsequent messages intentionally fall back to size=0.
    }
}
