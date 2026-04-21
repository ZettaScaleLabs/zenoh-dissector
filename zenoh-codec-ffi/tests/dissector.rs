//! Integration tests that exercise the full dissector pipeline:
//! build Rust cdylib → cmake build C plugin → install → write pcap → run tshark → assert PDML.

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
        declare::{
            self, ext as dec_ext, DeclareFinal, DeclareKeyExpr, DeclareQueryable,
            DeclareSubscriber, DeclareToken, UndeclareKeyExpr, UndeclareSubscriber,
        },
        Declare, NetworkBody, NetworkMessage, Push, Request, Response, ResponseFinal,
    },
    transport::{
        fragment::ext as frag_ext, frame::ext as frame_ext, init::ext::PatchType, BatchSize, Close,
        Fragment, Frame, InitSyn, Join, KeepAlive, PrioritySn, TransportBody, TransportMessage,
    },
    zenoh::{PushBody, Put, Query, Reply, RequestBody, ResponseBody},
};

const TP: &str = "zenoh.transport";
const NP: &str = "zenoh.transport.frame.network";

// ---------------------------------------------------------------------------
// Dissector install: build Rust cdylib + cmake C plugin + install
// ---------------------------------------------------------------------------

static INSTALL_ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn install_dissector() {
    INSTALL_ONCE.get_or_init(|| {
        install_dissector_impl();
    });
}

fn install_dissector_impl() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().expect("workspace root");

    // Step 1: build the Rust cdylib
    let status = Command::new("cargo")
        .args(["build", "-p", "zenoh-codec-ffi", "-j4"])
        .env("RUSTFLAGS", "-C linker=gcc")
        .current_dir(workspace)
        .status()
        .expect("cargo build failed");
    assert!(status.success(), "cargo build -p zenoh-codec-ffi failed");

    // Step 2: cmake configure
    let build_dir = workspace.join("_tmp/cmake-build");
    std::fs::create_dir_all(&build_dir).unwrap();

    let status = Command::new("cmake")
        .args([
            "-B",
            build_dir.to_str().unwrap(),
            "-S",
            workspace.to_str().unwrap(),
        ])
        .current_dir(workspace)
        .status()
        .expect("cmake configure failed");
    assert!(status.success(), "cmake configure failed");

    // Step 3: cmake build
    let status = Command::new("cmake")
        .args(["--build", build_dir.to_str().unwrap(), "-j4"])
        .current_dir(workspace)
        .status()
        .expect("cmake build failed");
    assert!(status.success(), "cmake --build failed");

    // Determine wireshark version for plugin directory
    let ws_version = {
        let out = Command::new("tshark")
            .arg("--version")
            .output()
            .expect("tshark not found");
        let s = String::from_utf8_lossy(&out.stdout);
        let line = s.lines().next().unwrap_or("");
        let ver = line
            .split_whitespace()
            .find(|t| {
                t.contains('.')
                    && t.chars()
                        .next()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
            })
            .unwrap_or("4.6");
        ver.splitn(3, '.').take(2).collect::<Vec<_>>().join(".")
    };

    let plugin_dir = format!(
        "{}/.local/lib/wireshark/plugins/{ws_version}/epan",
        std::env::var("HOME").unwrap_or_default()
    );
    std::fs::create_dir_all(&plugin_dir).unwrap();

    // Install the C plugin
    let so = build_dir.join("packet-zenoh.so");
    std::fs::copy(&so, format!("{plugin_dir}/packet-zenoh.so"))
        .unwrap_or_else(|e| panic!("failed to copy packet-zenoh.so: {e}"));

    // Install the Rust cdylib alongside (needed at runtime by the C plugin)
    let cdylib = workspace.join("target/debug/libzenoh_codec_ffi.so");
    std::fs::copy(&cdylib, format!("{plugin_dir}/libzenoh_codec_ffi.so"))
        .unwrap_or_else(|e| panic!("failed to copy libzenoh_codec_ffi.so: {e}"));
}

// ---------------------------------------------------------------------------
// Minimal pcap writer
// ---------------------------------------------------------------------------

fn pcap_global_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&65535u32.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    h
}

fn ethernet_ipv4_tcp_packet(tcp_payload: &[u8], seq: u32) -> Vec<u8> {
    let tcp_len = 20 + tcp_payload.len();
    let ip_len = 20 + tcp_len;
    let mut pkt = Vec::with_capacity(14 + ip_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(ip_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x40, 0x00]);
    pkt.push(64);
    pkt.push(6);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[127, 0, 0, 1]);
    pkt.extend_from_slice(&[127, 0, 0, 1]);
    pkt.extend_from_slice(&60000u16.to_be_bytes());
    pkt.extend_from_slice(&7447u16.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.push(0x50);
    pkt.push(0x18);
    pkt.extend_from_slice(&65535u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(tcp_payload);
    pkt
}

fn ethernet_ipv4_udp_packet(udp_payload: &[u8], dstport: u16) -> Vec<u8> {
    let udp_len = 8 + udp_payload.len();
    let ip_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(14 + ip_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(ip_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x40, 0x00]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[127, 0, 0, 1]);
    pkt.extend_from_slice(&[127, 0, 0, 1]);
    pkt.extend_from_slice(&60001u16.to_be_bytes());
    pkt.extend_from_slice(&dstport.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(udp_payload);
    pkt
}

fn pcap_record(pkt: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + pkt.len());
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&0u32.to_le_bytes());
    let len = pkt.len() as u32;
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(pkt);
    r
}

fn zenoh_batch_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(2 + payload.len());
    f.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

fn write_single_tcp_pcap(path: &Path, payload: &[u8]) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&pcap_global_header()).unwrap();
    let pkt = ethernet_ipv4_tcp_packet(&zenoh_batch_frame(payload), 1);
    f.write_all(&pcap_record(&pkt)).unwrap();
}

fn write_single_udp_pcap(path: &Path, payload: &[u8], dstport: u16) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&pcap_global_header()).unwrap();
    let pkt = ethernet_ipv4_udp_packet(payload, dstport);
    f.write_all(&pcap_record(&pkt)).unwrap();
}

fn write_bug4_pcap(path: &Path, payload1: &[u8], payload2: &[u8]) {
    let frame1 = zenoh_batch_frame(payload1);
    let frame2 = zenoh_batch_frame(payload2);
    let mut seg1 = frame1.clone();
    seg1.push(frame2[0]);
    let seg2 = &frame2[1..];
    let seq2 = 1 + seg1.len() as u32;
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&pcap_global_header()).unwrap();
    f.write_all(&pcap_record(&ethernet_ipv4_tcp_packet(&seg1, 1)))
        .unwrap();
    f.write_all(&pcap_record(&ethernet_ipv4_tcp_packet(seg2, seq2)))
        .unwrap();
}

// ---------------------------------------------------------------------------
// Zenoh message encoding helpers
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
            ext_shm: None,
            ext_auth: None,
            ext_mlink: None,
            ext_lowlatency: None,
            ext_compression: None,
            ext_patch: PatchType::NONE,
            ext_region_name: None,
        }),
    }
}

fn make_frame_with(msgs: Vec<NetworkMessage>) -> TransportMessage {
    TransportMessage {
        body: TransportBody::Frame(Frame {
            reliability: Reliability::Reliable,
            sn: 1,
            ext_qos: frame_ext::QoSType::DEFAULT,
            payload: msgs,
        }),
    }
}

fn make_declare_msg(body: declare::DeclareBody) -> NetworkMessage {
    NetworkMessage {
        body: NetworkBody::Declare(Declare {
            interest_id: None,
            ext_qos: dec_ext::QoSType::DEFAULT,
            ext_tstamp: None,
            ext_nodeid: dec_ext::NodeIdType::DEFAULT,
            body,
        }),
        reliability: Reliability::Reliable,
    }
}

fn make_push_put(wire_expr: impl Into<String>, payload_data: &[u8]) -> NetworkMessage {
    NetworkMessage {
        body: NetworkBody::Push(Push {
            wire_expr: WireExpr::from(wire_expr.into()),
            ext_qos: dec_ext::QoSType::DEFAULT,
            ext_tstamp: None,
            ext_nodeid: dec_ext::NodeIdType::DEFAULT,
            payload: PushBody::Put(Put {
                timestamp: None,
                encoding: zenoh_protocol::core::Encoding::default(),
                ext_sinfo: None,
                ext_shm: None,
                ext_attachment: None,
                ext_unknown: vec![],
                payload: zenoh_buffers::ZBuf::from(payload_data.to_vec()),
            }),
        }),
        reliability: Reliability::BestEffort,
    }
}

// ---------------------------------------------------------------------------
// tshark runner + PDML helpers
// ---------------------------------------------------------------------------

fn run_tshark(pcap: &Path) -> String {
    let out = Command::new("tshark")
        .args([
            "-r",
            pcap.to_str().unwrap(),
            "-T",
            "pdml",
            "-d",
            "tcp.port==7447,zenoh",
            "-d",
            "udp.port==7446,zenoh",
            "-d",
            "udp.port==7447,zenoh",
            "-o",
            "tcp.desegment_tcp_streams:TRUE",
        ])
        .output()
        .expect("tshark not found");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

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

fn unclaimed_fields(pdml: &str) -> Vec<String> {
    const ABSENT_SHOW: &[&str] = &["None", "[]"];
    const BRANCH_WORDS: &[&str] = &[
        "TransportBody",
        "NetworkBody",
        "DeclareBody",
        "PushBody",
        "RequestBody",
        "ResponseBody",
        "Zenoh Protocol",
        "Transport (",
        "Scouting (",
        "Network (",
        "Declare (",
        "Push (",
        "Request (",
        "Response (",
        "Batch,",
        "Source ZID:",
        "Destination ZID:",
    ];
    const DEFAULT_SHOW_SUBSTRINGS: &[&str] = &[
        "QoSType { inner: 5 }",
        "priority: Data, congestion: Drop, express: false",
        "NodeIdType { node_id: 0 }",
    ];
    const CONDITIONAL_SUFFIXES: &[&str] = &[".resolution", ".batch_size"];

    let mut suspicious = Vec::new();
    for line in pdml.lines() {
        if !line.contains("name=\"zenoh") {
            continue;
        }
        let size = match attr(line, "size") {
            Some(s) => s,
            None => continue,
        };
        if size > 0 {
            continue;
        }

        let extract = |attr_name: &str| -> Option<String> {
            let needle = format!("{attr_name}=\"");
            let start = line.find(&needle)? + needle.len();
            let end = line[start..].find('"')? + start;
            Some(line[start..end].to_string())
        };

        let name = match extract("name") {
            Some(n) => n,
            None => continue,
        };
        let show = match extract("show") {
            Some(s) => s,
            None => continue,
        };
        let showname = match extract("showname") {
            Some(s) => s,
            None => continue,
        };

        if CONDITIONAL_SUFFIXES.iter().any(|s| name.ends_with(s)) {
            continue;
        }
        if BRANCH_WORDS.iter().any(|w| showname.contains(w)) {
            continue;
        }
        if ABSENT_SHOW.iter().any(|a| show == *a) {
            continue;
        }
        if DEFAULT_SHOW_SUBSTRINGS.iter().any(|d| show.contains(d)) {
            continue;
        }

        suspicious.push(format!("{name}: {showname}"));
    }
    suspicious
}

macro_rules! assert_size {
    ($pdml:expr, $field:expr, $expected:expr) => {{
        let spans = field_spans($pdml, $field);
        let sizes: Vec<usize> = spans.iter().map(|&(_, s)| s).filter(|&s| s > 0).collect();
        assert!(
            !sizes.is_empty(),
            "field '{}' not found with size>0 in PDML",
            $field
        );
        for &sz in &sizes {
            assert_eq!(
                sz, $expected,
                "field '{}' expected size={} got {}",
                $field, $expected, sz
            );
        }
    }};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn nested_fields_have_correct_byte_size() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let msg = make_init_syn();
    let payload = encode_transport(&msg);
    let total_len = payload.len();

    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("init_syn.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);

    let version_spans = field_spans(&pdml, &format!("{TP}.init_syn.version"));
    assert!(
        !version_spans.is_empty(),
        "version field not found in PDML:\n{pdml}"
    );
    for (_, size) in &version_spans {
        assert_eq!(*size, 1, "version must be 1 byte, got {size}");
    }

    for suffix in [
        "version",
        "whatami",
        "zid",
        "resolution",
        "batch_size",
        "ext_qos",
        "ext_qos_link",
        "ext_auth",
        "ext_mlink",
    ] {
        let name = format!("{TP}.init_syn.{suffix}");
        for (_, size) in field_spans(&pdml, &name) {
            assert_ne!(
                size, total_len,
                "'{name}' size={size} equals total message length (Bug 3)"
            );
        }
    }
}

#[test]
fn trailing_byte_batch_boundary_triggers_reassembly() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let batch1 = encode_transport(&make_init_syn());
    let batch2 = encode_transport(&make_init_syn());

    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bug4.pcap");
    write_bug4_pcap(&pcap, &batch1, &batch2);
    let pdml = run_tshark(&pcap);

    let count = field_spans(&pdml, &format!("{TP}.init_syn.version")).len();
    assert_eq!(
        count, 2,
        "expected init_syn.version twice (one per batch), got {count}.\n{pdml}"
    );
}

#[test]
fn first_declare_in_multi_message_frame_highlights_correct_bytes() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let decl1 = make_declare_msg(declare::DeclareBody::DeclareKeyExpr(DeclareKeyExpr {
        id: 1 as ExprId,
        wire_expr: WireExpr::from("demo/example"),
    }));
    let decl2 = make_declare_msg(declare::DeclareBody::DeclareSubscriber(DeclareSubscriber {
        id: 0,
        wire_expr: WireExpr::from("/**"),
    }));

    let payload = encode_transport(&make_frame_with(vec![decl1, decl2]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("multi_declare.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);

    let key_expr_spans = field_spans(&pdml, &format!("{NP}.declare.declare_key_expr.id"));
    assert!(
        !key_expr_spans.is_empty(),
        "declare_key_expr.id not found:\n{pdml}"
    );
    let (key_expr_pos, key_expr_size) = key_expr_spans[0];
    assert_eq!(
        key_expr_size, 1,
        "declare_key_expr.id must be 1 byte, got {key_expr_size}"
    );

    if let Some(&(sub_pos, sub_size)) =
        field_spans(&pdml, &format!("{NP}.declare.declare_subscriber.id")).first()
    {
        if sub_size > 0 {
            assert!(key_expr_pos < sub_pos,
                "declare_key_expr.id at pos={key_expr_pos} must precede declare_subscriber.id at pos={sub_pos}");
        }
    }
}

#[test]
fn sample_pcap_all_encoded_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let pcap = Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets/sample-data.pcap");
    let pdml = run_tshark(&pcap);

    let unclaimed = unclaimed_fields(&pdml);
    assert!(
        unclaimed.is_empty(),
        "Fields with non-absent values but size=0:\n{}",
        unclaimed.join("\n")
    );

    assert_size!(&pdml, &format!("{TP}.init_syn.version"), 1);
    assert_size!(&pdml, &format!("{TP}.init_syn.whatami"), 1);
    assert_size!(&pdml, &format!("{TP}.init_syn.zid"), 16);
    assert_size!(&pdml, &format!("{TP}.init_ack.version"), 1);
    assert_size!(&pdml, &format!("{TP}.init_ack.zid"), 16);
    assert_size!(&pdml, &format!("{TP}.init_ack.cookie"), 50);
    assert_size!(&pdml, &format!("{TP}.open_syn.lease"), 1);
    assert_size!(&pdml, &format!("{TP}.open_syn.initial_sn"), 4);
    assert_size!(&pdml, &format!("{TP}.open_syn.cookie"), 50);
    assert_size!(&pdml, &format!("{TP}.open_ack.lease"), 1);
    assert_size!(&pdml, &format!("{TP}.open_ack.initial_sn"), 4);
    assert_size!(&pdml, &format!("{TP}.frame.sn"), 4);
    assert_size!(&pdml, &format!("{NP}.declare.declare_key_expr.id"), 1);
    assert_size!(&pdml, &format!("{NP}.push.wire_expr"), 27);
    assert_size!(&pdml, &format!("{TP}.close.reason"), 1);
}

#[test]
fn keepalive_decodes() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let msg = TransportMessage {
        body: TransportBody::KeepAlive(KeepAlive {}),
    };
    let payload = encode_transport(&msg);
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("keepalive.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert!(
        pdml.contains("zenoh.transport.keep_alive"),
        "KeepAlive not found:\n{pdml}"
    );
}

#[test]
fn close_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let msg = TransportMessage {
        body: TransportBody::Close(Close {
            reason: 0x05,
            session: true,
        }),
    };
    let payload = encode_transport(&msg);
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("close.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{TP}.close.session"), 1);
    assert_size!(&pdml, &format!("{TP}.close.reason"), 1);
}

#[test]
fn fragment_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let msg = TransportMessage {
        body: TransportBody::Fragment(Fragment {
            reliability: Reliability::Reliable,
            more: false,
            sn: 42,
            payload: zenoh_buffers::ZSlice::from(vec![0xde, 0xad, 0xbe, 0xef]),
            ext_qos: frag_ext::QoSType::DEFAULT,
            ext_first: None,
            ext_drop: None,
        }),
    };
    let payload = encode_transport(&msg);
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fragment.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{TP}.fragment.sn"), 1);
}

#[test]
fn join_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    use std::time::Duration;
    let msg = TransportMessage {
        body: TransportBody::Join(Join {
            version: 0x08,
            whatami: WhatAmI::Peer,
            zid: ZenohIdProto::rand(),
            resolution: Resolution::default(),
            batch_size: BatchSize::default(),
            lease: Duration::from_secs(10),
            next_sn: PrioritySn::DEFAULT,
            ext_qos: None,
            ext_shm: None,
            ext_patch: zenoh_protocol::transport::join::ext::PatchType::NONE,
        }),
    };
    let payload = encode_transport(&msg);
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("join.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{TP}.join.version"), 1);
    assert_size!(&pdml, &format!("{TP}.join.zid"), 16);
    assert_size!(&pdml, &format!("{TP}.join.lease"), 1);
}

#[test]
fn push_put_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let nmsg = make_push_put("demo/test", b"hello world");
    let payload = encode_transport(&make_frame_with(vec![nmsg]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("push_put.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.push.wire_expr"), 11);
    assert_size!(&pdml, &format!("{NP}.push.put.payload"), 11);
}

#[test]
fn declare_queryable_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let decl = make_declare_msg(declare::DeclareBody::DeclareQueryable(DeclareQueryable {
        id: 7,
        wire_expr: WireExpr::from("my/query"),
        ext_info: zenoh_protocol::network::declare::queryable::ext::QueryableInfoType::DEFAULT,
    }));
    let payload = encode_transport(&make_frame_with(vec![decl]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("declare_queryable.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.declare.declare_queryable.id"), 1);
}

#[test]
fn declare_token_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let decl = make_declare_msg(declare::DeclareBody::DeclareToken(DeclareToken {
        id: 3,
        wire_expr: WireExpr::from("tok"),
    }));
    let payload = encode_transport(&make_frame_with(vec![decl]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("declare_token.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.declare.declare_token.id"), 1);
}

#[test]
fn undeclare_key_expr_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let decl = make_declare_msg(declare::DeclareBody::UndeclareKeyExpr(UndeclareKeyExpr {
        id: 1 as ExprId,
    }));
    let payload = encode_transport(&make_frame_with(vec![decl]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("undeclare_key_expr.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.declare.undeclare_key_expr.id"), 1);
}

#[test]
fn undeclare_subscriber_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let decl = make_declare_msg(declare::DeclareBody::UndeclareSubscriber(
        UndeclareSubscriber {
            id: 2,
            ext_wire_expr: zenoh_protocol::network::declare::common::ext::WireExprType::null(),
        },
    ));
    let payload = encode_transport(&make_frame_with(vec![decl]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("undeclare_subscriber.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.declare.undeclare_subscriber.id"), 1);
}

#[test]
fn declare_final_decodes() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let decl = make_declare_msg(declare::DeclareBody::DeclareFinal(DeclareFinal {}));
    let payload = encode_transport(&make_frame_with(vec![decl]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("declare_final.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert!(
        pdml.contains("declare_final"),
        "DeclareFinal not found:\n{pdml}"
    );
}

#[test]
fn request_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let req = NetworkMessage {
        body: NetworkBody::Request(Request {
            id: 1,
            wire_expr: WireExpr::from("demo/query"),
            ext_qos: dec_ext::QoSType::DEFAULT,
            ext_tstamp: None,
            ext_nodeid: dec_ext::NodeIdType::DEFAULT,
            ext_target: zenoh_protocol::network::request::ext::QueryTarget::DEFAULT,
            ext_budget: None,
            ext_timeout: None,
            payload: RequestBody::Query(Query {
                parameters: String::new(),
                consolidation: zenoh_protocol::zenoh::query::ConsolidationMode::DEFAULT,
                ext_sinfo: None,
                ext_body: None,
                ext_attachment: None,
                ext_unknown: vec![],
            }),
        }),
        reliability: Reliability::Reliable,
    };
    let payload = encode_transport(&make_frame_with(vec![req]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("request.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.request.id"), 1);
    assert_size!(&pdml, &format!("{NP}.request.wire_expr"), 12);
}

#[test]
fn response_fields_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let resp = NetworkMessage {
        body: NetworkBody::Response(Response {
            rid: 1,
            wire_expr: WireExpr::from("demo/ans"),
            ext_qos: dec_ext::QoSType::DEFAULT,
            ext_tstamp: None,
            ext_respid: None,
            payload: ResponseBody::Reply(Reply {
                consolidation: zenoh_protocol::zenoh::query::ConsolidationMode::DEFAULT,
                ext_unknown: vec![],
                payload: PushBody::Put(Put {
                    timestamp: None,
                    encoding: zenoh_protocol::core::Encoding::default(),
                    ext_sinfo: None,
                    ext_shm: None,
                    ext_attachment: None,
                    ext_unknown: vec![],
                    payload: zenoh_buffers::ZBuf::from(b"answer".to_vec()),
                }),
            }),
        }),
        reliability: Reliability::Reliable,
    };
    let payload = encode_transport(&make_frame_with(vec![resp]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("response.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.response.rid"), 1);
    assert_size!(&pdml, &format!("{NP}.response.wire_expr"), 10);
}

#[test]
fn response_final_highlighted() {
    if !tshark_available() {
        return;
    }
    install_dissector();

    let rf = NetworkMessage {
        body: NetworkBody::ResponseFinal(ResponseFinal {
            rid: 1,
            ext_qos: dec_ext::QoSType::DEFAULT,
            ext_tstamp: None,
        }),
        reliability: Reliability::Reliable,
    };
    let payload = encode_transport(&make_frame_with(vec![rf]));
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("response_final.pcap");
    write_single_tcp_pcap(&pcap, &payload);
    let pdml = run_tshark(&pcap);
    assert_size!(&pdml, &format!("{NP}.response_final.rid"), 1);
}

#[test]
fn scouting_scout_fields_highlighted() {
    use zenoh_protocol::core::WhatAmIMatcher;
    use zenoh_protocol::scouting::{Scout, ScoutingBody, ScoutingMessage};

    if !tshark_available() {
        return;
    }
    install_dissector();

    let msg = ScoutingMessage {
        body: ScoutingBody::Scout(Scout {
            version: 0x08,
            what: WhatAmIMatcher::try_from(3).unwrap(),
            zid: None,
        }),
    };
    let payload = encode_transport(&msg);
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("scout.pcap");
    write_single_udp_pcap(&pcap, &payload, 7446);
    let pdml = run_tshark(&pcap);
    assert!(pdml.contains("zenoh.scout"), "Scout not decoded:\n{pdml}");
    assert_size!(&pdml, "zenoh.scout.version", 1);
    assert_size!(&pdml, "zenoh.scout.what", 1);
}

#[test]
fn scouting_hello_fields_highlighted() {
    use zenoh_protocol::scouting::{HelloProto, ScoutingBody, ScoutingMessage};

    if !tshark_available() {
        return;
    }
    install_dissector();

    let msg = ScoutingMessage {
        body: ScoutingBody::Hello(HelloProto {
            version: 0x08,
            whatami: WhatAmI::Peer,
            zid: ZenohIdProto::rand(),
            locators: vec![],
        }),
    };
    let payload = encode_transport(&msg);
    let pcap = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("hello.pcap");
    write_single_udp_pcap(&pcap, &payload, 7446);
    let pdml = run_tshark(&pcap);
    assert!(pdml.contains("zenoh.hello"), "Hello not decoded:\n{pdml}");
    assert_size!(&pdml, "zenoh.hello.version", 1);
    assert_size!(&pdml, "zenoh.hello.zid", 16);
}
