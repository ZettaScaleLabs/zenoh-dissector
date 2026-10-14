/*
 * Zenoh protocol dissector for Wireshark.
 * Protocol decoding is provided by zenoh-codec-ffi (Rust cdylib).
 * This plugin handles all epan interactions: field registration, tree building,
 * TCP reassembly, and conversation state.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ws_version.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/address.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-tcp.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include "zenoh_codec_ffi.h"

/* Default Zenoh ports */
#define ZENOH_PORT          7447  /* TCP + UDP: transport messages (and scouting on UDP) */
#define ZENOH_SCOUTING_PORT 7446  /* UDP only: Scout / Hello scouting messages */

/* Zenoh TCP batch: 2-byte LE length prefix + payload */
#define ZENOH_BATCH_HEADER_LEN 2

static int proto_zenoh = -1;

/* Dissector handles */
static dissector_handle_t zenoh_tcp_handle;
static dissector_handle_t zenoh_udp_handle;
static dissector_handle_t zenoh_udp_scouting_handle;

/* ---------------------------------------------------------------------------
 * Dynamic field registration (filled from Rust cdylib at startup)
 * --------------------------------------------------------------------------- */

static uint32_t g_field_count = 0;
static int *g_hf_handles = NULL;           /* int[g_field_count], each starts at -1 */
static hf_register_info *g_hf_array = NULL; /* hf_register_info[g_field_count] */

static uint32_t g_subtree_count = 0;
static gint *g_ett_handles = NULL;   /* gint[g_subtree_count] */
static gint **g_ett_ptrs = NULL;     /* gint*[g_subtree_count] → g_ett_handles[i] */

/* Lookup: field key (char*) → int* (pointer into g_hf_handles) */
static GHashTable *g_hf_by_key = NULL;
/* Lookup: field key (char*) → display name (char*, static lifetime from Rust cdylib) */
static GHashTable *g_name_by_key = NULL;

/* ---------------------------------------------------------------------------
 * Capture-wide peer state, reinitialised per capture file (register_init_routine).
 *
 * An IP address does not identify a Zenoh peer: two processes on one host share it, and both
 * ends of a loopback connection do. A peer is identified by its ZID, which it announces in Init
 * and Join. Until a ZID is known for an endpoint, nothing is shared with other links.
 * --------------------------------------------------------------------------- */

/* "<addr>:<port>" -> ZID entry (byte 0 = length, then the ZID bytes) */
static wmem_map_t *g_zid_by_endpoint = NULL;
/* "<zid hex>/<key-expr id>" -> resolved key expression, shared by every link of that peer */
static wmem_map_t *g_decl_by_zid = NULL;

/* Subtree handles: field key -> gint* (into g_ett_handles); keys of fields that open a subtree */
static GHashTable *g_ett_by_key = NULL;
static GHashTable *g_branch_by_key = NULL;
static gint ett_zenoh = -1;

/* ---------------------------------------------------------------------------
 * Static synthetic fields: session ZID and resolved key-expr
 * These are not from the Rust cdylib — registered directly here.
 * --------------------------------------------------------------------------- */

static int hf_session_src_zid   = -1;
static int hf_session_dst_zid   = -1;
static int hf_key_expr_resolved = -1;
static int hf_batch_compressed  = -1;

static hf_register_info g_static_hf[] = {
    { &hf_session_src_zid,
      { "Src ZID", "zenoh.session.src_zid",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_session_dst_zid,
      { "Dst ZID", "zenoh.session.dst_zid",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_key_expr_resolved,
      { "Key Expression (resolved)", "zenoh.key_expr_resolved",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_batch_compressed,
      { "Batch Compressed", "zenoh.batch.compressed",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
};

/* ---------------------------------------------------------------------------
 * Per-conversation state
 * --------------------------------------------------------------------------- */

typedef struct {
    /* Key-expr declarations of this connection, per declaring endpoint:
     * "<addr>:<port>/<id>" -> resolved key expression. An id is only meaningful to the peer
     * that declared it, so the two directions of one connection keep separate tables. */
    wmem_map_t *key_expr_map;
    /* True once compression is negotiated (an InitAck, OpenSyn or OpenAck with ext_compression
     * was seen). */
    bool is_compression;
    /* True once the OpenAck has been seen. Zenoh runs the whole Init and Open exchange with
     * compression off; only after the OpenAck does a connection with compression negotiated
     * start every batch with a one-byte BatchHeader. */
    bool handshake_done;
} zenoh_conv_data_t;

static zenoh_conv_data_t *get_conv_data(packet_info *pinfo)
{
    conversation_t *conv = find_or_create_conversation(pinfo);
    zenoh_conv_data_t *data = (zenoh_conv_data_t *)conversation_get_proto_data(conv, proto_zenoh);
    if (!data) {
        data = wmem_new0(wmem_file_scope(), zenoh_conv_data_t);
        data->key_expr_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        conversation_add_proto_data(conv, proto_zenoh, data);
    }
    return data;
}

/* ---------------------------------------------------------------------------
 * Forward declarations
 * --------------------------------------------------------------------------- */

static int dissect_zenoh_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zenoh_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static bool dissect_zenoh_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        void *data);

/* ---------------------------------------------------------------------------
 * Helpers: string suffix match and VLE decode from raw bytes
 * --------------------------------------------------------------------------- */

static bool key_endswith(const char *key, const char *suffix)
{
    size_t kl = strlen(key), sl = strlen(suffix);
    return kl >= sl && strcmp(key + kl - sl, suffix) == 0;
}

/* Decode a Zenoh VLE (LEB128) integer from buf at offset.
 * Returns the decoded value; sets *n_out to the number of bytes consumed. */
static uint64_t vle_at(const uint8_t *buf, uint32_t off, uint32_t buf_len, int *n_out)
{
    uint64_t v = 0;
    int shift = 0, n = 0;
    while ((uint32_t)(off + n) < buf_len) {
        uint8_t b = buf[off + n++];
        v |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80))
            break;
        shift += 7;
    }
    if (n_out)
        *n_out = n;
    return v;
}

/* ---------------------------------------------------------------------------
 * build_info_col: summarise the message types in a batch for COL_INFO.
 * Transport-level messages (init_syn, frame, …) are shown; for frame, the
 * enclosed network messages (push, declare, …) are listed in parens.
 * --------------------------------------------------------------------------- */

/* Converts a snake_case segment to a short display label. */
static const char *msg_label(const char *seg, gsize len)
{
    if (len == 8  && memcmp(seg, "init_syn", 8) == 0) return "InitSyn";
    if (len == 8  && memcmp(seg, "init_ack", 8) == 0) return "InitAck";
    if (len == 8  && memcmp(seg, "open_syn", 8) == 0) return "OpenSyn";
    if (len == 8  && memcmp(seg, "open_ack", 8) == 0) return "OpenAck";
    if (len == 5  && memcmp(seg, "frame", 5) == 0)    return "Frame";
    if (len == 8  && memcmp(seg, "fragment", 8) == 0) return "Fragment";
    if (len == 10 && memcmp(seg, "keep_alive", 10) == 0) return "KeepAlive";
    if (len == 4  && memcmp(seg, "join", 4) == 0)     return "Join";
    if (len == 5  && memcmp(seg, "close", 5) == 0)    return "Close";
    if (len == 3  && memcmp(seg, "o_a_m", 3) == 0)    return "OAM";
    if (len == 4  && memcmp(seg, "push", 4) == 0)     return "Push";
    if (len == 7  && memcmp(seg, "declare", 7) == 0)  return "Declare";
    if (len == 7  && memcmp(seg, "request", 7) == 0)  return "Request";
    if (len == 8  && memcmp(seg, "response", 8) == 0) return "Response";
    if (len == 14 && memcmp(seg, "response_final", 14) == 0) return "ResponseFinal";
    return NULL;
}

static void build_info_col(packet_info *pinfo, const CSpanEntry *spans, uint32_t count)
{
    /* Prefix lengths: "zenoh.transport." = 16, "zenoh.transport.frame.network." = 30 */
    static const char tp_pfx[]  = "zenoh.transport.";
    static const char net_pfx[] = "zenoh.transport.frame.network.";
    const gsize tp_len  = sizeof(tp_pfx)  - 1;
    const gsize net_len = sizeof(net_pfx) - 1;

    /* Collect seen transport-level and network-level labels (no duplicates, order-stable). */
    const char *tp_seen[8];  gsize n_tp  = 0;
    const char *net_seen[8]; gsize n_net = 0;

    for (uint32_t i = 0; i < count; i++) {
        const char *k = spans[i].key;
        const char *seg;
        const char *dot;
        const char *label;

        if (strncmp(k, net_pfx, net_len) == 0) {
            seg = k + net_len;
            dot = strchr(seg, '.');
            gsize slen = dot ? (gsize)(dot - seg) : strlen(seg);
            label = msg_label(seg, slen);
            if (label) {
                gsize j; for (j = 0; j < n_net && net_seen[j] != label; j++) {}
                if (j == n_net && n_net < 8) net_seen[n_net++] = label;
            }
        } else if (strncmp(k, tp_pfx, tp_len) == 0) {
            seg = k + tp_len;
            dot = strchr(seg, '.');
            gsize slen = dot ? (gsize)(dot - seg) : strlen(seg);
            label = msg_label(seg, slen);
            if (label) {
                gsize j; for (j = 0; j < n_tp && tp_seen[j] != label; j++) {}
                if (j == n_tp && n_tp < 8) tp_seen[n_tp++] = label;
            }
        }
    }

    if (n_tp == 0) return;

    wmem_strbuf_t *buf = wmem_strbuf_new(pinfo->pool, "");
    for (gsize i = 0; i < n_tp; i++) {
        if (i > 0) wmem_strbuf_append(buf, ", ");
        wmem_strbuf_append(buf, tp_seen[i]);
        /* For Frame, append enclosed network message types in parens */
        if (strcmp(tp_seen[i], "Frame") == 0 && n_net > 0) {
            wmem_strbuf_append_c(buf, ' ');
            wmem_strbuf_append_c(buf, '(');
            for (gsize j = 0; j < n_net; j++) {
                if (j > 0) wmem_strbuf_append(buf, ", ");
                wmem_strbuf_append(buf, net_seen[j]);
            }
            wmem_strbuf_append_c(buf, ')');
        }
    }
    col_set_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(buf));
}

/* ---------------------------------------------------------------------------
 * Per-PDU results
 *
 * Everything that depends on the capture so far is decided once, the first time a PDU is
 * dissected, and kept with the PDU. Dissecting the packet again (clicking it, tshark -2, a
 * filter) then shows what was true when it arrived, not what the conversation state became by
 * the end of the capture.
 * --------------------------------------------------------------------------- */

typedef struct {
    bool decided;           /* has_batch_header is settled */
    bool has_batch_header;  /* the batch starts with a one-byte BatchHeader */
    bool analyzed;          /* conversation state is updated and the fields below are final */
    uint8_t *src_zid;       /* ZID entry of the sender, or NULL */
    uint8_t *dst_zid;       /* ZID entry of the destination, or NULL */
    /* position in the decoded buffer + 1 (as a pointer) -> resolved key expression */
    wmem_map_t *resolved;
} zenoh_pdu_t;

static zenoh_pdu_t *get_pdu(packet_info *pinfo, tvbuff_t *tvb)
{
    /* A frame can hold several PDUs. They differ in their place in the frame's data and length. */
    uint32_t key = (uint32_t)tvb_raw_offset(tvb) * 31u + (uint32_t)tvb_captured_length(tvb);
    zenoh_pdu_t *pdu = (zenoh_pdu_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_zenoh, key);
    if (!pdu) {
        pdu = wmem_new0(wmem_file_scope(), zenoh_pdu_t);
        pdu->resolved = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_zenoh, key, pdu);
    }
    return pdu;
}

/* "<addr>:<port>": the address alone does not tell two peers on one host apart. */
static char *endpoint_str(wmem_allocator_t *scope, const address *addr, uint32_t port)
{
    return wmem_strdup_printf(scope, "%s:%u", address_to_str(scope, addr), (unsigned)port);
}

static char *zid_hex(wmem_allocator_t *scope, const uint8_t *entry)
{
    wmem_strbuf_t *buf = wmem_strbuf_new(scope, "");
    for (uint8_t i = 0; i < entry[0]; i++)
        wmem_strbuf_append_printf(buf, "%02x", entry[1 + i]);
    return wmem_strbuf_finalize(buf);
}

static const uint8_t *zid_of(const char *endpoint)
{
    return g_zid_by_endpoint ? (const uint8_t *)wmem_map_lookup(g_zid_by_endpoint, endpoint) : NULL;
}

/* Key expression `id` as declared by the endpoint `ep`. The connection's own table answers
 * first. Another link answers only if it belongs to the same peer, which the ZID confirms. */
static const char *lookup_decl(zenoh_conv_data_t *conv, const char *ep, uint64_t id,
                               wmem_allocator_t *tmp)
{
    char *key = wmem_strdup_printf(tmp, "%s/%u", ep, (unsigned)id);
    const char *found = (const char *)wmem_map_lookup(conv->key_expr_map, key);
    if (found)
        return found;
    const uint8_t *zid = zid_of(ep);
    if (zid && g_decl_by_zid) {
        char *zkey = wmem_strdup_printf(tmp, "%s/%u", zid_hex(tmp, zid), (unsigned)id);
        found = (const char *)wmem_map_lookup(g_decl_by_zid, zkey);
    }
    return found;
}

/* One DeclareKeyExpr, gathered from its id, scope and suffix spans. */
typedef struct {
    bool     have;
    uint64_t id;
    uint64_t scope;
    const char *suffix; /* NULL when the wire expression has none */
} decl_t;

/* The endpoint no longer has this id: it undeclared it, or declared it again in terms the
 * capture cannot resolve. A later Push must not resolve to what the id used to mean. */
static void forget_decl(zenoh_conv_data_t *conv, packet_info *pinfo, const char *ep, uint64_t id)
{
    wmem_map_remove(conv->key_expr_map,
                    wmem_strdup_printf(pinfo->pool, "%s/%u", ep, (unsigned)id));
    const uint8_t *zid = zid_of(ep);
    if (zid && g_decl_by_zid) {
        wmem_map_remove(g_decl_by_zid,
                        wmem_strdup_printf(pinfo->pool, "%s/%u", zid_hex(pinfo->pool, zid),
                                           (unsigned)id));
    }
}

static void commit_decl(zenoh_conv_data_t *conv, packet_info *pinfo, const char *src_ep,
                        const decl_t *d)
{
    if (!d->have)
        return;
    /* A declaration may build on an earlier one: scope names the id it extends. */
    const char *base = "";
    if (d->scope != 0) {
        base = lookup_decl(conv, src_ep, d->scope, pinfo->pool);
        if (!base) {
            forget_decl(conv, pinfo, src_ep, d->id);
            return;
        }
    }
    char *full = wmem_strdup_printf(wmem_file_scope(), "%s%s", base, d->suffix ? d->suffix : "");
    wmem_map_insert(conv->key_expr_map,
                    wmem_strdup_printf(wmem_file_scope(), "%s/%u", src_ep, (unsigned)d->id),
                    full);
    const uint8_t *zid = zid_of(src_ep);
    if (zid && g_decl_by_zid) {
        wmem_map_insert(g_decl_by_zid,
                        wmem_strdup_printf(wmem_file_scope(), "%s/%u",
                                           zid_hex(wmem_file_scope(), zid), (unsigned)d->id),
                        full);
    }
}

/* The string a suffix span holds: a VLE length, then that many bytes. */
static const char *suffix_str(const uint8_t *payload, uint32_t payload_len, uint32_t off)
{
    if (off >= payload_len)
        return NULL;
    int vle_bytes = 0;
    uint64_t str_len = vle_at(payload, off, payload_len, &vle_bytes);
    uint64_t str_off = (uint64_t)off + (uint64_t)vle_bytes;
    if (str_off + str_len > payload_len)
        return NULL;
    return wmem_strndup(wmem_file_scope(), (const gchar *)(payload + str_off), (gsize)str_len);
}

static bool is_wire_expr_scope(const char *key)
{
    return key_endswith(key, ".wire_expr.scope") && !strstr(key, "declare_key_expr");
}

/* Header flag M of a Push, Request or Response: set means the key-expression ids are the ones
 * the sender declared, clear means the ones the receiver declared. */
#define ZENOH_FLAG_MAPPING_SENDER 0x40

/* Work out, once per PDU, what the capture so far says about it: update the peer and
 * declaration tables, and resolve the wire expressions this PDU carries. */
static void analyze_pdu(zenoh_pdu_t *pdu, zenoh_conv_data_t *conv, const CSpanEntry *spans,
                        uint32_t count, const uint8_t *payload, uint32_t payload_len,
                        int payload_offset, packet_info *pinfo)
{
    char *src_ep = endpoint_str(wmem_file_scope(), &pinfo->src, pinfo->srcport);
    char *dst_ep = endpoint_str(wmem_file_scope(), &pinfo->dst, pinfo->destport);

    /* --- ZID: the sender of an InitSyn, InitAck or Join announces its own --- */
    for (uint32_t i = 0; i < count; i++) {
        const char *k = spans[i].key;
        if (!key_endswith(k, ".zid"))
            continue;
        if (!strstr(k, "init_syn") && !strstr(k, "init_ack") && !strstr(k, ".join."))
            continue;
        uint32_t off = spans[i].start, len = spans[i].length;
        if (len == 0 || off + len > payload_len)
            continue;
        uint8_t *entry = (uint8_t *)wmem_alloc(wmem_file_scope(), 1 + len);
        entry[0] = (uint8_t)len;
        memcpy(entry + 1, payload + off, len);
        wmem_map_insert(g_zid_by_endpoint, src_ep, entry);
    }
    pdu->src_zid = (uint8_t *)wmem_map_lookup(g_zid_by_endpoint, src_ep);
    pdu->dst_zid = (uint8_t *)wmem_map_lookup(g_zid_by_endpoint, dst_ep);

    /* --- DeclareKeyExpr. Spans arrive in wire order, so a declaration's id comes first and
     * its scope and suffix follow before the next id. A declaration with no suffix still
     * pairs with its own id. --- */
    decl_t cur = { 0 };
    for (uint32_t i = 0; i < count; i++) {
        const char *k = spans[i].key;
        uint32_t off = spans[i].start;
        if (key_endswith(k, ".declare_key_expr.id")) {
            commit_decl(conv, pinfo, src_ep, &cur);
            memset(&cur, 0, sizeof cur);
            if (off < payload_len) {
                cur.have = true;
                cur.id = (uint16_t)vle_at(payload, off, payload_len, NULL);
            }
        } else if (cur.have && key_endswith(k, ".declare_key_expr.wire_expr.scope")) {
            if (off < payload_len)
                cur.scope = vle_at(payload, off, payload_len, NULL);
        } else if (cur.have && key_endswith(k, ".declare_key_expr.wire_expr.suffix")) {
            cur.suffix = suffix_str(payload, payload_len, off);
        } else if (key_endswith(k, ".undeclare_key_expr.id")) {
            /* Keep the order of the wire: finish the declaration before it, then forget. */
            commit_decl(conv, pinfo, src_ep, &cur);
            memset(&cur, 0, sizeof cur);
            if (off < payload_len)
                forget_decl(conv, pinfo, src_ep,
                            (uint16_t)vle_at(payload, off, payload_len, NULL));
        }
    }
    commit_decl(conv, pinfo, src_ep, &cur);

    /* --- Wire expressions that name a declared id --- */
    for (uint32_t i = 0; i < count; i++) {
        const char *k = spans[i].key;
        uint32_t off = spans[i].start;
        if (!is_wire_expr_scope(k) || off >= payload_len)
            continue;
        uint64_t scope = vle_at(payload, off, payload_len, NULL);
        if (scope == 0)
            continue; /* the wire expression is a plain string */

        /* The suffix of this wire expression follows its scope, before the next one. */
        size_t base_len = strlen(k) - strlen(".scope");
        const char *suffix = "";
        for (uint32_t j = i + 1; j < count; j++) {
            const char *kj = spans[j].key;
            if (key_endswith(kj, ".wire_expr.scope"))
                break;
            if (strlen(kj) == base_len + strlen(".suffix") && strncmp(kj, k, base_len) == 0 &&
                strcmp(kj + base_len, ".suffix") == 0) {
                const char *sfx = suffix_str(payload, payload_len, spans[j].start);
                if (sfx)
                    suffix = sfx;
                break;
            }
        }

        /* The mapping flag sits in the header byte of the message that holds this wire
         * expression, which precedes it. Without one, assume the sender's mapping. */
        bool sender_mapping = true;
        char *mapping_key = wmem_strdup_printf(pinfo->pool, "%.*s.mapping", (int)base_len, k);
        for (uint32_t j = i; j-- > 0;) {
            if (strcmp(spans[j].key, mapping_key) == 0) {
                if (spans[j].start < payload_len)
                    sender_mapping =
                        (payload[spans[j].start] & ZENOH_FLAG_MAPPING_SENDER) != 0;
                break;
            }
        }

        const char *base = lookup_decl(conv, sender_mapping ? src_ep : dst_ep, scope, pinfo->pool);
        if (!base)
            continue;
        wmem_map_insert(pdu->resolved, GUINT_TO_POINTER((guint)(payload_offset + (int)off) + 1),
                        wmem_strdup_printf(wmem_file_scope(), "%s%s", base, suffix));
    }

    /* --- Compression negotiation: set after InitAck/OpenSyn/OpenAck with ext_compression.
     * Setting it after InitAck (not InitSyn) keeps the InitAck batch itself undecorated. --- */
    if (!conv->is_compression) {
        for (uint32_t i = 0; i < count; i++) {
            const char *k = spans[i].key;
            if (!key_endswith(k, ".ext_compression"))
                continue;
            if (strstr(k, "init_ack") || strstr(k, "open_syn") || strstr(k, "open_ack")) {
                conv->is_compression = true;
                break;
            }
        }
    }

    /* The OpenAck ends the handshake. Batches after it carry a BatchHeader if compression was
     * negotiated. */
    if (!conv->handshake_done) {
        for (uint32_t i = 0; i < count; i++) {
            if (key_endswith(spans[i].key, ".open_ack")) {
                conv->handshake_done = true;
                break;
            }
        }
    }

    pdu->analyzed = true;
}

/* ---------------------------------------------------------------------------
 * update_conv_and_annotate: analyse the PDU once, then annotate the tree with the session ZIDs
 * and the resolved key expressions that analysis settled.
 * --------------------------------------------------------------------------- */

static void update_conv_and_annotate(
    proto_tree      *tree,
    tvbuff_t        *tvb,
    int              payload_offset,
    const CSpanEntry *spans,
    uint32_t         count,
    const uint8_t   *payload,
    uint32_t         payload_len,
    packet_info     *pinfo,
    zenoh_pdu_t     *pdu)
{
    if (!pdu->analyzed)
        analyze_pdu(pdu, get_conv_data(pinfo), spans, count, payload, payload_len,
                    payload_offset, pinfo);

    /* --- Annotate tree with session ZID (every packet) --- */
    if (pdu->src_zid && pdu->src_zid[0] > 0) {
        proto_item *it = proto_tree_add_bytes_with_length(tree, hf_session_src_zid,
                                                          tvb, 0, 0,
                                                          pdu->src_zid + 1, pdu->src_zid[0]);
        proto_item_set_len(it, 0);
        PROTO_ITEM_SET_GENERATED(it);
    }
    if (pdu->dst_zid && pdu->dst_zid[0] > 0) {
        proto_item *it = proto_tree_add_bytes_with_length(tree, hf_session_dst_zid,
                                                          tvb, 0, 0,
                                                          pdu->dst_zid + 1, pdu->dst_zid[0]);
        proto_item_set_len(it, 0);
        PROTO_ITEM_SET_GENERATED(it);
    }

    /* --- Resolved wire expressions --- */
    for (uint32_t i = 0; i < count; i++) {
        if (!is_wire_expr_scope(spans[i].key))
            continue;
        const char *resolved = (const char *)wmem_map_lookup(
            pdu->resolved, GUINT_TO_POINTER((guint)(payload_offset + (int)spans[i].start) + 1));
        if (!resolved)
            continue;
        proto_item *it = proto_tree_add_string(tree, hf_key_expr_resolved,
                                               tvb,
                                               payload_offset + (int)spans[i].start,
                                               (int)spans[i].length,
                                               resolved);
        PROTO_ITEM_SET_GENERATED(it);
    }
}

/* ---------------------------------------------------------------------------
 * Helper: add all spans from Rust as items in the proto_tree
 *
 * Spans arrive in wire order with an enclosing span before the spans it contains. A branch field
 * (a message or a group of fields) opens a subtree, and the spans that fall inside its byte range
 * go under it. A repeated message has its own span, so it gets its own subtree.
 * --------------------------------------------------------------------------- */

#define ZENOH_MAX_NEST 32

typedef struct {
    uint32_t    start;
    uint32_t    end;
    proto_tree *tree;
} nest_t;

static void add_spans_to_tree(proto_tree *tree, tvbuff_t *tvb, int payload_offset,
                               const CSpanEntry *spans, uint32_t count)
{
    nest_t stack[ZENOH_MAX_NEST];
    int depth = 0;

    for (uint32_t i = 0; i < count; i++) {
        int *hf_ptr = (int *)g_hash_table_lookup(g_hf_by_key, spans[i].key);
        if (hf_ptr == NULL || *hf_ptr == -1) {
            continue;
        }
        uint32_t start = spans[i].start;
        uint32_t end = start + spans[i].length;

        /* Leave every subtree whose byte range does not hold this span. */
        while (depth > 0 && !(start >= stack[depth - 1].start && end <= stack[depth - 1].end))
            depth--;
        proto_tree *parent = depth > 0 ? stack[depth - 1].tree : tree;

        proto_item *it = proto_tree_add_item(parent, *hf_ptr, tvb,
                                             payload_offset + (int)start,
                                             (int)spans[i].length, ENC_NA);
        if (spans[i].display[0] != '\0') {
            if (spans[i].replace_display) {
                const char *fname = (const char *)g_hash_table_lookup(
                                        g_name_by_key, spans[i].key);
                proto_item_set_text(it, "%s: %s",
                                    fname ? fname : spans[i].key,
                                    spans[i].display);
            } else {
                proto_item_append_text(it, " (%s)", spans[i].display);
            }
        }

        if (g_hash_table_lookup(g_branch_by_key, spans[i].key) != NULL &&
            depth < ZENOH_MAX_NEST) {
            gint *ett = (gint *)g_hash_table_lookup(g_ett_by_key, spans[i].key);
            stack[depth].start = start;
            stack[depth].end = end;
            stack[depth].tree = proto_item_add_subtree(it, ett ? *ett : ett_zenoh);
            depth++;
        }
    }
}

/* ---------------------------------------------------------------------------
 * TCP: PDU length callback for tcp_dissect_pdus
 * TVB is positioned at the batch start (2-byte length prefix).
 * --------------------------------------------------------------------------- */

static guint get_zenoh_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                                void *data _U_)
{
    if (tvb_captured_length_remaining(tvb, offset) < ZENOH_BATCH_HEADER_LEN) {
        return 0;
    }
    guint16 batch_len = tvb_get_letohs(tvb, offset);
    return (guint)(ZENOH_BATCH_HEADER_LEN + batch_len);
}

/* ---------------------------------------------------------------------------
 * Decode one transport batch, with or without a BatchHeader.
 *
 * Whether the batch starts with a BatchHeader is decided once, from what the conversation knew
 * when the PDU arrived: only after the handshake is done, and only if compression was negotiated.
 * Nothing is guessed by trying to decode both ways.
 *
 * `base` is where the batch starts in `tvb` (after the length prefix on TCP, 0 on UDP).
 * --------------------------------------------------------------------------- */

typedef struct {
    CSpanEntry   *spans;      /* NULL when nothing decoded */
    uint32_t      count;
    tvbuff_t     *tvb;        /* the tvb the span offsets refer to */
    int           offset;     /* where the decoded bytes start in that tvb */
    const guint8 *payload;    /* the decoded bytes */
    uint32_t      len;
    bool          has_header; /* a BatchHeader was read */
    bool          compressed; /* and it said the batch was lz4-compressed */
} batch_t;

static void decode_batch(packet_info *pinfo, tvbuff_t *tvb, int base, const guint8 *payload,
                         uint32_t len, zenoh_pdu_t *pdu, batch_t *out)
{
    zenoh_conv_data_t *conv = get_conv_data(pinfo);

    memset(out, 0, sizeof *out);
    out->tvb = tvb;
    out->offset = base;
    out->payload = payload;
    out->len = len;

    if (!pdu->decided) {
        pdu->has_batch_header = conv->is_compression && conv->handshake_done && len >= 1;
        pdu->decided = true;
    }

    if (!pdu->has_batch_header) {
        out->spans = zenoh_codec_ffi_decode_transport(payload, len, &out->count);
        return;
    }
    if (len < 2)
        return; /* a header and nothing after it */

    if (payload[0] & 0x01) {
        /* BatchHeader bit 0 set: payload is lz4-compressed.
         * Decompress to a new tvb so span offsets map correctly. */
        uint32_t decomp_len = 0;
        uint8_t *decomp = zenoh_codec_ffi_decompress(payload + 1, len - 1, &decomp_len);
        if (decomp != NULL) {
            out->spans = zenoh_codec_ffi_decode_transport(decomp, decomp_len, &out->count);
            if (out->spans != NULL) {
                /* Copy into a wmem allocation so Wireshark owns the lifetime */
                guint8 *buf = (guint8 *)wmem_memdup(pinfo->pool, decomp, decomp_len);
                out->tvb = tvb_new_child_real_data(tvb, buf, decomp_len, decomp_len);
                /* Without this the bytes pane cannot show what the fields highlight. */
                add_new_data_source(pinfo, out->tvb, "Decompressed Zenoh batch");
                out->payload = buf;
                out->len = decomp_len;
                out->offset = 0;
                out->has_header = true;
                out->compressed = true;
            }
            zenoh_codec_ffi_free_buf(decomp, decomp_len);
        }
    } else {
        /* BatchHeader bit 0 clear: header present, payload uncompressed */
        out->spans = zenoh_codec_ffi_decode_transport(payload + 1, len - 1, &out->count);
        if (out->spans != NULL) {
            out->payload = payload + 1;
            out->len = len - 1;
            out->offset = base + 1;
            out->has_header = true;
        }
    }
}

/* ---------------------------------------------------------------------------
 * TCP: dissect a single reassembled PDU
 * TVB covers exactly one batch: [2-byte length][payload…]
 * --------------------------------------------------------------------------- */

static int dissect_zenoh_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                  void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Zenoh");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, "Zenoh batch");

    guint16 batch_len = tvb_get_letohs(tvb, 0);

    /* Root zenoh item covering the entire batch */
    proto_item *ti = proto_tree_add_protocol_format(
        tree, proto_zenoh, tvb, 0, ZENOH_BATCH_HEADER_LEN + batch_len,
        "Zenoh Protocol, batch length: %u", batch_len);
    proto_tree *zenoh_tree = proto_item_add_subtree(ti, ett_zenoh);

    if (batch_len == 0) {
        return ZENOH_BATCH_HEADER_LEN;
    }

    /* Get payload bytes for the Rust decoder */
    const guint8 *payload = tvb_get_ptr(tvb, ZENOH_BATCH_HEADER_LEN, batch_len);
    if (payload == NULL) {
        return ZENOH_BATCH_HEADER_LEN;
    }

    zenoh_pdu_t *pdu = get_pdu(pinfo, tvb);

    batch_t batch;
    decode_batch(pinfo, tvb, ZENOH_BATCH_HEADER_LEN, payload, batch_len, pdu, &batch);

    if (batch.spans != NULL) {
        if (batch.has_header) {
            proto_item *hdr_it = proto_tree_add_boolean(
                zenoh_tree, hf_batch_compressed,
                tvb, ZENOH_BATCH_HEADER_LEN, 1,
                batch.compressed ? TRUE : FALSE);
            PROTO_ITEM_SET_GENERATED(hdr_it);
        }
        build_info_col(pinfo, batch.spans, batch.count);
        add_spans_to_tree(zenoh_tree, batch.tvb, batch.offset, batch.spans, batch.count);
        update_conv_and_annotate(zenoh_tree, batch.tvb, batch.offset,
                                 batch.spans, batch.count,
                                 batch.payload, batch.len, pinfo, pdu);
        zenoh_codec_ffi_free_spans(batch.spans, batch.count);
    }

    return tvb_captured_length(tvb);
}

/* ---------------------------------------------------------------------------
 * TCP entry point
 * --------------------------------------------------------------------------- */

static int dissect_zenoh_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree,
                     TRUE,                   /* desegment */
                     ZENOH_BATCH_HEADER_LEN, /* fixed header length to determine PDU length */
                     get_zenoh_pdu_len,
                     dissect_zenoh_tcp_pdu,
                     data);
    return tvb_captured_length(tvb);
}

/* ---------------------------------------------------------------------------
 * UDP entry point
 * UDP batches have no length prefix; the entire UDP payload is the batch.
 * Try transport decode first, then scouting.
 * --------------------------------------------------------------------------- */

static int dissect_zenoh_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Zenoh");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, "Zenoh UDP");

    gint payload_len = tvb_reported_length(tvb);
    if (payload_len <= 0) {
        return 0;
    }

    proto_item *ti = proto_tree_add_protocol_format(
        tree, proto_zenoh, tvb, 0, payload_len, "Zenoh Protocol");
    proto_tree *zenoh_tree = proto_item_add_subtree(ti, ett_zenoh);

    const guint8 *payload = tvb_get_ptr(tvb, 0, payload_len);
    if (payload == NULL) {
        return 0;
    }

    zenoh_pdu_t *pdu = get_pdu(pinfo, tvb);

    /* Transport first: Scout/Hello share header bytes 0x01/0x02 with Init/Open, so a
     * transport message also parses as scouting and would be shown as the wrong message.
     * Scouting proper arrives on port 7446, which has its own scouting-only handler. */
    batch_t batch;
    decode_batch(pinfo, tvb, 0, payload, (uint32_t)payload_len, pdu, &batch);
    if (batch.spans == NULL) {
        /* Fallback: try scouting message */
        memset(&batch, 0, sizeof batch);
        batch.tvb = tvb;
        batch.payload = payload;
        batch.len = (uint32_t)payload_len;
        batch.spans = zenoh_codec_ffi_decode_scouting(payload, (uint32_t)payload_len,
                                                      &batch.count);
    }

    if (batch.spans != NULL) {
        if (batch.has_header) {
            proto_item *hdr_it = proto_tree_add_boolean(
                zenoh_tree, hf_batch_compressed, tvb, 0, 1,
                batch.compressed ? TRUE : FALSE);
            PROTO_ITEM_SET_GENERATED(hdr_it);
        }
        add_spans_to_tree(zenoh_tree, batch.tvb, batch.offset, batch.spans, batch.count);
        update_conv_and_annotate(zenoh_tree, batch.tvb, batch.offset,
                                 batch.spans, batch.count,
                                 batch.payload, batch.len, pinfo, pdu);
        zenoh_codec_ffi_free_spans(batch.spans, batch.count);
    }

    return payload_len;
}

/* ---------------------------------------------------------------------------
 * UDP scouting entry point (port 7446)
 * Port 7446 carries only Scout / Hello messages.  No transport fallback.
 * --------------------------------------------------------------------------- */

static int dissect_zenoh_scouting_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Zenoh");
    col_clear(pinfo->cinfo, COL_INFO);

    gint payload_len = tvb_reported_length(tvb);
    if (payload_len <= 0)
        return 0;

    proto_item *ti = proto_tree_add_protocol_format(
        tree, proto_zenoh, tvb, 0, payload_len, "Zenoh Scouting");
    proto_tree *zenoh_tree = proto_item_add_subtree(ti, ett_zenoh);

    const guint8 *payload = tvb_get_ptr(tvb, 0, payload_len);
    if (payload == NULL)
        return 0;

    uint32_t span_count = 0;
    CSpanEntry *spans = zenoh_codec_ffi_decode_scouting(payload, (uint32_t)payload_len,
                                                         &span_count);
    if (spans != NULL) {
        add_spans_to_tree(zenoh_tree, tvb, 0, spans, span_count);
        update_conv_and_annotate(zenoh_tree, tvb, 0,
                                 spans, span_count,
                                 payload, (uint32_t)payload_len, pinfo, get_pdu(pinfo, tvb));
        zenoh_codec_ffi_free_spans(spans, span_count);
    } else {
        col_add_str(pinfo->cinfo, COL_INFO, "Unknown Zenoh Scouting");
    }

    return payload_len;
}

/* ---------------------------------------------------------------------------
 * Heuristic: detect Zenoh UDP by attempting to decode the payload
 * --------------------------------------------------------------------------- */

static bool dissect_zenoh_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                    void *data)
{
    gint payload_len = tvb_captured_length(tvb);
    if (payload_len <= 0)
        return false;

    const guint8 *payload = tvb_get_ptr(tvb, 0, payload_len);
    if (payload == NULL)
        return false;

    uint32_t span_count = 0;
    CSpanEntry *spans = zenoh_codec_ffi_decode_scouting(payload, (uint32_t)payload_len, &span_count);
    if (spans == NULL)
        spans = zenoh_codec_ffi_decode_transport(payload, (uint32_t)payload_len, &span_count);

    if (spans == NULL)
        return false;

    zenoh_codec_ffi_free_spans(spans, span_count);

    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, zenoh_udp_handle);

    dissect_zenoh_udp(tvb, pinfo, tree, data);
    return true;
}

/* ---------------------------------------------------------------------------
 * Heuristic: detect Zenoh TCP by checking batch length sanity
 * --------------------------------------------------------------------------- */

static bool dissect_zenoh_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        void *data)
{
    if (tvb_captured_length(tvb) < ZENOH_BATCH_HEADER_LEN) {
        return false;
    }

    guint16 batch_len = tvb_get_letohs(tvb, 0);

    /* Reject obviously invalid batch lengths */
    if (batch_len == 0) {
        return false;
    }

    /* Need at least the 2-byte length prefix + 1-byte message header */
    if (tvb_captured_length(tvb) < 3) {
        return false;
    }

    uint8_t hdr    = tvb_get_uint8(tvb, 2);
    uint8_t msg_id = hdr & 0x1F;  /* bits 4:0 */

    /* Valid transport message IDs: 0x01–0x07 (0x00 / OAM is too ambiguous) */
    if (msg_id == 0 || msg_id > 0x07) {
        return false;
    }

    /* For INIT (0x01) and JOIN (0x07) the next byte is the protocol version.
     * Reject version==0 — null bytes are common in non-Zenoh protocols. */
    if ((msg_id == 0x01 || msg_id == 0x07) && tvb_captured_length(tvb) >= 4) {
        if (tvb_get_uint8(tvb, 3) == 0) {
            return false;
        }
    }

    /* Claim the conversation */
    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, zenoh_tcp_handle);

    dissect_zenoh_tcp(tvb, pinfo, tree, data);
    return true;
}

/* ---------------------------------------------------------------------------
 * Registration
 * --------------------------------------------------------------------------- */

static void zenoh_init(void)
{
    g_zid_by_endpoint = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
    g_decl_by_zid = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
}

void proto_register_zenoh(void)
{
    /* Get field definitions from the Rust cdylib */
    const CFieldDef *fields = zenoh_codec_ffi_get_fields(&g_field_count);

    g_hf_handles = (int *)wmem_alloc0(wmem_epan_scope(), g_field_count * sizeof(int));
    g_hf_array = (hf_register_info *)wmem_alloc0(wmem_epan_scope(),
                                                   g_field_count * sizeof(hf_register_info));
    g_hf_by_key   = g_hash_table_new(g_str_hash, g_str_equal);
    g_name_by_key = g_hash_table_new(g_str_hash, g_str_equal);
    g_branch_by_key = g_hash_table_new(g_str_hash, g_str_equal);
    g_ett_by_key = g_hash_table_new(g_str_hash, g_str_equal);

    for (uint32_t i = 0; i < g_field_count; i++) {
        g_hf_handles[i] = -1;

        /*
         * The key and display_name pointers remain valid for the process lifetime
         * because they live inside the Rust OnceLock-backed static Vec.
         */
        const char *abbrev = fields[i].key;
        const char *name = fields[i].display_name;

        if (fields[i].is_branch) {
            g_hash_table_insert(g_branch_by_key, (gpointer)abbrev, GINT_TO_POINTER(1));
            g_hf_array[i] = (hf_register_info){
                .p_id = &g_hf_handles[i],
                .hfinfo = {
                    name, abbrev,
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL, HFILL
                }
            };
        } else {
            g_hf_array[i] = (hf_register_info){
                .p_id = &g_hf_handles[i],
                .hfinfo = {
                    name, abbrev,
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    NULL, HFILL
                }
            };
        }

        g_hash_table_insert(g_hf_by_key,   (gpointer)abbrev, &g_hf_handles[i]);
        g_hash_table_insert(g_name_by_key, (gpointer)abbrev, (gpointer)name);
    }

    /* Register protocol */
    proto_zenoh = proto_register_protocol("Zenoh", "Zenoh", "zenoh");
    proto_register_field_array(proto_zenoh, g_hf_array, (int)g_field_count);

    /* Register static synthetic fields */
    proto_register_field_array(proto_zenoh, g_static_hf,
                               (int)(sizeof(g_static_hf) / sizeof(g_static_hf[0])));

    /* Get subtree definitions from the Rust cdylib */
    uint32_t sub_count = 0;
    const char *const *sub_names = zenoh_codec_ffi_get_subtrees(&sub_count);
    g_subtree_count = sub_count;

    g_ett_handles = (gint *)wmem_alloc0(wmem_epan_scope(), g_subtree_count * sizeof(gint));
    g_ett_ptrs = (gint **)wmem_alloc0(wmem_epan_scope(), g_subtree_count * sizeof(gint *));

    for (uint32_t i = 0; i < g_subtree_count; i++) {
        g_ett_handles[i] = -1;
        g_ett_ptrs[i] = &g_ett_handles[i];
        g_hash_table_insert(g_ett_by_key, (gpointer)sub_names[i], &g_ett_handles[i]);
    }

    proto_register_subtree_array((gint *const *)g_ett_ptrs, (int)g_subtree_count);

    static gint *ett_root[] = { &ett_zenoh };
    proto_register_subtree_array(ett_root, 1);
}

void proto_reg_handoff_zenoh(void)
{
    register_init_routine(zenoh_init);

    zenoh_tcp_handle = create_dissector_handle(dissect_zenoh_tcp, proto_zenoh);
    zenoh_udp_handle = create_dissector_handle(dissect_zenoh_udp, proto_zenoh);
    zenoh_udp_scouting_handle = create_dissector_handle(dissect_zenoh_scouting_udp, proto_zenoh);

    dissector_add_uint("tcp.port", ZENOH_PORT, zenoh_tcp_handle);
    dissector_add_uint("udp.port", ZENOH_PORT, zenoh_udp_handle);
    dissector_add_uint("udp.port", ZENOH_SCOUTING_PORT, zenoh_udp_scouting_handle);

    heur_dissector_add("tcp", dissect_zenoh_tcp_heur, "Zenoh over TCP heuristic",
                       "zenoh_tcp_heur", proto_zenoh, HEURISTIC_DISABLE);
    heur_dissector_add("udp", dissect_zenoh_udp_heur, "Zenoh over UDP heuristic",
                       "zenoh_udp_heur", proto_zenoh, HEURISTIC_DISABLE);
}

/* ---------------------------------------------------------------------------
 * Wireshark plugin boilerplate
 * --------------------------------------------------------------------------- */

/* On Windows/MSVC symbols must be explicitly exported; on ELF platforms all
   symbols in a shared library are visible by default. WS_DLL_PUBLIC cannot be
   used on initialized variable definitions because some GCC builds of the
   Wireshark headers forward-declare these as `extern`, causing a conflict. */
#ifdef _MSC_VER
#  define ZENOH_PLUGIN_EXPORT __declspec(dllexport)
#else
#  define ZENOH_PLUGIN_EXPORT
#endif

ZENOH_PLUGIN_EXPORT const char plugin_version[] = "0.0.1";
ZENOH_PLUGIN_EXPORT const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
ZENOH_PLUGIN_EXPORT const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug = {
        .register_protoinfo = proto_register_zenoh,
        .register_handoff = proto_reg_handoff_zenoh,
    };
    proto_register_plugin(&plug);
}
