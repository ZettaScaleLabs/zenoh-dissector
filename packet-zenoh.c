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
#include <epan/dissectors/packet-tcp.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include "zenoh_codec_ffi.h"

/* Default Zenoh port for both TCP and UDP */
#define ZENOH_PORT 7447

/* Zenoh TCP batch: 2-byte LE length prefix + payload */
#define ZENOH_BATCH_HEADER_LEN 2

static int proto_zenoh = -1;

/* Dissector handles */
static dissector_handle_t zenoh_tcp_handle;
static dissector_handle_t zenoh_udp_handle;

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

/* ---------------------------------------------------------------------------
 * Static synthetic fields: session ZID and resolved key-expr
 * These are not from the Rust cdylib — registered directly here.
 * --------------------------------------------------------------------------- */

static int hf_session_src_zid   = -1;
static int hf_session_dst_zid   = -1;
static int hf_key_expr_resolved = -1;

static hf_register_info g_static_hf[] = {
    { &hf_session_src_zid,
      { "Session Source ZID", "zenoh.session.src_zid",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_session_dst_zid,
      { "Session Destination ZID", "zenoh.session.dst_zid",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_key_expr_resolved,
      { "Key Expression (resolved)", "zenoh.key_expr_resolved",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
};

/* ---------------------------------------------------------------------------
 * Per-conversation state
 * --------------------------------------------------------------------------- */

typedef struct {
    /* ZID per source address: gchar* addr_str → uint8_t* (byte[0]=len, bytes[1..n]=ZID) */
    wmem_map_t *zid_map;
    /* Key-expr mapping: GUINT_TO_POINTER(uint32 id) → gchar* suffix string */
    wmem_map_t *key_expr_map;
} zenoh_conv_data_t;

static zenoh_conv_data_t *get_conv_data(packet_info *pinfo)
{
    conversation_t *conv = find_or_create_conversation(pinfo);
    zenoh_conv_data_t *data = (zenoh_conv_data_t *)conversation_get_proto_data(conv, proto_zenoh);
    if (!data) {
        data = wmem_new0(wmem_file_scope(), zenoh_conv_data_t);
        data->zid_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        data->key_expr_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
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
 * update_conv_and_annotate: extract ZID / DeclareKeyExpr from spans,
 * update conversation state, then annotate the tree with session ZID fields
 * and resolved key-expr strings.
 * --------------------------------------------------------------------------- */

static void update_conv_and_annotate(
    proto_tree      *tree,
    tvbuff_t        *tvb,
    int              payload_offset,
    const CSpanEntry *spans,
    uint32_t         count,
    const uint8_t   *payload,
    uint32_t         payload_len,
    packet_info     *pinfo)
{
    zenoh_conv_data_t *conv = get_conv_data(pinfo);

    if (!pinfo->fd->visited) {
        /* --- ZID: store per source address from Init / Join messages --- */
        for (uint32_t i = 0; i < count; i++) {
            const char *k = spans[i].key;
            if (!key_endswith(k, ".zid"))
                continue;
            /* Only transport-level ZIDs (InitSyn, InitAck, Join) */
            if (!strstr(k, "init_syn") && !strstr(k, "init_ack") && !strstr(k, ".join."))
                continue;
            uint32_t off = spans[i].start, len = spans[i].length;
            if (len == 0 || off + len > payload_len)
                continue;
            gchar *addr_key = address_to_str(wmem_file_scope(), &pinfo->src);
            uint8_t *entry = (uint8_t *)wmem_alloc(wmem_file_scope(), 1 + len);
            entry[0] = (uint8_t)len;
            memcpy(entry + 1, payload + off, len);
            wmem_map_insert(conv->zid_map, addr_key, entry);
        }

        /* --- DeclareKeyExpr: collect (id, suffix) pairs and store in map --- */
        /* Collect all .declare_key_expr.id span positions */
        uint16_t id_vals[16];
        uint32_t n_ids = 0;
        for (uint32_t i = 0; i < count && n_ids < 16; i++) {
            if (!key_endswith(spans[i].key, ".declare_key_expr.id"))
                continue;
            uint32_t off = spans[i].start;
            if (off >= payload_len)
                continue;
            int nb = 0;
            uint64_t id = vle_at(payload, off, payload_len, &nb);
            id_vals[n_ids] = (uint16_t)id;
            n_ids++;
        }

        /* Collect all .declare_key_expr.wire_expr.suffix span positions */
        uint32_t suf_offs[16];
        uint32_t n_sufs = 0;
        for (uint32_t i = 0; i < count && n_sufs < 16; i++) {
            if (!key_endswith(spans[i].key, ".declare_key_expr.wire_expr.suffix"))
                continue;
            suf_offs[n_sufs] = spans[i].start;
            n_sufs++;
        }

        /* Pair id[p] with suffix[p] — ordering is best-effort for multi-Declare frames */
        uint32_t pairs = n_ids < n_sufs ? n_ids : n_sufs;
        for (uint32_t p = 0; p < pairs; p++) {
            uint32_t off = suf_offs[p];
            if (off >= payload_len)
                continue;
            /* The suffix span is: VLE-length-prefix + string bytes */
            int vle_bytes = 0;
            uint64_t str_len = vle_at(payload, off, payload_len, &vle_bytes);
            uint32_t str_off = off + (uint32_t)vle_bytes;
            if (str_off + str_len > payload_len)
                continue;
            gchar *suffix_str = wmem_strndup(wmem_file_scope(),
                                             (const gchar *)(payload + str_off),
                                             (gsize)str_len);
            wmem_map_insert(conv->key_expr_map,
                            GUINT_TO_POINTER((guint)id_vals[p]),
                            suffix_str);
        }
    }

    /* --- Annotate tree with session ZID (every packet) --- */
    gchar *src_addr = address_to_str(pinfo->pool, &pinfo->src);
    gchar *dst_addr = address_to_str(pinfo->pool, &pinfo->dst);

    uint8_t *src_entry = (uint8_t *)wmem_map_lookup(conv->zid_map, src_addr);
    if (src_entry && src_entry[0] > 0) {
        proto_item *it = proto_tree_add_bytes(tree, hf_session_src_zid,
                                              tvb, 0, 0,
                                              src_entry + 1);
        proto_item_set_len(it, 0);
        PROTO_ITEM_SET_GENERATED(it);
    }

    uint8_t *dst_entry = (uint8_t *)wmem_map_lookup(conv->zid_map, dst_addr);
    if (dst_entry && dst_entry[0] > 0) {
        proto_item *it = proto_tree_add_bytes(tree, hf_session_dst_zid,
                                              tvb, 0, 0,
                                              dst_entry + 1);
        proto_item_set_len(it, 0);
        PROTO_ITEM_SET_GENERATED(it);
    }

    /* --- Resolved wire-expr: Push / Request / Response with non-zero scope --- */
    for (uint32_t i = 0; i < count; i++) {
        const char *k = spans[i].key;
        if (!key_endswith(k, ".wire_expr.scope"))
            continue;
        /* Skip DeclareKeyExpr's own wire_expr */
        if (strstr(k, "declare_key_expr"))
            continue;
        uint32_t off = spans[i].start;
        if (off >= payload_len)
            continue;
        uint64_t scope = vle_at(payload, off, payload_len, NULL);
        if (scope == 0)
            continue; /* full string wire-expr — no resolution needed */
        gchar *resolved = (gchar *)wmem_map_lookup(conv->key_expr_map,
                                                    GUINT_TO_POINTER((guint)scope));
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
 * --------------------------------------------------------------------------- */

static void add_spans_to_tree(proto_tree *tree, tvbuff_t *tvb, int payload_offset,
                               const CSpanEntry *spans, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        int *hf_ptr = (int *)g_hash_table_lookup(g_hf_by_key, spans[i].key);
        if (hf_ptr == NULL || *hf_ptr == -1) {
            continue;
        }
        int start = payload_offset + (int)spans[i].start;
        int length = (int)spans[i].length;
        proto_tree_add_item(tree, *hf_ptr, tvb, start, length, ENC_NA);
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
    proto_tree *zenoh_tree = proto_item_add_subtree(ti, 0);

    if (batch_len == 0) {
        return ZENOH_BATCH_HEADER_LEN;
    }

    /* Get payload bytes for the Rust decoder */
    const guint8 *payload = tvb_get_ptr(tvb, ZENOH_BATCH_HEADER_LEN, batch_len);
    if (payload == NULL) {
        return ZENOH_BATCH_HEADER_LEN;
    }

    uint32_t span_count = 0;
    CSpanEntry *spans = zenoh_codec_ffi_decode_transport(payload, batch_len, &span_count);
    if (spans != NULL) {
        add_spans_to_tree(zenoh_tree, tvb, ZENOH_BATCH_HEADER_LEN, spans, span_count);
        update_conv_and_annotate(zenoh_tree, tvb, ZENOH_BATCH_HEADER_LEN,
                                 spans, span_count,
                                 payload, batch_len, pinfo);
        zenoh_codec_ffi_free_spans(spans, span_count);
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
    proto_tree *zenoh_tree = proto_item_add_subtree(ti, 0);

    const guint8 *payload = tvb_get_ptr(tvb, 0, payload_len);
    if (payload == NULL) {
        return 0;
    }

    uint32_t span_count = 0;

    /* Try scouting first (Scout/Hello have a distinct header byte) */
    CSpanEntry *spans = zenoh_codec_ffi_decode_scouting(payload, (uint32_t)payload_len, &span_count);
    if (spans == NULL) {
        /* Fallback: try transport message */
        spans = zenoh_codec_ffi_decode_transport(payload, (uint32_t)payload_len, &span_count);
    }

    if (spans != NULL) {
        add_spans_to_tree(zenoh_tree, tvb, 0, spans, span_count);
        update_conv_and_annotate(zenoh_tree, tvb, 0,
                                 spans, span_count,
                                 payload, (uint32_t)payload_len, pinfo);
        zenoh_codec_ffi_free_spans(spans, span_count);
    }

    return payload_len;
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

    /* Claim the conversation */
    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, zenoh_tcp_handle);

    dissect_zenoh_tcp(tvb, pinfo, tree, data);
    return true;
}

/* ---------------------------------------------------------------------------
 * Registration
 * --------------------------------------------------------------------------- */

void proto_register_zenoh(void)
{
    /* Get field definitions from the Rust cdylib */
    const CFieldDef *fields = zenoh_codec_ffi_get_fields(&g_field_count);

    g_hf_handles = (int *)wmem_alloc0(wmem_epan_scope(), g_field_count * sizeof(int));
    g_hf_array = (hf_register_info *)wmem_alloc0(wmem_epan_scope(),
                                                   g_field_count * sizeof(hf_register_info));
    g_hf_by_key = g_hash_table_new(g_str_hash, g_str_equal);

    for (uint32_t i = 0; i < g_field_count; i++) {
        g_hf_handles[i] = -1;

        /*
         * The key and display_name pointers remain valid for the process lifetime
         * because they live inside the Rust OnceLock-backed static Vec.
         */
        const char *abbrev = fields[i].key;
        const char *name = fields[i].display_name;

        if (fields[i].is_branch) {
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

        g_hash_table_insert(g_hf_by_key, (gpointer)abbrev, &g_hf_handles[i]);
    }

    /* Register protocol */
    proto_zenoh = proto_register_protocol("Zenoh", "Zenoh", "zenoh");
    proto_register_field_array(proto_zenoh, g_hf_array, (int)g_field_count);

    /* Register static synthetic fields */
    proto_register_field_array(proto_zenoh, g_static_hf,
                               (int)(sizeof(g_static_hf) / sizeof(g_static_hf[0])));

    /* Get subtree definitions from the Rust cdylib */
    uint32_t sub_count = 0;
    (void)zenoh_codec_ffi_get_subtrees(&sub_count);
    g_subtree_count = sub_count;

    g_ett_handles = (gint *)wmem_alloc0(wmem_epan_scope(), g_subtree_count * sizeof(gint));
    g_ett_ptrs = (gint **)wmem_alloc0(wmem_epan_scope(), g_subtree_count * sizeof(gint *));

    for (uint32_t i = 0; i < g_subtree_count; i++) {
        g_ett_handles[i] = -1;
        g_ett_ptrs[i] = &g_ett_handles[i];
    }

    proto_register_subtree_array((gint *const *)g_ett_ptrs, (int)g_subtree_count);
}

void proto_reg_handoff_zenoh(void)
{
    zenoh_tcp_handle = create_dissector_handle(dissect_zenoh_tcp, proto_zenoh);
    zenoh_udp_handle = create_dissector_handle(dissect_zenoh_udp, proto_zenoh);

    dissector_add_uint("tcp.port", ZENOH_PORT, zenoh_tcp_handle);
    dissector_add_uint("udp.port", ZENOH_PORT, zenoh_udp_handle);

    heur_dissector_add("tcp", dissect_zenoh_tcp_heur, "Zenoh over TCP heuristic",
                       "zenoh_tcp_heur", proto_zenoh, HEURISTIC_ENABLE);
}

/* ---------------------------------------------------------------------------
 * Wireshark plugin boilerplate
 * --------------------------------------------------------------------------- */

const char plugin_version[] = "0.0.1";
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug = {
        .register_protoinfo = proto_register_zenoh,
        .register_handoff = proto_reg_handoff_zenoh,
    };
    proto_register_plugin(&plug);
}
