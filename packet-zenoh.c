/*
 * Copyright (c) 2026 ZettaScale Technology
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 *
 * Contributors:
 *   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
 *
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
 * Forward declarations
 * --------------------------------------------------------------------------- */

static int dissect_zenoh_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zenoh_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static bool dissect_zenoh_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        void *data);

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

WS_DLL_PUBLIC const char plugin_version[] = "0.0.1";
WS_DLL_PUBLIC const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug = {
        .register_protoinfo = proto_register_zenoh,
        .register_handoff = proto_reg_handoff_zenoh,
    };
    proto_register_plugin(&plug);
}
