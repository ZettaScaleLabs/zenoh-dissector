#pragma once
#include <stdint.h>

/** Maximum length of a field key or display name string (including null terminator). */
#define ZENOH_FFI_KEY_LEN 128

/**
 * A Wireshark field definition, returned once at plugin startup.
 * Both `key` and `display_name` are null-terminated strings.
 */
typedef struct {
    char key[ZENOH_FFI_KEY_LEN];
    char display_name[ZENOH_FFI_KEY_LEN];
    /** 1 = branch/subtree node (FT_NONE), 0 = leaf field (FT_BYTES). */
    uint8_t is_branch;
} CFieldDef;

/**
 * A single decoded field with its byte position in the wire data.
 * `key` is a null-terminated string matching a registered field abbrev.
 * `start` and `length` are byte offsets relative to the PDU payload
 * (NOT including the 2-byte TCP length prefix).
 */
typedef struct {
    char key[ZENOH_FFI_KEY_LEN];
    uint32_t start;
    uint32_t length;
    /** Optional human-readable value string. Empty string means no override. */
    char display[ZENOH_FFI_KEY_LEN];
    /** If non-zero, display replaces the raw-bytes label; otherwise it is appended in parens. */
    uint8_t replace_display;
} CSpanEntry;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return a pointer to a static array of CFieldDef, writing the count to *out_count.
 * The returned pointer and its contents are valid for the lifetime of the process.
 * Never call free() on this pointer.
 */
const CFieldDef *zenoh_codec_ffi_get_fields(uint32_t *out_count);

/**
 * Return a pointer to a static array of null-terminated subtree key strings.
 * Each entry is a field key that should be registered as a subtree (proto_register_subtree_array).
 * The returned pointer and all string pointers are valid for the lifetime of the process.
 * Never call free() on this pointer or the strings it contains.
 */
const char *const *zenoh_codec_ffi_get_subtrees(uint32_t *out_count);

/**
 * Decode a Zenoh transport-level PDU from raw bytes.
 *
 * `data` points to the PDU payload (NOT including the 2-byte TCP batch length prefix).
 * `len` is the payload length in bytes.
 *
 * On success, writes the span count to *out_count and returns a heap-allocated CSpanEntry[].
 * The caller MUST call zenoh_codec_ffi_free_spans(ptr, count) when done with the result.
 *
 * Returns NULL on decode error; *out_count is set to 0.
 */
CSpanEntry *zenoh_codec_ffi_decode_transport(const uint8_t *data, uint32_t len,
                                              uint32_t *out_count);

/**
 * Decode a Zenoh transport-level PDU from an lz4-compressed payload.
 *
 * `data` points to the raw lz4 block bytes with the BatchHeader byte already stripped.
 * Decompresses into a temporary buffer then decodes normally.
 * Same ownership rules as zenoh_codec_ffi_decode_transport.
 * Returns NULL if decompression or decoding fails.
 */
CSpanEntry *zenoh_codec_ffi_decode_transport_compressed(const uint8_t *data, uint32_t len,
                                                         uint32_t *out_count);

/**
 * Decode a Zenoh scouting-level PDU from raw bytes (typically UDP, no length prefix).
 * Same ownership rules as zenoh_codec_ffi_decode_transport.
 */
CSpanEntry *zenoh_codec_ffi_decode_scouting(const uint8_t *data, uint32_t len,
                                             uint32_t *out_count);

/**
 * Free a CSpanEntry[] returned by a decode function.
 * `entries` must be the exact pointer returned by the decode call.
 * `count` must match the value written to *out_count by that call.
 */
void zenoh_codec_ffi_free_spans(CSpanEntry *entries, uint32_t count);

#ifdef __cplusplus
}
#endif
