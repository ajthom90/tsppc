#ifndef TS_PROTO_HPACK_H
#define TS_PROTO_HPACK_H

#include <stddef.h>
#include <stdint.h>

/* HPACK (RFC 7541) header block decoder with a dynamic table and Huffman
 * strings, and a literal-only encoder. No allocation: the dynamic table is
 * fixed storage inside ts_hpack.
 *
 * The decoder accepts any header table size update up to TS_HPACK_TABLE_MAX
 * (the SETTINGS_HEADER_TABLE_SIZE we advertise is the 4096 default). Decoded
 * names and values may contain any bytes; the callback gets lengths and the
 * strings are not NUL-terminated. A decoded string longer than
 * TS_HPACK_FIELD_MAX is an error. */

#define TS_HPACK_TABLE_MAX 4096
#define TS_HPACK_FIELD_MAX 8192

/* Each dynamic entry costs its name and value lengths plus 32 octets, so the
 * table holds at most TS_HPACK_TABLE_MAX / 32 entries. */
#define TS_HPACK_ENTRY_MAX (TS_HPACK_TABLE_MAX / 32)

/* Dynamic table: entry 0 is the newest. Entry i's name then value are stored
 * back to back, after those of entries 0..i-1, in data[]. Treat as opaque
 * outside tests. */
typedef struct {
    uint8_t data[TS_HPACK_TABLE_MAX];
    uint16_t nlen[TS_HPACK_ENTRY_MAX];
    uint16_t vlen[TS_HPACK_ENTRY_MAX];
    unsigned count;     /* entries in use */
    uint32_t size;      /* RFC 7541 size: sum of (nlen + vlen + 32) */
    uint32_t max;       /* current maximum, set by size updates */
} ts_hpack;

void ts_hpack_init(ts_hpack *d);

/* Called once per decoded header field, in order. name and value are valid only
 * during the call. */
typedef void (*ts_hpack_cb)(void *user, const char *name, size_t nlen,
                            const char *value, size_t vlen);

/* Decode one complete header block, calling cb for each field. Returns 0, or -1
 * on any error (bad index, bad integer or Huffman data, truncated block, size
 * update above TS_HPACK_TABLE_MAX or after a field, string over
 * TS_HPACK_FIELD_MAX); after an error the decoder must not be used again,
 * though its table is always internally consistent. Fields already delivered
 * before the error were valid. */
int ts_hpack_decode(ts_hpack *d, const uint8_t *block, size_t len,
                    ts_hpack_cb cb, void *user);

/* Encode name and value (NUL-terminated) as a literal header field without
 * indexing, without Huffman. Returns the bytes written, or 0 if cap is too
 * small. */
size_t ts_hpack_encode(uint8_t *out, size_t cap, const char *name, const char *value);

#endif
