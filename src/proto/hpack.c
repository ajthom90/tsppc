#include "hpack.h"

#include <string.h>

#include "hpack_huffman.inc"

#define TS_HPACK_STATIC 61

static const struct { const char *name, *value; } ts_hpack_static[TS_HPACK_STATIC] = {
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" },
};

void ts_hpack_init(ts_hpack *d)
{
    d->count = 0;
    d->size = 0;
    d->max = TS_HPACK_TABLE_MAX;
}

/* Bytes of data[] in use. */
static size_t table_bytes(const ts_hpack *d)
{
    size_t i, n = 0;
    for (i = 0; i < d->count; i++) n += (size_t)d->nlen[i] + d->vlen[i];
    return n;
}

/* Drop the oldest entries until the table fits in limit octets. */
static void evict(ts_hpack *d, uint32_t limit)
{
    while (d->count > 0 && d->size > limit) {
        unsigned last = d->count - 1;
        d->size -= (uint32_t)d->nlen[last] + d->vlen[last] + 32;
        d->count = last;
    }
}

/* Add an entry; name and value must not point into d. */
static void table_add(ts_hpack *d, const uint8_t *name, size_t nl, const uint8_t *value, size_t vl)
{
    uint32_t esz = (uint32_t)(nl + vl + 32);   /* both are at most TS_HPACK_FIELD_MAX */
    size_t used;
    if (esz > d->max) {      /* RFC 7541 4.4: too big for the table empties it */
        d->count = 0;
        d->size = 0;
        return;
    }
    evict(d, d->max - esz);
    used = table_bytes(d);
    memmove(d->data + nl + vl, d->data, used);
    memmove(d->nlen + 1, d->nlen, d->count * sizeof d->nlen[0]);
    memmove(d->vlen + 1, d->vlen, d->count * sizeof d->vlen[0]);
    memcpy(d->data, name, nl);
    memcpy(d->data + nl, value, vl);
    d->nlen[0] = (uint16_t)nl;
    d->vlen[0] = (uint16_t)vl;
    d->count++;
    d->size += esz;
}

/* Find entry idx (1-based over the static then dynamic table). */
static int lookup(const ts_hpack *d, uint32_t idx, const uint8_t **name, size_t *nl,
                  const uint8_t **value, size_t *vl)
{
    if (idx == 0) return -1;
    if (idx <= TS_HPACK_STATIC) {
        *name = (const uint8_t *)ts_hpack_static[idx - 1].name;
        *value = (const uint8_t *)ts_hpack_static[idx - 1].value;
        *nl = strlen((const char *)*name);
        *vl = strlen((const char *)*value);
        return 0;
    }
    idx -= TS_HPACK_STATIC + 1;
    if (idx >= d->count) return -1;
    {
        size_t off = 0, i;
        for (i = 0; i < idx; i++) off += (size_t)d->nlen[i] + d->vlen[i];
        *name = d->data + off;
        *nl = d->nlen[idx];
        *value = d->data + off + *nl;
        *vl = d->vlen[idx];
    }
    return 0;
}

/* RFC 7541 5.1 integer with an n-bit prefix. The value must fit in 32 bits. */
static int get_int(const uint8_t *b, size_t len, size_t *pos, unsigned n, uint32_t *out)
{
    uint32_t mask = ((uint32_t)1 << n) - 1;
    uint64_t v;
    unsigned m = 0;
    if (*pos >= len) return -1;
    v = b[(*pos)++] & mask;
    if (v < mask) { *out = (uint32_t)v; return 0; }
    for (;;) {
        uint8_t c;
        if (*pos >= len || m > 28) return -1;
        c = b[(*pos)++];
        v += (uint64_t)(c & 0x7f) << m;
        if (v > 0xffffffffu) return -1;
        if (!(c & 0x80)) break;
        m += 7;
    }
    *out = (uint32_t)v;
    return 0;
}

/* Huffman-decode src into out (cap bytes); returns the length or -1. The code
 * is canonical (see tools/gen_hpack_tables.py), so decoding walks the lengths. */
static int huff_decode(uint8_t *out, size_t cap, const uint8_t *src, size_t n)
{
    size_t o = 0, i;
    uint32_t code = 0, first = 0;
    unsigned index = 0, len = 0;
    for (i = 0; i < n; i++) {
        int bit;
        for (bit = 7; bit >= 0; bit--) {
            uint32_t cnt;
            code |= (src[i] >> bit) & 1u;
            len++;
            cnt = ts_hpack_huff_count[len];
            if (code - first < cnt) {         /* unsigned: also fails if code < first */
                unsigned sym = ts_hpack_huff_sym[index + (code - first)];
                if (sym == 256 || o >= cap) return -1;   /* EOS in data, or too long */
                out[o++] = (uint8_t)sym;
                code = 0; first = 0; index = 0; len = 0;
            } else {
                if (len >= 30) return -1;
                index += cnt;
                first = (first + cnt) << 1;
                code <<= 1;
            }
        }
    }
    /* What is left must be at most 7 bits of padding, all ones (a prefix of EOS).
     * The loop shifted code once past the last bit it took. */
    if (len > 7 || (len > 0 && (code >> 1) != ((1u << len) - 1))) return -1;
    return (int)o;
}

/* Read a string literal into out (room for TS_HPACK_FIELD_MAX + 1), NUL-terminated. */
static int get_string(const uint8_t *b, size_t len, size_t *pos, uint8_t *out, size_t *outlen)
{
    uint32_t n;
    int huff;
    if (*pos >= len) return -1;
    huff = (b[*pos] & 0x80) != 0;
    if (get_int(b, len, pos, 7, &n) < 0) return -1;
    if (n > len - *pos) return -1;
    if (huff) {
        int r = huff_decode(out, TS_HPACK_FIELD_MAX, b + *pos, n);
        if (r < 0) return -1;
        *outlen = (size_t)r;
    } else {
        if (n > TS_HPACK_FIELD_MAX) return -1;
        memcpy(out, b + *pos, n);
        *outlen = n;
    }
    out[*outlen] = 0;
    *pos += n;
    return 0;
}

int ts_hpack_decode(ts_hpack *d, const uint8_t *block, size_t len, ts_hpack_cb cb, void *user)
{
    uint8_t nbuf[TS_HPACK_FIELD_MAX + 1], vbuf[TS_HPACK_FIELD_MAX + 1];
    size_t pos = 0;
    int seen_field = 0;

    while (pos < len) {
        uint8_t c = block[pos];
        uint32_t v;
        const uint8_t *name, *value;
        size_t nl, vl;

        if (c & 0x80) {                                   /* indexed field */
            if (get_int(block, len, &pos, 7, &v) < 0) return -1;
            if (lookup(d, v, &name, &nl, &value, &vl) < 0) return -1;
            seen_field = 1;
            cb(user, (const char *)name, nl, (const char *)value, vl);
        } else if ((c & 0xe0) == 0x20) {                  /* size update */
            if (seen_field) return -1;
            if (get_int(block, len, &pos, 5, &v) < 0) return -1;
            if (v > TS_HPACK_TABLE_MAX) return -1;
            d->max = v;
            evict(d, d->max);
        } else {                                          /* literal */
            int incr = (c & 0xc0) == 0x40;
            if (get_int(block, len, &pos, incr ? 6 : 4, &v) < 0) return -1;
            if (v == 0) {
                if (get_string(block, len, &pos, nbuf, &nl) < 0) return -1;
            } else {
                if (lookup(d, v, &name, &nl, &value, &vl) < 0) return -1;
                memcpy(nbuf, name, nl);     /* a table entry may be evicted below */
                nbuf[nl] = 0;
            }
            if (get_string(block, len, &pos, vbuf, &vl) < 0) return -1;
            seen_field = 1;
            cb(user, (const char *)nbuf, nl, (const char *)vbuf, vl);
            if (incr) table_add(d, nbuf, nl, vbuf, vl);
        }
    }
    return 0;
}

/* Integer with an n-bit prefix; flags are the high bits of the first octet. */
static size_t put_int(uint8_t *out, size_t cap, uint8_t flags, unsigned n, size_t v)
{
    size_t k = 0, mask = ((size_t)1 << n) - 1;
    if (v < mask) {
        if (cap < 1) return 0;
        out[0] = (uint8_t)(flags | v);
        return 1;
    }
    if (cap < 1) return 0;
    out[k++] = (uint8_t)(flags | mask);
    v -= mask;
    while (v >= 128) {
        if (k >= cap) return 0;
        out[k++] = (uint8_t)(0x80 | (v & 0x7f));
        v >>= 7;
    }
    if (k >= cap) return 0;
    out[k++] = (uint8_t)v;
    return k;
}

static size_t put_string(uint8_t *out, size_t cap, const char *s)
{
    size_t n = strlen(s), k = put_int(out, cap, 0, 7, n);
    if (k == 0 || n > cap - k) return 0;
    memcpy(out + k, s, n);
    return k + n;
}

size_t ts_hpack_encode(uint8_t *out, size_t cap, const char *name, const char *value)
{
    size_t k, r;
    if (cap < 1) return 0;
    out[0] = 0x00;                   /* literal without indexing, new name */
    k = 1;
    r = put_string(out + k, cap - k, name);
    if (r == 0) return 0;
    k += r;
    r = put_string(out + k, cap - k, value);
    if (r == 0) return 0;
    return k + r;
}
