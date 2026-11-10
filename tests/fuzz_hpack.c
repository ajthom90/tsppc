#include "fuzz.h"
#include "../src/proto/hpack.h"

#include <stdlib.h>
#include <string.h>

/* Largest block ts_hpack_encode can make for one field: two 3-octet lengths,
 * the opcode and two strings of TS_HPACK_FIELD_MAX. */
#define ENC_MAX (1 + 3 + TS_HPACK_FIELD_MAX + 3 + TS_HPACK_FIELD_MAX)

typedef struct {
    uint64_t hash;
    unsigned fields;
    int roundtrip;      /* also re-encode and decode each field */
} run_t;

typedef struct { const char *name, *value; size_t nl, vl; int ok; } want_t;

static void expect(void *user, const char *name, size_t nlen, const char *value, size_t vlen)
{
    want_t *w = (want_t *)user;
    if (w->ok && nlen == w->nl && vlen == w->vl && memcmp(name, w->name, nlen) == 0 &&
        memcmp(value, w->value, vlen) == 0) w->ok = 1;
    else w->ok = 0;
}

/* The table must always be internally consistent, even after an error. */
static void check_table(const ts_hpack *d)
{
    uint32_t size = 0, bytes = 0;
    unsigned i;
    TS_FUZZ_ASSERT(d->count <= TS_HPACK_ENTRY_MAX);
    TS_FUZZ_ASSERT(d->max <= TS_HPACK_TABLE_MAX);
    TS_FUZZ_ASSERT(d->size <= d->max);
    for (i = 0; i < d->count; i++) {
        size += (uint32_t)d->nlen[i] + d->vlen[i] + 32;
        bytes += (uint32_t)d->nlen[i] + d->vlen[i];
    }
    TS_FUZZ_ASSERT(size == d->size);
    TS_FUZZ_ASSERT(bytes <= TS_HPACK_TABLE_MAX);
}

static void on_field(void *user, const char *name, size_t nlen, const char *value, size_t vlen)
{
    run_t *r = (run_t *)user;
    size_t i;
    TS_FUZZ_ASSERT(nlen <= TS_HPACK_FIELD_MAX && vlen <= TS_HPACK_FIELD_MAX);
    r->fields++;
    r->hash = (r->hash ^ nlen) * 1099511628211ull;
    r->hash = (r->hash ^ vlen) * 1099511628211ull;
    for (i = 0; i < nlen; i++) r->hash = (r->hash ^ (uint8_t)name[i]) * 1099511628211ull;
    for (i = 0; i < vlen; i++) r->hash = (r->hash ^ (uint8_t)value[i]) * 1099511628211ull;

    /* Whatever the decoder produced, the literal encoder must reproduce, unless
     * a NUL makes it not a C string. */
    if (r->roundtrip && memchr(name, 0, nlen) == NULL && memchr(value, 0, vlen) == NULL) {
        char *cn = (char *)malloc(nlen + 1), *cv = (char *)malloc(vlen + 1);
        TS_FUZZ_ASSERT(cn != NULL && cv != NULL);
        memcpy(cn, name, nlen); cn[nlen] = 0;     /* the encoder takes C strings; the callback's are not terminated */
        memcpy(cv, value, vlen); cv[vlen] = 0;
        static uint8_t enc[ENC_MAX];
        ts_hpack d;
        want_t w;
        size_t n = ts_hpack_encode(enc, sizeof enc, cn, cv);
        TS_FUZZ_ASSERT(n > 0 && n <= ENC_MAX);
        TS_FUZZ_ASSERT(ts_hpack_encode(enc, n - 1, cn, cv) == 0);
        w.name = cn; w.value = cv; w.nl = nlen; w.vl = vlen; w.ok = 1;
        ts_hpack_init(&d);
        TS_FUZZ_ASSERT(ts_hpack_decode(&d, enc, n, expect, &w) == 0);
        TS_FUZZ_ASSERT(w.ok && d.count == 0);
        free(cn);
        free(cv);
    }
}

static void target(const uint8_t *data, size_t len)
{
    ts_hpack a, b;
    run_t ra, rb;
    int res_a, res_b;

    memset(&ra, 0, sizeof ra); ra.hash = 14695981039346656037ull; ra.roundtrip = 1;
    rb = ra; rb.roundtrip = 0;
    ts_hpack_init(&a);
    ts_hpack_init(&b);
    res_a = ts_hpack_decode(&a, data, len, on_field, &ra);
    res_b = ts_hpack_decode(&b, data, len, on_field, &rb);
    TS_FUZZ_ASSERT(res_a == 0 || res_a == -1);
    TS_FUZZ_ASSERT(res_a == res_b && ra.hash == rb.hash && ra.fields == rb.fields);   /* deterministic */
    check_table(&a);
    TS_FUZZ_ASSERT(a.count == b.count && a.size == b.size && a.max == b.max);
    TS_FUZZ_ASSERT(memcmp(a.nlen, b.nlen, a.count * sizeof a.nlen[0]) == 0);
    /* A second pass over the same decoder runs against the table the first left,
     * and a size update at its start now meets a populated table. */
    (void)ts_hpack_decode(&a, data, len, on_field, &ra);
    check_table(&a);
    /* Any prefix of the block is also safe to decode. */
    if (len > 1) {
        (void)ts_hpack_decode(&b, data, len / 2, on_field, &rb);
        check_table(&b);
    }
}

static size_t hexn(uint8_t *out, const char *hex)
{
    size_t n = 0, i;
    for (i = 0; hex[i]; i += 2) {
        unsigned v;
        char c[3];
        c[0] = hex[i]; c[1] = hex[i + 1]; c[2] = 0;
        v = (unsigned)strtoul(c, NULL, 16);
        out[n++] = (uint8_t)v;
    }
    return n;
}

void ts_fuzz_hpack(void)
{
    /* RFC 7541 Appendix C.3, C.4 (requests) and C.5, C.6 (responses with a
     * 256 octet table, so the dynamic table evicts). */
    static const char *const hex[] = {
        "828684410f7777772e6578616d706c652e636f6d",
        "828684be58086e6f2d6361636865",
        "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        "828684be5886a8eb10649cbf",
        "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
        "3fe1014803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        "4803333037c1c0bf",
        "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        "3fe101488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        "4883640effc1c0bf",
        "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        /* Size updates: shrink to 40 then fill, a name taken from the entry it
         * evicts, then indexes of live and evicted entries; and an update after a field. */
        "3f09" "4001610162" "4001630164" "7e0165" "be" "bf",
        "203fe11f" "82",
        "823f09",
        "3fe21f",                                  /* 4097: over the limit */
        /* Literal forms with static name indexes, and Huffman padding cases. */
        "0f10027869" "1f10027869" "41027869" "0001618107" "0001618100" "00016184ffffffff",
        /* Integers: the overflow boundaries and a zero-padded long form. */
        "ffffffffff0f", "ffffffffff7f", "ff808080808080808001", "007fffffffff7f",
        /* Index 61 and 62, an empty block, and truncated forms. */
        "bd", "be", "", "40", "4001", "ff",
    };
    enum { NHEX = sizeof hex / sizeof hex[0], NEXTRA = 3, NSEED = NHEX + NEXTRA };
    static uint8_t buf[NSEED][4400];
    const uint8_t *seeds[NSEED];
    size_t lens[NSEED];
    size_t i, n, k;

    for (i = 0; i < NHEX; i++) lens[i] = hexn(buf[i], hex[i]);

    /* Eviction pressure: a 256 octet table, then 40 incremental literals of
     * growing size, each followed by references to the newest entries. */
    n = 0;
    buf[NHEX][n++] = 0x3f; buf[NHEX][n++] = 0xe1; buf[NHEX][n++] = 0x01;
    for (k = 1; k <= 40; k++) {
        size_t vl = k * 3;
        buf[NHEX][n++] = 0x40;
        buf[NHEX][n++] = 0x02; buf[NHEX][n++] = 'k'; buf[NHEX][n++] = (uint8_t)('a' + k % 26);
        buf[NHEX][n++] = (uint8_t)vl;
        memset(buf[NHEX] + n, 'v', vl);
        n += vl;
        buf[NHEX][n++] = 0xbe; buf[NHEX][n++] = 0xbf; buf[NHEX][n++] = 0xc0;
    }
    lens[NHEX] = n;
    /* The same through the default 4096 table with entries near the limit. */
    n = 0;
    for (k = 0; k < 4; k++) {
        buf[NHEX + 1][n++] = 0x40;
        buf[NHEX + 1][n++] = 0x01; buf[NHEX + 1][n++] = (uint8_t)('a' + k);
        buf[NHEX + 1][n++] = 0x7f; buf[NHEX + 1][n++] = 0x80 | ((1000 - 127) & 0x7f); buf[NHEX + 1][n++] = (uint8_t)((1000 - 127) >> 7);
        memset(buf[NHEX + 1] + n, 'z', 1000);
        n += 1000;
    }
    buf[NHEX + 1][n++] = 0xbe; buf[NHEX + 1][n++] = 0xc1;
    lens[NHEX + 1] = n;
    /* Several encoder-made fields, one with a long value. */
    n = 0;
    n += ts_hpack_encode(buf[NHEX + 2] + n, sizeof buf[0] - n, "x-custom", "short");
    {
        char longv[301];
        memset(longv, 'q', 300); longv[300] = 0;
        n += ts_hpack_encode(buf[NHEX + 2] + n, sizeof buf[0] - n, "x-long-header-name", longv);
    }
    lens[NHEX + 2] = n;

    for (i = 0; i < NSEED; i++) seeds[i] = buf[i];
    ts_fuzz_run("hpack", target, seeds, lens, NSEED, TS_FUZZ_DEFAULT_ITERS);
}
