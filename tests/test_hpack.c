#include "harness.h"
#include "../src/proto/hpack.h"

#include <stdio.h>
#include <string.h>

#include "hpack_fixture.inc"

#define MAXF 16

typedef struct {
    int n;
    char name[MAXF][64];
    char val[MAXF][96];
    size_t nl[MAXF], vl[MAXF];
} got_t;

static void collect(void *user, const char *name, size_t nlen, const char *value, size_t vlen)
{
    got_t *g = (got_t *)user;
    if (g->n >= MAXF) return;
    if (nlen >= sizeof g->name[0] || vlen >= sizeof g->val[0]) { g->nl[g->n] = nlen; g->vl[g->n] = vlen; g->n++; return; }
    memcpy(g->name[g->n], name, nlen); g->name[g->n][nlen] = 0;
    memcpy(g->val[g->n], value, vlen); g->val[g->n][vlen] = 0;
    g->nl[g->n] = nlen; g->vl[g->n] = vlen;
    g->n++;
}

static int dec_raw(ts_hpack *d, const uint8_t *b, size_t n, got_t *g)
{
    memset(g, 0, sizeof *g);
    return ts_hpack_decode(d, b, n, collect, g);
}

static int dec_hex(ts_hpack *d, const char *hex, got_t *g)
{
    uint8_t buf[512];
    size_t n = strlen(hex) / 2;
    memset(g, 0, sizeof *g);
    t_unhex(buf, hex);
    return ts_hpack_decode(d, buf, n, collect, g);
}

/* Compare the collected fields with a flat list of name, value pairs. */
static int is(const got_t *g, int n, const char *const *kv)
{
    int i;
    if (g->n != n) return 0;
    for (i = 0; i < n; i++)
        if (strcmp(g->name[i], kv[2 * i]) != 0 || strcmp(g->val[i], kv[2 * i + 1]) != 0) return 0;
    return 1;
}

static void sequence(const char *label, const char *const *blocks)
{
    static const char *const first[] = { ":method", "GET", ":scheme", "http", ":path", "/", ":authority", "www.example.com" };
    static const char *const second[] = { ":method", "GET", ":scheme", "http", ":path", "/", ":authority", "www.example.com", "cache-control", "no-cache" };
    static const char *const third[] = { ":method", "GET", ":scheme", "https", ":path", "/index.html", ":authority", "www.example.com", "custom-key", "custom-value" };
    ts_hpack d;
    got_t g;
    char nm[64];
    ts_hpack_init(&d);
    snprintf(nm, sizeof nm, "%s first", label);
    t_true(nm, dec_hex(&d, blocks[0], &g) == 0 && is(&g, 4, first));
    snprintf(nm, sizeof nm, "%s second", label);
    t_true(nm, dec_hex(&d, blocks[1], &g) == 0 && is(&g, 5, second));
    snprintf(nm, sizeof nm, "%s third", label);
    t_true(nm, dec_hex(&d, blocks[2], &g) == 0 && is(&g, 5, third));
    /* Third request leaves custom-key, cache-control, www.example.com. */
    snprintf(nm, sizeof nm, "%s table", label);
    t_true(nm, d.count == 3 && d.size == 164);
}

static void test_appendix_c(void)
{
    static const char *const c3[] = {
        "828684410f7777772e6578616d706c652e636f6d",
        "828684be58086e6f2d6361636865",
        "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565" };
    static const char *const c4[] = {
        "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        "828684be5886a8eb10649cbf",
        "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf" };
    sequence("C.3", c3);
    sequence("C.4", c4);
}

/* RFC 7541 C.5 / C.6: responses with a 256 octet table, so entries are evicted. */
static void test_appendix_c_eviction(void)
{
    static const char *const r1[] = { ":status", "302", "cache-control", "private", "date", "Mon, 21 Oct 2013 20:13:21 GMT", "location", "https://www.example.com" };
    static const char *const r2[] = { ":status", "307", "cache-control", "private", "date", "Mon, 21 Oct 2013 20:13:21 GMT", "location", "https://www.example.com" };
    static const char *const r3[] = { ":status", "200", "cache-control", "private", "date", "Mon, 21 Oct 2013 20:13:22 GMT", "location", "https://www.example.com", "content-encoding", "gzip", "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" };
    static const char *const plain[] = {
        "3fe1014803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        "4803333037c1c0bf",
        "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31" };
    static const char *const huff[] = {
        "3fe101488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        "4883640effc1c0bf",
        "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007" };
    int pass;
    for (pass = 0; pass < 2; pass++) {
        const char *const *b = pass ? huff : plain;
        ts_hpack d;
        got_t g;
        ts_hpack_init(&d);
        t_true(pass ? "C.6 first" : "C.5 first", dec_hex(&d, b[0], &g) == 0 && is(&g, 4, r1));
        t_true(pass ? "C.6 first table" : "C.5 first table", d.count == 4 && d.size == 222 && d.max == 256);
        t_true(pass ? "C.6 second" : "C.5 second", dec_hex(&d, b[1], &g) == 0 && is(&g, 4, r2));
        t_true(pass ? "C.6 second table" : "C.5 second table", d.count == 4 && d.size == 222);
        t_true(pass ? "C.6 third" : "C.5 third", dec_hex(&d, b[2], &g) == 0 && is(&g, 6, r3));
        t_true(pass ? "C.6 third table" : "C.5 third table", d.count == 3 && d.size == 215);
    }
}

static void test_size_update(void)
{
    ts_hpack d;
    got_t g;
    ts_hpack_init(&d);
    /* Two entries of 34 octets (1 + 1 + 32) each. */
    t_true("two entries", dec_hex(&d, "4001610162" "4001630164", &g) == 0 && d.count == 2 && d.size == 68);
    /* Shrinking to 40 evicts the older entry (a: b) and keeps the newer (c: d). */
    t_true("shrink evicts oldest", dec_hex(&d, "3f09", &g) == 0 && d.count == 1 && d.size == 34 && d.max == 40);
    t_true("survivor is c: d", dec_hex(&d, "be", &g) == 0 && g.n == 1 && strcmp(g.name[0], "c") == 0 && strcmp(g.val[0], "d") == 0);
    t_true("evicted index fails", dec_hex(&d, "bf", &g) == -1);
    /* Inserting under pressure: the new entry's name comes from the entry it evicts. */
    ts_hpack_init(&d);
    t_true("fill one", dec_hex(&d, "3f09" "4001610162", &g) == 0 && d.count == 1);
    t_true("name from evicted entry", dec_hex(&d, "7e0163", &g) == 0 && g.n == 1 &&
           strcmp(g.name[0], "a") == 0 && strcmp(g.val[0], "c") == 0 && d.count == 1 && d.size == 34);
    t_true("table holds a: c", dec_hex(&d, "be", &g) == 0 && strcmp(g.val[0], "c") == 0);
    /* Size 0 empties the table and nothing is stored afterwards. */
    ts_hpack_init(&d);
    t_true("fill", dec_hex(&d, "4001610162", &g) == 0 && d.count == 1);
    t_true("size 0", dec_hex(&d, "20", &g) == 0 && d.count == 0 && d.size == 0 && d.max == 0);
    t_true("not stored at size 0", dec_hex(&d, "4001610162", &g) == 0 && g.n == 1 && d.count == 0 && d.size == 0);
    /* An entry bigger than the whole table empties it rather than failing. */
    ts_hpack_init(&d);
    t_true("fill again", dec_hex(&d, "4001610162", &g) == 0 && d.count == 1);
    t_true("shrink to 33", dec_hex(&d, "3f02", &g) == 0 && d.count == 0 && d.max == 33);
    t_true("oversize entry ok", dec_hex(&d, "4001610162", &g) == 0 && g.n == 1 && d.count == 0);
    /* A minimum then a final size at the start of a block. */
    ts_hpack_init(&d);
    t_true("0 then 4096", dec_hex(&d, "203fe11f82", &g) == 0 && d.max == 4096 && g.n == 1);
    /* The limit: 4096 passes, 4097 is an error. */
    ts_hpack_init(&d);
    t_true("update to 4096", dec_hex(&d, "3fe11f", &g) == 0 && d.max == 4096);
    ts_hpack_init(&d);
    t_true("update to 4097 rejected", dec_hex(&d, "3fe21f", &g) == -1);
    /* A size update must come first in a block. */
    ts_hpack_init(&d);
    t_true("update after field", dec_hex(&d, "823f09", &g) == -1);
    ts_hpack_init(&d);
    t_true("update before field", dec_hex(&d, "3f0982", &g) == 0 && g.n == 1);
}

static void test_errors(void)
{
    ts_hpack d;
    got_t g;
    static uint8_t big[9000];
    size_t n;

    ts_hpack_init(&d);
    t_true("index 0", dec_hex(&d, "80", &g) == -1);
    t_true("index 62 on empty table", dec_hex(&d, "be", &g) == -1);
    t_true("index 127 (needs ext)", dec_hex(&d, "ff00", &g) == -1);
    t_true("literal name index 62 on empty table", dec_hex(&d, "7e0161", &g) == -1);
    t_true("literal name index 62 never indexed", dec_hex(&d, "1f2f0161", &g) == -1);
    t_true("index 61 ok", dec_hex(&d, "bd", &g) == 0 && g.n == 1 && strcmp(g.name[0], "www-authenticate") == 0);
    t_true("index 1 ok", dec_hex(&d, "81", &g) == 0 && strcmp(g.name[0], ":authority") == 0 && g.vl[0] == 0);

    /* Integers: a value that needs more than 32 bits, in an index and in a length. */
    t_true("index overflow", dec_hex(&d, "ffffffffff7f", &g) == -1);
    t_true("index overflow, long zero run", dec_hex(&d, "ff808080808080808001", &g) == -1);
    t_true("length overflow", dec_hex(&d, "00" "7fffffffff7f", &g) == -1);
    t_true("size update overflow", dec_hex(&d, "3fffffffff7f", &g) == -1);
    t_true("index 2^32-1 is just a missing index", dec_hex(&d, "ffffffffff0f", &g) == -1);

    /* Truncation. */
    t_true("empty block", dec_hex(&d, "", &g) == 0 && g.n == 0);
    t_true("truncated int", dec_hex(&d, "ff", &g) == -1);
    t_true("truncated int ext", dec_hex(&d, "ff80", &g) == -1);
    t_true("no name", dec_hex(&d, "40", &g) == -1);
    t_true("no value", dec_hex(&d, "400161", &g) == -1);
    t_true("short name", dec_hex(&d, "400361", &g) == -1);
    t_true("short value", dec_hex(&d, "4001610261", &g) == -1);

    /* Huffman padding. '0' is 00000, so 0x07 is a valid byte and 0x00 is not. */
    t_true("huffman '0' ok", dec_hex(&d, "0001618107", &g) == 0 && g.n == 1 && strcmp(g.val[0], "0") == 0);
    t_true("huffman zero padding", dec_hex(&d, "0001618100", &g) == -1);
    t_true("huffman short padding", dec_hex(&d, "0001618106", &g) == -1);
    t_true("huffman padding over 7 bits", dec_hex(&d, "00016182" "07ff", &g) == -1);
    t_true("huffman EOS", dec_hex(&d, "00016184ffffffff", &g) == -1);
    t_true("huffman EOS then padding", dec_hex(&d, "00016184fffffffc", &g) == -1);
    t_true("huffman empty", dec_hex(&d, "00016180", &g) == 0 && g.vl[0] == 0);

    /* TS_HPACK_FIELD_MAX: 8192 passes, 8193 does not; for names and values. */
    memset(big, 'x', sizeof big);
    ts_hpack_init(&d);
    n = 0;
    big[n++] = 0x00; big[n++] = 0x01; big[n++] = 'a';
    big[n++] = 0x7f; big[n++] = 0x81; big[n++] = 0x3f;           /* 8192 */
    n += 8192;
    t_true("value of exactly FIELD_MAX", dec_raw(&d, big, n, &g) == 0);
    t_true("  reported length", g.vl[0] == 8192);
    big[5] = 0x40;                                                /* 8193 */
    n++;
    t_true("value over FIELD_MAX", dec_raw(&d, big, n, &g) == -1);
    n = 0;
    big[n++] = 0x00; big[n++] = 0x7f; big[n++] = 0x82; big[n++] = 0x3f;
    t_true("name over FIELD_MAX, data missing", dec_raw(&d, big, n, &g) == -1);
    n += 8193;
    big[n++] = 0x00;
    t_true("name over FIELD_MAX", dec_raw(&d, big, n, &g) == -1);
    /* Huffman: '0' is 5 bits, so 5120 zero octets decode to exactly 8192 symbols
     * and 5121 octets (last one 0x07, three padding bits) to 8193. */
    {
        size_t enc;
        for (enc = 5120; enc <= 5121; enc++) {
            ts_hpack_init(&d);
            n = 0;
            big[n++] = 0x00; big[n++] = 0x01; big[n++] = 'a';
            big[n++] = 0xff;
            big[n++] = (uint8_t)(0x80 | ((enc - 127) & 0x7f));
            big[n++] = (uint8_t)((enc - 127) >> 7);
            memset(big + n, 0, enc);
            if (enc == 5121) big[n + 5120] = 0x07;
            n += enc;
            if (enc == 5120)
                t_true("huffman value of 8192 symbols", dec_raw(&d, big, n, &g) == 0 && g.vl[0] == 8192);
            else
                t_true("huffman value of 8193 symbols", dec_raw(&d, big, n, &g) == -1);
        }
    }
}

static void test_static_table(void)
{
    ts_hpack d;
    got_t g;
    int i, ok = 1;
    ts_hpack_init(&d);
    for (i = 1; i <= 61; i++) {
        uint8_t b = (uint8_t)(0x80 | i);
        memset(&g, 0, sizeof g);
        if (ts_hpack_decode(&d, &b, 1, collect, &g) != 0 || g.n != 1 ||
            strlen(fx_static[i - 1].n) != g.nl[0] || strlen(fx_static[i - 1].v) != g.vl[0] ||
            strcmp(fx_static[i - 1].n, g.name[0]) != 0 || strcmp(fx_static[i - 1].v, g.val[0]) != 0) {
            ok = 0;
            printf("  static index %d mismatch\n", i);
        }
    }
    t_true("static table 1..61", ok);
    /* Literal with a static name index: 0x41 is :authority incremental. */
    t_true("static name index, literal value", dec_hex(&d, "41027869", &g) == 0 && strcmp(g.name[0], ":authority") == 0 && strcmp(g.val[0], "xi") == 0);
    t_true("never-indexed literal", dec_hex(&d, "1f10027869", &g) == 0 && strcmp(g.name[0], "content-type") == 0 && d.count == 1);
    t_true("without-indexing literal", dec_hex(&d, "0f10027869", &g) == 0 && strcmp(g.name[0], "content-type") == 0 && d.count == 1);
}

typedef struct { const uint8_t *want; size_t n; int calls, bad; } bin_t;

static void check_bin(void *user, const char *name, size_t nlen, const char *value, size_t vlen)
{
    bin_t *b = (bin_t *)user;
    b->calls++;
    if (nlen != 1 || name[0] != 'x' || vlen != b->n || memcmp(value, b->want, b->n) != 0) b->bad++;
}

static size_t put_len(uint8_t *p, size_t v)    /* 7-bit prefix with the Huffman bit set */
{
    size_t n = 0;
    if (v < 127) { p[n++] = (uint8_t)(0x80 | v); return n; }
    p[n++] = 0xff;
    v -= 127;
    while (v >= 128) { p[n++] = (uint8_t)(0x80 | (v & 0x7f)); v >>= 7; }
    p[n++] = (uint8_t)v;
    return n;
}

static void test_huffman_all(void)
{
    int b, bad = 0;
    uint8_t blk[600], all[256];
    size_t n;
    bin_t bt;
    ts_hpack d;
    for (b = 0; b < 256; b++) {
        uint8_t v = (uint8_t)b;
        ts_hpack_init(&d);
        n = 0;
        blk[n++] = 0x00; blk[n++] = 0x01; blk[n++] = 'x';
        blk[n++] = (uint8_t)(0x80 | fx_huff[b].n);
        memcpy(blk + n, fx_huff[b].b, fx_huff[b].n);
        n += fx_huff[b].n;
        bt.want = &v; bt.n = 1; bt.calls = 0; bt.bad = 0;
        if (ts_hpack_decode(&d, blk, n, check_bin, &bt) != 0 || bt.calls != 1 || bt.bad) {
            bad++;
            printf("  huffman byte 0x%02x failed\n", b);
        }
    }
    t_true("huffman: all 256 single bytes", bad == 0);
    for (b = 0; b < 256; b++) all[b] = (uint8_t)b;
    ts_hpack_init(&d);
    n = 0;
    blk[n++] = 0x00; blk[n++] = 0x01; blk[n++] = 'x';
    n += put_len(blk + n, sizeof fx_huff_all);
    memcpy(blk + n, fx_huff_all, sizeof fx_huff_all);
    n += sizeof fx_huff_all;
    bt.want = all; bt.n = 256; bt.calls = 0; bt.bad = 0;
    t_true("huffman: 256-byte string", ts_hpack_decode(&d, blk, n, check_bin, &bt) == 0 && bt.calls == 1 && !bt.bad);
}

static void test_encode(void)
{
    uint8_t out[1024], in[1024];
    char nm[400], vl[400];
    size_t n, k, i;
    ts_hpack d, d2;
    got_t g;
    static const char *const pairs[][2] = {
        { "a", "b" }, { ":status", "200" }, { "x-empty", "" },
        { "content-type", "application/json" }, { "k", "v" },
    };

    n = ts_hpack_encode(out, sizeof out, "custom-key", "custom-value");
    t_hex("encode literal", out, n, "00" "0a637573746f6d2d6b6579" "0c637573746f6d2d76616c7565");
    ts_hpack_init(&d);
    t_true("encode round trip", dec_raw(&d, out, n, &g) == 0 && g.n == 1 &&
           strcmp(g.name[0], "custom-key") == 0 && strcmp(g.val[0], "custom-value") == 0 && d.count == 0);

    /* Every cap below the needed size returns 0; the exact size works and is
     * not overrun. */
    for (k = 0; k < n; k++) {
        memset(in, 0xaa, sizeof in);
        if (ts_hpack_encode(in, k, "custom-key", "custom-value") != 0) break;
        for (i = k; i < sizeof in; i++) if (in[i] != 0xaa) break;
        if (i != sizeof in) break;
    }
    t_true("encode: small caps return 0 and write nothing past cap", k == n);
    memset(in, 0xaa, sizeof in);
    t_true("encode: exact cap", ts_hpack_encode(in, n, "custom-key", "custom-value") == n && in[n] == 0xaa);

    /* Lengths at the 7-bit prefix boundaries. */
    ts_hpack_init(&d);
    {
        static const size_t lens[] = { 0, 1, 126, 127, 128, 254, 255, 300 };
        int ok = 1;
        for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            size_t l = lens[i];
            memset(nm, 'n', l); nm[l] = 0;
            memset(vl, 'v', l); vl[l] = 0;
            n = ts_hpack_encode(out, sizeof out, nm, vl);
            memset(&g, 0, sizeof g);
            ts_hpack_init(&d2);
            /* collect() truncates what it stores; compare lengths and the first byte. */
            if (n == 0 || dec_raw(&d2, out, n, &g) != 0 || g.n != 1 ||
                g.nl[0] != l || g.vl[0] != l) { ok = 0; printf("  length %u failed\n", (unsigned)l); }
        }
        t_true("encode round trip at length boundaries", ok);
    }
    {
        int ok = 1;
        for (i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
            n = ts_hpack_encode(out, sizeof out, pairs[i][0], pairs[i][1]);
            ts_hpack_init(&d2);
            if (n == 0 || dec_raw(&d2, out, n, &g) != 0 || g.n != 1 ||
                strcmp(g.name[0], pairs[i][0]) != 0 || strcmp(g.val[0], pairs[i][1]) != 0) ok = 0;
        }
        t_true("encode round trip pairs", ok);
    }
    /* Several fields back to back make one block. */
    n = ts_hpack_encode(out, sizeof out, "a", "b");
    n += ts_hpack_encode(out + n, sizeof out - n, "c", "d");
    ts_hpack_init(&d);
    t_true("two fields in one block", dec_raw(&d, out, n, &g) == 0 && g.n == 2 &&
           strcmp(g.name[1], "c") == 0);
}

void test_hpack(void)
{
    test_appendix_c();
    test_appendix_c_eviction();
    test_size_update();
    test_errors();
    test_static_table();
    test_huffman_all();
    test_encode();
}
