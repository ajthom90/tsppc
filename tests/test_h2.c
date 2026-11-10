#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "h2_script.inc"

/* ---- Callback recorder ------------------------------------------------- */

typedef struct {
    char log[1 << 17];
    size_t n;
    int consume;             /* call ts_h2_consume_data from the data callback */
    int quiet;               /* log data sizes only, not contents */
    ts_h2 *c;
    uint64_t bytes[16];      /* data bytes per stream id */
    int ended[16];
} rec_t;

static void logf_(rec_t *r, const char *s, size_t len)
{
    if (len > sizeof r->log - 1 - r->n) len = sizeof r->log - 1 - r->n;
    memcpy(r->log + r->n, s, len);
    r->n += len;
    r->log[r->n] = 0;
}

static void on_headers(void *u, uint32_t sid, int status)
{
    char b[64];
    snprintf(b, sizeof b, "H%u:%d;", (unsigned)sid, status);
    logf_((rec_t *)u, b, strlen(b));
}

static void on_header(void *u, uint32_t sid, const char *n, size_t nl, const char *v, size_t vl)
{
    rec_t *r = (rec_t *)u;
    char b[32];
    snprintf(b, sizeof b, "h%u:", (unsigned)sid);
    logf_(r, b, strlen(b));
    logf_(r, n, nl);
    logf_(r, "=", 1);
    logf_(r, v, vl);
    logf_(r, ";", 1);
}

static void on_data(void *u, uint32_t sid, const uint8_t *d, size_t n)
{
    rec_t *r = (rec_t *)u;
    if (sid < 16) r->bytes[sid] += n;
    if (!r->quiet) {
        char b[32];
        snprintf(b, sizeof b, "D%u:", (unsigned)sid);
        logf_(r, b, strlen(b));
        logf_(r, (const char *)d, n);
        logf_(r, ";", 1);
    }
    if (r->consume) (void)ts_h2_consume_data(r->c, sid, n);
}

static void on_end(void *u, uint32_t sid, int error)
{
    rec_t *r = (rec_t *)u;
    char b[64];
    if (sid < 16) r->ended[sid] = 1;
    snprintf(b, sizeof b, "E%u:%d;", (unsigned)sid, error);
    logf_(r, b, strlen(b));
}

static void on_goaway(void *u, uint32_t last, uint32_t code)
{
    char b[64];
    snprintf(b, sizeof b, "G%u:%u;", (unsigned)last, (unsigned)code);
    logf_((rec_t *)u, b, strlen(b));
}

static const ts_h2_cbs CBS = { on_headers, on_header, on_data, on_end, on_goaway };

/* ---- Client output, parsed into frames --------------------------------- */

#define WIRE_CAP (1u << 20)
#define WIRE_FRAMES 4096

typedef struct { unsigned type, flags; uint32_t sid; size_t off, len; } fr_t;

typedef struct {
    uint8_t *b;
    size_t n, parsed;
    fr_t f[WIRE_FRAMES];
    size_t nf, seen;         /* frames parsed; frames the scripted server has looked at */
    int bad;                 /* malformed output or overflow */
    /* Scripted server's view of its send windows. */
    int64_t conn, init, strm[16];
} wire_t;

static void wire_init(wire_t *w)
{
    memset(w, 0, sizeof *w);
    w->b = (uint8_t *)malloc(WIRE_CAP);
    w->conn = 65535;
    w->init = 65535;
}

static void wire_free(wire_t *w) { free(w->b); w->b = NULL; }

/* Drain all of the client's output, then parse new complete frames. The first
 * 24 bytes must be the preface. */
static void take(wire_t *w, ts_h2 *c)
{
    const uint8_t *o;
    size_t k;
    while ((k = ts_h2_output(c, &o)) > 0) {
        if (k > WIRE_CAP - w->n) { w->bad = 1; ts_h2_consumed(c, k); continue; }
        memcpy(w->b + w->n, o, k);
        w->n += k;
        ts_h2_consumed(c, k);
    }
    if (w->parsed == 0) {
        if (w->n < 24) return;
        if (memcmp(w->b, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) w->bad = 1;
        w->parsed = 24;
    }
    while (w->n - w->parsed >= 9 && w->nf < WIRE_FRAMES) {
        size_t len = ts_get_be32(w->b + w->parsed) >> 8;
        fr_t *f;
        if (w->n - w->parsed < 9 + len) break;
        f = &w->f[w->nf++];
        f->type = w->b[w->parsed + 3];
        f->flags = w->b[w->parsed + 4];
        f->sid = ts_get_be32(w->b + w->parsed + 5);
        f->off = w->parsed + 9;
        f->len = len;
        w->parsed += 9 + len;
    }
}

/* The scripted server reads the client's new frames: SETTINGS and WINDOW_UPDATE
 * change its send windows, and HEADERS opens a stream window. */
static void scan(wire_t *w)
{
    for (; w->seen < w->nf; w->seen++) {
        const fr_t *f = &w->f[w->seen];
        const uint8_t *p = w->b + f->off;
        size_t i;
        if (f->type == H2S_SETTINGS && !(f->flags & H2S_ACK)) {
            for (i = 0; i + 6 <= f->len; i += 6)
                if (ts_get_be16(p + i) == 4) {
                    int64_t v = ts_get_be32(p + i + 2), d = v - w->init;
                    unsigned s;
                    for (s = 0; s < 16; s++) if (w->strm[s]) w->strm[s] += d;
                    w->init = v;
                }
        } else if (f->type == H2S_WINDOW && f->len == 4) {
            uint32_t inc = ts_get_be32(p) & 0x7fffffffu;
            if (f->sid == 0) w->conn += inc;
            else if (f->sid < 16) w->strm[f->sid] += inc;
        } else if (f->type == H2S_HEADERS && f->sid < 16) {
            w->strm[f->sid] = w->init;
        }
    }
}

/* Count frames of a type (and stream, unless sid is ~0) in frames [from, nf). */
static size_t count(const wire_t *w, size_t from, unsigned type, uint32_t sid)
{
    size_t i, k = 0;
    for (i = from; i < w->nf; i++)
        if (w->f[i].type == type && (sid == ~0u || w->f[i].sid == sid)) k++;
    return k;
}

/* Concatenate DATA payloads for a stream from frame index from; *end is set if
 * a DATA frame had END_STREAM. Returns the byte count. */
static size_t data_out(const wire_t *w, size_t from, uint32_t sid, uint8_t *out, size_t cap, int *end, size_t *maxframe)
{
    size_t i, n = 0;
    *end = 0;
    if (maxframe) *maxframe = 0;
    for (i = from; i < w->nf; i++) {
        const fr_t *f = &w->f[i];
        if (f->type != H2S_DATA || f->sid != sid) continue;
        if (n + f->len <= cap) memcpy(out + n, w->b + f->off, f->len);
        n += f->len;
        if (maxframe && f->len > *maxframe) *maxframe = f->len;
        if (f->flags & H2S_END_STREAM) *end = 1;
    }
    return n;
}

static ts_h2 *new_conn(rec_t *r, wire_t *w)
{
    ts_h2 *c = (ts_h2 *)malloc(sizeof *c);
    memset(r, 0, sizeof *r);
    r->c = c;
    ts_h2_init(c, &CBS, r);
    wire_init(w);
    take(w, c);
    scan(w);
    return c;
}

static void del_conn(ts_h2 *c, wire_t *w)
{
    ts_h2_free(c);
    free(c);
    wire_free(w);
}

static int feed(ts_h2 *c, wire_t *w, const uint8_t *b, size_t n)
{
    int rc = ts_h2_feed(c, b, n);
    take(w, c);
    scan(w);
    return rc;
}

static int feed_settings(ts_h2 *c, wire_t *w, const uint32_t *kv, size_t npairs)
{
    uint8_t b[128];
    return feed(c, w, b, h2s_settings(b, kv, npairs));
}

static int feed_frame(ts_h2 *c, wire_t *w, unsigned type, unsigned flags, uint32_t sid, const void *p, size_t len)
{
    static uint8_t b[9 + 70000];
    return feed(c, w, b, h2s_frame(b, type, flags, sid, p, len));
}

static int feed_u32(ts_h2 *c, wire_t *w, unsigned type, uint32_t sid, uint32_t v)
{
    uint8_t b[16];
    return feed(c, w, b, h2s_u32(b, type, sid, v));
}

/* HEADERS with :status 200 and END_HEADERS. */
static int feed_200(ts_h2 *c, wire_t *w, uint32_t sid, unsigned flags)
{
    static const uint8_t s200 = 0x88;
    return feed_frame(c, w, H2S_HEADERS, H2S_END_HEADERS | flags, sid, &s200, 1);
}

/* Serve total bytes of DATA on sid within the windows the client grants, the
 * last frame with END_STREAM. Stops when the windows are exhausted (stall).
 * Returns bytes sent so far. */
static uint64_t serve(ts_h2 *c, wire_t *w, uint32_t sid, uint64_t total, uint64_t *sent, int *rc)
{
    static uint8_t chunk[16384];
    memset(chunk, 'z', sizeof chunk);
    *rc = 0;
    while (*sent < total) {
        int64_t k = 16384;
        if ((int64_t)(total - *sent) < k) k = (int64_t)(total - *sent);
        if (w->conn < k) k = w->conn;
        if (w->strm[sid] < k) k = w->strm[sid];
        if (k <= 0) break;
        w->conn -= k;
        w->strm[sid] -= k;
        *sent += (uint64_t)k;
        *rc = feed_frame(c, w, H2S_DATA, *sent == total ? H2S_END_STREAM : 0, sid, chunk, (size_t)k);
        if (*rc) break;
    }
    return *sent;
}

/* ---- Tests ------------------------------------------------------------- */

static void test_preface(void)
{
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    t_hex("preface, SETTINGS, connection WINDOW_UPDATE", w.b, w.n,
          "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
          "00000c040000000000" "000200000000" "000400100000"
          "000004080000000000" "000f0001");
    t_true("init output well formed", !w.bad && w.nf == 2);
    del_conn(c, &w);
}

static void test_settings_ping(void)
{
    static const uint8_t ping[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    size_t at = w.n;
    t_true("server SETTINGS accepted", feed_settings(c, &w, NULL, 0) == 0);
    t_hex("SETTINGS ACK", w.b + at, w.n - at, "000000040100000000");
    at = w.n;
    t_true("PING accepted", feed_frame(c, &w, H2S_PING, 0, 0, ping, 8) == 0);
    t_hex("PING ACK echoes", w.b + at, w.n - at, "000008060100000000" "0908070605040302");
    at = w.n;
    t_true("PING ACK from server accepted", feed_frame(c, &w, H2S_PING, H2S_ACK, 0, ping, 8) == 0);
    t_true("no reply to a PING ACK", w.n == at);
    ts_h2_ping(c);
    take(&w, c);
    t_true("ts_h2_ping sends PING", w.nf > 0 && w.f[w.nf - 1].type == H2S_PING &&
           w.f[w.nf - 1].flags == 0 && w.f[w.nf - 1].len == 8 && w.f[w.nf - 1].sid == 0);
    del_conn(c, &w);
}

typedef struct { int n; char f[16][80]; } fields_t;

static void collect(void *u, const char *n, size_t nl, const char *v, size_t vl)
{
    fields_t *g = (fields_t *)u;
    if (g->n < 16 && nl + vl + 2 < 80) {
        memcpy(g->f[g->n], n, nl);
        g->f[g->n][nl] = ' ';
        memcpy(g->f[g->n] + nl + 1, v, vl);
        g->f[g->n][nl + 1 + vl] = 0;
    }
    g->n++;
}

static void test_simple_response(void)
{
    static const char *const hdrs[] = { "Ts-Lb", "nodekey:00", "accept", "*/*" };
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t sid = 0;
    size_t from = w.nf;
    fields_t g;
    ts_hpack d;
    int rc;

    t_true("request ok", ts_h2_request(c, &sid, "GET", "/key", "control.example", hdrs, 2, NULL, 0) == 0 && sid == 1);
    take(&w, c);
    t_true("one HEADERS frame", count(&w, from, H2S_HEADERS, 1) == 1 && w.nf == from + 1);
    t_true("HEADERS ends stream and headers", w.f[from].flags == (H2S_END_STREAM | H2S_END_HEADERS));
    memset(&g, 0, sizeof g);
    ts_hpack_init(&d);
    rc = ts_hpack_decode(&d, w.b + w.f[from].off, w.f[from].len, collect, &g);
    t_true("request block decodes", rc == 0 && g.n == 6);
    t_true("request pseudo-headers", strcmp(g.f[0], ":method GET") == 0 && strcmp(g.f[1], ":scheme https") == 0 &&
           strcmp(g.f[2], ":path /key") == 0 && strcmp(g.f[3], ":authority control.example") == 0);
    t_true("header names lowercased", strcmp(g.f[4], "ts-lb nodekey:00") == 0 && strcmp(g.f[5], "accept */*") == 0);

    t_true("settings", feed_settings(c, &w, NULL, 0) == 0);
    t_true("headers", feed_200(c, &w, 1, 0) == 0);
    t_true("data", feed_frame(c, &w, H2S_DATA, H2S_END_STREAM, 1, "hello", 5) == 0);
    t_true("headers, data, end in order", strcmp(r.log, "H1:200;D1:hello;E1:0;") == 0);
    t_true("second stream id is 3", ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0) == 0 && sid == 3);
    del_conn(c, &w);
}

static void test_continuation_padding(void)
{
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t sid;
    uint8_t blk[64], p[16];
    size_t bl = 0;

    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    blk[bl++] = 0x88;
    bl += ts_hpack_encode(blk + bl, sizeof blk - bl, "x-a", "1");
    t_true("HEADERS without END_HEADERS", feed_frame(c, &w, H2S_HEADERS, 0, 1, blk, 3) == 0);
    t_true("nothing delivered mid-block", r.n == 0);
    t_true("CONTINUATION 1", feed_frame(c, &w, H2S_CONT, 0, 1, blk + 3, 2) == 0);
    t_true("CONTINUATION 2", feed_frame(c, &w, H2S_CONT, H2S_END_HEADERS, 1, blk + 5, bl - 5) == 0);
    p[0] = 3; memcpy(p + 1, "abc", 3); memset(p + 4, 0, 3);
    t_true("padded DATA", feed_frame(c, &w, H2S_DATA, H2S_PADDED | H2S_END_STREAM, 1, p, 7) == 0);
    t_true("one block, data without padding", strcmp(r.log, "h1:x-a=1;H1:200;D1:abc;E1:0;") == 0);
    del_conn(c, &w);
}

static void test_informational_trailers(void)
{
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t sid;
    uint8_t blk[64];
    size_t bl;

    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    bl = ts_hpack_encode(blk, sizeof blk, ":status", "100");
    bl += ts_hpack_encode(blk + bl, sizeof blk - bl, "x-info", "1");
    t_true("100 Continue", feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS, 1, blk, bl) == 0);
    t_true("1xx delivers nothing", r.n == 0);
    t_true("final", feed_200(c, &w, 1, 0) == 0);
    t_true("data", feed_frame(c, &w, H2S_DATA, 0, 1, "x", 1) == 0);
    bl = ts_hpack_encode(blk, sizeof blk, "x-t", "2");
    t_true("trailers", feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS | H2S_END_STREAM, 1, blk, bl) == 0);
    t_true("trailers via header only", strcmp(r.log, "H1:200;D1:x;h1:x-t=2;E1:0;") == 0);

    /* Trailers without END_STREAM and a block without :status are errors. */
    del_conn(c, &w);
    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    (void)feed_200(c, &w, 1, 0);
    t_true("trailers without END_STREAM", feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS, 1, blk, bl) == -1);
    del_conn(c, &w);
    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    t_true("response without :status", feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS, 1, blk, bl) == -1);
    t_true("nothing delivered after error", r.n == 0 || strstr(r.log, "H1") == NULL);
    del_conn(c, &w);
}

static void test_receive_window(void)
{
    const uint64_t total = (uint64_t)TS_H2_WINDOW + 5 * 16384 + 100;
    int pass;
    for (pass = 0; pass < 2; pass++) {
        rec_t r;
        wire_t w;
        ts_h2 *c = new_conn(&r, &w);
        uint32_t sid;
        uint64_t sent = 0;
        int rc;
        size_t from;
        r.quiet = 1;
        r.consume = pass;
        (void)ts_h2_request(c, &sid, "GET", "/big", "a", NULL, 0, NULL, 0);
        (void)feed_settings(c, &w, NULL, 0);
        (void)feed_200(c, &w, 1, 0);
        from = w.nf;
        serve(c, &w, 1, total, &sent, &rc);
        if (!pass) {
            t_true("no consume: stalls at the window", rc == 0 && sent == TS_H2_WINDOW && r.bytes[1] == TS_H2_WINDOW && !r.ended[1]);
            t_true("no consume: no WINDOW_UPDATE", count(&w, from, H2S_WINDOW, ~0u) == 0);
            /* Consuming afterwards releases credit and the rest arrives. */
            t_true("late consume", ts_h2_consume_data(c, 1, TS_H2_WINDOW) == 0);
            take(&w, c);
            scan(&w);
            t_true("late consume sends WINDOW_UPDATEs", count(&w, from, H2S_WINDOW, 0) > 0 && count(&w, from, H2S_WINDOW, 1) > 0);
            r.consume = 1;
            serve(c, &w, 1, total, &sent, &rc);
        }
        t_true(pass ? "consume: completes" : "late consume: completes",
               rc == 0 && sent == total && r.bytes[1] == total && r.ended[1] && strstr(r.log, "E1:0;") != NULL);
        t_true("consume on an ended stream is a no-op", ts_h2_consume_data(c, 1, 1) == 0 && ts_h2_consume_data(c, 3, 1) == 0);
        del_conn(c, &w);
    }
    /* Consuming more than was delivered on a live stream is an error. */
    {
        rec_t r;
        wire_t w;
        ts_h2 *c = new_conn(&r, &w);
        uint32_t sid;
        (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
        (void)feed_settings(c, &w, NULL, 0);
        (void)feed_200(c, &w, 1, 0);
        (void)feed_frame(c, &w, H2S_DATA, 0, 1, "abcd", 4);
        t_true("over-consume rejected", ts_h2_consume_data(c, 1, 5) == -1);
        t_true("exact consume ok", ts_h2_consume_data(c, 1, 4) == 0);
        del_conn(c, &w);
    }
}

static void test_request_body(void)
{
    static uint8_t body[40000], got[40000];
    static const uint32_t small[] = { 4, 1000 };
    rec_t r;
    wire_t w;
    ts_h2 *c;
    uint32_t sid;
    size_t i, n, from, maxf;
    int end;

    for (i = 0; i < sizeof body; i++) body[i] = (uint8_t)(i * 7 + i / 251);

    /* Peer initial window 1000: 1000 bytes go, the rest after WINDOW_UPDATE. */
    c = new_conn(&r, &w);
    (void)feed_settings(c, &w, small, 1);
    from = w.nf;
    t_true("request with 5000-byte body", ts_h2_request(c, &sid, "POST", "/p", "a", NULL, 0, body, 5000) == 0);
    take(&w, c);
    n = data_out(&w, from, 1, got, sizeof got, &end, NULL);
    t_true("first 1000 bytes only", n == 1000 && !end);
    t_true("HEADERS without END_STREAM", w.f[from].type == H2S_HEADERS && w.f[from].flags == H2S_END_HEADERS);
    t_true("stream WINDOW_UPDATE", feed_u32(c, &w, H2S_WINDOW, 1, 4000) == 0);
    n = data_out(&w, from, 1, got, sizeof got, &end, NULL);
    t_true("whole body after credit", n == 5000 && end && memcmp(got, body, 5000) == 0);
    del_conn(c, &w);

    /* Shrinking and growing INITIAL_WINDOW_SIZE adjusts the open stream. */
    c = new_conn(&r, &w);
    (void)feed_settings(c, &w, small, 1);
    from = w.nf;
    (void)ts_h2_request(c, &sid, "POST", "/p", "a", NULL, 0, body, 3000);
    take(&w, c);
    {
        static const uint32_t s500[] = { 4, 500 }, s2000[] = { 4, 2000 };
        t_true("1000 sent", data_out(&w, from, 1, got, sizeof got, &end, NULL) == 1000);
        t_true("shrink to 500", feed_settings(c, &w, s500, 1) == 0);
        t_true("credit 400: window still -100", feed_u32(c, &w, H2S_WINDOW, 1, 400) == 0 &&
               data_out(&w, from, 1, got, sizeof got, &end, NULL) == 1000);
        t_true("credit 600: 500 more", feed_u32(c, &w, H2S_WINDOW, 1, 600) == 0 &&
               data_out(&w, from, 1, got, sizeof got, &end, NULL) == 1500 && !end);
        t_true("grow to 2000: the rest", feed_settings(c, &w, s2000, 1) == 0 &&
               data_out(&w, from, 1, got, sizeof got, &end, NULL) == 3000 && end && memcmp(got, body, 3000) == 0);
    }
    del_conn(c, &w);

    /* A larger MAX_FRAME_SIZE from the peer is used; the connection window
     * (65535) limits the body until the server opens it. */
    c = new_conn(&r, &w);
    {
        static const uint32_t big[] = { 5, 20000, 4, 100000 };
        (void)feed_settings(c, &w, big, 2);
    }
    from = w.nf;
    (void)ts_h2_request(c, &sid, "POST", "/p", "a", NULL, 0, body, sizeof body);
    take(&w, c);
    n = data_out(&w, from, 1, got, sizeof got, &end, &maxf);
    t_true("connection window limits", n == sizeof body && end && maxf == 20000);
    t_true("body intact", memcmp(got, body, sizeof body) == 0);
    del_conn(c, &w);

    c = new_conn(&r, &w);
    from = w.nf;
    (void)ts_h2_request(c, &sid, "POST", "/p", "a", NULL, 0, body, sizeof body);
    take(&w, c);
    n = data_out(&w, from, 1, got, sizeof got, &end, &maxf);
    t_true("default MAX_FRAME_SIZE", n == sizeof body && maxf == 16384);
    del_conn(c, &w);

    /* Three queued bodies; cancelling the first leaves the others intact. */
    c = new_conn(&r, &w);
    (void)feed_settings(c, &w, small, 1);
    from = w.nf;
    {
        uint32_t s1 = 0, s3 = 0, s5 = 0;
        t_true("three bodies queued", ts_h2_request(c, &s1, "POST", "/1", "a", NULL, 0, body, 4000) == 0 &&
               ts_h2_request(c, &s3, "POST", "/3", "a", NULL, 0, body + 4000, 5000) == 0 &&
               ts_h2_request(c, &s5, "POST", "/5", "a", NULL, 0, body + 9000, 3000) == 0);
        t_true("cancel first", ts_h2_cancel(c, s1) == 0);
        t_true("credit 3", feed_u32(c, &w, H2S_WINDOW, s3, 4000) == 0);
        t_true("credit 5", feed_u32(c, &w, H2S_WINDOW, s5, 2000) == 0);
        n = data_out(&w, from, s3, got, sizeof got, &end, NULL);
        t_true("body 3 intact", n == 5000 && end && memcmp(got, body + 4000, 5000) == 0);
        n = data_out(&w, from, s5, got, sizeof got, &end, NULL);
        t_true("body 5 intact", n == 3000 && end && memcmp(got, body + 9000, 3000) == 0);
        t_true("body area empty", c->body_used == 0);
    }
    del_conn(c, &w);
}

static void test_connection_window_body(void)
{
    static uint8_t body[TS_H2_BODY_MAX], got[TS_H2_BODY_MAX];
    static const uint32_t big[] = { 4, 200000 };
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t sid;
    size_t from, n;
    int end;
    memset(body, 'q', sizeof body);
    (void)feed_settings(c, &w, big, 1);
    from = w.nf;
    (void)ts_h2_request(c, &sid, "POST", "/p", "a", NULL, 0, body, sizeof body);
    take(&w, c);
    t_true("stops at connection window", data_out(&w, from, 1, got, sizeof got, &end, NULL) == 65535 && !end);
    t_true("connection WINDOW_UPDATE", feed_u32(c, &w, H2S_WINDOW, 0, 1) == 0);
    n = data_out(&w, from, 1, got, sizeof got, &end, NULL);
    t_true("rest sent", n == sizeof body && end && memcmp(got, body, n) == 0);
    del_conn(c, &w);
}

static void test_interleave(void)
{
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t a, b;
    (void)ts_h2_request(c, &a, "GET", "/a", "h", NULL, 0, NULL, 0);
    (void)ts_h2_request(c, &b, "GET", "/b", "h", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    t_true("two streams", a == 1 && b == 3);
    t_true("frames", feed_200(c, &w, 1, 0) == 0 && feed_200(c, &w, 3, 0) == 0 &&
           feed_frame(c, &w, H2S_DATA, 0, 3, "b1", 2) == 0 && feed_frame(c, &w, H2S_DATA, 0, 1, "a1", 2) == 0 &&
           feed_frame(c, &w, H2S_DATA, H2S_END_STREAM, 3, "b2", 2) == 0 &&
           feed_frame(c, &w, H2S_DATA, H2S_END_STREAM, 1, "a2", 2) == 0);
    t_true("interleaved callbacks", strcmp(r.log, "H1:200;H3:200;D3:b1;D1:a1;D3:b2;E3:0;D1:a2;E1:0;") == 0);
    del_conn(c, &w);
}

static void test_reset_goaway(void)
{
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t a, b, d;
    uint8_t buf[64];
    size_t from;

    (void)ts_h2_request(c, &a, "GET", "/a", "h", NULL, 0, NULL, 0);
    (void)ts_h2_request(c, &b, "GET", "/b", "h", NULL, 0, NULL, 0);
    (void)ts_h2_request(c, &d, "GET", "/c", "h", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    (void)feed_200(c, &w, 1, 0);
    from = w.nf;
    t_true("RST_STREAM NO_ERROR", feed_u32(c, &w, H2S_RST, 1, 0) == 0);
    t_true("RST_STREAM REFUSED_STREAM", feed_u32(c, &w, H2S_RST, 3, 7) == 0);
    t_true("reset ends with errors", strcmp(r.log, "H1:200;E1:1;E3:2;") == 0);
    t_true("no RST sent back", count(&w, from, H2S_RST, ~0u) == 0);
    t_true("RST on closed stream ignored", feed_u32(c, &w, H2S_RST, 1, 8) == 0);
    t_true("DATA on reset stream ignored", feed_frame(c, &w, H2S_DATA, 0, 1, "late", 4) == 0 && strstr(r.log, "late") == NULL);
    r.n = 0; r.log[0] = 0;
    (void)ts_h2_request(c, &a, "GET", "/d", "h", NULL, 0, NULL, 0);
    t_true("GOAWAY", feed(c, &w, buf, h2s_goaway(buf, 5, 0, "x")) == 0);
    t_true("goaway then refused streams", strcmp(r.log, "G5:0;E7:2;") == 0);
    t_true("no requests after GOAWAY", ts_h2_request(c, &a, "GET", "/e", "h", NULL, 0, NULL, 0) == -1);
    t_true("stream 5 still works", feed_200(c, &w, 5, H2S_END_STREAM) == 0 && strcmp(r.log, "G5:0;E7:2;H5:200;E5:0;") == 0);
    del_conn(c, &w);
}

static void test_cancel(void)
{
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t a, b;
    uint8_t blk[64];
    size_t bl = 0, from;
    uint64_t sent = 0;
    int rc;

    (void)ts_h2_request(c, &a, "GET", "/a", "h", NULL, 0, NULL, 0);
    (void)ts_h2_request(c, &b, "GET", "/b", "h", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    from = w.nf;
    t_true("cancel", ts_h2_cancel(c, a) == 0);
    take(&w, c);
    t_true("RST_STREAM CANCEL sent", count(&w, from, H2S_RST, 1) == 1 &&
           ts_get_be32(w.b + w.f[w.nf - 1].off) == 8);
    t_true("cancel unknown", ts_h2_cancel(c, a) == -1 && ts_h2_cancel(c, 9) == -1);
    /* HPACK stays in sync: the cancelled stream's block adds index 62. */
    blk[bl++] = 0x88;
    blk[bl++] = 0x40; blk[bl++] = 3; memcpy(blk + bl, "x-k", 3); bl += 3; blk[bl++] = 1; blk[bl++] = 'v';
    t_true("HEADERS for cancelled stream", feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS, 1, blk, bl) == 0);
    blk[0] = 0x88; blk[1] = 0xbe;
    t_true("HEADERS using its entry", feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS, 3, blk, 2) == 0);
    t_true("decoded on live stream only", strcmp(r.log, "h3:x-k=v;H3:200;") == 0);
    /* The cancelled stream's DATA is charged and credited back: after nearly a
     * full window on stream 1, stream 3 can still receive more than a window. */
    r.quiet = 1;
    r.consume = 1;
    w.strm[1] = 2 * (int64_t)TS_H2_WINDOW;   /* the server has not seen the RST yet */
    serve(c, &w, 1, TS_H2_WINDOW - 1000, &sent, &rc);
    t_true("cancelled stream's DATA accepted", rc == 0 && sent == TS_H2_WINDOW - 1000 && r.bytes[1] == 0);
    sent = 0;
    serve(c, &w, 3, TS_H2_WINDOW + 50000, &sent, &rc);
    t_true("connection window not leaked", rc == 0 && sent == TS_H2_WINDOW + 50000 && r.bytes[3] == sent && r.ended[3]);
    del_conn(c, &w);
}

/* Unconsumed data on a stream that ends returns to the connection window. */
static void test_end_credits_connection(void)
{
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t a, b;
    uint64_t sent = 0;
    int rc;
    r.quiet = 1;
    (void)ts_h2_request(c, &a, "GET", "/a", "h", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    (void)feed_200(c, &w, 1, 0);
    serve(c, &w, 1, TS_H2_WINDOW - 10, &sent, &rc);
    t_true("stream 1 done unconsumed", rc == 0 && r.ended[1]);
    (void)ts_h2_request(c, &b, "GET", "/b", "h", NULL, 0, NULL, 0);
    take(&w, c);
    scan(&w);
    (void)feed_200(c, &w, 3, 0);
    r.consume = 1;
    sent = 0;
    serve(c, &w, 3, 100000, &sent, &rc);
    t_true("stream 3 not starved", rc == 0 && sent == 100000 && r.ended[3]);
    del_conn(c, &w);
}

static void test_errors(void)
{
    static uint8_t big[16385];
    rec_t r;
    wire_t w;
    ts_h2 *c;
    uint32_t sid;
    uint8_t blk[8];
    size_t at;
    uint64_t sent = 0;
    int rc;

    memset(big, 0, sizeof big);
    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    (void)feed_200(c, &w, 1, 0);
    at = w.nf;
    t_true("frame over MAX_FRAME_SIZE", feed_frame(c, &w, H2S_DATA, 0, 1, big, 16385) == -1);
    t_true("error code FRAME_SIZE_ERROR", ts_h2_error(c) == 6);
    t_true("GOAWAY sent", count(&w, at, H2S_GOAWAY, 0) == 1 && ts_get_be32(w.b + w.f[w.nf - 1].off + 4) == 6);
    t_true("dead after error", ts_h2_feed(c, blk, 0) == -1 && ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0) == -1);
    del_conn(c, &w);

    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    blk[0] = 0x88;
    (void)feed_frame(c, &w, H2S_HEADERS, 0, 1, blk, 1);
    t_true("CONTINUATION on the wrong stream", feed_frame(c, &w, H2S_CONT, H2S_END_HEADERS, 3, blk, 0) == -1);
    t_true("no callbacks", r.n == 0);
    del_conn(c, &w);

    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    (void)feed_frame(c, &w, H2S_HEADERS, 0, 1, blk, 1);
    t_true("other frame inside a header block", feed_settings(c, &w, NULL, 0) == -1);
    del_conn(c, &w);

    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    t_true("CONTINUATION without HEADERS", feed_frame(c, &w, H2S_CONT, H2S_END_HEADERS, 1, blk, 1) == -1);
    del_conn(c, &w);

    /* DATA beyond the window the client advertised. */
    c = new_conn(&r, &w);
    r.quiet = 1;
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    (void)feed_200(c, &w, 1, 0);
    serve(c, &w, 1, TS_H2_WINDOW + 1, &sent, &rc);
    t_true("window filled", rc == 0 && sent == TS_H2_WINDOW);
    t_true("one byte beyond the window", feed_frame(c, &w, H2S_DATA, 0, 1, "x", 1) == -1 && ts_h2_error(c) == 3);
    del_conn(c, &w);

    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    {
        uint8_t pp[8] = { 0, 0, 0, 2, 0x88, 0, 0, 0 };
        t_true("PUSH_PROMISE", feed_frame(c, &w, H2S_PUSH, H2S_END_HEADERS, 1, pp, 5) == -1 && ts_h2_error(c) == 1);
    }
    del_conn(c, &w);

    c = new_conn(&r, &w);
    t_true("first frame must be SETTINGS", feed_u32(c, &w, H2S_WINDOW, 0, 1) == -1);
    del_conn(c, &w);

    c = new_conn(&r, &w);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    t_true("unknown frame type ignored", feed_frame(c, &w, 0x42, 0xff, 1, "abc", 3) == 0);
    {
        static const uint32_t unk[] = { 0x7777, 1, 6, 100 };
        static const uint32_t badmax[] = { 5, 16383 };
        static const uint32_t badwin[] = { 4, 0x80000000u };
        static const uint32_t push[] = { 2, 1 };
        t_true("unknown settings ignored", feed_settings(c, &w, unk, 2) == 0);
        t_true("HEADERS on idle stream", feed_200(c, &w, 5, 0) == -1);
        del_conn(c, &w);
        c = new_conn(&r, &w);
        t_true("MAX_FRAME_SIZE below 16384", feed_settings(c, &w, badmax, 1) == -1);
        del_conn(c, &w);
        c = new_conn(&r, &w);
        t_true("INITIAL_WINDOW_SIZE over 2^31-1", feed_settings(c, &w, badwin, 1) == -1 && ts_h2_error(c) == 3);
        del_conn(c, &w);
        c = new_conn(&r, &w);
        t_true("ENABLE_PUSH 1 from server", feed_settings(c, &w, push, 1) == -1);
        del_conn(c, &w);
    }
    c = new_conn(&r, &w);
    (void)feed_settings(c, &w, NULL, 0);
    t_true("connection window overflow", feed_u32(c, &w, H2S_WINDOW, 0, 0x7fffffffu) == -1 && ts_h2_error(c) == 3);
    del_conn(c, &w);
    c = new_conn(&r, &w);
    (void)feed_settings(c, &w, NULL, 0);
    t_true("zero WINDOW_UPDATE", feed_u32(c, &w, H2S_WINDOW, 0, 0) == -1);
    del_conn(c, &w);
}

/* Header block limits: 128 fields and 65536 decoded bytes. */
static void test_header_limits(void)
{
    static uint8_t blk[16384];
    int pass;
    for (pass = 0; pass < 2; pass++) {
        rec_t r;
        wire_t w;
        ts_h2 *c = new_conn(&r, &w);
        uint32_t sid;
        size_t bl = 0, i;
        (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
        (void)feed_settings(c, &w, NULL, 0);
        blk[bl++] = 0x88;
        for (i = 0; i < (size_t)TS_H2_HDR_FIELDS_MAX - 1 + pass; i++)
            bl += ts_hpack_encode(blk + bl, sizeof blk - bl, "x", "y");
        t_true(pass ? "129 fields fail" : "128 fields pass",
               feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS, 1, blk, bl) == (pass ? -1 : 0));
        del_conn(c, &w);
    }
    for (pass = 0; pass < 2; pass++) {
        static char v[4001];
        rec_t r;
        wire_t w;
        ts_h2 *c = new_conn(&r, &w);
        uint32_t sid;
        size_t bl = 0, i;
        memset(v, 'v', 4000);
        v[4000] = 0;
        (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
        (void)feed_settings(c, &w, NULL, 0);
        /* :status 200 (10 bytes), a: <4000> indexed (4001 bytes) and then 15
         * more references to it: 10 + 16 * 4001 = 64026. A last literal brings
         * the total to 65536, or 65537. */
        blk[bl++] = 0x88;
        blk[bl++] = 0x40; blk[bl++] = 1; blk[bl++] = 'a';
        blk[bl++] = 0x7f; blk[bl++] = (uint8_t)(0x80 | ((4000 - 127) & 0x7f)); blk[bl++] = (uint8_t)((4000 - 127) >> 7);
        memcpy(blk + bl, v, 4000); bl += 4000;
        for (i = 0; i < 15; i++) blk[bl++] = 0xbe;
        v[1509 + pass] = 0;
        bl += ts_hpack_encode(blk + bl, sizeof blk - bl, "b", v);
        t_true(pass ? "65537 decoded bytes fail" : "65536 decoded bytes pass",
               feed_frame(c, &w, H2S_HEADERS, H2S_END_HEADERS, 1, blk, bl) == (pass ? -1 : 0));
        if (!pass) t_true("fields delivered", strstr(r.log, "H1:200;") != NULL);
        del_conn(c, &w);
    }
}

/* The recorded stream fed whole and one byte at a time. */
static void test_split(void)
{
    static uint8_t s[1024];
    size_t n = h2s_recorded(s), i;
    rec_t r1, r2;
    wire_t w1, w2;
    ts_h2 *c1 = new_conn(&r1, &w1), *c2 = new_conn(&r2, &w2);
    uint32_t a, b;
    int rc1, rc2 = 0;

    h2s_open_two(c1, &a, &b);
    t_true("recorded setup", a == 1 && b == 3);
    h2s_open_two(c2, &a, &b);
    rc1 = feed(c1, &w1, s, n);
    for (i = 0; i < n && rc2 == 0; i++) rc2 = feed(c2, &w2, s + i, 1);
    t_true("whole feed ok", rc1 == 0);
    t_true("byte feed ok", rc2 == 0);
    t_true("recorded callbacks", strcmp(r1.log, H2S_RECORDED_LOG) == 0);
    t_true("split callbacks identical", strcmp(r1.log, r2.log) == 0);
    t_true("split output identical", w1.n == w2.n && memcmp(w1.b, w2.b, w1.n) == 0);
    {
        uint8_t got[H2S_BODY1_LEN + 10];
        int end;
        t_true("body of stream 1 sent", data_out(&w1, 0, 1, got, sizeof got, &end, NULL) == H2S_BODY1_LEN && end);
    }
    del_conn(c1, &w1);
    del_conn(c2, &w2);
}

/* A request made from inside a callback, and cancel from the data callback. */
static ts_h2 *g_reent;
static uint32_t g_new_sid;
static void on_end_reenter(void *u, uint32_t sid, int error)
{
    on_end(u, sid, error);
    if (sid == 1) (void)ts_h2_request(g_reent, &g_new_sid, "GET", "/again", "h", NULL, 0, NULL, 0);
}
static void on_data_cancel(void *u, uint32_t sid, const uint8_t *d, size_t n)
{
    on_data(u, sid, d, n);
    (void)ts_h2_cancel(g_reent, sid);
}

static void test_reentrant(void)
{
    static const ts_h2_cbs cbs = { on_headers, on_header, on_data_cancel, on_end_reenter, on_goaway };
    rec_t r;
    wire_t w;
    ts_h2 *c = (ts_h2 *)malloc(sizeof *c);
    uint32_t sid;
    memset(&r, 0, sizeof r);
    r.c = c;
    g_reent = c;
    ts_h2_init(c, &cbs, &r);
    wire_init(&w);
    take(&w, c);
    (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
    (void)feed_settings(c, &w, NULL, 0);
    (void)feed_200(c, &w, 1, 0);
    t_true("cancel in data callback, END_STREAM ignored",
           feed_frame(c, &w, H2S_DATA, H2S_END_STREAM, 1, "x", 1) == 0 && strcmp(r.log, "H1:200;D1:x;") == 0);
    t_true("later frames for the cancelled stream ignored",
           feed_frame(c, &w, H2S_DATA, 0, 1, "y", 1) == 0 && strcmp(r.log, "H1:200;D1:x;") == 0);
    del_conn(c, &w);

    {
        static const ts_h2_cbs cbs2 = { on_headers, on_header, on_data, on_end_reenter, on_goaway };
        c = (ts_h2 *)malloc(sizeof *c);
        memset(&r, 0, sizeof r);
        g_reent = c;
        g_new_sid = 0;
        ts_h2_init(c, &cbs2, &r);
        wire_init(&w);
        take(&w, c);
        (void)ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0);
        (void)feed_settings(c, &w, NULL, 0);
        t_true("end then new request", feed_200(c, &w, 1, H2S_END_STREAM) == 0 && g_new_sid == 3 &&
               count(&w, 0, H2S_HEADERS, 3) == 1);
        del_conn(c, &w);
    }
}

static void test_request_limits(void)
{
    static uint8_t body[TS_H2_BODY_MAX + 1];
    static char longv[TS_H2_REQ_HDR_MAX];
    const char *hdrs[2];
    rec_t r;
    wire_t w;
    ts_h2 *c = new_conn(&r, &w);
    uint32_t sid = 77;
    int i;
    size_t at;
    t_true("body over limit", ts_h2_request(c, &sid, "POST", "/", "a", NULL, 0, body, sizeof body) == -1 && sid == 77);
    memset(longv, 'v', sizeof longv - 1);
    longv[sizeof longv - 1] = 0;
    hdrs[0] = "x"; hdrs[1] = longv;
    at = w.n;
    take(&w, c);
    t_true("header block over limit", ts_h2_request(c, &sid, "GET", "/", "a", hdrs, 1, NULL, 0) == -1);
    take(&w, c);
    t_true("failed requests emit nothing", w.n == at);
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        t_true("open stream", ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0) == 0);
    t_true("stream limit", ts_h2_request(c, &sid, "GET", "/", "a", NULL, 0, NULL, 0) == -1);
    t_true("failures consumed no stream ids", sid == 2 * TS_H2_MAX_STREAMS - 1);
    del_conn(c, &w);
}

void test_h2(void)
{
    test_preface();
    test_settings_ping();
    test_simple_response();
    test_continuation_padding();
    test_informational_trailers();
    test_receive_window();
    test_request_body();
    test_connection_window_body();
    test_interleave();
    test_reset_goaway();
    test_cancel();
    test_end_credits_connection();
    test_errors();
    test_header_limits();
    test_split();
    test_reentrant();
    test_request_limits();
}
