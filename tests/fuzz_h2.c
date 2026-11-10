#include "fuzz.h"

#include <stdlib.h>
#include <string.h>

#include "h2_script.inc"

/* Input: one mode byte, then server bytes. The client has opened stream 1 (a
 * POST with a body) and stream 3 before the server bytes arrive.
 *
 * Mode bits: 1 consume data in the data callback, 2 cancel a stream from the
 * data callback, 4 open a new request from the end callback, 8 queue a PING
 * first, 16 receive SETTINGS with a 100-byte INITIAL_WINDOW_SIZE before the
 * streams open, so stream 1's body is queued and waits for credit.
 *
 * The same input goes to two connections, one fed whole and one in small
 * pieces; both must give the same result, callbacks and output. */

#define MAX_SID 64

typedef struct {
    ts_h2 *c;
    unsigned mode;
    uint64_t hash;           /* callbacks */
    uint64_t ohash;          /* output bytes */
    size_t out_total;
    int dead;                /* feed returned -1: no callback may follow */
    uint8_t live[MAX_SID];   /* opened and not ended or cancelled */
    uint8_t final[MAX_SID];  /* headers callback seen */
    unsigned events;
} fz_t;

static void mix(uint64_t *h, uint64_t v) { *h = (*h ^ v) * 1099511628211ull; }

static void mix_bytes(uint64_t *h, const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < n; i++) mix(h, b[i]);
}

static int is_live(const fz_t *f, uint32_t sid) { return sid < MAX_SID && f->live[sid]; }

static void open_req(fz_t *f)
{
    uint32_t sid = 0;
    if (ts_h2_request(f->c, &sid, "GET", "/again", "h", NULL, 0, NULL, 0) == 0) {
        TS_FUZZ_ASSERT(sid & 1);
        if (sid < MAX_SID) f->live[sid] = 1;
        else (void)ts_h2_cancel(f->c, sid);   /* keep the bookkeeping small */
    }
}

static void cb_headers(void *u, uint32_t sid, int status)
{
    fz_t *f = (fz_t *)u;
    TS_FUZZ_ASSERT(!f->dead && is_live(f, sid) && !f->final[sid]);
    TS_FUZZ_ASSERT(status >= 200 && status <= 599);
    f->final[sid] = 1;
    f->events++;
    mix(&f->hash, 'H'); mix(&f->hash, sid); mix(&f->hash, (uint64_t)status);
}

static void cb_header(void *u, uint32_t sid, const char *n, size_t nl, const char *v, size_t vl)
{
    fz_t *f = (fz_t *)u;
    TS_FUZZ_ASSERT(!f->dead && is_live(f, sid));
    TS_FUZZ_ASSERT(nl <= TS_HPACK_FIELD_MAX && vl <= TS_HPACK_FIELD_MAX);
    TS_FUZZ_ASSERT(nl == 0 || n[0] != ':');
    f->events++;
    mix(&f->hash, 'h'); mix(&f->hash, sid); mix(&f->hash, nl); mix(&f->hash, vl);
    mix_bytes(&f->hash, n, nl);
    mix_bytes(&f->hash, v, vl);
}

static void cb_data(void *u, uint32_t sid, const uint8_t *d, size_t n)
{
    fz_t *f = (fz_t *)u;
    TS_FUZZ_ASSERT(!f->dead && is_live(f, sid) && f->final[sid]);
    TS_FUZZ_ASSERT(n > 0 && n <= TS_H2_FRAME_MAX);
    f->events++;
    mix(&f->hash, 'D'); mix(&f->hash, sid); mix(&f->hash, n);
    mix_bytes(&f->hash, d, n);
    if (f->mode & 1) {
        TS_FUZZ_ASSERT(ts_h2_consume_data(f->c, sid, n) == 0);
        TS_FUZZ_ASSERT(ts_h2_consume_data(f->c, sid, 1) == -1);   /* nothing more is held */
    }
    if ((f->mode & 2) && (f->hash & 3) == 0) {
        TS_FUZZ_ASSERT(ts_h2_cancel(f->c, sid) == 0);
        f->live[sid] = 0;
        mix(&f->hash, 'C');
    }
}

static void cb_end(void *u, uint32_t sid, int error)
{
    fz_t *f = (fz_t *)u;
    TS_FUZZ_ASSERT(!f->dead && is_live(f, sid));
    TS_FUZZ_ASSERT(error == TS_H2_END_OK || error == TS_H2_END_RESET || error == TS_H2_END_REFUSED);
    TS_FUZZ_ASSERT(error != TS_H2_END_OK || f->final[sid]);
    f->live[sid] = 0;
    f->events++;
    mix(&f->hash, 'E'); mix(&f->hash, sid); mix(&f->hash, (uint64_t)error);
    if ((f->mode & 4) && f->events < 64) open_req(f);
}

static void cb_goaway(void *u, uint32_t last, uint32_t code)
{
    fz_t *f = (fz_t *)u;
    TS_FUZZ_ASSERT(!f->dead);
    TS_FUZZ_ASSERT(last <= 0x7fffffffu);
    f->events++;
    mix(&f->hash, 'G'); mix(&f->hash, last); mix(&f->hash, code);
}

static const ts_h2_cbs FZ_CBS = { cb_headers, cb_header, cb_data, cb_end, cb_goaway };

/* Accounting that must hold after every call. */
static void check(const fz_t *f)
{
    const ts_h2 *c = f->c;
    int64_t held = 0;
    size_t body = 0;
    unsigned i;
    TS_FUZZ_ASSERT(c->out_len <= TS_H2_OUT_MAX && c->out_off + c->out_len <= TS_H2_OUT_MAX);
    TS_FUZZ_ASSERT(c->conn_recv >= 0 && c->conn_send <= 0x7fffffffLL);
    TS_FUZZ_ASSERT(c->body_used <= TS_H2_BODY_MAX);
    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        const ts_h2_stream *s = &c->st[i];
        if (s->id == 0) continue;
        TS_FUZZ_ASSERT(is_live(f, s->id));
        TS_FUZZ_ASSERT(s->recv_win >= 0 && s->send_win <= 0x7fffffffLL);
        TS_FUZZ_ASSERT(s->recv_win + s->credit + s->held == (int64_t)TS_H2_WINDOW);
        TS_FUZZ_ASSERT(s->body_sent <= s->body_len);
        TS_FUZZ_ASSERT((size_t)s->body_off + s->body_len <= c->body_used);
        held += s->held;
        body += s->body_len;
    }
    TS_FUZZ_ASSERT(body == c->body_used);
    /* Every byte of the connection window is either still open to the server,
     * owed back to it, or held by the caller. */
    TS_FUZZ_ASSERT(c->conn_recv + c->conn_credit + held == (int64_t)TS_H2_WINDOW);
    /* Every stream the caller thinks is open is open. */
    for (i = 0; i < MAX_SID; i++) {
        unsigned k, found = 0;
        if (!f->live[i]) continue;
        for (k = 0; k < TS_H2_MAX_STREAMS; k++) found += c->st[k].id == i;
        TS_FUZZ_ASSERT(found == 1);
    }
}

/* Drain output: whole frames only, each no longer than the server allows, and
 * DATA, HEADERS and RST_STREAM only on streams the client opened. */
static void drain(fz_t *f)
{
    const uint8_t *o;
    size_t n = ts_h2_output(f->c, &o), at = 0;
    if (n == 0) return;
    if (f->out_total == 0) {
        TS_FUZZ_ASSERT(n >= 24 && memcmp(o, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
        at = 24;
    }
    while (at < n) {
        size_t len;
        uint32_t sid;
        unsigned type;
        TS_FUZZ_ASSERT(n - at >= 9);
        len = ts_get_be32(o + at) >> 8;
        type = o[at + 3];
        sid = ts_get_be32(o + at + 5);
        TS_FUZZ_ASSERT(len <= f->c->peer_max_frame && n - at - 9 >= len);
        if (type == H2S_DATA || type == H2S_HEADERS || type == H2S_RST)
            TS_FUZZ_ASSERT(sid & 1);
        if (type == H2S_DATA) TS_FUZZ_ASSERT(len <= H2S_BODY1_LEN);
        at += 9 + len;
    }
    mix_bytes(&f->ohash, o, n);
    f->out_total += n;
    ts_h2_consumed(f->c, n);
}

static void start(fz_t *f, ts_h2 *c, unsigned mode)
{
    uint32_t a, b;
    memset(f, 0, sizeof *f);
    f->c = c;
    f->mode = mode;
    f->hash = f->ohash = 14695981039346656037ull;
    ts_h2_init(c, &FZ_CBS, f);
    if (mode & 16) {
        static const uint32_t set[] = { 4, 100 };
        uint8_t pre[32];
        TS_FUZZ_ASSERT(ts_h2_feed(c, pre, h2s_settings(pre, set, 1)) == 0);
    }
    h2s_open_two(c, &a, &b);
    TS_FUZZ_ASSERT(a == 1 && b == 3);
    f->live[1] = f->live[3] = 1;
    if (mode & 8) ts_h2_ping(c);
    check(f);
}

static int feed(fz_t *f, const uint8_t *in, size_t n)
{
    int rc = ts_h2_feed(f->c, in, n);
    TS_FUZZ_ASSERT(rc == 0 || rc == -1);
    if (rc) {
        TS_FUZZ_ASSERT(f->c->dead && ts_h2_error(f->c) != TS_H2_NO_ERROR);
        f->dead = 1;
    }
    check(f);
    drain(f);
    check(f);
    return rc;
}

static void target(const uint8_t *data, size_t len)
{
    static ts_h2 ca, cb;
    fz_t fa, fb;
    unsigned mode;
    int ra, rb = 0;
    size_t at;
    uint64_t rs;

    if (len == 0) return;
    mode = data[0];
    data++;
    len--;

    start(&fa, &ca, mode);
    start(&fb, &cb, mode);
    ra = feed(&fa, data, len);

    rs = 0x9e3779b97f4a7c15ull ^ len;
    for (at = 0; at < len && rb == 0;) {
        size_t k;
        rs = rs * 6364136223846793005ull + 1442695040888963407ull;
        k = 1 + (size_t)((rs >> 33) % 17);
        if (k > len - at) k = len - at;
        rb = feed(&fb, data + at, k);
        at += k;
    }
    if (rb == 0) rb = feed(&fb, data, 0);

    TS_FUZZ_ASSERT(ra == rb);
    TS_FUZZ_ASSERT(fa.hash == fb.hash && fa.events == fb.events);
    TS_FUZZ_ASSERT(fa.ohash == fb.ohash && fa.out_total == fb.out_total);
    TS_FUZZ_ASSERT(ts_h2_error(&ca) == ts_h2_error(&cb));

    /* A dead connection stays dead and silent. */
    if (ra) {
        uint32_t sid = 0;
        TS_FUZZ_ASSERT(ts_h2_feed(&ca, data, len) == -1);
        TS_FUZZ_ASSERT(ts_h2_request(&ca, &sid, "GET", "/", "h", NULL, 0, NULL, 0) == -1);
    }
    ts_h2_free(&ca);
    ts_h2_free(&cb);
}

/* ---- Seeds ------------------------------------------------------------- */

static size_t s_settings_plain(uint8_t *o)
{
    return h2s_settings(o, NULL, 0);
}

static size_t s_simple(uint8_t *o)
{
    static const uint8_t s200 = 0x88;
    size_t n = s_settings_plain(o);
    n += h2s_frame(o + n, H2S_HEADERS, H2S_END_HEADERS, 3, &s200, 1);
    n += h2s_frame(o + n, H2S_DATA, H2S_END_STREAM, 3, "hello", 5);
    n += h2s_u32(o + n, H2S_RST, 1, 7);
    return n;
}

static size_t s_info_trailers(uint8_t *o)
{
    uint8_t blk[64];
    size_t n = s_settings_plain(o), bl;
    bl = ts_hpack_encode(blk, sizeof blk, ":status", "103");
    bl += ts_hpack_encode(blk + bl, sizeof blk - bl, "link", "</a>");
    n += h2s_frame(o + n, H2S_HEADERS, 0, 1, blk, 4);
    n += h2s_frame(o + n, H2S_CONT, H2S_END_HEADERS, 1, blk + 4, bl - 4);
    blk[0] = 0x8d;   /* :status 404 */
    n += h2s_frame(o + n, H2S_HEADERS, H2S_END_HEADERS, 1, blk, 1);
    n += h2s_frame(o + n, H2S_DATA, 0, 1, "nf", 2);
    bl = ts_hpack_encode(blk, sizeof blk, "grpc-status", "0");
    n += h2s_frame(o + n, H2S_HEADERS, H2S_END_HEADERS | H2S_END_STREAM, 1, blk, bl);
    n += h2s_goaway(o + n, 1, 2, "");
    return n;
}

/* Header amplification up to the decoded-bytes limit. */
static size_t s_amplify(uint8_t *o, int over)
{
    static uint8_t blk[4200];
    size_t n = s_settings_plain(o), bl = 0, i;
    blk[bl++] = 0x88;
    blk[bl++] = 0x40; blk[bl++] = 1; blk[bl++] = 'a';
    blk[bl++] = 0x7f; blk[bl++] = (uint8_t)(0x80 | ((4000 - 127) & 0x7f)); blk[bl++] = (uint8_t)((4000 - 127) >> 7);
    memset(blk + bl, 'v', 4000); bl += 4000;
    for (i = 0; i < 15u + (unsigned)over; i++) blk[bl++] = 0xbe;
    n += h2s_frame(o + n, H2S_HEADERS, H2S_END_HEADERS, 3, blk, bl);
    n += h2s_frame(o + n, H2S_DATA, H2S_END_STREAM, 3, "x", 1);
    return n;
}

static size_t s_windows(uint8_t *o)
{
    static const uint32_t set[] = { 4, 100, 5, 20000, 3, 2 };
    static const uint32_t set2[] = { 4, 3000 };
    static const uint8_t s200 = 0x88;
    uint8_t pad[32];
    size_t n = h2s_settings(o, set, 3);
    n += h2s_u32(o + n, H2S_WINDOW, 1, 50);
    n += h2s_settings(o + n, set2, 1);
    n += h2s_u32(o + n, H2S_WINDOW, 0, 70000);
    n += h2s_frame(o + n, H2S_HEADERS, H2S_END_HEADERS, 1, &s200, 1);
    pad[0] = 20; memset(pad + 1, 'p', 31);
    n += h2s_frame(o + n, H2S_DATA, H2S_PADDED, 1, pad, 32);
    n += h2s_frame(o + n, H2S_PRIORITY, 0, 3, "\0\0\0\1\x10", 5);
    n += h2s_frame(o + n, H2S_PING, H2S_ACK, 0, "tspp\0\0\0\1", 8);
    n += h2s_frame(o + n, H2S_DATA, H2S_END_STREAM, 1, "end", 3);
    n += h2s_u32(o + n, H2S_RST, 3, 2);
    return n;
}

void ts_fuzz_h2(void)
{
    enum { NSEED = 12 };
    static uint8_t buf[NSEED][8192];
    const uint8_t *seeds[NSEED];
    size_t lens[NSEED], i;
    static const uint8_t modes[] = { 0, 1, 3, 5, 17, 9, 7, 1, 1, 0, 22, 17 };

    lens[0] = 1 + h2s_recorded(buf[0] + 1);
    lens[1] = 1 + h2s_recorded(buf[1] + 1);
    lens[2] = 1 + h2s_recorded(buf[2] + 1);
    lens[3] = 1 + s_simple(buf[3] + 1);
    lens[4] = 1 + h2s_recorded(buf[4] + 1);
    lens[5] = 1 + s_info_trailers(buf[5] + 1);
    lens[6] = 1 + s_windows(buf[6] + 1);
    lens[7] = 1 + s_amplify(buf[7] + 1, 0);
    lens[8] = 1 + s_amplify(buf[8] + 1, 1);
    lens[9] = 1 + s_settings_plain(buf[9] + 1);
    lens[10] = 1 + s_info_trailers(buf[10] + 1);
    lens[11] = 1 + s_windows(buf[11] + 1);
    for (i = 0; i < NSEED; i++) {
        buf[i][0] = modes[i];
        seeds[i] = buf[i];
    }
    ts_fuzz_run("h2", target, seeds, lens, NSEED, TS_FUZZ_DEFAULT_ITERS);
}
