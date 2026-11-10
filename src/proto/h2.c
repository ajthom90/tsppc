#include "h2.h"

#include "../core/bytes.h"

#include <stdlib.h>
#include <string.h>

enum {
    F_DATA = 0x0, F_HEADERS = 0x1, F_PRIORITY = 0x2, F_RST_STREAM = 0x3, F_SETTINGS = 0x4,
    F_PUSH_PROMISE = 0x5, F_PING = 0x6, F_GOAWAY = 0x7, F_WINDOW_UPDATE = 0x8, F_CONTINUATION = 0x9
};
enum { FL_END_STREAM = 0x1, FL_ACK = 0x1, FL_END_HEADERS = 0x4, FL_PADDED = 0x8, FL_PRIORITY = 0x20 };
enum {
    S_HEADER_TABLE_SIZE = 1, S_ENABLE_PUSH = 2, S_MAX_CONCURRENT_STREAMS = 3,
    S_INITIAL_WINDOW_SIZE = 4, S_MAX_FRAME_SIZE = 5
};

#define DEFAULT_WINDOW 65535
#define WINDOW_LIMIT 0x7fffffffLL           /* 2^31 - 1 */
#define FRAME_SIZE_LIMIT 16777215u
#define CREDIT_THRESHOLD (TS_H2_WINDOW / 4)  /* send WINDOW_UPDATE once this much is owed */
#define OUT_RESERVE 4096                    /* output kept free of DATA for control frames */
#define NAME_MAX_LEN 255                    /* request header name, before lowercasing */

static const char PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define PREFACE_LEN 24
static const ts_h2_cbs NO_CBS = { NULL, NULL, NULL, NULL, NULL };

/* ---- Output queue ------------------------------------------------------ */

static uint8_t *out_reserve(ts_h2 *c, size_t need)
{
    uint8_t *p;
    if (c->mem == NULL || need > TS_H2_OUT_MAX - c->out_len) return NULL;
    if (need > TS_H2_OUT_MAX - c->out_off - c->out_len) {
        memmove(c->mem, c->mem + c->out_off, c->out_len);
        c->out_off = 0;
    }
    p = c->mem + c->out_off + c->out_len;
    c->out_len += need;
    return p;
}

static void put_frame_header(uint8_t *p, size_t len, unsigned type, unsigned flags, uint32_t sid)
{
    uint8_t l[4];
    ts_put_be32(l, (uint32_t)len);
    p[0] = l[1];
    p[1] = l[2];
    p[2] = l[3];
    p[3] = (uint8_t)type;
    p[4] = (uint8_t)flags;
    ts_put_be32(p + 5, sid);
}

static int emit(ts_h2 *c, unsigned type, unsigned flags, uint32_t sid, const uint8_t *payload, size_t len)
{
    uint8_t *p = out_reserve(c, 9 + len);
    if (p == NULL) return -1;
    put_frame_header(p, len, type, flags, sid);
    if (len) memcpy(p + 9, payload, len);
    return 0;
}

static int emit_u32(ts_h2 *c, unsigned type, uint32_t sid, uint32_t v)
{
    uint8_t b[4];
    ts_put_be32(b, v);
    return emit(c, type, 0, sid, b, 4);
}

/* Kill the connection: queue GOAWAY if there is room. Always returns -1. */
static int fail(ts_h2 *c, uint32_t code)
{
    if (!c->dead) {
        uint8_t b[8];
        c->dead = 1;
        c->err = code;
        ts_put_be32(b, 0);       /* the server opened no streams */
        ts_put_be32(b + 4, code);
        (void)emit(c, F_GOAWAY, 0, 0, b, 8);
    }
    return -1;
}

/* ---- Streams ----------------------------------------------------------- */

static ts_h2_stream *find(ts_h2 *c, uint32_t sid)
{
    unsigned i;
    if (sid == 0) return NULL;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        if (c->st[i].id == sid) return &c->st[i];
    return NULL;
}

/* A stream id the client has not opened (or an even, server-initiated one). */
static int idle(const ts_h2 *c, uint32_t sid)
{
    return (sid & 1) == 0 || sid >= c->next_id;
}

static uint8_t *body_area(ts_h2 *c) { return c->mem + TS_H2_OUT_MAX; }

/* Remove a stream's body from the body area, closing the gap. */
static void body_drop(ts_h2 *c, ts_h2_stream *s)
{
    unsigned i;
    uint32_t off = s->body_off, len = s->body_len;
    if (len == 0) return;
    memmove(body_area(c) + off, body_area(c) + off + len, c->body_used - off - len);
    c->body_used -= len;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        if (c->st[i].id && c->st[i].body_len && c->st[i].body_off > off) c->st[i].body_off -= len;
    s->body_off = s->body_len = s->body_sent = 0;
}

/* Free the slot. Data the caller still holds is credited to the connection. */
static void release(ts_h2 *c, ts_h2_stream *s)
{
    c->conn_credit += s->held;
    body_drop(c, s);
    memset(s, 0, sizeof *s);
}

static void flush_credit(ts_h2 *c)
{
    unsigned i;
    if (c->dead) return;
    if (c->conn_credit >= CREDIT_THRESHOLD && emit_u32(c, F_WINDOW_UPDATE, 0, c->conn_credit) == 0) {
        c->conn_recv += c->conn_credit;
        c->conn_credit = 0;
    }
    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        ts_h2_stream *s = &c->st[i];
        if (s->id && s->credit >= CREDIT_THRESHOLD && emit_u32(c, F_WINDOW_UPDATE, s->id, s->credit) == 0) {
            s->recv_win += s->credit;
            s->credit = 0;
        }
    }
}

/* Send request body DATA as windows, frame size and queue space allow, one
 * frame per stream per round. */
static void pump(ts_h2 *c)
{
    int progress = 1;
    if (c->dead || c->mem == NULL) return;
    while (progress) {
        unsigned i;
        progress = 0;
        for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
            ts_h2_stream *s = &c->st[i];
            size_t k, room;
            unsigned flags;
            uint8_t *p;
            if (s->id == 0 || s->local_done || s->body_sent >= s->body_len) continue;
            if (c->conn_send <= 0) return;
            if (s->send_win <= 0) continue;
            if (c->out_len + OUT_RESERVE + 9 >= TS_H2_OUT_MAX) return;
            room = TS_H2_OUT_MAX - OUT_RESERVE - 9 - c->out_len;
            k = s->body_len - s->body_sent;
            if (k > c->peer_max_frame) k = c->peer_max_frame;
            if ((int64_t)k > s->send_win) k = (size_t)s->send_win;
            if ((int64_t)k > c->conn_send) k = (size_t)c->conn_send;
            if (k > room) k = room;
            flags = s->body_sent + k == s->body_len ? FL_END_STREAM : 0;
            p = out_reserve(c, 9 + k);
            if (p == NULL) return;
            put_frame_header(p, k, F_DATA, flags, s->id);
            memcpy(p + 9, body_area(c) + s->body_off + s->body_sent, k);
            s->body_sent += (uint32_t)k;
            s->send_win -= (int64_t)k;
            c->conn_send -= (int64_t)k;
            if (flags) {
                s->local_done = 1;
                body_drop(c, s);
            }
            progress = 1;
        }
    }
}

/* The server finished the stream. */
static void remote_end(ts_h2 *c, ts_h2_stream *s)
{
    uint32_t sid = s->id;
    if (!s->local_done) (void)emit_u32(c, F_RST_STREAM, sid, TS_H2_NO_ERROR);
    release(c, s);
    if (c->cbs->end) c->cbs->end(c->user, sid, TS_H2_END_OK);
}

/* ---- Public: setup and output ------------------------------------------ */

void ts_h2_init(ts_h2 *c, const ts_h2_cbs *cbs, void *user)
{
    uint8_t s[12], *p;
    memset(c, 0, sizeof *c);
    c->cbs = cbs ? cbs : &NO_CBS;
    c->user = user;
    c->next_id = 1;
    c->conn_send = DEFAULT_WINDOW;
    c->conn_recv = TS_H2_WINDOW;
    c->peer_init_win = DEFAULT_WINDOW;
    c->peer_max_frame = TS_H2_FRAME_MAX;
    c->peer_max_streams = 0xffffffffu;
    ts_hpack_init(&c->hpack);
    c->mem = (uint8_t *)malloc(TS_H2_OUT_MAX + TS_H2_BODY_MAX);
    if (c->mem == NULL) {
        c->dead = 1;
        c->err = TS_H2_INTERNAL_ERROR;
        return;
    }
    p = out_reserve(c, PREFACE_LEN);
    memcpy(p, PREFACE, PREFACE_LEN);
    ts_put_be16(s, S_ENABLE_PUSH);
    ts_put_be32(s + 2, 0);
    ts_put_be16(s + 6, S_INITIAL_WINDOW_SIZE);
    ts_put_be32(s + 8, TS_H2_WINDOW);
    (void)emit(c, F_SETTINGS, 0, 0, s, sizeof s);
    (void)emit_u32(c, F_WINDOW_UPDATE, 0, TS_H2_WINDOW - DEFAULT_WINDOW);
}

void ts_h2_free(ts_h2 *c)
{
    free(c->mem);
    c->mem = NULL;
    c->out_off = c->out_len = 0;
    c->dead = 1;
}

size_t ts_h2_output(ts_h2 *c, const uint8_t **out)
{
    *out = c->mem ? c->mem + c->out_off : NULL;
    return c->out_len;
}

void ts_h2_consumed(ts_h2 *c, size_t n)
{
    if (n > c->out_len) n = c->out_len;
    c->out_off += n;
    c->out_len -= n;
    if (c->out_len == 0) c->out_off = 0;
    flush_credit(c);
    pump(c);
}

uint32_t ts_h2_error(const ts_h2 *c)
{
    return c->dead ? c->err : TS_H2_NO_ERROR;
}

/* ---- Public: requests -------------------------------------------------- */

static size_t encode(ts_h2 *c, size_t at, const char *name, const char *value)
{
    size_t r;
    if (at >= sizeof c->ebuf) return 0;
    r = ts_hpack_encode(c->ebuf + at, sizeof c->ebuf - at, name, value);
    return r ? at + r : 0;
}

int ts_h2_request(ts_h2 *c, uint32_t *sid, const char *method, const char *path,
                  const char *authority, const char *const *headers, size_t nheaders,
                  const uint8_t *body, size_t bodylen)
{
    ts_h2_stream *s = NULL;
    unsigned i, open = 0;
    size_t bl = 0, h;

    if (c->dead || c->goaway || c->mem == NULL || !method || !path || !authority) return -1;
    if (c->next_id > 0x7fffffffu) return -1;
    if (bodylen && body == NULL) return -1;
    for (i = 0; i < TS_H2_MAX_STREAMS; i++) {
        if (c->st[i].id) open++;
        else if (s == NULL) s = &c->st[i];
    }
    if (s == NULL || open >= c->peer_max_streams) return -1;
    if (bodylen > TS_H2_BODY_MAX - c->body_used) return -1;

    bl = encode(c, bl, ":method", method);
    if (bl) bl = encode(c, bl, ":scheme", "https");
    if (bl) bl = encode(c, bl, ":path", path);
    if (bl) bl = encode(c, bl, ":authority", authority);
    for (h = 0; bl && h < nheaders; h++) {
        char name[NAME_MAX_LEN + 1];
        const char *n = headers[2 * h], *v = headers[2 * h + 1];
        size_t k, nl;
        if (n == NULL || v == NULL) return -1;
        nl = strlen(n);
        if (nl == 0 || nl > NAME_MAX_LEN || n[0] == ':') return -1;
        for (k = 0; k <= nl; k++) name[k] = (char)(n[k] >= 'A' && n[k] <= 'Z' ? n[k] - 'A' + 'a' : n[k]);
        bl = encode(c, bl, name, v);
    }
    if (bl == 0) return -1;
    /* TS_H2_REQ_HDR_MAX never exceeds the minimum MAX_FRAME_SIZE, so one HEADERS frame. */
    if (9 + bl > TS_H2_OUT_MAX - c->out_len) return -1;

    memset(s, 0, sizeof *s);
    s->id = c->next_id;
    c->next_id += 2;
    s->send_win = c->peer_init_win;
    s->recv_win = TS_H2_WINDOW;
    if (bodylen) {
        s->body_off = (uint32_t)c->body_used;
        s->body_len = (uint32_t)bodylen;
        memcpy(body_area(c) + c->body_used, body, bodylen);
        c->body_used += bodylen;
    } else {
        s->local_done = 1;
    }
    (void)emit(c, F_HEADERS, FL_END_HEADERS | (bodylen ? 0 : FL_END_STREAM), s->id, c->ebuf, bl);
    *sid = s->id;
    pump(c);
    return 0;
}

int ts_h2_cancel(ts_h2 *c, uint32_t sid)
{
    ts_h2_stream *s = find(c, sid);
    if (s == NULL) return -1;
    if (!c->dead) (void)emit_u32(c, F_RST_STREAM, sid, TS_H2_CANCEL);
    release(c, s);
    flush_credit(c);
    return 0;
}

int ts_h2_consume_data(ts_h2 *c, uint32_t sid, size_t n)
{
    ts_h2_stream *s = find(c, sid);
    if (s == NULL) return 0;
    if (n > s->held) return -1;
    s->held -= (uint32_t)n;
    s->credit += (uint32_t)n;
    c->conn_credit += (uint32_t)n;
    flush_credit(c);
    return 0;
}

void ts_h2_ping(ts_h2 *c)
{
    uint8_t b[8];
    if (c->dead) return;
    c->ping_seq++;
    ts_put_be32(b, 0x74737070u);   /* "tspp" */
    ts_put_be32(b + 4, c->ping_seq);
    (void)emit(c, F_PING, 0, 0, b, 8);
}

/* ---- Header blocks ----------------------------------------------------- */

static void on_field(void *user, const char *name, size_t nl, const char *value, size_t vl)
{
    ts_h2 *c = (ts_h2 *)user;
    if (c->dec_bad) return;
    c->dec_fields++;
    c->dec_bytes += (uint32_t)(nl + vl);
    if (c->dec_fields > TS_H2_HDR_FIELDS_MAX || c->dec_bytes > TS_H2_HDR_BYTES_MAX) {
        c->dec_bad = TS_H2_ENHANCE_YOUR_CALM;
        return;
    }
    if (c->dec_sid == 0) return;    /* stream gone: decode for the table only */
    if (nl > 0 && name[0] == ':') {
        int st;
        if (c->dec_trailers || c->dec_regular || c->dec_status >= 0 ||
            nl != 7 || memcmp(name, ":status", 7) != 0 || vl != 3 ||
            value[0] < '1' || value[0] > '5' || value[1] < '0' || value[1] > '9' ||
            value[2] < '0' || value[2] > '9') {
            c->dec_bad = TS_H2_PROTOCOL_ERROR;
            return;
        }
        st = (value[0] - '0') * 100 + (value[1] - '0') * 10 + (value[2] - '0');
        if (st == 101) {            /* no Upgrade in HTTP/2 */
            c->dec_bad = TS_H2_PROTOCOL_ERROR;
            return;
        }
        c->dec_status = st;
        return;
    }
    if (!c->dec_trailers && c->dec_status < 0) {
        c->dec_bad = TS_H2_PROTOCOL_ERROR;   /* a response must start with :status */
        return;
    }
    c->dec_regular = 1;
    if (!c->dec_trailers && c->dec_status < 200) return;   /* informational: dropped */
    if (c->cbs->header) {
        c->cbs->header(c->user, c->dec_sid, name, nl, value, vl);
        if (find(c, c->dec_sid) == NULL) c->dec_sid = 0;   /* cancelled in the callback */
    }
}

static int finish_block(ts_h2 *c)
{
    uint32_t sid = c->hb_sid;
    int end_stream = c->hb_end_stream;
    ts_h2_stream *s = find(c, sid);

    c->hb_sid = 0;
    c->dec_sid = s ? sid : 0;
    c->dec_trailers = s ? s->got_final : 0;
    c->dec_status = -1;
    c->dec_regular = 0;
    c->dec_bad = 0;
    c->dec_fields = 0;
    c->dec_bytes = 0;
    if (ts_hpack_decode(&c->hpack, c->hblock, c->hb_len, on_field, c) != 0)
        return fail(c, TS_H2_COMPRESSION_ERROR);
    if (c->dec_bad) return fail(c, (uint32_t)c->dec_bad);
    s = c->dec_sid ? find(c, sid) : NULL;
    if (s == NULL) return 0;
    if (c->dec_trailers) {
        if (!end_stream) return fail(c, TS_H2_PROTOCOL_ERROR);
        remote_end(c, s);
        return 0;
    }
    if (c->dec_status < 0) return fail(c, TS_H2_PROTOCOL_ERROR);
    if (c->dec_status < 200) {
        if (end_stream) return fail(c, TS_H2_PROTOCOL_ERROR);
        return 0;
    }
    s->got_final = 1;
    if (c->cbs->headers) c->cbs->headers(c->user, sid, c->dec_status);
    if (end_stream && (s = find(c, sid)) != NULL) remote_end(c, s);
    return 0;
}

static int add_fragment(ts_h2 *c, const uint8_t *p, size_t n)
{
    if (n > TS_H2_HBLOCK_MAX - c->hb_len) return fail(c, TS_H2_ENHANCE_YOUR_CALM);
    memcpy(c->hblock + c->hb_len, p, n);
    c->hb_len += n;
    return 0;
}

/* ---- Frames ------------------------------------------------------------ */

static int on_data(ts_h2 *c, unsigned flags, uint32_t sid, const uint8_t *p, size_t len)
{
    ts_h2_stream *s;
    size_t dlen = len;
    const uint8_t *d = p;

    if (sid == 0 || idle(c, sid)) return fail(c, TS_H2_PROTOCOL_ERROR);
    if (flags & FL_PADDED) {
        if (len < 1 || p[0] > len - 1) return fail(c, TS_H2_PROTOCOL_ERROR);
        d = p + 1;
        dlen = len - 1 - p[0];
    }
    /* The whole payload, padding included, counts against the windows. */
    s = find(c, sid);
    if ((int64_t)len > c->conn_recv || (s && (int64_t)len > s->recv_win))
        return fail(c, TS_H2_FLOW_CONTROL_ERROR);
    if (s && !s->got_final) return fail(c, TS_H2_PROTOCOL_ERROR);
    c->conn_recv -= (int64_t)len;
    if (s == NULL) {                 /* closed or cancelled: charge and credit back */
        c->conn_credit += (uint32_t)len;
        return 0;
    }
    s->recv_win -= (int64_t)len;
    s->credit += (uint32_t)(len - dlen);
    c->conn_credit += (uint32_t)(len - dlen);
    s->held += (uint32_t)dlen;
    if (dlen && c->cbs->data) c->cbs->data(c->user, sid, d, dlen);
    if ((flags & FL_END_STREAM) && (s = find(c, sid)) != NULL) remote_end(c, s);
    return 0;
}

static int on_headers(ts_h2 *c, unsigned flags, uint32_t sid, const uint8_t *p, size_t len)
{
    size_t skip = 0, pad = 0;
    if (sid == 0 || idle(c, sid)) return fail(c, TS_H2_PROTOCOL_ERROR);
    if (flags & FL_PADDED) {
        if (len < 1) return fail(c, TS_H2_PROTOCOL_ERROR);
        pad = p[0];
        skip = 1;
    }
    if (flags & FL_PRIORITY) skip += 5;
    if (skip > len || pad > len - skip) return fail(c, TS_H2_PROTOCOL_ERROR);
    c->hb_sid = sid;
    c->hb_end_stream = (uint8_t)(flags & FL_END_STREAM);
    c->hb_len = 0;
    if (add_fragment(c, p + skip, len - skip - pad) != 0) return -1;
    if (flags & FL_END_HEADERS) return finish_block(c);
    return 0;
}

static int on_settings(ts_h2 *c, unsigned flags, uint32_t sid, const uint8_t *p, size_t len)
{
    size_t i;
    if (sid != 0) return fail(c, TS_H2_PROTOCOL_ERROR);
    if (flags & FL_ACK) return len == 0 ? 0 : fail(c, TS_H2_FRAME_SIZE_ERROR);
    if (len % 6 != 0) return fail(c, TS_H2_FRAME_SIZE_ERROR);
    for (i = 0; i < len; i += 6) {
        uint16_t id = ts_get_be16(p + i);
        uint32_t v = ts_get_be32(p + i + 2);
        unsigned k;
        switch (id) {
        case S_ENABLE_PUSH:
            if (v != 0) return fail(c, TS_H2_PROTOCOL_ERROR);
            break;
        case S_MAX_CONCURRENT_STREAMS:
            c->peer_max_streams = v;
            break;
        case S_INITIAL_WINDOW_SIZE:
            if (v > WINDOW_LIMIT) return fail(c, TS_H2_FLOW_CONTROL_ERROR);
            /* Retroactive: every open stream's send window moves by the change
             * (and may go negative). Check all before changing any. */
            for (k = 0; k < TS_H2_MAX_STREAMS; k++)
                if (c->st[k].id && c->st[k].send_win + ((int64_t)v - c->peer_init_win) > WINDOW_LIMIT)
                    return fail(c, TS_H2_FLOW_CONTROL_ERROR);
            for (k = 0; k < TS_H2_MAX_STREAMS; k++)
                if (c->st[k].id) c->st[k].send_win += (int64_t)v - c->peer_init_win;
            c->peer_init_win = v;
            break;
        case S_MAX_FRAME_SIZE:
            if (v < TS_H2_FRAME_MAX || v > FRAME_SIZE_LIMIT) return fail(c, TS_H2_PROTOCOL_ERROR);
            c->peer_max_frame = v;
            break;
        case S_HEADER_TABLE_SIZE:   /* our encoder never indexes */
        default:                    /* unknown: ignored */
            break;
        }
    }
    c->got_settings = 1;
    if (emit(c, F_SETTINGS, FL_ACK, 0, NULL, 0) != 0) return fail(c, TS_H2_ENHANCE_YOUR_CALM);
    pump(c);
    return 0;
}

static int on_goaway(ts_h2 *c, uint32_t sid, const uint8_t *p, size_t len)
{
    uint32_t last, code, ids[TS_H2_MAX_STREAMS];
    unsigned i, n = 0;
    if (sid != 0) return fail(c, TS_H2_PROTOCOL_ERROR);
    if (len < 8) return fail(c, TS_H2_FRAME_SIZE_ERROR);
    last = ts_get_be32(p) & 0x7fffffffu;
    code = ts_get_be32(p + 4);
    c->goaway = 1;
    if (c->cbs->goaway) c->cbs->goaway(c->user, last, code);
    for (i = 0; i < TS_H2_MAX_STREAMS; i++)
        if (c->st[i].id > last) ids[n++] = c->st[i].id;
    for (i = 0; i < n; i++) {
        ts_h2_stream *s = find(c, ids[i]);
        if (s == NULL) continue;
        release(c, s);
        if (c->cbs->end) c->cbs->end(c->user, ids[i], TS_H2_END_REFUSED);
    }
    return 0;
}

static int on_window_update(ts_h2 *c, uint32_t sid, const uint8_t *p, size_t len)
{
    uint32_t inc;
    if (len != 4) return fail(c, TS_H2_FRAME_SIZE_ERROR);
    inc = ts_get_be32(p) & 0x7fffffffu;
    if (inc == 0) return fail(c, TS_H2_PROTOCOL_ERROR);
    if (sid == 0) {
        if (c->conn_send + inc > WINDOW_LIMIT) return fail(c, TS_H2_FLOW_CONTROL_ERROR);
        c->conn_send += inc;
    } else {
        ts_h2_stream *s;
        if (idle(c, sid)) return fail(c, TS_H2_PROTOCOL_ERROR);
        s = find(c, sid);
        if (s == NULL) return 0;
        if (s->send_win + inc > WINDOW_LIMIT) return fail(c, TS_H2_FLOW_CONTROL_ERROR);
        s->send_win += inc;
    }
    pump(c);
    return 0;
}

static int on_rst_stream(ts_h2 *c, uint32_t sid, const uint8_t *p, size_t len)
{
    ts_h2_stream *s;
    uint32_t code;
    if (len != 4) return fail(c, TS_H2_FRAME_SIZE_ERROR);
    if (sid == 0 || idle(c, sid)) return fail(c, TS_H2_PROTOCOL_ERROR);
    s = find(c, sid);
    if (s == NULL) return 0;
    code = ts_get_be32(p);
    release(c, s);
    if (c->cbs->end) c->cbs->end(c->user, sid, code == TS_H2_REFUSED_STREAM ? TS_H2_END_REFUSED : TS_H2_END_RESET);
    return 0;
}

static int process(ts_h2 *c)
{
    unsigned type = c->fh[3], flags = c->fh[4];
    uint32_t sid = ts_get_be32(c->fh + 5) & 0x7fffffffu;
    const uint8_t *p = c->frame;
    size_t len = c->f_len;

    if (!c->got_settings && (type != F_SETTINGS || (flags & FL_ACK)))
        return fail(c, TS_H2_PROTOCOL_ERROR);   /* the server preface is a SETTINGS frame */
    if (c->hb_sid != 0) {
        /* Inside a header block only its CONTINUATION frames may appear. */
        if (type != F_CONTINUATION || sid != c->hb_sid) return fail(c, TS_H2_PROTOCOL_ERROR);
        if (add_fragment(c, p, len) != 0) return -1;
        return (flags & FL_END_HEADERS) ? finish_block(c) : 0;
    }
    switch (type) {
    case F_DATA:          return on_data(c, flags, sid, p, len);
    case F_HEADERS:       return on_headers(c, flags, sid, p, len);
    case F_PRIORITY:
        if (sid == 0) return fail(c, TS_H2_PROTOCOL_ERROR);
        return len == 5 ? 0 : fail(c, TS_H2_FRAME_SIZE_ERROR);
    case F_RST_STREAM:    return on_rst_stream(c, sid, p, len);
    case F_SETTINGS:      return on_settings(c, flags, sid, p, len);
    case F_PUSH_PROMISE:  return fail(c, TS_H2_PROTOCOL_ERROR);   /* we disabled push */
    case F_PING:
        if (sid != 0) return fail(c, TS_H2_PROTOCOL_ERROR);
        if (len != 8) return fail(c, TS_H2_FRAME_SIZE_ERROR);
        if (flags & FL_ACK) return 0;
        return emit(c, F_PING, FL_ACK, 0, p, 8) == 0 ? 0 : fail(c, TS_H2_ENHANCE_YOUR_CALM);
    case F_GOAWAY:        return on_goaway(c, sid, p, len);
    case F_WINDOW_UPDATE: return on_window_update(c, sid, p, len);
    case F_CONTINUATION:  return fail(c, TS_H2_PROTOCOL_ERROR);   /* no block in progress */
    default:              return 0;                               /* unknown types are ignored */
    }
}

int ts_h2_feed(ts_h2 *c, const uint8_t *in, size_t n)
{
    if (c->dead) return -1;
    for (;;) {
        size_t k;
        if (c->fh_len < 9) {
            if (n == 0) break;
            k = 9 - c->fh_len;
            if (k > n) k = n;
            memcpy(c->fh + c->fh_len, in, k);
            c->fh_len += k;
            in += k;
            n -= k;
            if (c->fh_len < 9) break;
            c->f_len = ts_get_be32(c->fh) >> 8;
            c->f_have = 0;
            if (c->f_len > TS_H2_FRAME_MAX) return fail(c, TS_H2_FRAME_SIZE_ERROR);
        }
        if (c->f_have < c->f_len) {
            if (n == 0) break;
            k = c->f_len - c->f_have;
            if (k > n) k = n;
            memcpy(c->frame + c->f_have, in, k);
            c->f_have += k;
            in += k;
            n -= k;
            if (c->f_have < c->f_len) break;
        }
        c->fh_len = 0;
        if (process(c) != 0 || c->dead) return -1;
    }
    flush_credit(c);
    return 0;
}
