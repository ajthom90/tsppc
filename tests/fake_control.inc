/* A fake control server for the session tests and the session fuzz target.
 *
 * It sits behind a fake ts_sess_io: the session's connect, send and disconnect
 * only record or queue, and fk_pump moves the queued bytes both ways
 * afterwards, so the session is never re-entered from its own callbacks.
 *
 * Server side: the HTTP/1.1 upgrade, the Noise responder from
 * noise_responder.inc, and a minimal HTTP/2 server (preface, SETTINGS and
 * their ACK, PING ACK, flow-controlled DATA, requests decoded with the HPACK
 * decoder). Every request is recorded; a handler may answer it when it is
 * complete, or a test answers it later. Invented keys, names and URLs only. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/control/session.h"
#include "../src/proto/hpack.h"

#include "noise_responder.inc"

/* Not every user of this file needs every helper. */
#define FK_FN static __attribute__((unused))

#define FK_MAXREQ 512
#define FK_MAXOUT 16
#define FK_T0 1000000

enum { FK_DATA = 0, FK_HEADERS = 1, FK_RST = 3, FK_SETTINGS = 4, FK_PING = 6, FK_GOAWAY = 7,
       FK_WINDOW = 8, FK_CONT = 9 };

typedef struct {
    uint32_t sid;
    int conn;                 /* connection number it arrived on */
    char method[16];
    char scheme[16];
    char path[1100];
    char authority[300];
    char ctype[64];
    char lb[2][80];           /* ts-lb values, in order */
    int nlb;
    int nfields;              /* regular header fields */
    char *body;
    size_t blen, bcap;
    int complete;             /* END_STREAM from the client */
    int reset;                /* the client sent RST_STREAM */
    int answered;             /* response headers sent */
    int closed;               /* ended by us, by a reset, or by the connection closing */
    int64_t at;               /* fake time it completed */
} fk_req;

typedef struct {
    uint32_t sid;             /* 0: free */
    int64_t win;
    uint8_t *buf;
    size_t len, cap;
    int end;                  /* send END_STREAM after the queued bytes */
} fk_out;

typedef struct fake {
    ts_sess *s;
    ts_sess_io io;
    ts_state st;              /* the state the session starts with */
    int64_t now;
    uint8_t control_priv[32], control_pub[32], resp_eph[32];
    uint32_t rng;

    /* What the session asked of its I/O. */
    int nconnect;
    uint16_t ports[256];
    int connect_pending;
    uint16_t refuse_port;     /* refuse connections to this port (0: none) */
    int refuse_all;
    int ndisconnect;
    int nsave;
    ts_state saved;
    int reqs_at_save;
    int save_fail;
    int rand_fail;            /* randomness requests of exactly 32 bytes (keys) fail */
    int send_fail;            /* the next sends fail (the connection stays open until disconnect) */
    int64_t save_at[512];     /* fake time of each save */

    /* The connection. */
    int up;
    int conn;
    uint8_t *c2s;
    size_t c2s_len, c2s_cap;
    uint8_t *s2c;
    size_t s2c_len, s2c_cap;
    size_t rx_chunk;          /* deliver to the session in pieces of this size (0: whole) */
    int phase;                /* 0: HTTP upgrade, 1: Noise transport, 2: silent */
    const char *hs_error;     /* answer the handshake with this error frame */
    uint16_t hs_error_port;   /* ... only on this port (0: any) */
    uint16_t hs_corrupt_port; /* send a handshake response that fails to verify on this port (0: none) */
    const char *early;        /* early payload JSON to send before HTTP/2 */
    int no_preface;           /* send no frames of our own: the caller writes the whole stream */
    r_session rs;
    uint64_t rx_ctr, tx_ctr;
    uint8_t *pt;
    size_t pt_len, pt_cap;
    int preface;
    ts_hpack dec;
    fk_req *cur;              /* request whose header block is being decoded */
    int64_t conn_win, init_win;
    fk_out out[FK_MAXOUT];
    int auto_ping_ack;
    int npings;
    int nwinupd;
    uint64_t winupd_bytes;
    uint64_t data_sent;
    int ngoaway_rx;
    int bad;                  /* the client broke the protocol */

    fk_req req[FK_MAXREQ];
    int nreq;
    void (*handler)(struct fake *, fk_req *);
    int hold_followup;        /* handler helpers: leave Followups unanswered */
    const char *map_first;    /* first map message the default handler sends */
} fake;

/* ---- Growable buffers ------------------------------------------------ */

FK_FN void fk_append(uint8_t **b, size_t *len, size_t *cap, const void *p, size_t n)
{
    if (*len + n > *cap) {
        size_t nc = *cap ? *cap : 256;
        while (nc < *len + n) nc *= 2;
        *b = (uint8_t *)realloc(*b, nc);
        if (!*b) abort();
        *cap = nc;
    }
    if (n) memcpy(*b + *len, p, n);
    *len += n;
}

FK_FN void fk_consume(uint8_t *b, size_t *len, size_t n)
{
    memmove(b, b + n, *len - n);
    *len -= n;
}

/* ---- io callbacks ---------------------------------------------------- */

FK_FN int fk_io_connect(void *u, const char *host, uint16_t port)
{
    fake *f = (fake *)u;
    if (strcmp(host, TS_CONTROL_HOST) != 0 && strcmp(host, "control.example.test") != 0) f->bad = 1;
    if (f->nconnect < 256) f->ports[f->nconnect] = port;
    f->nconnect++;
    if (f->connect_pending || f->up) f->bad = 1;   /* one connection at a time */
    f->connect_pending = port;
    return 0;
}

FK_FN int fk_io_send(void *u, const uint8_t *p, size_t n)
{
    fake *f = (fake *)u;
    if (!f->up) { f->bad = 1; return -1; }
    if (f->send_fail) return -1;
    fk_append(&f->c2s, &f->c2s_len, &f->c2s_cap, p, n);
    return 0;
}

FK_FN void fk_conn_reset(fake *f)
{
    int i;
    f->c2s_len = f->s2c_len = f->pt_len = 0;
    f->phase = 0;
    f->preface = 0;
    f->rx_ctr = f->tx_ctr = 0;
    ts_hpack_init(&f->dec);
    f->conn_win = f->init_win = 65535;
    for (i = 0; i < FK_MAXOUT; i++) {
        free(f->out[i].buf);
        memset(&f->out[i], 0, sizeof f->out[i]);
    }
    for (i = 0; i < f->nreq; i++) f->req[i].closed = 1;
}

FK_FN void fk_io_disconnect(void *u)
{
    fake *f = (fake *)u;
    f->ndisconnect++;
    f->up = 0;
    f->connect_pending = 0;
    fk_conn_reset(f);
}

FK_FN int fk_io_save(void *u, const ts_state *st)
{
    fake *f = (fake *)u;
    if (f->save_fail) return -1;
    if (f->nsave < 512) f->save_at[f->nsave] = f->now;
    f->nsave++;
    f->saved = *st;
    f->reqs_at_save = f->nreq;
    return 0;
}

FK_FN int fk_io_random(void *u, uint8_t *out, size_t n)
{
    fake *f = (fake *)u;
    size_t i;
    if (f->rand_fail && n == 32) return -1;
    for (i = 0; i < n; i++) {
        f->rng ^= f->rng << 13;
        f->rng ^= f->rng >> 17;
        f->rng ^= f->rng << 5;
        out[i] = (uint8_t)(f->rng >> 7);
    }
    return 0;
}

/* ---- Server output --------------------------------------------------- */

/* Seal plaintext into records toward the client. */
FK_FN void fk_send_plain(fake *f, const uint8_t *p, size_t n)
{
    uint8_t rec[TS_NOISE_MAX_MSG];
    while (n > 0) {
        size_t k = n > TS_NOISE_MAX_PLAIN ? TS_NOISE_MAX_PLAIN : n;
        size_t w = r_seal(rec, f->rs.c2, f->tx_ctr++, 0, p, k);
        fk_append(&f->s2c, &f->s2c_len, &f->s2c_cap, rec, w);
        p += k;
        n -= k;
    }
}

FK_FN void fk_frame(fake *f, unsigned type, unsigned flags, uint32_t sid, const void *payload, size_t len)
{
    uint8_t h[9], l[4];
    uint8_t *buf;
    if (!f->up || f->phase != 1 || f->no_preface) return;
    buf = (uint8_t *)malloc(9 + len);
    if (!buf) abort();
    ts_put_be32(l, (uint32_t)len);
    memcpy(h, l + 1, 3);
    h[3] = (uint8_t)type;
    h[4] = (uint8_t)flags;
    ts_put_be32(h + 5, sid);
    memcpy(buf, h, 9);
    if (len) memcpy(buf + 9, payload, len);
    fk_send_plain(f, buf, 9 + len);
    free(buf);
}

FK_FN fk_out *fk_out_slot(fake *f, uint32_t sid, int create)
{
    int i;
    for (i = 0; i < FK_MAXOUT; i++)
        if (f->out[i].sid == sid) return &f->out[i];
    if (!create) return NULL;
    for (i = 0; i < FK_MAXOUT; i++) {
        if (f->out[i].sid == 0) {
            f->out[i].sid = sid;
            f->out[i].win = f->init_win;
            return &f->out[i];
        }
    }
    abort();
    return NULL;
}

FK_FN fk_req *fk_find(fake *f, uint32_t sid)
{
    int i;
    for (i = f->nreq - 1; i >= 0; i--)
        if (f->req[i].sid == sid && f->req[i].conn == f->conn) return &f->req[i];
    return NULL;
}

/* Send queued DATA as the client's windows allow. */
FK_FN void fk_flush_out(fake *f)
{
    int i;
    for (i = 0; i < FK_MAXOUT; i++) {
        fk_out *o = &f->out[i];
        while (o->sid && (o->len > 0 || o->end)) {
            size_t k = o->len;
            int64_t room = o->win < f->conn_win ? o->win : f->conn_win;
            int last;
            if (k > 16384) k = 16384;
            if ((int64_t)k > room) k = room > 0 ? (size_t)room : 0;
            if (k == 0 && o->len > 0) break;
            last = o->end && k == o->len;
            fk_frame(f, FK_DATA, last ? 1 : 0, o->sid, o->buf, k);
            fk_consume(o->buf, &o->len, k);
            o->win -= (int64_t)k;
            f->conn_win -= (int64_t)k;
            f->data_sent += k;
            if (last) {
                fk_req *r = fk_find(f, o->sid);
                if (r) r->closed = 1;
                free(o->buf);
                memset(o, 0, sizeof *o);
            }
        }
    }
}

/* Response headers: :status, then nh (name, value) pairs. */
FK_FN void fk_headers(fake *f, fk_req *r, int status, const char *const *hdrs, size_t nh, int end)
{
    uint8_t blk[4096];
    char st[8];
    size_t bl = 0, i;
    snprintf(st, sizeof st, "%d", status);
    bl += ts_hpack_encode(blk + bl, sizeof blk - bl, ":status", st);
    for (i = 0; i < nh; i++) bl += ts_hpack_encode(blk + bl, sizeof blk - bl, hdrs[2 * i], hdrs[2 * i + 1]);
    fk_frame(f, FK_HEADERS, 0x4 | (end ? 1 : 0), r->sid, blk, bl);
    r->answered = 1;
    if (end) r->closed = 1;
}

FK_FN void fk_data(fake *f, fk_req *r, const void *p, size_t n, int end)
{
    fk_out *o = fk_out_slot(f, r->sid, 1);
    fk_append(&o->buf, &o->len, &o->cap, p, n);
    if (end) o->end = 1;
    fk_flush_out(f);
}

FK_FN void fk_reply(fake *f, fk_req *r, int status, const char *json)
{
    fk_headers(f, r, status, NULL, 0, json == NULL);
    if (json) fk_data(f, r, json, strlen(json), 1);
}

/* One map message: 4-byte little-endian length, then the JSON. */
FK_FN void fk_map_msg(fake *f, fk_req *r, const char *json)
{
    uint8_t h[4];
    size_t n = strlen(json);
    ts_put_le32(h, (uint32_t)n);
    fk_data(f, r, h, 4, 0);
    fk_data(f, r, json, n, 0);
}

FK_FN void fk_rst(fake *f, fk_req *r, uint32_t code)
{
    uint8_t p[4];
    fk_out *o = fk_out_slot(f, r->sid, 0);
    ts_put_be32(p, code);
    fk_frame(f, FK_RST, 0, r->sid, p, 4);
    r->closed = 1;
    if (o) {
        free(o->buf);
        memset(o, 0, sizeof *o);
    }
}

FK_FN void fk_goaway(fake *f, uint32_t last, uint32_t code)
{
    uint8_t p[8];
    ts_put_be32(p, last);
    ts_put_be32(p + 4, code);
    fk_frame(f, FK_GOAWAY, 0, 0, p, 8);
}

/* ---- Server input ---------------------------------------------------- */

FK_FN void fk_copy(char *dst, size_t cap, const char *v, size_t vl)
{
    if (vl >= cap) vl = cap - 1;
    memcpy(dst, v, vl);
    dst[vl] = 0;
}

FK_FN void fk_field(void *u, const char *n, size_t nl, const char *v, size_t vl)
{
    fake *f = (fake *)u;
    fk_req *r = f->cur;
    if (!r) return;
#define FK_IS(s) (nl == sizeof(s) - 1 && memcmp(n, s, nl) == 0)
    if (FK_IS(":method")) fk_copy(r->method, sizeof r->method, v, vl);
    else if (FK_IS(":path")) fk_copy(r->path, sizeof r->path, v, vl);
    else if (FK_IS(":authority")) fk_copy(r->authority, sizeof r->authority, v, vl);
    else if (FK_IS(":scheme")) fk_copy(r->scheme, sizeof r->scheme, v, vl);
    else {
        r->nfields++;
        if (FK_IS("content-type")) fk_copy(r->ctype, sizeof r->ctype, v, vl);
        else if (FK_IS("ts-lb") && r->nlb < 2) fk_copy(r->lb[r->nlb++], sizeof r->lb[0], v, vl);
    }
#undef FK_IS
}

FK_FN void fk_complete(fake *f, fk_req *r)
{
    r->complete = 1;
    r->at = f->now;
    fk_append((uint8_t **)&r->body, &r->blen, &r->bcap, "", 1);   /* NUL-terminate */
    r->blen--;
    if (f->handler) f->handler(f, r);
}

FK_FN void fk_frames(fake *f)
{
    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t off = 0;
    if (!f->preface) {
        if (f->pt_len < 24) return;
        if (memcmp(f->pt, preface, 24) != 0) f->bad = 1;
        f->preface = 1;
        off = 24;
    }
    while (f->pt_len - off >= 9) {
        const uint8_t *h = f->pt + off;
        uint32_t len = ((uint32_t)h[0] << 16) | ((uint32_t)h[1] << 8) | h[2];
        unsigned type = h[3], flags = h[4];
        uint32_t sid = ts_get_be32(h + 5) & 0x7fffffffu;
        const uint8_t *p = h + 9;
        fk_req *r;
        size_t i;
        if (f->pt_len - off < 9 + len) break;
        off += 9 + len;
        switch (type) {
        case FK_SETTINGS:
            if (flags & 1) break;
            for (i = 0; i + 6 <= len; i += 6) {
                if (ts_get_be16(p + i) == 4) {
                    int64_t nw = ts_get_be32(p + i + 2), d = nw - f->init_win;
                    int k;
                    for (k = 0; k < FK_MAXOUT; k++)
                        if (f->out[k].sid) f->out[k].win += d;
                    f->init_win = nw;
                }
            }
            fk_frame(f, FK_SETTINGS, 1, 0, NULL, 0);
            break;
        case FK_WINDOW: {
            uint32_t inc = ts_get_be32(p) & 0x7fffffffu;
            fk_out *o;
            f->nwinupd++;
            if (sid == 0) {
                f->conn_win += inc;
                f->winupd_bytes += inc;
            } else if ((o = fk_out_slot(f, sid, 0)) != NULL) {
                o->win += inc;
            }
            break;
        }
        case FK_HEADERS:
            if (f->nreq >= FK_MAXREQ || !(flags & 0x4) || (flags & 0x28)) { f->bad = 1; break; }
            r = &f->req[f->nreq++];
            memset(r, 0, sizeof *r);
            r->sid = sid;
            r->conn = f->conn;
            f->cur = r;
            if (ts_hpack_decode(&f->dec, p, len, fk_field, f) != 0) f->bad = 1;
            f->cur = NULL;
            if (flags & 1) fk_complete(f, r);
            break;
        case FK_DATA:
            r = fk_find(f, sid);
            if (!r || r->complete) { f->bad = 1; break; }
            fk_append((uint8_t **)&r->body, &r->blen, &r->bcap, p, len);
            if (flags & 1) fk_complete(f, r);
            break;
        case FK_RST:
            r = fk_find(f, sid);
            if (r) {
                fk_out *o = fk_out_slot(f, sid, 0);
                r->reset = r->closed = 1;
                if (o) {
                    free(o->buf);
                    memset(o, 0, sizeof *o);
                }
            }
            break;
        case FK_PING:
            if (!(flags & 1)) {
                f->npings++;
                if (f->auto_ping_ack) fk_frame(f, FK_PING, 1, 0, p, 8);
            }
            break;
        case FK_GOAWAY:
            f->ngoaway_rx++;
            break;
        default:
            f->bad = 1;
        }
    }
    fk_consume(f->pt, &f->pt_len, off);
    fk_flush_out(f);
}

FK_FN int fk_b64val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode base64 into out; returns the length or -1. */
FK_FN long fk_b64dec(uint8_t *out, size_t cap, const char *s, size_t n)
{
    size_t i, o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (i = 0; i < n; i++) {
        int v;
        if (s[i] == '=') break;
        v = fk_b64val((unsigned char)s[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return (long)o;
}

/* Handle the upgrade request; returns the bytes used, or 0 if incomplete. */
FK_FN size_t fk_upgrade(fake *f)
{
    static const char hdr[] = "X-Tailscale-Handshake: ";
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN];
    const char *b = (const char *)f->c2s, *end = NULL, *hv, *le;
    static const char ok[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n"
                             "Connection: upgrade\r\n\r\n";
    size_t i;
    uint16_t port;
    for (i = 0; i + 4 <= f->c2s_len; i++)
        if (memcmp(b + i, "\r\n\r\n", 4) == 0) { end = b + i + 4; break; }
    if (!end) return 0;
    if (memcmp(b, "POST /ts2021 HTTP/1.1\r\n", 23) != 0) f->bad = 1;
    hv = NULL;
    for (i = 0; b + i + sizeof hdr - 1 < end; i++)
        if (memcmp(b + i, hdr, sizeof hdr - 1) == 0) { hv = b + i + sizeof hdr - 1; break; }
    if (!hv) { f->bad = 1; return (size_t)(end - b); }
    le = hv;
    while (le < end && *le != '\r') le++;
    if (fk_b64dec(init, sizeof init, hv, (size_t)(le - hv)) != TS_NOISE_INIT_LEN) f->bad = 1;
    port = f->nconnect > 0 && f->nconnect <= 256 ? f->ports[f->nconnect - 1] : 0;
    fk_append(&f->s2c, &f->s2c_len, &f->s2c_cap, ok, sizeof ok - 1);
    if (f->hs_error && (f->hs_error_port == 0 || f->hs_error_port == port)) {
        uint8_t h[3];
        size_t n = strlen(f->hs_error);
        h[0] = 3;
        ts_put_be16(h + 1, (uint16_t)n);
        fk_append(&f->s2c, &f->s2c_len, &f->s2c_cap, h, 3);
        fk_append(&f->s2c, &f->s2c_len, &f->s2c_cap, f->hs_error, n);
        f->phase = 2;
        return (size_t)(end - b);
    }
    if (responder(&f->rs, resp, init, f->control_priv, f->resp_eph) != 0) {
        f->bad = 1;
        f->phase = 2;
        return (size_t)(end - b);
    }
    if (f->hs_corrupt_port != 0 && f->hs_corrupt_port == port) {
        resp[sizeof resp - 1] ^= 1;   /* in the tag: the client cannot verify it */
        fk_append(&f->s2c, &f->s2c_len, &f->s2c_cap, resp, sizeof resp);
        f->phase = 2;
        return (size_t)(end - b);
    }
    fk_append(&f->s2c, &f->s2c_len, &f->s2c_cap, resp, sizeof resp);
    f->phase = 1;
    if (f->no_preface) return (size_t)(end - b);
    if (f->early) {
        uint8_t eh[9];
        size_t n = strlen(f->early);
        uint8_t *buf = (uint8_t *)malloc(9 + n);
        if (!buf) abort();
        memcpy(eh, "\xff\xff\xffTS", 5);
        ts_put_be32(eh + 5, (uint32_t)n);
        memcpy(buf, eh, 9);
        memcpy(buf + 9, f->early, n);
        fk_send_plain(f, buf, 9 + n);
        free(buf);
    }
    fk_frame(f, FK_SETTINGS, 0, 0, NULL, 0);
    return (size_t)(end - b);
}

/* Process client bytes; returns 1 if any were used. */
FK_FN int fk_process(fake *f)
{
    int progress = 0;
    if (f->phase == 0) {
        size_t n = fk_upgrade(f);
        if (n == 0) return 0;
        fk_consume(f->c2s, &f->c2s_len, n);
        progress = 1;
    }
    if (f->phase == 2) {
        if (f->c2s_len) progress = 1;
        f->c2s_len = 0;
        return progress;
    }
    while (f->c2s_len >= 3) {
        uint8_t pt[TS_NOISE_MAX_MSG];
        size_t len = ts_get_be16(f->c2s + 1);
        long n;
        if (f->c2s_len < 3 + len) break;
        n = r_open(pt, f->rs.c1, f->rx_ctr++, 0, f->c2s);
        if (n < 0) f->bad = 1;
        else fk_append(&f->pt, &f->pt_len, &f->pt_cap, pt, (size_t)n);
        fk_consume(f->c2s, &f->c2s_len, 3 + len);
        progress = 1;
    }
    if (progress) fk_frames(f);
    return progress;
}

/* Move bytes both ways until nothing changes. */
FK_FN void fk_pump(fake *f)
{
    int guard;
    for (guard = 0; guard < 1000000; guard++) {
        if (f->connect_pending) {
            uint16_t port = (uint16_t)f->connect_pending;
            f->connect_pending = 0;
            if (f->refuse_all || port == f->refuse_port) {
                ts_sess_disconnected(f->s, "connection refused");
            } else {
                f->up = 1;
                f->conn++;
                fk_conn_reset(f);
                ts_sess_connected(f->s);
            }
            continue;
        }
        if (f->up && f->c2s_len && fk_process(f)) continue;
        if (f->up && f->s2c_len && ts_sess_want_read(f->s)) {
            size_t n = f->s2c_len;
            uint8_t *tmp;
            if (f->rx_chunk && n > f->rx_chunk) n = f->rx_chunk;
            tmp = (uint8_t *)malloc(n);
            if (!tmp) abort();
            memcpy(tmp, f->s2c, n);
            fk_consume(f->s2c, &f->s2c_len, n);
            ts_sess_recv(f->s, tmp, n);
            free(tmp);
            continue;
        }
        break;
    }
}

/* The server closes the connection. */
FK_FN void fk_close(fake *f, const char *why)
{
    if (!f->up) return;
    f->up = 0;
    fk_conn_reset(f);
    ts_sess_disconnected(f->s, why);
    fk_pump(f);
}

FK_FN void fk_tick(fake *f)
{
    ts_sess_tick(f->s, (uint64_t)f->now);
    fk_pump(f);
}

/* Advance the fake clock by ms in steps of step ms, ticking and pumping. */
FK_FN void fk_advance(fake *f, int64_t ms, int64_t step)
{
    int64_t end = f->now + ms;
    while (f->now < end) {
        f->now += end - f->now < step ? end - f->now : step;
        fk_tick(f);
    }
}

/* Requests with this path (and, if sub is set, a body containing it). */
FK_FN int fk_count(const fake *f, const char *path, const char *sub)
{
    int i, n = 0;
    for (i = 0; i < f->nreq; i++)
        if (strcmp(f->req[i].path, path) == 0 && (!sub || (f->req[i].body && strstr(f->req[i].body, sub))))
            n++;
    return n;
}

FK_FN fk_req *fk_last(fake *f, const char *path)
{
    int i;
    for (i = f->nreq - 1; i >= 0; i--)
        if (strcmp(f->req[i].path, path) == 0) return &f->req[i];
    return NULL;
}

/* Open requests with this path on the live connection. */
FK_FN int fk_open(const fake *f, const char *path)
{
    int i, n = 0;
    for (i = 0; i < f->nreq; i++)
        if (f->req[i].conn == f->conn && f->up && !f->req[i].closed && strcmp(f->req[i].path, path) == 0) n++;
    return n;
}

/* Set up a fake and a session; the session is not started. */
FK_FN void fk_init(fake *f, ts_sess *s, const char *hostinfo)
{
    size_t i;
    memset(f, 0, sizeof *f);
    f->s = s;
    f->rng = 0x12345678u;
    f->auto_ping_ack = 1;
    f->now = FK_T0;
    for (i = 0; i < 32; i++) {
        f->control_priv[i] = (uint8_t)(0x40 + 3 * i);
        f->resp_eph[i] = (uint8_t)(0x21 + 11 * i);
        f->st.machine_priv[i] = (uint8_t)(0x10 + i);
        f->st.node_priv[i] = (uint8_t)(0x90 + i);
        f->st.disco_priv[i] = (uint8_t)(0x50 + 5 * i);
    }
    ts_state_clamp_key(f->st.machine_priv);
    ts_state_clamp_key(f->st.node_priv);
    ts_state_clamp_key(f->st.disco_priv);
    ts_x25519_public(f->control_pub, f->control_priv);
    f->io.connect = fk_io_connect;
    f->io.send = fk_io_send;
    f->io.disconnect = fk_io_disconnect;
    f->io.save_state = fk_io_save;
    f->io.random = fk_io_random;
    fk_conn_reset(f);
    (void)hostinfo;
}

FK_FN void fk_start(fake *f, const char *hostinfo)
{
    ts_sess_init(f->s, &f->st, &f->io, f, f->control_pub, hostinfo);
    ts_sess_tick(f->s, (uint64_t)f->now);
}

FK_FN void fk_free(fake *f)
{
    int i;
    ts_sess_free(f->s);
    for (i = 0; i < f->nreq; i++) free(f->req[i].body);
    for (i = 0; i < FK_MAXOUT; i++) free(f->out[i].buf);
    free(f->c2s);
    free(f->s2c);
    free(f->pt);
    memset(f, 0, sizeof *f);
}
