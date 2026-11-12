#include "derp.h"

#include <string.h>

#include "../core/bytes.h"
#include "../crypto/nacl.h"
#include "../crypto/random.h"
#include "../crypto/x25519.h"
#include "../daemon/ipc.h"
#include "../proto/json.h"

enum { DS_NEW = 0, DS_HTTP, DS_KEY, DS_INFO, DS_READY, DS_DEAD };

static const uint8_t MAGIC[8] = { 'D', 'E', 'R', 'P', 0xf0, 0x9f, 0x94, 0x91 };
static const char CLIENT_JSON[] = "{\"version\":2,\"CanAckPings\":true}";

#define SERVER_KEY_MAX 1024   /* upstream recvServerKey reads with 1<<10 */
#define NONCE_LEN 24
#define BOX_TAG 16

static int fail(ts_derp *d, const char *why)
{
    if (d->state != DS_DEAD) d->err = why;
    d->state = DS_DEAD;
    ts_wipe(d->shared, sizeof d->shared);
    return -1;
}

/* Send one frame: header, then a and b, in one send call. */
static void send_frame(ts_derp *d, int type, const uint8_t *a, size_t an,
                       const uint8_t *b, size_t bn)
{
    d->wbuf[0] = (uint8_t)type;
    ts_put_be32(d->wbuf + 1, (uint32_t)(an + bn));
    if (an) memcpy(d->wbuf + 5, a, an);
    if (bn) memcpy(d->wbuf + 5 + an, b, bn);
    if (d->io->send) d->io->send(d->user, d->wbuf, 5 + an + bn);
}

void ts_derp_init(ts_derp *d, const char *host, const uint8_t node_priv[32], int preferred,
                  const ts_derp_io *io, void *user)
{
    size_t hl = strlen(host), i;

    memset(d, 0, sizeof *d);
    d->io = io;
    d->user = user;
    d->preferred = preferred != 0;
    memcpy(d->priv, node_priv, 32);
    ts_x25519_public(d->pub, d->priv);
    d->state = DS_NEW;
    if (hl == 0 || hl > TS_DERP_HOST_MAX) {
        fail(d, "invalid relay host name");
        return;
    }
    for (i = 0; i < hl; i++) {
        if ((unsigned char)host[i] <= ' ' || (unsigned char)host[i] > '~') {
            fail(d, "invalid relay host name");
            return;
        }
    }
    memcpy(d->host, host, hl + 1);
}

void ts_derp_start(ts_derp *d, int64_t now_ms)
{
    static const char l1[] = "GET /derp HTTP/1.1\r\nHost: ";
    static const char l2[] = "\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
    size_t hl, at = 0;

    if (d->state != DS_NEW) return;
    hl = strlen(d->host);
    memcpy(d->wbuf, l1, sizeof l1 - 1);
    at += sizeof l1 - 1;
    memcpy(d->wbuf + at, d->host, hl);
    at += hl;
    memcpy(d->wbuf + at, l2, sizeof l2 - 1);
    at += sizeof l2 - 1;
    d->start_ms = now_ms;
    d->last_frame_ms = now_ms;
    d->state = DS_HTTP;
    if (d->io->send) d->io->send(d->user, d->wbuf, at);
}

int ts_derp_ready(const ts_derp *d)
{
    return d->state == DS_READY;
}

/* One complete JSON value. */
static int is_json(const uint8_t *p, size_t n)
{
    ts_json j;
    ts_json_tok t;
    ts_json_type ty;

    ts_json_init(&j, (const char *)p, n);
    do ty = ts_json_next(&j, &t);
    while (ty != TS_JSON_END && ty != TS_JSON_ERROR);
    return ty == TS_JSON_END;
}

static int send_client_info(ts_derp *d)
{
    uint8_t body[32 + NONCE_LEN + BOX_TAG + sizeof CLIENT_JSON - 1];

    memcpy(body, d->pub, 32);
    if (ts_random_bytes(body + 32, NONCE_LEN) != 0) return fail(d, "no randomness");
    ts_secretbox_seal(body + 32 + NONCE_LEN, d->shared, body + 32,
                      (const uint8_t *)CLIENT_JSON, sizeof CLIENT_JSON - 1);
    send_frame(d, TS_DERP_CLIENT_INFO, body, sizeof body, NULL, 0);
    return 0;
}

/* How much of a frame body to buffer, once its header is in; -1 if fatal. */
static int frame_keep(ts_derp *d, int type, uint32_t len, uint32_t *keep)
{
    uint32_t k;

    if (len > TS_DERP_MAX_FRAME) return fail(d, "relay sent an oversized frame");
    if (d->state == DS_KEY) {
        if (type != TS_DERP_SERVER_KEY || len < 40 || len > SERVER_KEY_MAX)
            return fail(d, "invalid relay greeting");
        *keep = 40;
        return 0;
    }
    switch (type) {
    case TS_DERP_SERVER_INFO:
        if (len > sizeof d->rbuf) return fail(d, "relay server info too long");
        k = len;
        break;
    case TS_DERP_RECV_PACKET:
        k = len <= sizeof d->rbuf ? len : 0;
        break;
    case TS_DERP_PING:
    case TS_DERP_PONG:
        k = 8;
        break;
    case TS_DERP_PEER_GONE:
        k = 32;
        break;
    case TS_DERP_HEALTH:
        k = TS_DERP_HEALTH_MAX;
        break;
    default:
        k = 0;
        break;
    }
    *keep = k < len ? k : len;
    return 0;
}

static int on_server_info(ts_derp *d, uint32_t len)
{
    uint8_t *c = d->rbuf + NONCE_LEN;
    size_t clen;

    if (len < NONCE_LEN + BOX_TAG) return fail(d, "relay server info too short");
    clen = len - NONCE_LEN;
    /* Opened in place: plaintext at rbuf + 40. */
    if (ts_secretbox_open(c + BOX_TAG, d->shared, d->rbuf, c, clen) != 0)
        return fail(d, "relay server info did not verify");
    if (!is_json(c + BOX_TAG, clen - BOX_TAG)) return fail(d, "relay server info is not JSON");
    if (d->state == DS_INFO) {
        d->state = DS_READY;
        if (d->preferred) {
            uint8_t one = 1;
            send_frame(d, TS_DERP_NOTE_PREFERRED, &one, 1, NULL, 0);
            d->sent_preferred = 1;
        }
    }
    return 0;
}

/* A whole frame is in: rbuf holds the first d->keep bytes of its body. */
static int dispatch(ts_derp *d, int type, uint32_t len)
{
    const ts_derp_io *io = d->io;
    uint32_t keep = d->keep;

    if (d->state == DS_KEY) {
        if (memcmp(d->rbuf, MAGIC, sizeof MAGIC) != 0) return fail(d, "invalid relay greeting");
        memcpy(d->server, d->rbuf + 8, 32);
        if (ts_box_beforenm(d->shared, d->server, d->priv) != 0)
            return fail(d, "invalid relay key");
        d->state = DS_INFO;
        return send_client_info(d);
    }
    switch (type) {
    case TS_DERP_SERVER_INFO:
        return on_server_info(d, len);
    case TS_DERP_RECV_PACKET:
        if (len >= 32 && keep == len && io->recv_packet)
            io->recv_packet(d->user, d->rbuf, d->rbuf + 32, len - 32);
        break;
    case TS_DERP_PING:
        if (len >= 8) send_frame(d, TS_DERP_PONG, d->rbuf, 8, NULL, 0);
        break;
    case TS_DERP_PONG:
        if (len >= 8 && io->pong) io->pong(d->user, d->rbuf);
        break;
    case TS_DERP_PEER_GONE:
        if (len >= 32 && io->peer_gone) io->peer_gone(d->user, d->rbuf);
        break;
    case TS_DERP_HEALTH:
        if (io->health) {
            char text[TS_DERP_HEALTH_MAX + 1];
            ts_ipc_clean(text, sizeof text, (const char *)d->rbuf, keep, 0);
            io->health(d->user, text);
        }
        break;
    default:
        break;   /* KeepAlive, Restarting, PeerPresent, ServerKey, unknown */
    }
    return 0;
}

/* Frames from in[0..n). */
static int frames(ts_derp *d, const uint8_t *in, size_t n, int64_t now_ms)
{
    while (n > 0 && d->state != DS_DEAD) {
        if (d->fh_len < 5) {
            size_t take = 5 - d->fh_len;
            if (take > n) take = n;
            memcpy(d->fh + d->fh_len, in, take);
            d->fh_len += take;
            in += take;
            n -= take;
            if (d->fh_len < 5) break;
            d->flen = ts_get_be32(d->fh + 1);
            d->fgot = 0;
            if (frame_keep(d, d->fh[0], d->flen, &d->keep) != 0) return -1;
        } else {
            size_t take = d->flen - d->fgot;
            if (take > n) take = n;
            if (d->fgot < d->keep) {
                size_t c = d->keep - d->fgot;
                if (c > take) c = take;
                memcpy(d->rbuf + d->fgot, in, c);
            }
            d->fgot += (uint32_t)take;
            in += take;
            n -= take;
        }
        if (d->fgot == d->flen) {
            /* Reset first: a callback may send, never feed. */
            d->fh_len = 0;
            d->last_frame_ms = now_ms;
            if (dispatch(d, d->fh[0], d->flen) != 0) return -1;
        }
    }
    return d->state == DS_DEAD ? -1 : 0;
}

int ts_derp_feed(ts_derp *d, const uint8_t *in, size_t n, int64_t now_ms)
{
    if (d->state == DS_DEAD) return -1;
    if (d->state == DS_NEW) return fail(d, "relay connection not started");
    if (d->state == DS_HTTP) {
        size_t before = d->hdr_len, room = sizeof d->hdr - d->hdr_len, consumed, skip;
        size_t c = n < room ? n : room;
        int rc;
        memcpy(d->hdr + d->hdr_len, in, c);
        d->hdr_len += c;
        rc = ts_http_upgrade_response(d->hdr, d->hdr_len, "DERP", &consumed);
        if (rc < 0) return fail(d, "relay refused the DERP upgrade");
        if (rc > 0) return 0;
        /* The headers ended in this input; frames follow at once. */
        skip = consumed - before;
        in += skip;
        n -= skip;
        d->state = DS_KEY;
        d->fh_len = 0;
    }
    return frames(d, in, n, now_ms);
}

int ts_derp_send_packet(ts_derp *d, const uint8_t dst[32], const uint8_t *p, size_t n)
{
    if (d->state != DS_READY || n > TS_DERP_MAX_PACKET) return -1;
    send_frame(d, TS_DERP_SEND_PACKET, dst, 32, p, n);
    return 0;
}

int ts_derp_ping(ts_derp *d, const uint8_t data[8])
{
    if (d->state != DS_READY) return -1;
    send_frame(d, TS_DERP_PING, data, 8, NULL, 0);
    return 0;
}

void ts_derp_note_preferred(ts_derp *d, int preferred)
{
    uint8_t v = preferred != 0;
    d->preferred = v;
    if (d->state != DS_READY || v == d->sent_preferred) return;
    send_frame(d, TS_DERP_NOTE_PREFERRED, &v, 1, NULL, 0);
    d->sent_preferred = v;
}

int ts_derp_tick(ts_derp *d, int64_t now_ms)
{
    if (d->state == DS_DEAD) return -1;
    if (d->state == DS_NEW) return 0;
    if (d->state != DS_READY && now_ms - d->start_ms >= TS_DERP_HANDSHAKE_TIMEOUT_MS)
        return fail(d, "relay handshake timed out");
    if (now_ms - d->last_frame_ms >= TS_DERP_READ_TIMEOUT_MS)
        return fail(d, "nothing from the relay for 120 s");
    return 0;
}

void ts_derp_free(ts_derp *d)
{
    ts_wipe(d, sizeof *d);
}
