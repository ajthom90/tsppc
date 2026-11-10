/* Scripted HTTP/2 server streams, shared by tests/test_h2.c and tests/fuzz_h2.c.
 * Frames are built by hand here; only the response header blocks use the HPACK
 * literal encoder or hand-written HPACK bytes. */

#include "../src/core/bytes.h"
#include "../src/proto/h2.h"
#include "../src/proto/hpack.h"

#include <string.h>

enum {
    H2S_DATA = 0, H2S_HEADERS = 1, H2S_PRIORITY = 2, H2S_RST = 3, H2S_SETTINGS = 4,
    H2S_PUSH = 5, H2S_PING = 6, H2S_GOAWAY = 7, H2S_WINDOW = 8, H2S_CONT = 9
};
enum { H2S_END_STREAM = 0x1, H2S_ACK = 0x1, H2S_END_HEADERS = 0x4, H2S_PADDED = 0x8, H2S_PRIO = 0x20 };

/* One frame: 24-bit length, type, flags, stream id, payload. Returns 9 + len. */
static size_t h2s_frame(uint8_t *out, unsigned type, unsigned flags, uint32_t sid,
                        const void *payload, size_t len)
{
    uint8_t l[4];
    ts_put_be32(l, (uint32_t)len);
    memcpy(out, l + 1, 3);
    out[3] = (uint8_t)type;
    out[4] = (uint8_t)flags;
    ts_put_be32(out + 5, sid);
    if (len) memcpy(out + 9, payload, len);
    return 9 + len;
}

/* SETTINGS with npairs (id, value) pairs. */
static size_t h2s_settings(uint8_t *out, const uint32_t *kv, size_t npairs)
{
    uint8_t p[6 * 16];
    size_t i;
    for (i = 0; i < npairs; i++) {
        ts_put_be16(p + 6 * i, (uint16_t)kv[2 * i]);
        ts_put_be32(p + 6 * i + 2, kv[2 * i + 1]);
    }
    return h2s_frame(out, H2S_SETTINGS, 0, 0, p, 6 * npairs);
}

static size_t h2s_u32(uint8_t *out, unsigned type, uint32_t sid, uint32_t v)
{
    uint8_t p[4];
    ts_put_be32(p, v);
    return h2s_frame(out, type, 0, sid, p, 4);
}

static size_t h2s_goaway(uint8_t *out, uint32_t last, uint32_t code, const char *debug)
{
    uint8_t p[64];
    size_t dl = strlen(debug);
    ts_put_be32(p, last);
    ts_put_be32(p + 4, code);
    memcpy(p + 8, debug, dl);
    return h2s_frame(out, H2S_GOAWAY, 0, 0, p, 8 + dl);
}

/* The client side of the recorded exchange: stream 1 is a POST with a
 * 3000-byte body, stream 3 a GET. */
#define H2S_BODY1_LEN 3000
static void h2s_open_two(ts_h2 *c, uint32_t *s1, uint32_t *s3)
{
    static uint8_t body[H2S_BODY1_LEN];
    static const char *const hdrs[] = { "Content-Type", "application/json", "ts-lb", "nodekey:00" };
    size_t i;
    for (i = 0; i < sizeof body; i++) body[i] = (uint8_t)('a' + i % 26);
    *s1 = *s3 = 0;
    (void)ts_h2_request(c, s1, "POST", "/machine/register", "control.example", hdrs, 2, body, sizeof body);
    (void)ts_h2_request(c, s3, "GET", "/x", "control.example", NULL, 0, NULL, 0);
}

/* A recorded server stream against h2s_open_two. Expected callbacks:
 *   h1:x-k=v; h1:content-type=application/json; H1:200; h3:x-k=v; H3:200;
 *   D3:b1; D1:{"a":1}; D3:b2; E3:0; D1:tail; h1:x-t=1; E1:0; G3:0;
 * It exercises settings (including an unknown one), PING, an unknown frame
 * type, HEADERS split by CONTINUATION, padding and priority on HEADERS, padded
 * DATA, a dynamic table entry shared across streams, trailers, a retroactive
 * window change and GOAWAY. out must hold 1024 bytes. */
static size_t h2s_recorded(uint8_t *out)
{
    static const uint32_t set[] = { 4, 1000, 5, 16384, 0x99, 5, 3, 100 };
    static const uint8_t ping[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t blk[128], p[64];
    size_t n = 0, bl = 0, k;

    n += h2s_settings(out + n, set, 4);
    n += h2s_frame(out + n, H2S_SETTINGS, H2S_ACK, 0, NULL, 0);
    n += h2s_u32(out + n, H2S_WINDOW, 0, 100000);
    n += h2s_frame(out + n, H2S_PING, 0, 0, ping, 8);
    n += h2s_frame(out + n, 0xfa, 0x3, 0, "zz", 2);

    /* :status 200, x-k: v (incremental indexing, so it becomes index 62), content-type. */
    blk[bl++] = 0x88;
    blk[bl++] = 0x40; blk[bl++] = 3; memcpy(blk + bl, "x-k", 3); bl += 3; blk[bl++] = 1; blk[bl++] = 'v';
    bl += ts_hpack_encode(blk + bl, sizeof blk - bl, "content-type", "application/json");
    k = 6;   /* split inside the x-k literal */
    n += h2s_frame(out + n, H2S_HEADERS, 0, 1, blk, k);
    n += h2s_frame(out + n, H2S_CONT, H2S_END_HEADERS, 1, blk + k, bl - k);

    /* Stream 3: padded, with priority, block 0x88 0xbe. */
    p[0] = 2;
    ts_put_be32(p + 1, 0); p[5] = 15;
    p[6] = 0x88; p[7] = 0xbe; p[8] = 0; p[9] = 0;
    n += h2s_frame(out + n, H2S_HEADERS, H2S_END_HEADERS | H2S_PADDED | H2S_PRIO, 3, p, 10);

    n += h2s_u32(out + n, H2S_WINDOW, 1, 2000);
    n += h2s_frame(out + n, H2S_DATA, 0, 3, "b1", 2);
    p[0] = 4; memcpy(p + 1, "{\"a\":1}", 7); memset(p + 8, 0, 4);
    n += h2s_frame(out + n, H2S_DATA, H2S_PADDED, 1, p, 12);
    n += h2s_frame(out + n, H2S_DATA, H2S_END_STREAM, 3, "b2", 2);
    n += h2s_frame(out + n, H2S_DATA, 0, 1, "tail", 4);
    bl = ts_hpack_encode(blk, sizeof blk, "x-t", "1");
    n += h2s_frame(out + n, H2S_HEADERS, H2S_END_HEADERS | H2S_END_STREAM, 1, blk, bl);
    n += h2s_goaway(out + n, 3, 0, "bye");
    return n;
}

#define H2S_RECORDED_LOG "h1:x-k=v;h1:content-type=application/json;H1:200;h3:x-k=v;H3:200;" \
    "D3:b1;D1:{\"a\":1};D3:b2;E3:0;D1:tail;h1:x-t=1;E1:0;G3:0;"
