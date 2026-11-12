#include "fuzz.h"

#include <string.h>

#include "../src/core/bytes.h"
#include "../src/crypto/blake2s.h"
#include "../src/wg/handshake.h"

#include "wg_vectors.inc"

/* Input: one mode byte, then a message (zero padded or truncated to size).
 *   mode & 3 == 0  an initiation to the responder: open_static, then
 *                  init_finish with the initiator's ss, create_resp, derive
 *   mode & 3 == 1  a response to a pending initiation: consume_resp, derive;
 *                  a rejected response must leave the handshake unchanged
 *   otherwise      a cookie reply against the last mac1 sent
 * Bit 7 recomputes a valid mac1 so mutations reach the DH and AEAD paths; for
 * responses bit 6 also sets the expected receiver index, and for cookie
 * replies bit 6 takes the last mac1 from the input's first 16 bytes. */

static int g_ready;
static ts_wg_static g_i, g_r;
static ts_wg_hs g_pending;   /* initiator after the vector initiation */
static uint8_t g_ss[32], g_init[TS_WG_INIT_LEN], g_resp[TS_WG_RESP_LEN];
static uint8_t g_cookie_reply[TS_WG_COOKIE_LEN];

static void unhex(uint8_t *out, const char *hex)
{
    size_t i;
    for (i = 0; hex[2 * i]; i++) {
        unsigned v = 0, k;
        for (k = 0; k < 2; k++) {
            char c = hex[2 * i + k];
            v = v * 16 + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
}

static void setup(void)
{
    uint8_t k[32], eph[32], ts[12], out[TS_WG_INIT_LEN];
    if (g_ready) return;
    unhex(k, WGV_I_STATIC_PRIV);
    ts_wg_static_init(&g_i, k);
    unhex(k, WGV_R_STATIC_PRIV);
    ts_wg_static_init(&g_r, k);
    unhex(g_ss, WGV_SS);
    unhex(eph, WGV_I_EPH_PRIV);
    unhex(ts, WGV_TAI64N);
    unhex(g_init, WGV_INIT);
    unhex(g_resp, WGV_RESP);
    unhex(g_cookie_reply, WGV_COOKIE_REPLY);
    TS_FUZZ_ASSERT(ts_wg_create_init(&g_pending, &g_i, g_r.pub, g_ss, WGV_I_INDEX, eph, ts,
                                     NULL, out) == 0);
    TS_FUZZ_ASSERT(memcmp(out, g_init, sizeof out) == 0);
    g_ready = 1;
}

static void set_mac1(uint8_t *msg, size_t len, const uint8_t key[32])
{
    ts_blake2s_ctx c;
    TS_FUZZ_ASSERT(ts_blake2s_init(&c, 16, key, 32) == 0);
    ts_blake2s_update(&c, msg, len);
    ts_blake2s_final(&c, msg + len);
}

static void fill(uint8_t *dst, size_t n, const uint8_t *src, size_t len)
{
    memset(dst, 0, n);
    memcpy(dst, src, len < n ? len : n);
}

static void target(const uint8_t *data, size_t len)
{
    uint8_t mode, peer[32], ts[12], send[32], recv[32], cookie[16], mac[16];
    uint8_t init[TS_WG_INIT_LEN], resp[TS_WG_RESP_LEN], cr[TS_WG_COOKIE_LEN];
    uint8_t eph[32];
    ts_wg_hs hs;
    uint32_t idx;

    setup();
    if (len < 1) return;
    mode = data[0];
    data++;
    len--;
    memset(eph, 0x5a, sizeof eph);

    switch (mode & 3) {
    case 0:
        fill(init, sizeof init, data, len);
        if (mode & 0x80) set_mac1(init, 116, g_r.mac1_key);
        if (ts_wg_init_open_static(&hs, &g_r, init, peer) != 0) {
            TS_FUZZ_ASSERT(hs.state == 0);
            return;
        }
        if (ts_wg_init_finish(&hs, g_ss, ts, &idx) != 0) {
            TS_FUZZ_ASSERT(hs.state == 0);
            return;
        }
        if (ts_wg_create_resp(&hs, 7, eph, (mode & 0x40) ? init : NULL, resp) == 0)
            ts_wg_derive(&hs, 0, send, recv);
        TS_FUZZ_ASSERT(hs.state == 0 || hs.state == 4);
        if (hs.state) ts_wg_derive(&hs, 0, send, recv);
        break;
    case 1:
        fill(resp, sizeof resp, data, len);
        if (mode & 0x40) ts_put_le32(resp + 8, WGV_I_INDEX);
        if (mode & 0x80) set_mac1(resp, 60, g_i.mac1_key);
        hs = g_pending;
        if (ts_wg_consume_resp(&hs, &g_i, resp, &idx) == 0) {
            ts_wg_derive(&hs, 1, send, recv);
        } else {
            TS_FUZZ_ASSERT(memcmp(&hs, &g_pending, sizeof hs) == 0);
        }
        break;
    default:
        fill(cr, sizeof cr, data, len);
        if (mode & 0x40) fill(mac, sizeof mac, data, len);
        else memcpy(mac, g_init + 116, 16);
        if (ts_wg_cookie_open(cookie, g_r.pub, mac, cr) != 0) {
            uint8_t acc = 0;
            size_t i;
            for (i = 0; i < 16; i++) acc |= cookie[i];
            TS_FUZZ_ASSERT(acc == 0);
        }
        break;
    }
}

void ts_fuzz_wg_handshake(void)
{
    enum { NS = 6 };
    uint8_t s[NS][1 + TS_WG_INIT_LEN];
    const uint8_t *seeds[NS];
    size_t lens[NS], i;

    setup();
    s[0][0] = 0x00; memcpy(s[0] + 1, g_init, TS_WG_INIT_LEN); lens[0] = 1 + TS_WG_INIT_LEN;
    s[1][0] = 0x80; memcpy(s[1] + 1, g_init, TS_WG_INIT_LEN); lens[1] = 1 + TS_WG_INIT_LEN;
    s[2][0] = 0x01; memcpy(s[2] + 1, g_resp, TS_WG_RESP_LEN); lens[2] = 1 + TS_WG_RESP_LEN;
    s[3][0] = 0xc1; memcpy(s[3] + 1, g_resp, TS_WG_RESP_LEN); lens[3] = 1 + TS_WG_RESP_LEN;
    s[4][0] = 0x02; memcpy(s[4] + 1, g_cookie_reply, TS_WG_COOKIE_LEN); lens[4] = 1 + TS_WG_COOKIE_LEN;
    s[5][0] = 0x42; memcpy(s[5] + 1, g_cookie_reply, TS_WG_COOKIE_LEN); lens[5] = 1 + TS_WG_COOKIE_LEN;
    for (i = 0; i < NS; i++) seeds[i] = s[i];
    ts_fuzz_run("wg_handshake", target, seeds, lens, NS, TS_FUZZ_DEFAULT_ITERS);
}
