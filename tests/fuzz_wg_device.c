#include "fuzz.h"

#include <string.h>

#include "../src/core/bytes.h"
#include "../src/crypto/blake2s.h"
#include "../src/filter/packet.h"
#include "../src/wg/device.h"
#include "../src/wg/handshake.h"

#include "wg_vectors.inc"

/* A fresh device B (the vector responder) with peer A (the vector initiator)
 * per input. B's random stream starts with the vector's responder index and
 * ephemeral, so WGV_INIT then WGV_TRANSPORT (or a seed sealed with the
 * vector keys) reach the keypair, replay and delivery paths.
 *
 * Input: records of op, len (2 bytes LE), then len bytes (truncated at the
 * end of input). The kind is (op & 0x3f) % 6; bits 6 and 7 are flags:
 *   kind == 0  ts_wg_receive from A
 *   kind == 1  ts_wg_receive from an unknown key
 *   kind == 2  tick: advance by len * 10 ms (len * 1000 ms if op & 0x80);
 *                no payload follows
 *   kind == 3  ts_wg_send_packet to A
 *   kind == 4  ts_wg_receive from A with a valid mac1 (initiation, response);
 *                with op & 0x40 a response's receiver is set to WGV_R_INDEX,
 *                B's sender index when its first random draw is its own
 *                initiation, so forged responses reach ts_wg_consume_resp
 *   kind == 5  remove A, then add it back
 * Checked: every delivered packet parses and has A's source; messages sent
 * are well-sized; DH work stays within the handshake budget. */

#define A_IP 0x64400001u

static int g_ready;
static uint8_t g_r_priv[32], g_a_pub[32], g_unknown[32], g_mac1_key[32];
static uint8_t g_script[36];
static size_t g_script_at;
static uint64_t g_rng;

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

static void cb_send(void *user, const uint8_t peer[32], const uint8_t *msg, size_t n)
{
    uint32_t t;
    (void)user;
    TS_FUZZ_ASSERT(memcmp(peer, g_a_pub, 32) == 0);
    TS_FUZZ_ASSERT(n >= 32);
    t = ts_get_le32(msg);
    TS_FUZZ_ASSERT((t == 1 && n == TS_WG_INIT_LEN) || (t == 2 && n == TS_WG_RESP_LEN) ||
                   (t == 4 && n % 16 == 0 && n <= 32 + TS_WG_MAX_PACKET + 15));
}

static void cb_deliver(void *user, const uint8_t peer[32], const uint8_t *ip, size_t n)
{
    ts_pkt p;
    (void)user;
    TS_FUZZ_ASSERT(memcmp(peer, g_a_pub, 32) == 0);
    TS_FUZZ_ASSERT(ts_pkt_parse(&p, ip, n) == 0);
    TS_FUZZ_ASSERT(p.src == A_IP && p.len == n);
}

static int cb_random(void *user, uint8_t *out, size_t n)
{
    size_t i;
    (void)user;
    if (g_script_at + n <= sizeof g_script) {
        memcpy(out, g_script + g_script_at, n);
        g_script_at += n;
        return 0;
    }
    for (i = 0; i < n; i++) {
        g_rng = g_rng * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = (uint8_t)(g_rng >> 56);
    }
    return 0;
}

static int64_t cb_wall(void *user, uint32_t *nsec)
{
    (void)user;
    *nsec = 0;
    return 1700000000;
}

static size_t cb_priority(void *user, const uint8_t peer[32], uint8_t *out, size_t cap)
{
    uint8_t disco[32];
    (void)user;
    (void)peer;
    if (cap < 53) return 0;
    memset(disco, 0x77, 32);
    return ts_pkt_tsmp_disco(out, 0x64400002u, A_IP, disco);
}

static const ts_wg_io IO = { cb_send, cb_deliver, cb_random, cb_wall, cb_priority };

static void setup(void)
{
    ts_wg_static r;
    if (g_ready) return;
    unhex(g_r_priv, WGV_R_STATIC_PRIV);
    unhex(g_a_pub, WGV_I_STATIC_PUB);
    ts_put_le32(g_script, WGV_R_INDEX);
    unhex(g_script + 4, WGV_R_EPH_PRIV);
    memset(g_unknown, 0x42, 32);
    ts_wg_static_init(&r, g_r_priv);
    memcpy(g_mac1_key, r.mac1_key, 32);
    ts_wipe(&r, sizeof r);
    g_ready = 1;
}

static void fix_mac1(uint8_t *m, size_t n)
{
    size_t at;
    ts_blake2s_ctx c;
    if (n == TS_WG_INIT_LEN) at = 116;
    else if (n == TS_WG_RESP_LEN) at = 60;
    else return;
    ts_blake2s_init(&c, 16, g_mac1_key, 32);
    ts_blake2s_update(&c, m, at);
    ts_blake2s_final(&c, m + at);
}

static void target(const uint8_t *in, size_t n)
{
    static uint8_t buf[65536 + 16];
    ts_wg_dev *d;
    int64_t now = 1000, start = 1000;
    size_t at = 0;

    setup();
    g_script_at = 0;
    g_rng = 0x1234567;
    ts_wg_test_dh_count = 0;
    d = ts_wg_new(g_r_priv, &IO, NULL);
    TS_FUZZ_ASSERT(d != NULL);
    ts_wg_tick(d, now);
    TS_FUZZ_ASSERT(ts_wg_set_peer(d, g_a_pub, A_IP) == 0);

    while (at + 3 <= n) {
        uint8_t op = in[at];
        unsigned kind = (op & 0x3fu) % 6;
        size_t len = ts_get_le16(in + at + 1);
        const uint8_t *data = in + at + 3;
        at += 3;
        if (kind != 2) {
            if (len > n - at) len = n - at;
            at += len;
        }
        switch (kind) {
        case 0:
            ts_wg_receive(d, g_a_pub, data, len);
            break;
        case 1:
            ts_wg_receive(d, g_unknown, data, len);
            break;
        case 2:
            now += (int64_t)len * ((op & 0x80) ? 1000 : 10);
            ts_wg_tick(d, now);
            break;
        case 3:
            ts_wg_send_packet(d, g_a_pub, data, len);
            break;
        case 4:
            if (len <= sizeof buf) {
                memcpy(buf, data, len);
                if ((op & 0x40) && len == TS_WG_RESP_LEN) ts_put_le32(buf + 8, WGV_R_INDEX);
                fix_mac1(buf, len);
                ts_wg_receive(d, g_a_pub, buf, len);
            }
            break;
        default:
            ts_wg_remove_peer(d, g_a_pub);
            TS_FUZZ_ASSERT(ts_wg_set_peer(d, g_a_pub, A_IP) == 0);
            break;
        }
        /* An accepted initiation costs 3 DH, a response 2; at most
         * TS_WG_HS_PER_SEC of them in any second. */
        TS_FUZZ_ASSERT(ts_wg_test_dh_count <=
                       3ul * TS_WG_HS_PER_SEC * (unsigned long)((now - start) / 1000 + 1));
    }
    ts_wg_free(d);
}

static size_t rec(uint8_t *out, uint8_t op, const uint8_t *data, size_t len)
{
    out[0] = op;
    ts_put_le16(out + 1, (uint16_t)len);
    if (!data) return 3;   /* a tick: the amount is the length field */
    memcpy(out + 3, data, len);
    return 3 + len;
}

void ts_fuzz_wg_device(void)
{
    static uint8_t s1[512], s2[512], s3[512], s4[512];
    const uint8_t *seeds[4];
    size_t lens[4], k;
    uint8_t init[TS_WG_INIT_LEN], tr[48], key[32], ip[28], tr2[64], resp[TS_WG_RESP_LEN];
    uint8_t cookie[TS_WG_COOKIE_LEN];

    setup();
    unhex(init, WGV_INIT);
    unhex(tr, WGV_TRANSPORT);
    unhex(resp, WGV_RESP);
    unhex(cookie, WGV_COOKIE_REPLY);
    /* A valid IPv4 packet from A, sealed with the vector's initiator key at counter 1. */
    memset(ip, 0, sizeof ip);
    ip[0] = 0x45;
    ts_put_be16(ip + 2, 28);
    ip[8] = 64;
    ip[9] = 1;
    ts_put_be32(ip + 12, A_IP);
    ts_put_be32(ip + 16, 0x64400002u);
    ip[20] = 8;
    unhex(key, WGV_I_SEND);
    ts_wg_transport_seal(tr2, key, WGV_R_INDEX, 1, ip, sizeof ip);

    k = rec(s1, 0, init, sizeof init);
    k += rec(s1 + k, 0, tr, sizeof tr);
    k += rec(s1 + k, 0, tr2, sizeof tr2);
    k += rec(s1 + k, 2, NULL, 30);
    k += rec(s1 + k, 0, tr2, sizeof tr2);
    lens[0] = k;

    k = rec(s2, 0, init, sizeof init);
    k += rec(s2 + k, 0, tr2, sizeof tr2);
    k += rec(s2 + k, 0x82, NULL, 200);
    k += rec(s2 + k, 3, ip, sizeof ip);
    k += rec(s2 + k, 0x82, NULL, 6);
    k += rec(s2 + k, 0, cookie, sizeof cookie);
    lens[1] = k;

    k = rec(s3, 3, ip, sizeof ip);
    k += rec(s3 + k, 4 | 0x40, resp, sizeof resp);
    k += rec(s3 + k, 0, cookie, sizeof cookie);
    k += rec(s3 + k, 2, NULL, 255);
    k += rec(s3 + k, 4, init, sizeof init);
    lens[2] = k;

    k = rec(s4, 1, init, sizeof init);
    k += rec(s4 + k, 4, init, sizeof init);
    k += rec(s4 + k, 5, NULL, 0);
    k += rec(s4 + k, 0, tr2, sizeof tr2);
    lens[3] = k;

    seeds[0] = s1;
    seeds[1] = s2;
    seeds[2] = s3;
    seeds[3] = s4;
    ts_fuzz_run("wg_device", target, seeds, lens, 4, TS_FUZZ_DEFAULT_ITERS);
}
