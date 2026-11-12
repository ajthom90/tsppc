#include "fuzz.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/control/netmap.h"
#include "../src/core/bytes.h"
#include "../src/crypto/nacl.h"
#include "../src/crypto/x25519.h"
#include "../src/data/dataplane.h"
#include "../src/disco/disco.h"

/* Disco packets from a relay into one long-lived data plane with one peer,
 * through a minimal in-harness relay (101, ServerKey, ServerInfo; everything
 * the data plane sends is captured). The clock moves 1 s per input, so the
 * pong limits and the DH budget refill and the answer paths stay reachable;
 * one ping of ours is kept outstanding with a fixed TxID (the randomness is
 * reset before each ts_dp_ping), so authentic pongs can match it.
 *
 * Input: byte 0 picks the mode, byte 1 the frame source (bit 0: a stranger
 * instead of the peer). Mode 0: magic and the peer's disco key, then the rest
 * (nonce and box). Mode 1: the rest is a plaintext, sealed with the peer's
 * disco key. Mode 2: the rest is the whole packet. Mode 3: a pong plaintext
 * with our outstanding TxID, then the rest, sealed with the peer's key.
 * Checked: whatever the data plane sends over the relay to anyone is the
 * DERP handshake or a SendPacket to the peer holding an authentic ping or
 * pong under the peer's disco key; results name region 1 and a known status.
 * Keys are made up. */

#define SELF_PRIV  "c8e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e48"
#define SELF_DISCO "d0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e50"
#define PEER_PRIV  "e0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e58"
#define PEER_DISCO "f8a9bacbdcedfe0f1021324354657687f8a9bacbdcedfe0f1021324354657660"
#define SERVER_PRIV "18e2d4c6b8a0f1e3d5c7b9a1f2e4d6c8b0a1c3e5f7092b4d6f8a1c3e5f709250"
#define SELF_IP 0x64400001u   /* 100.64.0.1 */
#define PEER_IP 0x64400002u   /* 100.64.0.2 */
#define BUF (64 * 1024)

typedef struct {
    int dialed, up, http_done, ready;
    size_t n;
    uint8_t b[BUF];
} fslot;

static ts_dp *g_dp;
static ts_netmap g_m;
static fslot g_s[TS_DP_MAX_CONNS];
static uint8_t g_self_priv[32], g_self_pub[32], g_self_dpriv[32], g_self_dpub[32];
static uint8_t g_peer_priv[32], g_peer_pub[32], g_peer_dpriv[32], g_peer_dpub[32];
static uint8_t g_srv_priv[32], g_srv_pub[32], g_stranger[32];
static ts_disco_shared g_peer_sh;    /* the peer's side: peer disco priv, our disco pub */
static uint8_t g_txid[12];
static int g_have_txid, g_outstanding;
static uint64_t g_rng;
static int64_t g_now = 1000000;
static uint8_t g_out[BUF + 64];
static const uint8_t MAGIC[6] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };
static const uint8_t NONCE[24] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

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

static void tohex(char *out, const uint8_t *k)
{
    static const char d[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) {
        out[2 * i] = d[k[i] >> 4];
        out[2 * i + 1] = d[k[i] & 15];
    }
    out[64] = 0;
}

/* ---- Data plane callbacks ------------------------------------------------- */

static int cb_dial(void *u, int i, const ts_derp_node *node)
{
    (void)u;
    (void)node;
    TS_FUZZ_ASSERT(i >= 0 && i < TS_DP_MAX_CONNS);
    memset(&g_s[i], 0, offsetof(fslot, b));
    g_s[i].dialed = 1;
    return 0;
}

static int cb_send(void *u, int i, const uint8_t *p, size_t n)
{
    fslot *s = &g_s[i];
    (void)u;
    TS_FUZZ_ASSERT(s->dialed && s->up);
    if (s->n + n > BUF) return -1;
    memcpy(s->b + s->n, p, n);
    s->n += n;
    return 0;
}

static void cb_close(void *u, int i)
{
    (void)u;
    memset(&g_s[i], 0, offsetof(fslot, b));
}

static void cb_tun(void *u, const uint8_t *ip, size_t n)
{
    (void)u;
    (void)ip;
    (void)n;
}

static int cb_random(void *u, uint8_t *out, size_t n)
{
    size_t i;
    (void)u;
    for (i = 0; i < n; i++) {
        g_rng = g_rng * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = (uint8_t)(g_rng >> 56);
    }
    return 0;
}

static int64_t cb_wall(void *u, uint32_t *nsec)
{
    (void)u;
    if (nsec) *nsec = 0;
    return 1800000000;
}

static void cb_result(void *u, uint64_t cookie, int status, uint32_t latency_us, int region)
{
    (void)u;
    (void)latency_us;
    TS_FUZZ_ASSERT(cookie == 7 && region == 1);
    TS_FUZZ_ASSERT(status == TS_DP_PONG || status == TS_DP_PING_TIMEOUT || status == TS_DP_PING_STOPPED);
    g_outstanding = 0;
}

static const ts_dp_io IO = { cb_dial, cb_send, cb_close, cb_tun, cb_random, cb_wall, cb_result };

/* ---- The relay -------------------------------------------------------------- */

static size_t frame(uint8_t *out, int type, const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    out[0] = (uint8_t)type;
    ts_put_be32(out + 1, (uint32_t)(an + bn));
    if (an) memcpy(out + 5, a, an);
    if (bn) memcpy(out + 5 + an, b, bn);
    return 5 + an + bn;
}

/* A SendPacket from the data plane: only to the peer, only an authentic ping
 * or pong under the peer's disco key. */
static void check_send(const uint8_t *body, size_t len)
{
    ts_disco_msg m;
    TS_FUZZ_ASSERT(len >= 32 && memcmp(body, g_peer_pub, 32) == 0);
    body += 32;
    len -= 32;
    TS_FUZZ_ASSERT(len == TS_DISCO_PING_LEN || len == TS_DISCO_PONG_LEN);
    TS_FUZZ_ASSERT(memcmp(ts_disco_sender(body), g_self_dpub, 32) == 0);
    TS_FUZZ_ASSERT(ts_disco_open(&m, body, len, &g_peer_sh) == 0);
    if (len == TS_DISCO_PING_LEN) {
        TS_FUZZ_ASSERT(m.type == TS_DISCO_PING && m.have_node_key && memcmp(m.node_key, g_self_pub, 32) == 0);
        memcpy(g_txid, m.txid, 12);
        g_have_txid = 1;
    } else {
        TS_FUZZ_ASSERT(m.type == TS_DISCO_PONG && m.src_port == 1);
    }
}

/* Answer what each connection sent, until nothing more happens. */
static void serve(void)
{
    static const char resp[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n"
                               "Connection: Upgrade\r\nDerp-Version: 2\r\n\r\n";
    static const char sj[] = "{\"version\":2}";
    int round, i, busy = 1;
    for (round = 0; round < 50 && busy; round++) {
        busy = 0;
        for (i = 0; i < TS_DP_MAX_CONNS; i++) {
            fslot *s = &g_s[i];
            size_t at = 0, on = 0;
            if (!s->dialed) continue;
            if (!s->up) {
                s->up = 1;
                busy = 1;
                ts_dp_conn_up(g_dp, i);
                continue;
            }
            if (!s->http_done) {
                size_t k;
                uint8_t sk[40];
                for (k = 0; k + 4 <= s->n; k++)
                    if (memcmp(s->b + k, "\r\n\r\n", 4) == 0) break;
                if (k + 4 > s->n) continue;
                at = k + 4;
                s->http_done = 1;
                memcpy(g_out, resp, sizeof resp - 1);
                on = sizeof resp - 1;
                memcpy(sk, "DERP\xf0\x9f\x94\x91", 8);
                memcpy(sk + 8, g_srv_pub, 32);
                on += frame(g_out + on, TS_DERP_SERVER_KEY, sk, 40, NULL, 0);
            }
            while (s->n - at >= 5) {
                uint32_t len = ts_get_be32(s->b + at + 1);
                const uint8_t *body = s->b + at + 5;
                if (s->n - at - 5 < len) break;
                if (s->b[at] == TS_DERP_CLIENT_INFO) {
                    uint8_t info[24 + 16 + sizeof sj];
                    TS_FUZZ_ASSERT(len >= 32 && memcmp(body, g_self_pub, 32) == 0);
                    memset(info, 0x40, 24);
                    ts_box_seal(info + 24, info, g_self_pub, g_srv_priv, (const uint8_t *)sj, sizeof sj - 1);
                    on += frame(g_out + on, TS_DERP_SERVER_INFO, info, 24 + 16 + sizeof sj - 1, NULL, 0);
                    s->ready = 1;
                } else if (s->b[at] == TS_DERP_SEND_PACKET) {
                    check_send(body, len);
                }
                at += 5 + len;
            }
            memmove(s->b, s->b + at, s->n - at);
            s->n -= at;
            if (on) {
                busy = 1;
                ts_dp_conn_recv(g_dp, i, g_out, on);
            }
        }
    }
}

static int ready_slot(void)
{
    int i;
    for (i = 0; i < TS_DP_MAX_CONNS; i++)
        if (g_s[i].dialed && g_s[i].up && g_s[i].ready) return i;
    return -1;
}

/* Keep one ping outstanding, always with the same TxID. */
static void keep_ping(void)
{
    uint64_t save = g_rng;
    if (g_outstanding) return;
    g_rng = 0x1234;
    if (ts_dp_ping(g_dp, PEER_IP, 3000000000u, 7, g_now) == 0) g_outstanding = 1;
    g_rng = save ^ 0x9e3779b97f4a7c15ull;
    serve();
}

static void setup(void)
{
    char json[2048], self_k[65], peer_k[65], peer_d[65];
    int n;

    unhex(g_self_priv, SELF_PRIV);
    unhex(g_self_dpriv, SELF_DISCO);
    unhex(g_peer_priv, PEER_PRIV);
    unhex(g_peer_dpriv, PEER_DISCO);
    unhex(g_srv_priv, SERVER_PRIV);
    ts_x25519_public(g_self_pub, g_self_priv);
    ts_x25519_public(g_self_dpub, g_self_dpriv);
    ts_x25519_public(g_peer_pub, g_peer_priv);
    ts_x25519_public(g_peer_dpub, g_peer_dpriv);
    ts_x25519_public(g_srv_pub, g_srv_priv);
    memset(g_stranger, 0x5a, 32);
    ts_disco_shared_init(&g_peer_sh, g_peer_dpriv, g_self_dpub);

    g_dp = ts_dp_new(&IO, NULL);
    if (!g_dp || ts_netmap_init(&g_m) != 0) ts_fuzz_fail("setup: memory", __FILE__, __LINE__);
    ts_dp_tick(g_dp, g_now);
    if (ts_dp_start(g_dp, g_self_priv, g_self_dpriv, SELF_IP) != 0) ts_fuzz_fail("setup: start", __FILE__, __LINE__);
    ts_dp_tick(g_dp, g_now);
    tohex(self_k, g_self_pub);
    tohex(peer_k, g_peer_pub);
    tohex(peer_d, g_peer_dpub);
    n = snprintf(json, sizeof json,
                 "{\"Node\":{\"ID\":1,\"Key\":\"nodekey:%s\",\"Addresses\":[\"100.64.0.1/32\"],\"HomeDERP\":1},"
                 "\"Peers\":[{\"ID\":2,\"Key\":\"nodekey:%s\",\"DiscoKey\":\"discokey:%s\","
                 "\"Addresses\":[\"100.64.0.2/32\"],\"HomeDERP\":1,\"Online\":true,\"MachineAuthorized\":true}],"
                 "\"DERPMap\":{\"Regions\":{\"1\":{\"RegionCode\":\"r1\",\"Nodes\":[{\"Name\":\"1a\","
                 "\"HostName\":\"r1.derp.test\",\"IPv4\":\"192.0.2.1\"}]}}},\"KeepAlive\":false}",
                 self_k, peer_k, peer_d);
    if (n <= 0 || (size_t)n >= sizeof json || ts_netmap_apply(&g_m, json, (size_t)n) != 0)
        ts_fuzz_fail("setup: map", __FILE__, __LINE__);
    ts_dp_set_netmap(g_dp, &g_m);
    ts_dp_set_home(g_dp, 1);
    serve();
    if (ready_slot() < 0) ts_fuzz_fail("setup: relay not ready", __FILE__, __LINE__);
    keep_ping();
    if (!g_outstanding || !g_have_txid) ts_fuzz_fail("setup: ping", __FILE__, __LINE__);
}

static uint8_t g_pkt[8192 + 128], g_fr[8192 + 256];

static void target(const uint8_t *in, size_t n)
{
    const uint8_t *rest;
    size_t rn, pn = 0, fn;
    int slot;

    if (n < 2) return;
    rest = in + 2;
    rn = n - 2;
    g_now += 1000;
    ts_dp_tick(g_dp, g_now);
    serve();
    keep_ping();
    slot = ready_slot();
    if (slot < 0) return;
    switch (in[0] & 3) {
    case 0:
        memcpy(g_pkt, MAGIC, 6);
        memcpy(g_pkt + 6, g_peer_dpub, 32);
        memcpy(g_pkt + 38, rest, rn);
        pn = 38 + rn;
        break;
    case 1:
    case 3: {
        size_t at = 62 + 16;
        memcpy(g_pkt, MAGIC, 6);
        memcpy(g_pkt + 6, g_peer_dpub, 32);
        memcpy(g_pkt + 38, NONCE, 24);
        if ((in[0] & 3) == 3) {
            g_pkt[at] = TS_DISCO_PONG;
            g_pkt[at + 1] = 0;
            memcpy(g_pkt + at + 2, g_txid, 12);
            memcpy(g_pkt + at + 14, rest, rn);
            ts_secretbox_seal(g_pkt + 62, g_peer_sh.k, NONCE, g_pkt + at, 14 + rn);
            pn = at + 14 + rn;
        } else {
            memcpy(g_pkt + at, rest, rn);
            ts_secretbox_seal(g_pkt + 62, g_peer_sh.k, NONCE, g_pkt + at, rn);
            pn = at + rn;
        }
        break;
    }
    default:
        memcpy(g_pkt, rest, rn);
        pn = rn;
        break;
    }
    fn = frame(g_fr, TS_DERP_RECV_PACKET, (in[1] & 1) ? g_stranger : g_peer_pub, 32, g_pkt, pn);
    ts_dp_conn_recv(g_dp, slot, g_fr, fn);
    serve();
}

void ts_fuzz_dp_disco(void);

void ts_fuzz_dp_disco(void)
{
    static uint8_t s0[2 + 46], s1[2 + 18], s2[2 + 32], s3[2 + 80], s4[2 + 20], s5[2 + 46];
    const uint8_t *seeds[6];
    size_t lens[6];

    setup();
    /* A ping from the peer (with its node key), as a plaintext. */
    memset(s0, 0, sizeof s0);
    s0[0] = 1;
    s0[2] = TS_DISCO_PING;
    memset(s0 + 4, 0x3c, 12);
    memcpy(s0 + 16, g_peer_pub, 32);
    /* The rest of a pong for our ping. */
    memset(s1, 0, sizeof s1);
    s1[0] = 3;
    s1[12] = s1[13] = 0xff;
    s1[14] = 127;
    s1[15] = s1[16] = 3;
    s1[17] = 40;
    s1[19] = 1;
    /* A pong with an unknown TxID. */
    memset(s2, 0x11, sizeof s2);
    s2[0] = 1;
    s2[1] = 0;
    s2[2] = TS_DISCO_PONG;
    s2[3] = 0;
    /* Nonce and box of noise. */
    memset(s3, 0x6b, sizeof s3);
    s3[0] = 0;
    s3[1] = 0;
    /* CallMeMaybe. */
    memset(s4, 0, sizeof s4);
    s4[0] = 1;
    s4[2] = 3;
    /* The peer's ping from a stranger's frame. */
    memcpy(s5, s0, sizeof s5);
    s5[1] = 1;

    seeds[0] = s0; lens[0] = sizeof s0;
    seeds[1] = s1; lens[1] = sizeof s1;
    seeds[2] = s2; lens[2] = sizeof s2;
    seeds[3] = s3; lens[3] = sizeof s3;
    seeds[4] = s4; lens[4] = sizeof s4;
    seeds[5] = s5; lens[5] = sizeof s5;
    ts_fuzz_run("dp_disco", target, seeds, lens, 6, TS_FUZZ_DEFAULT_ITERS);
    {
        ts_dp_status st;
        ts_dp_get_status(g_dp, &st);
        if (st.pongs_sent == 0 || st.pongs_in == 0 || st.disco_bad == 0)
            ts_fuzz_fail("dp_disco: the answer and match paths were not reached", __FILE__, __LINE__);
    }
    ts_dp_free(g_dp);
    g_dp = NULL;
    ts_netmap_free(&g_m);
}
