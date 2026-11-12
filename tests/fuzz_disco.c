#include "fuzz.h"

#include <stdlib.h>
#include <string.h>

#include "../src/crypto/nacl.h"
#include "../src/crypto/x25519.h"
#include "../src/disco/disco.h"

/* Disco packets from a relay, opened with a fixed shared key.
 *
 * Input: byte 0 picks the mode. Even: the rest is a whole packet, fed to
 * ts_disco_looks_like and ts_disco_open (mostly forged boxes, so this covers
 * the header and length checks). Odd: the rest is a plaintext, sealed under
 * the shared key into a buffer of exactly the packet's length and opened, so
 * the parser sees arbitrary authentic plaintexts; the result must match the
 * parse rules (version 0, ping payload >= 12, pong payload >= 30) and the
 * fields must be the plaintext's bytes. Keys are made up. */

#define MY_PRIV   "b0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9e6f"
#define PEER_PRIV "28394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f50657"

static ts_disco_shared g_s;
static uint8_t g_peer_pub[32];
static const uint8_t NONCE[24] = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                   0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
                                   0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };

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

static void touch(const ts_disco_msg *m)
{
    volatile uint8_t t = 0;
    size_t i;
    for (i = 0; i < sizeof m->txid; i++) t ^= m->txid[i];
    for (i = 0; i < sizeof m->node_key; i++) t ^= m->node_key[i];
    for (i = 0; i < sizeof m->src_ip16; i++) t ^= m->src_ip16[i];
    t ^= (uint8_t)(m->type ^ m->have_node_key ^ m->src_port);
    (void)t;
}

static int nonzero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (p[i]) return 1;
    return 0;
}

static void raw_packet(const uint8_t *p, size_t n)
{
    ts_disco_msg m;
    int looks = ts_disco_looks_like(p, n);
    if (looks) {
        volatile uint8_t t = ts_disco_sender(p)[31];
        (void)t;
    }
    if (ts_disco_open(&m, p, n, &g_s) == 0) {
        TS_FUZZ_ASSERT(looks && n >= 80 && n <= TS_DISCO_MAX);
        touch(&m);
    }
}

static void sealed_plain(const uint8_t *plain, size_t plen)
{
    ts_disco_msg m;
    uint8_t *p;
    size_t n;
    int want, r;

    if (plen > TS_DISCO_MAX - 78) plen = TS_DISCO_MAX - 78;
    n = 78 + plen;
    p = malloc(n);
    if (!p) return;
    memcpy(p, "\x54\x53\xf0\x9f\x92\xac", 6);
    memcpy(p + 6, g_peer_pub, 32);
    memcpy(p + 38, NONCE, 24);
    ts_secretbox_seal(p + 62, g_s.k, NONCE, plain, plen);

    want = plen >= 2 && plain[1] == 0;
    if (want && plain[0] == TS_DISCO_PING) want = plen >= 14;
    if (want && plain[0] == TS_DISCO_PONG) want = plen >= 32;
    r = ts_disco_open(&m, p, n, &g_s);
    TS_FUZZ_ASSERT(r == (want ? 0 : -1));
    if (r == 0) {
        touch(&m);
        TS_FUZZ_ASSERT(m.type == plain[0]);
        if (m.type == TS_DISCO_PING) {
            int key = plen >= 46 && nonzero(plain + 14, 32);
            TS_FUZZ_ASSERT(memcmp(m.txid, plain + 2, 12) == 0);
            TS_FUZZ_ASSERT(m.have_node_key == key);
            if (key) TS_FUZZ_ASSERT(memcmp(m.node_key, plain + 14, 32) == 0);
        } else if (m.type == TS_DISCO_PONG) {
            TS_FUZZ_ASSERT(memcmp(m.txid, plain + 2, 12) == 0);
            TS_FUZZ_ASSERT(memcmp(m.src_ip16, plain + 14, 16) == 0);
            TS_FUZZ_ASSERT(m.src_port == (uint16_t)(plain[30] << 8 | plain[31]));
            TS_FUZZ_ASSERT(!m.have_node_key);
        }
    }
    free(p);
}

static void target(const uint8_t *in, size_t n)
{
    if (n == 0) return;
    if (in[0] & 1)
        sealed_plain(in + 1, n - 1);
    else
        raw_packet(in + 1, n - 1);
}

void ts_fuzz_disco(void);

void ts_fuzz_disco(void)
{
    static uint8_t s1[1 + TS_DISCO_PING_LEN], s2[1 + TS_DISCO_PONG_LEN], s3[1 + 64], s4[1 + 32],
        s5[1 + 40];
    const uint8_t *seeds[5];
    size_t lens[5];
    uint8_t my_priv[32], peer_priv[32], my_pub[32], txid[12], node[32], ip[16];
    ts_disco_shared peer;
    ts_disco_msg m;

    unhex(my_priv, MY_PRIV);
    unhex(peer_priv, PEER_PRIV);
    ts_x25519_public(my_pub, my_priv);
    ts_x25519_public(g_peer_pub, peer_priv);
    ts_disco_shared_init(&g_s, my_priv, g_peer_pub);
    ts_disco_shared_init(&peer, peer_priv, my_pub);
    memset(txid, 0x3c, sizeof txid);
    memset(node, 0x4d, sizeof node);
    memset(ip, 0, sizeof ip);
    ip[10] = ip[11] = 0xff;
    ip[12] = 127; ip[13] = 3; ip[14] = 3; ip[15] = 40;

    /* Whole packets from the peer. */
    s1[0] = 0;
    if (ts_disco_seal_ping(s1 + 1, TS_DISCO_PING_LEN, g_peer_pub, &peer, NONCE, txid, node) !=
        TS_DISCO_PING_LEN || ts_disco_open(&m, s1 + 1, TS_DISCO_PING_LEN, &g_s) != 0)
        ts_fuzz_fail("seed ping opens", __FILE__, __LINE__);
    lens[0] = sizeof s1;
    s2[0] = 2;
    if (ts_disco_seal_pong(s2 + 1, TS_DISCO_PONG_LEN, g_peer_pub, &peer, NONCE, txid, ip, 7) !=
        TS_DISCO_PONG_LEN || ts_disco_open(&m, s2 + 1, TS_DISCO_PONG_LEN, &g_s) != 0)
        ts_fuzz_fail("seed pong opens", __FILE__, __LINE__);
    lens[1] = sizeof s2;

    /* Plaintexts: a padded ping, a pong, an unknown type. */
    memset(s3, 0, sizeof s3);
    s3[0] = 1;
    s3[1] = TS_DISCO_PING;
    memcpy(s3 + 3, txid, 12);
    memcpy(s3 + 15, node, 32);
    lens[2] = sizeof s3;
    s4[0] = 3;
    s4[1] = TS_DISCO_PONG;
    s4[2] = 0;
    memcpy(s4 + 3, txid, 12);
    memcpy(s4 + 15, ip, 16);
    s4[31] = 0;
    s4[32] = 7;
    lens[3] = sizeof s4;
    memset(s5, 0x44, sizeof s5);
    s5[0] = 5;
    s5[1] = 3;
    s5[2] = 0;
    lens[4] = sizeof s5;

    seeds[0] = s1;
    seeds[1] = s2;
    seeds[2] = s3;
    seeds[3] = s4;
    seeds[4] = s5;
    ts_fuzz_run("disco", target, seeds, lens, 5, TS_FUZZ_DEFAULT_ITERS);
}
