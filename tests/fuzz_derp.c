#include "fuzz.h"

#include <string.h>

#include "../src/core/bytes.h"
#include "../src/crypto/nacl.h"
#include "../src/crypto/x25519.h"
#include "../src/derp/derp.h"

/* A relay stream from a fake server whose key the fuzzer holds (so seeds get
 * past the handshake), fed to a fresh client per input.
 *
 * Input: byte 0 seeds the chunking; the rest is the server stream, fed in
 * pseudo-random chunks of 1 to 2048 bytes, with the clock moving between
 * chunks (sometimes past the timeouts). While ready, the client also sends a
 * packet and a ping. Checked: delivered packets fit TS_DERP_MAX_PACKET, health
 * text is at most 200 printable bytes, every send is the request or one whole
 * well-formed frame, and death is sticky. Keys are made up. */

#define CLIENT_PRIV "a8f1c3d2e4b5a6978899aabbccddeeff00112233445566778899aabbccddee40"
#define SERVER_PRIV "18e2d4c6b8a0f1e3d5c7b9a1f2e4d6c8b0a1c3e5f7092b4d6f8a1c3e5f709250"
#define OTHER_PRIV "60a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e4f"

static ts_derp g_d;
static uint8_t g_c_priv[32], g_c_pub[32], g_s_priv[32], g_s_pub[32], g_o_priv[32];
static int g_nsend;

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

static void cb_send(void *user, const uint8_t *p, size_t n)
{
    uint32_t len;
    (void)user;
    if (g_nsend++ == 0) {
        TS_FUZZ_ASSERT(n > 4 && memcmp(p, "GET ", 4) == 0);
        return;
    }
    TS_FUZZ_ASSERT(n >= 5);
    len = ts_get_be32(p + 1);
    TS_FUZZ_ASSERT(n == 5 + (size_t)len);
    switch (p[0]) {
    case TS_DERP_CLIENT_INFO: TS_FUZZ_ASSERT(len == 104); break;
    case TS_DERP_PONG: TS_FUZZ_ASSERT(len == 8); break;
    case TS_DERP_PING: TS_FUZZ_ASSERT(len == 8); break;
    case TS_DERP_NOTE_PREFERRED: TS_FUZZ_ASSERT(len == 1 && p[5] <= 1); break;
    case TS_DERP_SEND_PACKET: TS_FUZZ_ASSERT(len >= 32 && len <= 32 + TS_DERP_MAX_PACKET); break;
    default: TS_FUZZ_ASSERT(0);
    }
}

static void cb_recv(void *user, const uint8_t src[32], const uint8_t *p, size_t n)
{
    (void)user;
    (void)src;
    TS_FUZZ_ASSERT(n <= TS_DERP_MAX_PACKET);
    if (n) {
        volatile uint8_t touch = (uint8_t)(p[0] ^ p[n - 1]);   /* in bounds for ASan */
        (void)touch;
    }
}

static void cb_gone(void *user, const uint8_t key[32])
{
    (void)user;
    (void)key;
}

static void cb_health(void *user, const char *text)
{
    size_t i, n = strlen(text);
    (void)user;
    TS_FUZZ_ASSERT(n <= TS_DERP_HEALTH_MAX);
    for (i = 0; i < n; i++)
        TS_FUZZ_ASSERT((unsigned char)text[i] >= 0x20 && (unsigned char)text[i] < 0x7f);
}

static void cb_pong(void *user, const uint8_t data[8])
{
    (void)user;
    (void)data;
}

static const ts_derp_io IO = { cb_send, cb_recv, cb_gone, cb_health, cb_pong };

static void target(const uint8_t *in, size_t n)
{
    uint32_t rng;
    int64_t now = 1000;
    size_t at = 1;
    int dead = 0;
    static const uint8_t pkt[40] = { 0x45 };

    if (n == 0) return;
    rng = 0x9e3779b9u ^ in[0];
    g_nsend = 0;
    ts_derp_init(&g_d, "derp.example.net", g_c_priv, in[0] & 1, &IO, NULL);
    ts_derp_start(&g_d, now);
    while (at < n) {
        size_t k;
        int rc;
        rng = rng * 1103515245u + 12345u;
        k = 1 + (rng >> 8) % ((rng & 0x80000000u) ? 2048 : 64);
        if (k > n - at) k = n - at;
        rc = ts_derp_feed(&g_d, in + at, k, now);
        at += k;
        if (dead) TS_FUZZ_ASSERT(rc == -1);
        if (rc != 0) {
            dead = 1;
            TS_FUZZ_ASSERT(g_d.err != NULL && !ts_derp_ready(&g_d));
            TS_FUZZ_ASSERT(ts_derp_tick(&g_d, now) == -1);
            TS_FUZZ_ASSERT(ts_derp_send_packet(&g_d, g_s_pub, pkt, sizeof pkt) == -1);
        }
        if (ts_derp_ready(&g_d)) {
            TS_FUZZ_ASSERT(ts_derp_send_packet(&g_d, g_s_pub, pkt, sizeof pkt) == 0);
            TS_FUZZ_ASSERT(ts_derp_ping(&g_d, pkt) == 0);
            ts_derp_note_preferred(&g_d, (int)(rng >> 3) & 1);
        }
        now += (rng & 0x7000) ? 1000 : 40000;
        if (ts_derp_tick(&g_d, now) != 0) {
            dead = 1;
            TS_FUZZ_ASSERT(!ts_derp_ready(&g_d));
        }
    }
    ts_derp_free(&g_d);
}

static void frame(uint8_t *out, size_t *at, int type, const uint8_t *body, size_t n)
{
    out[*at] = (uint8_t)type;
    ts_put_be32(out + *at + 1, (uint32_t)n);
    if (n) memcpy(out + *at + 5, body, n);
    *at += 5 + n;
}

static void put(uint8_t *out, size_t *at, const char *s)
{
    size_t n = strlen(s);
    memcpy(out + *at, s, n);
    *at += n;
}

static void greeting(uint8_t *out, size_t *at, const uint8_t info_priv[32])
{
    static const char json[] = "{\"version\":2}";
    uint8_t b[40], info[24 + 16 + sizeof json];
    size_t i;
    put(out, at, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n");
    memcpy(b, "DERP\xf0\x9f\x94\x91", 8);
    memcpy(b + 8, g_s_pub, 32);
    frame(out, at, TS_DERP_SERVER_KEY, b, 40);
    for (i = 0; i < 24; i++) info[i] = (uint8_t)(0xa0 + i);
    ts_box_seal(info + 24, info, g_c_pub, info_priv, (const uint8_t *)json, sizeof json - 1);
    frame(out, at, TS_DERP_SERVER_INFO, info, sizeof info - 1);
}

void ts_fuzz_derp(void);

void ts_fuzz_derp(void)
{
    static uint8_t s1[2048], s2[512], s3[512], s4[256];
    const uint8_t *seeds[4];
    size_t lens[4], k;
    uint8_t body[64];

    unhex(g_c_priv, CLIENT_PRIV);
    unhex(g_s_priv, SERVER_PRIV);
    unhex(g_o_priv, OTHER_PRIV);
    ts_x25519_public(g_c_pub, g_c_priv);
    ts_x25519_public(g_s_pub, g_s_priv);
    memset(body, 0x51, sizeof body);

    /* Ready, then one of each frame the client handles. */
    k = 0;
    s1[k++] = 0x01;
    greeting(s1, &k, g_s_priv);
    frame(s1, &k, TS_DERP_RECV_PACKET, body, 60);
    frame(s1, &k, TS_DERP_RECV_PACKET, body, 20);
    frame(s1, &k, TS_DERP_PING, (const uint8_t *)"pingping", 8);
    frame(s1, &k, TS_DERP_PONG, (const uint8_t *)"pongpong", 8);
    frame(s1, &k, TS_DERP_PEER_GONE, body, 33);
    frame(s1, &k, TS_DERP_HEALTH, (const uint8_t *)"relay is \x01unhappy", 17);
    frame(s1, &k, TS_DERP_HEALTH, NULL, 0);
    frame(s1, &k, TS_DERP_KEEP_ALIVE, NULL, 0);
    frame(s1, &k, TS_DERP_RESTARTING, (const uint8_t *)"\0\0\0\1\0\0\0\2", 8);
    frame(s1, &k, 0x09, body, 32);
    frame(s1, &k, 0x40, body, 50);
    lens[0] = k;

    /* ServerInfo forged with another key. */
    k = 0;
    s2[k++] = 0x80;
    greeting(s2, &k, g_o_priv);
    frame(s2, &k, TS_DERP_RECV_PACKET, body, 40);
    lens[1] = k;

    /* Ready, then a large unknown frame cut short. */
    k = 0;
    s3[k++] = 0x42;
    greeting(s3, &k, g_s_priv);
    s3[k++] = 0x7e;
    ts_put_be32(s3 + k, 70000);
    k += 4;
    memset(s3 + k, 0x05, 100);
    k += 100;
    lens[2] = k;

    /* A refusal. */
    k = 0;
    s4[k++] = 0x07;
    put(s4, &k, "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n");
    lens[3] = k;

    /* The seeds must get past the handshake, or the fuzzer never would. */
    g_nsend = 0;
    ts_derp_init(&g_d, "derp.example.net", g_c_priv, 0, &IO, NULL);
    ts_derp_start(&g_d, 0);
    if (ts_derp_feed(&g_d, s1 + 1, lens[0] - 1, 0) != 0 || !ts_derp_ready(&g_d))
        ts_fuzz_fail("seed 1 reaches ready", __FILE__, __LINE__);
    ts_derp_free(&g_d);

    seeds[0] = s1;
    seeds[1] = s2;
    seeds[2] = s3;
    seeds[3] = s4;
    ts_fuzz_run("derp", target, seeds, lens, 4, TS_FUZZ_DEFAULT_ITERS);
}
