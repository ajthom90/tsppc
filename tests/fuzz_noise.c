#include "fuzz.h"

#include <stdlib.h>
#include <string.h>

#include "../src/control/noise.h"
#include "../src/control/upgrade.h"

#include "noise_responder.inc"

/* Input: one mode byte, then data. mode % 5 selects the target:
 *   0  server records fed to a ready session, whole and in pieces
 *   1  input-derived plaintext sealed and fed back (bits 5-6 add 4000-byte
 *      blocks so records split; bit 7 flips one ciphertext byte), whole and in
 *      pieces
 *   2  the handshake response (first 51 bytes, zero padded)
 *   3  the HTTP upgrade response, whole and as prefixes
 *   4  the early payload, whole and as prefixes
 * Sessions come from a fixed handshake, so every run is deterministic. */

#define BIG (4 * TS_NOISE_MAX_PLAIN + 64)

static int g_ready;
static ts_noise g_sent, g_live, g_loop;   /* after init; after response; rx = tx */
static uint8_t g_resp[TS_NOISE_RESP_LEN];
static r_session g_rs;

static void setup(void)
{
    uint8_t machine[32], control[32], control_pub[32], ce[32], re[32];
    uint8_t init[TS_NOISE_INIT_LEN];
    size_t i;

    if (g_ready) return;
    for (i = 0; i < 32; i++) {
        machine[i] = (uint8_t)(0x10 + i);
        control[i] = (uint8_t)(0x40 + 3 * i);
        ce[i] = (uint8_t)(0xc0 ^ (7 * i));
        re[i] = (uint8_t)(0x21 + 11 * i);
    }
    ts_x25519_public(control_pub, control);
    TS_FUZZ_ASSERT(ts_noise_init_eph(&g_sent, init, machine, control_pub, TS_CAPVER, ce) == 0);
    TS_FUZZ_ASSERT(responder(&g_rs, g_resp, init, control, re) == 0);
    g_live = g_sent;
    TS_FUZZ_ASSERT(ts_noise_read_response(&g_live, g_resp) == 0);
    /* A session that receives what it sends. */
    g_loop = g_live;
    memcpy(g_loop.rx_key, g_loop.tx_key, 32);
    g_ready = 1;
}

typedef struct {
    uint8_t *buf;            /* optional copy of delivered bytes, BIG long */
    size_t len;
    uint64_t hash;
    unsigned calls;
    int dead;
} sink_t;

static void mix(uint64_t *h, uint64_t v) { *h = (*h ^ v) * 1099511628211ull; }

static void sink_init(sink_t *s, uint8_t *buf)
{
    memset(s, 0, sizeof *s);
    s->buf = buf;
    s->hash = 14695981039346656037ull;
}

static void deliver(void *u, const uint8_t *p, size_t n)
{
    sink_t *s = (sink_t *)u;
    size_t i;
    TS_FUZZ_ASSERT(!s->dead);
    TS_FUZZ_ASSERT(n > 0 && n <= TS_NOISE_MAX_PLAIN);
    if (s->buf) {
        TS_FUZZ_ASSERT(n <= BIG - s->len);
        memcpy(s->buf + s->len, p, n);
    }
    s->len += n;
    s->calls++;
    mix(&s->hash, n);
    for (i = 0; i < n; i++) mix(&s->hash, p[i]);
}

/* Feed in pieces of 1..16 bytes chosen by the data. Returns the first -1 or 0. */
static int feed_split(ts_noise *n, const uint8_t *d, size_t len, sink_t *s)
{
    size_t at = 0, k = 0;
    while (at < len) {
        size_t piece = (size_t)(d[k++ % len] & 15) + 1;
        if (piece > len - at) piece = len - at;
        if (ts_noise_feed(n, d + at, piece, deliver, s) != 0) {
            s->dead = 1;
            TS_FUZZ_ASSERT(n->state == TS_NOISE_FAILED);
            TS_FUZZ_ASSERT(ts_noise_feed(n, d, len, deliver, s) == -1);
            return -1;
        }
        at += piece;
    }
    return 0;
}

static int feed_whole(ts_noise *n, const uint8_t *d, size_t len, sink_t *s)
{
    int rc = ts_noise_feed(n, d, len, deliver, s);
    TS_FUZZ_ASSERT(rc == 0 || rc == -1);
    if (rc) {
        s->dead = 1;
        TS_FUZZ_ASSERT(n->state == TS_NOISE_FAILED);
    }
    return rc;
}

static void same(const sink_t *a, const sink_t *b, int rca, int rcb)
{
    TS_FUZZ_ASSERT(rca == rcb);
    TS_FUZZ_ASSERT(a->len == b->len && a->calls == b->calls && a->hash == b->hash);
}

static void do_feed(const uint8_t *d, size_t len)
{
    ts_noise a = g_live, b = g_live;
    sink_t sa, sb;
    int ra, rb;
    sink_init(&sa, NULL);
    sink_init(&sb, NULL);
    ra = feed_whole(&a, d, len, &sa);
    rb = len ? feed_split(&b, d, len, &sb) : feed_whole(&b, d, len, &sb);
    same(&sa, &sb, ra, rb);
    TS_FUZZ_ASSERT(a.rx_ctr == b.rx_ctr && a.rlen == b.rlen);
}

static void do_loop(unsigned mode, const uint8_t *d, size_t len)
{
    static uint8_t pt[BIG], ct[BIG + 8 * TS_NOISE_RECORD_OVERHEAD], got1[BIG], got2[BIG];
    ts_noise tx = g_loop, a, b;
    size_t plen = len + ((mode >> 5) & 3) * 4000, clen, i;
    sink_t sa, sb;
    int ra, rb, flipped = 0;

    for (i = 0; i < plen; i++) pt[i] = len ? (uint8_t)(d[i % len] + i / len) : (uint8_t)i;
    clen = ts_noise_seal(&tx, ct, sizeof ct, pt, plen);
    if (plen == 0) {
        TS_FUZZ_ASSERT(clen == 0);
        return;
    }
    TS_FUZZ_ASSERT(clen == plen + TS_NOISE_RECORD_OVERHEAD *
                   ((plen + TS_NOISE_MAX_PLAIN - 1) / TS_NOISE_MAX_PLAIN));
    TS_FUZZ_ASSERT(ts_noise_seal(&tx, ct, clen - 1, pt, plen) == 0);   /* short cap */
    if ((mode & 0x80) && len) {
        ct[(d[0] * 131u + len) % clen] ^= (uint8_t)(1u << (d[len - 1] & 7));
        flipped = 1;
    }
    a = g_loop;
    b = g_loop;
    sink_init(&sa, got1);
    sink_init(&sb, got2);
    ra = feed_whole(&a, ct, clen, &sa);
    rb = feed_split(&b, ct, clen, &sb);
    same(&sa, &sb, ra, rb);
    TS_FUZZ_ASSERT(memcmp(got1, pt, sa.len) == 0);   /* delivered bytes are a prefix */
    /* A flipped bit fails a tag or the framing, or (in the last record's
     * length) leaves that record waiting for bytes that never come. */
    if (!flipped) TS_FUZZ_ASSERT(ra == 0 && sa.len == plen);
    else TS_FUZZ_ASSERT(sa.len < plen && (ra == -1 || a.rlen > 0));
}

static void do_response(const uint8_t *d, size_t len)
{
    uint8_t resp[TS_NOISE_RESP_LEN];
    ts_noise n = g_sent;
    int rc;

    memset(resp, 0, sizeof resp);
    memcpy(resp, d, len < sizeof resp ? len : sizeof resp);
    rc = ts_noise_read_response(&n, resp);
    if (memcmp(resp, g_resp, sizeof resp) == 0) {
        TS_FUZZ_ASSERT(rc == 0);
        TS_FUZZ_ASSERT(memcmp(n.tx_key, g_rs.c1, 32) == 0 && memcmp(n.rx_key, g_rs.c2, 32) == 0);
    } else {
        TS_FUZZ_ASSERT(rc == -1 && n.state == TS_NOISE_FAILED);
    }
}

/* Prefix lengths worth checking: a few spread out, plus around the answer. */
static size_t pick(const uint8_t *d, size_t len, unsigned i, size_t c)
{
    if (i == 0) return c > 0 ? c - 1 : 0;
    if (i == 1) return c;
    if (i == 2) return c + 1;
    return len ? (size_t)(d[(i * 7) % len] * (i + 1)) : 0;
}

static void do_upgrade(const uint8_t *d, size_t len)
{
    const char *buf = (const char *)d;
    size_t c = 99, pc;
    unsigned i;
    int rc = ts_upgrade_response(buf, len, &c);

    TS_FUZZ_ASSERT(rc >= -1 && rc <= 1);
    TS_FUZZ_ASSERT(rc == 0 ? c >= 4 && c <= len && memcmp(buf + c - 4, "\r\n\r\n", 4) == 0 : c == 0);
    for (i = 0; i < 8; i++) {
        size_t k = pick(d, len, i, c);
        int prc;
        if (k > len) continue;
        prc = ts_upgrade_response(buf, k, &pc);
        if (rc == 1) TS_FUZZ_ASSERT(prc == 1);
        else if (rc == 0) TS_FUZZ_ASSERT(k >= c ? prc == 0 && pc == c : prc == 1);
        else TS_FUZZ_ASSERT(prc == 1 || prc == -1);
    }
}

static void do_early(const uint8_t *d, size_t len)
{
    size_t c = 99, pc;
    unsigned i;
    int rc = ts_early_payload(d, len, &c);

    TS_FUZZ_ASSERT(rc >= -1 && rc <= 1);
    TS_FUZZ_ASSERT(rc == 0 ? c <= len && (c == 0 || c >= 9) : c == 0);
    for (i = 0; i < 8; i++) {
        size_t k = pick(d, len, i, c);
        int prc;
        if (k > len) continue;
        prc = ts_early_payload(d, k, &pc);
        if (rc == 1) TS_FUZZ_ASSERT(prc == 1);
        else if (rc == -1) TS_FUZZ_ASSERT(k >= 9 ? prc == -1 : prc == 1);
        else if (c > 0) TS_FUZZ_ASSERT(k >= c ? prc == 0 && pc == c : prc == 1);
        else TS_FUZZ_ASSERT((prc == 0 && pc == 0) || prc == 1);
    }
}

static void target(const uint8_t *d, size_t len)
{
    unsigned mode;
    if (len == 0) return;
    setup();
    mode = d[0];
    d++;
    len--;
    switch (mode % 5) {
    case 0: do_feed(d, len); break;
    case 1: do_loop(mode, d, len); break;
    case 2: do_response(d, len); break;
    case 3: do_upgrade(d, len); break;
    default: do_early(d, len); break;
    }
}

void ts_fuzz_noise(void)
{
    static uint8_t s_feed[200], s_loop[40], s_resp[1 + TS_NOISE_RESP_LEN], s_err[9];
    static const char s_up[] = "\x03HTTP/1.1 101 Switching Protocols\r\n"
                               "Upgrade: tailscale-control-protocol\r\n"
                               "Connection: upgrade\r\n\r\n\x02\x00\x30";
    static const char s_200[] = "\x03HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    static const char s_early[] = "\x04\xff\xff\xffTS\x00\x00\x00\x0a{\"a\":\"b\"} \x00\x00\x06\x04";
    static const char s_h2[] = "\x04\x00\x00\x06\x04\x00\x00\x00\x00\x00";
    const uint8_t *seeds[8];
    size_t lens[8], at = 1;
    uint8_t probe[4];
    long ok;
    uint64_t ctr;

    setup();
    /* Three server records, then the start of a fourth. */
    s_feed[0] = 0;
    for (ctr = 0; ctr < 3; ctr++) {
        static const char *const msg[] = { "{\"x\":1}", "hello", "" };
        at += r_seal(s_feed + at, g_rs.c2, ctr, 0, (const uint8_t *)msg[ctr], strlen(msg[ctr]));
    }
    s_feed[at++] = 4;
    /* The responder decrypts what the client seals. */
    {
        ts_noise tx = g_live;
        uint8_t rec[32];
        TS_FUZZ_ASSERT(ts_noise_seal(&tx, rec, sizeof rec, (const uint8_t *)"ping", 4) == 23);
        ok = r_open(probe, g_rs.c1, 0, 0, rec);
        TS_FUZZ_ASSERT(ok == 4 && memcmp(probe, "ping", 4) == 0);
    }
    s_loop[0] = 1 | 0x20;
    memcpy(s_loop + 1, "plaintext for the loop target", 29);
    s_resp[0] = 2;
    memcpy(s_resp + 1, g_resp, TS_NOISE_RESP_LEN);
    memcpy(s_err, "\x00\x03\x00\x05nope", 9);

    seeds[0] = s_feed; lens[0] = at;
    seeds[1] = s_loop; lens[1] = 30;
    seeds[2] = s_resp; lens[2] = sizeof s_resp;
    seeds[3] = (const uint8_t *)s_up; lens[3] = sizeof s_up - 1;
    seeds[4] = (const uint8_t *)s_200; lens[4] = sizeof s_200 - 1;
    seeds[5] = (const uint8_t *)s_early; lens[5] = sizeof s_early - 1;
    seeds[6] = (const uint8_t *)s_h2; lens[6] = sizeof s_h2 - 1;
    seeds[7] = s_err; lens[7] = sizeof s_err;
    ts_fuzz_run("noise", target, seeds, lens, 8, TS_FUZZ_DEFAULT_ITERS);
}
