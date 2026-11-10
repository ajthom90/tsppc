#include "harness.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/control/noise.h"
#include "../src/control/upgrade.h"
#include "../src/proto/encoding.h"

#include "noise_responder.inc"

/* ---- Fixtures ------------------------------------------------------------ */

static uint8_t MACHINE[32], CONTROL[32], CONTROL_PUB[32], OTHER[32], OTHER_PUB[32];
static uint8_t C_EPH[32], R_EPH[32];

static void fixtures(void)
{
    size_t i;
    for (i = 0; i < 32; i++) {
        MACHINE[i] = (uint8_t)(0x10 + i);
        CONTROL[i] = (uint8_t)(0x40 + 3 * i);
        OTHER[i] = (uint8_t)(0x90 + 5 * i);
        C_EPH[i] = (uint8_t)(0xc0 ^ (7 * i));
        R_EPH[i] = (uint8_t)(0x21 + 11 * i);
    }
    ts_x25519_public(CONTROL_PUB, CONTROL);
    ts_x25519_public(OTHER_PUB, OTHER);
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* Complete a handshake between n and the responder. */
static int establish(ts_noise *n, r_session *rs)
{
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN];
    if (ts_noise_init(n, init, MACHINE, CONTROL_PUB, TS_CAPVER) != 0) return -1;
    if (responder(rs, resp, init, CONTROL, R_EPH) != 0) return -1;
    return ts_noise_read_response(n, resp);
}

typedef struct {
    uint8_t buf[16384];
    size_t len;
    unsigned calls;
    size_t max_call;
} sink_t;

static void sink(void *u, const uint8_t *p, size_t n)
{
    sink_t *s = (sink_t *)u;
    if (n > sizeof s->buf - s->len) n = sizeof s->buf - s->len;
    memcpy(s->buf + s->len, p, n);
    s->len += n;
    s->calls++;
    if (n > s->max_call) s->max_call = n;
}

/* ---- Tests --------------------------------------------------------------- */

static void test_handshake(void)
{
    ts_noise n;
    r_session rs;
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN], mpub[32];

    t_true("noise: constants", TS_NOISE_INIT_LEN == 101 && TS_NOISE_RESP_LEN == 51 &&
                               TS_NOISE_MAX_PLAIN == 4077 && TS_CAPVER == 150);

    t_true("noise: init ok", ts_noise_init(&n, init, MACHINE, CONTROL_PUB, TS_CAPVER) == 0);
    t_hex("noise: init header", init, 5, "0096010060");
    t_true("noise: responder accepts init", responder(&rs, resp, init, CONTROL, R_EPH) == 0);
    ts_x25519_public(mpub, MACHINE);
    t_true("noise: responder decrypts machine key", memcmp(rs.machine_pub, mpub, 32) == 0);
    t_hex("noise: response header", resp, 3, "020030");

    t_true("noise: response ok", ts_noise_read_response(&n, resp) == 0);
    t_true("noise: client send = responder receive", memcmp(n.tx_key, rs.c1, 32) == 0);
    t_true("noise: client receive = responder send", memcmp(n.rx_key, rs.c2, 32) == 0);
    t_true("noise: counters start at 0", n.tx_ctr == 0 && n.rx_ctr == 0);
    t_true("noise: handshake secrets wiped",
           all_zero(n.ck, 32) && all_zero(n.e_priv, 32) && all_zero(n.s_priv, 32));
    t_true("noise: response twice fails", ts_noise_read_response(&n, resp) == -1);

    /* The version argument drives both the header and the prologue: a v149
     * handshake completes, and the same init relabelled v150 does not. */
    t_true("noise: init v149", ts_noise_init(&n, init, MACHINE, CONTROL_PUB, 149) == 0);
    t_hex("noise: init v149 header", init, 5, "0095010060");
    t_true("noise: v149 responder accepts", responder(&rs, resp, init, CONTROL, R_EPH) == 0);
    t_true("noise: v149 response ok", ts_noise_read_response(&n, resp) == 0 &&
                                      memcmp(n.tx_key, rs.c1, 32) == 0 &&
                                      memcmp(n.rx_key, rs.c2, 32) == 0);
    t_true("noise: init v149", ts_noise_init(&n, init, MACHINE, CONTROL_PUB, 149) == 0);
    ts_put_be16(init, 150);
    t_true("noise: relabelled version rejected", responder(&rs, resp, init, CONTROL, R_EPH) == -1);

    /* Two inits use fresh ephemerals. */
    {
        ts_noise a, b;
        uint8_t i1[TS_NOISE_INIT_LEN], i2[TS_NOISE_INIT_LEN];
        t_true("noise: init a", ts_noise_init(&a, i1, MACHINE, CONTROL_PUB, TS_CAPVER) == 0);
        t_true("noise: init b", ts_noise_init(&b, i2, MACHINE, CONTROL_PUB, TS_CAPVER) == 0);
        t_true("noise: random ephemerals differ", memcmp(i1 + 5, i2 + 5, 32) != 0);
        ts_noise_clear(&a);
        ts_noise_clear(&b);
    }
    ts_noise_clear(&n);
}

static void test_wrong_key(void)
{
    ts_noise good, bad;
    r_session rs;
    uint8_t ig[TS_NOISE_INIT_LEN], ib[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN];
    uint8_t low[32];
    sink_t s;

    /* Same machine key and ephemeral; only the control key differs. */
    t_true("noise: init good", ts_noise_init_eph(&good, ig, MACHINE, CONTROL_PUB, TS_CAPVER, C_EPH) == 0);
    t_true("noise: init bad", ts_noise_init_eph(&bad, ib, MACHINE, OTHER_PUB, TS_CAPVER, C_EPH) == 0);
    t_true("noise: same ephemeral", memcmp(ig + 5, ib + 5, 32) == 0);
    t_true("noise: responder rejects init for another key",
           responder(&rs, resp, ib, CONTROL, R_EPH) == -1);
    t_true("noise: good responds", responder(&rs, resp, ig, CONTROL, R_EPH) == 0);
    t_true("noise: wrong control key fails", ts_noise_read_response(&bad, resp) == -1);
    t_true("noise: failure wipes", all_zero(bad.s_priv, 32) && all_zero(bad.e_priv, 32) &&
                                   all_zero(bad.ck, 32) && all_zero(bad.rx_key, 32) &&
                                   all_zero(bad.tx_key, 32));
    t_true("noise: failed session cannot seal", ts_noise_seal(&bad, resp, sizeof resp,
                                                              (const uint8_t *)"x", 1) == 0);
    memset(&s, 0, sizeof s);
    t_true("noise: failed session cannot feed", ts_noise_feed(&bad, resp, 3, sink, &s) == -1);
    t_true("noise: right key succeeds", ts_noise_read_response(&good, resp) == 0);

    /* Response tampering. */
    t_true("noise: reinit", ts_noise_init_eph(&good, ig, MACHINE, CONTROL_PUB, TS_CAPVER, C_EPH) == 0);
    resp[50] ^= 1;
    t_true("noise: bad response tag fails", ts_noise_read_response(&good, resp) == -1);
    resp[50] ^= 1;
    t_true("noise: reinit", ts_noise_init_eph(&good, ig, MACHINE, CONTROL_PUB, TS_CAPVER, C_EPH) == 0);
    resp[0] = 3;
    t_true("noise: error frame instead of response fails", ts_noise_read_response(&good, resp) == -1);
    resp[0] = 2;
    t_true("noise: reinit", ts_noise_init_eph(&good, ig, MACHINE, CONTROL_PUB, TS_CAPVER, C_EPH) == 0);
    resp[2] = 47;
    t_true("noise: bad response length fails", ts_noise_read_response(&good, resp) == -1);
    resp[2] = 48;
    /* A low-order point as the response ephemeral (all zero). */
    t_true("noise: reinit", ts_noise_init_eph(&good, ig, MACHINE, CONTROL_PUB, TS_CAPVER, C_EPH) == 0);
    memset(low, 0, sizeof low);
    memcpy(resp + 3, low, 32);
    t_true("noise: low-order response ephemeral fails", ts_noise_read_response(&good, resp) == -1);
    /* A low-order control key fails at init. */
    t_true("noise: low-order control key fails",
           ts_noise_init_eph(&good, ig, MACHINE, low, TS_CAPVER, C_EPH) == -1);
    t_true("noise: response without init fails", ts_noise_read_response(&good, resp) == -1);
    ts_noise_clear(&good);
    ts_noise_clear(&bad);
}

static void test_records(void)
{
    ts_noise n;
    r_session rs;
    uint8_t out[256], pt[64], rec[256];
    long got;
    size_t len, r1;
    sink_t s;

    t_true("noise: establish", establish(&n, &rs) == 0);

    /* Client to responder: counter 0, then 1, big-endian. */
    len = ts_noise_seal(&n, out, sizeof out, (const uint8_t *)"hello", 5);
    t_true("noise: seal one record", len == 3 + 5 + 16);
    t_hex("noise: record header", out, 3, "040015");
    got = r_open(pt, rs.c1, 0, 0, out);
    t_true("noise: responder opens counter 0", got == 5 && memcmp(pt, "hello", 5) == 0);
    len = ts_noise_seal(&n, out, sizeof out, (const uint8_t *)"world!", 6);
    t_true("noise: second record LE counter fails", r_open(pt, rs.c1, 1, 1, out) == -1);
    got = r_open(pt, rs.c1, 1, 0, out);
    t_true("noise: second record BE counter 1", got == 6 && memcmp(pt, "world!", 6) == 0);

    /* Responder to client. */
    memset(&s, 0, sizeof s);
    r1 = r_seal(rec, rs.c2, 0, 0, (const uint8_t *)"abc", 3);
    t_true("noise: feed record 0", ts_noise_feed(&n, rec, r1, sink, &s) == 0);
    r1 = r_seal(rec, rs.c2, 1, 0, (const uint8_t *)"defg", 4);
    t_true("noise: feed record 1", ts_noise_feed(&n, rec, r1, sink, &s) == 0);
    t_true("noise: delivered", s.len == 7 && memcmp(s.buf, "abcdefg", 7) == 0 && s.calls == 2);
    t_true("noise: delivered plaintext wiped", n.rlen == 0 && all_zero(n.rbuf, sizeof n.rbuf));
    /* An empty record is authentic but delivers nothing. */
    r1 = r_seal(rec, rs.c2, 2, 0, NULL, 0);
    t_true("noise: empty record", ts_noise_feed(&n, rec, r1, sink, &s) == 0 && s.calls == 2);
    /* Little-endian counter 3 is rejected. */
    r1 = r_seal(rec, rs.c2, 3, 1, (const uint8_t *)"x", 1);
    t_true("noise: LE counter record fails", ts_noise_feed(&n, rec, r1, sink, &s) == -1);
    ts_noise_clear(&n);
}

static void test_large(void)
{
    static uint8_t big[10000], out[11000], pt[4096];
    ts_noise n;
    r_session rs;
    size_t len, at = 0, total = 0, i;
    uint64_t ctr = 0;
    int ok = 1;

    for (i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 31 + 7);
    t_true("noise: establish", establish(&n, &rs) == 0);
    len = ts_noise_seal(&n, out, sizeof out, big, sizeof big);
    t_true("noise: 10000 bytes in three records", len == sizeof big + 3 * 19);
    while (at < len) {
        long got = r_open(pt, rs.c1, ctr++, 0, out + at);
        if (got < 0 || got > TS_NOISE_MAX_PLAIN || memcmp(pt, big + total, (size_t)got) != 0) {
            ok = 0;
            break;
        }
        total += (size_t)got;
        at += 3 + (size_t)got + 16;
    }
    t_true("noise: records open in order", ok && total == sizeof big && ctr == 3);
    t_true("noise: first record is 4077", ts_get_be16(out + 1) == 4077 + 16);
    t_true("noise: tx counter 3", n.tx_ctr == 3);

    /* A short buffer writes nothing and uses no nonce. */
    t_true("noise: short cap", ts_noise_seal(&n, out, sizeof big + 3 * 19 - 1, big, sizeof big) == 0);
    t_true("noise: short cap keeps counter", n.tx_ctr == 3);
    t_true("noise: empty seal", ts_noise_seal(&n, out, sizeof out, big, 0) == 0);
    ts_noise_clear(&n);
}

static void test_split(void)
{
    static uint8_t stream[8192], pt[4077];
    ts_noise n, m;
    r_session rs;
    sink_t whole, bytes;
    size_t len = 0, i;
    static const size_t sizes[] = { 1, 4077, 500, 0, 33 };
    uint64_t ctr;

    for (i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)(i ^ 0x5a);
    t_true("noise: establish", establish(&n, &rs) == 0);
    for (ctr = 0; ctr < sizeof sizes / sizeof sizes[0]; ctr++)
        len += r_seal(stream + len, rs.c2, ctr, 0, pt, sizes[ctr]);
    m = n;

    memset(&whole, 0, sizeof whole);
    memset(&bytes, 0, sizeof bytes);
    t_true("noise: whole feed", ts_noise_feed(&n, stream, len, sink, &whole) == 0);
    for (i = 0; i < len; i++)
        if (ts_noise_feed(&m, stream + i, 1, sink, &bytes) != 0) break;
    t_true("noise: byte feed", i == len);
    t_true("noise: split deliveries match",
           whole.len == 4611 && bytes.len == whole.len &&
           memcmp(whole.buf, bytes.buf, whole.len) == 0 && whole.calls == 4 && bytes.calls == 4);
    t_true("noise: records delivered whole", bytes.max_call == 4077);
    ts_noise_clear(&n);
    ts_noise_clear(&m);
}

static void test_bad_records(void)
{
    ts_noise n, base;
    r_session rs;
    uint8_t rec[4200];
    size_t len;
    sink_t s;
    static const uint8_t errframe[] = { 3, 0, 5, 'n', 'o', 'p', 'e', '!' };

    t_true("noise: establish", establish(&base, &rs) == 0);
    memset(&s, 0, sizeof s);

    n = base;
    len = r_seal(rec, rs.c2, 0, 0, (const uint8_t *)"payload", 7);
    rec[5] ^= 0x04;
    t_true("noise: flipped bit fails", ts_noise_feed(&n, rec, len, sink, &s) == -1 && s.calls == 0);
    rec[5] ^= 0x04;
    t_true("noise: bad record wipes keys", n.state == TS_NOISE_FAILED &&
                                           all_zero(n.tx_key, 32) && all_zero(n.rx_key, 32));
    t_true("noise: dead after failure", ts_noise_feed(&n, rec, len, sink, &s) == -1 && s.calls == 0);

    n = base;
    t_true("noise: error frame fails", ts_noise_feed(&n, errframe, sizeof errframe, sink, &s) == -1);
    n = base;
    t_true("noise: error frame type byte alone fails", ts_noise_feed(&n, errframe, 1, sink, &s) == -1);
    n = base;
    rec[0] = 7;
    t_true("noise: unknown type fails", ts_noise_feed(&n, rec, 3, sink, &s) == -1);
    rec[0] = 4;
    n = base;
    ts_put_be16(rec + 1, 15);
    t_true("noise: record under a tag fails", ts_noise_feed(&n, rec, 3, sink, &s) == -1);
    n = base;
    ts_put_be16(rec + 1, 4094);
    t_true("noise: record over 4096 fails", ts_noise_feed(&n, rec, 3, sink, &s) == -1);
    n = base;
    len = r_seal(rec, rs.c2, 0, 0, rec + 100, 4077);
    t_true("noise: largest record ok", len == 4096 && ts_noise_feed(&n, rec, len, sink, &s) == 0);

    /* Nonce exhaustion fails closed: 2^64 - 1 is never used. */
    n = base;
    n.tx_ctr = UINT64_MAX - 1;
    len = ts_noise_seal(&n, rec, sizeof rec, (const uint8_t *)"a", 1);
    t_true("noise: last nonce usable", len == 20 && r_open(rec + 1000, rs.c1, UINT64_MAX - 1, 0, rec) == 1);
    t_true("noise: tx nonce exhausted", ts_noise_seal(&n, rec, sizeof rec, (const uint8_t *)"a", 1) == 0);
    t_true("noise: tx counter does not wrap", n.tx_ctr == UINT64_MAX);
    n = base;
    n.tx_ctr = UINT64_MAX - 2;
    t_true("noise: multi-record seal past the limit fails",
           ts_noise_seal(&n, rec, sizeof rec, rec + 4100, 4078 + 4077) == 0 && n.tx_ctr == UINT64_MAX - 2);
    n = base;
    n.rx_ctr = UINT64_MAX;
    len = r_seal(rec, rs.c2, UINT64_MAX, 0, (const uint8_t *)"a", 1);
    t_true("noise: rx nonce exhausted", ts_noise_feed(&n, rec, len, sink, &s) == -1);

    {
        ts_noise fresh;
        uint8_t init[TS_NOISE_INIT_LEN];
        t_true("noise: fresh init", ts_noise_init_eph(&fresh, init, MACHINE, CONTROL_PUB, TS_CAPVER, C_EPH) == 0);
        t_true("noise: feed before established fails",
               ts_noise_feed(&fresh, errframe, 3, sink, &s) == -1);
        t_true("noise: fresh init", ts_noise_init_eph(&fresh, init, MACHINE, CONTROL_PUB, TS_CAPVER, C_EPH) == 0);
        t_true("noise: seal before established fails",
               ts_noise_seal(&fresh, rec, sizeof rec, (const uint8_t *)"a", 1) == 0);
        ts_noise_clear(&fresh);
    }
    ts_noise_clear(&n);
    ts_noise_clear(&base);
}

static void test_upgrade(void)
{
    uint8_t init[TS_NOISE_INIT_LEN];
    char req[512], want[512], b64[160];
    size_t len, consumed = 99, i;
    static const char ok[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: tailscale-control-protocol\r\n"
        "Connection: upgrade\r\n"
        "\r\n";
    char buf[512];

    for (i = 0; i < sizeof init; i++) init[i] = (uint8_t)i;
    ts_b64_encode(b64, sizeof b64, init, sizeof init);
    snprintf(want, sizeof want,
             "POST /ts2021 HTTP/1.1\r\n"
             "Host: control.example\r\n"
             "Upgrade: tailscale-control-protocol\r\n"
             "Connection: upgrade\r\n"
             "Content-Length: 0\r\n"
             "X-Tailscale-Handshake: %s\r\n"
             "\r\n", b64);
    len = ts_upgrade_request(req, sizeof req, "control.example", init);
    t_true("upgrade: request text", len == strlen(want) && strcmp(req, want) == 0);
    t_true("upgrade: base64 is 136 chars", strlen(b64) == 136);
    t_true("upgrade: short cap", ts_upgrade_request(req, len, "control.example", init) == 0);
    t_true("upgrade: exact cap", ts_upgrade_request(req, len + 1, "control.example", init) == len);
    t_true("upgrade: CRLF in host", ts_upgrade_request(req, sizeof req, "a\r\nX: y", init) == 0);
    t_true("upgrade: space in host", ts_upgrade_request(req, sizeof req, "a b", init) == 0);
    t_true("upgrade: empty host", ts_upgrade_request(req, sizeof req, "", init) == 0);

    /* 101, then the Noise response in the same read. */
    len = strlen(ok);
    memcpy(buf, ok, len);
    memset(buf + len, 2, 51);
    t_true("upgrade: partial status", ts_upgrade_response(buf, 10, &consumed) == 1);
    t_true("upgrade: partial headers", ts_upgrade_response(buf, len - 1, &consumed) == 1);
    t_true("upgrade: 101", ts_upgrade_response(buf, len + 51, &consumed) == 0 && consumed == len);

    {
        static const char lc[] = "HTTP/1.1 101 x\r\nupgrade: \tTailscale-Control-Protocol \r\n\r\n";
        t_true("upgrade: lower-case header names, padded value",
               ts_upgrade_response(lc, sizeof lc - 1, &consumed) == 0 && consumed == sizeof lc - 1);
    }
    t_true("upgrade: 200 refused",
           ts_upgrade_response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 38, &consumed) == -1);
    t_true("upgrade: 200 refused before headers end",
           ts_upgrade_response("HTTP/1.1 200 OK\r\n", 17, &consumed) == -1);
    t_true("upgrade: 101 without Upgrade header",
           ts_upgrade_response("HTTP/1.1 101 x\r\n\r\n", 18, &consumed) == -1);
    {
        static const char first[] = "HTTP/1.1 101 x\r\nUpgrade: tailscale-control-protocol\r\n"
                                    "Upgrade: websocket\r\n\r\n";
        static const char second[] = "HTTP/1.1 101 x\r\nUpgrade: websocket\r\n"
                                     "Upgrade: tailscale-control-protocol\r\n\r\n";
        t_true("upgrade: first Upgrade header wins",
               ts_upgrade_response(first, sizeof first - 1, &consumed) == 0);
        t_true("upgrade: later Upgrade header ignored",
               ts_upgrade_response(second, sizeof second - 1, &consumed) == -1);
    }
    t_true("upgrade: 101 to another protocol",
           ts_upgrade_response("HTTP/1.1 101 x\r\nUpgrade: websocket\r\n\r\n", 38, &consumed) == -1);
    t_true("upgrade: not HTTP", ts_upgrade_response("SSH-2.0-x\r\n\r\n", 13, &consumed) == -1);
    t_true("upgrade: 1010 is not 101",
           ts_upgrade_response("HTTP/1.1 1010 x\r\n\r\n", 19, &consumed) == -1);
    {
        static char huge[TS_UPGRADE_HEADER_MAX + 1];
        memset(huge, 'a', sizeof huge);
        memcpy(huge, "HTTP/1.1 101 x\r\n", 16);
        t_true("upgrade: endless headers refused",
               ts_upgrade_response(huge, sizeof huge, &consumed) == -1);
        t_true("upgrade: long headers still pending",
               ts_upgrade_response(huge, TS_UPGRADE_HEADER_MAX - 1, &consumed) == 1);
        memcpy(huge + TS_UPGRADE_HEADER_MAX - 2, "\r\n", 2);
        memcpy(huge + 16, "Upgrade: tailscale-control-protocol\r\nX: ", 40);
        memcpy(huge + TS_UPGRADE_HEADER_MAX - 4, "\r\n", 2);
        t_true("upgrade: headers of exactly the limit",
               ts_upgrade_response(huge, sizeof huge, &consumed) == 0 &&
               consumed == TS_UPGRADE_HEADER_MAX);
    }
}

static void test_early(void)
{
    uint8_t buf[80];
    size_t consumed = 99;
    static const char json[] = "{\"nodeKeyChallenge\":\"x\"}";
    size_t jl = sizeof json - 1;

    memcpy(buf, "\xff\xff\xffTS", 5);
    ts_put_be32(buf + 5, (uint32_t)jl);
    memcpy(buf + 9, json, jl);
    memcpy(buf + 9 + jl, "\0\0\x06\x04", 4);   /* start of the HTTP/2 SETTINGS that follows */

    t_true("early: empty needs more", ts_early_payload(buf, 0, &consumed) == 1);
    t_true("early: magic prefix needs more", ts_early_payload(buf, 3, &consumed) == 1);
    t_true("early: header needs more", ts_early_payload(buf, 8, &consumed) == 1);
    t_true("early: body needs more", ts_early_payload(buf, 9 + jl - 1, &consumed) == 1);
    consumed = 99;
    t_true("early: consumed", ts_early_payload(buf, 9 + jl + 4, &consumed) == 0 && consumed == 9 + jl);

    consumed = 99;
    t_true("early: none present", ts_early_payload((const uint8_t *)"\0\0\x06\x04\0\0\0\0\0", 9,
                                                   &consumed) == 0 && consumed == 0);
    consumed = 99;
    t_true("early: mismatch on second byte", ts_early_payload((const uint8_t *)"\xff\0", 2,
                                                              &consumed) == 0 && consumed == 0);
    ts_put_be32(buf + 5, 65537);
    t_true("early: over 64 KiB", ts_early_payload(buf, 9, &consumed) == -1);
    ts_put_be32(buf + 5, 65536);
    t_true("early: 64 KiB waits", ts_early_payload(buf, 20, &consumed) == 1);
    ts_put_be32(buf + 5, 0);
    t_true("early: empty payload is not JSON", ts_early_payload(buf, 9, &consumed) == -1);
    ts_put_be32(buf + 5, 3);
    memcpy(buf + 9, "{a}", 3);
    t_true("early: invalid JSON", ts_early_payload(buf, 12, &consumed) == -1 && consumed == 0);
    t_true("early: invalid JSON waits until complete", ts_early_payload(buf, 11, &consumed) == 1);
    ts_put_be32(buf + 5, 5);
    memcpy(buf + 9, "{} {}", 5);
    t_true("early: trailing data", ts_early_payload(buf, 14, &consumed) == -1);
    memcpy(buf + 9, " {} \n", 5);
    t_true("early: surrounding whitespace", ts_early_payload(buf, 14, &consumed) == 0 && consumed == 14);
}

void test_noise(void)
{
    fixtures();
    test_handshake();
    test_wrong_key();
    test_records();
    test_large();
    test_split();
    test_bad_records();
    test_upgrade();
    test_early();
}
