#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/bytes.h"
#include "../src/crypto/nacl.h"
#include "../src/crypto/x25519.h"
#include "../src/derp/derp.h"

/* A fake relay built from the frame layout (derp/derp.go), holding its own
 * key. The client's sends are captured; callbacks are logged as text so a
 * stream fed whole and fed byte by byte can be compared. Keys are made up. */

#define HOST "derp.example.net"
#define CLIENT_PRIV "a8f1c3d2e4b5a6978899aabbccddeeff00112233445566778899aabbccddee40"
#define SERVER_PRIV "18e2d4c6b8a0f1e3d5c7b9a1f2e4d6c8b0a1c3e5f7092b4d6f8a1c3e5f709250"
#define OTHER_PRIV "60a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e4f"
#define PEER_HEX "5151515151515151515151515151515151515151515151515151515151515151"

static const char REQUEST[] = "GET /derp HTTP/1.1\r\nHost: " HOST "\r\n"
                              "Upgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
static const char RESP101[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n"
                              "Connection: Upgrade\r\nDerp-Version: 2\r\n\r\n";
static const char CLIENT_JSON[] = "{\"version\":2,\"CanAckPings\":true}";

static uint8_t c_priv[32], c_pub[32], s_priv[32], s_pub[32], o_priv[32], peer[32];

#define SENTCAP (5 + 32 + TS_DERP_MAX_PACKET + 4096)
static uint8_t sent[SENTCAP];
static size_t sent_n;
static char logbuf[1 << 16];
static size_t log_n;
static size_t last_pkt_n;
static uint8_t last_pkt[TS_DERP_MAX_PACKET];
static char last_health[512];
static int n_health;

static ts_derp *D;

static void logf_(const char *s)
{
    size_t n = strlen(s);
    if (log_n + n < sizeof logbuf) {
        memcpy(logbuf + log_n, s, n + 1);
        log_n += n;
    }
}

static void cb_send(void *user, const uint8_t *p, size_t n)
{
    (void)user;
    if (sent_n + n <= SENTCAP) {
        memcpy(sent + sent_n, p, n);
        sent_n += n;
    }
}

static void cb_recv(void *user, const uint8_t src[32], const uint8_t *p, size_t n)
{
    char b[64];
    (void)user;
    snprintf(b, sizeof b, "recv %02x %u %02x;", src[0], (unsigned)n, n ? p[n - 1] : 0);
    logf_(b);
    memcpy(last_pkt, p, n);
    last_pkt_n = n;
}

static void cb_gone(void *user, const uint8_t key[32])
{
    char b[32];
    (void)user;
    snprintf(b, sizeof b, "gone %02x%02x;", key[0], key[31]);
    logf_(b);
}

static void cb_health(void *user, const char *text)
{
    (void)user;
    snprintf(last_health, sizeof last_health, "%s", text);
    n_health++;
    logf_("health[");
    logf_(text);
    logf_("];");
}

static void cb_pong(void *user, const uint8_t data[8])
{
    char b[32];
    (void)user;
    snprintf(b, sizeof b, "pong %02x%02x;", data[0], data[7]);
    logf_(b);
}

static const ts_derp_io IO = { cb_send, cb_recv, cb_gone, cb_health, cb_pong };

static void reset_capture(void)
{
    sent_n = 0;
    log_n = 0;
    logbuf[0] = 0;
    last_pkt_n = 0;
    last_health[0] = 0;
    n_health = 0;
}

static void keys(void)
{
    t_unhex(c_priv, CLIENT_PRIV);
    t_unhex(s_priv, SERVER_PRIV);
    t_unhex(o_priv, OTHER_PRIV);
    t_unhex(peer, PEER_HEX);
    ts_x25519_public(c_pub, c_priv);
    ts_x25519_public(s_pub, s_priv);
}

/* Append a frame to out at *at. */
static void frame(uint8_t *out, size_t *at, int type, const uint8_t *body, size_t n)
{
    out[*at] = (uint8_t)type;
    ts_put_be32(out + *at + 1, (uint32_t)n);
    if (n) memcpy(out + *at + 5, body, n);
    *at += 5 + n;
}

static void put(uint8_t *out, size_t *at, const void *p, size_t n)
{
    memcpy(out + *at, p, n);
    *at += n;
}

static void server_key_frame(uint8_t *out, size_t *at)
{
    uint8_t b[40];
    memcpy(b, "DERP\xf0\x9f\x94\x91", 8);
    memcpy(b + 8, s_pub, 32);
    frame(out, at, TS_DERP_SERVER_KEY, b, sizeof b);
}

/* ServerInfo sealed with key_priv (the relay's, or a forger's). */
static void server_info_frame(uint8_t *out, size_t *at, const uint8_t key_priv[32], const char *json)
{
    uint8_t b[24 + 16 + 256];
    size_t jl = strlen(json), i;
    for (i = 0; i < 24; i++) b[i] = (uint8_t)(0x30 + i);
    ts_box_seal(b + 24, b, c_pub, key_priv, (const uint8_t *)json, jl);
    frame(out, at, TS_DERP_SERVER_INFO, b, 24 + 16 + jl);
}

static const char INFO_JSON[] =
    "{\"version\":2,\"TokenBucketBytesPerSecond\":1000,\"TokenBucketBytesBurst\":2000}";

/* 101, ServerKey and a good ServerInfo. */
static size_t greeting(uint8_t *out)
{
    size_t at = 0;
    put(out, &at, RESP101, sizeof RESP101 - 1);
    server_key_frame(out, &at);
    server_info_frame(out, &at, s_priv, INFO_JSON);
    return at;
}

static void client_new(int preferred)
{
    reset_capture();
    ts_derp_init(D, HOST, c_priv, preferred, &IO, NULL);
    ts_derp_start(D, 1000);
}

/* Connect a fresh client up to ready; the capture is reset afterwards. */
static int connect_ready(int preferred)
{
    uint8_t g[512];
    size_t n = greeting(g);
    client_new(preferred);
    if (ts_derp_feed(D, g, n, 1000) != 0 || !ts_derp_ready(D)) return -1;
    reset_capture();
    return 0;
}

static int feed_bytes(const uint8_t *p, size_t n, int64_t now)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (ts_derp_feed(D, p + i, 1, now) != 0) return -1;
    return 0;
}

/* The ClientInfo frame, which follows the request in the capture. */
static int open_client_info(char *json, size_t cap, size_t *jl)
{
    const uint8_t *f = sent + sizeof REQUEST - 1;
    uint32_t len;
    if (sent_n < sizeof REQUEST - 1 + 5) return -1;
    len = ts_get_be32(f + 1);
    if (f[0] != TS_DERP_CLIENT_INFO || sent_n != sizeof REQUEST - 1 + 5 + len) return -1;
    if (len < 32 + 24 + 16 || len - 72 >= cap) return -1;
    if (memcmp(f + 5, c_pub, 32) != 0) return -1;
    if (ts_box_open((uint8_t *)json, f + 5 + 32, c_pub, s_priv, f + 5 + 56, len - 56) != 0)
        return -1;
    *jl = len - 72;
    json[*jl] = 0;
    return 0;
}

void test_derp_handshake(void);
void test_derp_frames(void);
void test_derp_send(void);

void test_derp_handshake(void)
{
    uint8_t g[512], s[1024];
    char json[128];
    size_t n, jl = 0, at;
    char log_whole[sizeof logbuf];

    D = malloc(sizeof *D);
    keys();

    /* Request bytes. */
    client_new(0);
    t_true("derp: request", sent_n == sizeof REQUEST - 1 && memcmp(sent, REQUEST, sent_n) == 0);
    t_true("derp: not ready before 101", !ts_derp_ready(D));

    /* 101 and ServerKey: ClientInfo goes out, opening to exactly the JSON. */
    at = 0;
    put(s, &at, RESP101, sizeof RESP101 - 1);
    server_key_frame(s, &at);
    t_true("derp: 101 + ServerKey", ts_derp_feed(D, s, at, 1100) == 0);
    t_true("derp: client info opens", open_client_info(json, sizeof json, &jl) == 0);
    t_true("derp: client info json", jl == sizeof CLIENT_JSON - 1 && strcmp(json, CLIENT_JSON) == 0);
    t_true("derp: not ready before server info", !ts_derp_ready(D));
    at = 0;
    server_info_frame(s, &at, s_priv, INFO_JSON);
    t_true("derp: server info", ts_derp_feed(D, s, at, 1200) == 0 && ts_derp_ready(D));
    t_true("derp: nothing sent at ready when not preferred",
           sent_n == sizeof REQUEST - 1 + 5 + 104);

    /* The same stream, with frames, whole and byte by byte: same callbacks. */
    n = greeting(g);
    {
        uint8_t body[40];
        memcpy(body, peer, 32);
        memcpy(body + 32, "abcdefgh", 8);
        frame(g, &n, TS_DERP_RECV_PACKET, body, 40);
        frame(g, &n, TS_DERP_KEEP_ALIVE, NULL, 0);
        frame(g, &n, TS_DERP_PEER_GONE, peer, 32);
        frame(g, &n, TS_DERP_HEALTH, (const uint8_t *)"bad", 3);
        frame(g, &n, TS_DERP_HEALTH, NULL, 0);
    }
    client_new(1);
    t_true("derp: whole stream", ts_derp_feed(D, g, n, 1000) == 0 && ts_derp_ready(D));
    memcpy(log_whole, logbuf, log_n + 1);
    t_true("derp: whole stream log",
           strcmp(log_whole, "recv 51 8 68;gone 5151;health[bad];health[];") == 0);
    client_new(1);
    t_true("derp: byte stream", feed_bytes(g, n, 1000) == 0 && ts_derp_ready(D));
    t_true("derp: byte stream log", strcmp(log_whole, logbuf) == 0);

    /* Bad host: dead from the start. */
    reset_capture();
    ts_derp_init(D, "bad host", c_priv, 0, &IO, NULL);
    ts_derp_start(D, 0);
    t_true("derp: bad host", sent_n == 0 && ts_derp_feed(D, g, 1, 0) == -1 && D->err != NULL);
    ts_derp_init(D, "", c_priv, 0, &IO, NULL);
    ts_derp_start(D, 0);
    t_true("derp: empty host", sent_n == 0 && ts_derp_tick(D, 0) == -1);

    /* ServerKey problems are fatal. */
    client_new(0);
    at = 0;
    put(s, &at, RESP101, sizeof RESP101 - 1);
    {
        uint8_t b[40];
        memcpy(b, "DERP\xf0\x9f\x94\x92", 8);
        memcpy(b + 8, s_pub, 32);
        frame(s, &at, TS_DERP_SERVER_KEY, b, 40);
    }
    t_true("derp: wrong magic", ts_derp_feed(D, s, at, 1000) == -1);
    client_new(0);
    at = 0;
    put(s, &at, RESP101, sizeof RESP101 - 1);
    {
        uint8_t b[39];
        memcpy(b, "DERP\xf0\x9f\x94\x91", 8);
        memcpy(b + 8, s_pub, 31);
        frame(s, &at, TS_DERP_SERVER_KEY, b, 39);
    }
    t_true("derp: short server key", ts_derp_feed(D, s, at, 1000) == -1);
    client_new(0);
    at = 0;
    put(s, &at, RESP101, sizeof RESP101 - 1);
    frame(s, &at, TS_DERP_KEEP_ALIVE, NULL, 0);
    t_true("derp: first frame not server key", ts_derp_feed(D, s, at, 1000) == -1);
    /* Before ServerInfo only ServerInfo is accepted: RecvPacket, Ping, Health
     * and PeerGone are fatal, with no callback and nothing sent. */
    {
        static const int types[4] = { TS_DERP_RECV_PACKET, TS_DERP_PING, TS_DERP_HEALTH,
                                      TS_DERP_PEER_GONE };
        static const char *const names[4] = { "derp: recv packet before server info",
                                               "derp: ping before server info",
                                               "derp: health before server info",
                                               "derp: peer gone before server info" };
        uint8_t body[40], g2[512];
        size_t k, before;
        int i;
        memcpy(body, peer, 32);
        memcpy(body + 32, "abcdefgh", 8);
        for (i = 0; i < 4; i++) {
            k = 0;
            put(g2, &k, RESP101, sizeof RESP101 - 1);
            server_key_frame(g2, &k);
            frame(g2, &k, types[i], body, 40);
            server_info_frame(g2, &k, s_priv, INFO_JSON);
            client_new(0);
            before = sizeof REQUEST - 1 + 5 + 104;   /* request and ClientInfo */
            t_true(names[i], ts_derp_feed(D, g2, k, 1000) == -1 && !ts_derp_ready(D) &&
                             log_n == 0 && sent_n == before && D->err != NULL);
        }
    }
    /* A longer ServerKey (future use) is fine. */
    client_new(0);
    at = 0;
    put(s, &at, RESP101, sizeof RESP101 - 1);
    {
        uint8_t b[100];
        memset(b, 0xee, sizeof b);
        memcpy(b, "DERP\xf0\x9f\x94\x91", 8);
        memcpy(b + 8, s_pub, 32);
        frame(s, &at, TS_DERP_SERVER_KEY, b, sizeof b);
    }
    t_true("derp: long server key", ts_derp_feed(D, s, at, 1000) == 0 &&
                                    open_client_info(json, sizeof json, &jl) == 0);
    /* A ServerInfo that is not JSON is fatal. */
    at = 0;
    server_info_frame(s, &at, s_priv, "{\"version\":2");
    t_true("derp: server info not json", ts_derp_feed(D, s, at, 1000) == -1 && !ts_derp_ready(D));

    /* Handshake timeout: 30 s from start without ServerInfo. */
    client_new(0);
    t_true("derp: handshake 29.999 s", ts_derp_tick(D, 1000 + 29999) == 0);
    t_true("derp: handshake 30 s", ts_derp_tick(D, 1000 + 30000) == -1 && D->err != NULL);
    t_true("derp: dead stays dead", ts_derp_tick(D, 1000) == -1 &&
                                    ts_derp_feed(D, s, 1, 1000) == -1);

    ts_derp_free(D);
    free(D);
}

void test_derp_frames(void)
{
    static uint8_t s[5 + 70000];
    uint8_t b[300];
    size_t at, i;
    int ok;

    D = malloc(sizeof *D);
    keys();

    /* RecvPacket delivered, short ones dropped, the largest delivered. */
    t_true("derp: ready", connect_ready(0) == 0);
    at = 0;
    memcpy(b, peer, 32);
    for (i = 0; i < 20; i++) b[32 + i] = (uint8_t)i;
    frame(s, &at, TS_DERP_RECV_PACKET, b, 52);
    frame(s, &at, TS_DERP_RECV_PACKET, b, 31);
    t_true("derp: recv packet", ts_derp_feed(D, s, at, 2000) == 0 &&
                                strcmp(logbuf, "recv 51 20 13;") == 0 && last_pkt_n == 20 &&
                                memcmp(last_pkt, b + 32, 20) == 0);
    reset_capture();
    at = 0;
    s[0] = TS_DERP_RECV_PACKET;
    ts_put_be32(s + 1, 32 + TS_DERP_MAX_PACKET);
    memcpy(s + 5, peer, 32);
    for (i = 0; i < TS_DERP_MAX_PACKET; i++) s[5 + 32 + i] = (uint8_t)(i * 7);
    t_true("derp: largest packet", ts_derp_feed(D, s, 5 + 32 + TS_DERP_MAX_PACKET, 2000) == 0 &&
                                   last_pkt_n == TS_DERP_MAX_PACKET &&
                                   memcmp(last_pkt, s + 37, TS_DERP_MAX_PACKET) == 0);
    reset_capture();
    ts_put_be32(s + 1, 32 + TS_DERP_MAX_PACKET + 1);
    t_true("derp: packet over the limit skipped",
           ts_derp_feed(D, s, 5 + 32 + TS_DERP_MAX_PACKET + 1, 2000) == 0 && log_n == 0 &&
           ts_derp_ready(D));

    /* Ping answered with a Pong; short Ping ignored; longer echoes 8. */
    reset_capture();
    at = 0;
    frame(s, &at, TS_DERP_PING, (const uint8_t *)"12345678", 8);
    frame(s, &at, TS_DERP_PING, (const uint8_t *)"1234567", 7);
    frame(s, &at, TS_DERP_PING, (const uint8_t *)"ABCDEFGHI", 9);
    ok = ts_derp_feed(D, s, at, 2000) == 0;
    t_true("derp: ping answered",
           ok && sent_n == 26 && memcmp(sent, "\x13\x00\x00\x00\x08" "12345678", 13) == 0 &&
           memcmp(sent + 13, "\x13\x00\x00\x00\x08" "ABCDEFGH", 13) == 0);
    /* Pong passed on. */
    reset_capture();
    at = 0;
    frame(s, &at, TS_DERP_PONG, (const uint8_t *)"\x01xxxxxx\x02", 8);
    t_true("derp: pong", ts_derp_feed(D, s, at, 2000) == 0 && strcmp(logbuf, "pong 0102;") == 0);

    /* PeerGone, with and without the reason byte; short ignored. */
    reset_capture();
    at = 0;
    memcpy(b, peer, 32);
    b[31] = 0x77;
    b[32] = 1;
    frame(s, &at, TS_DERP_PEER_GONE, b, 33);
    frame(s, &at, TS_DERP_PEER_GONE, b, 32);
    frame(s, &at, TS_DERP_PEER_GONE, b, 31);
    t_true("derp: peer gone", ts_derp_feed(D, s, at, 2000) == 0 &&
                              strcmp(logbuf, "gone 5177;gone 5177;") == 0);

    /* Health set (cleaned, capped at 200) and cleared; the clear is the last
     * bytes of a feed. */
    reset_capture();
    at = 0;
    frame(s, &at, TS_DERP_HEALTH, (const uint8_t *)"relay\x01 sad\n\x7f", 12);
    t_true("derp: health set", ts_derp_feed(D, s, at, 2000) == 0 &&
                               strcmp(last_health, "relay? sad??") == 0);
    memset(b, 'h', sizeof b);
    at = 0;
    frame(s, &at, TS_DERP_HEALTH, b, 300);
    t_true("derp: health capped", ts_derp_feed(D, s, at, 2000) == 0 &&
                                  strlen(last_health) == TS_DERP_HEALTH_MAX);
    at = 0;
    frame(s, &at, TS_DERP_HEALTH, NULL, 0);
    t_true("derp: health cleared", ts_derp_feed(D, s, at, 2000) == 0 && n_health == 3 &&
                                   last_health[0] == 0);

    /* Restarting, KeepAlive, PeerPresent, ServerKey again: ignored. An
     * unknown type of 70000 bytes skipped across many feeds. */
    reset_capture();
    at = 0;
    frame(s, &at, TS_DERP_RESTARTING, (const uint8_t *)"\0\0\0\1\0\0\0\2", 8);
    frame(s, &at, TS_DERP_KEEP_ALIVE, NULL, 0);
    frame(s, &at, 0x09, peer, 32);
    t_true("derp: ignored frames", ts_derp_feed(D, s, at, 2000) == 0 && log_n == 0 && sent_n == 0);
    s[0] = 0x7e;
    ts_put_be32(s + 1, 70000);
    memset(s + 5, 0x05, 70000);   /* body looks like frames: must not be parsed */
    ok = 1;
    for (i = 0; i < 5 + 70000; i += 999) {
        size_t k = 5 + 70000 - i < 999 ? 5 + 70000 - i : 999;
        if (ts_derp_feed(D, s + i, k, 2000) != 0) ok = 0;
    }
    at = 0;
    frame(s, &at, TS_DERP_PONG, (const uint8_t *)"\x03xxxxxx\x04", 8);
    t_true("derp: unknown 70000 skipped",
           ok && ts_derp_feed(D, s, at, 2000) == 0 && strcmp(logbuf, "pong 0304;") == 0);

    /* Exactly TS_DERP_MAX_FRAME is allowed; 2 MiB is fatal. */
    {
        uint8_t *big = calloc(1, 5 + TS_DERP_MAX_FRAME);
        big[0] = 0x7f;
        ts_put_be32(big + 1, TS_DERP_MAX_FRAME);
        t_true("derp: 1 MiB frame", ts_derp_feed(D, big, 5 + TS_DERP_MAX_FRAME, 2000) == 0);
        free(big);
    }
    s[0] = 0x7f;
    ts_put_be32(s + 1, 2u << 20);
    t_true("derp: 2 MiB fatal", ts_derp_feed(D, s, 5, 2000) == -1 && !ts_derp_ready(D) &&
                                D->err != NULL);
    t_true("derp: dead send refused", ts_derp_send_packet(D, peer, b, 1) == -1 &&
                                      ts_derp_ping(D, b) == -1);

    /* ServerInfo forged with a wrong key: fatal, before or after ready. */
    {
        uint8_t g[512];
        at = 0;
        put(g, &at, RESP101, sizeof RESP101 - 1);
        server_key_frame(g, &at);
        server_info_frame(g, &at, o_priv, INFO_JSON);
        client_new(0);
        t_true("derp: forged server info", ts_derp_feed(D, g, at, 1000) == -1 && !ts_derp_ready(D));
        t_true("derp: ready again", connect_ready(0) == 0);
        at = 0;
        server_info_frame(g, &at, o_priv, INFO_JSON);
        t_true("derp: forged later server info", ts_derp_feed(D, g, at, 1000) == -1);
        t_true("derp: ready for good info", connect_ready(0) == 0);
        at = 0;
        server_info_frame(g, &at, s_priv, "{}");
        t_true("derp: good later server info", ts_derp_feed(D, g, at, 1000) == 0 && ts_derp_ready(D));
    }

    /* A non-101 response is fatal. */
    client_new(0);
    {
        static const char r[] = "HTTP/1.1 426 Upgrade Required\r\n\r\n";
        t_true("derp: non-101", ts_derp_feed(D, (const uint8_t *)r, sizeof r - 1, 1000) == -1);
    }
    client_new(0);
    {
        static const char r[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        t_true("derp: wrong upgrade", ts_derp_feed(D, (const uint8_t *)r, sizeof r - 1, 1000) == -1);
    }

    /* Read timeout: 120 s with no frame is dead, 119 s is not; a frame
     * resets the clock. */
    t_true("derp: ready for timeout", connect_ready(0) == 0);
    t_true("derp: 119 s", ts_derp_tick(D, 1000 + 119000) == 0);
    at = 0;
    frame(s, &at, TS_DERP_KEEP_ALIVE, NULL, 0);
    t_true("derp: keepalive", ts_derp_feed(D, s, at, 1000 + 119000) == 0);
    t_true("derp: 119 s after keepalive", ts_derp_tick(D, 1000 + 238000) == 0);
    t_true("derp: 120 s after keepalive", ts_derp_tick(D, 1000 + 239000) == -1 && D->err != NULL);
    t_true("derp: not ready after timeout", !ts_derp_ready(D));
    /* A partial frame does not reset it. */
    t_true("derp: ready for partial", connect_ready(0) == 0);
    at = 0;
    frame(s, &at, TS_DERP_PONG, (const uint8_t *)"12345678", 8);
    t_true("derp: partial frame", ts_derp_feed(D, s, 4, 1000 + 60000) == 0);
    t_true("derp: 120 s since the last whole frame", ts_derp_tick(D, 1000 + 120000) == -1);

    ts_derp_free(D);
    free(D);
}

void test_derp_send(void)
{
    static uint8_t p[TS_DERP_MAX_PACKET + 1];
    uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t i;

    D = malloc(sizeof *D);
    keys();
    for (i = 0; i < sizeof p; i++) p[i] = (uint8_t)(i * 3 + 1);

    /* Nothing before ready. */
    client_new(0);
    reset_capture();
    t_true("derp: send before ready", ts_derp_send_packet(D, peer, p, 10) == -1 && sent_n == 0);
    t_true("derp: ping before ready", ts_derp_ping(D, data) == -1 && sent_n == 0);

    /* SendPacket framing; 65536 accepted in one send, 65537 refused. */
    t_true("derp: send ready", connect_ready(0) == 0);
    t_true("derp: send small", ts_derp_send_packet(D, peer, p, 3) == 0 && sent_n == 5 + 32 + 3 &&
                               sent[0] == TS_DERP_SEND_PACKET && ts_get_be32(sent + 1) == 35 &&
                               memcmp(sent + 5, peer, 32) == 0 && memcmp(sent + 37, p, 3) == 0);
    reset_capture();
    t_true("derp: send 65536", ts_derp_send_packet(D, peer, p, TS_DERP_MAX_PACKET) == 0 &&
                               sent_n == 5 + 32 + TS_DERP_MAX_PACKET &&
                               ts_get_be32(sent + 1) == 32 + TS_DERP_MAX_PACKET &&
                               memcmp(sent + 37, p, TS_DERP_MAX_PACKET) == 0);
    reset_capture();
    t_true("derp: send 65537 refused",
           ts_derp_send_packet(D, peer, p, TS_DERP_MAX_PACKET + 1) == -1 && sent_n == 0 &&
           ts_derp_ready(D));

    /* Ping framing. */
    reset_capture();
    t_true("derp: ping", ts_derp_ping(D, data) == 0 && sent_n == 13 &&
                         memcmp(sent, "\x12\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08", 13) == 0);

    /* NotePreferred: once at ready when preferred, then only on change. */
    {
        uint8_t g[512];
        size_t n = greeting(g);
        const uint8_t *np;
        client_new(1);
        t_true("derp: preferred ready", ts_derp_feed(D, g, n, 1000) == 0 && ts_derp_ready(D));
        np = sent + sizeof REQUEST - 1 + 5 + 104;
        t_true("derp: note preferred at ready",
               sent_n == sizeof REQUEST - 1 + 5 + 104 + 6 &&
               memcmp(np, "\x07\x00\x00\x00\x01\x01", 6) == 0);
        reset_capture();
        ts_derp_note_preferred(D, 1);
        t_true("derp: note preferred unchanged", sent_n == 0);
        ts_derp_note_preferred(D, 0);
        t_true("derp: note preferred off", sent_n == 6 && memcmp(sent, "\x07\x00\x00\x00\x01\x00", 6) == 0);
        reset_capture();
        ts_derp_note_preferred(D, 0);
        t_true("derp: note preferred off again", sent_n == 0);

        /* Not preferred at init, set before ready: sent once at ready. */
        client_new(0);
        ts_derp_note_preferred(D, 1);
        t_true("derp: note preferred waits", sent_n == sizeof REQUEST - 1);
        t_true("derp: ready 2", ts_derp_feed(D, g, n, 1000) == 0);
        t_true("derp: note preferred sent at ready",
               sent_n == sizeof REQUEST - 1 + 5 + 104 + 6 &&
               memcmp(sent + sizeof REQUEST - 1 + 5 + 104, "\x07\x00\x00\x00\x01\x01", 6) == 0);
    }

    ts_derp_free(D);
    free(D);
}
