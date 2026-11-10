#include "fuzz.h"

#include <stdlib.h>
#include <string.h>

#include "../src/control/session.h"

#include "fake_control.inc"

/* Two targets.
 *
 * "session": the session's own parsers. One mode byte, then data; mode % 3:
 *   0  a RegisterResponse document
 *   1  a Retry-After value
 *   2  a PingRequest URL split into authority and path
 *
 * "session_stream": the server's HTTP/2 plaintext after a real handshake with
 * the fake server, when the session has sent its register. Input: BE16 split,
 * then bytes; bytes[0..split) and the rest are sealed and delivered in two
 * reads, so the map request opened after the first can be answered by the
 * second. Then the clock runs for a while. Each iteration is a full handshake,
 * so this target runs fewer iterations. */

#define STREAM_ITERS 10000u

static ts_sess *g_s;
static fake g_f;

static void parsers(const uint8_t *d, size_t len)
{
    char *z;
    if (len == 0) return;
    z = (char *)malloc(len);
    TS_FUZZ_ASSERT(z != NULL);
    memcpy(z, d + 1, len - 1);
    z[len - 1] = 0;
    switch (d[0] % 3) {
    case 0: {
        ts_reg_resp r;
        int rc = ts_reg_resp_parse(&r, (const char *)d + 1, len - 1);
        TS_FUZZ_ASSERT(rc == 0 || rc == -1);
        TS_FUZZ_ASSERT(strlen(r.auth_url) <= TS_SESS_URL_MAX && strlen(r.error) <= TS_SESS_ERR_BODY_MAX);
        if (rc == -1) TS_FUZZ_ASSERT(!r.auth_url[0] && !r.node_key_expired && !r.machine_authorized);
        break;
    }
    case 1: {
        int ms = ts_retry_after_parse((const char *)d + 1, len - 1);
        TS_FUZZ_ASSERT(ms == -1 || (ms >= 1000 && ms <= TS_SESS_RETRY_AFTER_MAX_MS && ms % 1000 == 0));
        break;
    }
    default: {
        char a[64], p[64];
        size_t i;
        if (ts_url_split(z, a, sizeof a, p, sizeof p) == 0) {
            TS_FUZZ_ASSERT(a[0] && p[0] == '/');
            for (i = 0; a[i]; i++) TS_FUZZ_ASSERT(a[i] > ' ' && a[i] <= '~' && a[i] != '/' && a[i] != '@');
            for (i = 0; p[i]; i++) TS_FUZZ_ASSERT(p[i] > ' ' && p[i] <= '~' && p[i] != '#');
        } else {
            TS_FUZZ_ASSERT(a[0] == 0 && p[0] == 0);
        }
    }
    }
    free(z);
}

static ts_sess_state stream_run(const uint8_t *d, size_t len)
{
    char st[2048];
    size_t split;
    const char *url;
    ts_sess_state state;
    fk_init(&g_f, g_s, NULL);
    fk_start(&g_f, "{\"OS\":\"macOS\"}");
    ts_sess_up(g_s);
    fk_pump(&g_f);
    TS_FUZZ_ASSERT(g_f.nreq == 1 && g_f.up);
    if (len >= 2) {
        split = ts_get_be16(d);
        d += 2;
        len -= 2;
        if (split > len) split = len;
        fk_send_plain(&g_f, d, split);
        fk_pump(&g_f);
        if (g_f.up && len > split) {
            fk_send_plain(&g_f, d + split, len - split);
            fk_pump(&g_f);
        }
    }
    fk_advance(&g_f, 200000, 10000);
    state = ts_sess_get_state(g_s);
    TS_FUZZ_ASSERT(state >= TS_SESS_IDLE && state <= TS_SESS_FAILED);
    ts_sess_status(g_s, st, sizeof st);
    TS_FUZZ_ASSERT(strlen(st) < sizeof st);
    url = ts_sess_login_url(g_s);
    TS_FUZZ_ASSERT(!url || state == TS_SESS_NEED_LOGIN);
    fk_free(&g_f);
    return state;
}

static void stream(const uint8_t *d, size_t len)
{
    (void)stream_run(d, len);
}

/* ---- Seeds ------------------------------------------------------------ */

typedef struct {
    uint8_t b[4096];
    size_t n;
} sbuf;

static void s_frame(sbuf *o, unsigned type, unsigned flags, uint32_t sid, const void *p, size_t len)
{
    uint8_t l[4];
    ts_put_be32(l, (uint32_t)len);
    TS_FUZZ_ASSERT(o->n + 9 + len <= sizeof o->b);
    memcpy(o->b + o->n, l + 1, 3);
    o->b[o->n + 3] = (uint8_t)type;
    o->b[o->n + 4] = (uint8_t)flags;
    ts_put_be32(o->b + o->n + 5, sid);
    if (len) memcpy(o->b + o->n + 9, p, len);
    o->n += 9 + len;
}

static void s_headers(sbuf *o, uint32_t sid, const char *status, const char *ra, int end)
{
    uint8_t blk[256];
    size_t bl = ts_hpack_encode(blk, sizeof blk, ":status", status);
    if (ra) bl += ts_hpack_encode(blk + bl, sizeof blk - bl, "retry-after", ra);
    s_frame(o, FK_HEADERS, 0x4 | (end ? 1 : 0), sid, blk, bl);
}

static void s_data(sbuf *o, uint32_t sid, const char *s, int end)
{
    s_frame(o, FK_DATA, end ? 1 : 0, sid, s, strlen(s));
}

static void s_msg(sbuf *o, uint32_t sid, const char *json)
{
    uint8_t buf[2048];
    size_t n = strlen(json);
    TS_FUZZ_ASSERT(n + 4 <= sizeof buf);
    ts_put_le32(buf, (uint32_t)n);
    memcpy(buf + 4, json, n);
    s_frame(o, FK_DATA, 0, sid, buf, n + 4);
}

static void s_split(sbuf *o)
{
    ts_put_be16(o->b, (uint16_t)(o->n - 2));
}

#define SEED_SELF "{\"ID\":1,\"Name\":\"self.example.test.\",\"Key\":\"nodekey:" \
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"Addresses\":[\"100.64.0.1/32\"]," \
    "\"MachineAuthorized\":true,\"KeyExpiry\":\"2027-01-01T00:00:00Z\"}"

void ts_fuzz_session(void)
{
    static const char *const P[] = {
        "\x00{\"User\":{\"ID\":1},\"Login\":{},\"NodeKeyExpired\":false,\"MachineAuthorized\":true,"
        "\"AuthURL\":\"https://login.example.test/a/b\",\"NodeKeySignature\":null,\"Error\":\"x\\u0041\"}",
        "\x00{\"NodeKeySignature\":\"AAEC\",\"AuthURL\":null}",
        "\x01 30 ",
        "\x01" "99999999999",
        "\x02https://ping.example.test:443/p/1?x=y",
        "\x02http://h?q",
    };
    static sbuf seeds[4];
    const uint8_t *sp[6], *ss[4];
    size_t sl[6], sn[4], i;
    static const uint8_t ping[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    for (i = 0; i < 6; i++) {
        sp[i] = (const uint8_t *)P[i];
        sl[i] = strlen(P[i] + 1) + 1;
    }
    ts_fuzz_run("session", parsers, sp, sl, 6, TS_FUZZ_DEFAULT_ITERS);

    g_s = (ts_sess *)calloc(1, sizeof *g_s);
    TS_FUZZ_ASSERT(g_s != NULL);
    memset(seeds, 0, sizeof seeds);
    /* Login accepted, then a map with a ping, a sleep, a keepalive and a PING. */
    seeds[0].n = 2;
    s_headers(&seeds[0], 1, "200", NULL, 0);
    s_data(&seeds[0], 1, "{\"MachineAuthorized\":true}", 1);
    s_split(&seeds[0]);
    s_headers(&seeds[0], 3, "200", NULL, 0);
    s_msg(&seeds[0], 3, "{\"Node\":" SEED_SELF ",\"Peers\":[{\"ID\":10,\"Addresses\":[\"100.64.0.10/32\"]}]}");
    s_msg(&seeds[0], 3, "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p\",\"URLIsNoise\":true}}");
    s_msg(&seeds[0], 3, "{\"Debug\":{\"SleepSeconds\":20},\"PeersRemoved\":[10]}");
    s_frame(&seeds[0], FK_PING, 0, 0, ping, 8);
    /* A login URL, then rate limits and a GOAWAY. */
    seeds[1].n = 2;
    s_headers(&seeds[1], 1, "200", NULL, 0);
    s_data(&seeds[1], 1, "{\"AuthURL\":\"https://login.example.test/a/c\"}", 1);
    s_split(&seeds[1]);
    s_headers(&seeds[1], 3, "429", "5", 1);
    s_frame(&seeds[1], FK_GOAWAY, 0, 0, "\0\0\0\3\0\0\0\0", 8);
    /* Register rate limited, then NodeKeyExpired on the retry. */
    seeds[2].n = 2;
    s_headers(&seeds[2], 1, "429", "1", 0);
    s_data(&seeds[2], 1, "slow", 1);
    s_split(&seeds[2]);
    s_headers(&seeds[2], 3, "200", NULL, 0);
    s_data(&seeds[2], 3, "{\"NodeKeyExpired\":true}", 1);
    /* Map 404, a Tailnet Lock map, Debug.Exit. */
    seeds[3].n = 2;
    s_headers(&seeds[3], 1, "200", NULL, 0);
    s_data(&seeds[3], 1, "{}", 1);
    s_split(&seeds[3]);
    s_headers(&seeds[3], 3, "200", NULL, 0);
    s_msg(&seeds[3], 3, "{\"Node\":" SEED_SELF ",\"TKAInfo\":{},\"Debug\":{\"Exit\":0}}");
    s_headers(&seeds[3], 5, "404", NULL, 1);
    for (i = 0; i < 4; i++) {
        ss[i] = seeds[i].b;
        sn[i] = seeds[i].n;
    }
    /* The seeds reach the states they were written for. */
    TS_FUZZ_ASSERT(stream_run(ss[0], sn[0]) == TS_SESS_RUNNING);
    TS_FUZZ_ASSERT(stream_run(ss[1], sn[1]) == TS_SESS_NEED_LOGIN);
    TS_FUZZ_ASSERT(stream_run(ss[2], sn[2]) == TS_SESS_CONNECTING);
    TS_FUZZ_ASSERT(stream_run(ss[3], sn[3]) == TS_SESS_FAILED);
    ts_fuzz_run("session_stream", stream, ss, sn, 4, STREAM_ITERS);
    free(g_s);
}
