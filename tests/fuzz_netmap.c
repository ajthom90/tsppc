#include "fuzz.h"
#include "../src/control/netmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Oracles, for each input:
 * - apply it to a map restored from one of two base states (3 peers, or 255
 *   so the TS_MAX_PEERS limit is reachable);
 * - invariants hold after every apply: npeers <= TS_MAX_PEERS, unique IDs,
 *   every name and ping string NUL-terminated, sleep within its cap;
 * - a rejected message leaves the observable state byte-for-byte unchanged;
 * - an accepted message is idempotent: applying it again succeeds and changes
 *   nothing (every MapResponse field we apply is);
 * - the input fed to the stream framer whole and in small pieces gives the
 *   same messages and the same result. */

#define HA "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HB "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

typedef struct {
    ts_node self;
    int have_self, tka, have_exit, exit_code;
    uint32_t sleep_ms;
    size_t npeers;
    ts_node peers[TS_MAX_PEERS];
    ts_ping_req ping;
} snap;

static ts_netmap M;
static snap *BASE[2], *S1, *S2;

static void take(snap *s, const ts_netmap *m)
{
    memset(s, 0, sizeof *s);
    s->self = m->self;
    s->have_self = m->have_self;
    s->tka = m->tka_enabled;
    s->have_exit = m->have_exit;
    s->exit_code = m->exit_code;
    s->sleep_ms = m->sleep_ms;
    s->npeers = m->npeers;
    if (m->npeers) memcpy(s->peers, m->peers, m->npeers * sizeof(ts_node));
    s->ping = m->ping;
}

static void restore(ts_netmap *m, const snap *s)
{
    ts_netmap_reset(m);
    m->self = s->self;
    m->have_self = s->have_self;
    m->tka_enabled = s->tka;
    m->have_exit = s->have_exit;
    m->exit_code = s->exit_code;
    m->sleep_ms = s->sleep_ms;
    m->npeers = s->npeers;
    if (s->npeers) memcpy(m->peers, s->peers, s->npeers * sizeof(ts_node));
    m->ping = s->ping;
}

static void check_node(const ts_node *n)
{
    TS_FUZZ_ASSERT(memchr(n->name, 0, sizeof n->name) != NULL);
    TS_FUZZ_ASSERT(n->have_ipv4 == 0 || n->have_ipv4 == 1);
    TS_FUZZ_ASSERT(n->have_ipv4 || n->ipv4 == 0);
}

static void invariants(const ts_netmap *m)
{
    size_t i, k;
    TS_FUZZ_ASSERT(m->npeers <= TS_MAX_PEERS);
    for (i = 0; i < m->npeers; i++) {
        check_node(&m->peers[i]);
        for (k = i + 1; k < m->npeers; k++) TS_FUZZ_ASSERT(m->peers[i].id != m->peers[k].id);
    }
    check_node(&m->self);
    TS_FUZZ_ASSERT(memchr(m->ping.url, 0, sizeof m->ping.url) != NULL);
    TS_FUZZ_ASSERT(memchr(m->ping.types, 0, sizeof m->ping.types) != NULL);
    TS_FUZZ_ASSERT(!m->ping.pending || m->ping.url[0] != 0);
    TS_FUZZ_ASSERT(m->sleep_ms <= TS_MAP_SLEEP_MAX_MS);
    TS_FUZZ_ASSERT(memchr(m->last_error, 0, sizeof m->last_error) != NULL);
}

typedef struct {
    uint8_t *buf;
    size_t len, cap;
    size_t count;
    uint32_t sum;     /* of message lengths and order */
} collect;

static void on_msg(void *user, const char *data, size_t len)
{
    collect *c = (collect *)user;
    c->count++;
    c->sum = c->sum * 31u + (uint32_t)len;
    if (c->len + len > c->cap) {
        size_t nc = (c->len + len) * 2 + 16;
        uint8_t *nb = (uint8_t *)realloc(c->buf, nc);
        TS_FUZZ_ASSERT(nb != NULL);
        c->buf = nb;
        c->cap = nc;
    }
    if (len) memcpy(c->buf + c->len, data, len);
    c->len += len;
}

static void stream_check(const uint8_t *data, size_t len)
{
    collect a, b;
    ts_map_stream s;
    int ra, rb = 0;
    size_t i, step = 1 + (len % 7);

    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    ts_map_stream_init(&s, on_msg, &a);
    ra = ts_map_stream_feed(&s, data, len);
    TS_FUZZ_ASSERT(s.cap <= TS_MAP_MSG_MAX);
    ts_map_stream_free(&s);

    ts_map_stream_init(&s, on_msg, &b);
    for (i = 0; i < len && rb == 0; i += step)
        rb = ts_map_stream_feed(&s, data + i, len - i < step ? len - i : step);
    TS_FUZZ_ASSERT(s.cap <= TS_MAP_MSG_MAX);
    ts_map_stream_free(&s);

    TS_FUZZ_ASSERT(ra == rb);
    TS_FUZZ_ASSERT(a.count == b.count && a.sum == b.sum && a.len == b.len);
    TS_FUZZ_ASSERT(a.len == 0 || memcmp(a.buf, b.buf, a.len) == 0);
    free(a.buf);
    free(b.buf);
}

static void target(const uint8_t *data, size_t len)
{
    const char *json = (const char *)data;

    restore(&M, BASE[len & 1]);
    take(S1, &M);
    if (ts_netmap_apply(&M, json, len) != 0) {
        invariants(&M);
        TS_FUZZ_ASSERT(M.last_error[0] != 0);
        take(S2, &M);
        TS_FUZZ_ASSERT(memcmp(S1, S2, sizeof *S1) == 0);
    } else {
        invariants(&M);
        take(S1, &M);
        TS_FUZZ_ASSERT(ts_netmap_apply(&M, json, len) == 0);
        invariants(&M);
        take(S2, &M);
        TS_FUZZ_ASSERT(memcmp(S1, S2, sizeof *S1) == 0);
    }
    stream_check(data, len);
}

static char *big_base(void)
{
    size_t cap = 255 * 100 + 256, n;
    char *s = (char *)malloc(cap);
    int i;
    TS_FUZZ_ASSERT(s != NULL);
    n = (size_t)snprintf(s, cap, "{\"Node\":{\"ID\":1},\"Peers\":[");
    for (i = 0; i < 255; i++)
        n += (size_t)snprintf(s + n, cap - n, "%s{\"ID\":%d,\"Name\":\"p%d.\",\"Online\":true}",
                              i ? "," : "", 100 + i, i);
    snprintf(s + n, cap - n, "]}");
    return s;
}

static const char *const SEEDS[] = {
    "{\"Node\":{\"ID\":1,\"Name\":\"self.example.test.\",\"Key\":\"nodekey:" HA "\","
    "\"DiscoKey\":\"discokey:" HB "\",\"Addresses\":[\"fd7a:115c:a1e0::1/128\",\"100.64.0.1/32\"],"
    "\"HomeDERP\":2,\"MachineAuthorized\":true,\"KeyExpiry\":\"2026-12-01T00:00:00Z\","
    "\"Expired\":false,\"IsJailed\":true,\"IsWireGuardOnly\":false,\"Online\":true},"
    "\"Peers\":[{\"ID\":10,\"Name\":\"a.example.test.\",\"DERP\":\"127.3.3.40:7\"},{\"ID\":11}],"
    "\"TKAInfo\":{\"Head\":\"h\",\"Disabled\":false},\"Debug\":{\"Exit\":1,\"SleepSeconds\":2.5},"
    "\"PingRequest\":{\"URL\":\"https://ping.example.test/x\",\"URLIsNoise\":true,\"Types\":\"\"},"
    "\"DERPMap\":{\"Regions\":{}},\"KeepAlive\":false}",
    "{\"PeersRemoved\":[10],\"OnlineChange\":{\"11\":true},\"PeerSeenChange\":{\"11\":true},"
    "\"PeersChanged\":[{\"ID\":12,\"Key\":\"nodekey:" HB "\"}],"
    "\"PeersChangedPatch\":[{\"NodeID\":11,\"DERPRegion\":4,\"Online\":false,\"Key\":\"nodekey:" HA "\","
    "\"DiscoKey\":\"discokey:" HA "\",\"KeyExpiry\":\"2100-01-01T00:00:00.5+02:00\"}],"
    "\"Peers\":[{\"ID\":13}]}",
    "{\"PeersChanged\":[{\"ID\":500},{\"ID\":501}],\"PeersRemoved\":[101]}",
    "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/y\",\"Types\":\"c2n\"}}",
    "{\"Peers\":[],\"OnlineChange\":{\"100\":false,\"-5\":true},\"Debug\":{\"Exit\":null,\"SleepSeconds\":1e400}}",
    "\x0f\x00\x00\x00{\"KeepAlive\":1}\x00\x00\x00\x00\x02\x00\x00\x00{}\xff\xff\xff\x7f",
};

void ts_fuzz_netmap(void)
{
    const uint8_t *seeds[sizeof SEEDS / sizeof SEEDS[0]];
    size_t lens[sizeof SEEDS / sizeof SEEDS[0]], i, nseeds = sizeof SEEDS / sizeof SEEDS[0];
    static const size_t framed_len = 4 + 15 + 4 + 4 + 2 + 4;
    char *big;

    TS_FUZZ_ASSERT(ts_netmap_init(&M) == 0);
    BASE[0] = (snap *)malloc(sizeof(snap));
    BASE[1] = (snap *)malloc(sizeof(snap));
    S1 = (snap *)malloc(sizeof(snap));
    S2 = (snap *)malloc(sizeof(snap));
    TS_FUZZ_ASSERT(BASE[0] && BASE[1] && S1 && S2);
    TS_FUZZ_ASSERT(ts_netmap_apply(&M, SEEDS[0], strlen(SEEDS[0])) == 0);
    take(BASE[0], &M);
    ts_netmap_reset(&M);
    big = big_base();
    TS_FUZZ_ASSERT(ts_netmap_apply(&M, big, strlen(big)) == 0 && M.npeers == 255);
    take(BASE[1], &M);
    free(big);

    for (i = 0; i < nseeds; i++) {
        seeds[i] = (const uint8_t *)SEEDS[i];
        lens[i] = i + 1 == nseeds ? framed_len : strlen(SEEDS[i]);
    }
    ts_fuzz_run("netmap", target, seeds, lens, nseeds, TS_FUZZ_DEFAULT_ITERS);

    ts_netmap_free(&M);
    free(BASE[0]);
    free(BASE[1]);
    free(S1);
    free(S2);
}
