#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/control/netmap.h"

/* Invented keys and names only. */
#define HA "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HB "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define HC "1111111111111111111111111111111111111111111111111111111111111111"

#define SELF_JSON(auth) \
    "{\"ID\":1,\"Name\":\"self.example.test.\",\"Key\":\"nodekey:" HA "\"," \
    "\"DiscoKey\":\"discokey:" HB "\",\"Addresses\":[\"100.64.0.1/32\",\"fd7a:115c:a1e0::1/128\"]," \
    "\"HomeDERP\":2,\"MachineAuthorized\":" auth ",\"KeyExpiry\":\"2026-12-01T00:00:00Z\"}"

#define PEER_A \
    "{\"ID\":10,\"Name\":\"alpha.example.test.\",\"Key\":\"nodekey:" HB "\"," \
    "\"DiscoKey\":\"discokey:" HC "\",\"Addresses\":[\"fd7a:115c:a1e0::a/128\",\"100.64.0.10/32\"]," \
    "\"HomeDERP\":3,\"Online\":true,\"MachineAuthorized\":true,\"KeyExpiry\":\"0001-01-01T00:00:00Z\"}"

#define PEER_B \
    "{\"ID\":11,\"Name\":\"beta.example.test.\",\"Key\":\"nodekey:" HC "\"," \
    "\"Addresses\":[\"100.64.0.11/32\"],\"DERP\":\"127.3.3.40:7\",\"MachineAuthorized\":true," \
    "\"Expired\":true,\"IsJailed\":true,\"IsWireGuardOnly\":true}"

#define FULL_MAP "{\"Node\":" SELF_JSON("true") ",\"Peers\":[" PEER_A "," PEER_B "]}"

static int apply(ts_netmap *m, const char *s)
{
    return ts_netmap_apply(m, s, strlen(s));
}

/* The observable state, for "unchanged" checks. */
typedef struct {
    ts_node self;
    int have_self, tka, have_exit, exit_code;
    uint32_t sleep_ms;
    size_t npeers;
    ts_node peers[TS_MAX_PEERS];
    ts_ping_req ping;
} snap;

static snap *take(const ts_netmap *m)
{
    snap *s = (snap *)calloc(1, sizeof *s);
    if (!s) abort();
    s->self = m->self;
    s->have_self = m->have_self;
    s->tka = m->tka_enabled;
    s->have_exit = m->have_exit;
    s->exit_code = m->exit_code;
    s->sleep_ms = m->sleep_ms;
    s->npeers = m->npeers;
    if (m->npeers) memcpy(s->peers, m->peers, m->npeers * sizeof(ts_node));
    s->ping = m->ping;
    return s;
}

static int same(const snap *a, const snap *b)
{
    return memcmp(a, b, sizeof *a) == 0;
}

static void t_unchanged(const char *name, ts_netmap *m, const char *msg)
{
    snap *a = take(m), *b;
    char label[160];
    int rc = apply(m, msg);
    b = take(m);
    snprintf(label, sizeof label, "%s: rejected", name);
    t_true(label, rc == -1 && m->last_error[0] != 0);
    snprintf(label, sizeof label, "%s: map unchanged", name);
    t_true(label, same(a, b));
    free(a);
    free(b);
}

static void test_full_map(void)
{
    ts_netmap m;
    const ts_node *a, *b;
    uint8_t k[32];

    t_true("netmap init", ts_netmap_init(&m) == 0);
    t_true("full map applies", apply(&m, FULL_MAP) == 0);
    t_true("self present", m.have_self && m.self.id == 1);
    t_true("self name", strcmp(m.self.name, "self.example.test.") == 0);
    t_unhex(k, HA);
    t_true("self node key", memcmp(m.self.node_key, k, 32) == 0);
    t_unhex(k, HB);
    t_true("self disco key", memcmp(m.self.disco_key, k, 32) == 0);
    t_true("self ipv4", m.self.have_ipv4 && m.self.ipv4 == 0x64400001u);
    t_true("self home derp", m.self.home_derp == 2);
    t_true("self authorized", m.self.authorized == 1);
    t_true("self key expiry", m.self.key_expiry == (int64_t)1796083200);
    t_true("two peers", m.npeers == 2);
    a = ts_netmap_peer(&m, 10);
    b = ts_netmap_peer(&m, 11);
    t_true("peer a found", a != NULL);
    t_true("peer b found", b != NULL);
    if (a) {
        t_true("peer a ipv4 after an ipv6", a->have_ipv4 && a->ipv4 == 0x6440000au);
        t_true("peer a online", a->online == 1);
        t_true("peer a derp", a->home_derp == 3);
        t_true("peer a zero-time expiry is 0", a->key_expiry == 0);
        t_true("peer a name", strcmp(a->name, "alpha.example.test.") == 0);
        t_true("peer a flags", !a->expired && !a->jailed && !a->wireguard_only);
    }
    if (b) {
        t_true("peer b online absent is 0", b->online == 0);
        t_true("peer b legacy DERP string", b->home_derp == 7);
        t_true("peer b no disco key", b->disco_key[0] == 0 && b->disco_key[31] == 0);
        t_true("peer b expired, jailed, wg-only", b->expired && b->jailed && b->wireguard_only);
        t_true("peer b no expiry", b->key_expiry == 0);
    }
    t_true("no tka, no exit, no sleep, no ping",
           !m.tka_enabled && !m.have_exit && m.sleep_ms == 0 && !m.ping.pending);
    ts_netmap_free(&m);
}

static void test_authorization(void)
{
    ts_netmap m;
    ts_netmap_init(&m);
    t_true("unauthorized map applies", apply(&m, "{\"Node\":" SELF_JSON("false") "}") == 0);
    t_true("self not authorized", m.have_self && m.self.authorized == 0);
    t_true("approval arrives",
           apply(&m, "{\"PeersChanged\":[" PEER_A "],\"Node\":" SELF_JSON("true") "}") == 0);
    t_true("self authorized", m.self.authorized == 1);
    t_true("peer added with it", m.npeers == 1 && ts_netmap_peer(&m, 10) != NULL);
    ts_netmap_free(&m);
}

static void test_deltas(void)
{
    ts_netmap m;
    const ts_node *p;
    snap *before;
    uint8_t k[32];

    ts_netmap_init(&m);
    apply(&m, FULL_MAP);

    /* Add one, change one. PeersChanged replaces the whole node. */
    t_true("upsert applies", apply(&m,
        "{\"PeersChanged\":[{\"ID\":12,\"Name\":\"gamma.example.test.\",\"Key\":\"nodekey:" HA "\","
        "\"Addresses\":[\"100.64.0.12/32\"]},"
        "{\"ID\":10,\"Name\":\"alpha2.example.test.\",\"Key\":\"nodekey:" HB "\"}]}") == 0);
    t_true("three peers", m.npeers == 3);
    p = ts_netmap_peer(&m, 10);
    t_true("peer changed wholesale", p && strcmp(p->name, "alpha2.example.test.") == 0
           && p->online == 0 && p->home_derp == 0 && !p->have_ipv4);
    p = ts_netmap_peer(&m, 12);
    t_true("peer added", p && p->ipv4 == 0x6440000cu);

    t_true("remove applies", apply(&m, "{\"PeersRemoved\":[11,999]}") == 0);
    t_true("peer removed", m.npeers == 2 && ts_netmap_peer(&m, 11) == NULL);
    t_true("others kept", ts_netmap_peer(&m, 10) && ts_netmap_peer(&m, 12));

    /* Patch: only Online present, nothing else changes. */
    apply(&m, "{\"PeersChanged\":[" PEER_A "]}");
    before = take(&m);
    t_true("patch applies", apply(&m, "{\"PeersChangedPatch\":[{\"NodeID\":10,\"Online\":false},"
                                      "{\"NodeID\":4242,\"Online\":true}]}") == 0);
    p = ts_netmap_peer(&m, 10);
    t_true("patch changed Online", p && p->online == 0);
    if (p) {
        ts_node want = *ts_netmap_peer(&m, 10);
        size_t i;
        want.online = 1;
        for (i = 0; i < before->npeers; i++)
            if (before->peers[i].id == 10)
                t_true("patch changed only Online", memcmp(&before->peers[i], &want, sizeof want) == 0);
    }
    t_true("patch for unknown ID ignored", m.npeers == 2);
    free(before);

    t_true("patch other fields", apply(&m,
        "{\"PeersChangedPatch\":[{\"NodeID\":10,\"DERPRegion\":9,\"Key\":\"nodekey:" HC "\","
        "\"DiscoKey\":\"discokey:" HA "\",\"KeyExpiry\":\"2100-01-01T00:00:00Z\","
        "\"Endpoints\":[\"192.0.2.1:41641\"],\"LastSeen\":\"2026-01-01T00:00:00Z\",\"Cap\":150}]}") == 0);
    p = ts_netmap_peer(&m, 10);
    t_unhex(k, HC);
    t_true("patch key", p && memcmp(p->node_key, k, 32) == 0);
    t_unhex(k, HA);
    t_true("patch disco key", p && memcmp(p->disco_key, k, 32) == 0);
    t_true("patch derp", p && p->home_derp == 9);
    t_true("patch key expiry past 2038", p && p->key_expiry == (int64_t)4102444800LL);
    t_true("patch DERPRegion 0 is unchanged",
           apply(&m, "{\"PeersChangedPatch\":[{\"NodeID\":10,\"DERPRegion\":0}]}") == 0
           && ts_netmap_peer(&m, 10)->home_derp == 9);

    t_true("online change applies", apply(&m, "{\"OnlineChange\":{\"10\":true,\"12\":false,\"777\":true}}") == 0);
    t_true("online change set", ts_netmap_peer(&m, 10)->online == 1 && ts_netmap_peer(&m, 12)->online == 0);
    t_true("online change unknown ignored", m.npeers == 2);
    t_true("peer seen change ignored", apply(&m, "{\"PeerSeenChange\":{\"10\":true}}") == 0 && m.npeers == 2);

    /* Upstream order: Removed, Changed, OnlineChange, Patch, whatever the key order. */
    t_true("delta order", apply(&m,
        "{\"PeersChangedPatch\":[{\"NodeID\":20,\"DERPRegion\":5}],\"OnlineChange\":{\"20\":true},"
        "\"PeersChanged\":[{\"ID\":20,\"Name\":\"delta.example.test.\"}],\"PeersRemoved\":[20]}") == 0);
    p = ts_netmap_peer(&m, 20);
    t_true("delta order: added after remove, then online, then patch",
           p && p->online == 1 && p->home_derp == 5);

    /* Empty Peers never clears; deltas in that message still apply. */
    t_true("empty Peers applies", apply(&m, "{\"Peers\":[],\"PeersRemoved\":[20]}") == 0);
    t_true("empty Peers keeps peers", m.npeers == 2 && ts_netmap_peer(&m, 20) == NULL);
    t_true("null Peers applies", apply(&m, "{\"Peers\":null}") == 0 && m.npeers == 2);

    /* Non-empty Peers replaces and precludes the deltas of the same message. */
    t_true("Peers with deltas", apply(&m,
        "{\"PeersRemoved\":[11],\"OnlineChange\":{\"11\":false},"
        "\"PeersChanged\":[{\"ID\":30,\"Name\":\"x.example.test.\"}],"
        "\"PeersChangedPatch\":[{\"NodeID\":11,\"DERPRegion\":4}],"
        "\"Peers\":[" PEER_B "," PEER_B "]}") == 0);
    p = ts_netmap_peer(&m, 11);
    t_true("Peers replaced, duplicates collapse", m.npeers == 1 && p != NULL);
    t_true("deltas ignored with Peers", p && p->home_derp == 7 && ts_netmap_peer(&m, 30) == NULL);

    /* The last peer leaves through PeersRemoved. */
    t_true("last peer removed", apply(&m, "{\"PeersRemoved\":[11]}") == 0 && m.npeers == 0);
    ts_netmap_free(&m);
}

static void test_keepalive_and_extras(void)
{
    ts_netmap m;
    snap *a, *b;

    ts_netmap_init(&m);
    t_true("keepalive before any map", apply(&m, "{\"KeepAlive\":true}") == 0 && !m.have_self);
    t_unchanged("first map without Node", &m, "{\"Peers\":[" PEER_A "]}");
    t_true("first map error names Node", strstr(m.last_error, "Node") != NULL);
    apply(&m, FULL_MAP);

    a = take(&m);
    t_true("keepalive with other fields", apply(&m,
        "{\"Node\":" SELF_JSON("false") ",\"PeersRemoved\":[10],\"Debug\":{\"Exit\":3},"
        "\"TKAInfo\":{\"Head\":\"x\"},\"KeepAlive\":true}") == 0);
    b = take(&m);
    t_true("keepalive changes nothing", same(a, b));
    free(a);
    free(b);

    t_true("ping on keepalive", apply(&m,
        "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p/1\",\"URLIsNoise\":true,"
        "\"Log\":true,\"Payload\":\"AAEC\",\"IP\":\"100.64.0.10\"}}") == 0);
    t_true("ping pending", m.ping.pending && m.ping.url_is_noise
           && strcmp(m.ping.url, "https://ping.example.test/p/1") == 0 && m.ping.types[0] == 0);
    t_true("ping still only map change", m.npeers == 2 && m.self.authorized == 1);
    m.ping.pending = 0;
    t_true("ping with types", apply(&m,
        "{\"PingRequest\":{\"URL\":\"https://ping.example.test/p/2\",\"Types\":\"c2n\"}}") == 0);
    t_true("ping types", m.ping.pending && !m.ping.url_is_noise && strcmp(m.ping.types, "c2n") == 0);
    m.ping.pending = 0;
    t_unchanged("rejected message carrying a ping", &m,
        "{\"PingRequest\":{\"URL\":\"https://ping.example.test/p/3\"},\"PeersRemoved\":[\"x\"]}");
    t_true("rejected ping not stored", !m.ping.pending && strcmp(m.ping.url, "https://ping.example.test/p/2") == 0);
    t_true("ping without URL ignored",
           apply(&m, "{\"PingRequest\":{\"URLIsNoise\":true}}") == 0 && !m.ping.pending);
    {
        char *big = (char *)malloc(TS_PING_URL_MAX + 200);
        size_t n;
        strcpy(big, "{\"PingRequest\":{\"URL\":\"https://ping.example.test/");
        n = strlen(big);
        memset(big + n, 'a', TS_PING_URL_MAX);
        strcpy(big + n + TS_PING_URL_MAX, "\"}}");
        t_true("over-long ping URL ignored", apply(&m, big) == 0 && !m.ping.pending);
        free(big);
    }

    t_true("debug", apply(&m, "{\"Debug\":{\"Exit\":0,\"SleepSeconds\":1.5,\"DisableLogTail\":true}}") == 0);
    t_true("debug exit 0 present", m.have_exit && m.exit_code == 0);
    t_true("debug sleep", m.sleep_ms == 1500);
    t_true("debug ignored on keepalive", apply(&m, "{\"KeepAlive\":true,\"Debug\":{\"Exit\":5}}") == 0
           && !m.have_exit && m.exit_code == 0 && m.sleep_ms == 0);
    apply(&m, "{\"Debug\":{\"Exit\":0,\"SleepSeconds\":1.5}}");
    t_true("debug is per message", apply(&m, "{}") == 0 && !m.have_exit && m.sleep_ms == 0);
    apply(&m, "{\"Debug\":{\"Exit\":4}}");
    t_unchanged("rejected message keeps debug", &m, "{\"Debug\":{\"Exit\":9},\"PeersRemoved\":[\"x\"]}");
    t_true("debug kept after rejection", m.have_exit && m.exit_code == 4);
    t_true("debug sleep clamped", apply(&m, "{\"Debug\":{\"SleepSeconds\":1e9}}") == 0
           && m.sleep_ms == TS_MAP_SLEEP_MAX_MS);
    t_true("debug sleep negative", apply(&m, "{\"Debug\":{\"SleepSeconds\":-3}}") == 0 && m.sleep_ms == 0);
    t_true("debug exit 7", apply(&m, "{\"Debug\":{\"Exit\":7}}") == 0 && m.have_exit && m.exit_code == 7);

    t_true("tka on", apply(&m, "{\"TKAInfo\":{\"Head\":\"abc\"}}") == 0 && m.tka_enabled);
    t_true("tka absent unchanged", apply(&m, "{}") == 0 && m.tka_enabled);
    t_true("tka disabled", apply(&m, "{\"TKAInfo\":{\"Disabled\":true}}") == 0 && !m.tka_enabled);

    ts_netmap_reset(&m);
    t_true("reset clears", !m.have_self && m.npeers == 0 && !m.tka_enabled);
    t_unchanged("first map after reset needs Node", &m, "{\"PeersRemoved\":[1]}");
    ts_netmap_free(&m);
}

static char *many_peers(const char *field, int count, int first_id)
{
    size_t cap = (size_t)count * 160 + 64, n;
    char *s = (char *)malloc(cap);
    int i;
    n = (size_t)snprintf(s, cap, "{\"%s\":[", field);
    for (i = 0; i < count; i++)
        n += (size_t)snprintf(s + n, cap - n, "%s{\"ID\":%d,\"Name\":\"n%d.example.test.\","
                              "\"Addresses\":[\"100.64.%d.%d/32\"]}",
                              i ? "," : "", first_id + i, i, (i >> 8) & 255, i & 255);
    snprintf(s + n, cap - n, "]}");
    return s;
}

static void test_limits(void)
{
    ts_netmap m;
    char *s;
    char name[400];

    ts_netmap_init(&m);
    apply(&m, FULL_MAP);
    s = many_peers("Peers", TS_MAX_PEERS + 1, 100);
    t_unchanged("257 peers", &m, s);
    t_true("limit named", strstr(m.last_error, "256") != NULL);
    free(s);
    s = many_peers("Peers", TS_MAX_PEERS, 100);
    t_true("256 peers fit", apply(&m, s) == 0 && m.npeers == TS_MAX_PEERS);
    free(s);
    s = many_peers("PeersChanged", 1, 5000);
    t_unchanged("257th peer by PeersChanged", &m, s);
    free(s);

    /* Names: 255 bytes kept, 256 rejected. */
    ts_netmap_reset(&m);
    apply(&m, FULL_MAP);
    {
        char msg[600];
        memset(name, 'n', 255);
        name[255] = 0;
        snprintf(msg, sizeof msg, "{\"PeersChanged\":[{\"ID\":50,\"Name\":\"%s\"}]}", name);
        t_true("255-byte name kept", apply(&m, msg) == 0 && ts_netmap_peer(&m, 50)
               && strlen(ts_netmap_peer(&m, 50)->name) == 255);
        name[255] = 'n';
        name[256] = 0;
        snprintf(msg, sizeof msg, "{\"PeersChanged\":[{\"ID\":51,\"Name\":\"%s\"}]}", name);
        t_unchanged("256-byte name", &m, msg);
        t_true("name error names field", strstr(m.last_error, "Name") != NULL);
    }

    t_unchanged("short key", &m, "{\"PeersChanged\":[{\"ID\":52,\"Key\":\"nodekey:abcd\"}]}");
    t_unchanged("key wrong prefix", &m, "{\"PeersChanged\":[{\"ID\":52,\"Key\":\"discokey:" HA "\"}]}");
    t_unchanged("key bad hex", &m, "{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" "zz" HA "\"}}");
    t_unchanged("empty key", &m, "{\"PeersChanged\":[{\"ID\":52,\"Key\":\"\"}]}");
    t_unchanged("bad address", &m, "{\"PeersChanged\":[{\"ID\":52,\"Addresses\":[\"100.64.0.300/32\"]}]}");
    t_unchanged("bad prefix", &m, "{\"PeersChanged\":[{\"ID\":52,\"Addresses\":[\"100.64.0.3/33\"]}]}");
    t_unchanged("bad time", &m, "{\"PeersChanged\":[{\"ID\":52,\"KeyExpiry\":\"2026-13-01T00:00:00Z\"}]}");
    t_unchanged("wrong type", &m, "{\"PeersChanged\":[{\"ID\":\"52\"}]}");
    t_unchanged("wrong type Online", &m, "{\"OnlineChange\":{\"10\":1}}");
    t_unchanged("bad OnlineChange key", &m, "{\"OnlineChange\":{\"ten\":true}}");
    t_unchanged("HomeDERP overflow", &m, "{\"PeersChanged\":[{\"ID\":52,\"HomeDERP\":9999999999}]}");
    t_unchanged("invalid JSON", &m, "{\"PeersRemoved\":[10],");
    t_unchanged("trailing data", &m, "{\"PeersRemoved\":[10]} x");
    t_unchanged("not an object", &m, "[1]");
    t_unchanged("empty message", &m, "");
    /* A good delta before the bad part must not survive. */
    t_unchanged("partial apply", &m, "{\"PeersRemoved\":[10],\"PeersChanged\":[{\"ID\":53,\"Key\":\"x\"}]}");
    ts_netmap_free(&m);
}

static void test_unknown_and_null(void)
{
    ts_netmap m;
    const ts_node *p;
    ts_netmap_init(&m);
    t_true("unknown fields skipped", apply(&m,
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[{\"Name\":\"1a\"}]}}},\"Future\":[1,{\"a\":null},[[]]],"
        "\"Num\":-1.5e3,\"Nul\":null,\"T\":true,\"Str\":\"s\\u00e9\",\"PacketFilter\":[],\"Domain\":\"d\","
        "\"Node\":{\"ID\":1,\"Name\":\"s.example.test.\",\"CapMap\":{\"k\":[{}]},\"Hostinfo\":{},"
        "\"Addresses\":null,\"Online\":null,\"KeyExpiry\":null,\"Extra\":[true,false]},"
        "\"Peers\":[{\"ID\":2,\"AllowedIPs\":[\"0.0.0.0/0\"],\"Endpoints\":[\"192.0.2.1:1\"],"
        "\"Addresses\":[\"100.64.0.2/24\",\"100.64.0.3/32\"],\"Key\":null}],"
        "\"UserProfiles\":[{\"ID\":1}],\"ControlTime\":\"2026-01-01T00:00:00Z\",\"Seq\":5}") == 0);
    t_true("self from map with unknowns", m.have_self && m.self.id == 1 && !m.self.have_ipv4);
    p = ts_netmap_peer(&m, 2);
    t_true("first /32 IPv4 chosen", p && p->have_ipv4 && p->ipv4 == 0x64400003u);
    t_true("fractional offset time", apply(&m,
        "{\"Node\":{\"ID\":1,\"KeyExpiry\":\"2026-12-01T02:30:00.123456789+01:00\"}}") == 0
        && m.self.key_expiry == (int64_t)1796088600);
    t_true("pre-1970 expiry is not 0", apply(&m,
        "{\"Node\":{\"ID\":1,\"KeyExpiry\":\"1969-12-31T23:59:59Z\"}}") == 0 && m.self.key_expiry == -1);
    t_true("duplicate key: last wins", apply(&m,
        "{\"Node\":{\"ID\":1,\"HomeDERP\":1,\"HomeDERP\":4}}") == 0 && m.self.home_derp == 4);
    ts_netmap_free(&m);
}

/* Stream framing. */
typedef struct {
    char buf[4096];
    size_t len;
    int count;
    size_t lens[16];
} collect;

static void on_msg(void *user, const char *data, size_t len)
{
    collect *c = (collect *)user;
    if (c->count < 16) c->lens[c->count] = len;
    c->count++;
    if (c->len + len <= sizeof c->buf) {
        if (len) memcpy(c->buf + c->len, data, len);
        c->len += len;
    }
}

static int big_seen;

static void on_big(void *user, const char *data, size_t len)
{
    size_t k;
    int ok = 1;
    (void)user;
    if (big_seen == 0) {
        ok = len == 100000;
        for (k = 0; ok && k < len; k++) ok = data[k] == (char)('a' + k % 26);
    } else {
        ok = len == 2 && memcmp(data, "{}", 2) == 0;
    }
    if (ok) big_seen++;
}

static size_t frame(uint8_t *out, const char *s, size_t n)
{
    out[0] = (uint8_t)n; out[1] = (uint8_t)(n >> 8); out[2] = (uint8_t)(n >> 16); out[3] = (uint8_t)(n >> 24);
    memcpy(out + 4, s, n);
    return n + 4;
}

static void test_stream(void)
{
    static const char *msgs[] = { FULL_MAP, "{\"KeepAlive\":true}", "", "{\"PeersRemoved\":[10]}" };
    uint8_t wire[4096];
    size_t n = 0, i;
    collect whole, split;
    ts_map_stream s;
    ts_netmap m1, m2;
    uint8_t big[4] = { 0x01, 0x00, 0x40, 0x00 };   /* 4 MiB + 1 */

    for (i = 0; i < 4; i++) n += frame(wire + n, msgs[i], strlen(msgs[i]));

    memset(&whole, 0, sizeof whole);
    ts_map_stream_init(&s, on_msg, &whole);
    t_true("stream whole", ts_map_stream_feed(&s, wire, n) == 0);
    ts_map_stream_free(&s);

    memset(&split, 0, sizeof split);
    ts_map_stream_init(&s, on_msg, &split);
    for (i = 0; i < n; i++)
        if (ts_map_stream_feed(&s, wire + i, 1) != 0) break;
    t_true("stream split ok", i == n);
    ts_map_stream_free(&s);

    t_true("four messages", whole.count == 4 && split.count == 4);
    t_true("same lengths", memcmp(whole.lens, split.lens, sizeof whole.lens) == 0);
    t_true("same bytes", whole.len == split.len && memcmp(whole.buf, split.buf, whole.len) == 0);
    t_true("empty message delivered", whole.lens[2] == 0);
    t_true("first message intact", whole.lens[0] == strlen(FULL_MAP)
           && memcmp(whole.buf, FULL_MAP, whole.lens[0]) == 0);

    /* Feeding both message sequences into maps gives the same map. */
    ts_netmap_init(&m1);
    ts_netmap_init(&m2);
    apply(&m1, FULL_MAP);
    apply(&m1, "{\"PeersRemoved\":[10]}");
    {
        size_t off = 0;
        int k;
        for (k = 0; k < split.count; k++) {
            ts_netmap_apply(&m2, split.buf + off, split.lens[k]);
            off += split.lens[k];
        }
    }
    t_true("same map from split stream", m1.npeers == m2.npeers && m2.npeers == 1
           && memcmp(m1.peers, m2.peers, m1.npeers * sizeof(ts_node)) == 0
           && memcmp(&m1.self, &m2.self, sizeof m1.self) == 0);
    ts_netmap_free(&m1);
    ts_netmap_free(&m2);

    memset(&whole, 0, sizeof whole);
    ts_map_stream_init(&s, on_msg, &whole);
    t_true("oversize length rejected", ts_map_stream_feed(&s, big, 4) == -1);
    t_true("oversize did not allocate", s.buf == NULL && s.cap == 0 && whole.count == 0);
    t_true("oversize reason", s.failed == TS_MAP_STREAM_TOO_BIG);
    t_true("error is sticky", ts_map_stream_feed(&s, wire, n) == -1 && whole.count == 0);
    ts_map_stream_free(&s);

    /* A large message fed in chunks grows the buffer, then frees it; a small
     * message after it still arrives intact. */
    {
        size_t blen = 100000, off;
        uint8_t *bw = (uint8_t *)malloc(blen + 4 + 4 + 2);
        size_t k;
        int ok = 1;
        bw[0] = (uint8_t)blen; bw[1] = (uint8_t)(blen >> 8); bw[2] = (uint8_t)(blen >> 16); bw[3] = 0;
        for (k = 0; k < blen; k++) bw[4 + k] = (uint8_t)('a' + k % 26);
        frame(bw + 4 + blen, "{}", 2);
        big_seen = 0;
        ts_map_stream_init(&s, on_big, NULL);
        for (off = 0; off < blen + 10 && ok; off += 3001) {
            size_t c = blen + 10 - off < 3001 ? blen + 10 - off : 3001;
            ok = ts_map_stream_feed(&s, bw + off, c) == 0;
            if (off == 9 * 3001) t_true("buffer grows in steps", s.cap > 4096 && s.cap < blen);
        }
        t_true("large then small", ok && big_seen == 2);
        t_true("large buffer freed, small one sized to its message", s.cap == 2);
        ts_map_stream_free(&s);
        free(bw);
    }

    /* Exactly the maximum is accepted as a length; nothing is allocated before body bytes. */
    {
        uint8_t mx[4] = { 0x00, 0x00, 0x40, 0x00 };
        ts_map_stream_init(&s, on_msg, &whole);
        t_true("max length header ok", ts_map_stream_feed(&s, mx, 4) == 0 && s.cap == 0);
        t_true("grows only with data", ts_map_stream_feed(&s, wire, 100) == 0
               && s.cap >= 100 && s.cap < 65536);
        ts_map_stream_free(&s);
    }
}

void test_netmap(void)
{
    test_full_map();
    test_authorization();
    test_deltas();
    test_keepalive_and_extras();
    test_limits();
    test_unknown_and_null();
    test_stream();
}
