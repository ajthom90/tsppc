#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/control/netmap.h"
#include "../src/filter/filter.h"

/* Invented keys and names only. */
#define HA "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HB "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define HC "1111111111111111111111111111111111111111111111111111111111111111"
/* HA with two digits that are not hex: the same length, so only the hex check can reject it. */
#define HZ "0123456789abcdef0123456789abzzef0123456789abcdef0123456789abcdef"

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
    /* DERP map and filters, including the internal score table and session flags */
    size_t nregions, nscores, nfilters, fblob_len;
    uint32_t derp_gen, filter_gen;
    int have_filter, derp_fresh, filter_fresh;
    ts_derp_region regions[TS_DERP_MAX_REGIONS];
    ts_derp_score scores[TS_DERP_SCORES_MAX];
    char fblob[TS_FILTER_JSON_MAX + 4096];   /* each filter: name, NUL, length, text */
} snap;

static snap *take(const ts_netmap *m)
{
    snap *s = (snap *)calloc(1, sizeof *s);
    size_t i;
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
    s->nregions = m->nregions;
    if (m->nregions) memcpy(s->regions, m->regions, m->nregions * sizeof(ts_derp_region));
    s->nscores = m->nscores;
    if (m->nscores) memcpy(s->scores, m->scores, m->nscores * sizeof(ts_derp_score));
    s->derp_gen = m->derp_gen;
    s->filter_gen = m->filter_gen;
    s->have_filter = m->have_filter;
    s->derp_fresh = m->derp_fresh;
    s->filter_fresh = m->filter_fresh;
    s->nfilters = m->nfilters;
    for (i = 0; i < m->nfilters; i++) {
        size_t nl = strlen(m->filter_name[i]) + 1, len = m->filter_len[i];
        if (s->fblob_len + nl + sizeof len + len > sizeof s->fblob) abort();
        memcpy(s->fblob + s->fblob_len, m->filter_name[i], nl);
        s->fblob_len += nl;
        memcpy(s->fblob + s->fblob_len, &len, sizeof len);
        s->fblob_len += sizeof len;
        memcpy(s->fblob + s->fblob_len, m->filter_json[i], len);
        s->fblob_len += len;
    }
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
        ts_node want = *p;
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
           && (p = ts_netmap_peer(&m, 10)) != NULL && p->home_derp == 9);

    t_true("online change applies", apply(&m, "{\"OnlineChange\":{\"10\":true,\"12\":false,\"777\":true}}") == 0);
    t_true("online change set", (p = ts_netmap_peer(&m, 10)) != NULL && p->online == 1
           && (p = ts_netmap_peer(&m, 12)) != NULL && p->online == 0);
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
    t_true("limit flagged", m.last_limit == 1);
    free(s);
    s = many_peers("Peers", TS_MAX_PEERS, 100);
    t_true("256 peers fit", apply(&m, s) == 0 && m.npeers == TS_MAX_PEERS);
    t_true("success clears the limit flag", m.last_limit == 0);
    free(s);
    s = many_peers("PeersChanged", 1, 5000);
    t_unchanged("257th peer by PeersChanged", &m, s);
    t_true("257th peer flagged as the limit", m.last_limit == 1);
    free(s);
    t_unchanged("other rejection after the limit", &m, "{\"PeersRemoved\":[\"x\"]}");
    t_true("other rejection is not the limit", m.last_limit == 0);

    /* Names: 255 bytes kept, 256 rejected. */
    ts_netmap_reset(&m);
    apply(&m, FULL_MAP);
    {
        char msg[600];
        memset(name, 'n', 255);
        name[255] = 0;
        snprintf(msg, sizeof msg, "{\"PeersChanged\":[{\"ID\":50,\"Name\":\"%s\"}]}", name);
        const ts_node *p;
        t_true("255-byte name kept", apply(&m, msg) == 0 && (p = ts_netmap_peer(&m, 50)) != NULL
               && strlen(p->name) == 255);
        name[255] = 'n';
        name[256] = 0;
        snprintf(msg, sizeof msg, "{\"PeersChanged\":[{\"ID\":51,\"Name\":\"%s\"}]}", name);
        t_unchanged("256-byte name", &m, msg);
        t_true("name error names field", strstr(m.last_error, "Name") != NULL);
    }

    t_unchanged("short key", &m, "{\"PeersChanged\":[{\"ID\":52,\"Key\":\"nodekey:abcd\"}]}");
    /* Same length as a good key, so each reaches the check it is named for. */
    t_unchanged("key wrong prefix", &m, "{\"PeersChanged\":[{\"ID\":52,\"Key\":\"nodekex:" HA "\"}]}");
    t_unchanged("key bad hex", &m, "{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" HZ "\"}}");
    t_unchanged("disco key wrong prefix", &m, "{\"PeersChanged\":[{\"ID\":52,\"DiscoKey\":\"discokex:" HA "\"}]}");
    t_unchanged("disco key bad hex", &m, "{\"Node\":{\"ID\":1,\"DiscoKey\":\"discokey:" HZ "\"}}");
    t_unchanged("patch key wrong prefix", &m, "{\"PeersChangedPatch\":[{\"NodeID\":10,\"Key\":\"nodekex:" HA "\"}]}");
    t_unchanged("patch key bad hex", &m, "{\"PeersChangedPatch\":[{\"NodeID\":10,\"Key\":\"nodekey:" HZ "\"}]}");
    t_unchanged("patch disco key wrong prefix", &m,
                "{\"PeersChangedPatch\":[{\"NodeID\":10,\"DiscoKey\":\"discokex:" HA "\"}]}");
    t_unchanged("patch disco key bad hex", &m,
                "{\"PeersChangedPatch\":[{\"NodeID\":10,\"DiscoKey\":\"discokey:" HZ "\"}]}");
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
    t_true("expiry at the epoch is not 0", apply(&m,
        "{\"Node\":{\"ID\":1,\"KeyExpiry\":\"1970-01-01T00:00:00Z\"}}") == 0 && m.self.key_expiry == -1);
    t_true("expiry at the epoch via offset is not 0", apply(&m,
        "{\"Node\":{\"ID\":1,\"KeyExpiry\":\"1970-01-01T01:00:00+01:00\"}}") == 0 && m.self.key_expiry == -1);
    t_true("expiry one second after the epoch", apply(&m,
        "{\"Node\":{\"ID\":1,\"KeyExpiry\":\"1970-01-01T00:00:01Z\"}}") == 0 && m.self.key_expiry == 1);
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

/* ---- DERP map ------------------------------------------------------------ */

static const ts_derp_region *region(const ts_netmap *m, int id)
{
    size_t i;
    for (i = 0; i < m->nregions; i++)
        if (m->regions[i].id == id) return &m->regions[i];
    return NULL;
}

#define SELF_MSG "{\"Node\":" SELF_JSON("true") "}"

#define REGION_1 \
    "{\"RegionID\":1,\"RegionCode\":\"r1\",\"RegionName\":\"One\",\"NoMeasureNoHome\":true," \
    "\"Nodes\":[{\"Name\":\"1a\",\"RegionID\":1,\"HostName\":\"derp1.example.test\"," \
    "\"IPv4\":\"198.51.100.1\",\"IPv6\":\"2001:db8::1\",\"DERPPort\":443,\"STUNPort\":-1}]}"

#define REGION_2 \
    "{\"RegionID\":2,\"RegionCode\":\"r2\",\"Avoid\":true,\"Latitude\":1.5,\"Nodes\":[" \
    "{\"Name\":\"2a\",\"HostName\":\"derp2.example.test\",\"IPv4\":\"192.0.2.2\",\"DERPPort\":0}," \
    "{\"Name\":\"2b\",\"HostName\":\"derp2b.example.test\",\"IPv4\":\"none\"}," \
    "{\"Name\":\"2c\",\"HostName\":\"derp2c.example.test\",\"IPv4\":\"192.0.2.3\",\"STUNOnly\":true}," \
    "{\"Name\":\"2d\",\"HostName\":\"derp2d.example.test\",\"IPv4\":\"192.0.2.4\"," \
    "\"CertName\":\"sha256-raw:00ff\"}," \
    "null," \
    "{\"Name\":\"2e\",\"HostName\":\"derp2e.example.test\",\"IPv4\":\"192.0.2.5\"," \
    "\"CertName\":\"cert.example.test\",\"DERPPort\":8443,\"CanPort80\":true}," \
    "{\"Name\":\"2f\",\"HostName\":\"derp2f.example.test\",\"IPv4\":\"192.0.2.6\",\"InsecureForTests\":true}," \
    "{\"Name\":\"2g\",\"HostName\":\"bad host\",\"IPv4\":\"192.0.2.7\"}," \
    "{\"Name\":\"2h\",\"HostName\":\"derp2h.example.test\"}," \
    "{\"Name\":\"2i\",\"HostName\":\"derp2i.example.test\",\"IPv4\":\"192.0.2.08\"}," \
    "{\"Name\":\"2j\",\"HostName\":\"derp2j.example.test\",\"IPv4\":\"192.0.2.9\",\"DERPPort\":70000}," \
    "{\"Name\":\"2k\",\"HostName\":\"derp2k.example.test\",\"IPv4\":\"192.0.2.10\",\"DERPPort\":-1}]}"

#define REGION_3 "{\"RegionCode\":\"r3\",\"Nodes\":[]}"

#define DERP_FULL \
    "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":0.5,\"2\":2,\"7\":3}},\"Regions\":{" \
    "\"2\":" REGION_2 ",\"1\":" REGION_1 ",\"3\":" REGION_3 ",\"4\":null},\"omitDefaultRegions\":true}}"

static char *many_regions(int count, int first_id, const char *extra)
{
    size_t cap = (size_t)count * 160 + 512, n;
    char *s = (char *)malloc(cap);
    int i;
    if (!s) abort();
    n = (size_t)snprintf(s, cap, "{\"DERPMap\":{\"Regions\":{%s", extra);
    /* Descending, so the lowest IDs arrive last and must evict higher ones. */
    for (i = count - 1; i >= 0; i--)
        n += (size_t)snprintf(s + n, cap - n, "%s\"%d\":{\"RegionCode\":\"x%d\",\"Nodes\":[{\"HostName\":"
                              "\"d.example.test\",\"IPv4\":\"192.0.2.1\"}]}",
                              (i == count - 1 && extra[0] == 0) ? "" : ",", first_id + i, i);
    snprintf(s + n, cap - n, "}}}");
    return s;
}

static void test_netmap_derpmap(void)
{
    ts_netmap m;
    const ts_derp_region *r;
    uint32_t g;
    char *big;
    size_t i;
    int sorted;

    ts_netmap_init(&m);
    t_true("derp: none at first", m.nregions == 0 && m.derp_gen == 0 && m.regions != NULL);
    t_true("derp: full map applies", apply(&m, SELF_MSG) == 0 && apply(&m, DERP_FULL) == 0);
    t_true("derp: three regions, null one deleted", m.nregions == 3);
    t_true("derp: sorted by ID", m.nregions == 3 && m.regions[0].id == 1 && m.regions[1].id == 2
           && m.regions[2].id == 3);
    t_true("derp: gen bumped", m.derp_gen != 0);
    r = region(&m, 1);
    t_true("derp: region 1", r && strcmp(r->code, "r1") == 0 && r->no_home == 1 && r->avoid == 0
           && r->score == 0.5 && r->nnodes == 1);
    if (r && r->nnodes == 1) {
        t_true("derp: node 1a", strcmp(r->nodes[0].name, "1a") == 0
               && strcmp(r->nodes[0].host, "derp1.example.test") == 0
               && r->nodes[0].ipv4 == 0xC6336401u && r->nodes[0].port == 443);
    }
    r = region(&m, 2);
    t_true("derp: region 2 flags and score", r && r->avoid == 1 && r->no_home == 0 && r->score == 2.0);
    t_true("derp: region 2 keeps only usable nodes", r && r->nnodes == 2);
    if (r && r->nnodes == 2) {
        t_true("derp: DERPPort 0 is 443", strcmp(r->nodes[0].name, "2a") == 0
               && strcmp(r->nodes[0].host, "derp2.example.test") == 0
               && r->nodes[0].ipv4 == 0xC0000202u && r->nodes[0].port == 443);
        t_true("derp: CertName is the TLS name", strcmp(r->nodes[1].name, "2e") == 0
               && strcmp(r->nodes[1].host, "cert.example.test") == 0
               && r->nodes[1].ipv4 == 0xC0000205u && r->nodes[1].port == 8443);
    }
    r = region(&m, 3);
    t_true("derp: region without usable nodes kept", r && r->nnodes == 0 && r->score == 1.0
           && strcmp(r->code, "r3") == 0);

    g = m.derp_gen;
    t_true("derp: same map again", apply(&m, DERP_FULL) == 0 && m.derp_gen == g);
    t_true("derp: absent DERPMap", apply(&m, "{\"PeersRemoved\":[]}") == 0 && m.derp_gen == g
           && m.nregions == 3);
    t_true("derp: null DERPMap", apply(&m, "{\"DERPMap\":null}") == 0 && m.derp_gen == g && m.nregions == 3);
    t_true("derp: empty DERPMap", apply(&m, "{\"DERPMap\":{}}") == 0 && m.derp_gen == g && m.nregions == 3);
    t_true("derp: null RegionScore inherits", apply(&m,
        "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":null}}}") == 0 && m.derp_gen == g
        && region(&m, 1) && region(&m, 1)->score == 0.5);
    t_true("derp: empty HomeParams inherits", apply(&m, "{\"DERPMap\":{\"HomeParams\":{}}}") == 0
        && m.derp_gen == g);

    /* A non-null Regions replaces every region; HomeParams is inherited. */
    t_true("derp: replacement", apply(&m,
        "{\"DERPMap\":{\"Regions\":{\"7\":" REGION_3 ",\"1\":" REGION_1 "}}}") == 0);
    t_true("derp: replacement gen", m.derp_gen != g);
    t_true("derp: replaced set", m.nregions == 2 && region(&m, 2) == NULL && region(&m, 1) && region(&m, 7));
    t_true("derp: inherited score", region(&m, 1) && region(&m, 1)->score == 0.5);
    t_true("derp: score for a region absent before", region(&m, 7) && region(&m, 7)->score == 3.0);
    t_true("derp: regions back, scores still held", apply(&m,
        "{\"DERPMap\":{\"Regions\":{\"2\":" REGION_2 "}}}") == 0 && m.nregions == 1
        && region(&m, 2) && region(&m, 2)->score == 2.0);
    g = m.derp_gen;
    t_true("derp: new RegionScore replaces the table", apply(&m,
        "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"2\":0,\"5\":-1}}}}") == 0
        && region(&m, 2) && region(&m, 2)->score == 1.0 && m.derp_gen != g);
    t_true("derp: score null is 1.0", apply(&m,
        "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"2\":null}}}}") == 0
        && region(&m, 2) && region(&m, 2)->score == 1.0);
    g = m.derp_gen;
    t_true("derp: duplicate region key, last wins", apply(&m,
        "{\"DERPMap\":{\"Regions\":{\"2\":" REGION_2 ",\"9\":" REGION_1 ",\"2\":null,"
        "\"9\":" REGION_3 "}}}") == 0 && m.nregions == 1 && region(&m, 9)
        && strcmp(region(&m, 9)->code, "r3") == 0 && region(&m, 9)->nnodes == 0 && m.derp_gen != g);
    t_true("derp: overlong RegionCode and Name stored empty", apply(&m,
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionCode\":\"0123456789012345678901234567890123\","
        "\"Nodes\":[{\"Name\":\"" HA "\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"}]}}}}") == 0
        && region(&m, 1) && region(&m, 1)->code[0] == 0 && region(&m, 1)->nnodes == 1
        && region(&m, 1)->nodes[0].name[0] == 0);
    t_true("derp: more than 8 nodes, first 8 kept", apply(&m,
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":["
        "{\"Name\":\"n1\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n2\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n3\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n4\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n5\",\"HostName\":\"d.example.test\",\"IPv4\":\"none\"},"
        "{\"Name\":\"n6\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n7\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n8\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n9\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"},"
        "{\"Name\":\"n10\",\"HostName\":\"d.example.test\",\"IPv4\":\"192.0.2.1\"}]}}}}") == 0
        && region(&m, 1) && region(&m, 1)->nnodes == 8
        && strcmp(region(&m, 1)->nodes[7].name, "n9") == 0);
    t_true("derp: empty Regions clears", apply(&m, "{\"DERPMap\":{\"Regions\":{}}}") == 0 && m.nregions == 0);

    /* More than TS_DERP_MAX_REGIONS: the lowest IDs are kept. IDs above
     * INT_MAX are valid but never stored. */
    big = many_regions(70, 100, "\"3000000000\":" REGION_3 ",\"9007199254740991\":" REGION_3);
    t_true("derp: 72 regions apply", apply(&m, big) == 0);
    free(big);
    t_true("derp: lowest 64 kept", m.nregions == TS_DERP_MAX_REGIONS && m.regions[0].id == 100
           && m.regions[TS_DERP_MAX_REGIONS - 1].id == 163);
    sorted = 1;
    for (i = 1; i < m.nregions; i++)
        if (m.regions[i - 1].id >= m.regions[i].id) sorted = 0;
    t_true("derp: still sorted", sorted);

    /* Rejections: the map, regions and filters stay byte-identical. */
    t_true("derp: back to the full map", apply(&m, DERP_FULL) == 0 && m.nregions == 3);
    t_unchanged("derp: region ID 0", &m, "{\"DERPMap\":{\"Regions\":{\"0\":" REGION_3 "}}}");
    t_unchanged("derp: region ID 2^53", &m, "{\"DERPMap\":{\"Regions\":{\"9007199254740992\":" REGION_3 "}}}");
    t_unchanged("derp: region ID negative", &m, "{\"DERPMap\":{\"Regions\":{\"-1\":" REGION_3 "}}}");
    t_unchanged("derp: region ID not a number", &m, "{\"DERPMap\":{\"Regions\":{\"x\":" REGION_3 "}}}");
    t_unchanged("derp: score key not a number", &m,
        "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"x\":1}}}}");
    t_unchanged("derp: score key 0", &m, "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"0\":1}}}}");
    t_unchanged("derp: score not a number", &m, "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":\"x\"}}}}");
    t_unchanged("derp: DERPMap not an object", &m, "{\"DERPMap\":[]}");
    t_unchanged("derp: Regions not an object", &m, "{\"DERPMap\":{\"Regions\":[]}}");
    t_unchanged("derp: HomeParams not an object", &m, "{\"DERPMap\":{\"HomeParams\":1}}");
    t_unchanged("derp: region not an object", &m, "{\"DERPMap\":{\"Regions\":{\"1\":true}}}");
    t_unchanged("derp: Nodes not an array", &m, "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":{}}}}}");
    t_unchanged("derp: node not an object", &m, "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[1]}}}}");
    t_unchanged("derp: Avoid not a bool", &m, "{\"DERPMap\":{\"Regions\":{\"1\":{\"Avoid\":1}}}}");
    t_unchanged("derp: RegionCode not a string", &m, "{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionCode\":1}}}}");
    t_unchanged("derp: IPv4 not a string", &m,
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[{\"HostName\":\"d.example.test\",\"IPv4\":1}]}}}}");
    t_unchanged("derp: DERPPort not an int", &m,
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[{\"DERPPort\":\"443\"}]}}}}");
    t_unchanged("derp: STUNOnly not a bool", &m,
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[{\"STUNOnly\":\"no\"}]}}}}");
    t_unchanged("derp: valid map, bad peer", &m,
        "{\"DERPMap\":{\"Regions\":{\"5\":" REGION_1 "}},\"PacketFilters\":{\"q\":[]},"
        "\"Peers\":[{\"ID\":\"bad\"}]}");

    /* KeepAlive: checked, not applied. */
    g = m.derp_gen;
    t_true("derp: keepalive ignores DERPMap", apply(&m,
        "{\"KeepAlive\":true,\"DERPMap\":{\"Regions\":{}}}") == 0 && m.nregions == 3 && m.derp_gen == g);
    t_unchanged("derp: keepalive still type-checks", &m, "{\"KeepAlive\":true,\"DERPMap\":{\"Regions\":1}}");

    /* Reset keeps the regions, and a reconnect map without DERPMap keeps them. */
    ts_netmap_reset(&m);
    t_true("derp: reset keeps regions", m.nregions == 3 && m.derp_gen == g && region(&m, 1)
           && region(&m, 1)->score == 0.5);
    t_true("derp: reconnect map without DERPMap keeps them", apply(&m, SELF_MSG) == 0
           && m.nregions == 3 && m.derp_gen == g);
    /* The first DERPMap of a session starts from nothing: no inherited scores. */
    t_true("derp: first DERPMap after reset", apply(&m,
        "{\"DERPMap\":{\"Regions\":{\"1\":" REGION_1 "}}}") == 0 && m.nregions == 1
        && region(&m, 1) && region(&m, 1)->score == 1.0 && m.derp_gen != g);
    t_true("derp: second DERPMap inherits again", apply(&m,
        "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":4}}}}") == 0 && m.nregions == 1
        && region(&m, 1)->score == 4.0);
    ts_netmap_reset(&m);
    t_true("derp: first DERPMap without Regions empties", apply(&m,
        "{\"Node\":" SELF_JSON("true") ",\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":4}}}}") == 0
        && m.nregions == 0);
    ts_netmap_free(&m);
}

/* ---- packet filters -------------------------------------------------------- */

#define RULE_SSH "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":22,\"Last\":22}}]}]"
#define RULE_WEB "[{\"SrcIPs\":[\"100.64.0.0/10\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":80,\"Last\":80}}]}]"

static int filters_are(const ts_netmap *m, const char *const *names, const char *const *texts, size_t n)
{
    size_t i;
    if (m->nfilters != n) return 0;
    for (i = 0; i < n; i++) {
        if (strcmp(m->filter_name[i], names[i]) != 0) return 0;
        if (m->filter_len[i] != strlen(texts[i]) || memcmp(m->filter_json[i], texts[i], m->filter_len[i]))
            return 0;
    }
    return 1;
}

static int compiles(const ts_netmap *m)
{
    ts_filter *f = NULL;
    char err[128];
    int rc = ts_filter_compile(&f, (const char *const *)m->filter_json, m->filter_len, m->nfilters,
                               0x64400001u, err, sizeof err);
    ts_filter_free(f);
    return rc == 0;
}

static char *names_msg(int count, const char *extra)
{
    size_t cap = (size_t)count * 32 + 256, n;
    char *s = (char *)malloc(cap);
    int i;
    if (!s) abort();
    n = (size_t)snprintf(s, cap, "{\"PacketFilters\":{%s", extra);
    for (i = 0; i < count; i++)
        n += (size_t)snprintf(s + n, cap - n, "%s\"n%02d\":[]", (i == 0 && extra[0] == 0) ? "" : ",", i);
    snprintf(s + n, cap - n, "}}");
    return s;
}

static void test_netmap_filters(void)
{
    ts_netmap m;
    uint32_t g;
    char *s;
    size_t n, cap;
    static const char *const n3[] = { "aa", "base", "zz" };
    static const char *const t3[] = { "[ ]", RULE_SSH, RULE_WEB };
    static const char *const n2[] = { "aa", "base" };
    static const char *const t2[] = { "[ ]", RULE_SSH };

    ts_netmap_init(&m);
    t_true("filter: none at first", apply(&m, SELF_MSG) == 0 && !m.have_filter && m.nfilters == 0
           && m.filter_gen == 0);
    t_true("filter: PacketFilter and PacketFilters in one message", apply(&m,
        "{\"PacketFilters\":{\"zz\":" RULE_WEB ",\"aa\":[ ]},\"PacketFilter\":" RULE_SSH "}") == 0);
    t_true("filter: sorted, base included, exact text", filters_are(&m, n3, t3, 3));
    t_true("filter: have_filter and gen", m.have_filter == 1 && m.filter_gen != 0);
    t_true("filter: texts NUL-terminated", m.nfilters == 3 && m.filter_json[1][m.filter_len[1]] == 0);
    t_true("filter: stored texts compile", compiles(&m));
    g = m.filter_gen;
    t_true("filter: same again, gen unchanged", apply(&m,
        "{\"PacketFilter\":" RULE_SSH ",\"PacketFilters\":{\"aa\":[ ],\"zz\":" RULE_WEB "}}") == 0
        && filters_are(&m, n3, t3, 3) && m.filter_gen == g);
    t_true("filter: absent means unchanged", apply(&m, "{\"PeersRemoved\":[]}") == 0
           && filters_are(&m, n3, t3, 3) && m.filter_gen == g);
    t_true("filter: null means unchanged", apply(&m, "{\"PacketFilter\":null,\"PacketFilters\":null}") == 0
           && filters_are(&m, n3, t3, 3) && m.filter_gen == g);
    t_true("filter: delete by null", apply(&m, "{\"PacketFilters\":{\"zz\":null,\"nope\":null}}") == 0
           && filters_are(&m, n2, t2, 2) && m.filter_gen != g);
    g = m.filter_gen;
    {
        static const char *const nn[] = { "new" };
        static const char *const tn[] = { "[]" };
        t_true("filter: \"*\":null clears first, wherever it is", apply(&m,
            "{\"PacketFilters\":{\"new\":[],\"*\":null}}") == 0 && filters_are(&m, nn, tn, 1)
            && m.filter_gen != g);
    }
    {
        static const char *const nx[] = { "x" };
        static const char *const tx[] = { "[]" };
        t_true("filter: \"*\":null also clears this message's base", apply(&m,
            "{\"PacketFilter\":" RULE_SSH ",\"PacketFilters\":{\"*\":null,\"x\":[]}}") == 0
            && filters_are(&m, nx, tx, 1));
        g = m.filter_gen;
        t_true("filter: non-null \"*\" ignored", apply(&m, "{\"PacketFilters\":{\"*\":[]}}") == 0
               && filters_are(&m, nx, tx, 1) && m.filter_gen == g);
        t_true("filter: duplicate name, last wins", apply(&m,
            "{\"PacketFilters\":{\"y\":[],\"y\":null,\"x\":null,\"x\":[]}}") == 0 && filters_are(&m, nx, tx, 1)
            && m.filter_gen == g);
    }
    {
        static const char *const nb[] = { "base" };
        static const char *const tb[] = { "[]" };
        t_true("filter: \"*\":null after PacketFilter clears it too", apply(&m,
            "{\"PacketFilters\":{\"*\":null},\"PacketFilter\":[]}") == 0 && m.nfilters == 0);
        t_true("filter: [] is a real, empty filter", apply(&m, "{\"PacketFilter\":[]}") == 0
            && filters_are(&m, nb, tb, 1) && m.have_filter && compiles(&m));
    }

    /* Rejections leave everything byte-identical. */
    t_unchanged("filter: PacketFilter not an array", &m, "{\"PacketFilter\":{}}");
    t_unchanged("filter: PacketFilter a string", &m, "{\"PacketFilter\":\"[]\"}");
    t_unchanged("filter: PacketFilters not an object", &m, "{\"PacketFilters\":[]}");
    t_unchanged("filter: named value not an array", &m, "{\"PacketFilters\":{\"a\":{}}}");
    t_unchanged("filter: \"*\" not an array", &m, "{\"PacketFilters\":{\"*\":1}}");
    t_true("filter: plain rejection is not a limit", apply(&m, "{\"PacketFilters\":{\"a\":1}}") == -1
           && !m.last_limit);
    s = names_msg(TS_FILTER_NAMES_MAX + 1, "\"*\":null");
    t_unchanged("filter: 17 names", &m, s);
    t_true("filter: 17 names is a limit", apply(&m, s) == -1 && m.last_limit == 1);
    free(s);
    t_unchanged("filter: name of 64 bytes", &m,
        "{\"PacketFilters\":{\"" HA "\":[]}}");
    t_true("filter: long name is a limit", apply(&m, "{\"PacketFilters\":{\"" HA "\":[]}}") == -1
           && m.last_limit == 1);
    t_true("filter: name of 63 bytes", apply(&m,
        "{\"PacketFilters\":{\"" "123456789012345678901234567890123456789012345678901234567890123" "\":[]}}") == 0
        && m.nfilters == 2);
    s = names_msg(TS_FILTER_NAMES_MAX, "\"*\":null");
    t_true("filter: 16 names", apply(&m, s) == 0 && m.nfilters == TS_FILTER_NAMES_MAX);
    free(s);
    t_true("filter: at 16, set one and delete one", apply(&m,
        "{\"PacketFilters\":{\"new\":[],\"n01\":null}}") == 0 && m.nfilters == TS_FILTER_NAMES_MAX);
    t_true("filter: at 16, delete after set still passes", apply(&m,
        "{\"PacketFilters\":{\"new2\":[],\"n02\":null}}") == 0 && m.nfilters == TS_FILTER_NAMES_MAX);
    t_unchanged("filter: at 16, one more", &m, "{\"PacketFilters\":{\"extra\":[]}}");

    /* All texts together over TS_FILTER_JSON_MAX. */
    t_true("filter: back to one", apply(&m, "{\"PacketFilters\":{\"*\":null,\"a\":[]}}") == 0);
    cap = TS_FILTER_JSON_MAX + 256;
    s = (char *)malloc(cap);
    if (!s) abort();
    n = (size_t)snprintf(s, cap, "{\"PacketFilters\":{\"b\":[");
    while (n < TS_FILTER_JSON_MAX + 64) s[n++] = ' ';
    n += (size_t)snprintf(s + n, cap - n, "]}}");
    t_unchanged("filter: total over TS_FILTER_JSON_MAX", &m, s);
    t_true("filter: size is a limit", apply(&m, s) == -1 && m.last_limit == 1);
    /* Exactly at the limit, together with "a" ([] is 2 bytes). */
    n = (size_t)snprintf(s, cap, "{\"PacketFilters\":{\"b\":[");
    while (n < sizeof "{\"PacketFilters\":{\"b\":[" - 1 + TS_FILTER_JSON_MAX - 4) s[n++] = ' ';
    n += (size_t)snprintf(s + n, cap - n, "]}}");
    t_true("filter: total at TS_FILTER_JSON_MAX", apply(&m, s) == 0 && m.nfilters == 2
           && m.filter_len[0] + m.filter_len[1] == TS_FILTER_JSON_MAX);
    free(s);

    /* A message rejected after the filters were staged changes nothing. */
    t_unchanged("filter: good filters, bad peer", &m,
        "{\"PacketFilters\":{\"*\":null,\"q\":[]},\"Peers\":[{\"ID\":\"bad\"}]}");
    g = m.filter_gen;
    t_true("filter: keepalive ignores filters", apply(&m,
        "{\"KeepAlive\":true,\"PacketFilters\":{\"*\":null}}") == 0 && m.nfilters == 2 && m.filter_gen == g);

    /* Reset keeps the filters; a reconnect map without filter fields keeps them. */
    t_true("filter: set a and stale", apply(&m, "{\"PacketFilters\":{\"*\":null,\"a\":[],\"stale\":[]}}") == 0);
    g = m.filter_gen;
    ts_netmap_reset(&m);
    t_true("filter: reset keeps filters", m.nfilters == 2 && m.have_filter && m.filter_gen == g);
    t_true("filter: reconnect map without filters keeps them", apply(&m, SELF_MSG) == 0
           && m.nfilters == 2 && m.filter_gen == g);
    {
        static const char *const na[] = { "a" };
        static const char *const ta[] = { "[]" };
        t_true("filter: no stale named filter after a reconnect", apply(&m,
            "{\"PacketFilters\":{\"a\":[]}}") == 0 && filters_are(&m, na, ta, 1) && m.filter_gen != g);
        g = m.filter_gen;
        t_true("filter: then deltas merge again", apply(&m, "{\"PacketFilters\":{\"b\":[]}}") == 0
               && m.nfilters == 2 && m.filter_gen != g);
    }
    ts_netmap_free(&m);

    /* have_filter alone counts as a change. */
    ts_netmap_init(&m);
    t_true("filter: delete-only message sets have_filter", apply(&m, SELF_MSG) == 0
           && apply(&m, "{\"PacketFilters\":{\"x\":null}}") == 0 && m.have_filter && m.nfilters == 0
           && m.filter_gen != 0);
    ts_netmap_free(&m);
}

void test_netmap(void)
{
    test_full_map();
    test_authorization();
    test_deltas();
    test_keepalive_and_extras();
    test_limits();
    test_unknown_and_null();
    test_netmap_derpmap();
    test_netmap_filters();
    test_stream();
}
