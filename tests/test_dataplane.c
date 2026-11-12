#include "harness.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/control/netmap.h"
#include "../src/core/bytes.h"
#include "../src/crypto/nacl.h"
#include "../src/crypto/x25519.h"
#include "../src/data/dataplane.h"
#include "../src/filter/packet.h"

/* Data planes joined by an in-test fake relay built from the DERP frame layout
 * (type byte, BE32 length): it answers the upgrade request with 101 and a
 * ServerKey, opens each ClientInfo box to learn the client's key, answers
 * with a sealed ServerInfo, and routes SendPacket(dst) as RecvPacket(src) to
 * the connection in the same region whose key is dst. Region N is the host
 * "rN.derp.test". Everything the data planes send is queued; pump() delivers
 * it from the top level, so no callback re-enters a data plane. Maps are
 * built as MapResponse JSON and applied with ts_netmap_apply. Keys are made
 * up. */

#define NODES 3
#define BUFCAP (128 * 1024)
#define LOGMAX 16

typedef struct {
    int dialed, up;
    int region;
    int http_done, have_key, preferred, npref;
    uint8_t key[32];
    unsigned long nsend;            /* SendPacket frames from this client */
    uint8_t first_dst[32], last_dst[32];
    size_t c2s_n, s2c_n;
    uint8_t c2s[BUFCAP];
    uint8_t s2c[BUFCAP];
} tconn;

typedef struct {
    int active;
    ts_dp *dp;
    ts_netmap m;
    uint8_t priv[32], pub[32], disco[32];
    uint32_t ip;
    tconn c[TS_DP_MAX_CONNS];
    int auto_up, dial_fail, rand_mode;
    uint64_t rng;
    int ndial, nclose, last_dial_region, max_active;
    int closed_region[32];
    int tun_n;
    uint8_t tun_last[2048];
    size_t tun_last_n;
    int ndeliv;
    uint8_t deliv[LOGMAX][64];
    size_t deliv_n[LOGMAX];
    int check_tun;                  /* assert tun packets are from a peer to us */
    int bad_tun;
} tnode;

static tnode N[NODES];
static int64_t g_now = 1000;
static uint8_t s_priv[32], s_pub[32];
static uint8_t g_tmp[BUFCAP];

static const uint8_t DISCO_MAGIC[6] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };
static const char RESP101[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n"
                              "Connection: Upgrade\r\nDerp-Version: 2\r\n\r\n";

#define IP_OF(i) (0x64400000u | (uint32_t)(i))   /* 100.64.0.i */

/* ---- Callbacks ----------------------------------------------------------- */

static int active_conns(const tnode *n)
{
    int s, k = 0;
    for (s = 0; s < TS_DP_MAX_CONNS; s++) k += n->c[s].dialed;
    return k;
}

static void conn_reset(tconn *c)
{
    memset(c, 0, offsetof(tconn, c2s));
}

static int cb_dial(void *user, int slot, const ts_derp_node *node)
{
    tnode *n = (tnode *)user;
    tconn *c;
    int region = 0;
    if (slot < 0 || slot >= TS_DP_MAX_CONNS) {
        n->bad_tun++;
        return -1;
    }
    c = &n->c[slot];
    sscanf(node->host, "r%d.", &region);
    n->ndial++;
    n->last_dial_region = region;
    if (c->dialed) n->bad_tun++;   /* dialed twice without close or down */
    conn_reset(c);
    c->c2s_n = c->s2c_n = 0;
    if (n->dial_fail) return -1;
    c->dialed = 1;
    c->region = region;
    if (active_conns(n) > n->max_active) n->max_active = active_conns(n);
    return 0;
}

static void cb_conn_send(void *user, int slot, const uint8_t *p, size_t len)
{
    tnode *n = (tnode *)user;
    tconn *c = &n->c[slot];
    if (!c->dialed || !c->up) {
        n->bad_tun++;   /* bytes for a stream that is not up */
        return;
    }
    if (c->c2s_n + len <= BUFCAP) {
        memcpy(c->c2s + c->c2s_n, p, len);
        c->c2s_n += len;
    }
}

static void cb_conn_close(void *user, int slot)
{
    tnode *n = (tnode *)user;
    tconn *c = &n->c[slot];
    if (n->nclose < 32) n->closed_region[n->nclose] = c->region;
    n->nclose++;
    conn_reset(c);
    c->c2s_n = c->s2c_n = 0;
}

static int is_peer_ip(const tnode *n, uint32_t ip);

static void cb_tun_write(void *user, const uint8_t *ip, size_t len)
{
    tnode *n = (tnode *)user;
    n->tun_n++;
    if (len <= sizeof n->tun_last) {
        memcpy(n->tun_last, ip, len);
        n->tun_last_n = len;
    }
    if (n->check_tun) {
        ts_pkt p;
        if (ts_pkt_parse(&p, ip, len) != 0 || p.dst != n->ip || !is_peer_ip(n, p.src) ||
            p.proto == TS_IPPROTO_TSMP)
            n->bad_tun++;
    }
}

static int cb_random(void *user, uint8_t *out, size_t len)
{
    tnode *n = (tnode *)user;
    size_t i;
    for (i = 0; i < len; i++) {
        if (n->rand_mode == 1) out[i] = 0;
        else if (n->rand_mode == 2) out[i] = 0xff;
        else {
            n->rng = n->rng * 6364136223846793005ull + 1442695040888963407ull;
            out[i] = (uint8_t)(n->rng >> 56);
        }
    }
    return 0;
}

static int64_t cb_wall(void *user, uint32_t *nsec)
{
    (void)user;
    if (nsec) *nsec = (uint32_t)(g_now % 1000) * 1000000u;
    return 1800000000 + g_now / 1000;
}

static const ts_dp_io IO = { cb_dial, cb_conn_send, cb_conn_close, cb_tun_write, cb_random, cb_wall };

static void on_deliver(void *user, const uint8_t *ip, size_t len)
{
    tnode *n = (tnode *)user;
    if (n->ndeliv < LOGMAX) {
        size_t k = len < 64 ? len : 64;
        memcpy(n->deliv[n->ndeliv], ip, k);
        n->deliv_n[n->ndeliv] = len;
    }
    n->ndeliv++;
}

/* ---- The fake relay ------------------------------------------------------ */

static void append(tconn *c, const void *p, size_t len)
{
    if (c->s2c_n + len <= BUFCAP) {
        memcpy(c->s2c + c->s2c_n, p, len);
        c->s2c_n += len;
    }
}

static void append_frame(tconn *c, int type, const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    uint8_t h[5];
    if (c->s2c_n + 5 + an + bn > BUFCAP) return;
    h[0] = (uint8_t)type;
    ts_put_be32(h + 1, (uint32_t)(an + bn));
    append(c, h, 5);
    if (an) append(c, a, an);
    if (bn) append(c, b, bn);
}

static void route(const tconn *from, const uint8_t dst[32], const uint8_t *p, size_t len)
{
    int i, s;
    for (i = 0; i < NODES; i++) {
        if (!N[i].active) continue;
        for (s = 0; s < TS_DP_MAX_CONNS; s++) {
            tconn *d = &N[i].c[s];
            if (d->dialed && d->up && d->have_key && d->region == from->region &&
                memcmp(d->key, dst, 32) == 0) {
                append_frame(d, TS_DERP_RECV_PACKET, from->key, 32, p, len);
                return;
            }
        }
    }
}

static void relay_conn(tconn *c)
{
    size_t at = 0;
    if (!c->http_done) {
        size_t i;
        uint8_t sk[40];
        for (i = 0; i + 4 <= c->c2s_n; i++)
            if (memcmp(c->c2s + i, "\r\n\r\n", 4) == 0) break;
        if (i + 4 > c->c2s_n) return;
        at = i + 4;
        c->http_done = 1;
        append(c, RESP101, sizeof RESP101 - 1);
        memcpy(sk, "DERP\xf0\x9f\x94\x91", 8);
        memcpy(sk + 8, s_pub, 32);
        append_frame(c, TS_DERP_SERVER_KEY, sk, 40, NULL, 0);
    }
    while (c->c2s_n - at >= 5) {
        uint32_t len = ts_get_be32(c->c2s + at + 1);
        const uint8_t *body = c->c2s + at + 5;
        if (c->c2s_n - at - 5 < len) break;
        switch (c->c2s[at]) {
        case TS_DERP_CLIENT_INFO:
            if (len >= 32 + 24 + 16 && len - 72 < 256) {
                uint8_t json[256], info[24 + 16 + 16];
                static const char sj[] = "{\"version\":2}";
                size_t i;
                if (ts_box_open(json, body + 32, body, s_priv, body + 56, len - 56) == 0) {
                    memcpy(c->key, body, 32);
                    c->have_key = 1;
                    for (i = 0; i < 24; i++) info[i] = (uint8_t)(0x40 + i);
                    ts_box_seal(info + 24, info, c->key, s_priv, (const uint8_t *)sj, sizeof sj - 1);
                    append_frame(c, TS_DERP_SERVER_INFO, info, 24 + 16 + sizeof sj - 1, NULL, 0);
                }
            }
            break;
        case TS_DERP_SEND_PACKET:
            if (c->have_key && len >= 32) {
                if (c->nsend == 0) memcpy(c->first_dst, body, 32);
                memcpy(c->last_dst, body, 32);
                c->nsend++;
                route(c, body, body + 32, len - 32);
            }
            break;
        case TS_DERP_NOTE_PREFERRED:
            if (len == 1) {
                c->preferred = body[0];
                c->npref++;
            }
            break;
        default:
            break;
        }
        at += 5 + len;
    }
    memmove(c->c2s, c->c2s + at, c->c2s_n - at);
    c->c2s_n -= at;
}

static void pump(void)
{
    int again = 1, rounds = 0, i, s;
    while (again && rounds++ < 10000) {
        again = 0;
        for (i = 0; i < NODES; i++) {
            tnode *n = &N[i];
            if (!n->active) continue;
            for (s = 0; s < TS_DP_MAX_CONNS; s++) {
                tconn *c = &n->c[s];
                if (c->dialed && !c->up && n->auto_up) {
                    c->up = 1;
                    ts_dp_conn_up(n->dp, s);
                    again = 1;
                }
                if (c->dialed && c->up && c->c2s_n) {
                    size_t before = c->c2s_n;
                    relay_conn(c);
                    if (c->c2s_n != before) again = 1;
                }
                if (c->dialed && c->up && c->s2c_n) {
                    size_t len = c->s2c_n;
                    memcpy(g_tmp, c->s2c, len);
                    c->s2c_n = 0;
                    ts_dp_conn_recv(n->dp, s, g_tmp, len);
                    again = 1;
                }
            }
        }
    }
}

static void tick_all(void)
{
    int i;
    for (i = 0; i < NODES; i++)
        if (N[i].active) ts_dp_tick(N[i].dp, g_now);
}

/* Move the clock in 50 ms steps, ticking and pumping. */
static void advance(int64_t ms)
{
    int64_t end = g_now + ms;
    while (g_now < end) {
        g_now += end - g_now < 50 ? end - g_now : 50;
        tick_all();
        pump();
    }
}

/* ---- Keys, maps and packets ---------------------------------------------- */

static void mk_key(uint8_t priv[32], uint8_t pub[32], int seed)
{
    int i;
    for (i = 0; i < 32; i++) priv[i] = (uint8_t)(seed * 37 + i * 11 + 5);
    ts_x25519_public(pub, priv);
}

static void hex(char *out, const uint8_t *k)
{
    static const char d[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) {
        out[2 * i] = d[k[i] >> 4];
        out[2 * i + 1] = d[k[i] & 15];
    }
    out[64] = 0;
}

enum { P_JAILED = 1, P_EXPIRED = 2, P_WGONLY = 4, P_NODISCO = 8 };

typedef struct {
    int id;
    const uint8_t *key;
    uint32_t ip;          /* 0: no address */
    int home;
    int flags;
} pspec;

static size_t addf(char *s, size_t cap, size_t n, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
    ;

#include <stdarg.h>
static size_t addf(char *s, size_t cap, size_t n, const char *fmt, ...)
{
    va_list ap;
    int k;
    if (n >= cap) return n;
    va_start(ap, fmt);
    k = vsnprintf(s + n, cap - n, fmt, ap);
    va_end(ap);
    return k < 0 ? n : n + (size_t)k;
}

/* A MapResponse for self with peers, regions 1..nregions and, if filter is
 * not NULL, "PacketFilter": filter. self NULL leaves out Node. */
static char *map_json(const tnode *self, const pspec *p, size_t np, int nregions, const char *filter)
{
    size_t cap = np * 400 + (size_t)nregions * 200 + (filter ? strlen(filter) : 0) + 1024, n = 0, i;
    char *s = (char *)malloc(cap), kh[65];
    int r;
    if (!s) abort();
    n = addf(s, cap, n, "{");
    if (self) {
        hex(kh, self->pub);
        n = addf(s, cap, n, "\"Node\":{\"ID\":%d,\"Key\":\"nodekey:%s\",\"Addresses\":[\"100.64.0.%u/32\"],"
                 "\"HomeDERP\":1},", (int)(self - N) + 1, kh, (unsigned)(self->ip & 0xff));
    }
    if (np) {
        n = addf(s, cap, n, "\"Peers\":[");
        for (i = 0; i < np; i++) {
            hex(kh, p[i].key);
            n = addf(s, cap, n, "%s{\"ID\":%d,\"Key\":\"nodekey:%s\"", i ? "," : "", p[i].id, kh);
            if (!(p[i].flags & P_NODISCO))
                n = addf(s, cap, n, ",\"DiscoKey\":\"discokey:%s\"", kh);
            if (p[i].ip)
                n = addf(s, cap, n, ",\"Addresses\":[\"%u.%u.%u.%u/32\"]", (unsigned)(p[i].ip >> 24),
                         (unsigned)(p[i].ip >> 16 & 0xff), (unsigned)(p[i].ip >> 8 & 0xff),
                         (unsigned)(p[i].ip & 0xff));
            if (p[i].home) n = addf(s, cap, n, ",\"HomeDERP\":%d", p[i].home);
            if (p[i].flags & P_JAILED) n = addf(s, cap, n, ",\"IsJailed\":true");
            if (p[i].flags & P_EXPIRED) n = addf(s, cap, n, ",\"Expired\":true");
            if (p[i].flags & P_WGONLY) n = addf(s, cap, n, ",\"IsWireGuardOnly\":true");
            n = addf(s, cap, n, ",\"Online\":true,\"MachineAuthorized\":true}");
        }
        n = addf(s, cap, n, "],");
    }
    if (nregions) {
        n = addf(s, cap, n, "\"DERPMap\":{\"Regions\":{");
        for (r = 1; r <= nregions; r++)
            n = addf(s, cap, n, "%s\"%d\":{\"RegionCode\":\"r%d\",\"Nodes\":[{\"Name\":\"%da\","
                     "\"HostName\":\"r%d.derp.test\",\"IPv4\":\"192.0.2.%d\"}]}",
                     r > 1 ? "," : "", r, r, r, r, r);
        n = addf(s, cap, n, "}},");
    }
    if (filter) n = addf(s, cap, n, "\"PacketFilter\":%s,", filter);
    n = addf(s, cap, n, "\"KeepAlive\":false}");
    if (n >= cap) abort();
    return s;
}

static int apply_json(tnode *n, char *json)
{
    int rc = ts_netmap_apply(&n->m, json, strlen(json));
    free(json);
    if (rc == 0) ts_dp_set_netmap(n->dp, &n->m);
    return rc;
}

/* The map node i sees: every other active node as a peer, home region 1. */
static int map_of(int i, int nregions, const char *filter)
{
    pspec p[NODES];
    size_t np = 0;
    int j;
    for (j = 0; j < NODES; j++) {
        if (j == i || !N[j].active) continue;
        p[np].id = j + 1;
        p[np].key = N[j].pub;
        p[np].ip = N[j].ip;
        p[np].home = 1;
        p[np].flags = 0;
        np++;
    }
    return apply_json(&N[i], map_json(&N[i], p, np, nregions, filter));
}

static int is_peer_ip(const tnode *n, uint32_t ip)
{
    int j;
    for (j = 0; j < NODES; j++)
        if (N[j].active && &N[j] != n && N[j].ip == ip) return 1;
    return 0;
}

static void ip_hdr(uint8_t *b, size_t total, int proto, uint32_t src, uint32_t dst)
{
    memset(b, 0, 20);
    b[0] = 0x45;
    ts_put_be16(b + 2, (uint16_t)total);
    b[8] = 64;
    b[9] = (uint8_t)proto;
    ts_put_be32(b + 12, src);
    ts_put_be32(b + 16, dst);
    ts_put_be16(b + 10, ts_ip_checksum(b, 20));
}

static size_t icmp_pkt(uint8_t *b, uint32_t src, uint32_t dst, int type, int seq)
{
    ip_hdr(b, 36, TS_IPPROTO_ICMP, src, dst);
    memset(b + 20, 0, 16);
    b[20] = (uint8_t)type;
    ts_put_be16(b + 24, 0x1234);
    ts_put_be16(b + 26, (uint16_t)seq);
    memcpy(b + 28, "tsppc-dp", 8);
    ts_put_be16(b + 22, ts_ip_checksum(b + 20, 16));
    return 36;
}

static size_t tcp_syn(uint8_t *b, uint32_t src, uint32_t dst, int dport)
{
    ip_hdr(b, 40, TS_IPPROTO_TCP, src, dst);
    memset(b + 20, 0, 20);
    ts_put_be16(b + 20, 40000);
    ts_put_be16(b + 22, (uint16_t)dport);
    b[32] = 0x50;
    b[33] = 0x02;   /* SYN */
    return 40;
}

static size_t tsmp_pkt(uint8_t *b, uint32_t src, uint32_t dst)
{
    ip_hdr(b, 28, TS_IPPROTO_TSMP, src, dst);
    memset(b + 20, 0, 8);
    b[20] = '!';
    return 28;
}

/* ---- Setup --------------------------------------------------------------- */

static void node_start(tnode *n)
{
    t_true("dp start", ts_dp_start(n->dp, n->priv, n->disco, n->ip) == 0);
    ts_dp_tick(n->dp, g_now);
}

static void node_init(int i)
{
    tnode *n = &N[i];
    memset(n, 0, sizeof *n);
    n->active = 1;
    mk_key(n->priv, n->pub, i + 1);
    memset(n->disco, 0xd0 + i, 32);
    n->ip = IP_OF(i + 1);
    n->auto_up = 1;
    n->rng = 0x1234567ull * (uint64_t)(i + 1);
    n->check_tun = 1;
    n->dp = ts_dp_new(&IO, n);
    if (!n->dp || ts_netmap_init(&n->m) != 0) abort();
    node_start(n);
}

static void nodes_free(void)
{
    int i;
    for (i = 0; i < NODES; i++) {
        if (!N[i].active) continue;
        ts_dp_free(N[i].dp);
        ts_netmap_free(&N[i].m);
        N[i].active = 0;
    }
}

static int slot_of(const tnode *n, int region)
{
    int s;
    for (s = 0; s < TS_DP_MAX_CONNS; s++)
        if (n->c[s].dialed && n->c[s].region == region) return s;
    return -1;
}

static tconn g_none;

/* The test side of the connection to region, or an empty one. */
static tconn *conn_of(tnode *n, int region)
{
    int s = slot_of(n, region);
    return s < 0 ? &g_none : &n->c[s];
}

static const char ALLOW_ALL_ICMP[] =
    "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}],"
    "\"IPProto\":[1]}]";

/* Nodes 0..count-1 on region 1 (home), each with the given filter. */
static void setup(int count, const char *filter)
{
    int i;
    ts_dp_test_on_deliver = on_deliver;
    for (i = 0; i < count; i++) node_init(i);
    for (i = 0; i < count; i++) {
        t_true("setup map", map_of(i, 3, filter) == 0);
        ts_dp_set_home(N[i].dp, 1);
    }
    pump();
    advance(100);
}

static int ping(int from, int to, int seq)
{
    uint8_t b[64];
    size_t len = icmp_pkt(b, N[from].ip, N[to].ip, 8, seq);
    int before = N[to].tun_n;
    ts_dp_from_tun(N[from].dp, b, len);
    pump();
    advance(100);
    return N[to].tun_n == before + 1 && N[to].tun_last_n == len && memcmp(N[to].tun_last, b, len) == 0;
}

static void inject(tnode *n, int slot, const uint8_t src[32], const uint8_t *p, size_t len)
{
    append_frame(&n->c[slot], TS_DERP_RECV_PACKET, src, 32, p, len);
    pump();
}

/* The caller's side of a dropped stream. */
static void down(tnode *n, int s)
{
    if (s < 0 || s >= TS_DP_MAX_CONNS) {
        t_true("down: slot exists", 0);
        return;
    }
    conn_reset(&n->c[s]);
    ts_dp_conn_down(n->dp, s, "test");
}

static const ts_dp_test_counts *CNT(int i)
{
    return ts_dp_test_counters(N[i].dp);
}

/* ---- Tests --------------------------------------------------------------- */

void test_dp_ping(void);
void test_dp_filter(void);
void test_dp_spoof(void);
void test_dp_disco_and_unknown(void);
void test_dp_peer_change(void);
void test_dp_conns(void);
void test_dp_pick_home(void);
void test_dp_stress(void);

void test_dp_ping(void)
{
    uint8_t b[64];
    size_t len;
    int before;
    ts_dp_status st;
    ts_wg_stats ws;
    int region = 0;

    mk_key(s_priv, s_pub, 99);
    setup(2, ALLOW_ALL_ICMP);
    t_true("ping: running", ts_dp_running(N[0].dp) && ts_dp_running(N[1].dp));
    t_true("ping: one home connection each", active_conns(&N[0]) == 1 && active_conns(&N[1]) == 1);
    t_true("ping: home preferred", conn_of(&N[0], 1)->preferred == 1);
    ts_dp_get_status(N[0].dp, &st);
    t_true("ping: status", st.home == 1 && st.home_up == 1 && strcmp(st.filter, "ok") == 0 &&
                               st.problem[0] == 0);

    t_true("ping: A to B echo request", ping(0, 1, 1));
    len = icmp_pkt(b, N[1].ip, N[0].ip, 0, 1);
    before = N[0].tun_n;
    ts_dp_from_tun(N[1].dp, b, len);
    pump();
    t_true("ping: B to A echo reply", N[0].tun_n == before + 1 && N[0].tun_last_n == len &&
                                         memcmp(N[0].tun_last, b, len) == 0);
    t_true("ping: stats", ts_dp_peer_status(N[0].dp, N[1].ip, &ws, &region) == 0 &&
                              ws.have_session && ws.rx_packets >= 1 && ws.tx_packets >= 1 && region == 1);
    t_true("ping: unknown peer status", ts_dp_peer_status(N[0].dp, IP_OF(77), &ws, &region) == -1);
    t_true("ping: no bad callbacks", N[0].bad_tun == 0 && N[1].bad_tun == 0);
    t_true("ping: one connection each", active_conns(&N[0]) == 1 && active_conns(&N[1]) == 1);

    /* Non-IPv4 and packets to no peer go nowhere. */
    {
        unsigned long s0 = conn_of(&N[0], 1)->nsend;
        uint8_t v6[48];
        memset(v6, 0, sizeof v6);
        v6[0] = 0x60;
        ts_dp_from_tun(N[0].dp, v6, sizeof v6);
        len = icmp_pkt(b, N[0].ip, IP_OF(77), 8, 2);
        ts_dp_from_tun(N[0].dp, b, len);
        pump();
        t_true("ping: non-IPv4 and unknown dst dropped", conn_of(&N[0], 1)->nsend == s0);
    }

    ts_dp_stop(N[0].dp);
    t_true("ping: stopped", !ts_dp_running(N[0].dp) && active_conns(&N[0]) == 0);
    nodes_free();

    /* B's map puts A's home in region 2, where A has no connection. B
     * answers on region 1, where it last heard A (B1's derpRoute), and
     * dials nothing. */
    setup(2, ALLOW_ALL_ICMP);
    {
        pspec p;
        p.id = 1;
        p.key = N[0].pub;
        p.ip = N[0].ip;
        p.home = 2;
        p.flags = 0;
        t_true("route: map", apply_json(&N[1], map_json(&N[1], &p, 1, 3, NULL)) == 0);
    }
    t_true("route: A to B", ping(0, 1, 1));
    t_true("route: B to A over the receive region", ping(1, 0, 2));
    t_true("route: B dialed nothing", N[1].ndial == 1 && active_conns(&N[1]) == 1);
    t_true("route: region", ts_dp_peer_status(N[1].dp, N[0].ip, &ws, &region) == 0 && region == 1);
    nodes_free();
}

void test_dp_filter(void)
{
    static const char TCP22[] =
        "[{\"SrcIPs\":[\"100.64.0.1\"],\"DstPorts\":[{\"IP\":\"100.64.0.2\",\"Ports\":{\"First\":22,\"Last\":22}}]}]";
    uint8_t b[64];
    size_t len;
    int before;
    unsigned long f0;
    ts_dp_status st;
    char *big;
    size_t cap = 1100 * 100 + 16, n = 0;
    int i;

    /* No filter yet: nothing reaches B, though WireGuard delivers. */
    setup(2, NULL);
    ts_dp_get_status(N[1].dp, &st);
    t_true("filter: none", strcmp(st.filter, "none") == 0);
    f0 = CNT(1)->filtered;
    t_true("filter: no filter, no delivery", !ping(0, 1, 1));
    t_true("filter: no filter, dropped by the filter", CNT(1)->filtered > f0 && N[1].ndeliv > 0);

    /* Then a filter arrives. */
    t_true("filter: map with filter", map_of(1, 3, TCP22) == 0);
    ts_dp_get_status(N[1].dp, &st);
    t_true("filter: ok", strcmp(st.filter, "ok") == 0 && st.problem[0] == 0);
    before = N[1].tun_n;
    len = tcp_syn(b, N[0].ip, N[1].ip, 80);
    f0 = CNT(1)->filtered;
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("filter: SYN to a denied port", N[1].tun_n == before && CNT(1)->filtered == f0 + 1);
    len = tcp_syn(b, N[0].ip, N[1].ip, 22);
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("filter: SYN to an allowed port", N[1].tun_n == before + 1 && N[1].tun_last_n == len);

    /* Invalid: drop-all. */
    t_true("filter: invalid map", map_of(1, 3, "[1]") == 0);
    ts_dp_get_status(N[1].dp, &st);
    t_true("filter: invalid", strcmp(st.filter, "invalid") == 0 && st.problem[0] != 0);
    before = N[1].tun_n;
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("filter: invalid drops all", N[1].tun_n == before);

    /* Over the limit: drop-all, the problem names it, not the content. */
    big = (char *)malloc(cap);
    if (!big) abort();
    n = addf(big, cap, n, "[");
    for (i = 0; i < 1100; i++)
        n = addf(big, cap, n, "%s{\"SrcIPs\":[\"100.64.0.1\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":"
                 "{\"First\":%d,\"Last\":%d}}]}", i ? "," : "", i + 1, i + 1);
    addf(big, cap, n, "]");
    t_true("filter: big map", map_of(1, 3, big) == 0);
    free(big);
    ts_dp_get_status(N[1].dp, &st);
    t_true("filter: too large", strcmp(st.filter, "too large") == 0 && strstr(st.problem, "too large") &&
                                    !strstr(st.problem, "100.64") && !strstr(st.problem, "SrcIPs"));
    before = N[1].tun_n;
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("filter: too large drops all", N[1].tun_n == before);

    /* Good again, then a reconnect (reset) and a map without filter fields:
     * the old filter stays. */
    t_true("filter: good again", map_of(1, 3, TCP22) == 0);
    ts_netmap_reset(&N[1].m);
    t_true("filter: map after reset", map_of(1, 3, NULL) == 0);
    ts_dp_get_status(N[1].dp, &st);
    t_true("filter: kept after reset", strcmp(st.filter, "ok") == 0);
    before = N[1].tun_n;
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("filter: kept filter allows", N[1].tun_n == before + 1);
    len = tcp_syn(b, N[0].ip, N[1].ip, 23);
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("filter: kept filter denies", N[1].tun_n == before + 1);

    /* A restart forgets the filter: nothing gets through until a map. */
    node_start(&N[1]);
    ts_dp_get_status(N[1].dp, &st);
    t_true("filter: restart forgets", strcmp(st.filter, "none") == 0);
    t_true("filter: no bad tun", N[0].bad_tun == 0 && N[1].bad_tun == 0);
    nodes_free();
}

void test_dp_spoof(void)
{
    uint8_t b[64];
    size_t len;
    int before;
    unsigned long w0;

    setup(3, ALLOW_ALL_ICMP);
    t_true("spoof: genuine first", ping(0, 1, 1));
    /* A sends with C's address as the inner source. */
    len = icmp_pkt(b, N[2].ip, N[1].ip, 8, 2);
    before = N[1].tun_n;
    w0 = CNT(1)->wg_in;
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("spoof: decrypted but not written", CNT(1)->wg_in > w0 && N[1].tun_n == before);
    t_true("spoof: genuine after", ping(0, 1, 3));
    t_true("spoof: C still fine", ping(2, 1, 4));
    t_true("spoof: no bad tun", N[1].bad_tun == 0);
    nodes_free();
}

static int is_advert(const uint8_t *p, size_t len, uint32_t src, uint32_t dst, const uint8_t disco[32])
{
    return len == 53 && p[9] == TS_IPPROTO_TSMP && ts_get_be32(p + 12) == src &&
           ts_get_be32(p + 16) == dst && p[20] == 'a' && memcmp(p + 21, disco, 32) == 0;
}

void test_dp_disco_and_unknown(void)
{
    uint8_t b[128], other_priv[32], other[32];
    size_t len;
    int s, before;
    unsigned long w0;

    setup(2, ALLOW_ALL_ICMP);
    t_true("disco: ping", ping(0, 1, 1));
    t_true("disco: B saw A's advert first", N[1].ndeliv >= 2 &&
                                               is_advert(N[1].deliv[0], N[1].deliv_n[0], N[0].ip, N[1].ip, N[0].disco));
    t_true("disco: A saw B's advert first", N[0].ndeliv >= 1 &&
                                               is_advert(N[0].deliv[0], N[0].deliv_n[0], N[1].ip, N[0].ip, N[1].disco));
    t_true("disco: advert not written", N[1].tun_n == 1 && CNT(1)->tsmp >= 1);

    s = slot_of(&N[1], 1);
    memset(b, 0x11, sizeof b);
    memcpy(b, DISCO_MAGIC, 6);
    w0 = CNT(1)->wg_in;
    inject(&N[1], s, N[0].pub, b, 38);
    t_true("disco: magic dropped before WireGuard", CNT(1)->disco == 1 && CNT(1)->wg_in == w0);
    inject(&N[1], s, N[0].pub, b, 37);
    t_true("disco: 37 bytes go to WireGuard", CNT(1)->disco == 1 && CNT(1)->wg_in == w0 + 1);

    mk_key(other_priv, other, 50);
    memset(b, 0, sizeof b);
    b[0] = 4;
    inject(&N[1], s, other, b, 64);
    t_true("disco: unknown source dropped", CNT(1)->unknown == 1 && CNT(1)->wg_in == w0 + 1);

    len = tsmp_pkt(b, N[0].ip, N[1].ip);
    before = N[1].tun_n;
    {
        unsigned long t0 = CNT(1)->tsmp;
        ts_dp_from_tun(N[0].dp, b, len);
        pump();
        t_true("disco: protocol 99 dropped", N[1].tun_n == before && CNT(1)->tsmp == t0 + 1);
    }
    t_true("disco: still delivers", ping(0, 1, 2));

    /* A new keypair: the advert comes first again. */
    advance(100);
    node_start(&N[0]);
    t_true("disco: map again", map_of(0, 3, ALLOW_ALL_ICMP) == 0);
    ts_dp_set_home(N[0].dp, 1);
    pump();
    advance(100);
    N[1].ndeliv = 0;
    t_true("disco: ping on a new keypair", ping(0, 1, 3));
    t_true("disco: advert first on the new keypair", N[1].ndeliv >= 2 &&
               is_advert(N[1].deliv[0], N[1].deliv_n[0], N[0].ip, N[1].ip, N[0].disco) &&
               N[1].deliv[1][9] == TS_IPPROTO_ICMP);

    /* With no disco key there is no advert. */
    advance(100);
    memset(N[0].disco, 0, 32);
    node_start(&N[0]);
    t_true("disco: map 3", map_of(0, 3, ALLOW_ALL_ICMP) == 0);
    ts_dp_set_home(N[0].dp, 1);
    pump();
    advance(100);
    N[1].ndeliv = 0;
    t_true("disco: ping without disco key", ping(0, 1, 4));
    t_true("disco: no advert", N[1].ndeliv >= 1 && N[1].deliv[0][9] == TS_IPPROTO_ICMP);
    t_true("disco: no bad tun", N[0].bad_tun == 0 && N[1].bad_tun == 0);
    nodes_free();
}

void test_dp_peer_change(void)
{
    uint8_t a2_priv[32], a2_pub[32];
    pspec p;
    unsigned long u0;
    int before;
    uint8_t b[64];
    size_t len;
    ts_wg_stats ws;

    setup(2, ALLOW_ALL_ICMP);
    t_true("change: ping", ping(0, 1, 1));
    t_true("change: B has keys for A", ts_dp_test_has_keys(N[1].dp, N[0].pub));

    /* A's key changes in B's map. */
    mk_key(a2_priv, a2_pub, 60);
    p.id = 1;
    p.key = a2_pub;
    p.ip = N[0].ip;
    p.home = 1;
    p.flags = 0;
    t_true("change: map", apply_json(&N[1], map_json(&N[1], &p, 1, 3, NULL)) == 0);
    t_true("change: old key wiped", !ts_dp_test_has_keys(N[1].dp, N[0].pub));
    u0 = CNT(1)->unknown;
    before = N[1].tun_n;
    len = icmp_pkt(b, N[0].ip, N[1].ip, 8, 2);
    ts_dp_from_tun(N[0].dp, b, len);
    pump();
    t_true("change: old key dropped", N[1].tun_n == before && CNT(1)->unknown > u0);

    /* A comes back under the new key. */
    advance(100);
    memcpy(N[0].priv, a2_priv, 32);
    memcpy(N[0].pub, a2_pub, 32);
    node_start(&N[0]);
    t_true("change: A's map", map_of(0, 3, ALLOW_ALL_ICMP) == 0);
    ts_dp_set_home(N[0].dp, 1);
    pump();
    advance(100);
    t_true("change: new key works", ping(0, 1, 3));
    t_true("change: B has keys for A2", ts_dp_test_has_keys(N[1].dp, a2_pub));

    /* Jailed: removed at once. */
    p.flags = P_JAILED;
    t_true("change: jailed map", apply_json(&N[1], map_json(&N[1], &p, 1, 3, NULL)) == 0);
    t_true("change: jailed wiped", !ts_dp_test_has_keys(N[1].dp, a2_pub) &&
                                       ts_dp_peer_status(N[1].dp, N[0].ip, &ws, NULL) == -1);
    t_true("change: jailed dropped", !ping(0, 1, 4));
    p.flags = 0;
    t_true("change: unjailed", apply_json(&N[1], map_json(&N[1], &p, 1, 3, NULL)) == 0);
    /* B lost its sessions; B's ping to A starts a fresh handshake. */
    t_true("change: unjailed B to A", ping(1, 0, 5));
    t_true("change: unjailed works", ping(0, 1, 5));

    /* Expired, WireGuard-only, no address: not configured. */
    p.flags = P_EXPIRED;
    t_true("change: expired", apply_json(&N[1], map_json(&N[1], &p, 1, 3, NULL)) == 0 &&
                                  !ts_dp_test_has_keys(N[1].dp, a2_pub) &&
                                  ts_dp_peer_status(N[1].dp, N[0].ip, &ws, NULL) == -1);
    p.flags = P_WGONLY;
    t_true("change: wireguard-only", apply_json(&N[1], map_json(&N[1], &p, 1, 3, NULL)) == 0 &&
                                         ts_dp_peer_status(N[1].dp, N[0].ip, &ws, NULL) == -1);
    p.flags = 0;
    t_true("change: back", apply_json(&N[1], map_json(&N[1], &p, 1, 3, NULL)) == 0 &&
                               ts_dp_peer_status(N[1].dp, N[0].ip, &ws, NULL) == 0);
    t_true("change: works again B to A", ping(1, 0, 6));
    t_true("change: works again", ping(0, 1, 6));
    t_true("change: keys", ts_dp_test_has_keys(N[1].dp, a2_pub));

    /* Removed from the map: sessions wiped. A "Peers" list cannot be empty,
     * so the peer is removed by a delta. */
    t_true("change: removed", apply_json(&N[1], strdup("{\"PeersRemoved\":[1]}")) == 0);
    t_true("change: removed wipes", !ts_dp_test_has_keys(N[1].dp, a2_pub) &&
                                        ts_dp_peer_status(N[1].dp, N[0].ip, &ws, NULL) == -1);
    t_true("change: removed drops", !ping(0, 1, 7));
    t_true("change: no bad tun", N[1].bad_tun == 0);
    nodes_free();
}

static void conns_map(tnode *n, int npeers, int region_of_all, int nregions, uint8_t (*keys)[32])
{
    pspec p[64];
    uint8_t priv[32];
    int k;
    for (k = 0; k < npeers; k++) {
        mk_key(priv, keys[k], 200 + k);
        p[k].id = 100 + k;
        p[k].key = keys[k];
        p[k].ip = 0x64400100u + (uint32_t)k;
        p[k].home = region_of_all ? region_of_all : k + 1;
        p[k].flags = 0;
    }
    t_true("conns: map", apply_json(n, map_json(n, p, (size_t)npeers, nregions, "[]")) == 0);
}

static void send_to(tnode *n, uint32_t dst)
{
    uint8_t b[64];
    size_t len = icmp_pkt(b, n->ip, dst, 8, 1);
    ts_dp_from_tun(n->dp, b, len);
}

void test_dp_conns(void)
{
    static uint8_t keys[64][32];
    tnode *a = &N[0];
    int k, s, t;
    int64_t t0;
    ts_dp_status st;

    /* Peers in 10 regions: at most 8 slots, least recently written closed. */
    setup(1, "[]");
    conns_map(a, 10, 0, 10, keys);
    for (k = 2; k <= 10; k++) {
        advance(10);
        send_to(a, 0x64400100u + (uint32_t)(k - 1));
        pump();
    }
    t_true("conns: 10 dials", a->ndial == 10);
    t_true("conns: at most 8 open", a->max_active == TS_DP_MAX_CONNS && active_conns(a) == 8);
    t_true("conns: closed the least recently written", a->nclose == 2 && a->closed_region[0] == 2 &&
                                                          a->closed_region[1] == 3);
    t_true("conns: home kept", slot_of(a, 1) >= 0);
    nodes_free();

    /* Idle close at 60 s, not 59.999 s. */
    setup(1, "[]");
    conns_map(a, 1, 2, 3, keys);
    advance(10);
    send_to(a, 0x64400100u);
    pump();
    t0 = g_now;
    s = slot_of(a, 2);
    t_true("idle: dialed region 2", s >= 0 && a->c[s].up);
    /* Drop the peer so retransmits stop writing. */
    t_true("idle: peer gone", apply_json(a, strdup("{\"PeersRemoved\":[100]}")) == 0);
    ts_dp_tick(a->dp, t0 + TS_DP_IDLE_CLOSE_MS - 1);
    t_true("idle: open at 59.999 s", a->nclose == 0 && slot_of(a, 2) == s);
    ts_dp_tick(a->dp, t0 + TS_DP_IDLE_CLOSE_MS);
    t_true("idle: closed at 60 s", a->nclose == 1 && a->closed_region[0] == 2 && slot_of(a, 2) < 0);
    t_true("idle: home kept", slot_of(a, 1) >= 0);
    g_now = t0 + TS_DP_IDLE_CLOSE_MS;
    nodes_free();

    /* A non-home connection that drops with nothing queued is not redialed. */
    setup(1, "[]");
    conns_map(a, 1, 2, 3, keys);
    send_to(a, 0x64400100u);
    pump();
    s = slot_of(a, 2);
    t_true("drop: non-home up", s >= 0);
    t_true("drop: peer gone", apply_json(a, strdup("{\"PeersRemoved\":[100]}")) == 0);
    k = a->ndial;
    down(a, s);
    advance(40000);
    t_true("drop: not redialed", a->ndial == k);
    nodes_free();

    /* Home redial: 1 s, 2 s, 4 s, then back to 1 s once ready. */
    setup(1, "[]");
    a->rand_mode = 1;   /* no jitter */
    s = slot_of(a, 1);
    t_true("redial: home up", s >= 0);
    ts_dp_get_status(a->dp, &st);
    t_true("redial: status up", st.home == 1 && st.home_up == 1);
    a->auto_up = 0;
    for (k = 0; k < 3; k++) {
        int want = TS_DP_REDIAL_MIN_MS << k;
        int d0 = a->ndial;
        s = slot_of(a, 1);
        down(a, s);
        t0 = g_now;
        if (k == 0) {
            ts_dp_get_status(a->dp, &st);
            t_true("redial: status down", st.home == 1 && st.home_up == 0);
        }
        ts_dp_tick(a->dp, t0 + want - 1);
        t_true("redial: not yet", a->ndial == d0);
        ts_dp_tick(a->dp, t0 + want);
        g_now = t0 + want;
        t_true("redial: on time", a->ndial == d0 + 1 && a->last_dial_region == 1);
    }
    a->auto_up = 1;
    pump();
    s = slot_of(a, 1);
    t_true("redial: ready again", s >= 0 && a->c[s].up);
    t = a->ndial;
    down(a, s);
    t0 = g_now;
    ts_dp_tick(a->dp, t0 + TS_DP_REDIAL_MIN_MS);
    g_now = t0 + TS_DP_REDIAL_MIN_MS;
    t_true("redial: backoff reset", a->ndial == t + 1);
    pump();

    /* With jitter: up to 25 percent earlier. */
    a->rand_mode = 2;
    a->auto_up = 0;
    for (k = 0; k < 2; k++) {
        int want = TS_DP_REDIAL_MIN_MS << k, d0 = a->ndial, at = -1;
        ts_dp_tick(a->dp, g_now);   /* the data plane's clock is the last tick */
        s = slot_of(a, 1);
        down(a, s);
        t0 = g_now;
        for (t = 0; t <= want && at < 0; t++) {
            ts_dp_tick(a->dp, t0 + t);
            if (a->ndial != d0) at = t;
        }
        g_now = t0 + want;
        t_true("jitter: within 75..100 percent", at >= want * 3 / 4 && at < want);
    }
    /* A dial that fails at once counts as a drop. */
    a->dial_fail = 1;
    s = slot_of(a, 1);
    down(a, s);
    a->rand_mode = 1;
    t = a->ndial;
    advance(4000);
    t_true("redial: failed dial retried later", a->ndial == t + 1);
    advance(8000);
    t_true("redial: failed dial retried again", a->ndial == t + 2);
    a->dial_fail = 0;
    nodes_free();

    /* Queue overflow: 40 initiations for a relay still connecting. */
    setup(1, "[]");
    a->auto_up = 0;
    conns_map(a, 40, 2, 3, keys);
    {
        unsigned long q0 = CNT(0)->queue_full;
        for (k = 0; k < 40; k++) send_to(a, 0x64400100u + (uint32_t)k);
        s = slot_of(a, 2);
        t_true("queue: dialed once", s >= 0 && a->ndial == 2);
        t_true("queue: 8 dropped", CNT(0)->queue_full == q0 + 8);
        a->auto_up = 1;
        pump();
        t_true("queue: 32 sent in order", s >= 0 && a->c[s].nsend == TS_DP_QUEUE_PER_CONN &&
                                              memcmp(a->c[s].first_dst, keys[0], 32) == 0 &&
                                              memcmp(a->c[s].last_dst, keys[31], 32) == 0);
    }
    nodes_free();

    /* Home change: NotePreferred 0 to the old home, 1 to the new. */
    setup(1, "[]");
    s = slot_of(a, 1);
    ts_dp_set_home(a->dp, 2);
    pump();
    t = slot_of(a, 2);
    t_true("home change: new home preferred", t >= 0 && a->c[t].preferred == 1);
    t_true("home change: old home told", s >= 0 && a->c[s].preferred == 0 && a->c[s].npref == 2);
    ts_dp_get_status(a->dp, &st);
    t_true("home change: status", st.home == 2 && st.home_up == 1);
    ts_dp_tick(a->dp, g_now + TS_DP_IDLE_CLOSE_MS + 1000);
    t_true("home change: old home idles out", slot_of(a, 1) < 0 && slot_of(a, 2) == t);
    g_now += TS_DP_IDLE_CLOSE_MS + 1000;
    t_true("conns: no bad callbacks", a->bad_tun == 0);
    nodes_free();
}

static void region(ts_derp_region *r, int id)
{
    memset(r, 0, sizeof *r);
    r->id = id;
    r->score = 1.0;
    r->nnodes = 1;
}

void test_dp_pick_home(void)
{
    ts_derp_region r[4];
    int lat[4], i;

    for (i = 0; i < 4; i++) region(&r[i], i + 1);
    lat[0] = 30; lat[1] = 20; lat[2] = -1; lat[3] = -1;
    t_true("pick: lowest", ts_dp_pick_home(r, 4, lat, 0, 0) == 2);
    lat[0] = 29;
    t_true("pick: 9 ms keeps current", ts_dp_pick_home(r, 4, lat, 1, 0) == 1);
    lat[0] = 30;
    t_true("pick: 10 ms switches", ts_dp_pick_home(r, 4, lat, 1, 0) == 2);
    lat[0] = 100; lat[1] = 67;
    t_true("pick: within 2/3 keeps", ts_dp_pick_home(r, 4, lat, 1, 0) == 1);
    lat[1] = 66;
    t_true("pick: past 2/3 switches", ts_dp_pick_home(r, 4, lat, 1, 0) == 2);
    lat[0] = -1;
    t_true("pick: current unmeasured switches", ts_dp_pick_home(r, 4, lat, 1, 0) == 2);
    lat[0] = 50; lat[1] = 60;
    t_true("pick: current not in map", ts_dp_pick_home(r, 4, lat, 9, 0) == 1);

    /* RegionScore scales latency. */
    lat[0] = 30; lat[1] = 20;
    r[0].score = 0.5;
    t_true("pick: score", ts_dp_pick_home(r, 4, lat, 0, 0) == 1);
    r[0].score = 1.0;
    r[1].score = 2.0;
    t_true("pick: score 2", ts_dp_pick_home(r, 4, lat, 0, 0) == 1);
    r[1].score = 1.0;

    /* Ineligible regions. */
    lat[0] = 5; lat[1] = 6; lat[2] = 7; lat[3] = 50;
    r[0].avoid = 1;
    r[1].no_home = 1;
    r[2].nnodes = 0;
    t_true("pick: avoid, no_home, no nodes skipped", ts_dp_pick_home(r, 4, lat, 0, 0) == 4);
    t_true("pick: ineligible current not kept", ts_dp_pick_home(r, 4, lat, 1, 0) == 4);

    /* No latencies: keep current, else upstream's fallback over all regions. */
    for (i = 0; i < 4; i++) lat[i] = -1;
    t_true("pick: no data keeps current", ts_dp_pick_home(r, 4, lat, 3, 7) == 3);
    t_true("pick: fallback", ts_dp_pick_home(r, 4, lat, 0, 5) == 2);
    t_true("pick: fallback includes avoid", ts_dp_pick_home(r, 4, lat, 0, 4) == 1);
    lat[0] = 5;   /* only an ineligible region measured: no data */
    t_true("pick: only ineligible measured", ts_dp_pick_home(r, 4, lat, 0, 6) == 3);
    t_true("pick: empty", ts_dp_pick_home(r, 0, lat, 0, 6) == 0);
}

/* Random events, garbage and out-of-range slots, under the sanitizers. Every
 * tun write must be a parsed packet from a peer to us. */
void test_dp_stress(void)
{
    uint64_t rng = 0x5eed;
    int step, i;
    uint8_t b[256];

    setup(2, ALLOW_ALL_ICMP);
    for (step = 0; step < 4000; step++) {
        int who, act, slot;
        size_t len;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        who = (int)(rng >> 60) & 1;
        act = (int)(rng >> 40) % 12;
        slot = (int)((rng >> 20) % (TS_DP_MAX_CONNS + 2)) - 1;
        len = (size_t)((rng >> 8) % sizeof b);
        for (i = 0; i < (int)len; i++) b[i] = (uint8_t)((rng >> (i % 56)) ^ (uint64_t)i * 31);
        switch (act) {
        case 0:
            ts_dp_conn_recv(N[who].dp, slot, b, len);
            break;
        case 1:
            if (slot >= 0 && slot < TS_DP_MAX_CONNS && N[who].c[slot].dialed && N[who].c[slot].up) {
                /* A framed RecvPacket with garbage from the peer. */
                append_frame(&N[who].c[slot], TS_DERP_RECV_PACKET, N[1 - who].pub, 32, b, len);
            }
            break;
        case 2:
            if (slot >= 0 && slot < TS_DP_MAX_CONNS && N[who].c[slot].dialed) N[who].c[slot].up = 1;
            ts_dp_conn_up(N[who].dp, slot);
            break;
        case 3:
            if (slot >= 0 && slot < TS_DP_MAX_CONNS) conn_reset(&N[who].c[slot]);
            ts_dp_conn_down(N[who].dp, slot, "stress");
            break;
        case 4:
            ts_dp_from_tun(N[who].dp, b, len);
            break;
        case 5:
            ping(who, 1 - who, step);
            break;
        case 6:
            advance((int64_t)(rng >> 32) % 3000);
            break;
        case 7:
            ts_dp_set_home(N[who].dp, (int)(rng >> 24) % 5);
            break;
        case 8:
            map_of(who, (int)(rng >> 28) % 4, (rng >> 30) & 1 ? ALLOW_ALL_ICMP : NULL);
            break;
        case 9:
            if ((rng >> 33) % 16 == 0) {
                node_start(&N[who]);
                map_of(who, 3, ALLOW_ALL_ICMP);
                ts_dp_set_home(N[who].dp, 1);
            }
            break;
        case 10:
            if ((rng >> 33) % 32 == 0) ts_dp_stop(N[who].dp);
            break;
        default: {
            ts_dp_status st;
            ts_wg_stats ws;
            int r;
            ts_dp_get_status(N[who].dp, &st);
            ts_dp_peer_status(N[who].dp, N[1 - who].ip, &ws, &r);
            break;
        }
        }
        pump();
    }
    t_true("stress: tun only from peers", N[0].bad_tun == 0 && N[1].bad_tun == 0);
    t_true("stress: at most 8 open", N[0].max_active <= TS_DP_MAX_CONNS && N[1].max_active <= TS_DP_MAX_CONNS);
    nodes_free();
    ts_dp_test_on_deliver = NULL;
}
