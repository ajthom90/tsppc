#include "dataplane.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../core/bytes.h"
#include "../daemon/ipc.h"
#include "../filter/packet.h"
#include "../wg/handshake.h"

/* The largest WireGuard message the device sends: a transport message
 * carrying a TS_WG_MAX_PACKET packet padded to 16, plus header and tag. */
#define MSG_MAX (TS_WG_TRANSPORT_HDR + ((TS_WG_MAX_PACKET + 15) & ~15) + 16)
#define DISCO_HDR_LEN 38   /* magic (6) + disco public key (32) */

static const uint8_t DISCO_MAGIC[6] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };

enum { S_FREE = 0, S_DIALING, S_UP, S_BACKOFF };
enum { F_NONE = 0, F_OK, F_BIG, F_INVALID };

typedef struct {
    uint8_t dst[32];
    size_t n;
    uint8_t b[MSG_MAX];
} qent;

typedef struct {
    ts_dp *dp;
    int idx;
    int state;           /* S_* */
    int region;          /* 0 when free */
    int dead;            /* failed inside its own feed: torn down when the feed returns */
    int ever_ready;      /* reached ready since the last dial */
    size_t node;         /* which of the region's nodes the next dial uses */
    int64_t last_write;  /* last WireGuard message queued or sent (or created) */
    int64_t redial_at;
    int backoff;         /* next redial delay before jitter, ms */
    size_t qhead, qn;
    qent q[TS_DP_QUEUE_PER_CONN];
    ts_derp *d;          /* heap, ~140 KiB, kept for the life of the data plane */
} slot;

typedef struct {
    uint8_t key[32];
    uint32_t ipv4;
    int have_ipv4, home, online, jailed, expired, wgonly;
    int configured;      /* in the WireGuard device */
    int rx_region;       /* region we last received this peer on, 0 none */
    int tx_region;       /* region last used to send to it, 0 none */
} dpeer;

struct ts_dp {
    ts_dp_io io;
    void *user;
    int running;
    uint8_t priv[32], disco[32];
    uint32_t self_ip;
    ts_wg_dev *wg;
    int64_t now;
    dpeer peers[TS_MAX_PEERS];
    size_t npeers;
    dpeer stage[TS_MAX_PEERS];
    ts_derp_region *regions;   /* TS_DERP_MAX_REGIONS */
    size_t nregions;
    int have_derp;
    uint32_t derp_gen;
    ts_filter *filter;         /* NULL: drop every inbound packet */
    int fstate;                /* F_* */
    int have_fgen;
    uint32_t filter_gen;
    ts_flows flows;
    int home;
    char home_err[120];
    int feeding;               /* slot inside ts_derp_feed, or -1 */
    slot *slots[TS_DP_MAX_CONNS];
#ifdef TS_TEST_HOOKS
    ts_dp_test_counts cnt;
#endif
};

#ifdef TS_TEST_HOOKS
void (*ts_dp_test_on_deliver)(void *user, const uint8_t *ip, size_t n);
#define COUNT(dp, f) ((dp)->cnt.f++)
#else
#define COUNT(dp, f) ((void)0)
#endif

static int key_zero(const uint8_t k[32])
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < 32; i++) acc |= k[i];
    return acc == 0;
}

/* ---- Lookups --------------------------------------------------------------- */

static dpeer *peer_by_key(ts_dp *dp, const uint8_t key[32])
{
    size_t i;
    for (i = 0; i < dp->npeers; i++)
        if (dp->peers[i].configured && memcmp(dp->peers[i].key, key, 32) == 0) return &dp->peers[i];
    return NULL;
}

static const dpeer *peer_by_ip(const ts_dp *dp, uint32_t ip)
{
    size_t i;
    for (i = 0; i < dp->npeers; i++)
        if (dp->peers[i].configured && dp->peers[i].ipv4 == ip) return &dp->peers[i];
    return NULL;
}

static const ts_derp_region *region_find(const ts_dp *dp, int id)
{
    size_t i;
    if (id <= 0) return NULL;
    for (i = 0; i < dp->nregions; i++)
        if (dp->regions[i].id == id) return &dp->regions[i];
    return NULL;
}

static int region_usable(const ts_dp *dp, int id)
{
    const ts_derp_region *r = region_find(dp, id);
    return r && r->nnodes > 0;
}

static slot *slot_for_region(ts_dp *dp, int region)
{
    int i;
    if (region <= 0) return NULL;
    for (i = 0; i < TS_DP_MAX_CONNS; i++) {
        slot *s = dp->slots[i];
        if (s->state != S_FREE && !s->dead && s->region == region) return s;
    }
    return NULL;
}

static int slot_ready(const slot *s)
{
    return s->state == S_UP && !s->dead && ts_derp_ready(s->d);
}

/* ---- Slots ----------------------------------------------------------------- */

static void queue_clear(slot *s)
{
    ts_wipe(s->q, sizeof s->q);
    s->qhead = s->qn = 0;
}

static void flush(slot *s)
{
    while (s->qn && slot_ready(s)) {
        qent *e = &s->q[s->qhead];
        ts_derp_send_packet(s->d, e->dst, e->b, e->n);
        ts_wipe(e, sizeof *e);
        s->qhead = (s->qhead + 1) % TS_DP_QUEUE_PER_CONN;
        s->qn--;
    }
}

/* Close the stream (if open) and forget the slot. */
static void slot_free(slot *s)
{
    ts_dp *dp = s->dp;
    if (s->state == S_DIALING || s->state == S_UP) dp->io.conn_close(dp->user, s->idx);
    ts_derp_free(s->d);
    queue_clear(s);
    s->state = S_FREE;
    s->region = 0;
    s->dead = 0;
    s->ever_ready = 0;
    s->node = 0;
    s->backoff = TS_DP_REDIAL_MIN_MS;
}

static int64_t redial_delay(ts_dp *dp, slot *s)
{
    uint8_t b[4];
    uint32_t r = 0, d = (uint32_t)s->backoff;
    if (dp->io.random(dp->user, b, 4) == 0) r = ts_get_be32(b);
    s->backoff = s->backoff >= TS_DP_REDIAL_MAX_MS / 2 ? TS_DP_REDIAL_MAX_MS : s->backoff * 2;
    return (int64_t)(d - r % (d / 4 + 1));
}

static void set_home_err(ts_dp *dp, const char *why)
{
    char clean[100];
    if (!why) why = "connection lost";
    ts_ipc_clean(clean, sizeof clean, why, strlen(why), 0);
    snprintf(dp->home_err, sizeof dp->home_err, "home relay: %s", clean);
}

/* The stream is gone (close_stream: we end it). The home slot, or one with
 * packets waiting, waits to redial; any other slot is freed. */
static void slot_down(slot *s, int close_stream, const char *why)
{
    ts_dp *dp = s->dp;
    if (s->region == dp->home) set_home_err(dp, why);
    if (close_stream && (s->state == S_DIALING || s->state == S_UP)) dp->io.conn_close(dp->user, s->idx);
    ts_derp_free(s->d);
    s->dead = 0;
    if (dp->running && region_usable(dp, s->region) && (s->region == dp->home || s->qn > 0)) {
        if (!s->ever_ready) s->node++;   /* try the region's next node */
        s->ever_ready = 0;
        s->state = S_BACKOFF;
        s->redial_at = dp->now + redial_delay(dp, s);
        return;
    }
    s->state = S_FREE;   /* the stream is already closed */
    slot_free(s);
}

static void derp_send(void *user, const uint8_t *p, size_t n);
static void derp_recv(void *user, const uint8_t src[32], const uint8_t *p, size_t n);
static void derp_gone(void *user, const uint8_t key[32]);
static void derp_health(void *user, const char *text);
static void derp_pong(void *user, const uint8_t data[8]);

static const ts_derp_io DERP_IO = { derp_send, derp_recv, derp_gone, derp_health, derp_pong };

static void dial(slot *s)
{
    ts_dp *dp = s->dp;
    const ts_derp_region *r = region_find(dp, s->region);
    const ts_derp_node *node;
    char host[TS_DERP_HOST_MAX + 1];

    if (!r || r->nnodes == 0) {
        s->state = S_FREE;
        slot_free(s);
        return;
    }
    node = &r->nodes[s->node % r->nnodes];
    if (node->port == 0 || node->port == 443) snprintf(host, sizeof host, "%s", node->host);
    else snprintf(host, sizeof host, "%s:%u", node->host, (unsigned)node->port);
    ts_derp_init(s->d, host, dp->priv, s->region == dp->home, &DERP_IO, s);
    s->state = S_DIALING;
    s->ever_ready = 0;
    s->dead = 0;
    if (s->d->err || dp->io.dial(dp->user, s->idx, node) != 0) {
        s->state = S_BACKOFF;   /* no stream to close */
        slot_down(s, 0, s->d->err ? s->d->err : "dial failed");
    }
}

/* A free slot, closing the least recently written non-home one if needed
 * (never the slot inside a feed). */
static slot *slot_alloc(ts_dp *dp)
{
    slot *victim = NULL;
    int i;
    for (i = 0; i < TS_DP_MAX_CONNS; i++)
        if (dp->slots[i]->state == S_FREE) return dp->slots[i];
    for (i = 0; i < TS_DP_MAX_CONNS; i++) {
        slot *s = dp->slots[i];
        if (s->region == dp->home || i == dp->feeding || s->dead) continue;
        if (!victim || s->last_write < victim->last_write) victim = s;
    }
    if (!victim) return NULL;
    slot_free(victim);
    return victim;
}

static slot *slot_open(ts_dp *dp, int region)
{
    slot *s;
    if (!region_usable(dp, region)) return NULL;
    s = slot_alloc(dp);
    if (!s) return NULL;
    s->region = region;
    s->last_write = dp->now;
    s->backoff = TS_DP_REDIAL_MIN_MS;
    s->node = 0;
    s->state = S_BACKOFF;   /* claimed; dial() moves it on */
    return s;
}

static void ensure_home(ts_dp *dp)
{
    const ts_derp_region *r;
    slot *s;
    if (!dp->running || dp->home <= 0 || slot_for_region(dp, dp->home)) return;
    r = region_find(dp, dp->home);
    if (!r || r->nnodes == 0) {
        snprintf(dp->home_err, sizeof dp->home_err, "%s",
                 r ? "home relay region has no usable relay" : "home relay region not in the map");
        return;
    }
    s = slot_open(dp, dp->home);
    if (!s) return;
    dp->home_err[0] = 0;
    dial(s);
}

/* One SendPacket on s: sent if the relay is ready (after anything queued),
 * else queued, else dropped. */
static void slot_send(slot *s, const uint8_t dst[32], const uint8_t *msg, size_t n)
{
    ts_dp *dp = s->dp;
    qent *e;
    s->last_write = dp->now;
    if (n > MSG_MAX) return;
    flush(s);
    if (s->qn == 0 && slot_ready(s)) {
        ts_derp_send_packet(s->d, dst, msg, n);
        return;
    }
    if (s->qn == TS_DP_QUEUE_PER_CONN) {
        COUNT(dp, queue_full);
        return;
    }
    e = &s->q[(s->qhead + s->qn) % TS_DP_QUEUE_PER_CONN];
    memcpy(e->dst, dst, 32);
    memcpy(e->b, msg, n);
    e->n = n;
    s->qn++;
}

/* After a feed: tear down a failed slot, or note ready and flush. */
static void after_feed(slot *s, int rc)
{
    ts_dp *dp = s->dp;
    if (rc != 0 || s->dead) {
        slot_down(s, 1, s->d->err ? s->d->err : "relay connection failed");
        return;
    }
    if (!s->ever_ready && ts_derp_ready(s->d)) {
        s->ever_ready = 1;
        s->backoff = TS_DP_REDIAL_MIN_MS;
        if (s->region == dp->home) dp->home_err[0] = 0;
    }
    flush(s);
}

/* ---- DERP callbacks (user is the slot) ------------------------------------- */

static void derp_send(void *user, const uint8_t *p, size_t n)
{
    slot *s = (slot *)user;
    if (s->state == S_UP && !s->dead) s->dp->io.conn_send(s->dp->user, s->idx, p, n);
}

static void derp_recv(void *user, const uint8_t src[32], const uint8_t *p, size_t n)
{
    slot *s = (slot *)user;
    ts_dp *dp = s->dp;
    dpeer *peer;

    if (s->dead || !dp->running || s->state != S_UP) return;
    if (n >= DISCO_HDR_LEN && memcmp(p, DISCO_MAGIC, sizeof DISCO_MAGIC) == 0) {
        COUNT(dp, disco);   /* no disco support: dropped, never WireGuard */
        return;
    }
    peer = peer_by_key(dp, src);
    if (!peer) {
        COUNT(dp, unknown);
        return;
    }
    peer->rx_region = s->region;
    COUNT(dp, wg_in);
    ts_wg_receive(dp->wg, src, p, n);
}

static void derp_gone(void *user, const uint8_t key[32])
{
    slot *s = (slot *)user;
    dpeer *peer = peer_by_key(s->dp, key);
    if (peer && peer->rx_region == s->region) peer->rx_region = 0;
}

static void derp_health(void *user, const char *text)
{
    (void)user;
    (void)text;
}

static void derp_pong(void *user, const uint8_t data[8])
{
    (void)user;
    (void)data;
}

/* ---- WireGuard callbacks (user is the data plane) -------------------------- */

static void wg_send(void *user, const uint8_t key[32], const uint8_t *msg, size_t n)
{
    ts_dp *dp = (ts_dp *)user;
    dpeer *peer = peer_by_key(dp, key);
    slot *home, *rx, *s;

    if (!peer) return;
    /* B1: the peer's home connection if it is open (ready), else the ready
     * connection we last heard the peer on, else queue on the home region's
     * connection (dialing it if there is none); the receive connection in
     * any state is the last resort (no usable home region). */
    home = slot_for_region(dp, peer->home);
    rx = slot_for_region(dp, peer->rx_region);
    if (home && slot_ready(home)) s = home;
    else if (rx && slot_ready(rx)) s = rx;
    else if (home) s = home;
    else {
        s = slot_open(dp, peer->home);
        if (s) {
            peer->tx_region = s->region;
            slot_send(s, key, msg, n);   /* queued before the dial, so a failed dial keeps it */
            dial(s);
            return;
        }
        s = rx;
    }
    if (!s) return;
    peer->tx_region = s->region;
    slot_send(s, key, msg, n);
}

static void wg_deliver(void *user, const uint8_t key[32], const uint8_t *ip, size_t n)
{
    ts_dp *dp = (ts_dp *)user;
    const dpeer *peer = peer_by_key(dp, key);
    ts_pkt pk;

#ifdef TS_TEST_HOOKS
    if (ts_dp_test_on_deliver) ts_dp_test_on_deliver(dp->user, ip, n);
#endif
    if (!peer || peer->jailed) {
        COUNT(dp, jailed);
        return;
    }
    if (ts_pkt_parse(&pk, ip, n) != 0 || pk.src != peer->ipv4) {
        COUNT(dp, spoof);
        return;
    }
    if (pk.proto == TS_IPPROTO_TSMP) {
        COUNT(dp, tsmp);   /* adverts and pings are not acted on */
        return;
    }
    if (!ts_filter_in(dp->filter, &dp->flows, &pk, NULL)) {
        COUNT(dp, filtered);
        return;
    }
    dp->io.tun_write(dp->user, ip, pk.len);
}

static size_t wg_priority(void *user, const uint8_t key[32], uint8_t *out, size_t cap)
{
    ts_dp *dp = (ts_dp *)user;
    const dpeer *peer = peer_by_key(dp, key);
    if (!peer || !peer->have_ipv4 || peer->wgonly || dp->self_ip == 0 || key_zero(dp->disco) || cap < 53)
        return 0;
    return ts_pkt_tsmp_disco(out, dp->self_ip, peer->ipv4, dp->disco);
}

static int wg_random(void *user, uint8_t *out, size_t n)
{
    ts_dp *dp = (ts_dp *)user;
    return dp->io.random(dp->user, out, n);
}

static int64_t wg_wall(void *user, uint32_t *nsec)
{
    ts_dp *dp = (ts_dp *)user;
    return dp->io.wall(dp->user, nsec);
}

static const ts_wg_io WG_IO = { wg_send, wg_deliver, wg_random, wg_wall, wg_priority };

/* ---- Public ---------------------------------------------------------------- */

ts_dp *ts_dp_new(const ts_dp_io *io, void *user)
{
    ts_dp *dp = (ts_dp *)calloc(1, sizeof *dp);
    int i;
    if (!dp) return NULL;
    dp->io = *io;
    dp->user = user;
    dp->feeding = -1;
    dp->regions = (ts_derp_region *)calloc(TS_DERP_MAX_REGIONS, sizeof *dp->regions);
    if (!dp->regions) goto fail;
    for (i = 0; i < TS_DP_MAX_CONNS; i++) {
        slot *s = (slot *)calloc(1, sizeof *s);
        if (!s) goto fail;
        dp->slots[i] = s;
        s->d = (ts_derp *)calloc(1, sizeof *s->d);
        if (!s->d) goto fail;
        s->dp = dp;
        s->idx = i;
        s->backoff = TS_DP_REDIAL_MIN_MS;
    }
    return dp;
fail:
    ts_dp_free(dp);
    return NULL;
}

void ts_dp_stop(ts_dp *dp)
{
    int i;
    for (i = 0; i < TS_DP_MAX_CONNS; i++)
        if (dp->slots[i] && dp->slots[i]->state != S_FREE) slot_free(dp->slots[i]);
    if (dp->wg) ts_wg_free(dp->wg);
    dp->wg = NULL;
    ts_filter_free(dp->filter);
    dp->filter = NULL;
    dp->fstate = F_NONE;
    dp->have_fgen = 0;
    dp->have_derp = 0;
    dp->nregions = 0;
    ts_wipe(dp->peers, sizeof dp->peers);
    ts_wipe(dp->stage, sizeof dp->stage);
    dp->npeers = 0;
    ts_wipe(&dp->flows, sizeof dp->flows);
    ts_wipe(dp->priv, sizeof dp->priv);
    ts_wipe(dp->disco, sizeof dp->disco);
    dp->self_ip = 0;
    dp->home = 0;
    dp->home_err[0] = 0;
    dp->running = 0;
}

void ts_dp_free(ts_dp *dp)
{
    int i;
    if (!dp) return;
    ts_dp_stop(dp);
    for (i = 0; i < TS_DP_MAX_CONNS; i++) {
        if (!dp->slots[i]) continue;
        if (dp->slots[i]->d) {
            ts_derp_free(dp->slots[i]->d);
            free(dp->slots[i]->d);
        }
        ts_wipe(dp->slots[i], sizeof *dp->slots[i]);
        free(dp->slots[i]);
    }
    free(dp->regions);
    ts_wipe(dp, sizeof *dp);
    free(dp);
}

int ts_dp_start(ts_dp *dp, const uint8_t node_priv[32], const uint8_t disco_pub[32], uint32_t self_ip)
{
    ts_dp_stop(dp);
    memcpy(dp->priv, node_priv, 32);
    memcpy(dp->disco, disco_pub, 32);
    dp->self_ip = self_ip;
    ts_flows_init(&dp->flows);
    dp->wg = ts_wg_new(node_priv, &WG_IO, dp);
    if (!dp->wg) {
        ts_dp_stop(dp);
        return -1;
    }
    ts_wg_tick(dp->wg, dp->now);
    dp->running = 1;
    return 0;
}

int ts_dp_running(const ts_dp *dp)
{
    return dp->running;
}

static void set_peers(ts_dp *dp, const ts_netmap *m)
{
    size_t i, j, n = m->npeers < TS_MAX_PEERS ? m->npeers : TS_MAX_PEERS;

    for (i = 0; i < n; i++) {
        const ts_node *src = &m->peers[i];
        dpeer *p = &dp->stage[i];
        memset(p, 0, sizeof *p);
        memcpy(p->key, src->node_key, 32);
        p->ipv4 = src->ipv4;
        p->have_ipv4 = src->have_ipv4 && src->ipv4 != 0;
        p->home = src->home_derp;
        p->online = src->online;
        p->jailed = src->jailed;
        p->expired = src->expired;
        p->wgonly = src->wireguard_only;
        p->configured = !p->jailed && !p->expired && !p->wgonly && p->have_ipv4 && !key_zero(p->key);
        for (j = 0; j < i && p->configured; j++)   /* one entry per key */
            if (dp->stage[j].configured && memcmp(dp->stage[j].key, p->key, 32) == 0) p->configured = 0;
    }
    /* Gone, ineligible or re-keyed: out of the device at once. */
    for (j = 0; j < dp->npeers; j++) {
        const dpeer *o = &dp->peers[j];
        int keep = 0;
        if (!o->configured) continue;
        for (i = 0; i < n && !keep; i++)
            keep = dp->stage[i].configured && memcmp(dp->stage[i].key, o->key, 32) == 0;
        if (!keep) ts_wg_remove_peer(dp->wg, o->key);
    }
    for (i = 0; i < n; i++) {
        dpeer *p = &dp->stage[i];
        if (!p->configured) continue;
        for (j = 0; j < dp->npeers; j++) {
            if (dp->peers[j].configured && memcmp(dp->peers[j].key, p->key, 32) == 0) {
                p->rx_region = dp->peers[j].rx_region;
                p->tx_region = dp->peers[j].tx_region;
                break;
            }
        }
        if (ts_wg_set_peer(dp->wg, p->key, p->ipv4) != 0) {
            p->configured = 0;
            ts_wg_remove_peer(dp->wg, p->key);   /* no stale sessions under this key */
        }
    }
    ts_wipe(dp->peers, sizeof dp->peers);
    memcpy(dp->peers, dp->stage, n * sizeof dp->peers[0]);
    ts_wipe(dp->stage, sizeof dp->stage);
    dp->npeers = n;
}

static void set_filter(ts_dp *dp, const ts_netmap *m)
{
    ts_filter *f = NULL;
    int rc;
    char err[128];

    rc = ts_filter_compile(&f, (const char *const *)m->filter_json, m->filter_len, m->nfilters,
                           dp->self_ip, err, sizeof err);
    ts_filter_free(dp->filter);
    dp->filter = rc == 0 ? f : NULL;   /* NULL drops every inbound packet */
    dp->fstate = rc == 0 ? F_OK : rc == -1 ? F_INVALID : F_BIG;
}

void ts_dp_set_netmap(ts_dp *dp, const ts_netmap *m)
{
    if (!dp->running) return;
    set_peers(dp, m);
    if (!dp->have_derp || m->derp_gen != dp->derp_gen) {
        size_t n = m->nregions < TS_DERP_MAX_REGIONS ? m->nregions : TS_DERP_MAX_REGIONS;
        if (n) memcpy(dp->regions, m->regions, n * sizeof *dp->regions);
        dp->nregions = n;
        dp->have_derp = 1;
        dp->derp_gen = m->derp_gen;
    }
    if (m->have_filter && (!dp->have_fgen || m->filter_gen != dp->filter_gen)) {
        set_filter(dp, m);
        dp->have_fgen = 1;
        dp->filter_gen = m->filter_gen;
    }
    ensure_home(dp);
}

void ts_dp_set_home(ts_dp *dp, int region)
{
    slot *s;
    if (!dp->running || region < 0 || region == dp->home) return;
    s = slot_for_region(dp, dp->home);
    if (s) ts_derp_note_preferred(s->d, 0);
    dp->home = region;
    dp->home_err[0] = 0;
    s = slot_for_region(dp, region);
    if (s) {
        ts_derp_note_preferred(s->d, 1);
        s->backoff = TS_DP_REDIAL_MIN_MS;
    }
    ensure_home(dp);
}

void ts_dp_from_tun(ts_dp *dp, const uint8_t *ip, size_t n)
{
    ts_pkt pk;
    const dpeer *peer;
    if (!dp->running || ts_pkt_parse(&pk, ip, n) != 0) return;
    peer = peer_by_ip(dp, pk.dst);
    if (!peer) return;
    ts_filter_out(&dp->flows, &pk);
    ts_wg_send_packet(dp->wg, peer->key, ip, pk.len);
}

static slot *slot_at(ts_dp *dp, int i)
{
    if (!dp->running || i < 0 || i >= TS_DP_MAX_CONNS) return NULL;
    return dp->slots[i];
}

void ts_dp_conn_up(ts_dp *dp, int i)
{
    slot *s = slot_at(dp, i);
    if (!s || s->state != S_DIALING) return;
    s->state = S_UP;
    ts_derp_start(s->d, dp->now);
}

void ts_dp_conn_recv(ts_dp *dp, int i, const uint8_t *p, size_t n)
{
    slot *s = slot_at(dp, i);
    int rc;
    if (!s || s->state != S_UP || n == 0) return;
    dp->feeding = i;
    rc = ts_derp_feed(s->d, p, n, dp->now);
    dp->feeding = -1;
    after_feed(s, rc);
}

void ts_dp_conn_down(ts_dp *dp, int i, const char *why)
{
    slot *s = slot_at(dp, i);
    if (!s || (s->state != S_DIALING && s->state != S_UP)) return;
    slot_down(s, 0, why);
}

void ts_dp_tick(ts_dp *dp, int64_t now_ms)
{
    int i;
    dp->now = now_ms;
    if (!dp->running) return;
    ts_wg_tick(dp->wg, now_ms);
    for (i = 0; i < TS_DP_MAX_CONNS; i++) {
        slot *s = dp->slots[i];
        if (s->state == S_FREE) continue;
        if (s->region != dp->home && now_ms - s->last_write >= TS_DP_IDLE_CLOSE_MS) {
            slot_free(s);
            continue;
        }
        if (s->state == S_UP) {
            if (ts_derp_tick(s->d, now_ms) != 0) slot_down(s, 1, s->d->err);
            else flush(s);
        } else if (s->state == S_BACKOFF && now_ms >= s->redial_at) {
            if (s->region == dp->home || s->qn > 0) dial(s);
            else slot_free(s);
        }
    }
    ensure_home(dp);
}

int ts_dp_pick_home(const ts_derp_region *r, size_t n, const int *lat_ms, int current,
                    uint32_t rand32)
{
    size_t i;
    int best_id = 0, have = 0, cur_ok = 0;
    double best = 0, cur = 0;

    for (i = 0; i < n; i++) {
        double d;
        if (lat_ms[i] < 0 || r[i].nnodes == 0 || r[i].avoid || r[i].no_home) continue;
        d = (double)lat_ms[i] * (r[i].score > 0 ? r[i].score : 1.0);
        if (r[i].id == current) {
            cur = d;
            cur_ok = 1;
        }
        if (!have || d < best) {
            best = d;
            best_id = r[i].id;
            have = 1;
        }
    }
    if (!have) {
        /* Keep a current home that can still be dialed; else upstream's
         * pickDERPFallback over every region with a usable node. */
        size_t k = 0;
        for (i = 0; i < n; i++)
            if (r[i].id == current && current > 0 && r[i].nnodes > 0) return current;
        for (i = 0; i < n; i++) k += r[i].nnodes > 0;
        if (k == 0) return 0;
        k = rand32 % k;
        for (i = 0; i < n; i++) {
            if (r[i].nnodes == 0) continue;
            if (k-- == 0) return r[i].id;
        }
        return 0;
    }
    /* Stickiness: keep the current home unless the best is clearly better. */
    if (cur_ok && best_id != current && (cur - best < 10.0 || best > cur * 2.0 / 3.0)) return current;
    return best_id;
}

void ts_dp_get_status(const ts_dp *dp, ts_dp_status *st)
{
    int i;
    st->home = dp->home;
    st->home_up = 0;
    for (i = 0; i < TS_DP_MAX_CONNS && dp->home > 0; i++) {
        const slot *s = dp->slots[i];
        if (s->state != S_FREE && s->region == dp->home && slot_ready(s)) st->home_up = 1;
    }
    switch (dp->fstate) {
    case F_OK: st->filter = "ok"; break;
    case F_BIG: st->filter = "too large"; break;
    case F_INVALID: st->filter = "invalid"; break;
    default: st->filter = "none"; break;
    }
    st->problem[0] = 0;
    if (dp->fstate == F_BIG)
        snprintf(st->problem, sizeof st->problem, "packet filter too large; inbound traffic blocked");
    else if (dp->fstate == F_INVALID)
        snprintf(st->problem, sizeof st->problem, "packet filter invalid; inbound traffic blocked");
    else if (dp->running && dp->home > 0 && !st->home_up && dp->home_err[0])
        snprintf(st->problem, sizeof st->problem, "%s", dp->home_err);
}

int ts_dp_peer_status(const ts_dp *dp, uint32_t ipv4, ts_wg_stats *st, int *region)
{
    const dpeer *peer;
    ts_wg_stats tmp;
    if (!dp->running) return -1;
    peer = peer_by_ip(dp, ipv4);
    if (!peer || ts_wg_peer_stats(dp->wg, peer->key, st ? st : &tmp) != 0) return -1;
    if (region) *region = peer->tx_region > 0 ? peer->tx_region : -1;
    return 0;
}

#ifdef TS_TEST_HOOKS
const ts_dp_test_counts *ts_dp_test_counters(const ts_dp *dp)
{
    return &dp->cnt;
}

int ts_dp_test_has_keys(const ts_dp *dp, const uint8_t key[32])
{
    return dp->wg ? ts_wg_test_has_keys(dp->wg, key) : 0;
}
#endif
