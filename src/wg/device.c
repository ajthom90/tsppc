#include "device.h"

#include <stdlib.h>
#include <string.h>

#include "../control/netmap.h"
#include "../core/bytes.h"
#include "../crypto/aead.h"
#include "../crypto/blake2s.h"
#include "../crypto/x25519.h"
#include "../filter/packet.h"
#include "handshake.h"

/* tailscale/wireguard-go device/constants.go, in milliseconds. */
#define REKEY_AFTER_MESSAGES (1ull << 60)
#define REJECT_AFTER_MESSAGES (~0ull - (1ull << 13))   /* (1<<64) - (1<<13) - 1 */
#define REKEY_AFTER_TIME 120000
#define REKEY_TIMEOUT 5000
#define MAX_TIMER_HANDSHAKES 18                          /* 90 / 5 */
#define JITTER_MAX_MS 334
#define REJECT_AFTER_TIME 180000
#define KEEPALIVE_TIMEOUT 10000
#define COOKIE_REFRESH_TIME 120000
#define INIT_RATE_MS 20                                  /* time.Second / 50 */
#define ZERO_AFTER (REJECT_AFTER_TIME * 3)

#define TYPE_MASK 0x7fffffffu
#define MSG_MAX 65536
#define MSG_MIN 32                                       /* header + tag */
#define MAC1_INIT 116
#define MAC1_RESP 60

/* Timer deadline that never fires, and "long ago" for last-event times. */
#define OFF INT64_MAX
#define NEVER (-((int64_t)1 << 62))

/* Replay window (replay/replay.go, RFC 6479). */
#define RING_BLOCKS 128
typedef struct {
    uint64_t last;
    uint64_t ring[RING_BLOCKS];
} replay;

typedef struct {
    int live;
    int initiator;
    uint8_t send[32], recv[32];
    uint64_t send_nonce;
    replay rf;
    int64_t created;
    uint32_t local_index, remote_index;
} keypair;

typedef struct {
    size_t n;
    uint8_t b[TS_WG_MAX_PACKET];
} slot;

typedef struct {
    uint8_t key[32];
    uint32_t ipv4;
    uint8_t ss[32];              /* DH(our static, the peer's static) */

    ts_wg_hs hs;                 /* our pending initiation */
    int hs_pending;

    keypair cur, prev, next;

    uint8_t last_ts[12];         /* newest accepted TAI64N */
    int have_ts;
    int64_t last_init_ok;        /* last accepted initiation */
    int64_t last_sent_hs;        /* last initiation or response sent */

    uint8_t last_mac1[16];       /* of the last handshake message sent */
    uint32_t last_mac1_index;    /* its sender index */
    int have_mac1;
    uint8_t cookie[16];
    int64_t cookie_at;
    int have_cookie;

    int64_t t_retransmit, t_keepalive, t_new_hs, t_zero;
    int need_another_keepalive;
    int attempts;
    int sent_last_minute;

    slot staged[TS_WG_STAGED_MAX];
    size_t shead, nstaged;

    ts_wg_stats st;
} peer;

struct ts_wg_dev {
    ts_wg_static me;
    ts_wg_io io;
    void *user;
    int64_t now;
    peer *peers[TS_MAX_PEERS];
    int64_t hs_times[TS_WG_HS_PER_SEC];   /* last DH-costing messages allowed */
    size_t hs_pos;
    uint8_t tx[TS_WG_TRANSPORT_HDR + TS_WG_MAX_PACKET + 16 + 16];
    uint8_t rx[MSG_MAX];
    uint8_t prio[TS_WG_PRIORITY_MAX];
};

#ifdef TS_TEST_HOOKS
unsigned long ts_wg_test_dh_count;
#define DH_COST(k) (ts_wg_test_dh_count += (k))
#else
#define DH_COST(k) ((void)0)
#endif

/* ---- Helpers ------------------------------------------------------------- */

static void kp_wipe(keypair *k)
{
    ts_wipe(k, sizeof *k);
}

/* dst = src, then src wiped. */
static void kp_move(keypair *dst, keypair *src)
{
    kp_wipe(dst);
    memcpy(dst, src, sizeof *dst);
    kp_wipe(src);
}

static int replay_check(replay *f, uint64_t c)
{
    uint64_t ib, bit, old;
    if (c >= REJECT_AFTER_MESSAGES) return 0;
    ib = c >> 6;
    if (c > f->last) {
        uint64_t cur = f->last >> 6, diff = ib - cur, i;
        if (diff > RING_BLOCKS) diff = RING_BLOCKS;
        for (i = cur + 1; i <= cur + diff; i++) f->ring[i & (RING_BLOCKS - 1)] = 0;
        f->last = c;
    } else if (f->last - c > TS_WG_REPLAY_BITS) {
        return 0;
    }
    ib &= RING_BLOCKS - 1;
    bit = 1ull << (c & 63);
    old = f->ring[ib];
    f->ring[ib] = old | bit;
    return old != f->ring[ib];
}

static peer *find(const ts_wg_dev *d, const uint8_t key[32])
{
    size_t i;
    for (i = 0; i < TS_MAX_PEERS; i++)
        if (d->peers[i] && memcmp(d->peers[i]->key, key, 32) == 0) return d->peers[i];
    return NULL;
}

static int index_used(const ts_wg_dev *d, uint32_t v)
{
    size_t i;
    for (i = 0; i < TS_MAX_PEERS; i++) {
        const peer *p = d->peers[i];
        if (!p) continue;
        if (p->hs_pending && p->hs.local_index == v) return 1;
        if (p->cur.live && p->cur.local_index == v) return 1;
        if (p->prev.live && p->prev.local_index == v) return 1;
        if (p->next.live && p->next.local_index == v) return 1;
    }
    return 0;
}

static int new_index(ts_wg_dev *d, uint32_t *out)
{
    int tries;
    for (tries = 0; tries < 8; tries++) {
        uint8_t b[4];
        uint32_t v;
        if (d->io.random(d->user, b, 4) != 0) return -1;
        v = ts_get_le32(b);
        if (!index_used(d, v)) { *out = v; return 0; }
    }
    return -1;
}

static int64_t jitter(ts_wg_dev *d)
{
    uint8_t b[4];
    if (d->io.random(d->user, b, 4) != 0) return 0;
    return (int64_t)(ts_get_le32(b) % JITTER_MAX_MS);
}

static int mac1_ok(const ts_wg_dev *d, const uint8_t *msg, size_t at)
{
    uint8_t mac[16], diff = 0;
    ts_blake2s_ctx c;
    size_t i;
    if (ts_blake2s_init(&c, 16, d->me.mac1_key, 32) != 0) return 0;
    ts_blake2s_update(&c, msg, at);
    ts_blake2s_final(&c, mac);
    for (i = 0; i < 16; i++) diff |= (uint8_t)(mac[i] ^ msg[at + i]);
    return diff == 0;
}

/* At most TS_WG_HS_PER_SEC DH-costing messages in any 1000 ms. */
static int hs_allow(ts_wg_dev *d)
{
    if (d->now - d->hs_times[d->hs_pos] < 1000) return 0;
    d->hs_times[d->hs_pos] = d->now;
    d->hs_pos = (d->hs_pos + 1) % TS_WG_HS_PER_SEC;
    return 1;
}

int ts_wg_dh_allow(ts_wg_dev *d)
{
    return hs_allow(d);
}

static const uint8_t *cookie_for(const ts_wg_dev *d, const peer *p)
{
    return p->have_cookie && d->now - p->cookie_at <= COOKIE_REFRESH_TIME ? p->cookie : NULL;
}

static int send_valid(const ts_wg_dev *d, const keypair *k)
{
    return k->live && k->send_nonce < REJECT_AFTER_MESSAGES && d->now - k->created < REJECT_AFTER_TIME;
}

static void stage(peer *p, const uint8_t *ip, size_t n)
{
    slot *s;
    if (p->nstaged == TS_WG_STAGED_MAX) {   /* drop the oldest */
        ts_wipe(&p->staged[p->shead], sizeof(slot));
        p->shead = (p->shead + 1) % TS_WG_STAGED_MAX;
        p->nstaged--;
    }
    s = &p->staged[(p->shead + p->nstaged) % TS_WG_STAGED_MAX];
    if (n) memcpy(s->b, ip, n);
    s->n = n;
    p->nstaged++;
}

static void flush_staged(peer *p)
{
    ts_wipe(p->staged, sizeof p->staged);
    p->shead = p->nstaged = 0;
}

static void zero_and_flush(peer *p)
{
    kp_wipe(&p->cur);
    kp_wipe(&p->prev);
    kp_wipe(&p->next);
    ts_wipe(&p->hs, sizeof p->hs);
    p->hs_pending = 0;
    ts_wipe(p->cookie, sizeof p->cookie);
    p->have_cookie = 0;
    flush_staged(p);
}

/* ---- Sending ------------------------------------------------------------- */

static void send_initiation(ts_wg_dev *d, peer *p, int is_retry);

/* Seal pt with k and send it. -1 if the keypair's nonces are used up. */
static int send_transport(ts_wg_dev *d, peer *p, keypair *k, const uint8_t *pt, size_t n)
{
    size_t len;
    uint64_t nonce = k->send_nonce;
    if (nonce >= REJECT_AFTER_MESSAGES) {
        k->send_nonce = REJECT_AFTER_MESSAGES;
        return -1;
    }
    k->send_nonce++;
    len = ts_wg_transport_seal(d->tx, k->send, k->remote_index, nonce, pt, n);
    d->io.send(d->user, p->key, d->tx, len);
    ts_wipe(d->tx, len);
    return 0;
}

/* Timers after transport messages were sent (send.go processOutboundContainer). */
static void after_send(ts_wg_dev *d, peer *p, int data)
{
    p->t_keepalive = OFF;   /* timersAnyAuthenticatedPacketSent */
    if (data && p->t_new_hs == OFF)
        p->t_new_hs = d->now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + jitter(d);
    /* keepKeyFreshSending */
    if (p->cur.live && (p->cur.send_nonce > REKEY_AFTER_MESSAGES ||
                        (p->cur.initiator && d->now - p->cur.created > REKEY_AFTER_TIME)))
        send_initiation(d, p, 0);
}

static void send_staged(ts_wg_dev *d, peer *p)
{
    int sent = 0, data = 0;
    if (p->nstaged == 0) return;
    if (!send_valid(d, &p->cur)) {
        send_initiation(d, p, 0);
        return;
    }
    while (p->nstaged) {
        slot *s = &p->staged[p->shead];
        if (send_transport(d, p, &p->cur, s->b, s->n) != 0) break;
        sent = 1;
        if (s->n) {
            data = 1;
            p->st.tx_packets++;
            p->st.tx_bytes += s->n;
        }
        ts_wipe(s, sizeof *s);
        p->shead = (p->shead + 1) % TS_WG_STAGED_MAX;
        p->nstaged--;
    }
    if (sent) after_send(d, p, data);
    if (p->nstaged) send_initiation(d, p, 0);   /* nonces used up */
}

static void send_keepalive(ts_wg_dev *d, peer *p)
{
    if (p->nstaged == 0) stage(p, NULL, 0);
    send_staged(d, p);
}

/* Never starts a handshake (send.go SendPriorityMessage). */
static void send_priority(ts_wg_dev *d, peer *p)
{
    size_t n;
    if (!d->io.priority || !send_valid(d, &p->cur)) return;
    n = d->io.priority(d->user, p->key, d->prio, sizeof d->prio);
    if (n > 0 && n <= sizeof d->prio && send_transport(d, p, &p->cur, d->prio, n) == 0) {
        p->st.tx_packets++;
        p->st.tx_bytes += n;
        after_send(d, p, 1);
    }
    ts_wipe(d->prio, sizeof d->prio);
}

static void send_initiation(ts_wg_dev *d, peer *p, int is_retry)
{
    uint8_t eph[32], ts[12], msg[TS_WG_INIT_LEN];
    uint32_t idx, nsec = 0;
    int64_t sec;

    if (!is_retry) p->attempts = 0;
    if (d->now - p->last_sent_hs < REKEY_TIMEOUT) return;
    p->last_sent_hs = d->now;

    /* The old pending initiation is replaced. */
    ts_wipe(&p->hs, sizeof p->hs);
    p->hs_pending = 0;
    if (new_index(d, &idx) != 0) return;
    if (d->io.random(d->user, eph, 32) != 0) { ts_wipe(eph, sizeof eph); return; }
    sec = d->io.wall(d->user, &nsec);
    ts_wg_tai64n(ts, sec, nsec);
    if (ts_wg_create_init(&p->hs, &d->me, p->key, p->ss, idx, eph, ts, cookie_for(d, p), msg) != 0) {
        ts_wipe(eph, sizeof eph);
        return;
    }
    ts_wipe(eph, sizeof eph);
    p->hs_pending = 1;
    memcpy(p->last_mac1, msg + MAC1_INIT, 16);
    p->last_mac1_index = idx;
    p->have_mac1 = 1;

    p->t_keepalive = OFF;
    d->io.send(d->user, p->key, msg, sizeof msg);
    p->t_retransmit = d->now + REKEY_TIMEOUT + jitter(d);   /* timersHandshakeInitiated */
}

/* Responder: hs has a consumed initiation. */
static void send_response(ts_wg_dev *d, peer *p, ts_wg_hs *hs)
{
    uint8_t eph[32], msg[TS_WG_RESP_LEN];
    keypair k;
    uint32_t idx;

    p->last_sent_hs = d->now;
    /* The peer's handshake state is shared, as upstream: our own pending
     * initiation is abandoned. */
    ts_wipe(&p->hs, sizeof p->hs);
    p->hs_pending = 0;
    if (new_index(d, &idx) != 0) return;
    if (d->io.random(d->user, eph, 32) != 0) { ts_wipe(eph, sizeof eph); return; }
    DH_COST(2);
    if (ts_wg_create_resp(hs, idx, eph, cookie_for(d, p), msg) != 0) {
        ts_wipe(eph, sizeof eph);
        return;
    }
    ts_wipe(eph, sizeof eph);
    memcpy(p->last_mac1, msg + MAC1_RESP, 16);
    p->last_mac1_index = idx;
    p->have_mac1 = 1;

    memset(&k, 0, sizeof k);
    k.remote_index = hs->remote_index;
    ts_wg_derive(hs, 0, k.send, k.recv);   /* right after create_resp */
    k.live = 1;
    k.initiator = 0;
    k.created = d->now;
    k.local_index = idx;
    kp_move(&p->next, &k);
    kp_wipe(&p->prev);

    p->t_zero = d->now + ZERO_AFTER;   /* timersSessionDerived */
    p->t_keepalive = OFF;
    d->io.send(d->user, p->key, msg, sizeof msg);
}

/* ---- Receiving ----------------------------------------------------------- */

static void handshake_complete(ts_wg_dev *d, peer *p)
{
    p->t_retransmit = OFF;
    p->attempts = 0;
    p->sent_last_minute = 0;
    p->st.last_handshake_ms = d->now;
}

static void recv_init(ts_wg_dev *d, peer *p, const uint8_t *msg)
{
    ts_wg_hs hs;
    uint8_t spub[32], ts[12];
    uint32_t sender;

    /* All before any DH. */
    if (d->now - p->last_init_ok <= INIT_RATE_MS) return;
    if (!mac1_ok(d, msg, MAC1_INIT)) return;
    if (!hs_allow(d)) return;

    DH_COST(1);
    if (ts_wg_init_open_static(&hs, &d->me, msg, spub) != 0) goto out;
    if (memcmp(spub, p->key, 32) != 0) goto out;
    if (ts_wg_init_finish(&hs, p->ss, ts, &sender) != 0) goto out;
    if (p->have_ts && memcmp(ts, p->last_ts, 12) <= 0) goto out;   /* big-endian: not newer */
    memcpy(p->last_ts, ts, 12);
    p->have_ts = 1;
    p->last_init_ok = d->now;
    p->t_new_hs = OFF;   /* timersAnyAuthenticatedPacketReceived */
    send_response(d, p, &hs);
out:
    ts_wipe(&hs, sizeof hs);
    ts_wipe(ts, sizeof ts);
}

static void recv_resp(ts_wg_dev *d, peer *p, const uint8_t *msg)
{
    keypair k;
    uint32_t sender;

    if (!p->hs_pending || ts_get_le32(msg + 8) != p->hs.local_index) return;
    if (!mac1_ok(d, msg, MAC1_RESP)) return;
    if (!hs_allow(d)) return;
    DH_COST(2);
    if (ts_wg_consume_resp(&p->hs, &d->me, msg, &sender) != 0) return;
    p->t_new_hs = OFF;

    memset(&k, 0, sizeof k);
    k.remote_index = p->hs.remote_index;
    k.local_index = p->hs.local_index;
    ts_wg_derive(&p->hs, 1, k.send, k.recv);   /* right after consume_resp */
    p->hs_pending = 0;
    k.live = 1;
    k.initiator = 1;
    k.created = d->now;

    /* Initiator rotation (noise-protocol.go BeginSymmetricSession). */
    if (p->next.live) {
        kp_wipe(&p->cur);
        kp_move(&p->prev, &p->next);
    } else {
        kp_move(&p->prev, &p->cur);
    }
    kp_move(&p->cur, &k);

    p->t_zero = d->now + ZERO_AFTER;
    handshake_complete(d, p);
    send_priority(d, p);
    send_keepalive(d, p);
}

static void recv_cookie(ts_wg_dev *d, peer *p, const uint8_t *msg)
{
    uint8_t c[16];
    if (!p->have_mac1 || ts_get_le32(msg + 4) != p->last_mac1_index) return;
    if (ts_wg_cookie_open(c, p->key, p->last_mac1, msg) != 0) return;
    memcpy(p->cookie, c, 16);
    ts_wipe(c, sizeof c);
    p->cookie_at = d->now;
    p->have_cookie = 1;
}

static void recv_transport(ts_wg_dev *d, peer *p, const uint8_t *msg, size_t n)
{
    uint32_t idx = ts_get_le32(msg + 4);
    keypair *k;
    long len;
    int data = 0;

    if (p->cur.live && p->cur.local_index == idx) k = &p->cur;
    else if (p->next.live && p->next.local_index == idx) k = &p->next;
    else if (p->prev.live && p->prev.local_index == idx) k = &p->prev;
    else return;
    if (d->now - k->created > REJECT_AFTER_TIME) return;

    len = ts_wg_transport_open(d->rx, k->recv, msg, n);
    if (len < 0) return;
    if (!replay_check(&k->rf, ts_get_le64(msg + 8))) goto out;

    if (k == &p->next) {   /* ReceivedWithKeypair */
        kp_move(&p->prev, &p->cur);
        kp_move(&p->cur, &p->next);
        handshake_complete(d, p);
        send_priority(d, p);
        send_staged(d, p);
    }

    if (len > 0) {
        ts_pkt pk;
        data = 1;
        if (ts_pkt_parse(&pk, d->rx, (size_t)len) == 0 && pk.src == p->ipv4) {
            p->st.rx_packets++;
            p->st.rx_bytes += pk.len;
            d->io.deliver(d->user, p->key, d->rx, pk.len);
        }
    }

    /* keepKeyFreshReceiving */
    if (!p->sent_last_minute && p->cur.live && p->cur.initiator &&
        d->now - p->cur.created > REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT) {
        p->sent_last_minute = 1;
        send_initiation(d, p, 0);
    }
    p->t_new_hs = OFF;
    if (data) {   /* timersDataReceived */
        if (p->t_keepalive == OFF) p->t_keepalive = d->now + KEEPALIVE_TIMEOUT;
        else p->need_another_keepalive = 1;
    }
out:
    ts_wipe(d->rx, (size_t)len);
}

/* ---- Public -------------------------------------------------------------- */

size_t ts_wg_transport_seal(uint8_t *out, const uint8_t key[32], uint32_t receiver,
                            uint64_t counter, const uint8_t *pt, size_t n)
{
    uint8_t nonce[12];
    size_t padded = (n + 15) & ~(size_t)15;
    ts_put_le32(out, 4);
    ts_put_le32(out + 4, receiver);
    ts_put_le64(out + 8, counter);
    if (n) memcpy(out + TS_WG_TRANSPORT_HDR, pt, n);
    memset(out + TS_WG_TRANSPORT_HDR + n, 0, padded - n);
    memset(nonce, 0, 4);
    ts_put_le64(nonce + 4, counter);
    ts_aead_seal(out + TS_WG_TRANSPORT_HDR, key, nonce, NULL, 0, out + TS_WG_TRANSPORT_HDR, padded);
    return TS_WG_TRANSPORT_HDR + padded + 16;
}

long ts_wg_transport_open(uint8_t *out, const uint8_t key[32], const uint8_t *msg, size_t n)
{
    uint8_t nonce[12];
    if (n < MSG_MIN) return -1;
    memset(nonce, 0, 4);
    memcpy(nonce + 4, msg + 8, 8);   /* the LE counter, as is */
    if (ts_aead_open(out, key, nonce, NULL, 0, msg + TS_WG_TRANSPORT_HDR, n - TS_WG_TRANSPORT_HDR) != 0)
        return -1;
    return (long)(n - MSG_MIN);
}

ts_wg_dev *ts_wg_new(const uint8_t node_priv[32], const ts_wg_io *io, void *user)
{
    ts_wg_dev *d = (ts_wg_dev *)calloc(1, sizeof *d);
    size_t i;
    if (!d) return NULL;
    ts_wg_static_init(&d->me, node_priv);
    d->io = *io;
    d->user = user;
    for (i = 0; i < TS_WG_HS_PER_SEC; i++) d->hs_times[i] = NEVER;
    return d;
}

static void free_peer(peer *p)
{
    ts_wipe(p, sizeof *p);
    free(p);
}

void ts_wg_free(ts_wg_dev *d)
{
    size_t i;
    if (!d) return;
    for (i = 0; i < TS_MAX_PEERS; i++)
        if (d->peers[i]) free_peer(d->peers[i]);
    ts_wipe(d, sizeof *d);
    free(d);
}

int ts_wg_set_peer(ts_wg_dev *d, const uint8_t key[32], uint32_t ipv4)
{
    peer *p = find(d, key);
    size_t i;
    if (p) {
        p->ipv4 = ipv4;
        return 0;
    }
    for (i = 0; i < TS_MAX_PEERS && d->peers[i]; i++) {}
    if (i == TS_MAX_PEERS) return -1;
    p = (peer *)calloc(1, sizeof *p);
    if (!p) return -1;
    memcpy(p->key, key, 32);
    if (ts_x25519(p->ss, d->me.priv, key) != 0) {   /* once per peer */
        free_peer(p);
        return -1;
    }
    p->ipv4 = ipv4;
    p->last_init_ok = p->last_sent_hs = NEVER;
    p->t_retransmit = p->t_keepalive = p->t_new_hs = p->t_zero = OFF;
    p->st.last_handshake_ms = -1;
    d->peers[i] = p;
    return 0;
}

void ts_wg_remove_peer(ts_wg_dev *d, const uint8_t key[32])
{
    size_t i;
    for (i = 0; i < TS_MAX_PEERS; i++) {
        if (d->peers[i] && memcmp(d->peers[i]->key, key, 32) == 0) {
            free_peer(d->peers[i]);
            d->peers[i] = NULL;
            return;
        }
    }
}

void ts_wg_send_packet(ts_wg_dev *d, const uint8_t key[32], const uint8_t *ip, size_t n)
{
    peer *p = find(d, key);
    if (!p || n == 0 || n > TS_WG_MAX_PACKET) return;
    stage(p, ip, n);
    send_staged(d, p);
}

void ts_wg_receive(ts_wg_dev *d, const uint8_t from[32], const uint8_t *msg, size_t n)
{
    peer *p = find(d, from);
    if (!p || n < 4) return;
    switch (ts_get_le32(msg) & TYPE_MASK) {
    case 1:
        if (n == TS_WG_INIT_LEN) recv_init(d, p, msg);
        break;
    case 2:
        if (n == TS_WG_RESP_LEN) recv_resp(d, p, msg);
        break;
    case 3:
        if (n == TS_WG_COOKIE_LEN) recv_cookie(d, p, msg);
        break;
    case 4:
        if (n >= MSG_MIN && n <= MSG_MAX) recv_transport(d, p, msg, n);
        break;
    default:
        break;
    }
}

void ts_wg_tick(ts_wg_dev *d, int64_t now_ms)
{
    size_t i;
    d->now = now_ms;
    for (i = 0; i < TS_MAX_PEERS; i++) {
        peer *p = d->peers[i];
        if (!p) continue;
        if (now_ms >= p->t_retransmit) {   /* expiredRetransmitHandshake */
            p->t_retransmit = OFF;
            if (p->attempts > MAX_TIMER_HANDSHAKES) {
                p->t_keepalive = OFF;
                flush_staged(p);
                if (p->t_zero == OFF) p->t_zero = now_ms + ZERO_AFTER;
            } else {
                p->attempts++;
                send_initiation(d, p, 1);
            }
        }
        if (now_ms >= p->t_keepalive) {   /* expiredSendKeepalive */
            p->t_keepalive = OFF;
            send_keepalive(d, p);
            if (p->need_another_keepalive) {
                p->need_another_keepalive = 0;
                p->t_keepalive = now_ms + KEEPALIVE_TIMEOUT;
            }
        }
        if (now_ms >= p->t_new_hs) {   /* expiredNewHandshake */
            p->t_new_hs = OFF;
            send_initiation(d, p, 0);
        }
        if (now_ms >= p->t_zero) {   /* expiredZeroKeyMaterial */
            p->t_zero = OFF;
            zero_and_flush(p);
        }
    }
}

void ts_wg_reset_sessions(ts_wg_dev *d)
{
    size_t i;
    for (i = 0; i < TS_MAX_PEERS; i++) {
        peer *p = d->peers[i];
        if (!p) continue;
        zero_and_flush(p);   /* keypairs, handshake, cookie, staged packets */
        ts_wipe(p->last_mac1, sizeof p->last_mac1);
        p->last_mac1_index = 0;
        p->have_mac1 = 0;
        p->cookie_at = 0;
        p->last_sent_hs = NEVER;
        p->t_retransmit = p->t_keepalive = p->t_new_hs = p->t_zero = OFF;
        p->need_another_keepalive = 0;
        p->attempts = 0;
        p->sent_last_minute = 0;
        /* Kept: key, ipv4, ss, stats, and last_ts / last_init_ok, so an old
         * initiation replayed after the reset is still refused. */
    }
}

int ts_wg_peer_stats(const ts_wg_dev *d, const uint8_t key[32], ts_wg_stats *out)
{
    const peer *p = find(d, key);
    if (!p) return -1;
    *out = p->st;
    out->have_session = send_valid(d, &p->cur);
    return 0;
}

#ifdef TS_TEST_HOOKS
int ts_wg_test_has_keys(const ts_wg_dev *d, const uint8_t key[32])
{
    const peer *p = find(d, key);
    const uint8_t *parts[4];
    size_t lens[4], i, j;
    uint8_t acc = 0;
    if (!p) return 0;
    parts[0] = (const uint8_t *)&p->cur; lens[0] = sizeof p->cur;
    parts[1] = (const uint8_t *)&p->prev; lens[1] = sizeof p->prev;
    parts[2] = (const uint8_t *)&p->next; lens[2] = sizeof p->next;
    parts[3] = (const uint8_t *)&p->hs; lens[3] = sizeof p->hs;
    for (i = 0; i < 4; i++)
        for (j = 0; j < lens[i]; j++) acc |= parts[i][j];
    return acc != 0;
}

int ts_wg_test_keypairs(const ts_wg_dev *d, const uint8_t key[32], uint32_t idx[3], int live[3])
{
    const peer *p = find(d, key);
    const keypair *k[3];
    int i;
    if (!p) return -1;
    k[0] = &p->cur;
    k[1] = &p->prev;
    k[2] = &p->next;
    for (i = 0; i < 3; i++) {
        live[i] = k[i]->live;
        idx[i] = k[i]->live ? k[i]->local_index : 0;
    }
    return 0;
}
#endif
