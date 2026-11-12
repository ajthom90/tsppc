#include "harness.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/core/bytes.h"
#include "../src/crypto/blake2s.h"
#include "../src/crypto/x25519.h"
#include "../src/crypto/xaead.h"
#include "../src/filter/packet.h"
#include "../src/wg/device.h"
#include "../src/wg/handshake.h"

#include "wg_vectors.inc"

/* Two (or three) devices joined by in-memory send callbacks and a fake
 * clock. Sent messages go to a queue; pump() delivers them in order.
 * Callbacks never re-enter a device. */

#define NODES 3
#define QCAP 512
#define MSGMAX 2048
#define DELIVMAX 64

typedef struct {
    ts_wg_dev *d;
    uint8_t priv[32], pub[32];
    uint32_t ip;
    int drop_out;                 /* drop everything this node sends */
    int nsent[5];                 /* by message type (1..4) */
    int ntransport_keepalive;     /* transport messages of 32 bytes */
    uint8_t last_sent[5][MSGMAX]; /* last message of each type */
    size_t last_sent_n[5];
    int ndeliv;
    uint8_t deliv[DELIVMAX][MSGMAX];
    size_t delivn[DELIVMAX];
    int use_priority;
    uint64_t rng;
    /* Scripted random: served in order while it lasts. */
    uint8_t script[128];
    size_t script_n, script_at;
    int64_t wall_sec;             /* 0: base + clock */
    uint32_t wall_nsec;
} node;

typedef struct {
    int dst;
    uint8_t from[32];
    uint8_t m[MSGMAX];
    size_t n;
} qmsg;

static node N[NODES];
static qmsg Q[QCAP];
static size_t q_head, q_len;
static int64_t now_ms;
static int capture;   /* 1: sends from node 0 are stored in CAP instead of queued */

#define CAPMAX 8300
static uint8_t CAP[CAPMAX][64];
static size_t ncap;

static int node_of_pub(const uint8_t pub[32])
{
    int i;
    for (i = 0; i < NODES; i++)
        if (memcmp(N[i].pub, pub, 32) == 0) return i;
    return -1;
}

static void cb_send(void *user, const uint8_t peer[32], const uint8_t *msg, size_t n)
{
    node *me = (node *)user;
    int dst = node_of_pub(peer);
    uint32_t t = n >= 4 ? ts_get_le32(msg) : 0;
    if (t >= 1 && t <= 4) {
        me->nsent[t]++;
        if (n <= MSGMAX) { memcpy(me->last_sent[t], msg, n); me->last_sent_n[t] = n; }
    }
    if (t == 4 && n == 32) me->ntransport_keepalive++;
    if (me->drop_out) return;
    if (capture && me == &N[0] && t == 4) {
        if (ncap < CAPMAX && n <= 64) { memcpy(CAP[ncap], msg, n); ncap++; }
        return;
    }
    if (dst < 0 || q_len == QCAP || n > MSGMAX) return;
    {
        qmsg *q = &Q[(q_head + q_len) % QCAP];
        q->dst = dst;
        memcpy(q->from, me->pub, 32);
        memcpy(q->m, msg, n);
        q->n = n;
        q_len++;
    }
}

static void cb_deliver(void *user, const uint8_t peer[32], const uint8_t *ip, size_t n)
{
    node *me = (node *)user;
    (void)peer;
    if (me->ndeliv < DELIVMAX && n <= MSGMAX) {
        memcpy(me->deliv[me->ndeliv], ip, n);
        me->delivn[me->ndeliv] = n;
    }
    me->ndeliv++;
}

static int cb_random(void *user, uint8_t *out, size_t n)
{
    node *me = (node *)user;
    size_t i;
    if (me->script_at + n <= me->script_n) {
        memcpy(out, me->script + me->script_at, n);
        me->script_at += n;
        return 0;
    }
    for (i = 0; i < n; i++) {
        me->rng ^= me->rng << 13;
        me->rng ^= me->rng >> 7;
        me->rng ^= me->rng << 17;
        out[i] = (uint8_t)(me->rng >> 24);
    }
    return 0;
}

static int64_t cb_wall(void *user, uint32_t *nsec)
{
    node *me = (node *)user;
    if (me->wall_sec) { *nsec = me->wall_nsec; return me->wall_sec; }
    *nsec = (uint32_t)((now_ms % 1000) * 1000000);
    return 1700000000 + now_ms / 1000;
}

static size_t cb_priority(void *user, const uint8_t peer[32], uint8_t *out, size_t cap)
{
    node *me = (node *)user;
    int o = node_of_pub(peer);
    uint8_t disco[32];
    if (!me->use_priority || o < 0 || cap < 53) return 0;
    memset(disco, 0xd0 + (int)(me - N), 32);
    return ts_pkt_tsmp_disco(out, me->ip, N[o].ip, disco);
}

static const ts_wg_io IO = { cb_send, cb_deliver, cb_random, cb_wall, cb_priority };

static void node_reset_counts(node *n)
{
    memset(n->nsent, 0, sizeof n->nsent);
    n->ntransport_keepalive = 0;
    n->ndeliv = 0;
}

/* Fresh nodes 0 (A), 1 (B), 2 (C); A and B know each other. */
static void setup(void)
{
    int i;
    for (i = 0; i < NODES; i++) {
        if (N[i].d) ts_wg_free(N[i].d);
    }
    memset(N, 0, sizeof N);
    q_head = q_len = 0;
    now_ms = 0;
    capture = 0;
    ncap = 0;
    for (i = 0; i < NODES; i++) {
        memset(N[i].priv, 0x11 * (i + 1), 32);
        N[i].priv[0] &= 248;
        N[i].priv[31] = (uint8_t)((N[i].priv[31] & 127) | 64);
        ts_x25519_public(N[i].pub, N[i].priv);
        N[i].ip = 0x64400001u + (uint32_t)i;   /* 100.64.0.1, .2, .3 */
        N[i].rng = 0x9e3779b97f4a7c15ull * (uint64_t)(i + 1);
        N[i].d = ts_wg_new(N[i].priv, &IO, &N[i]);
        ts_wg_tick(N[i].d, 0);
    }
    t_true("setup A knows B", ts_wg_set_peer(N[0].d, N[1].pub, N[1].ip) == 0);
    t_true("setup B knows A", ts_wg_set_peer(N[1].d, N[0].pub, N[0].ip) == 0);
}

static void teardown(void)
{
    int i;
    for (i = 0; i < NODES; i++) {
        if (N[i].d) ts_wg_free(N[i].d);
        N[i].d = NULL;
    }
}

static void pump(void)
{
    int guard = 0;
    while (q_len && guard++ < 100000) {
        qmsg *q = &Q[q_head];
        static qmsg cur;
        cur = *q;
        q_head = (q_head + 1) % QCAP;
        q_len--;
        ts_wg_receive(N[cur.dst].d, cur.from, cur.m, cur.n);
    }
}

static void tick_all(void)
{
    int i;
    for (i = 0; i < NODES; i++) ts_wg_tick(N[i].d, now_ms);
}

/* Advance the clock to t in 250 ms steps, pumping after each tick. */
static void run_until(int64_t t)
{
    while (now_ms < t) {
        now_ms += 250;
        if (now_ms > t) now_ms = t;
        tick_all();
        pump();
    }
}

/* An IPv4 ICMP echo request of n bytes (n >= 28), payload byte id. */
static size_t mk_ip(uint8_t *b, size_t n, uint32_t src, uint32_t dst, uint8_t id)
{
    memset(b, 0, n);
    b[0] = 0x45;
    ts_put_be16(b + 2, (uint16_t)n);
    b[8] = 64;
    b[9] = 1;
    ts_put_be32(b + 12, src);
    ts_put_be32(b + 16, dst);
    ts_put_be16(b + 10, ts_ip_checksum(b, 20));
    b[20] = 8;
    if (n > 28) memset(b + 28, id, n - 28);
    b[24] = id;
    return n;
}

static void send_ip(int from, int to, uint8_t id, size_t n)
{
    uint8_t b[256];
    mk_ip(b, n, N[from].ip, N[to].ip, id);
    ts_wg_send_packet(N[from].d, N[to].pub, b, n);
}

/* A sends one packet; the handshake runs; everything delivered. */
static void establish(void)
{
    send_ip(0, 1, 0xee, 28);
    pump();
    node_reset_counts(&N[0]);
    node_reset_counts(&N[1]);
}

static int stats_session(int a, int b)
{
    ts_wg_stats st;
    if (ts_wg_peer_stats(N[a].d, N[b].pub, &st) != 0) return -1;
    return st.have_session;
}

static void mac1_for(uint8_t *msg, size_t at, const uint8_t receiver_pub[32])
{
    uint8_t key[32];
    ts_blake2s_ctx c;
    ts_blake2s_ctx h;
    ts_blake2s_init(&h, 32, NULL, 0);
    ts_blake2s_update(&h, "mac1----", 8);
    ts_blake2s_update(&h, receiver_pub, 32);
    ts_blake2s_final(&h, key);
    ts_blake2s_init(&c, 16, key, 32);
    ts_blake2s_update(&c, msg, at);
    ts_blake2s_final(&c, msg + at);
}

/* ---- Tests --------------------------------------------------------------- */

/* The device's real transport path produces the Task 3 vector. */
static void test_wgdev_vector(void)
{
    uint8_t want_init[TS_WG_INIT_LEN], want_resp[TS_WG_RESP_LEN], want_tr[48], pl[3];
    uint8_t key[32], out[64];
    ts_wg_stats st;
    long n;

    setup();
    teardown();
    memset(N, 0, sizeof N);
    q_head = q_len = 0;
    now_ms = 1000;
    t_unhex(N[0].priv, WGV_I_STATIC_PRIV);
    t_unhex(N[1].priv, WGV_R_STATIC_PRIV);
    ts_x25519_public(N[0].pub, N[0].priv);
    ts_x25519_public(N[1].pub, N[1].priv);
    N[0].ip = 0x64400001u;
    N[1].ip = 0x64400002u;
    /* A: sender index, then ephemeral. B: the same for the response. */
    ts_put_le32(N[0].script, WGV_I_INDEX);
    t_unhex(N[0].script + 4, WGV_I_EPH_PRIV);
    N[0].script_n = 36;
    ts_put_le32(N[1].script, WGV_R_INDEX);
    t_unhex(N[1].script + 4, WGV_R_EPH_PRIV);
    N[1].script_n = 36;
    N[0].wall_sec = WGV_TS_SEC;
    N[0].wall_nsec = WGV_TS_NSEC;
    N[0].d = ts_wg_new(N[0].priv, &IO, &N[0]);
    N[1].d = ts_wg_new(N[1].priv, &IO, &N[1]);
    ts_wg_tick(N[0].d, now_ms);
    ts_wg_tick(N[1].d, now_ms);
    ts_wg_set_peer(N[0].d, N[1].pub, N[1].ip);
    ts_wg_set_peer(N[1].d, N[0].pub, N[0].ip);

    t_unhex(pl, WGV_PAYLOAD);
    ts_wg_send_packet(N[0].d, N[1].pub, pl, 3);
    t_unhex(want_init, WGV_INIT);
    t_true("vector: initiation from the device",
           N[0].last_sent_n[1] == TS_WG_INIT_LEN && memcmp(N[0].last_sent[1], want_init, TS_WG_INIT_LEN) == 0);
    pump();
    t_unhex(want_resp, WGV_RESP);
    t_true("vector: response from the device",
           N[1].last_sent_n[2] == TS_WG_RESP_LEN && memcmp(N[1].last_sent[2], want_resp, TS_WG_RESP_LEN) == 0);
    t_unhex(want_tr, WGV_TRANSPORT);
    t_true("vector: transport from ts_wg_send_packet",
           N[0].last_sent_n[4] == 48 && memcmp(N[0].last_sent[4], want_tr, 48) == 0);
    t_true("vector: B accepted it (handshake complete)",
           ts_wg_peer_stats(N[1].d, N[0].pub, &st) == 0 && st.last_handshake_ms == now_ms && st.have_session);
    t_true("vector: not IPv4, not delivered", N[1].ndeliv == 0);

    /* The helpers directly. */
    t_unhex(key, WGV_I_SEND);
    t_true("vector: seal", ts_wg_transport_seal(out, key, WGV_R_INDEX, WGV_TRANSPORT_COUNTER, pl, 3) == 48 &&
                           memcmp(out, want_tr, 48) == 0);
    t_unhex(key, WGV_R_RECV);
    n = ts_wg_transport_open(out, key, want_tr, 48);
    t_true("vector: open", n == 16 && memcmp(out, pl, 3) == 0 && out[3] == 0 && out[15] == 0);
    want_tr[20] ^= 1;
    t_true("vector: open rejects a flipped bit", ts_wg_transport_open(out, key, want_tr, 48) == -1);
    t_true("vector: open rejects short", ts_wg_transport_open(out, key, want_tr, 31) == -1);
    teardown();
}

static void test_wgdev_ping(void)
{
    ts_wg_stats st;
    ts_pkt p;
    setup();
    N[0].use_priority = N[1].use_priority = 1;
    t_true("ping: no session before", stats_session(0, 1) == 0);
    send_ip(0, 1, 0x42, 60);
    t_true("ping: one initiation", N[0].nsent[1] == 1 && N[0].nsent[4] == 0);
    pump();
    t_true("ping: B delivered two", N[1].ndeliv == 2);
    t_true("ping: priority first (TSMP from A)",
           ts_pkt_parse(&p, N[1].deliv[0], N[1].delivn[0]) == 0 && p.proto == 99 && p.src == N[0].ip &&
           N[1].delivn[0] == 53);
    t_true("ping: then the packet", N[1].delivn[1] == 60 && N[1].deliv[1][24] == 0x42 && N[1].deliv[1][59] == 0x42);
    t_true("ping: A got B's priority", N[0].ndeliv == 1 && N[0].delivn[0] == 53);
    t_true("ping: sessions", stats_session(0, 1) == 1 && stats_session(1, 0) == 1);
    ts_wg_peer_stats(N[0].d, N[1].pub, &st);
    t_true("ping: A tx stats", st.tx_packets == 2 && st.tx_bytes == 113 && st.last_handshake_ms == 0);
    ts_wg_peer_stats(N[1].d, N[0].pub, &st);
    t_true("ping: B rx stats", st.rx_packets == 2 && st.rx_bytes == 113);
    t_true("ping: unknown peer stats", ts_wg_peer_stats(N[0].d, N[2].pub, &st) == -1);

    /* And back. */
    send_ip(1, 0, 0x43, 40);
    pump();
    t_true("ping: reply delivered", N[0].ndeliv == 2 && N[0].delivn[1] == 40);
    teardown();

    /* Responder with staged packets: priority first, then the staged one. */
    setup();
    N[0].use_priority = N[1].use_priority = 1;
    N[1].drop_out = 1;
    send_ip(1, 0, 0x51, 30);   /* staged at B; B's initiation is lost */
    N[1].drop_out = 0;
    send_ip(0, 1, 0x52, 30);
    pump();
    t_true("ping: responder priority before staged",
           N[0].ndeliv == 2 && N[0].delivn[0] == 53 && N[0].delivn[1] == 30 && N[0].deliv[1][24] == 0x51);
    t_true("ping: and A's packet arrived", N[1].ndeliv == 2 && N[1].deliv[1][24] == 0x52);
    teardown();
}

static void test_wgdev_allowedips(void)
{
    uint8_t b[64];
    uint8_t held[MSGMAX];
    size_t heldn;
    setup();
    establish();

    mk_ip(b, 28, 0x64400063u, N[1].ip, 1);   /* spoofed source */
    ts_wg_send_packet(N[0].d, N[1].pub, b, 28);
    memset(b, 0, sizeof b);
    b[0] = 0x60;                              /* IPv6 */
    ts_wg_send_packet(N[0].d, N[1].pub, b, 48);
    ts_wg_send_packet(N[0].d, N[1].pub, (const uint8_t *)"junk", 4);
    mk_ip(b, 28, N[0].ip, N[1].ip, 2);
    ts_put_be16(b + 2, 200);                  /* total length over the buffer */
    ts_wg_send_packet(N[0].d, N[1].pub, b, 28);
    t_true("allowedips: four sent", N[0].nsent[4] == 4);
    pump();
    t_true("allowedips: nothing delivered", N[1].ndeliv == 0);

    /* Padding is trimmed with the IPv4 total length. */
    send_ip(0, 1, 3, 29);
    pump();
    t_true("allowedips: own source delivered, trimmed", N[1].ndeliv == 1 && N[1].delivn[0] == 29);

    /* A transport message of A's, but arriving from C (configured at B): dropped. */
    t_true("allowedips: B knows C", ts_wg_set_peer(N[1].d, N[2].pub, N[2].ip) == 0);
    send_ip(0, 1, 4, 28);
    t_true("allowedips: one queued", q_len == 1);
    heldn = Q[q_head].n;
    memcpy(held, Q[q_head].m, heldn);
    q_head = (q_head + 1) % QCAP;
    q_len--;
    ts_wg_receive(N[1].d, N[2].pub, held, heldn);
    t_true("allowedips: index bound to from", N[1].ndeliv == 1);
    ts_wg_receive(N[1].d, N[0].pub, held, heldn);
    t_true("allowedips: from A it is delivered", N[1].ndeliv == 2);
    teardown();
}

static void test_wgdev_timers(void)
{
    uint8_t held[MSGMAX];
    size_t heldn;

    /* Rekey at 120 s, initiator side, triggered by sending. */
    setup();
    establish();
    run_until(119000);
    node_reset_counts(&N[0]);
    send_ip(0, 1, 1, 28);
    pump();
    t_true("rekey: no initiation before 120 s", N[0].nsent[1] == 0 && N[0].nsent[4] >= 1);
    run_until(120250);
    node_reset_counts(&N[0]);
    send_ip(0, 1, 2, 28);
    t_true("rekey: data still sent, then an initiation", N[0].nsent[4] >= 1 && N[0].nsent[1] == 1);
    pump();
    t_true("rekey: new handshake complete", N[1].ndeliv >= 2);
    teardown();

    /* A session is dead at 180 s with no traffic. */
    setup();
    establish();
    run_until(1000);
    send_ip(0, 1, 5, 28);
    t_true("dead: one held", q_len == 1);
    heldn = Q[q_head].n;
    memcpy(held, Q[q_head].m, heldn);
    q_head = (q_head + 1) % QCAP;
    q_len--;
    run_until(179750);
    t_true("dead: alive at 179.75 s", stats_session(0, 1) == 1 && stats_session(1, 0) == 1);
    run_until(180250);
    t_true("dead: gone at 180 s", stats_session(0, 1) == 0 && stats_session(1, 0) == 0);
    node_reset_counts(&N[1]);
    ts_wg_receive(N[1].d, N[0].pub, held, heldn);
    t_true("dead: old message rejected", N[1].ndeliv == 0);
    node_reset_counts(&N[0]);
    N[0].drop_out = 1;
    send_ip(0, 1, 6, 28);
    t_true("dead: send stages and initiates", N[0].nsent[4] == 0 && N[0].nsent[1] == 1);
    N[0].drop_out = 0;
    teardown();

    /* 19 retries (20 initiations, as upstream), then staged packets dropped. */
    setup();
    N[0].drop_out = 1;
    send_ip(0, 1, 7, 28);
    run_until(4750);
    t_true("retry: one so far", N[0].nsent[1] == 1);
    run_until(5500);
    t_true("retry: first retry after 5 s + jitter", N[0].nsent[1] == 2);
    run_until(200000);
    t_true("retry: 20 initiations in all", N[0].nsent[1] == 20);
    N[0].drop_out = 0;
    node_reset_counts(&N[1]);
    send_ip(0, 1, 8, 28);
    pump();
    t_true("retry: only the new packet arrives", N[1].ndeliv == 1 && N[1].deliv[0][24] == 8);
    teardown();

    /* Passive keepalive 10 s after receiving with nothing sent. */
    setup();
    establish();
    run_until(30000);   /* settle the keepalives from the handshake */
    send_ip(0, 1, 9, 28);
    pump();
    node_reset_counts(&N[1]);
    run_until(39750);
    t_true("keepalive: none before 10 s", N[1].nsent[4] == 0);
    run_until(40250);
    t_true("keepalive: one at 10 s", N[1].nsent[4] == 1 && N[1].ntransport_keepalive == 1);
    run_until(70000);
    t_true("keepalive: only one", N[1].nsent[4] == 1);
    teardown();

    /* Key material wiped at 540 s. */
    setup();
    establish();
    t_true("wipe: keys held", ts_wg_test_has_keys(N[0].d, N[1].pub) && ts_wg_test_has_keys(N[1].d, N[0].pub));
    run_until(539750);
    t_true("wipe: still held at 539.75 s",
           ts_wg_test_has_keys(N[0].d, N[1].pub) && ts_wg_test_has_keys(N[1].d, N[0].pub));
    run_until(540250);
    t_true("wipe: gone at 540 s",
           !ts_wg_test_has_keys(N[0].d, N[1].pub) && !ts_wg_test_has_keys(N[1].d, N[0].pub));
    /* A new handshake still works. */
    node_reset_counts(&N[1]);
    send_ip(0, 1, 10, 28);
    pump();
    t_true("wipe: new session works", N[1].ndeliv == 1);
    teardown();
}

static int deliver_cap(size_t i)
{
    int before = N[1].ndeliv;
    ts_wg_receive(N[1].d, N[0].pub, CAP[i], 64);
    return N[1].ndeliv - before;
}

static void test_wgdev_replay(void)
{
    size_t i, total = 8200, last, at8128 = 0, at8129 = 0;
    uint64_t c_last;
    int f8128 = 0, f8129 = 0;
    setup();
    establish();
    capture = 1;
    for (i = 0; i < total; i++) send_ip(0, 1, (uint8_t)i, 28);
    capture = 0;
    t_true("replay: captured", ncap == total);
    last = ncap - 1;
    c_last = ts_get_le64(CAP[last] + 8);
    for (i = 0; i < ncap; i++) {
        uint64_t c = ts_get_le64(CAP[i] + 8);
        if (c == c_last - TS_WG_REPLAY_BITS) { at8128 = i; f8128 = 1; }
        if (c == c_last - TS_WG_REPLAY_BITS - 1) { at8129 = i; f8129 = 1; }
    }
    t_true("replay: counters found", f8128 && f8129);
    t_true("replay: newest accepted", deliver_cap(last) == 1);
    t_true("replay: replayed newest dropped", deliver_cap(last) == 0);
    t_true("replay: at the window edge accepted", deliver_cap(at8128) == 1);
    t_true("replay: edge replay dropped", deliver_cap(at8128) == 0);
    t_true("replay: just behind the window dropped", deliver_cap(at8129) == 0);
    t_true("replay: out of order inside accepted (n-2)", deliver_cap(last - 2) == 1);
    t_true("replay: out of order inside accepted (n-3)", deliver_cap(last - 3) == 1);
    t_true("replay: out of order inside accepted (n-1)", deliver_cap(last - 1) == 1);
    t_true("replay: then replayed dropped", deliver_cap(last - 3) == 0);
    teardown();
}

static void test_wgdev_flood(void)
{
    uint8_t m[TS_WG_INIT_LEN], dpriv[32], eph[32], ts[12], ss[32];
    ts_wg_static dme, ame;
    ts_wg_hs hs;
    int i, sent_before;
    unsigned long dh;

    setup();
    t_true("flood: B knows C", ts_wg_set_peer(N[1].d, N[2].pub, N[2].ip) == 0);
    run_until(1000);
    memset(dpriv, 0x5a, 32);
    ts_wg_static_init(&dme, dpriv);
    ts_wg_static_init(&ame, N[0].priv);
    /* Valid initiations from an unknown key D, before any budget is spent:
     * dropped with no DH. */
    ts_wg_test_dh_count = 0;
    for (i = 0; i < 100; i++) {
        cb_random(&N[2], eph, 32);
        ts_wg_tai64n(ts, 1700000001 + i, 0);
        ts_x25519(ss, dpriv, N[1].pub);
        ts_wg_create_init(&hs, &dme, N[1].pub, ss, (uint32_t)i, eph, ts, NULL, m);
        ts_wg_receive(N[1].d, dme.pub, m, sizeof m);
    }
    t_true("flood: unknown key costs no DH", ts_wg_test_dh_count == 0);
    sent_before = N[1].nsent[2];
    for (i = 0; i < 1000; i++) {
        cb_random(&N[2], m, sizeof m);
        ts_put_le32(m, 1);
        if (i & 1) mac1_for(m, 116, N[1].pub);   /* half pass mac1 */
        ts_wg_receive(N[1].d, (i & 2) ? N[0].pub : N[2].pub, m, sizeof m);
    }
    for (i = 0; i < 100; i++) {
        /* D's valid initiations relayed as C: static mismatch. */
        cb_random(&N[2], eph, 32);
        ts_wg_tai64n(ts, 1700000001 + i, 0);
        ts_x25519(ss, dpriv, N[1].pub);
        ts_wg_create_init(&hs, &dme, N[1].pub, ss, (uint32_t)i, eph, ts, NULL, m);
        ts_wg_receive(N[1].d, N[2].pub, m, sizeof m);
    }
    dh = ts_wg_test_dh_count;
    printf("  flood: %lu DH operations\n", dh);
    t_true("flood: some DH reached (not vacuous)", dh > 0);
    t_true("flood: at most 20 DH in the second", dh <= 20);
    t_true("flood: no response", N[1].nsent[2] == sent_before);

    /* The next second: a real handshake completes. */
    run_until(2000);
    send_ip(0, 1, 0x77, 28);
    pump();
    t_true("flood: real handshake after", N[1].ndeliv == 1);

    /* Per-peer rules, with initiations made by hand from A's key. */
    run_until(10000);
    cb_random(&N[0], eph, 32);
    ts_x25519(ss, N[0].priv, N[1].pub);
    sent_before = N[1].nsent[2];
    ts_wg_tai64n(ts, 1800000000, 0);
    ts_wg_create_init(&hs, &ame, N[1].pub, ss, 1, eph, ts, NULL, m);
    ts_wg_receive(N[1].d, N[0].pub, m, sizeof m);
    t_true("hs rules: accepted", N[1].nsent[2] == sent_before + 1);
    ts_wg_tai64n(ts, 1800000001, 0);
    ts_wg_create_init(&hs, &ame, N[1].pub, ss, 2, eph, ts, NULL, m);
    ts_wg_receive(N[1].d, N[0].pub, m, sizeof m);
    t_true("hs rules: second within 20 ms dropped", N[1].nsent[2] == sent_before + 1);
    now_ms += 25;
    tick_all();
    ts_wg_receive(N[1].d, N[0].pub, m, sizeof m);
    t_true("hs rules: after 20 ms accepted", N[1].nsent[2] == sent_before + 2);
    now_ms += 25;
    tick_all();
    ts_wg_receive(N[1].d, N[0].pub, m, sizeof m);
    t_true("hs rules: same timestamp dropped", N[1].nsent[2] == sent_before + 2);
    ts_wg_tai64n(ts, 1799999999, 0);
    ts_wg_create_init(&hs, &ame, N[1].pub, ss, 3, eph, ts, NULL, m);
    ts_wg_receive(N[1].d, N[0].pub, m, sizeof m);
    t_true("hs rules: older timestamp dropped", N[1].nsent[2] == sent_before + 2);
    /* A valid initiation from D's static, relayed as A or as C: dropped
     * (the budget is not exhausted here, so this is the static check). */
    run_until(20000);
    q_head = q_len = 0;
    ts_wg_test_dh_count = 0;
    ts_wg_tai64n(ts, 1900000000, 0);
    ts_x25519(ss, dpriv, N[1].pub);
    ts_wg_create_init(&hs, &dme, N[1].pub, ss, 4, eph, ts, NULL, m);
    ts_wg_receive(N[1].d, N[0].pub, m, sizeof m);
    ts_wg_receive(N[1].d, N[2].pub, m, sizeof m);
    t_true("hs rules: static must be from", N[1].nsent[2] == sent_before + 2 && ts_wg_test_dh_count == 2);
    q_head = q_len = 0;
    teardown();

    /* Forged responses to a pending initiation (anyone can compute mac1). */
    setup();
    run_until(1000);
    N[1].drop_out = 1;           /* B's real response is held back */
    send_ip(0, 1, 0x78, 28);
    pump();
    t_true("flood resp: B responded", N[1].nsent[2] == 1);
    N[1].drop_out = 0;
    {
        uint8_t r[TS_WG_RESP_LEN];
        uint32_t idx = ts_get_le32(N[0].last_sent[1] + 4);
        ts_wg_test_dh_count = 0;
        for (i = 0; i < 100; i++) {
            cb_random(&N[2], r, sizeof r);
            ts_put_le32(r, 2);
            ts_put_le32(r + 8, idx ^ 1);
            mac1_for(r, 60, N[0].pub);
            ts_wg_receive(N[0].d, N[1].pub, r, sizeof r);
        }
        t_true("flood resp: wrong index costs no DH", ts_wg_test_dh_count == 0);
        for (i = 0; i < 100; i++) {
            cb_random(&N[2], r, sizeof r);
            ts_put_le32(r, 2);
            ts_put_le32(r + 8, idx);
            mac1_for(r, 60, N[0].pub);
            ts_wg_receive(N[0].d, N[1].pub, r, sizeof r);
        }
        dh = ts_wg_test_dh_count;
        t_true("flood resp: some DH reached", dh > 0);
        t_true("flood resp: at most 20 responses (40 DH) in the second", dh <= 40);
        t_true("flood resp: no session from forgeries", stats_session(0, 1) == 0);
        run_until(2000);
        ts_wg_receive(N[0].d, N[1].pub, N[1].last_sent[2], N[1].last_sent_n[2]);
        pump();
        t_true("flood resp: the real response still completes", N[1].ndeliv == 1 && N[1].deliv[0][24] == 0x78);
    }
    teardown();
}

static void test_wgdev_remove(void)
{
    uint8_t held[MSGMAX];
    size_t heldn;
    setup();
    establish();
    send_ip(0, 1, 1, 28);
    heldn = Q[q_head].n;
    memcpy(held, Q[q_head].m, heldn);
    q_head = q_len = 0;
    ts_wg_remove_peer(N[1].d, N[0].pub);
    ts_wg_receive(N[1].d, N[0].pub, held, heldn);
    t_true("remove: dropped after remove", N[1].ndeliv == 0);
    ts_wg_set_peer(N[1].d, N[0].pub, N[0].ip);
    t_true("remove: re-added has no keys", !ts_wg_test_has_keys(N[1].d, N[0].pub));
    ts_wg_receive(N[1].d, N[0].pub, held, heldn);
    t_true("remove: old message dropped after re-add", N[1].ndeliv == 0);
    t_true("remove: stats gone", stats_session(1, 0) == 0);
    teardown();

    /* Staged packets go with the peer. */
    setup();
    N[0].drop_out = 1;
    send_ip(0, 1, 0x31, 28);
    send_ip(0, 1, 0x32, 28);
    ts_wg_remove_peer(N[0].d, N[1].pub);
    run_until(30000);
    t_true("remove: no retries after remove", N[0].nsent[1] == 1);
    N[0].drop_out = 0;
    ts_wg_set_peer(N[0].d, N[1].pub, N[1].ip);
    send_ip(0, 1, 0x33, 28);
    pump();
    t_true("remove: only the new packet", N[1].ndeliv == 1 && N[1].deliv[0][24] == 0x33);
    ts_wg_remove_peer(N[0].d, N[1].pub);
    ts_wg_remove_peer(N[0].d, N[1].pub);   /* twice: no-op */
    t_true("remove: unknown stats", ts_wg_peer_stats(N[0].d, N[1].pub, NULL) == -1);
    teardown();
}

static void make_cookie_reply(uint8_t out[TS_WG_COOKIE_LEN], uint32_t receiver, const uint8_t mac1[16],
                              const uint8_t cookie[16])
{
    uint8_t key[32];
    ts_blake2s_ctx h;
    ts_blake2s_init(&h, 32, NULL, 0);
    ts_blake2s_update(&h, "cookie--", 8);
    ts_blake2s_update(&h, N[1].pub, 32);
    ts_blake2s_final(&h, key);
    ts_put_le32(out, 3);
    ts_put_le32(out + 4, receiver);
    memset(out + 8, 0x24, 24);
    ts_xaead_seal(out + 32, key, out + 8, mac1, 16, cookie, 16);
}

static void test_wgdev_cookie(void)
{
    uint8_t init1[TS_WG_INIT_LEN], reply[TS_WG_COOKIE_LEN], cookie[16], mac2[16];
    static const uint8_t zero[16];
    ts_blake2s_ctx c;

    setup();
    N[0].drop_out = 1;
    send_ip(0, 1, 1, 28);
    memcpy(init1, N[0].last_sent[1], sizeof init1);
    t_true("cookie: first initiation has zero mac2", memcmp(init1 + 132, zero, 16) == 0);
    memset(cookie, 0xc5, 16);

    /* Wrong receiver index, wrong sender: ignored. */
    make_cookie_reply(reply, ts_get_le32(init1 + 4) ^ 1, init1 + 116, cookie);
    ts_wg_receive(N[0].d, N[1].pub, reply, sizeof reply);
    make_cookie_reply(reply, ts_get_le32(init1 + 4), init1 + 116, cookie);
    ts_wg_receive(N[0].d, N[2].pub, reply, sizeof reply);
    run_until(5400);
    t_true("cookie: retry sent", N[0].nsent[1] == 2);
    t_true("cookie: bad replies ignored", memcmp(N[0].last_sent[1] + 132, zero, 16) == 0);

    memcpy(init1, N[0].last_sent[1], sizeof init1);
    make_cookie_reply(reply, ts_get_le32(init1 + 4), init1 + 116, cookie);
    ts_wg_receive(N[0].d, N[1].pub, reply, sizeof reply);
    run_until(11000);
    t_true("cookie: next retry sent", N[0].nsent[1] == 3);
    ts_blake2s_init(&c, 16, cookie, 16);
    ts_blake2s_update(&c, N[0].last_sent[1], 132);
    ts_blake2s_final(&c, mac2);
    t_true("cookie: mac2 non-zero and correct",
           memcmp(N[0].last_sent[1] + 132, zero, 16) != 0 && memcmp(N[0].last_sent[1] + 132, mac2, 16) == 0);
    /* B (no load handling) still accepts it. */
    N[0].drop_out = 0;
    run_until(17000);
    t_true("cookie: handshake completes", N[1].ndeliv == 1);
    teardown();
}

/* Messages from unknown peers, short and odd messages, set_peer limits. */
static void test_wgdev_misc(void)
{
    uint8_t k[32], m[200];
    int i, ok = 1;
    setup();
    memset(m, 0, sizeof m);
    ts_put_le32(m, 4);
    for (i = 0; i < 200; i++) ts_wg_receive(N[1].d, N[0].pub, m, (size_t)i);
    for (i = 1; i <= 4; i++) {
        ts_put_le32(m, (uint32_t)i);
        ts_wg_receive(N[1].d, N[2].pub, m, sizeof m);
    }
    ts_wg_receive(N[1].d, N[0].pub, NULL, 0);
    t_true("misc: nothing sent or delivered", N[1].nsent[2] == 0 && N[1].ndeliv == 0);
    /* Oversize sends dropped. */
    {
        static uint8_t big[TS_WG_MAX_PACKET + 1];
        mk_ip(big, 28, N[0].ip, N[1].ip, 1);
        ts_wg_send_packet(N[0].d, N[1].pub, big, sizeof big);
        t_true("misc: oversize dropped", N[0].nsent[1] == 0);
        ts_wg_send_packet(N[0].d, N[2].pub, big, 28);
        t_true("misc: unknown peer send dropped", N[0].nsent[1] == 0);
    }
    /* Low-order key refused. */
    memset(k, 0, 32);
    t_true("misc: zero key refused", ts_wg_set_peer(N[0].d, k, 1) == -1);
    /* Fill to TS_MAX_PEERS (256): A has 1 peer. */
    for (i = 0; i < 255; i++) {
        memset(k, 0, 32);
        k[0] = 9;
        k[1] = (uint8_t)i;
        k[2] = 1;
        if (ts_wg_set_peer(N[0].d, k, (uint32_t)i) != 0) ok = 0;
    }
    t_true("misc: 256 peers", ok);
    k[1] = 0;
    k[2] = 2;
    t_true("misc: 257th refused", ts_wg_set_peer(N[0].d, k, 1) == -1);
    t_true("misc: update existing ok", ts_wg_set_peer(N[0].d, N[1].pub, N[1].ip) == 0);
    teardown();
}

/* Staging keeps the newest TS_WG_STAGED_MAX packets. */
static void test_wgdev_staging(void)
{
    int i;
    setup();
    N[0].drop_out = 1;
    for (i = 0; i < 20; i++) send_ip(0, 1, (uint8_t)(0x40 + i), 28);
    N[0].drop_out = 0;
    run_until(5400);   /* the retry gets through */
    t_true("staging: newest 16 delivered", N[1].ndeliv == TS_WG_STAGED_MAX);
    t_true("staging: oldest dropped", N[1].deliv[0][24] == 0x44 && N[1].deliv[15][24] == 0x53);
    teardown();
}

void test_wg_device(void)
{
    test_wgdev_vector();
    test_wgdev_ping();
    test_wgdev_allowedips();
    test_wgdev_timers();
    test_wgdev_replay();
    test_wgdev_flood();
    test_wgdev_remove();
    test_wgdev_cookie();
    test_wgdev_misc();
    test_wgdev_staging();
}
