#ifndef TS_DATA_DATAPLANE_H
#define TS_DATA_DATAPLANE_H

#include <stddef.h>
#include <stdint.h>

#include "../control/netmap.h"
#include "../derp/derp.h"
#include "../filter/filter.h"
#include "../wg/device.h"

/* The data plane: the packet filter, the WireGuard device and up to
 * TS_DP_MAX_CONNS DERP relay connections, joined. Sans-I/O and
 * single-threaded: the caller runs TCP and TLS for each connection slot and
 * the tun device, and calls ts_dp_tick at least every 250 ms.
 *
 * Fail closed (the project's anti-goals): an IP packet reaches tun_write only
 * if it came over a relay from a source key that is a configured peer of the
 * current map (not expired, not jailed, not WireGuard-only, with an IPv4
 * address and a node key), WireGuard decrypted it under that key, its inner
 * IPv4 source is that peer's address, it is not TSMP (protocol 99), and the
 * compiled packet filter accepts it. Before the first filter, and after a
 * filter that is too large or invalid, every inbound packet is dropped.
 *
 * Peer expiry (upstream ipnlocal/expiry.go): a peer is left out exactly as
 * an Expired one is (removed from the WireGuard device, its sessions wiped)
 * when its KeyExpiry is set and not after control's current time, which is
 * the last ControlTime given by ts_dp_set_control_time plus the monotonic
 * time since it arrived. The Mac's own clock is never used for this: with no
 * ControlTime yet, or one before 2023-01-10 (upstream's sanity epoch), only
 * control's Expired flag counts. Checked on every ts_dp_set_netmap, on
 * ts_dp_set_control_time and every TS_DP_EXPIRY_CHECK_MS in ts_dp_tick.
 *
 * Outbound: a tun packet that parses as IPv4 and is addressed to a configured
 * peer is recorded in the flow table (UDP) and handed to WireGuard; anything
 * else is dropped.
 *
 * Relays (upstream magicsock, derp.go): a message for a peer goes on the slot
 * for the peer's home region if one exists, else the slot we last received
 * that peer on, else a new slot dialed to the peer's home region (a home
 * region of 0 or one missing from the DERP map: dropped). With every slot in
 * use, the least recently written non-home slot is closed first. Until the
 * relay is ready, whole SendPacket requests wait in the slot's queue
 * (TS_DP_QUEUE_PER_CONN; when full, new ones are dropped) and are sent in
 * order once it is.
 *
 * Disco over relays (upstream disco and magicsock, relay paths only): a relay
 * packet of at least 38 bytes starting with the disco magic never reaches
 * WireGuard. It is accepted only if the frame's source is a configured peer
 * (as above) whose netmap DiscoKey is set and equals the packet's sender disco
 * key (stricter than upstream, which takes any known disco key), and the box
 * opens; anything else is dropped and counted (disco_bad). A packet that
 * fails the source and key checks costs no X25519. One that passes them
 * (from a real peer, under its disco key) but whose box does not open still
 * costs the one X25519 that computes that peer's box key, if it is not
 * cached yet, taken from the budget below.
 * The box key for a peer is computed once (one X25519, taken from the
 * WireGuard device's handshake budget, TS_WG_HS_PER_SEC; over budget the
 * packet is dropped and counted) and cached until the peer's disco key
 * changes, the peer leaves the device, or the data plane stops. Then:
 * - ping: answered with a pong sealed to that peer (Src ::ffff:127.3.3.40,
 *   port = the region ID it arrived on) on the same relay connection it
 *   arrived on, at most TS_DP_PONGS_PER_PEER per second per peer and
 *   TS_DP_PONGS_PER_SEC in all (excess dropped, counted pongs_limited);
 * - pong: delivered through io->ping_result if its TxID is an outstanding
 *   ping (ts_dp_ping) to that same peer that has not timed out; the first
 *   match ends the ping, so later copies are ignored;
 * - any other type (CallMeMaybe, the relay types): ignored, counted.
 * Our own pings go to the peer's home region (dialed if needed, as data).
 *
 * Contracts for the caller:
 * - Time is the now_ms of the last ts_dp_tick, as in the WireGuard device.
 * - Order: ts_dp_start, then ts_dp_set_netmap. ts_dp_start wipes everything
 *   of an earlier run (sessions, peers, filter, flows, connections);
 *   ts_dp_set_netmap and the traffic calls do nothing while stopped.
 * - Call ts_dp_tick once right after ts_dp_start (before any other call), so
 *   new connections and timers are stamped with the current time.
 * - ts_dp_set_netmap compares derp_gen and filter_gen with the last map it
 *   saw, so it must keep getting the same ts_netmap; after re-initialising
 *   the netmap, call ts_dp_start again.
 * - io callbacks must not call back into the data plane (report conn_up,
 *   conn_recv and conn_down later, from the event loop). ts_dp_new copies io.
 * - dial: the caller connects TCP to node->ipv4:port (0 means 443) and runs
 *   TLS with ServerName node->host, with its own timeouts; it reports
 *   ts_dp_conn_up when TLS is established, and ts_dp_conn_recv with the
 *   plaintext. conn_send carries bytes for that TLS stream, each call one
 *   whole frame (or the upgrade request). After conn_close, or after the
 *   caller reported ts_dp_conn_down, the slot is not used until a new dial.
 * - Events for a slot that is not dialed (or out of range) are ignored. */

#define TS_DP_MAX_CONNS 8
#define TS_DP_IDLE_CLOSE_MS 60000          /* non-home connection idle (last written) */
#define TS_DP_QUEUE_PER_CONN 32            /* packets queued while a relay connects */
#define TS_DP_REDIAL_MIN_MS 1000
#define TS_DP_REDIAL_MAX_MS 30000
#define TS_DP_EXPIRY_CHECK_MS 5000
#define TS_DP_MAX_PINGS 16                 /* outstanding ts_dp_ping calls */
#define TS_DP_PONGS_PER_PEER 10            /* pongs per second to one peer */
#define TS_DP_PONGS_PER_SEC 50             /* pongs per second in all */
/* ping_result status. */
#define TS_DP_PONG 0
#define TS_DP_PING_TIMEOUT 1
#define TS_DP_PING_STOPPED 2               /* the data plane stopped first */
/* ts_dp_ping errors. */
#define TS_DP_PING_UNKNOWN (-1)            /* no peer with that address in the device */
#define TS_DP_PING_NO_DISCO (-2)           /* the peer has no disco key */
#define TS_DP_PING_EXPIRED (-3)            /* the peer's node key has expired */
#define TS_DP_PING_NO_HOME (-4)            /* the peer's home region is 0, not in the map, or has no node */
#define TS_DP_PING_BUSY (-5)               /* TS_DP_MAX_PINGS outstanding */
#define TS_DP_PING_DOWN (-6)               /* the data plane is not running */
#define TS_DP_PING_FAILED (-7)             /* no disco key of our own, a key that cannot be used, no randomness, no slot */
typedef struct {
    /* Open a stream to node (TCP to node->ipv4:port, then TLS for node->host). Later
     * ts_dp_conn_up / ts_dp_conn_down report on slot. 0 started, -1 failed now. */
    int (*dial)(void *user, int slot, const ts_derp_node *node);
    /* 0 queued, or -1: no room (the frame is not sent). A SendPacket that
     * finds no room is dropped and counted (relay_full); any other frame
     * (the upgrade request, the handshake, keepalives) fails the connection. */
    int (*conn_send)(void *user, int slot, const uint8_t *p, size_t n);
    void (*conn_close)(void *user, int slot);
    void (*tun_write)(void *user, const uint8_t *ip, size_t n);
    int (*random)(void *user, uint8_t *out, size_t n);
    int64_t (*wall)(void *user, uint32_t *nsec);
    /* The end of a ts_dp_ping (may be NULL): status TS_DP_PONG with the
     * round trip in microseconds (at the data plane's clock resolution), or
     * TS_DP_PING_TIMEOUT or TS_DP_PING_STOPPED with latency 0. region_id is
     * the region the ping was sent to. Called from inside ts_dp_conn_recv,
     * ts_dp_tick, ts_dp_stop, ts_dp_start and ts_dp_free: must not call back
     * into the data plane. */
    void (*ping_result)(void *user, uint64_t cookie, int status, uint32_t latency_us, int region_id);
} ts_dp_io;
typedef struct ts_dp ts_dp;
ts_dp *ts_dp_new(const ts_dp_io *io, void *user);
void ts_dp_free(ts_dp *dp);
/* Start with our keys and address (wipes any earlier run). An all-zero
 * disco_priv means no disco key: no disco advert, no pongs, no pings. */
int ts_dp_start(ts_dp *dp, const uint8_t node_priv[32], const uint8_t disco_priv[32], uint32_t self_ip);
/* Closes every connection, wipes sessions, keys and cached disco keys, and
 * ends every outstanding ping with TS_DP_PING_STOPPED. */
void ts_dp_stop(ts_dp *dp);
int ts_dp_running(const ts_dp *dp);
/* Copy what the data plane needs from the map: peers (node key, disco key,
 * ipv4, home_derp, wireguard_only, jailed, expired, online), and the DERP map and filters when
 * their gens changed. Never keeps a pointer into m. */
void ts_dp_set_netmap(ts_dp *dp, const ts_netmap *m);
void ts_dp_set_home(ts_dp *dp, int region);
/* Control's clock: unix_sec (as ts_netmap.control_time) was control's time
 * when the message carrying it arrived at now_ms (the clock of ts_dp_tick).
 * Kept across ts_dp_start and ts_dp_stop. */
void ts_dp_set_control_time(ts_dp *dp, int64_t unix_sec, int64_t now_ms);
void ts_dp_from_tun(ts_dp *dp, const uint8_t *ip, size_t n);
void ts_dp_conn_up(ts_dp *dp, int slot);
void ts_dp_conn_recv(ts_dp *dp, int slot, const uint8_t *p, size_t n);
void ts_dp_conn_down(ts_dp *dp, int slot, const char *why);
void ts_dp_tick(ts_dp *dp, int64_t now_ms);
/* After a network change or a wake (the old streams are presumed dead):
 * every relay slot that is dialing or up is closed through io->conn_close,
 * and it and every slot waiting in backoff are dialed again at the next
 * ts_dp_tick, with no delay and the backoff back at TS_DP_REDIAL_MIN_MS. A
 * non-home slot is still closed TS_DP_IDLE_CLOSE_MS after its last write.
 * With reset_sessions (a real sleep): WireGuard sessions are dropped
 * (ts_wg_reset_sessions) and so are the WireGuard messages queued on every
 * slot (stale ones would reach the peer ahead of the new handshake); queued
 * disco frames stay. Without it (a network change, a clock stepped back)
 * sessions and the whole queue are kept. Outstanding pings are left to
 * finish or time out. Nothing if not running. */
void ts_dp_rebind(ts_dp *dp, int64_t now_ms, int reset_sessions);
/* Send a disco ping to the configured peer with tailnet address peer_ip, on
 * its home region. 0, or a TS_DP_PING_* error. On 0, io->ping_result reports
 * cookie exactly once: a pong, a timeout timeout_ms after now_ms (seen by
 * ts_dp_tick), or a stop. now_ms is the current time on the clock of
 * ts_dp_tick. The peer's box key, if not cached yet, is computed here without
 * the DH budget: this is asked for locally, and costs one X25519 per peer
 * disco key. */
int ts_dp_ping(ts_dp *dp, uint32_t peer_ip, uint32_t timeout_ms, uint64_t cookie, int64_t now_ms);
/* Forget the outstanding ping with cookie: it is never reported and its
 * place is free at once (a pong for it is then ignored). 0, or -1 if no
 * outstanding ping has that cookie. */
int ts_dp_ping_cancel(ts_dp *dp, uint64_t cookie);
/* The earliest deadline of an outstanding ping (the clock of ts_dp_tick),
 * or -1 if there is none: the caller wakes then, so a timeout is reported
 * on time rather than at its next regular tick. */
int64_t ts_dp_ping_deadline(const ts_dp *dp);
/* Pick a home region from probe latencies (ms, -1 unknown), per Appendix B, B4. */
int ts_dp_pick_home(const ts_derp_region *r, size_t n, const int *lat_ms, int current,
                    uint32_t rand32);
/* Status: home region and its connection state, filter state, per-peer stats. */
typedef struct {
    int home; int home_up; const char *filter;    /* "none", "ok", "too large", "invalid" */
    char problem[200];
    unsigned long filtered;      /* packets from peers the filter dropped (since ts_dp_new) */
    unsigned long relay_full;    /* packets dropped: a relay connection's output was full */
    /* Disco, since ts_dp_new. */
    unsigned long disco_in;      /* relay packets with the disco magic */
    unsigned long disco_bad;     /* of those, dropped: not from a peer's disco key, over the DH budget, box or parse failed */
    unsigned long pongs_sent, pongs_limited, pings_sent;
    unsigned long pongs_in;      /* authentic pongs received (matched or not) */
} ts_dp_status;
void ts_dp_get_status(const ts_dp *dp, ts_dp_status *st);
int ts_dp_peer_status(const ts_dp *dp, uint32_t ipv4, ts_wg_stats *st, int *region);

/* Details of the calls above:
 * - ts_dp_new: NULL if out of memory (it holds the connection slots, their
 *   queues and a copy of the DERP map: about 1.7 MiB).
 * - ts_dp_start: 0, or -1 if out of memory (the data plane is then stopped).
 * - ts_dp_set_home: region 0 means none. The home connection is dialed at
 *   once and kept open (redialed when it goes down); the old home is told
 *   NotePreferred 0 and becomes an ordinary connection.
 * - ts_dp_pick_home returns a region ID. With no usable latency it keeps
 *   current only if current is in r with a node, else picks among the regions
 *   with a node (rand32), else returns 0.
 * - A home region missing from the map, or with no usable node, is not
 *   dialed; ts_dp_get_status's problem then says so.
 * - ts_dp_get_status: problem is "" or a short reason, never filter content.
 * - ts_dp_peer_status: 0, or -1 if no configured peer has that ipv4. region is
 *   the region last used to send to the peer, or -1. */

#ifdef TS_TEST_HOOKS
/* Why inbound relay packets and delivered IP packets were dropped. */
typedef struct {
    unsigned long disco;       /* disco magic over a relay */
    unsigned long unknown;     /* source key not a configured peer */
    unsigned long wg_in;       /* messages handed to ts_wg_receive */
    unsigned long jailed;      /* deliver: peer jailed or gone */
    unsigned long spoof;       /* deliver: inner source not the peer's address */
    unsigned long tsmp;        /* deliver: protocol 99 */
    unsigned long filtered;    /* deliver: the filter said no */
    unsigned long queue_full;  /* SendPacket dropped: slot queue full */
    unsigned long disco_dh;    /* disco box keys computed (X25519) */
    unsigned long disco_budget;/* disco packets dropped over the DH budget */
    unsigned long disco_other; /* disco messages of other types, ignored */
} ts_dp_test_counts;
const ts_dp_test_counts *ts_dp_test_counters(const ts_dp *dp);
/* Called with every packet WireGuard delivers, before any check. */
extern void (*ts_dp_test_on_deliver)(void *user, const uint8_t *ip, size_t n);
/* 1 if the device holds key material for that peer key. */
int ts_dp_test_has_keys(const ts_dp *dp, const uint8_t key[32]);
/* 1 if the data plane holds a non-zero disco private key. */
int ts_dp_test_has_disco_priv(const ts_dp *dp);
/* How many peers have a cached disco box key. */
int ts_dp_test_disco_keys(const ts_dp *dp);
#endif

#endif
