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
 * order once it is. Relay packets starting with the disco magic are dropped.
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
typedef struct {
    /* Open a stream to node (TCP to node->ipv4:port, then TLS for node->host). Later
     * ts_dp_conn_up / ts_dp_conn_down report on slot. 0 started, -1 failed now. */
    int (*dial)(void *user, int slot, const ts_derp_node *node);
    void (*conn_send)(void *user, int slot, const uint8_t *p, size_t n);
    void (*conn_close)(void *user, int slot);
    void (*tun_write)(void *user, const uint8_t *ip, size_t n);
    int (*random)(void *user, uint8_t *out, size_t n);
    int64_t (*wall)(void *user, uint32_t *nsec);
} ts_dp_io;
typedef struct ts_dp ts_dp;
ts_dp *ts_dp_new(const ts_dp_io *io, void *user);
void ts_dp_free(ts_dp *dp);
/* Start with our keys and address (wipes any earlier run). */
int ts_dp_start(ts_dp *dp, const uint8_t node_priv[32], const uint8_t disco_pub[32], uint32_t self_ip);
void ts_dp_stop(ts_dp *dp);                       /* closes every connection, wipes sessions */
int ts_dp_running(const ts_dp *dp);
/* Copy what the data plane needs from the map: peers (node key, ipv4, home_derp,
 * wireguard_only, jailed, expired, online), and the DERP map and filters when
 * their gens changed. Never keeps a pointer into m. */
void ts_dp_set_netmap(ts_dp *dp, const ts_netmap *m);
void ts_dp_set_home(ts_dp *dp, int region);
void ts_dp_from_tun(ts_dp *dp, const uint8_t *ip, size_t n);
void ts_dp_conn_up(ts_dp *dp, int slot);
void ts_dp_conn_recv(ts_dp *dp, int slot, const uint8_t *p, size_t n);
void ts_dp_conn_down(ts_dp *dp, int slot, const char *why);
void ts_dp_tick(ts_dp *dp, int64_t now_ms);
/* Pick a home region from probe latencies (ms, -1 unknown), per Appendix B, B4. */
int ts_dp_pick_home(const ts_derp_region *r, size_t n, const int *lat_ms, int current,
                    uint32_t rand32);
/* Status: home region and its connection state, filter state, per-peer stats. */
typedef struct {
    int home; int home_up; const char *filter;    /* "none", "ok", "too large", "invalid" */
    char problem[200];
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
 * - ts_dp_pick_home returns a region ID, or 0 when n is 0 (and current is 0).
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
} ts_dp_test_counts;
const ts_dp_test_counts *ts_dp_test_counters(const ts_dp *dp);
/* Called with every packet WireGuard delivers, before any check. */
extern void (*ts_dp_test_on_deliver)(void *user, const uint8_t *ip, size_t n);
/* 1 if the device holds key material for that peer key. */
int ts_dp_test_has_keys(const ts_dp *dp, const uint8_t key[32]);
#endif

#endif
