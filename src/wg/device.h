#ifndef TS_WG_DEVICE_H
#define TS_WG_DEVICE_H

#include <stddef.h>
#include <stdint.h>

/* The WireGuard device: peers, keypairs (current, previous, next), timers,
 * the replay window, transport encryption, staging, handshake rate limits and
 * the priority message, after tailscale/wireguard-go (device/timers.go,
 * send.go, receive.go, noise-protocol.go). Sans-I/O and single-threaded:
 * messages leave through io->send, IP packets through io->deliver, and
 * ts_wg_tick (at least every 250 ms) drives every timer. The time used by
 * every timer and rate limit is the now_ms of the last tick.
 *
 * Callbacks must not call back into the device.
 *
 * Inbound rules (fail closed):
 * - a message whose `from` is not a configured peer is dropped;
 * - every index (transport, response, cookie reply) must belong to `from`;
 * - an initiation must carry `from` as its static key, a TAI64N timestamp
 *   newer than the last accepted one, and come at least 20 ms after the last
 *   accepted initiation from that peer (checked before any DH);
 * - at most TS_WG_HS_PER_SEC initiations or responses that pass mac1 reach a
 *   Diffie-Hellman operation in any second (sliding window, all peers);
 * - a decrypted packet is delivered only if ts_pkt_parse accepts it and its
 *   IPv4 source is the peer's ipv4. It is trimmed to the IPv4 total length.
 *   Keepalives are never delivered.
 *
 * Differences from the plan, after upstream: a handshake that gets no
 * response is retried 19 times (20 initiations, ~100 s) before the staged
 * packets are dropped, as expiredRetransmitHandshake does. */

#define TS_WG_STAGED_MAX 16
#define TS_WG_HS_PER_SEC 20
#define TS_WG_REPLAY_BITS 8128
/* Largest IP packet ts_wg_send_packet accepts (and the staging slot size).
 * Received transport messages may be up to 65536 bytes. */
#define TS_WG_MAX_PACKET 1500
/* Largest priority packet sent (upstream MaxPriorityMessageContentSize). */
#define TS_WG_PRIORITY_MAX 512

typedef struct {
    void (*send)(void *user, const uint8_t peer[32], const uint8_t *msg, size_t n);
    void (*deliver)(void *user, const uint8_t peer[32], const uint8_t *ip, size_t n);
    int (*random)(void *user, uint8_t *out, size_t n);
    int64_t (*wall)(void *user, uint32_t *nsec);            /* Unix seconds, for TAI64N */
    size_t (*priority)(void *user, const uint8_t peer[32], uint8_t *out, size_t cap);
} ts_wg_io;
typedef struct {
    uint64_t rx_packets, tx_packets, rx_bytes, tx_bytes;
    int64_t last_handshake_ms;   /* -1 never */
    int have_session;
} ts_wg_stats;
typedef struct ts_wg_dev ts_wg_dev;
/* io->random returns 0 on success; io->priority may be NULL. NULL if out of
 * memory. */
ts_wg_dev *ts_wg_new(const uint8_t node_priv[32], const ts_wg_io *io, void *user);
void ts_wg_free(ts_wg_dev *d);                  /* wipes everything */
/* ipv4 is the peer's tailnet address in host byte order (as ts_pkt.src).
 * -1: TS_MAX_PEERS peers already, out of memory, or a low-order key. Updating
 * a peer keeps its sessions. */
int ts_wg_set_peer(ts_wg_dev *d, const uint8_t key[32], uint32_t ipv4);   /* add/update; 0/-1 (full) */
void ts_wg_remove_peer(ts_wg_dev *d, const uint8_t key[32]);
void ts_wg_send_packet(ts_wg_dev *d, const uint8_t key[32], const uint8_t *ip, size_t n);
void ts_wg_receive(ts_wg_dev *d, const uint8_t from[32], const uint8_t *msg, size_t n);
void ts_wg_tick(ts_wg_dev *d, int64_t now_ms);  /* call at least every 250 ms */
/* 0, or -1 for an unknown peer. rx/tx count the IP packets delivered or sent
 * (priority packets included; keepalives and handshakes not) and their IP
 * bytes. */
int ts_wg_peer_stats(const ts_wg_dev *d, const uint8_t key[32], ts_wg_stats *out);
/* After a network change or a wake: wipe every peer's keypairs and any
 * handshake in progress (with its cookie and staged packets), and forget
 * queued handshake retries and timers. Peers, their addresses, statistics
 * and the replay protection for received initiations (newest TAI64N) stay.
 * The next packet to a peer starts a new handshake at once (the 5 s limit
 * between initiations starts over). */
void ts_wg_reset_sessions(ts_wg_dev *d);
/* Take one Diffie-Hellman operation from the handshake budget (at most
 * TS_WG_HS_PER_SEC in any second, shared with received handshakes) for work
 * outside the device (disco box keys). 1 taken, 0 over budget. */
int ts_wg_dh_allow(ts_wg_dev *d);

/* The transport framing the device uses: type 4, receiver, LE counter, then
 * the ChaCha20-Poly1305 seal of pt padded with zeros to a multiple of 16.
 * out holds TS_WG_TRANSPORT_HDR + padded + 16 bytes; returns that length. */
size_t ts_wg_transport_seal(uint8_t *out, const uint8_t key[32], uint32_t receiver,
                            uint64_t counter, const uint8_t *pt, size_t n);
/* Opens msg[0..n) (n >= 32) with key into out (n - 32 bytes). Returns the
 * plaintext length, or -1. */
long ts_wg_transport_open(uint8_t *out, const uint8_t key[32], const uint8_t *msg, size_t n);

#ifdef TS_TEST_HOOKS
/* Diffie-Hellman operations started by received handshake messages: 1 per
 * initiation opened, 2 per response created or consumed. */
extern unsigned long ts_wg_test_dh_count;
/* 1 if the peer holds any key material (keypair or handshake state). */
int ts_wg_test_has_keys(const ts_wg_dev *d, const uint8_t key[32]);
/* The peer's keypairs in order current, previous, next: live[i] is 1 for a
 * keypair in use and idx[i] its local (receiver) index, 0 otherwise. 0, or -1
 * for an unknown peer. */
int ts_wg_test_keypairs(const ts_wg_dev *d, const uint8_t key[32], uint32_t idx[3], int live[3]);
#endif

#endif
