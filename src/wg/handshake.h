#ifndef TS_WG_HANDSHAKE_H
#define TS_WG_HANDSHAKE_H

#include <stdint.h>

/* The classic WireGuard handshake (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
 * with an all-zero preshared key, as messages only: no I/O, no clock, no
 * randomness (callers pass ephemerals, indices and timestamps).
 *
 * Message layouts (fields little-endian):
 *   initiation 148: type 1 | sender 4 | ephemeral 8 | static 40 | timestamp 88
 *                   | mac1 116 | mac2 132
 *   response    92: type 2 | sender 4 | receiver 8 | ephemeral 12 | empty 44
 *                   | mac1 60 | mac2 76
 *   cookie      64: type 3 | receiver 4 | nonce 8 | cookie 32
 *   transport  16+: type 4 | receiver 4 | counter 8 | data 16
 * The type is a 32-bit little-endian word. Received handshake messages may
 * carry tailscale/wireguard-go's "retry" hint in bit 31 (upstream masks it
 * on parse); it is ignored here. Sent messages never set it.
 *
 * Keys: mac1 of a message is keyed by BLAKE2s("mac1----" || the RECEIVER's
 * static public key), so ts_wg_static.mac1_key checks messages sent to us,
 * and messages we send are keyed by the peer's public key (computed inside).
 * A cookie reply is sealed with BLAKE2s("cookie--" || its SENDER's static
 * public key); ts_wg_static.cookie_key would seal replies we send, which we
 * never do (no UDP), and ts_wg_cookie_open derives the peer's key itself. */

#define TS_WG_INIT_LEN 148
#define TS_WG_RESP_LEN 92
#define TS_WG_COOKIE_LEN 64
#define TS_WG_TRANSPORT_HDR 16

typedef struct { uint8_t priv[32], pub[32], mac1_key[32], cookie_key[32]; } ts_wg_static;

typedef struct {
    uint8_t ck[32];            /* chaining key */
    uint8_t h[32];             /* handshake hash */
    uint8_t eph_priv[32];      /* initiator: our ephemeral, until the response */
    uint8_t remote_eph[32];    /* responder: the initiator's ephemeral */
    uint8_t remote_static[32]; /* the peer's static public key */
    uint8_t enc_ts[28];        /* responder: encrypted timestamp, until finish */
    uint32_t local_index;
    uint32_t remote_index;
    int state;                 /* TS_WG_HS_* in handshake.c; 0 = empty */
} ts_wg_hs;

/* Derives pub, mac1_key and cookie_key from priv. */
void ts_wg_static_init(ts_wg_static *me, const uint8_t priv[32]);

/* TAI64N: 8-byte BE (0x400000000000000a + unix_sec), then 4-byte BE nsec
 * with the low 24 bits cleared (as wireguard-go's whitener). */
void ts_wg_tai64n(uint8_t out[12], int64_t unix_sec, uint32_t nsec);

/* Initiator. ss = X25519(me->priv, peer_pub), computed by the caller. mac1 is
 * keyed by peer_pub; mac2 by cookie16 if not NULL, else zero. Returns 0, or
 * -1 (low-order peer key or all-zero ss: out and hs are then zeroed). */
int ts_wg_create_init(ts_wg_hs *hs, const ts_wg_static *me, const uint8_t peer_pub[32],
                      const uint8_t ss[32], uint32_t sender_index, const uint8_t eph_priv[32],
                      const uint8_t tai64n[12], const uint8_t *cookie16, uint8_t out[TS_WG_INIT_LEN]);

/* Responder, in two steps so unknown senders cost one DH:
 * 1) type and mac1 (keyed by me->mac1_key) before any DH, then
 *    DH(me->priv, e_i) and decrypt the initiator's static -> peer_pub.
 *    mac2 is not checked (responders are never under load). Returns 0 or -1
 *    (hs is then wiped). */
int ts_wg_init_open_static(ts_wg_hs *hs, const ts_wg_static *me, const uint8_t in[TS_WG_INIT_LEN],
                           uint8_t peer_pub[32]);
/* 2) with that peer's precomputed ss = DH(s_r, s_i): decrypt the timestamp.
 *    Replay and flood checks on the timestamp are the caller's. Returns 0 or
 *    -1 (hs is then wiped). */
int ts_wg_init_finish(ts_wg_hs *hs, const uint8_t ss[32], uint8_t tai64n_out[12], uint32_t *sender_index);

/* Responder: after ts_wg_init_finish. mac1 is keyed by the initiator's
 * static public key. Returns 0 or -1 (wrong state, low-order key: hs wiped,
 * out zeroed). */
int ts_wg_create_resp(ts_wg_hs *hs, uint32_t sender_index, const uint8_t eph_priv[32],
                      const uint8_t *cookie16, uint8_t out[TS_WG_RESP_LEN]);

/* Initiator: checks the type, mac1 (keyed by me->mac1_key) and that the
 * receiver is our sender index, before any DH. On success *sender_index is
 * the responder's index. On failure returns -1 and hs is left unchanged, so
 * a forged response does not spoil the pending handshake. */
int ts_wg_consume_resp(ts_wg_hs *hs, const ts_wg_static *me,
                       const uint8_t in[TS_WG_RESP_LEN], uint32_t *sender_index);

/* Transport keys; wipes the handshake state. The initiator sends with the
 * first HKDF output, the responder with the second. If hs has not completed
 * (response created or consumed), send and recv are zeroed. */
void ts_wg_derive(ts_wg_hs *hs, int initiator, uint8_t send[32], uint8_t recv[32]);

/* A cookie reply addressed to us: decrypts the 16-byte cookie with
 * BLAKE2s("cookie--" || peer_pub) and the last mac1 we sent to that peer as
 * associated data. The receiver index is the caller's to check. 0 or -1
 * (cookie zeroed). */
int ts_wg_cookie_open(uint8_t cookie[16], const uint8_t peer_pub[32], const uint8_t last_mac1[16],
                      const uint8_t in[TS_WG_COOKIE_LEN]);

#endif
