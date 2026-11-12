#ifndef TS_DISCO_DISCO_H
#define TS_DISCO_DISCO_H

#include <stddef.h>
#include <stdint.h>

/* Tailscale disco messages, sans I/O (upstream disco/disco.go and
 * types/key/disco.go at tailscale@9476be9).
 *
 * Packet: magic(6) | sender disco public key(32) | nonce(24) | box, where box
 * is NaCl crypto_box (tag first) between the two disco keys. Plaintext:
 * type(1) | version(1) | payload. Ping payload: TxID(12) | NodeKey(32) |
 * padding; pong payload: TxID(12) | Src IP(16) | Src port(BE16).
 *
 * The box key is precomputed once per key pair (ts_disco_shared); sealing and
 * opening never do an X25519. Nonces are the caller's (random) bytes. */

#define TS_DISCO_MAGIC_LEN 6
#define TS_DISCO_HDR_LEN   38    /* magic + sender disco public key */
#define TS_DISCO_NONCE_LEN 24
#define TS_DISCO_TXID_LEN  12
#define TS_DISCO_PING_LEN  124   /* ping with NodeKey, no padding */
#define TS_DISCO_PONG_LEN  110
#define TS_DISCO_MAX       1500  /* largest packet built or accepted here */

#define TS_DISCO_PING 1
#define TS_DISCO_PONG 2

/* Magic prefix and n >= 6 + 32 + 24 (upstream LooksLikeDiscoWrapper). */
int ts_disco_looks_like(const uint8_t *p, size_t n);

/* The 32-byte sender disco public key in a packet's header; p must hold at
 * least TS_DISCO_HDR_LEN bytes (check ts_disco_looks_like first). */
const uint8_t *ts_disco_sender(const uint8_t *p);

typedef struct { uint8_t k[32]; } ts_disco_shared;

/* One X25519 + HSalsa20 (ts_box_beforenm). If their_pub is a low-order point
 * (all-zero X25519 result) the key is left all zero, and seal and open with
 * it then fail: no packet is ever sealed or accepted under a key anyone can
 * compute. Wipe with ts_wipe when the key is dropped. */
void ts_disco_shared_init(ts_disco_shared *s, const uint8_t my_priv[32],
                          const uint8_t their_pub[32]);

/* Build a sealed ping (with our node key, no padding) into out. Returns
 * TS_DISCO_PING_LEN, or -1 if cap is too small or the key is unusable
 * (out is then untouched). */
int ts_disco_seal_ping(uint8_t *out, size_t cap, const uint8_t my_disco_pub[32],
                       const ts_disco_shared *s, const uint8_t nonce[24],
                       const uint8_t txid[12], const uint8_t my_node_pub[32]);

/* Build a sealed pong. src_ip16 is the IPv6-form address (IPv4 as
 * ::ffff:a.b.c.d). Returns TS_DISCO_PONG_LEN or -1 as above. */
int ts_disco_seal_pong(uint8_t *out, size_t cap, const uint8_t my_disco_pub[32],
                       const ts_disco_shared *s, const uint8_t nonce[24],
                       const uint8_t txid[12], const uint8_t src_ip16[16],
                       uint16_t src_port);

typedef struct {
    int type;               /* TS_DISCO_PING, TS_DISCO_PONG, or the raw type byte */
    uint8_t txid[12];
    int have_node_key;      /* ping only */
    uint8_t node_key[32];   /* ping only */
    uint8_t src_ip16[16];   /* pong only, raw 16 bytes */
    uint16_t src_port;      /* pong only */
} ts_disco_msg;

/* Open and parse a packet (header included) with the shared key for its
 * sender. Returns 0 with m filled, or -1 (bad magic or length, n >
 * TS_DISCO_MAX, forged box, plaintext under 2 bytes, ping payload under 12
 * bytes, pong payload under 30 bytes). The version byte is ignored, as
 * upstream's parsePing/parsePong do. Bytes after a message are ignored. Ping
 * NodeKey: set only if the 32 bytes after the TxID exist and are not all
 * zero. Types other than ping and pong return 0 with only m->type set. */
int ts_disco_open(ts_disco_msg *m, const uint8_t *p, size_t n,
                  const ts_disco_shared *s);

#endif
