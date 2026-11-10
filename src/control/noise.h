#ifndef TS_CONTROL_NOISE_H
#define TS_CONTROL_NOISE_H

#include <stddef.h>
#include <stdint.h>

/* Sans-I/O Noise transport for the control connection (ts2021).
 *
 * Handshake: Noise_IK_25519_ChaChaPoly_BLAKE2s with prologue
 * "Tailscale Control Protocol v<capver>", the client as initiator and the
 * control server's static key known in advance. The init travels base64 in the
 * HTTP upgrade request (see upgrade.h); the 51-byte response comes back on the
 * upgraded connection.
 *
 *   init:     BE16 capver, 1, BE16 96, e (32), encrypted machine key (48), tag (16)
 *   response: 2, BE16 48, e (32), tag (16)
 *   record:   4, BE16 len, ciphertext (len = plaintext + 16, at most 4093)
 *   error:    3, BE16 len, unauthenticated text (always fatal here)
 *
 * Transport nonces are 4 zero bytes then a big-endian 64-bit counter, with empty
 * associated data. Counter 2^64 - 1 is never used: sealing or opening with it
 * fails, and the counter does not wrap.
 *
 * Any failure (bad response, bad record, error frame, exhausted nonce) is
 * sticky: the session wipes its keys, later seals return 0, later feeds -1. */

#define TS_CAPVER 150

#define TS_NOISE_INIT_LEN 101
#define TS_NOISE_RESP_LEN 51
#define TS_NOISE_MAX_MSG 4096                            /* header + ciphertext */
#define TS_NOISE_MAX_PLAIN (TS_NOISE_MAX_MSG - 3 - 16)  /* 4077 */
#define TS_NOISE_RECORD_OVERHEAD 19                     /* header + tag */

enum { TS_NOISE_EMPTY = 0, TS_NOISE_SENT, TS_NOISE_READY, TS_NOISE_FAILED };

typedef struct {
    int state;
    /* Handshake; ck, e_priv and s_priv are wiped when the handshake ends. */
    uint8_t h[32];           /* handshake hash, kept after the split */
    uint8_t ck[32];
    uint8_t e_priv[32];
    uint8_t s_priv[32];      /* copy of the machine key, needed for se */
    /* Transport */
    uint8_t tx_key[32];
    uint8_t rx_key[32];
    uint64_t tx_ctr;
    uint64_t rx_ctr;
    /* Reassembly of one incoming record */
    uint8_t rbuf[TS_NOISE_MAX_MSG];
    size_t rlen;
} ts_noise;

/* Start a handshake with a fresh random ephemeral and write the init message.
 * Returns 0, or -1 if randomness fails or control_pub is a low-order point
 * (n is then wiped and FAILED). */
int ts_noise_init(ts_noise *n, uint8_t init[TS_NOISE_INIT_LEN],
                  const uint8_t machine_priv[32], const uint8_t control_pub[32],
                  uint16_t capver);

#ifdef TS_TEST_HOOKS
/* As ts_noise_init with a caller-chosen ephemeral private key. Tests only. */
int ts_noise_init_eph(ts_noise *n, uint8_t init[TS_NOISE_INIT_LEN],
                      const uint8_t machine_priv[32], const uint8_t control_pub[32],
                      uint16_t capver, const uint8_t eph_priv[32]);
#endif

/* Complete the handshake with the server's response. Returns 0 (transport
 * ready) or -1 (wrong type or length, error frame, bad tag, wrong control key,
 * or no handshake in progress). */
int ts_noise_read_response(ts_noise *n, const uint8_t resp[TS_NOISE_RESP_LEN]);

/* Encrypt pt into one or more records of at most TS_NOISE_MAX_PLAIN plaintext
 * bytes each, written to out. Returns the bytes written, or 0 if ptlen is 0,
 * the session is not ready, out cannot hold every record
 * (ptlen + 19 per record), or the nonces would run out; then nothing is
 * written and no nonce is used (only running out of nonces is fatal). */
size_t ts_noise_seal(ts_noise *n, uint8_t *out, size_t cap, const uint8_t *pt, size_t ptlen);

/* Feed bytes received from the server, split anywhere. Each complete record is
 * authenticated and its plaintext passed to deliver (required; records with an
 * empty plaintext are not delivered). deliver may seal but must not feed.
 * Returns 0, or -1 on an unexpected message type, an error frame, a bad length
 * or tag, an exhausted nonce, or a session that is not ready; deliver is never
 * called after -1. */
int ts_noise_feed(ts_noise *n, const uint8_t *in, size_t len,
                  void (*deliver)(void *, const uint8_t *, size_t), void *user);

/* Wipe all state. */
void ts_noise_clear(ts_noise *n);

#endif
