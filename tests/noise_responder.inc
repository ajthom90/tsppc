/* Test responder for the Noise control handshake, shared by tests/test_noise.c
 * and tests/fuzz_noise.c. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/core/bytes.h"
#include "../src/crypto/aead.h"
#include "../src/crypto/blake2s.h"
#include "../src/crypto/kdf.h"
#include "../src/crypto/x25519.h"

/* ---- Test responder ------------------------------------------------------
 * Written from the Noise specification (revision 34) for
 * Noise_IK_25519_ChaChaPoly_BLAKE2s, using only the crypto primitives, so it
 * checks the initiator rather than sharing its code. Pattern IK:
 *   <- s
 *   ...
 *   -> e, es, s, ss
 *   <- e, ee, se
 * Prologue "Tailscale Control Protocol v<version>". Message layout follows
 * upstream's messages.go: init = BE16 version, 1, BE16 96, payload (96);
 * response = 2, BE16 48, payload (48). Payloads are empty. */

typedef struct {
    uint8_t h[32];
    uint8_t ck[32];
} r_sym;

typedef struct {
    uint8_t c1[32];          /* initiator to responder */
    uint8_t c2[32];          /* responder to initiator */
    uint8_t machine_pub[32]; /* the initiator's static key, as decrypted */
} r_session;

static void r_mix_hash(r_sym *s, const uint8_t *data, size_t len)
{
    ts_blake2s_ctx c;
    ts_blake2s_init(&c, 32, NULL, 0);
    ts_blake2s_update(&c, s->h, 32);
    ts_blake2s_update(&c, data, len);
    ts_blake2s_final(&c, s->h);
}

/* MixKey(DH(priv, pub)): returns the one-use cipher key k, or -1. */
static int r_mix_dh(r_sym *s, uint8_t k[32], const uint8_t priv[32], const uint8_t pub[32])
{
    uint8_t dh[32], ck[32];
    if (ts_x25519(dh, priv, pub) != 0) return -1;
    ts_hkdf2(ck, k, s->ck, dh, 32);
    memcpy(s->ck, ck, 32);
    return 0;
}

static void r_init(r_sym *s, unsigned version, const uint8_t rs[32])
{
    static const char name[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    char prologue[64];
    int n;
    /* The name is longer than HASHLEN, so h = HASH(name). */
    ts_blake2s(s->h, name, sizeof name - 1);
    memcpy(s->ck, s->h, 32);
    n = snprintf(prologue, sizeof prologue, "Tailscale Control Protocol v%u", version);
    r_mix_hash(s, (const uint8_t *)prologue, (size_t)n);
    r_mix_hash(s, rs, 32);   /* pre-message: responder's static key */
}

/* Handles an init and writes a response. Returns 0 or -1 (init rejected). */
static int responder(r_session *out, uint8_t resp[51], const uint8_t init[101],
                     const uint8_t control_priv[32], const uint8_t eph_priv[32])
{
    static const uint8_t zero_nonce[12];
    r_sym s;
    uint8_t control_pub[32], eph_pub[32], k[32], none[1];
    const uint8_t *re = init + 5;

    /* As upstream's server: the prologue uses the version the client sent. */
    if (init[2] != 1 || ts_get_be16(init + 3) != 96) return -1;
    ts_x25519_public(control_pub, control_priv);
    r_init(&s, ts_get_be16(init), control_pub);

    /* -> e, es, s, ss */
    r_mix_hash(&s, re, 32);
    if (r_mix_dh(&s, k, control_priv, re) != 0) return -1;
    if (ts_aead_open(out->machine_pub, k, zero_nonce, s.h, 32, init + 37, 48) != 0) return -1;
    r_mix_hash(&s, init + 37, 48);
    if (r_mix_dh(&s, k, control_priv, out->machine_pub) != 0) return -1;
    if (ts_aead_open(none, k, zero_nonce, s.h, 32, init + 85, 16) != 0) return -1;
    r_mix_hash(&s, init + 85, 16);

    /* <- e, ee, se */
    ts_x25519_public(eph_pub, eph_priv);
    resp[0] = 2;
    ts_put_be16(resp + 1, 48);
    memcpy(resp + 3, eph_pub, 32);
    r_mix_hash(&s, eph_pub, 32);
    if (r_mix_dh(&s, k, eph_priv, re) != 0) return -1;
    if (r_mix_dh(&s, k, eph_priv, out->machine_pub) != 0) return -1;
    ts_aead_seal(resp + 35, k, zero_nonce, s.h, 32, none, 0);
    r_mix_hash(&s, resp + 35, 16);

    /* Split */
    ts_hkdf2(out->c1, out->c2, s.ck, NULL, 0);
    return 0;
}

/* Transport nonce: 4 zero bytes then the counter, big-endian unless le. */
static void r_nonce(uint8_t nonce[12], uint64_t ctr, int le)
{
    memset(nonce, 0, 4);
    if (le) ts_put_le64(nonce + 4, ctr);
    else ts_put_be64(nonce + 4, ctr);
}

/* One record [4, BE16 len, ct]. Returns its total length. */
static size_t r_seal(uint8_t *out, const uint8_t key[32], uint64_t ctr, int le,
                     const uint8_t *pt, size_t len)
{
    uint8_t nonce[12];
    r_nonce(nonce, ctr, le);
    out[0] = 4;
    ts_put_be16(out + 1, (uint16_t)(len + 16));
    ts_aead_seal(out + 3, key, nonce, NULL, 0, pt, len);
    return 3 + len + 16;
}

/* Open one record at rec; returns the plaintext length or -1. */
static long r_open(uint8_t *pt, const uint8_t key[32], uint64_t ctr, int le, const uint8_t *rec)
{
    uint8_t nonce[12];
    size_t len = ts_get_be16(rec + 1);
    if (rec[0] != 4 || len < 16) return -1;
    r_nonce(nonce, ctr, le);
    if (ts_aead_open(pt, key, nonce, NULL, 0, rec + 3, len) != 0) return -1;
    return (long)(len - 16);
}
