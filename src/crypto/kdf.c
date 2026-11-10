#include "kdf.h"
#include <stdlib.h>
#include <string.h>
#include "blake2s.h"
#include "../core/bytes.h"

#define BLOCK 64

void ts_hmac_blake2s(uint8_t out[32], const uint8_t *key, size_t keylen,
                     const void *msg, size_t msglen)
{
    uint8_t k[BLOCK], pad[BLOCK], inner[32];
    ts_blake2s_ctx c;
    size_t i;

    memset(k, 0, sizeof k);
    if (keylen > BLOCK) ts_blake2s(k, key, keylen);
    else if (keylen > 0) memcpy(k, key, keylen);

    for (i = 0; i < BLOCK; i++) pad[i] = k[i] ^ 0x36;
    if (ts_blake2s_init(&c, 32, NULL, 0) != 0) abort();   /* fixed valid parameters */
    ts_blake2s_update(&c, pad, BLOCK);
    ts_blake2s_update(&c, msg, msglen);
    ts_blake2s_final(&c, inner);

    for (i = 0; i < BLOCK; i++) pad[i] = k[i] ^ 0x5c;
    if (ts_blake2s_init(&c, 32, NULL, 0) != 0) abort();   /* fixed valid parameters */
    ts_blake2s_update(&c, pad, BLOCK);
    ts_blake2s_update(&c, inner, 32);
    ts_blake2s_final(&c, out);

    ts_wipe(k, sizeof k);
    ts_wipe(pad, sizeof pad);
    ts_wipe(inner, sizeof inner);
}

/* tN = HMAC(prk, prev || n); prev is NULL for n == 1. */
static void expand(uint8_t out[32], const uint8_t prk[32], const uint8_t *prev, uint8_t n)
{
    uint8_t in[33];
    size_t len = 0;

    if (prev != NULL) { memcpy(in, prev, 32); len = 32; }
    in[len++] = n;
    ts_hmac_blake2s(out, prk, 32, in, len);
    ts_wipe(in, sizeof in);
}

void ts_hkdf3(uint8_t t1[32], uint8_t t2[32], uint8_t t3[32], const uint8_t salt[32],
              const uint8_t *ikm, size_t ikmlen)
{
    uint8_t prk[32];

    ts_hmac_blake2s(prk, salt, 32, ikm, ikmlen);
    expand(t1, prk, NULL, 1);
    expand(t2, prk, t1, 2);
    expand(t3, prk, t2, 3);
    ts_wipe(prk, sizeof prk);
}

void ts_hkdf2(uint8_t t1[32], uint8_t t2[32], const uint8_t salt[32],
              const uint8_t *ikm, size_t ikmlen)
{
    uint8_t prk[32];

    ts_hmac_blake2s(prk, salt, 32, ikm, ikmlen);
    expand(t1, prk, NULL, 1);
    expand(t2, prk, t1, 2);
    ts_wipe(prk, sizeof prk);
}
