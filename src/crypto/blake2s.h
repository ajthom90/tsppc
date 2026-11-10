#ifndef TS_CRYPTO_BLAKE2S_H
#define TS_CRYPTO_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint8_t  buf[64];
    size_t   buflen;
    size_t   outlen;
} ts_blake2s_ctx;

/* outlen 1..32, keylen 0..32 (key may be NULL when keylen is 0). */
void ts_blake2s_init(ts_blake2s_ctx *c, size_t outlen, const uint8_t *key, size_t keylen);
void ts_blake2s_update(ts_blake2s_ctx *c, const void *data, size_t len);
/* Writes outlen bytes and wipes the context. */
void ts_blake2s_final(ts_blake2s_ctx *c, uint8_t *out);
/* One-shot, 32-byte unkeyed digest. */
void ts_blake2s(uint8_t out[32], const void *data, size_t len);

#endif
