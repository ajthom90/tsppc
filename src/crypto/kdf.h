#ifndef TS_CRYPTO_KDF_H
#define TS_CRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>

/* HMAC with BLAKE2s-256 (64-byte block). Keys longer than 64 bytes are hashed first. */
void ts_hmac_blake2s(uint8_t out[32], const uint8_t *key, size_t keylen,
                     const void *msg, size_t msglen);

/* Noise HKDF with empty info: t1 = HMAC(HMAC(salt, ikm), 0x01), tN = HMAC(prk, t(N-1) || N). */
void ts_hkdf2(uint8_t t1[32], uint8_t t2[32], const uint8_t salt[32],
              const uint8_t *ikm, size_t ikmlen);
void ts_hkdf3(uint8_t t1[32], uint8_t t2[32], uint8_t t3[32], const uint8_t salt[32],
              const uint8_t *ikm, size_t ikmlen);

#endif
