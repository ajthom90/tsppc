#ifndef TS_CRYPTO_AEAD_H
#define TS_CRYPTO_AEAD_H

#include <stddef.h>
#include <stdint.h>

/* ChaCha20-Poly1305 (RFC 8439). out receives ptlen + 16 bytes: ciphertext
 * then tag. out may equal pt. */
void ts_aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *pt, size_t ptlen);

/* ctlen includes the 16-byte tag; out receives ctlen - 16 bytes. Returns 0 if
 * authentic, -1 otherwise (out is then wiped). out may equal ct. */
int ts_aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *ad, size_t adlen,
                 const uint8_t *ct, size_t ctlen);

#endif
