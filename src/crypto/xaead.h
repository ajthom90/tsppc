#ifndef TS_CRYPTO_XAEAD_H
#define TS_CRYPTO_XAEAD_H

#include <stddef.h>
#include <stdint.h>

void ts_hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[16]);

/* XChaCha20-Poly1305. Same layout and aliasing rules as ts_aead_seal/open. */
void ts_xaead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                   const uint8_t *ad, size_t adlen,
                   const uint8_t *pt, size_t ptlen);
int ts_xaead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *ct, size_t ctlen);

#endif
