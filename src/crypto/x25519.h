#ifndef TS_CRYPTO_X25519_H
#define TS_CRYPTO_X25519_H

#include <stdint.h>

/* Shared secret. Returns 0 on success, -1 if the result is all zero
 * (low-order peer key); out is wiped on failure. */
int ts_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]);

/* Public key for priv (scalar multiplication of the base point). */
void ts_x25519_public(uint8_t out[32], const uint8_t priv[32]);

#endif
