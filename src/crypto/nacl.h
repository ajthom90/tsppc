#ifndef TS_CRYPTO_NACL_H
#define TS_CRYPTO_NACL_H

#include <stddef.h>
#include <stdint.h>

/* Plain one-time Poly1305 MAC (RFC 8439 section 2.5). The PowerPC multiply
 * instruction takes data-dependent time on G3/G4, so the PowerPC build uses a
 * constant-time implementation and requires -DBR_CT_MUL15=1. */
void ts_poly1305(uint8_t tag[16], const uint8_t key[32],
                 const uint8_t *msg, size_t len);

void ts_hsalsa20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16]);

/* XSalsa20-Poly1305 secretbox. out receives mlen + 16 bytes: tag first, then
 * ciphertext. m may equal out + 16 (in place) or be disjoint from out. */
void ts_secretbox_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *m, size_t mlen);

/* clen includes the 16-byte tag (which comes first); out receives clen - 16
 * bytes. Returns 0 if authentic, -1 on short input or failure (out is then
 * wiped). out may equal c + 16 or be disjoint from c. */
int ts_secretbox_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t *c, size_t clen);

/* crypto_box_beforenm: HSalsa20(X25519(my_priv, their_pub), 0). Returns -1
 * if the X25519 result is all zero. */
int ts_box_beforenm(uint8_t k[32], const uint8_t their_pub[32], const uint8_t my_priv[32]);

/* NaCl box; same layout and aliasing rules as the secretbox functions.
 * Return -1 on a bad peer key (and, for open, on short or forged input). */
int ts_box_seal(uint8_t *out, const uint8_t nonce[24], const uint8_t their_pub[32],
                const uint8_t my_priv[32], const uint8_t *m, size_t mlen);
int ts_box_open(uint8_t *out, const uint8_t nonce[24], const uint8_t their_pub[32],
                const uint8_t my_priv[32], const uint8_t *c, size_t clen);

#endif
