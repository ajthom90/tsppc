#include "blake2s.h"
#include <stdlib.h>
#include <string.h>
#include "../core/bytes.h"

static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t SIGMA[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0}
};

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

#define G(a, b, c, d, x, y) do {          \
    v[a] = v[a] + v[b] + (x);             \
    v[d] = rotr(v[d] ^ v[a], 16);         \
    v[c] = v[c] + v[d];                   \
    v[b] = rotr(v[b] ^ v[c], 12);         \
    v[a] = v[a] + v[b] + (y);             \
    v[d] = rotr(v[d] ^ v[a], 8);          \
    v[c] = v[c] + v[d];                   \
    v[b] = rotr(v[b] ^ v[c], 7);          \
} while (0)

static void compress(ts_blake2s_ctx *c, const uint8_t *block, int last)
{
    uint32_t m[16], v[16];
    int i, r;

    for (i = 0; i < 16; i++) m[i] = ts_get_le32(block + 4 * i);
    for (i = 0; i < 8; i++) { v[i] = c->h[i]; v[i + 8] = IV[i]; }
    v[12] ^= c->t[0];
    v[13] ^= c->t[1];
    if (last) v[14] = ~v[14];

    for (r = 0; r < 10; r++) {
        const uint8_t *s = SIGMA[r];
        G(0, 4,  8, 12, m[s[0]],  m[s[1]]);
        G(1, 5,  9, 13, m[s[2]],  m[s[3]]);
        G(2, 6, 10, 14, m[s[4]],  m[s[5]]);
        G(3, 7, 11, 15, m[s[6]],  m[s[7]]);
        G(0, 5, 10, 15, m[s[8]],  m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    for (i = 0; i < 8; i++) c->h[i] ^= v[i] ^ v[i + 8];
    ts_wipe(m, sizeof m);
    ts_wipe(v, sizeof v);
}

static void add_count(ts_blake2s_ctx *c, uint32_t n)
{
    c->t[0] += n;
    if (c->t[0] < n) c->t[1]++;
}

int ts_blake2s_init(ts_blake2s_ctx *c, size_t outlen, const uint8_t *key, size_t keylen)
{
    int i;

    if (outlen < 1 || outlen > 32 || keylen > 32) return -1;
    memset(c, 0, sizeof *c);
    for (i = 0; i < 8; i++) c->h[i] = IV[i];
    c->h[0] ^= 0x01010000u ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;
    c->outlen = outlen;
    if (keylen > 0) {
        uint8_t block[64];
        memset(block, 0, sizeof block);
        memcpy(block, key, keylen);
        ts_blake2s_update(c, block, sizeof block);
        ts_wipe(block, sizeof block);
    }
    return 0;
}

void ts_blake2s_update(ts_blake2s_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    while (len > 0) {
        size_t n;
        if (c->buflen == 64) {   /* more input follows, so the buffered block is not last */
            add_count(c, 64);
            compress(c, c->buf, 0);
            c->buflen = 0;
        }
        n = 64 - c->buflen;
        if (n > len) n = len;
        memcpy(c->buf + c->buflen, p, n);
        c->buflen += n;
        p += n;
        len -= n;
    }
}

void ts_blake2s_final(ts_blake2s_ctx *c, uint8_t *out)
{
    uint8_t full[32];
    int i;

    add_count(c, (uint32_t)c->buflen);
    memset(c->buf + c->buflen, 0, 64 - c->buflen);
    compress(c, c->buf, 1);
    for (i = 0; i < 8; i++) ts_put_le32(full + 4 * i, c->h[i]);
    memcpy(out, full, c->outlen);
    ts_wipe(full, sizeof full);
    ts_wipe(c, sizeof *c);
}

void ts_blake2s(uint8_t out[32], const void *data, size_t len)
{
    ts_blake2s_ctx c;
    if (ts_blake2s_init(&c, 32, NULL, 0) != 0) abort();   /* fixed valid parameters */
    ts_blake2s_update(&c, data, len);
    ts_blake2s_final(&c, out);
}
