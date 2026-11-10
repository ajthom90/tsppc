#include "nacl.h"
#include <string.h>
#include "../core/bytes.h"
#include "x25519.h"

/* G3/G4 multiply instructions take variable time. PowerPC (and the host
 * ct-test build) therefore uses the 13-bit limb Poly1305 below, whose
 * multiplies are all TS_MUL15, and needs BearSSL's constant-time MUL15. */
#if defined(__ppc__) || defined(TS_FORCE_CT_POLY)
#define TS_CT_POLY 1
#if !defined(BR_CT_MUL15) || !BR_CT_MUL15
#error "constant-time Poly1305 requires -DBR_CT_MUL15=1"
#endif
#endif

#ifdef TS_CT_POLY

/* ---- Poly1305: 10 x 13-bit limbs, 32x32->32 multiplies only ---- */

/* Same layout and carry handling as BearSSL's poly1305_ctmul32. Like BearSSL's
 * MUL15, TS_MUL15 sets both operands' top bits so the multiplier always sees
 * full-width values. Upstream BearSSL then masks the product to 31 bits, but
 * gcc-4.0 works out that the top bits cannot reach a masked result and deletes
 * the ORs. Here bit 31 is cancelled by XOR instead: it equals bit 0 of x ^ y, so
 * the ORs stay necessary. The result is x * y as long as that is below 2^31:
 * the operands' bit lengths must sum to at most 31. Here a[] uses at most 15
 * bits and r[] at most 16 (a 13-bit limb times 5). */
#define TS_MUL15(x, y) \
    ((((uint32_t)(x) | 0x80000000u) * ((uint32_t)(y) | 0x80000000u)) ^ \
     (((uint32_t)(x) ^ (uint32_t)(y)) << 31))

#define M13 0x1fffu

/* r[9..18] holds the limbs of r, r[0..8] holds 5 * r[10..18], so r[u + 9 - v]
 * is the factor for a[v] in column u. b is working space. hibit is the bit
 * at position 128 for this block: 1 << 11 in the top limb, or 0 for a final
 * partial block (which carries its own 0x01 padding byte). */
static void poly_block(uint32_t a[10], uint32_t b[10], const uint32_t r[19],
                       const uint8_t *m, uint32_t hibit)
{
    uint32_t t0 = ts_get_le32(m), t1 = ts_get_le32(m + 4);
    uint32_t t2 = ts_get_le32(m + 8), t3 = ts_get_le32(m + 12);
    uint32_t cc1, cc2, s, z;
    unsigned u;

    a[0] += t0 & M13;
    a[1] += (t0 >> 13) & M13;
    a[2] += ((t0 >> 26) | (t1 << 6)) & M13;
    a[3] += (t1 >> 7) & M13;
    a[4] += ((t1 >> 20) | (t2 << 12)) & M13;
    a[5] += (t2 >> 1) & M13;
    a[6] += (t2 >> 14) & M13;
    a[7] += ((t2 >> 27) | (t3 << 5)) & M13;
    a[8] += (t3 >> 8) & M13;
    a[9] += (t3 >> 21) | hibit;

    /* Two passes with a carry between them: one full column of a[] * r[]
     * could overflow a 32-bit word. */
    cc1 = 0;
    for (u = 0; u < 10; u++) {
        s = cc1 + TS_MUL15(a[0], r[u + 9 - 0]) + TS_MUL15(a[1], r[u + 9 - 1]) +
            TS_MUL15(a[2], r[u + 9 - 2]) + TS_MUL15(a[3], r[u + 9 - 3]) +
            TS_MUL15(a[4], r[u + 9 - 4]);
        b[u] = s & M13;
        cc1 = s >> 13;
    }
    cc2 = 0;
    for (u = 0; u < 10; u++) {
        s = b[u] + cc2 + TS_MUL15(a[5], r[u + 9 - 5]) + TS_MUL15(a[6], r[u + 9 - 6]) +
            TS_MUL15(a[7], r[u + 9 - 7]) + TS_MUL15(a[8], r[u + 9 - 8]) +
            TS_MUL15(a[9], r[u + 9 - 9]);
        b[u] = s & M13;
        cc2 = s >> 13;
    }
    for (u = 0; u < 10; u++) a[u] = b[u];

    /* The carries out of the top wrap around with a factor of 5. */
    z = cc1 + cc2;
    z += (z << 2) + a[0];
    a[0] = z & M13;
    a[1] += z >> 13;
}

void ts_poly1305(uint8_t tag[16], const uint8_t key[32],
                 const uint8_t *msg, size_t len)
{
    uint32_t r[19], a[10], b[10], z, cc, ctl, x, mask;
    uint32_t t0 = ts_get_le32(key), t1 = ts_get_le32(key + 4);
    uint32_t t2 = ts_get_le32(key + 8), t3 = ts_get_le32(key + 12);
    unsigned i;

    /* Clamp r in 26-bit pieces, then split each piece in two 13-bit limbs. */
    z = t0 & 0x3ffffffu;
    r[9] = z & M13; r[10] = z >> 13;
    z = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    r[11] = z & M13; r[12] = z >> 13;
    z = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    r[13] = z & M13; r[14] = z >> 13;
    z = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    r[15] = z & M13; r[16] = z >> 13;
    z = (t3 >> 8) & 0x00fffffu;
    r[17] = z & M13; r[18] = z >> 13;
    for (i = 0; i < 9; i++) r[i] = TS_MUL15(5, r[i + 10]);

    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);

    while (len >= 16) {
        poly_block(a, b, r, msg, 1u << 11);
        msg += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t buf[16];
        memset(buf, 0, sizeof buf);
        memcpy(buf, msg, len);
        buf[len] = 1;
        poly_block(a, b, r, buf, 0);
        ts_wipe(buf, sizeof buf);
    }

    /* Full carry. poly_block left a[0] below 2^13 and only a[1] above it. */
    cc = 0;
    for (i = 1; i < 10; i++) {
        z = a[i] + cc;
        a[i] = z & M13;
        cc = z >> 13;
    }
    z = a[0] + cc + (cc << 2);
    a[0] = z & M13;
    a[1] += z >> 13;

    /* Subtract p if a >= p, without branching. a[1] may be 2^13 here, but
     * then a is below p and the comparison correctly fails. */
    ctl = (a[0] + 5) >> 13;
    for (i = 1; i < 10; i++) {
        x = a[i] ^ M13;
        ctl &= ((x | (0u - x)) >> 31) ^ 1;
    }
    mask = 0u - ctl;
    a[0] -= 0x1ffbu & mask;
    for (i = 1; i < 10; i++) a[i] &= ~mask;

    /* Back to bytes, adding the pad s modulo 2^128. */
    z = a[0] + (a[1] << 13) + ts_get_le16(key + 16);
    ts_put_le16(tag, (uint16_t)z);
    z = (z >> 16) + (a[2] << 10) + ts_get_le16(key + 18);
    ts_put_le16(tag + 2, (uint16_t)z);
    z = (z >> 16) + (a[3] << 7) + ts_get_le16(key + 20);
    ts_put_le16(tag + 4, (uint16_t)z);
    z = (z >> 16) + (a[4] << 4) + ts_get_le16(key + 22);
    ts_put_le16(tag + 6, (uint16_t)z);
    z = (z >> 16) + (a[5] << 1) + (a[6] << 14) + ts_get_le16(key + 24);
    ts_put_le16(tag + 8, (uint16_t)z);
    z = (z >> 16) + (a[7] << 11) + ts_get_le16(key + 26);
    ts_put_le16(tag + 10, (uint16_t)z);
    z = (z >> 16) + (a[8] << 8) + ts_get_le16(key + 28);
    ts_put_le16(tag + 12, (uint16_t)z);
    z = (z >> 16) + (a[9] << 5) + ts_get_le16(key + 30);
    ts_put_le16(tag + 14, (uint16_t)z);

    ts_wipe(r, sizeof r);
    ts_wipe(a, sizeof a);
    ts_wipe(b, sizeof b);
}

#else /* !TS_CT_POLY */

/* ---- Poly1305: 5 x 26-bit limbs, 32-bit words, 64-bit products ---- */

#define M26 0x3ffffffu

static void poly_block(uint32_t h[5], const uint32_t r[5], const uint8_t *m,
                       uint32_t hibit)
{
    uint32_t s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5, s4 = r[4] * 5;
    uint32_t t0 = ts_get_le32(m), t1 = ts_get_le32(m + 4);
    uint32_t t2 = ts_get_le32(m + 8), t3 = ts_get_le32(m + 12);
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    h[0] += t0 & M26;
    h[1] += ((t0 >> 26) | (t1 << 6)) & M26;
    h[2] += ((t1 >> 20) | (t2 << 12)) & M26;
    h[3] += ((t2 >> 14) | (t3 << 18)) & M26;
    h[4] += (t3 >> 8) | hibit;

    d0 = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * s4 + (uint64_t)h[2] * s3 +
         (uint64_t)h[3] * s2 + (uint64_t)h[4] * s1;
    d1 = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * s4 +
         (uint64_t)h[3] * s3 + (uint64_t)h[4] * s2;
    d2 = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] +
         (uint64_t)h[3] * s4 + (uint64_t)h[4] * s3;
    d3 = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] +
         (uint64_t)h[3] * r[0] + (uint64_t)h[4] * s4;
    d4 = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + (uint64_t)h[2] * r[2] +
         (uint64_t)h[3] * r[1] + (uint64_t)h[4] * r[0];

    c = (uint32_t)(d0 >> 26); h[0] = (uint32_t)d0 & M26; d1 += c;
    c = (uint32_t)(d1 >> 26); h[1] = (uint32_t)d1 & M26; d2 += c;
    c = (uint32_t)(d2 >> 26); h[2] = (uint32_t)d2 & M26; d3 += c;
    c = (uint32_t)(d3 >> 26); h[3] = (uint32_t)d3 & M26; d4 += c;
    c = (uint32_t)(d4 >> 26); h[4] = (uint32_t)d4 & M26;
    h[0] += c * 5;
    c = h[0] >> 26; h[0] &= M26;
    h[1] += c;
}

void ts_poly1305(uint8_t tag[16], const uint8_t key[32],
                 const uint8_t *msg, size_t len)
{
    uint32_t r[5], h[5] = {0, 0, 0, 0, 0}, g[5], c, mask;
    uint32_t t0 = ts_get_le32(key), t1 = ts_get_le32(key + 4);
    uint32_t t2 = ts_get_le32(key + 8), t3 = ts_get_le32(key + 12);
    uint64_t f;

    r[0] = t0 & 0x3ffffffu;
    r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    r[4] = (t3 >> 8) & 0x00fffffu;

    while (len >= 16) {
        poly_block(h, r, msg, 1u << 24);
        msg += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t buf[16];
        memset(buf, 0, sizeof buf);
        memcpy(buf, msg, len);
        buf[len] = 1;
        poly_block(h, r, buf, 0);
        ts_wipe(buf, sizeof buf);
    }

    /* Full carry. */
    c = h[1] >> 26; h[1] &= M26; h[2] += c;
    c = h[2] >> 26; h[2] &= M26; h[3] += c;
    c = h[3] >> 26; h[3] &= M26; h[4] += c;
    c = h[4] >> 26; h[4] &= M26; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= M26; h[1] += c;

    /* g = h + 5 - 2^130; select g if h >= p, without branching. */
    g[0] = h[0] + 5; c = g[0] >> 26; g[0] &= M26;
    g[1] = h[1] + c; c = g[1] >> 26; g[1] &= M26;
    g[2] = h[2] + c; c = g[2] >> 26; g[2] &= M26;
    g[3] = h[3] + c; c = g[3] >> 26; g[3] &= M26;
    g[4] = h[4] + c - (1u << 26);
    mask = (g[4] >> 31) - 1; /* all ones if h >= p */
    h[0] = (h[0] & ~mask) | (g[0] & mask);
    h[1] = (h[1] & ~mask) | (g[1] & mask);
    h[2] = (h[2] & ~mask) | (g[2] & mask);
    h[3] = (h[3] & ~mask) | (g[3] & mask);
    h[4] = (h[4] & ~mask) | (g[4] & mask);

    /* Repack to 128 bits and add the pad s. */
    t0 = h[0] | (h[1] << 26);
    t1 = (h[1] >> 6) | (h[2] << 20);
    t2 = (h[2] >> 12) | (h[3] << 14);
    t3 = (h[3] >> 18) | (h[4] << 8);
    f = (uint64_t)t0 + ts_get_le32(key + 16);
    ts_put_le32(tag, (uint32_t)f);
    f = (uint64_t)t1 + ts_get_le32(key + 20) + (f >> 32);
    ts_put_le32(tag + 4, (uint32_t)f);
    f = (uint64_t)t2 + ts_get_le32(key + 24) + (f >> 32);
    ts_put_le32(tag + 8, (uint32_t)f);
    f = (uint64_t)t3 + ts_get_le32(key + 28) + (f >> 32);
    ts_put_le32(tag + 12, (uint32_t)f);

    ts_wipe(r, sizeof r);
    ts_wipe(h, sizeof h);
    ts_wipe(g, sizeof g);
}

#endif /* TS_CT_POLY */

/* ---- Salsa20 / HSalsa20 ---- */

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static const uint32_t SIGMA[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};

static void salsa_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *b ^= ROTL(*a + *d, 7);
    *c ^= ROTL(*b + *a, 9);
    *d ^= ROTL(*c + *b, 13);
    *a ^= ROTL(*d + *c, 18);
}

static void salsa_rounds(uint32_t x[16])
{
    int i;
    for (i = 0; i < 10; i++) {
        salsa_qr(&x[0], &x[4], &x[8], &x[12]);
        salsa_qr(&x[5], &x[9], &x[13], &x[1]);
        salsa_qr(&x[10], &x[14], &x[2], &x[6]);
        salsa_qr(&x[15], &x[3], &x[7], &x[11]);
        salsa_qr(&x[0], &x[1], &x[2], &x[3]);
        salsa_qr(&x[5], &x[6], &x[7], &x[4]);
        salsa_qr(&x[10], &x[11], &x[8], &x[9]);
        salsa_qr(&x[15], &x[12], &x[13], &x[14]);
    }
}

static void salsa_setup(uint32_t x[16], const uint8_t key[32], const uint8_t in[16])
{
    int i;
    x[0] = SIGMA[0]; x[5] = SIGMA[1]; x[10] = SIGMA[2]; x[15] = SIGMA[3];
    for (i = 0; i < 4; i++) {
        x[1 + i] = ts_get_le32(key + 4 * i);
        x[11 + i] = ts_get_le32(key + 16 + 4 * i);
        x[6 + i] = ts_get_le32(in + 4 * i);
    }
}

void ts_hsalsa20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16])
{
    uint32_t x[16];
    static const int idx[8] = {0, 5, 10, 15, 6, 7, 8, 9};
    int i;
    salsa_setup(x, key, in);
    salsa_rounds(x);
    for (i = 0; i < 8; i++) ts_put_le32(out + 4 * i, x[idx[i]]);
    ts_wipe(x, sizeof x);
}

/* One 64-byte Salsa20 block for the 8-byte nonce and block counter. */
static void salsa_block(uint8_t out[64], const uint8_t key[32],
                        const uint8_t nonce8[8], uint64_t counter)
{
    uint32_t x[16], in[16];
    uint8_t iv[16];
    int i;
    memcpy(iv, nonce8, 8);
    ts_put_le64(iv + 8, counter);
    salsa_setup(x, key, iv);
    for (i = 0; i < 16; i++) in[i] = x[i];
    salsa_rounds(x);
    for (i = 0; i < 16; i++) ts_put_le32(out + 4 * i, x[i] + in[i]);
    ts_wipe(x, sizeof x);
    ts_wipe(in, sizeof in);
    ts_wipe(iv, sizeof iv);
}

/* XOR the Salsa20 stream, starting at stream offset 32, into dst from src.
 * src may equal dst. The first 32 stream bytes go to polykey. */
static void xsalsa_stream(uint8_t polykey[32], uint8_t *dst, const uint8_t *src,
                          size_t len, const uint8_t key[32], const uint8_t nonce[24])
{
    uint8_t sub[32], blk[64];
    uint64_t ctr = 0;
    size_t i, n;

    ts_hsalsa20(sub, key, nonce);
    salsa_block(blk, sub, nonce + 16, ctr++);
    memcpy(polykey, blk, 32);
    n = len < 32 ? len : 32;
    for (i = 0; i < n; i++) dst[i] = (uint8_t)(src[i] ^ blk[32 + i]);
    while (n < len) {
        size_t j, m = len - n < 64 ? len - n : 64;
        salsa_block(blk, sub, nonce + 16, ctr++);
        for (j = 0; j < m; j++) dst[n + j] = (uint8_t)(src[n + j] ^ blk[j]);
        n += m;
    }
    ts_wipe(sub, sizeof sub);
    ts_wipe(blk, sizeof blk);
}

void ts_secretbox_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *m, size_t mlen)
{
    uint8_t pk[32];
    xsalsa_stream(pk, out + 16, m, mlen, key, nonce);
    ts_poly1305(out, pk, out + 16, mlen);
    ts_wipe(pk, sizeof pk);
}

int ts_secretbox_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t *c, size_t clen)
{
    uint8_t pk[32], calc[16], tag[16], diff = 0, zero[1];
    size_t mlen, i;

    if (clen < 16) return -1;
    mlen = clen - 16;
    memcpy(tag, c, 16);
    /* Derive the Poly1305 key only (nothing is decrypted yet). */
    xsalsa_stream(pk, zero, zero, 0, key, nonce);
    ts_poly1305(calc, pk, c + 16, mlen);
    for (i = 0; i < 16; i++) diff |= (uint8_t)(calc[i] ^ tag[i]);
    ts_wipe(calc, sizeof calc);
    ts_wipe(tag, sizeof tag);
    ts_wipe(pk, sizeof pk);
    if (diff != 0) {
        ts_wipe(out, mlen);
        return -1;
    }
    xsalsa_stream(pk, out, c + 16, mlen, key, nonce);
    ts_wipe(pk, sizeof pk);
    return 0;
}

int ts_box_beforenm(uint8_t k[32], const uint8_t their_pub[32], const uint8_t my_priv[32])
{
    uint8_t shared[32], zero[16];
    if (ts_x25519(shared, my_priv, their_pub) != 0) return -1;
    memset(zero, 0, sizeof zero);
    ts_hsalsa20(k, shared, zero);
    ts_wipe(shared, sizeof shared);
    return 0;
}

int ts_box_seal(uint8_t *out, const uint8_t nonce[24], const uint8_t their_pub[32],
                const uint8_t my_priv[32], const uint8_t *m, size_t mlen)
{
    uint8_t k[32];
    if (ts_box_beforenm(k, their_pub, my_priv) != 0) return -1;
    ts_secretbox_seal(out, k, nonce, m, mlen);
    ts_wipe(k, sizeof k);
    return 0;
}

int ts_box_open(uint8_t *out, const uint8_t nonce[24], const uint8_t their_pub[32],
                const uint8_t my_priv[32], const uint8_t *c, size_t clen)
{
    uint8_t k[32];
    int r;
    if (clen < 16) return -1;
    if (ts_box_beforenm(k, their_pub, my_priv) != 0) {
        ts_wipe(out, clen - 16);
        return -1;
    }
    r = ts_secretbox_open(out, k, nonce, c, clen);
    ts_wipe(k, sizeof k);
    return r;
}
