#include "xaead.h"
#include "aead.h"
#include "../core/bytes.h"
#include <string.h>

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)                                  \
    do {                                                \
        a += b; d ^= a; d = ROTL(d, 16);                \
        c += d; b ^= c; b = ROTL(b, 12);                \
        a += b; d ^= a; d = ROTL(d, 8);                 \
        c += d; b ^= c; b = ROTL(b, 7);                 \
    } while (0)

void ts_hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[16])
{
    uint32_t x[16];
    int i;
    x[0] = 0x61707865u; x[1] = 0x3320646eu; x[2] = 0x79622d32u; x[3] = 0x6b206574u;
    for (i = 0; i < 8; i++) x[4 + i] = ts_get_le32(key + 4 * i);
    for (i = 0; i < 4; i++) x[12 + i] = ts_get_le32(nonce + 4 * i);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 4; i++) {
        ts_put_le32(out + 4 * i, x[i]);
        ts_put_le32(out + 16 + 4 * i, x[12 + i]);
    }
    ts_wipe(x, sizeof x);
}

static void xnonce(uint8_t sub[32], uint8_t n12[12], const uint8_t key[32],
                   const uint8_t nonce[24])
{
    ts_hchacha20(sub, key, nonce);
    memset(n12, 0, 4);
    memcpy(n12 + 4, nonce + 16, 8);
}

void ts_xaead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                   const uint8_t *ad, size_t adlen,
                   const uint8_t *pt, size_t ptlen)
{
    uint8_t sub[32], n12[12];
    xnonce(sub, n12, key, nonce);
    ts_aead_seal(out, sub, n12, ad, adlen, pt, ptlen);
    ts_wipe(sub, sizeof sub);
}

int ts_xaead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *ct, size_t ctlen)
{
    uint8_t sub[32], n12[12];
    int r;
    xnonce(sub, n12, key, nonce);
    r = ts_aead_open(out, sub, n12, ad, adlen, ct, ctlen);
    ts_wipe(sub, sizeof sub);
    return r;
}
