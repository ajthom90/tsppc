#include "aead.h"
#include <string.h>
#include <bearssl_block.h>
#include "../core/bytes.h"

/* br_poly1305_ctmul_run multiplies with variable-time instructions on G3/G4.
 * ctmul32 uses only MUL15, which BR_CT_MUL15 makes constant-time. */
#if defined(__ppc__) || defined(TS_FORCE_CT_POLY)
#if !defined(BR_CT_MUL15) || !BR_CT_MUL15
#error "constant-time Poly1305 requires -DBR_CT_MUL15=1"
#endif
#define TS_POLY1305_RUN br_poly1305_ctmul32_run
#else
#define TS_POLY1305_RUN br_poly1305_ctmul_run
#endif

void ts_aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *pt, size_t ptlen)
{
    if (ptlen > 0 && out != pt) memmove(out, pt, ptlen);
    TS_POLY1305_RUN(key, nonce, out, ptlen, ad, adlen, out + ptlen,
                    br_chacha20_ct_run, 1);
}

int ts_aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *ad, size_t adlen,
                 const uint8_t *ct, size_t ctlen)
{
    uint8_t tag[16], diff = 0;
    size_t ptlen, i;

    if (ctlen < 16) return -1;
    ptlen = ctlen - 16;
    /* Save the received tag first: out may alias ct. */
    memcpy(tag, ct + ptlen, 16);
    if (ptlen > 0 && out != ct) memmove(out, ct, ptlen);
    {
        uint8_t calc[16];
        TS_POLY1305_RUN(key, nonce, out, ptlen, ad, adlen, calc,
                        br_chacha20_ct_run, 0);
        for (i = 0; i < 16; i++) diff |= (uint8_t)(calc[i] ^ tag[i]);
        ts_wipe(calc, sizeof calc);
    }
    ts_wipe(tag, sizeof tag);
    if (diff != 0) {
        ts_wipe(out, ptlen);
        return -1;
    }
    return 0;
}
