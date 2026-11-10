/* G3/G4 multiply instructions take variable time; the PowerPC build must use
 * BearSSL's constant-time multiply (set by the ppc-test target). */
#if defined(__ppc__) && (!defined(BR_CT_MUL31) || !BR_CT_MUL31)
#error "PowerPC build requires -DBR_CT_MUL31=1 for constant-time X25519"
#endif

#include "x25519.h"
#include <string.h>
#include <bearssl_ec.h>
#include "../core/bytes.h"

/* BearSSL takes the scalar in the order given here (RFC 7748 little-endian
 * encoding is handled by the c25519 implementation, which also clamps). */

int ts_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32])
{
    const br_ec_impl *ec = &br_ec_c25519_m31;
    uint8_t acc = 0, scalar[32];
    size_t i;
    uint32_t ok;

    /* Read the scalar first: out may alias priv (or pub). */
    memcpy(scalar, priv, 32);
    memmove(out, pub, 32);
    ok = ec->mul(out, 32, scalar, 32, BR_EC_curve25519);
    ts_wipe(scalar, sizeof scalar);
    if (!ok) {
        ts_wipe(out, 32);
        return -1;
    }
    for (i = 0; i < 32; i++) acc |= out[i];
    if (acc == 0) {
        ts_wipe(out, 32);
        return -1;
    }
    return 0;
}

void ts_x25519_public(uint8_t out[32], const uint8_t priv[32])
{
    const br_ec_impl *ec = &br_ec_c25519_m31;
    uint8_t scalar[32];

    /* Read the scalar first: out may alias priv. */
    memcpy(scalar, priv, 32);
    ec->mulgen(out, scalar, 32, BR_EC_curve25519);
    ts_wipe(scalar, sizeof scalar);
}
