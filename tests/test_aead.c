#include "harness.h"
#include <string.h>
#include "../src/crypto/x25519.h"
#include "../src/crypto/aead.h"
#include "../src/crypto/random.h"

static const char *PT_TXT =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

static int all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static void test_x25519(void)
{
    uint8_t k[32], peer[32], o[32], zero32[32], low[32];
    memset(zero32, 0, sizeof zero32);
    memset(low, 0, sizeof low); low[0] = 1;
    t_unhex(k, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    ts_x25519_public(o, k);
    t_hex("x25519 public", o, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    t_unhex(peer, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    /* out may be the same buffer as the scalar. */
    memcpy(o, k, sizeof o);
    ts_x25519_public(o, o);
    t_hex("x25519 public out == priv", o, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    t_true("x25519 shared ok", ts_x25519(o, k, peer) == 0);
    t_hex("x25519 shared", o, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    t_true("x25519 rejects zero", ts_x25519(o, k, zero32) == -1);
    t_true("x25519 rejects low order", ts_x25519(o, k, low) == -1);
    memset(o, 0xaa, sizeof o);
    t_true("x25519 zero rejected again", ts_x25519(o, k, zero32) == -1);
    t_true("x25519 rejection wipes out", all_zero(o, sizeof o));
    memset(o, 0xaa, sizeof o);
    t_true("x25519 low order rejected again", ts_x25519(o, k, low) == -1);
    t_true("x25519 low order rejection wipes out", all_zero(o, sizeof o));
    /* out may be the same buffer as the scalar. */
    memcpy(o, k, sizeof o);
    t_true("x25519 out == priv ok", ts_x25519(o, o, peer) == 0);
    t_hex("x25519 out == priv", o, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}

static void test_chacha(void)
{
    uint8_t key[32], nonce[12], ad[12];
    uint8_t pt[114], ct[130], ct2[130], back[114], buf[130], raw1[140], raw2[140];
    uint8_t *op, *oo, bad[130];
    size_t i, ptlen = strlen(PT_TXT);
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    t_unhex(nonce, "070000004041424344454647");
    t_unhex(ad, "50515253c0c1c2c3c4c5c6c7");
    t_true("pt len", ptlen == 114);
    memcpy(pt, PT_TXT, 114);

    ts_aead_seal(ct, key, nonce, ad, sizeof ad, pt, 114);
    t_hex("seal ct start", ct, 16, "d31a8d34648e60db7b86afbc53ef7ec2");
    t_hex("seal tag", ct + 114, 16, "1ae10b594f09e26a7e902ecbd0600691");

    memset(back, 0, sizeof back);
    t_true("open ok", ts_aead_open(back, key, nonce, ad, sizeof ad, ct, 130) == 0);
    t_true("open round trip", memcmp(back, pt, 114) == 0);

    for (i = 0; i < 3; i++) {
        size_t pos = i == 0 ? 5 : 114 + 3;
        memcpy(bad, ct, 130);
        memset(back, 0, sizeof back);
        if (i < 2) {
            bad[pos] ^= 1;
            t_true(i == 0 ? "flip ct rejected" : "flip tag rejected",
                   ts_aead_open(back, key, nonce, ad, sizeof ad, bad, 130) == -1);
        } else {
            uint8_t ad2[12];
            memcpy(ad2, ad, 12); ad2[4] ^= 1;
            t_true("flip ad rejected",
                   ts_aead_open(back, key, nonce, ad2, sizeof ad2, ct, 130) == -1);
        }
        t_true("failed open wipes out", all_zero(back, 114));
    }

    memcpy(buf, pt, 114);
    ts_aead_seal(buf, key, nonce, ad, sizeof ad, buf, 114);
    t_true("seal in place", memcmp(buf, ct, 130) == 0);
    t_true("open in place", ts_aead_open(buf, key, nonce, ad, sizeof ad, buf, 130) == 0);
    t_true("open in place data", memcmp(buf, pt, 114) == 0);

    memcpy(buf, ct, 130);
    buf[5] ^= 1;
    t_true("tampered in place rejected", ts_aead_open(buf, key, nonce, ad, sizeof ad, buf, 130) == -1);
    t_true("tampered in place wipes", all_zero(buf, 114));

    /* ctlen == 16 (empty plaintext) with non-empty AD. */
    ts_aead_seal(ct2, key, nonce, ad, sizeof ad, NULL, 0);
    t_hex("ad only tag", ct2, 16, "e622e5647a38d967a7ecbcb46c7f675c");
    t_true("ad only open", ts_aead_open(back, key, nonce, ad, sizeof ad, ct2, 16) == 0);
    t_true("ad only without ad rejected", ts_aead_open(back, key, nonce, NULL, 0, ct2, 16) == -1);
    ct2[15] ^= 1;
    t_true("ad only tampered", ts_aead_open(back, key, nonce, ad, sizeof ad, ct2, 16) == -1);

    ts_aead_seal(ct2, key, nonce, NULL, 0, NULL, 0);
    memset(back, 0xaa, sizeof back);
    t_true("empty open", ts_aead_open(back, key, nonce, NULL, 0, ct2, 16) == 0);
    t_true("empty open untouched", back[0] == 0xaa);
    ct2[0] ^= 1;
    t_true("empty tampered", ts_aead_open(back, key, nonce, NULL, 0, ct2, 16) == -1);
    t_true("short input rejected", ts_aead_open(back, key, nonce, NULL, 0, ct, 15) == -1);

    op = raw1 + 1; oo = raw2 + 1;
    memcpy(op, pt, 114);
    ts_aead_seal(oo, key, nonce, ad, sizeof ad, op, 114);
    t_true("odd address seal", memcmp(oo, ct, 130) == 0);
    t_true("odd address open", ts_aead_open(op, key, nonce, ad, sizeof ad, oo, 130) == 0);
    t_true("odd address open data", memcmp(op, pt, 114) == 0);
}

static void test_random(void)
{
    uint8_t a[32], b[32];
    t_true("random a", ts_random_bytes(a, 32) == 0);
    t_true("random b", ts_random_bytes(b, 32) == 0);
    t_true("random differs", memcmp(a, b, 32) != 0);
}

void test_aead(void)
{
    test_x25519();
    test_chacha();
    test_random();
}
