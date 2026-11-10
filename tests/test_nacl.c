#include "harness.h"
#include <string.h>
#include "../src/crypto/nacl.h"
#include "../src/crypto/xaead.h"

static const char *PT_TXT =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

static const char *SB_MSG =
    "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705";
static const char *SB_OUT =
    "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5";

static void test_poly(void)
{
    uint8_t key[32], tag[16];
    const char *m = "Cryptographic Forum Research Group";
    t_unhex(key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    ts_poly1305(tag, key, (const uint8_t *)m, strlen(m));
    t_hex("poly1305 rfc8439", tag, 16, "a8061dc1305136c6c22b8baf0c0127a9");
    /* RFC 8439 appendix A.3, vectors 5 to 11: carry and reduction edge cases. */
    static const struct { const char *key, *data, *tag; } v[] = {
        /* #5 */ { "0200000000000000000000000000000000000000000000000000000000000000",
          "ffffffffffffffffffffffffffffffff",
          "03000000000000000000000000000000" },
        /* #6 */ { "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
          "02000000000000000000000000000000",
          "03000000000000000000000000000000" },
        /* #7 */ { "0100000000000000000000000000000000000000000000000000000000000000",
          "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
          "05000000000000000000000000000000" },
        /* #8 */ { "0100000000000000000000000000000000000000000000000000000000000000",
          "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101",
          "00000000000000000000000000000000" },
        /* #9 */ { "0200000000000000000000000000000000000000000000000000000000000000",
          "fdffffffffffffffffffffffffffffff",
          "faffffffffffffffffffffffffffffff" },
        /* #10 */ { "0100000000000000040000000000000000000000000000000000000000000000",
          "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000",
          "14000000000000005500000000000000" },
        /* #11 */ { "0100000000000000040000000000000000000000000000000000000000000000",
          "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000",
          "13000000000000000000000000000000" },
    };
    size_t i;
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t k2[32], d2[64], t2[16];
        size_t n = strlen(v[i].data) / 2;
        t_unhex(k2, v[i].key);
        t_unhex(d2, v[i].data);
        ts_poly1305(t2, k2, d2, n);
        t_hex("poly1305 a.3 vector", t2, 16, v[i].tag);
    }
}

static void test_box(void)
{
    uint8_t apriv[32], bpub[32], bpriv[32], apub[32], k[32], k2[32], nonce[24];
    uint8_t m[131], out[147], out2[147], back[131], bad[147], zero[32];
    size_t i;

    t_unhex(apriv, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    t_unhex(bpub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    t_unhex(bpriv, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    t_unhex(apub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    t_unhex(nonce, "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
    t_unhex(m, SB_MSG);
    memset(zero, 0, sizeof zero);

    t_true("beforenm ok", ts_box_beforenm(k, bpub, apriv) == 0);
    t_hex("beforenm", k, 32, "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
    t_true("beforenm symmetric", ts_box_beforenm(k2, apub, bpriv) == 0 && memcmp(k, k2, 32) == 0);
    t_true("beforenm rejects zero", ts_box_beforenm(k2, zero, apriv) == -1);

    ts_secretbox_seal(out, k, nonce, m, 131);
    t_hex("secretbox", out, 147, SB_OUT);
    memset(back, 0, sizeof back);
    t_true("secretbox open", ts_secretbox_open(back, k, nonce, out, 147) == 0);
    t_true("secretbox round trip", memcmp(back, m, 131) == 0);
    memcpy(bad, out, 147);
    bad[100] ^= 1;
    t_true("secretbox flip rejected", ts_secretbox_open(back, k, nonce, bad, 147) == -1);
    {
        uint8_t z = 0;
        for (i = 0; i < 131; i++) z |= back[i];
        t_true("secretbox failure wipes", z == 0);
    }
    memcpy(bad, out, 147);
    bad[3] ^= 0x80;
    t_true("secretbox tag flip rejected", ts_secretbox_open(back, k, nonce, bad, 147) == -1);
    t_true("secretbox short", ts_secretbox_open(back, k, nonce, out, 15) == -1);
    t_true("secretbox empty", ts_secretbox_open(back, k, nonce, out, 0) == -1);

    /* empty message and in-place use */
    ts_secretbox_seal(out2, k, nonce, m, 0);
    t_true("secretbox empty msg open", ts_secretbox_open(back, k, nonce, out2, 16) == 0);
    memcpy(out2 + 16, m, 131);
    ts_secretbox_seal(out2, k, nonce, out2 + 16, 131);
    t_true("secretbox in place seal", memcmp(out2, out, 147) == 0);
    ts_secretbox_open(out2 + 16, k, nonce, out2, 147);
    t_true("secretbox in place open", memcmp(out2 + 16, m, 131) == 0);

    t_true("box seal ok", ts_box_seal(out2, nonce, bpub, apriv, m, 131) == 0);
    t_hex("box seal", out2, 147, SB_OUT);
    memset(back, 0, sizeof back);
    t_true("box open ok", ts_box_open(back, nonce, apub, bpriv, out2, 147) == 0);
    t_true("box round trip", memcmp(back, m, 131) == 0);
    out2[50] ^= 1;
    t_true("box flip rejected", ts_box_open(back, nonce, apub, bpriv, out2, 147) == -1);
    t_true("box short", ts_box_open(back, nonce, apub, bpriv, out2, 10) == -1);
    t_true("box bad key", ts_box_seal(out2, nonce, zero, apriv, m, 131) == -1);
}

static void test_xchacha(void)
{
    uint8_t key[32], sub[32], hn[16], nonce[24], ad[12], pt[114], ct[130], back[114], bad[130];
    size_t i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    for (i = 0; i < 16; i++) hn[i] = (uint8_t)(0x40 + i);
    for (i = 0; i < 24; i++) nonce[i] = (uint8_t)(0x40 + i);
    t_unhex(ad, "50515253c0c1c2c3c4c5c6c7");
    memcpy(pt, PT_TXT, 114);

    ts_hchacha20(sub, key, hn);
    t_hex("hchacha20", sub, 32, "4a8ac0c0296222bafe959faabe06a45b89a3cee444fef6e3d77659a53f49ee32");

    ts_xaead_seal(ct, key, nonce, ad, sizeof ad, pt, 114);
    t_hex("xaead seal", ct, 130,
          "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49");
    t_true("xaead open", ts_xaead_open(back, key, nonce, ad, sizeof ad, ct, 130) == 0);
    t_true("xaead round trip", memcmp(back, pt, 114) == 0);
    memcpy(bad, ct, 130);
    bad[7] ^= 1;
    t_true("xaead flip rejected", ts_xaead_open(back, key, nonce, ad, sizeof ad, bad, 130) == -1);
    t_true("xaead short", ts_xaead_open(back, key, nonce, ad, sizeof ad, ct, 15) == -1);
}

void test_nacl(void)
{
    test_poly();
    test_box();
    test_xchacha();
}
