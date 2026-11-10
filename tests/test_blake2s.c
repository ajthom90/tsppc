#include <string.h>
#include "harness.h"
#include "../src/crypto/blake2s.h"
#include "../src/crypto/kdf.h"

static void seq(uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) p[i] = (uint8_t)i;
}

static const char *LONG_HEX =
    "6d244e1a06ce4ef578dd0f63aff0936706735119ca9c8d22d86c801414ab9741";

static void t_hex_ok(const uint8_t *got, const char *want_hex, int *all)
{
    uint8_t want[32];
    t_unhex(want, want_hex);
    if (memcmp(got, want, 32) != 0) *all = 0;
}

void test_blake2s(void)
{
    uint8_t s[200], key[32], out[32], t2[32], t3[32], salt[32];
    uint8_t buf[201];
    ts_blake2s_ctx c;
    size_t k;

    seq(s, sizeof s);
    seq(key, sizeof key);
    seq(salt, sizeof salt);

    ts_blake2s(out, "abc", 3);
    t_hex("blake2s abc", out, 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    ts_blake2s(out, "", 0);
    t_hex("blake2s empty", out, 32, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    ts_blake2s(out, s, 64);
    t_hex("blake2s one block", out, 32, "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e");
    ts_blake2s(out, s, 65);
    t_hex("blake2s block+1", out, 32, "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472");
    ts_blake2s(out, s, 200);
    t_hex("blake2s long", out, 32, LONG_HEX);

    t_true("init outlen 0", ts_blake2s_init(&c, 0, NULL, 0) == -1);
    t_true("init outlen 33", ts_blake2s_init(&c, 33, NULL, 0) == -1);
    t_true("init keylen 33", ts_blake2s_init(&c, 32, key, 33) == -1);
    t_true("init keylen 32 ok", ts_blake2s_init(&c, 32, key, 32) == 0);
    t_true("init ok", ts_blake2s_init(&c, 16, key, 32) == 0);
    ts_blake2s_update(&c, "abc", 3);
    ts_blake2s_final(&c, out);
    t_hex("blake2s keyed 16", out, 16, "61ba5f165c194692e09d12520cc4c74a");

    memset(key, 'k', 32);
    if (ts_blake2s_init(&c, 16, key, 32) != 0) t_true("init", 0);
    ts_blake2s_update(&c, s, 200);
    ts_blake2s_final(&c, out);
    t_hex("blake2s keyed long", out, 16, "a74b2926087ee84d2ca3c8402d4e695b");

    {
        int all = 1;
        for (k = 0; k <= 200; k++) {
            if (ts_blake2s_init(&c, 32, NULL, 0) != 0) t_true("init", 0);
            ts_blake2s_update(&c, s, k);
            ts_blake2s_update(&c, s + k, 200 - k);
            ts_blake2s_final(&c, out);
            t_hex_ok(out, LONG_HEX, &all);
        }
        t_true("chunked", all);
    }
    if (ts_blake2s_init(&c, 32, NULL, 0) != 0) t_true("init", 0);
    for (k = 0; k < 200; k++) ts_blake2s_update(&c, s + k, 1);
    ts_blake2s_final(&c, out);
    t_hex("chunked bytewise", out, 32, LONG_HEX);
    memcpy(buf + 1, s, 200);
    ts_blake2s(out, buf + 1, 200);
    t_hex("odd address", out, 32, LONG_HEX);

    ts_hmac_blake2s(out, (const uint8_t *)"key", 3, "data", 4);
    t_hex("hmac", out, 32, "84f646acda0776ee848b7f9dc5771c7d8cf023999c0c3dd84dc78636a146e805");
    seq(key, 32);
    {
        uint8_t k100[100];
        seq(k100, sizeof k100);
        ts_hmac_blake2s(out, k100, 100, "data", 4);
        t_hex("hmac long key", out, 32, "2624e61dfe9fcc84d3137a317c171ced634ef3fcd2fa3f5515940906f4e38c48");
    }

    ts_hkdf2(out, t2, salt, (const uint8_t *)"input key material", 18);
    t_hex("hkdf t1", out, 32, "93e2a65883e34ac95485f5d0aa4b09163a4e944dab8cf9406d3a138e362851c6");
    t_hex("hkdf t2", t2, 32, "dd6fae42afdb2a41170f44dc5b885ec4cfd17c8dd324d38b390c548630dd0a83");
    ts_hkdf3(out, t2, t3, salt, (const uint8_t *)"input key material", 18);
    t_hex("hkdf3 t1", out, 32, "93e2a65883e34ac95485f5d0aa4b09163a4e944dab8cf9406d3a138e362851c6");
    t_hex("hkdf3 t2", t2, 32, "dd6fae42afdb2a41170f44dc5b885ec4cfd17c8dd324d38b390c548630dd0a83");
    t_hex("hkdf3 t3", t3, 32, "4125e0adfa9b7e736615e99dde6f3f0b64b949d8b480e82cab2e685dc286e45d");
    ts_hkdf2(out, t2, salt, NULL, 0);
    t_hex("hkdf empty t1", out, 32, "7a38c34bf2b8738d7374ca77c44ecb309a11d2b2528304fa86052c365e722624");
    t_hex("hkdf empty t2", t2, 32, "1a17621f346abdc520746a9fb64d8eb03231d674fc15687537b0780fd9c060fd");
}
