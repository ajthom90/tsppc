#include "harness.h"

#include <stdint.h>
#include <string.h>

#include "../src/core/bytes.h"
#include "../src/crypto/aead.h"
#include "../src/crypto/blake2s.h"
#include "../src/crypto/x25519.h"
#include "../src/wg/handshake.h"

#include "wg_vectors.inc"

/* ---- Fixtures ------------------------------------------------------------ */

static ts_wg_static I, R;
static uint8_t SS[32], I_EPH[32], R_EPH[32], I_EPH2[32], TS[12], TS2[12];
static uint8_t INIT[TS_WG_INIT_LEN], RESP[TS_WG_RESP_LEN], COOKIE_REPLY[TS_WG_COOKIE_LEN];

static void fixtures(void)
{
    uint8_t k[32];
    t_unhex(k, WGV_I_STATIC_PRIV);
    ts_wg_static_init(&I, k);
    t_unhex(k, WGV_R_STATIC_PRIV);
    ts_wg_static_init(&R, k);
    t_unhex(SS, WGV_SS);
    t_unhex(I_EPH, WGV_I_EPH_PRIV);
    t_unhex(R_EPH, WGV_R_EPH_PRIV);
    t_unhex(I_EPH2, WGV_I_EPH2_PRIV);
    t_unhex(TS, WGV_TAI64N);
    t_unhex(TS2, WGV_TAI64N2);
    t_unhex(INIT, WGV_INIT);
    t_unhex(RESP, WGV_RESP);
    t_unhex(COOKIE_REPLY, WGV_COOKIE_REPLY);
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* mac1 over msg[0..len), keyed by a receiver's mac1 key. */
static void set_mac1(uint8_t *msg, size_t len, const uint8_t key[32])
{
    ts_blake2s_ctx c;
    if (ts_blake2s_init(&c, 16, key, 32) != 0) return;
    ts_blake2s_update(&c, msg, len);
    ts_blake2s_final(&c, msg + len);
}

/* ---- Vectors ------------------------------------------------------------- */

static void test_wg_vectors(void)
{
    ts_wg_hs hi, hr, h2;
    uint8_t out[TS_WG_INIT_LEN], resp[TS_WG_RESP_LEN], peer[32], ts[12], ss[32];
    uint8_t is[32], ir[32], rs[32], rr[32], cookie[16], pay[16], msg[48], back[16], nonce[12];
    uint32_t idx = 0;

    t_hex("wg static pub I", I.pub, 32, WGV_I_STATIC_PUB);
    t_hex("wg static pub R", R.pub, 32, WGV_R_STATIC_PUB);
    t_true("wg ss", ts_x25519(ss, I.priv, R.pub) == 0 && memcmp(ss, SS, 32) == 0);
    t_true("wg ss mirrored", ts_x25519(ss, R.priv, I.pub) == 0 && memcmp(ss, SS, 32) == 0);
    ts_wg_tai64n(ts, WGV_TS_SEC, WGV_TS_NSEC);
    t_hex("wg tai64n vector", ts, 12, WGV_TAI64N);

    /* Initiator writes the initiation. */
    memset(&hi, 0xee, sizeof hi);
    t_true("wg create_init", ts_wg_create_init(&hi, &I, R.pub, SS, WGV_I_INDEX, I_EPH, TS, NULL, out) == 0);
    t_hex("wg initiation", out, sizeof out, WGV_INIT);

    /* Responder reads it. */
    memset(&hr, 0xee, sizeof hr);
    t_true("wg open_static", ts_wg_init_open_static(&hr, &R, INIT, peer) == 0);
    t_hex("wg open_static peer", peer, 32, WGV_I_STATIC_PUB);
    t_true("wg init_finish", ts_wg_init_finish(&hr, SS, ts, &idx) == 0);
    t_hex("wg init_finish ts", ts, 12, WGV_TAI64N);
    t_true("wg init_finish index", idx == WGV_I_INDEX);

    /* Responder writes the response; initiator reads it. */
    t_true("wg create_resp", ts_wg_create_resp(&hr, WGV_R_INDEX, R_EPH, NULL, resp) == 0);
    t_hex("wg response", resp, sizeof resp, WGV_RESP);
    idx = 0;
    t_true("wg consume_resp", ts_wg_consume_resp(&hi, &I, RESP, &idx) == 0);
    t_true("wg consume_resp index", idx == WGV_R_INDEX);

    /* Transport keys, and the handshake state is wiped. */
    ts_wg_derive(&hi, 1, is, ir);
    ts_wg_derive(&hr, 0, rs, rr);
    t_hex("wg initiator send", is, 32, WGV_I_SEND);
    t_hex("wg initiator recv", ir, 32, WGV_I_RECV);
    t_hex("wg responder send", rs, 32, WGV_R_SEND);
    t_hex("wg responder recv", rr, 32, WGV_R_RECV);
    t_true("wg derive wipes initiator", all_zero(hi.ck, 32) && all_zero(hi.h, 32) &&
           all_zero(hi.eph_priv, 32) && hi.state == 0);
    t_true("wg derive wipes responder", all_zero(hr.ck, 32) && all_zero(hr.h, 32) &&
           all_zero(hr.remote_eph, 32) && hr.state == 0);
    ts_wg_derive(&hi, 1, is, ir);
    t_true("wg derive twice gives zero keys", all_zero(is, 32) && all_zero(ir, 32));
    t_unhex(is, WGV_I_SEND);
    t_unhex(rr, WGV_R_RECV);

    /* One transport message, 3 bytes padded to 16, counter 0. */
    memset(pay, 0, sizeof pay);
    t_unhex(pay, WGV_PAYLOAD);
    ts_put_le32(msg, 4);
    ts_put_le32(msg + 4, WGV_R_INDEX);
    ts_put_le64(msg + 8, WGV_TRANSPORT_COUNTER);
    memset(nonce, 0, 4);
    ts_put_le64(nonce + 4, WGV_TRANSPORT_COUNTER);
    ts_aead_seal(msg + TS_WG_TRANSPORT_HDR, is, nonce, NULL, 0, pay, sizeof pay);
    t_hex("wg transport", msg, sizeof msg, WGV_TRANSPORT);
    t_true("wg transport opens", ts_aead_open(back, rr, nonce, NULL, 0, msg + 16, 32) == 0 &&
           memcmp(back, pay, 16) == 0);

    /* Cookie reply to the first initiation, then an initiation with mac2. */
    t_true("wg cookie_open", ts_wg_cookie_open(cookie, R.pub, INIT + 116, COOKIE_REPLY) == 0);
    t_hex("wg cookie", cookie, 16, WGV_COOKIE);
    t_true("wg create_init with cookie",
           ts_wg_create_init(&h2, &I, R.pub, SS, WGV_I_INDEX2, I_EPH2, TS2, cookie, out) == 0);
    t_hex("wg initiation with mac2", out, sizeof out, WGV_INIT2);
    t_true("wg open_static with mac2", ts_wg_init_open_static(&hr, &R, out, peer) == 0);
    t_true("wg init_finish with mac2", ts_wg_init_finish(&hr, SS, ts, &idx) == 0 &&
           idx == WGV_I_INDEX2 && memcmp(ts, TS2, 12) == 0);
    ts_wg_derive(&h2, 1, is, ir);   /* only wipes: no response yet */
    t_true("wg derive incomplete zero", all_zero(is, 32) && all_zero(ir, 32) && all_zero(h2.eph_priv, 32));
    ts_wg_derive(&hr, 0, is, ir);
}

/* ---- Rejections ---------------------------------------------------------- */

static void test_wg_reject(void)
{
    ts_wg_hs hi, hr, hcopy;
    uint8_t m[TS_WG_INIT_LEN], r[TS_WG_RESP_LEN], peer[32], ts[12], ss[32], cookie[16], mac[16];
    uint8_t zero[32], out[TS_WG_INIT_LEN];
    uint32_t idx;

    memset(zero, 0, sizeof zero);

    /* A bad mac1, and a bad type. */
    memcpy(m, INIT, sizeof m);
    m[120] ^= 0x01;
    t_true("wg reject bad mac1", ts_wg_init_open_static(&hr, &R, m, peer) == -1);
    t_true("wg reject bad mac1 wipes", hr.state == 0 && all_zero(hr.ck, 32));
    memcpy(m, INIT, sizeof m);
    set_mac1(m, 116, I.mac1_key);
    t_true("wg reject mac1 for another key", ts_wg_init_open_static(&hr, &R, m, peer) == -1);
    memcpy(m, INIT, sizeof m);
    m[0] = 2;
    set_mac1(m, 116, R.mac1_key);
    t_true("wg reject init type 2", ts_wg_init_open_static(&hr, &R, m, peer) == -1);
    memcpy(m, INIT, sizeof m);
    m[1] = 1;
    set_mac1(m, 116, R.mac1_key);
    t_true("wg reject init reserved byte", ts_wg_init_open_static(&hr, &R, m, peer) == -1);
    memcpy(m, INIT, sizeof m);
    m[3] |= 0x80;   /* upstream's retry hint: masked, so accepted */
    set_mac1(m, 116, R.mac1_key);
    t_true("wg accept init retry bit", ts_wg_init_open_static(&hr, &R, m, peer) == 0);

    /* One flipped bit in the encrypted static, with a valid mac1. */
    memcpy(m, INIT, sizeof m);
    m[50] ^= 0x10;
    set_mac1(m, 116, R.mac1_key);
    t_true("wg reject flipped static", ts_wg_init_open_static(&hr, &R, m, peer) == -1);
    t_true("wg reject flipped static zeroes peer", all_zero(peer, 32));

    /* A bad timestamp tag, with a valid mac1. */
    memcpy(m, INIT, sizeof m);
    m[110] ^= 0x01;
    set_mac1(m, 116, R.mac1_key);
    t_true("wg bad ts tag opens static", ts_wg_init_open_static(&hr, &R, m, peer) == 0);
    t_true("wg reject bad ts tag", ts_wg_init_finish(&hr, SS, ts, &idx) == -1);
    t_true("wg reject bad ts tag wipes", hr.state == 0 && all_zero(hr.ck, 32));

    /* The wrong ss, and an all-zero ss. */
    memcpy(ss, SS, 32);
    ss[0] ^= 1;
    t_true("wg open for wrong ss", ts_wg_init_open_static(&hr, &R, INIT, peer) == 0);
    t_true("wg reject wrong ss", ts_wg_init_finish(&hr, ss, ts, &idx) == -1);
    t_true("wg open for zero ss", ts_wg_init_open_static(&hr, &R, INIT, peer) == 0);
    t_true("wg reject zero ss", ts_wg_init_finish(&hr, zero, ts, &idx) == -1);
    t_true("wg reject create_init zero ss",
           ts_wg_create_init(&hi, &I, R.pub, zero, 1, I_EPH, TS, NULL, out) == -1 && all_zero(out, sizeof out));
    t_true("wg reject create_init low-order peer",
           ts_wg_create_init(&hi, &I, zero, SS, 1, I_EPH, TS, NULL, out) == -1 && hi.state == 0);

    /* Out-of-order calls. */
    memset(&hr, 0, sizeof hr);
    t_true("wg reject finish before open", ts_wg_init_finish(&hr, SS, ts, &idx) == -1);
    t_true("wg reject resp before finish", ts_wg_create_resp(&hr, 1, R_EPH, NULL, r) == -1);
    t_true("wg open again", ts_wg_init_open_static(&hr, &R, INIT, peer) == 0);
    t_true("wg reject resp before finish 2", ts_wg_create_resp(&hr, 1, R_EPH, NULL, r) == -1);
    t_true("wg reject consume on responder", ts_wg_consume_resp(&hr, &R, RESP, &idx) == -1);

    /* A response to the wrong index (valid mac1); the pending handshake
     * survives every rejected response. */
    t_true("wg init for resp",
           ts_wg_create_init(&hi, &I, R.pub, SS, WGV_I_INDEX, I_EPH, TS, NULL, out) == 0);
    hcopy = hi;
    memcpy(r, RESP, sizeof r);
    ts_put_le32(r + 8, WGV_I_INDEX + 1);
    set_mac1(r, 60, I.mac1_key);
    t_true("wg reject resp wrong index", ts_wg_consume_resp(&hi, &I, r, &idx) == -1);
    memcpy(r, RESP, sizeof r);
    r[62] ^= 0x04;
    t_true("wg reject resp bad mac1", ts_wg_consume_resp(&hi, &I, r, &idx) == -1);
    memcpy(r, RESP, sizeof r);
    r[50] ^= 0x01;
    set_mac1(r, 60, I.mac1_key);
    t_true("wg reject resp bad empty tag", ts_wg_consume_resp(&hi, &I, r, &idx) == -1);
    memcpy(r, RESP, sizeof r);
    r[20] ^= 0x01;
    set_mac1(r, 60, I.mac1_key);
    t_true("wg reject resp other ephemeral", ts_wg_consume_resp(&hi, &I, r, &idx) == -1);
    memcpy(r, RESP, sizeof r);
    r[0] = 1;
    set_mac1(r, 60, I.mac1_key);
    t_true("wg reject resp type 1", ts_wg_consume_resp(&hi, &I, r, &idx) == -1);
    t_true("wg rejected resp leaves hs", memcmp(&hi, &hcopy, sizeof hi) == 0);
    t_true("wg genuine resp after rejects", ts_wg_consume_resp(&hi, &I, RESP, &idx) == 0 &&
           idx == WGV_R_INDEX);
    t_true("wg reject second resp", ts_wg_consume_resp(&hi, &I, RESP, &idx) == -1);
    {
        uint8_t k1[32], k2[32];
        ts_wg_derive(&hi, 1, k1, k2);   /* just wipe; keys are checked above */
        ts_wg_derive(&hr, 0, k1, k2);
    }

    /* A cookie reply with the wrong mac1, or under the wrong key. */
    memcpy(mac, INIT + 116, 16);
    mac[0] ^= 1;
    memset(cookie, 0xaa, sizeof cookie);
    t_true("wg reject cookie wrong mac1", ts_wg_cookie_open(cookie, R.pub, mac, COOKIE_REPLY) == -1);
    t_true("wg reject cookie zeroes", all_zero(cookie, 16));
    t_true("wg reject cookie wrong peer", ts_wg_cookie_open(cookie, I.pub, INIT + 116, COOKIE_REPLY) == -1);
    {
        uint8_t c[TS_WG_COOKIE_LEN];
        memcpy(c, COOKIE_REPLY, sizeof c);
        c[0] = 4;
        t_true("wg reject cookie type", ts_wg_cookie_open(cookie, R.pub, INIT + 116, c) == -1);
        memcpy(c, COOKIE_REPLY, sizeof c);
        c[63] ^= 1;
        t_true("wg reject cookie tag", ts_wg_cookie_open(cookie, R.pub, INIT + 116, c) == -1);
    }
}

/* ---- TAI64N -------------------------------------------------------------- */

static void test_tai64n(void)
{
    uint8_t t[12];
    ts_wg_tai64n(t, 0, 0);
    t_hex("tai64n epoch", t, 12, "400000000000000a00000000");
    ts_wg_tai64n(t, 0, 0xffffffffu);
    t_hex("tai64n nsec high byte only", t, 12, "400000000000000aff000000");
    ts_wg_tai64n(t, 0, 0x00ffffffu);
    t_hex("tai64n nsec low bits cleared", t, 12, "400000000000000a00000000");
    ts_wg_tai64n(t, 1, 999999999u);
    t_hex("tai64n one second", t, 12, "400000000000000b3b000000");
    ts_wg_tai64n(t, -1, 0);
    t_hex("tai64n before epoch", t, 12, "400000000000000900000000");
}

void test_wg(void)
{
    fixtures();
    test_wg_vectors();
    test_wg_reject();
    test_tai64n();
}
