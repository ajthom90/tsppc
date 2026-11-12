#include "handshake.h"

#include <stdlib.h>
#include <string.h>

#include "../core/bytes.h"
#include "../crypto/aead.h"
#include "../crypto/blake2s.h"
#include "../crypto/kdf.h"
#include "../crypto/x25519.h"
#include "../crypto/xaead.h"

#define TYPE_INIT 1u
#define TYPE_RESP 2u
#define TYPE_COOKIE 3u
/* tailscale/wireguard-go's retry hint (bit 31 of the type word), masked on
 * receive as upstream's parseTypeField does. */
#define TYPE_MASK 0x7fffffffu

/* Initiation offsets. */
#define I_SENDER 4
#define I_EPH 8
#define I_STATIC 40
#define I_TS 88
#define I_MAC1 116
#define I_MAC2 132
/* Response offsets. */
#define R_SENDER 4
#define R_RECEIVER 8
#define R_EPH 12
#define R_EMPTY 44
#define R_MAC1 60
#define R_MAC2 76
/* Cookie reply offsets. */
#define C_NONCE 8
#define C_COOKIE 32

/* Handshake states (ts_wg_hs.state). 0 is empty or wiped. */
#define HS_EMPTY 0
#define HS_INIT_SENT 1       /* initiator: initiation created */
#define HS_STATIC_OPENED 2   /* responder: static decrypted, timestamp pending */
#define HS_INIT_CONSUMED 3   /* responder: timestamp decrypted */
#define HS_RESP_CREATED 4    /* responder: complete */
#define HS_RESP_CONSUMED 5   /* initiator: complete */

static const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char LABEL_MAC1[] = "mac1----";
static const char LABEL_COOKIE[] = "cookie--";

static const uint8_t ZERO_NONCE[12];
static const uint8_t ZERO_PSK[32];

/* ---- Primitives ---------------------------------------------------------- */

/* out = BLAKE2s(a || b) */
static void hash2(uint8_t out[32], const void *a, size_t alen, const void *b, size_t blen)
{
    ts_blake2s_ctx c;
    if (ts_blake2s_init(&c, 32, NULL, 0) != 0) abort();   /* fixed valid parameters */
    ts_blake2s_update(&c, a, alen);
    ts_blake2s_update(&c, b, blen);
    ts_blake2s_final(&c, out);
}

static void mix_hash(uint8_t h[32], const uint8_t *data, size_t len)
{
    hash2(h, h, 32, data, len);
}

/* ck = HKDF1(ck, data) */
static void mix_key(uint8_t ck[32], const uint8_t *data, size_t len)
{
    uint8_t t1[32], t2[32];
    ts_hkdf2(t1, t2, ck, data, len);
    memcpy(ck, t1, 32);
    ts_wipe(t1, sizeof t1);
    ts_wipe(t2, sizeof t2);
}

/* (ck, k) = HKDF2(ck, dh) */
static void mix_key2(uint8_t ck[32], uint8_t k[32], const uint8_t dh[32])
{
    uint8_t t1[32];
    ts_hkdf2(t1, k, ck, dh, 32);
    memcpy(ck, t1, 32);
    ts_wipe(t1, sizeof t1);
}

/* 16-byte keyed BLAKE2s: mac1 (32-byte key) and mac2 (16-byte cookie). */
static void mac16(uint8_t out[16], const uint8_t *key, size_t keylen, const uint8_t *msg, size_t len)
{
    ts_blake2s_ctx c;
    if (ts_blake2s_init(&c, 16, key, keylen) != 0) abort();
    ts_blake2s_update(&c, msg, len);
    ts_blake2s_final(&c, out);
}

static void label_key(uint8_t out[32], const char *label, const uint8_t pub[32])
{
    hash2(out, label, 8, pub, 32);
}

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= p[i];
    return d == 0;
}

/* ck and h at the start of every handshake, then mixed with the responder's
 * static public key. */
static void initial(uint8_t ck[32], uint8_t h[32], const uint8_t responder_pub[32])
{
    ts_blake2s(ck, CONSTRUCTION, sizeof CONSTRUCTION - 1);
    hash2(h, ck, 32, IDENTIFIER, sizeof IDENTIFIER - 1);
    mix_hash(h, responder_pub, 32);
}

/* mac1 keyed by the receiver's public key; mac2 by the cookie, or zero. */
static void add_macs(uint8_t *msg, size_t mac1_at, const uint8_t receiver_pub[32],
                     const uint8_t *cookie16)
{
    uint8_t key[32];
    label_key(key, LABEL_MAC1, receiver_pub);
    mac16(msg + mac1_at, key, 32, msg, mac1_at);
    ts_wipe(key, sizeof key);
    if (cookie16) mac16(msg + mac1_at + 16, cookie16, 16, msg, mac1_at + 16);
    else memset(msg + mac1_at + 16, 0, 16);
}

static int check_mac1(const uint8_t *msg, size_t mac1_at, const uint8_t key[32])
{
    uint8_t mac[16];
    int ok;
    mac16(mac, key, 32, msg, mac1_at);
    ok = ct_eq(mac, msg + mac1_at, 16);
    ts_wipe(mac, sizeof mac);
    return ok;
}

static void wipe_hs(ts_wg_hs *hs)
{
    ts_wipe(hs, sizeof *hs);
}

/* ---- Public -------------------------------------------------------------- */

void ts_wg_static_init(ts_wg_static *me, const uint8_t priv[32])
{
    memcpy(me->priv, priv, 32);
    ts_x25519_public(me->pub, priv);
    label_key(me->mac1_key, LABEL_MAC1, me->pub);
    label_key(me->cookie_key, LABEL_COOKIE, me->pub);
}

void ts_wg_tai64n(uint8_t out[12], int64_t unix_sec, uint32_t nsec)
{
    ts_put_be64(out, 0x400000000000000aull + (uint64_t)unix_sec);
    ts_put_be32(out + 8, nsec & ~(uint32_t)0x00ffffffu);
}

int ts_wg_create_init(ts_wg_hs *hs, const ts_wg_static *me, const uint8_t peer_pub[32],
                      const uint8_t ss[32], uint32_t sender_index, const uint8_t eph_priv[32],
                      const uint8_t tai64n[12], const uint8_t *cookie16, uint8_t out[TS_WG_INIT_LEN])
{
    uint8_t dh[32], k[32];
    int rc = -1;

    wipe_hs(hs);
    memset(out, 0, TS_WG_INIT_LEN);
    if (all_zero(ss, 32)) goto out;

    initial(hs->ck, hs->h, peer_pub);
    memcpy(hs->eph_priv, eph_priv, 32);
    memcpy(hs->remote_static, peer_pub, 32);
    hs->local_index = sender_index;

    ts_put_le32(out, TYPE_INIT);
    ts_put_le32(out + I_SENDER, sender_index);
    ts_x25519_public(out + I_EPH, eph_priv);
    mix_key(hs->ck, out + I_EPH, 32);
    mix_hash(hs->h, out + I_EPH, 32);

    /* es: encrypt our static public key. */
    if (ts_x25519(dh, eph_priv, peer_pub) != 0) goto out;
    mix_key2(hs->ck, k, dh);
    ts_aead_seal(out + I_STATIC, k, ZERO_NONCE, hs->h, 32, me->pub, 32);
    mix_hash(hs->h, out + I_STATIC, 48);

    /* ss: encrypt the timestamp. */
    mix_key2(hs->ck, k, ss);
    ts_aead_seal(out + I_TS, k, ZERO_NONCE, hs->h, 32, tai64n, 12);
    mix_hash(hs->h, out + I_TS, 28);

    add_macs(out, I_MAC1, peer_pub, cookie16);
    hs->state = HS_INIT_SENT;
    rc = 0;
out:
    ts_wipe(dh, sizeof dh);
    ts_wipe(k, sizeof k);
    if (rc != 0) {
        wipe_hs(hs);
        memset(out, 0, TS_WG_INIT_LEN);
    }
    return rc;
}

int ts_wg_init_open_static(ts_wg_hs *hs, const ts_wg_static *me, const uint8_t in[TS_WG_INIT_LEN],
                           uint8_t peer_pub[32])
{
    uint8_t dh[32], k[32];
    int rc = -1;

    wipe_hs(hs);
    memset(peer_pub, 0, 32);
    /* Cheap checks before any DH. */
    if ((ts_get_le32(in) & TYPE_MASK) != TYPE_INIT) return -1;
    if (!check_mac1(in, I_MAC1, me->mac1_key)) return -1;

    initial(hs->ck, hs->h, me->pub);
    memcpy(hs->remote_eph, in + I_EPH, 32);
    mix_key(hs->ck, hs->remote_eph, 32);
    mix_hash(hs->h, hs->remote_eph, 32);

    if (ts_x25519(dh, me->priv, hs->remote_eph) != 0) goto out;
    mix_key2(hs->ck, k, dh);
    if (ts_aead_open(peer_pub, k, ZERO_NONCE, hs->h, 32, in + I_STATIC, 48) != 0) goto out;
    mix_hash(hs->h, in + I_STATIC, 48);

    memcpy(hs->remote_static, peer_pub, 32);
    memcpy(hs->enc_ts, in + I_TS, 28);
    hs->remote_index = ts_get_le32(in + I_SENDER);
    hs->state = HS_STATIC_OPENED;
    rc = 0;
out:
    ts_wipe(dh, sizeof dh);
    ts_wipe(k, sizeof k);
    if (rc != 0) {
        wipe_hs(hs);
        memset(peer_pub, 0, 32);
    }
    return rc;
}

int ts_wg_init_finish(ts_wg_hs *hs, const uint8_t ss[32], uint8_t tai64n_out[12], uint32_t *sender_index)
{
    uint8_t k[32];
    int rc = -1;

    memset(tai64n_out, 0, 12);
    if (hs->state != HS_STATIC_OPENED || all_zero(ss, 32)) goto out;
    mix_key2(hs->ck, k, ss);
    if (ts_aead_open(tai64n_out, k, ZERO_NONCE, hs->h, 32, hs->enc_ts, 28) != 0) goto out;
    mix_hash(hs->h, hs->enc_ts, 28);
    ts_wipe(hs->enc_ts, sizeof hs->enc_ts);
    *sender_index = hs->remote_index;
    hs->state = HS_INIT_CONSUMED;
    rc = 0;
out:
    ts_wipe(k, sizeof k);
    if (rc != 0) wipe_hs(hs);
    return rc;
}

int ts_wg_create_resp(ts_wg_hs *hs, uint32_t sender_index, const uint8_t eph_priv[32],
                      const uint8_t *cookie16, uint8_t out[TS_WG_RESP_LEN])
{
    uint8_t dh[32], tau[32], k[32];
    int rc = -1;

    memset(out, 0, TS_WG_RESP_LEN);
    if (hs->state != HS_INIT_CONSUMED) goto out;

    ts_put_le32(out, TYPE_RESP);
    ts_put_le32(out + R_SENDER, sender_index);
    ts_put_le32(out + R_RECEIVER, hs->remote_index);
    ts_x25519_public(out + R_EPH, eph_priv);
    mix_hash(hs->h, out + R_EPH, 32);
    mix_key(hs->ck, out + R_EPH, 32);

    if (ts_x25519(dh, eph_priv, hs->remote_eph) != 0) goto out;   /* ee */
    mix_key(hs->ck, dh, 32);
    if (ts_x25519(dh, eph_priv, hs->remote_static) != 0) goto out;   /* se */
    mix_key(hs->ck, dh, 32);

    ts_hkdf3(hs->ck, tau, k, hs->ck, ZERO_PSK, 32);   /* psk */
    mix_hash(hs->h, tau, 32);
    ts_aead_seal(out + R_EMPTY, k, ZERO_NONCE, hs->h, 32, NULL, 0);
    mix_hash(hs->h, out + R_EMPTY, 16);

    add_macs(out, R_MAC1, hs->remote_static, cookie16);
    hs->local_index = sender_index;
    ts_wipe(hs->remote_eph, sizeof hs->remote_eph);
    hs->state = HS_RESP_CREATED;
    rc = 0;
out:
    ts_wipe(dh, sizeof dh);
    ts_wipe(tau, sizeof tau);
    ts_wipe(k, sizeof k);
    if (rc != 0) {
        wipe_hs(hs);
        memset(out, 0, TS_WG_RESP_LEN);
    }
    return rc;
}

int ts_wg_consume_resp(ts_wg_hs *hs, const ts_wg_static *me,
                       const uint8_t in[TS_WG_RESP_LEN], uint32_t *sender_index)
{
    uint8_t ck[32], h[32], dh[32], tau[32], k[32], none[1];
    int rc = -1;

    /* Cheap checks before any DH. Nothing in hs changes unless every check
     * passes: mac1 is keyed by our public key, so anyone can pass it. */
    if (hs->state != HS_INIT_SENT) return -1;
    if ((ts_get_le32(in) & TYPE_MASK) != TYPE_RESP) return -1;
    if (!check_mac1(in, R_MAC1, me->mac1_key)) return -1;
    if (ts_get_le32(in + R_RECEIVER) != hs->local_index) return -1;

    memcpy(ck, hs->ck, 32);
    memcpy(h, hs->h, 32);
    mix_hash(h, in + R_EPH, 32);
    mix_key(ck, in + R_EPH, 32);
    if (ts_x25519(dh, hs->eph_priv, in + R_EPH) != 0) goto out;   /* ee */
    mix_key(ck, dh, 32);
    if (ts_x25519(dh, me->priv, in + R_EPH) != 0) goto out;   /* se */
    mix_key(ck, dh, 32);
    ts_hkdf3(ck, tau, k, ck, ZERO_PSK, 32);
    mix_hash(h, tau, 32);
    if (ts_aead_open(none, k, ZERO_NONCE, h, 32, in + R_EMPTY, 16) != 0) goto out;
    mix_hash(h, in + R_EMPTY, 16);

    memcpy(hs->ck, ck, 32);
    memcpy(hs->h, h, 32);
    ts_wipe(hs->eph_priv, sizeof hs->eph_priv);
    hs->remote_index = ts_get_le32(in + R_SENDER);
    *sender_index = hs->remote_index;
    hs->state = HS_RESP_CONSUMED;
    rc = 0;
out:
    ts_wipe(ck, sizeof ck);
    ts_wipe(h, sizeof h);
    ts_wipe(dh, sizeof dh);
    ts_wipe(tau, sizeof tau);
    ts_wipe(k, sizeof k);
    return rc;
}

void ts_wg_derive(ts_wg_hs *hs, int initiator, uint8_t send[32], uint8_t recv[32])
{
    if ((initiator && hs->state == HS_RESP_CONSUMED) ||
        (!initiator && hs->state == HS_RESP_CREATED)) {
        if (initiator) ts_hkdf2(send, recv, hs->ck, NULL, 0);
        else ts_hkdf2(recv, send, hs->ck, NULL, 0);
    } else {
        memset(send, 0, 32);
        memset(recv, 0, 32);
    }
    wipe_hs(hs);
}

int ts_wg_cookie_open(uint8_t cookie[16], const uint8_t peer_pub[32], const uint8_t last_mac1[16],
                      const uint8_t in[TS_WG_COOKIE_LEN])
{
    uint8_t key[32];
    int rc;

    memset(cookie, 0, 16);
    if ((ts_get_le32(in) & TYPE_MASK) != TYPE_COOKIE) return -1;
    label_key(key, LABEL_COOKIE, peer_pub);
    rc = ts_xaead_open(cookie, key, in + C_NONCE, last_mac1, 16, in + C_COOKIE, 32);
    ts_wipe(key, sizeof key);
    return rc == 0 ? 0 : -1;
}
