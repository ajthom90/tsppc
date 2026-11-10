#include "noise.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../core/bytes.h"
#include "../crypto/aead.h"
#include "../crypto/blake2s.h"
#include "../crypto/kdf.h"
#include "../crypto/random.h"
#include "../crypto/x25519.h"

#define TYPE_INIT 1
#define TYPE_RESP 2
#define TYPE_ERROR 3
#define TYPE_RECORD 4

#define MAX_CT (TS_NOISE_MAX_MSG - 3)     /* 4093 */
#define CTR_INVALID UINT64_MAX

static const char PROTOCOL_NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/* h = BLAKE2s(h || data) */
static void mix_hash(ts_noise *n, const uint8_t *data, size_t len)
{
    ts_blake2s_ctx c;
    if (ts_blake2s_init(&c, 32, NULL, 0) != 0) abort();   /* fixed valid parameters */
    ts_blake2s_update(&c, n->h, 32);
    ts_blake2s_update(&c, data, len);
    ts_blake2s_final(&c, n->h);
}

/* (ck, k) = HKDF(ck, DH(priv, pub)). Returns 0, or -1 for a low-order pub. */
static int mix_dh(ts_noise *n, uint8_t k[32], const uint8_t priv[32], const uint8_t pub[32])
{
    uint8_t dh[32], ck[32];
    int rc = -1;

    if (ts_x25519(dh, priv, pub) == 0) {
        ts_hkdf2(ck, k, n->ck, dh, sizeof dh);
        memcpy(n->ck, ck, 32);
        rc = 0;
    }
    ts_wipe(dh, sizeof dh);
    ts_wipe(ck, sizeof ck);
    return rc;
}

/* Handshake AEAD: one use per key, so the nonce is zero; AD is h. The
 * ciphertext is then mixed into h. */
static void encrypt_and_hash(ts_noise *n, uint8_t *out, const uint8_t k[32],
                             const uint8_t *pt, size_t ptlen)
{
    static const uint8_t zero[12];
    ts_aead_seal(out, k, zero, n->h, 32, pt, ptlen);
    mix_hash(n, out, ptlen + 16);
}

static int decrypt_and_hash(ts_noise *n, uint8_t *out, const uint8_t k[32],
                            const uint8_t *ct, size_t ctlen)
{
    static const uint8_t zero[12];
    if (ts_aead_open(out, k, zero, n->h, 32, ct, ctlen) != 0) return -1;
    mix_hash(n, ct, ctlen);
    return 0;
}

static void wipe_handshake(ts_noise *n)
{
    ts_wipe(n->ck, sizeof n->ck);
    ts_wipe(n->e_priv, sizeof n->e_priv);
    ts_wipe(n->s_priv, sizeof n->s_priv);
}

/* Fatal error: wipe every secret and refuse further use. Counters are kept. */
static void fail(ts_noise *n)
{
    wipe_handshake(n);
    ts_wipe(n->tx_key, sizeof n->tx_key);
    ts_wipe(n->rx_key, sizeof n->rx_key);
    ts_wipe(n->rbuf, sizeof n->rbuf);
    n->rlen = 0;
    n->state = TS_NOISE_FAILED;
}

static void nonce_for(uint8_t nonce[12], uint64_t ctr)
{
    memset(nonce, 0, 4);
    ts_put_be64(nonce + 4, ctr);
}

static int start(ts_noise *n, uint8_t init[TS_NOISE_INIT_LEN],
                 const uint8_t machine_priv[32], const uint8_t control_pub[32],
                 uint16_t capver)
{
    char prologue[48];
    uint8_t e_pub[32], s_pub[32], k[32];
    int len, rc = -1;

    /* The name is longer than 32 bytes, so h = BLAKE2s(name); ck = h. */
    ts_blake2s(n->h, PROTOCOL_NAME, sizeof PROTOCOL_NAME - 1);
    memcpy(n->ck, n->h, 32);
    len = snprintf(prologue, sizeof prologue, "Tailscale Control Protocol v%u", (unsigned)capver);
    mix_hash(n, (const uint8_t *)prologue, (size_t)len);
    mix_hash(n, control_pub, 32);                    /* pre-message <- s */

    memcpy(n->s_priv, machine_priv, 32);
    ts_put_be16(init, capver);
    init[2] = TYPE_INIT;
    ts_put_be16(init + 3, TS_NOISE_INIT_LEN - 5);

    /* -> e, es, s, ss */
    ts_x25519_public(e_pub, n->e_priv);
    memcpy(init + 5, e_pub, 32);
    mix_hash(n, e_pub, 32);
    if (mix_dh(n, k, n->e_priv, control_pub) != 0) goto out;
    ts_x25519_public(s_pub, n->s_priv);
    encrypt_and_hash(n, init + 37, k, s_pub, 32);
    if (mix_dh(n, k, n->s_priv, control_pub) != 0) goto out;
    encrypt_and_hash(n, init + 85, k, s_pub, 0);     /* empty payload */
    n->state = TS_NOISE_SENT;
    rc = 0;
out:
    ts_wipe(k, sizeof k);
    if (rc != 0) {
        fail(n);
        memset(init, 0, TS_NOISE_INIT_LEN);
    }
    return rc;
}

static void reset(ts_noise *n)
{
    ts_noise_clear(n);
    n->state = TS_NOISE_EMPTY;
}

int ts_noise_init(ts_noise *n, uint8_t init[TS_NOISE_INIT_LEN],
                  const uint8_t machine_priv[32], const uint8_t control_pub[32],
                  uint16_t capver)
{
    reset(n);
    if (ts_random_bytes(n->e_priv, 32) != 0) {
        fail(n);
        memset(init, 0, TS_NOISE_INIT_LEN);
        return -1;
    }
    return start(n, init, machine_priv, control_pub, capver);
}

#ifdef TS_TEST_HOOKS
int ts_noise_init_eph(ts_noise *n, uint8_t init[TS_NOISE_INIT_LEN],
                      const uint8_t machine_priv[32], const uint8_t control_pub[32],
                      uint16_t capver, const uint8_t eph_priv[32])
{
    reset(n);
    memcpy(n->e_priv, eph_priv, 32);
    return start(n, init, machine_priv, control_pub, capver);
}
#endif

int ts_noise_read_response(ts_noise *n, const uint8_t resp[TS_NOISE_RESP_LEN])
{
    const uint8_t *re = resp + 3;
    uint8_t k[32], none[1];
    int rc = -1;

    if (n->state != TS_NOISE_SENT) {
        if (n->state != TS_NOISE_READY) fail(n);
        return -1;   /* a stray second response does not end a live session */
    }
    if (resp[0] != TYPE_RESP || ts_get_be16(resp + 1) != TS_NOISE_RESP_LEN - 3) goto out;

    /* <- e, ee, se */
    mix_hash(n, re, 32);
    if (mix_dh(n, k, n->e_priv, re) != 0) goto out;
    if (mix_dh(n, k, n->s_priv, re) != 0) goto out;
    if (decrypt_and_hash(n, none, k, resp + 35, 16) != 0) goto out;

    /* Split: the initiator sends with the first key and receives with the second. */
    ts_hkdf2(n->tx_key, n->rx_key, n->ck, NULL, 0);
    wipe_handshake(n);
    n->tx_ctr = n->rx_ctr = 0;
    n->rlen = 0;
    n->state = TS_NOISE_READY;
    rc = 0;
out:
    ts_wipe(k, sizeof k);
    if (rc != 0) fail(n);
    return rc;
}

size_t ts_noise_seal(ts_noise *n, uint8_t *out, size_t cap, const uint8_t *pt, size_t ptlen)
{
    size_t records, need, at = 0;
    uint8_t nonce[12];

    if (n->state != TS_NOISE_READY || ptlen == 0) return 0;
    records = (ptlen + TS_NOISE_MAX_PLAIN - 1) / TS_NOISE_MAX_PLAIN;
    /* Counters tx_ctr .. tx_ctr + records - 1 must all be below CTR_INVALID. */
    if ((uint64_t)records > CTR_INVALID - n->tx_ctr) {
        fail(n);
        return 0;
    }
    if (records > (SIZE_MAX - ptlen) / TS_NOISE_RECORD_OVERHEAD) return 0;
    need = ptlen + records * TS_NOISE_RECORD_OVERHEAD;
    if (need > cap) return 0;

    while (ptlen > 0) {
        size_t chunk = ptlen < TS_NOISE_MAX_PLAIN ? ptlen : TS_NOISE_MAX_PLAIN;
        out[at] = TYPE_RECORD;
        ts_put_be16(out + at + 1, (uint16_t)(chunk + 16));
        nonce_for(nonce, n->tx_ctr++);
        ts_aead_seal(out + at + 3, n->tx_key, nonce, NULL, 0, pt, chunk);
        at += 3 + chunk + 16;
        pt += chunk;
        ptlen -= chunk;
    }
    return at;
}

int ts_noise_feed(ts_noise *n, const uint8_t *in, size_t len,
                  void (*deliver)(void *, const uint8_t *, size_t), void *user)
{
    if (n->state != TS_NOISE_READY) {
        if (n->state != TS_NOISE_FAILED) fail(n);
        return -1;
    }
    while (len > 0) {
        size_t want, take, ctlen;
        uint8_t nonce[12];

        /* The header first, then exactly the record it announces. */
        want = 3;
        if (n->rlen >= 3) want = 3 + (size_t)ts_get_be16(n->rbuf + 1);
        take = want - n->rlen;
        if (take > len) take = len;
        memcpy(n->rbuf + n->rlen, in, take);
        n->rlen += take;
        in += take;
        len -= take;

        if (n->rbuf[0] != TYPE_RECORD) {   /* error frames (type 3) included */
            fail(n);
            return -1;
        }
        if (n->rlen < 3) continue;
        ctlen = ts_get_be16(n->rbuf + 1);
        if (ctlen < 16 || ctlen > MAX_CT) {
            fail(n);
            return -1;
        }
        if (n->rlen < 3 + ctlen) continue;

        if (n->rx_ctr == CTR_INVALID) {
            fail(n);
            return -1;
        }
        nonce_for(nonce, n->rx_ctr);
        if (ts_aead_open(n->rbuf + 3, n->rx_key, nonce, NULL, 0, n->rbuf + 3, ctlen) != 0) {
            fail(n);
            return -1;
        }
        n->rx_ctr++;
        n->rlen = 0;
        if (ctlen > 16) deliver(user, n->rbuf + 3, ctlen - 16);
        ts_wipe(n->rbuf, 3 + ctlen);   /* no plaintext left behind */
        if (n->state != TS_NOISE_READY) return -1;   /* cleared from the callback */
    }
    return 0;
}

void ts_noise_clear(ts_noise *n)
{
    ts_wipe(n, sizeof *n);
}
