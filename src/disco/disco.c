#include "disco.h"

#include <string.h>

#include "../core/bytes.h"
#include "../crypto/nacl.h"

static const uint8_t MAGIC[TS_DISCO_MAGIC_LEN] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };

#define BOX_AT   (TS_DISCO_HDR_LEN + TS_DISCO_NONCE_LEN)   /* 62: tag, then ciphertext */
#define TAG_LEN  16
#define PLAIN_AT (BOX_AT + TAG_LEN)                          /* 78 */
#define PING_PLAIN (2 + TS_DISCO_TXID_LEN + 32)              /* 46 */
#define PONG_PLAIN (2 + TS_DISCO_TXID_LEN + 16 + 2)          /* 32 */

int ts_disco_looks_like(const uint8_t *p, size_t n)
{
    return n >= TS_DISCO_HDR_LEN + TS_DISCO_NONCE_LEN &&
           memcmp(p, MAGIC, TS_DISCO_MAGIC_LEN) == 0;
}

const uint8_t *ts_disco_sender(const uint8_t *p)
{
    return p + TS_DISCO_MAGIC_LEN;
}

/* The key is secret: look at every byte. */
static int key_usable(const ts_disco_shared *s)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < sizeof s->k; i++) acc |= s->k[i];
    return acc != 0;
}

void ts_disco_shared_init(ts_disco_shared *s, const uint8_t my_priv[32],
                          const uint8_t their_pub[32])
{
    if (ts_box_beforenm(s->k, their_pub, my_priv) != 0)
        memset(s->k, 0, sizeof s->k);
}

/* Header, nonce, then the box over plain (the secretbox "afternm" step with
 * the precomputed key: no X25519 here). */
static int seal(uint8_t *out, size_t cap, const uint8_t my_disco_pub[32],
                const ts_disco_shared *s, const uint8_t nonce[24],
                const uint8_t *plain, size_t plen)
{
    if (cap < PLAIN_AT + plen || !key_usable(s)) return -1;
    memcpy(out, MAGIC, TS_DISCO_MAGIC_LEN);
    memcpy(out + TS_DISCO_MAGIC_LEN, my_disco_pub, 32);
    memcpy(out + TS_DISCO_HDR_LEN, nonce, TS_DISCO_NONCE_LEN);
    ts_secretbox_seal(out + BOX_AT, s->k, nonce, plain, plen);
    return (int)(PLAIN_AT + plen);
}

int ts_disco_seal_ping(uint8_t *out, size_t cap, const uint8_t my_disco_pub[32],
                       const ts_disco_shared *s, const uint8_t nonce[24],
                       const uint8_t txid[12], const uint8_t my_node_pub[32])
{
    uint8_t m[PING_PLAIN];
    int r;
    m[0] = TS_DISCO_PING;
    m[1] = 0;
    memcpy(m + 2, txid, TS_DISCO_TXID_LEN);
    memcpy(m + 2 + TS_DISCO_TXID_LEN, my_node_pub, 32);
    r = seal(out, cap, my_disco_pub, s, nonce, m, sizeof m);
    ts_wipe(m, sizeof m);
    return r;
}

int ts_disco_seal_pong(uint8_t *out, size_t cap, const uint8_t my_disco_pub[32],
                       const ts_disco_shared *s, const uint8_t nonce[24],
                       const uint8_t txid[12], const uint8_t src_ip16[16],
                       uint16_t src_port)
{
    uint8_t m[PONG_PLAIN];
    int r;
    m[0] = TS_DISCO_PONG;
    m[1] = 0;
    memcpy(m + 2, txid, TS_DISCO_TXID_LEN);
    memcpy(m + 2 + TS_DISCO_TXID_LEN, src_ip16, 16);
    ts_put_be16(m + 2 + TS_DISCO_TXID_LEN + 16, src_port);
    r = seal(out, cap, my_disco_pub, s, nonce, m, sizeof m);
    ts_wipe(m, sizeof m);
    return r;
}

static int parse(ts_disco_msg *m, const uint8_t *b, size_t n)
{
    const uint8_t *d;
    size_t dn, i;
    uint8_t acc = 0;

    if (n < 2 || b[1] != 0) return -1;
    d = b + 2;
    dn = n - 2;
    m->type = b[0];
    switch (b[0]) {
    case TS_DISCO_PING:
        if (dn < TS_DISCO_TXID_LEN) return -1;
        memcpy(m->txid, d, TS_DISCO_TXID_LEN);
        d += TS_DISCO_TXID_LEN;
        dn -= TS_DISCO_TXID_LEN;
        if (dn >= 32) {
            for (i = 0; i < 32; i++) acc |= d[i];
            if (acc) {
                m->have_node_key = 1;
                memcpy(m->node_key, d, 32);
            }
        }
        return 0;
    case TS_DISCO_PONG:
        if (dn < TS_DISCO_TXID_LEN + 16 + 2) return -1;
        memcpy(m->txid, d, TS_DISCO_TXID_LEN);
        memcpy(m->src_ip16, d + TS_DISCO_TXID_LEN, 16);
        m->src_port = ts_get_be16(d + TS_DISCO_TXID_LEN + 16);
        return 0;
    default:
        return 0;   /* reported by type; the caller ignores it */
    }
}

int ts_disco_open(ts_disco_msg *m, const uint8_t *p, size_t n,
                  const ts_disco_shared *s)
{
    uint8_t buf[TS_DISCO_MAX - PLAIN_AT];
    size_t plen;
    int r;

    memset(m, 0, sizeof *m);
    if (n < PLAIN_AT + 2 || n > TS_DISCO_MAX || !ts_disco_looks_like(p, n) ||
        !key_usable(s))
        return -1;
    plen = n - PLAIN_AT;
    if (ts_secretbox_open(buf, s->k, p + TS_DISCO_HDR_LEN, p + BOX_AT, n - BOX_AT) != 0)
        return -1;
    r = parse(m, buf, plen);
    ts_wipe(buf, plen);
    if (r != 0) memset(m, 0, sizeof *m);
    return r;
}
