#include "tls.h"
#include "../core/bytes.h"
#include "../crypto/random.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

enum { IO_OK = 0, IO_EOF, IO_ERR };

static const uint16_t suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
};

/* The engine passes its own EC implementation (X25519 only, which has no
 * ECDSA) when it checks the ServerKeyExchange signature. Verify with the
 * general implementation instead: the key, hash and signature are all public. */
static uint32_t ecdsa_vrfy_public(const br_ec_impl *impl, const void *hash, size_t hash_len,
                                  const br_ec_public_key *pk, const void *sig, size_t sig_len)
{
    (void)impl;
    return br_ecdsa_i31_vrfy_asn1(&br_ec_all_m31, hash, hash_len, pk, sig, sig_len);
}

int ts_tls_start(ts_tls *t, int fd, const char *host)
{
    static const br_hash_class *const hashes[] = {
        &br_sha256_vtable, &br_sha384_vtable, &br_sha512_vtable
    };
    br_ssl_engine_context *e = &t->cc.eng;
    unsigned char seed[32];
    size_t i;

    memset(t, 0, sizeof *t);
    t->fd = fd;
    if (host == NULL || host[0] == '\0') return -1;

    br_ssl_client_zero(&t->cc);
    br_ssl_engine_set_versions(e, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(e, suites, sizeof suites / sizeof suites[0]);

    br_x509_minimal_init(&t->xc, &br_sha256_vtable, ts_anchors, TS_ANCHOR_COUNT);
    br_x509_minimal_set_rsa(&t->xc, br_rsa_i31_pkcs1_vrfy);
    br_x509_minimal_set_ecdsa(&t->xc, &br_ec_all_m31, br_ecdsa_i31_vrfy_asn1);

    br_ssl_engine_set_ec(e, &br_ec_c25519_m31);
    br_ssl_engine_set_rsavrfy(e, br_rsa_i31_pkcs1_vrfy);
    br_ssl_engine_set_ecdsa(e, ecdsa_vrfy_public);

    for (i = 0; i < sizeof hashes / sizeof hashes[0]; i++) {
        int id = (int)((hashes[i]->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK);
        br_ssl_engine_set_hash(e, id, hashes[i]);
        br_x509_minimal_set_hash(&t->xc, id, hashes[i]);
    }
    br_ssl_engine_set_x509(e, &t->xc.vtable);
    br_ssl_engine_set_prf_sha256(e, br_tls12_sha256_prf);

    br_ssl_engine_set_chapol(e, &br_sslrec_in_chapol_vtable, &br_sslrec_out_chapol_vtable);
    br_ssl_engine_set_chacha20(e, br_chacha20_ct_run);
    br_ssl_engine_set_poly1305(e, br_poly1305_ctmul32_run);

    br_ssl_engine_set_buffer(e, t->iobuf, sizeof t->iobuf, 1);

    /* BearSSL also seeds from /dev/urandom; add our own on top, and fail
     * closed if it is missing. */
    if (ts_random_bytes(seed, sizeof seed) != 0) return -1;
    br_ssl_engine_inject_entropy(e, seed, sizeof seed);
    ts_wipe(seed, sizeof seed);

    if (!br_ssl_client_reset(&t->cc, host, 0)) return -1;
    return 0;
}

/* Move records between the engine and the socket until neither can progress.
 * Returns 0, or -1 if the socket failed (t->io says how). */
static int pump(ts_tls *t)
{
    br_ssl_engine_context *e = &t->cc.eng;
    for (;;) {
        unsigned st = br_ssl_engine_current_state(e);
        int progress = 0;
        unsigned char *b;
        size_t len;
        ssize_t n;

        if (t->io != IO_OK) return -1;
        if (st & BR_SSL_CLOSED) return 0;
        if (st & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) t->hs_done = 1;
        if (st & BR_SSL_SENDREC) {
            b = br_ssl_engine_sendrec_buf(e, &len);
            n = send(t->fd, b, len, 0);
            if (n > 0) {
                br_ssl_engine_sendrec_ack(e, (size_t)n);
                progress = 1;
            } else if (!(n < 0 && (errno == EAGAIN || errno == EINTR))) {
                t->io = IO_ERR;
                return -1;
            }
        }
        if (st & BR_SSL_RECVREC) {
            b = br_ssl_engine_recvrec_buf(e, &len);
            n = recv(t->fd, b, len, 0);
            if (n > 0) {
                br_ssl_engine_recvrec_ack(e, (size_t)n);
                progress = 1;
            } else if (n == 0) {
                /* EOF without close_notify: possibly truncated, so fail. */
                t->io = IO_EOF;
                return -1;
            } else if (!(errno == EAGAIN || errno == EINTR)) {
                t->io = IO_ERR;
                return -1;
            }
        }
        if (!progress) return 0;
    }
}

static int failed(const ts_tls *t)
{
    unsigned st = br_ssl_engine_current_state(&t->cc.eng);
    if (t->io != IO_OK) return 1;
    return (st & BR_SSL_CLOSED) &&
           (br_ssl_engine_last_error(&t->cc.eng) != BR_ERR_OK || !t->hs_done);
}

int ts_tls_step(ts_tls *t)
{
    unsigned st;
    if (pump(t) != 0 || failed(t)) return -1;
    st = br_ssl_engine_current_state(&t->cc.eng);
    if (st & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) t->hs_done = 1;
    return t->hs_done ? 0 : 1;
}

int ts_tls_want(const ts_tls *t)
{
    unsigned st = br_ssl_engine_current_state(&t->cc.eng);
    int w = 0;
    if (t->io != IO_OK || (st & BR_SSL_CLOSED)) return 0;
    if (st & BR_SSL_SENDREC) w |= TS_TLS_WANT_WRITE;
    if (st & BR_SSL_RECVREC) w |= TS_TLS_WANT_READ;
    return w;
}

int ts_tls_read(ts_tls *t, void *buf, size_t cap)
{
    br_ssl_engine_context *e = &t->cc.eng;
    unsigned char *b;
    size_t len;

    (void)pump(t);
    if (br_ssl_engine_current_state(e) & BR_SSL_RECVAPP) {
        b = br_ssl_engine_recvapp_buf(e, &len);
        if (len > cap) len = cap;
        if (len > 0) {
            memcpy(buf, b, len);
            br_ssl_engine_recvapp_ack(e, len);
            (void)pump(t);   /* room freed: take in more records */
            return (int)len;
        }
    }
    if (failed(t)) return -1;
    if (br_ssl_engine_current_state(e) & BR_SSL_CLOSED) return TS_TLS_CLOSED;
    return 0;
}

int ts_tls_write(ts_tls *t, const void *buf, size_t len)
{
    br_ssl_engine_context *e = &t->cc.eng;
    unsigned char *b;
    size_t room;

    if (pump(t) != 0 || failed(t)) return -1;
    if (br_ssl_engine_current_state(e) & BR_SSL_CLOSED) return -1;
    if (!(br_ssl_engine_current_state(e) & BR_SSL_SENDAPP)) return 0;
    b = br_ssl_engine_sendapp_buf(e, &room);
    if (len > room) len = room;
    if (len > 0x7fffffff) len = 0x7fffffff;
    memcpy(b, buf, len);
    br_ssl_engine_sendapp_ack(e, len);
    br_ssl_engine_flush(e, 0);
    if (pump(t) != 0) return -1;
    return (int)len;
}

const char *ts_tls_error(const ts_tls *t)
{
    int err = br_ssl_engine_last_error(&t->cc.eng);
    if (err != BR_ERR_OK) return ts_tls_classify(err, time(NULL), ts_build_time);
    if (t->io == IO_EOF) return "connection closed by the server";
    if (t->io == IO_ERR) return "connection lost";
    if (br_ssl_engine_current_state(&t->cc.eng) & BR_SSL_CLOSED) return "connection closed";
    return "no error";
}

const char *ts_tls_classify(int br_err, time_t now, time_t build_time)
{
    int x509 = br_err >= BR_ERR_X509_OK && br_err <= BR_ERR_X509_NOT_TRUSTED;

    if (br_err == BR_ERR_X509_EXPIRED || br_err == BR_ERR_X509_TIME_UNKNOWN ||
        (x509 && now < build_time))
        return "system clock is wrong";
    switch (br_err) {
    case BR_ERR_OK:
        return "no error";
    case BR_ERR_IO:
        return "connection lost";
    case BR_ERR_X509_NOT_TRUSTED:
        return "server certificate is not from a trusted authority";
    case BR_ERR_X509_BAD_SERVER_NAME:
        return "server certificate does not match the host name";
    case BR_ERR_UNSUPPORTED_VERSION:
    case BR_ERR_BAD_CIPHER_SUITE:
    case BR_ERR_BAD_PARAM:
        return "server does not offer TLS 1.2 with ChaCha20-Poly1305 and X25519";
    case BR_ERR_BAD_SIGNATURE:
        return "server key exchange signature is invalid";
    default:
        break;
    }
    if (x509) return "server certificate rejected";
    if (br_err >= BR_ERR_RECV_FATAL_ALERT && br_err < BR_ERR_SEND_FATAL_ALERT)
        return "server ended the TLS session with an alert";
    return "TLS protocol error";
}

void ts_tls_wipe(ts_tls *t)
{
    ts_wipe(t, sizeof *t);
    t->fd = -1;
}
