#ifndef TS_NET_TLS_H
#define TS_NET_TLS_H

#include <stddef.h>
#include <time.h>

#include <bearssl.h>

/* TLS client over a caller-supplied non-blocking socket, for the /key fetch
 * and for the control connection on port 443.
 *
 * Offered: TLS 1.2 only, ECDHE_ECDSA and ECDHE_RSA with CHACHA20_POLY1305,
 * key exchange over X25519 only. ChaCha20 is br_chacha20_ct_run and Poly1305
 * br_poly1305_ctmul32_run on every target (constant-time on G3/G4 with
 * BR_CT_MUL15). No GCM, CCM, CBC or DES code is configured.
 *
 * The engine's EC implementation is br_ec_c25519_m31, the only curve code that
 * sees a secret. Signatures (the server's key exchange and the certificate
 * chain) are verified with br_ec_all_m31 / ECDSA i31 and RSA i31, which only
 * handle public values. Certificates chain to ISRG Root X1, X2, YR or YE
 * (anchors.c) and must match the host name. See docs/known-limits.md. */

#define TS_ANCHOR_COUNT 4
extern const br_x509_trust_anchor ts_anchors[TS_ANCHOR_COUNT];
/* Midnight UTC on the day anchors.c was generated: no correct clock is earlier. */
extern const time_t ts_build_time;

#define TS_TLS_WANT_READ 1
#define TS_TLS_WANT_WRITE 2
#define TS_TLS_CLOSED (-2)

typedef struct {
    br_ssl_client_context cc;
    br_x509_minimal_context xc;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    int fd;
    int io;          /* 0, or why the socket failed (see tls.c) */
    int hs_done;     /* the handshake completed at some point */
} ts_tls;

/* Set up a client on fd (non-blocking, owned by the caller) for host, which
 * goes in SNI and must match the certificate. host must be a name: an IPv4 or
 * IPv6 literal is refused, since BearSSL would send it as SNI. Nothing is sent
 * until ts_tls_step. Returns 0, or -1 (empty or literal host, no randomness). */
int ts_tls_start(ts_tls *t, int fd, const char *host);

/* Do all socket I/O possible without blocking. 1: handshake in progress, wait
 * as ts_tls_want says. 0: handshake complete (or the peer closed cleanly
 * after it). -1: failed, see ts_tls_error. */
int ts_tls_step(ts_tls *t);

/* TS_TLS_WANT_READ and/or TS_TLS_WANT_WRITE: what to wait for on fd before
 * the next step. 0 once closed or failed. */
int ts_tls_want(const ts_tls *t);

/* Copy up to cap bytes of received application data. Returns the count (> 0),
 * 0 if none is available yet, TS_TLS_CLOSED after the peer's close_notify, or
 * -1 on failure. Data received before a failure or close is returned first. */
int ts_tls_read(ts_tls *t, void *buf, size_t cap);

/* Queue up to len bytes and flush them. Returns the count accepted (0 when the
 * engine cannot take data now, for instance during the handshake), or -1. */
int ts_tls_write(ts_tls *t, const void *buf, size_t len);

/* Why the connection failed, for the operator. */
const char *ts_tls_error(const ts_tls *t);

/* The message for BearSSL error br_err, given the clock now and the build
 * time. Certificate time errors, and any certificate error while now is
 * before build_time, give exactly "system clock is wrong". */
const char *ts_tls_classify(int br_err, time_t now, time_t build_time);

/* Wipe the context (keys included). Does not close fd. */
void ts_tls_wipe(ts_tls *t);

#endif
