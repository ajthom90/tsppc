#ifndef TS_NET_KEYFETCH_H
#define TS_NET_KEYFETCH_H

#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>

#include "resolve.h"
#include "tls.h"

/* Fetch the control server's Noise public key: resolve the host, connect to
 * port 443, TLS, then "GET /key?v=<capver>" over HTTP/1.1 with
 * Connection: close. The whole response is bounded by TS_KEYFETCH_MAX. */

#define TS_KEYFETCH_MAX 65536

/* Parse the /key response body, a JSON object whose "publicKey" member is the
 * string "mkey:" followed by 64 hex digits (either case). Whitespace and other
 * members are allowed; a second "publicKey", anything after the object or a
 * malformed value is rejected. Returns 0 with pub set, or -1 (pub unchanged). */
int ts_control_key_parse(uint8_t pub[32], const char *json, size_t len);

/* Parse an HTTP/1.x response held in buf[0..len); eof says the stream has
 * ended. Returns 1 if more bytes are needed, 0 when complete, -1 if malformed
 * or unsupported. On 0, *status is the status code and the body is
 * buf[*body_off..*body_off + *body_len). A non-200 response is complete once
 * its headers are (its body is not needed, *body_len = 0). A 200 body is
 * framed by Content-Length (bytes beyond it are an error) or, without one, by
 * the end of the stream. Transfer-Encoding (chunked) and folded header lines
 * are refused. Lines may end in CRLF or LF. */
int ts_http1_response(const char *buf, size_t len, int eof,
                      int *status, size_t *body_off, size_t *body_len);

typedef struct {
    int state;
    int fd;
    ts_resolve res;
    ts_tls tls;
    char host[TS_RESOLVE_NAME_MAX + 1];
    char req[384];
    size_t reqlen, reqoff;
    char resp[TS_KEYFETCH_MAX];
    size_t resplen;
    uint8_t pub[32];
    uint16_t tls_suite;   /* negotiated cipher suite, once TLS is up */
    int tls_curve;        /* negotiated ECDHE curve (29 = X25519) */
    char err[128];
} ts_keyfetch;

/* Start a fetch from host, a DNS name (ts_host_name_ok; an address literal is
 * refused, as TLS needs a name), with ?v=capver. Returns 0, or -1 with
 * ts_keyfetch_error set. The struct is large (about 100 KiB); do not put it on
 * a small stack. Call ts_keyfetch_close when finished with it, after success,
 * failure or a failed start. The caller bounds the total time. */
int ts_keyfetch_start(ts_keyfetch *k, const char *host, int capver);

/* Add the descriptors to wait on to r and w, raising *maxfd. Returns 0, or -1
 * once the fetch is done or failed (nothing added). */
int ts_keyfetch_fds(const ts_keyfetch *k, fd_set *r, fd_set *w, int *maxfd);

/* Advance as far as possible without blocking. 1: pending. 0: done, pub holds
 * the key. -1: failed, see ts_keyfetch_error. */
int ts_keyfetch_step(ts_keyfetch *k, uint8_t pub[32]);

/* Why the fetch failed ("" while pending or after success). */
const char *ts_keyfetch_error(const ts_keyfetch *k);

/* Release everything: helper, socket, TLS state. Safe on a zero-initialised
 * struct, after any ts_keyfetch_start (successful or not), at any point of a
 * fetch, and again after a close. Not safe on uninitialised memory. */
void ts_keyfetch_close(ts_keyfetch *k);

#endif
