#include "keyfetch.h"
#include "sock.h"
#include "../proto/encoding.h"
#include "../proto/json.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

enum { KF_IDLE = 0, KF_RESOLVE, KF_CONNECT, KF_TLS, KF_SEND, KF_RECV, KF_DONE, KF_FAILED };

int ts_control_key_parse(uint8_t pub[32], const char *json, size_t len)
{
    static const char prefix[] = "mkey:";
    ts_json j;
    ts_json_tok t;
    char s[5 + 64 + 2];   /* room to see an over-long value */
    uint8_t key[32];
    int found = 0, n;

    ts_json_init(&j, json, len);
    if (ts_json_next(&j, &t) != TS_JSON_OBJ_START) return -1;
    for (;;) {
        ts_json_type ty = ts_json_next(&j, &t);
        if (ty == TS_JSON_OBJ_END) break;
        if (ty != TS_JSON_KEY) return -1;
        if (t.rawlen == 9 && memcmp(t.raw, "publicKey", 9) == 0) {
            if (found || ts_json_next(&j, &t) != TS_JSON_STRING) return -1;
            n = ts_json_string(s, sizeof s, &t);
            if (n != 5 + 64 || memcmp(s, prefix, 5) != 0) return -1;
            if (ts_hex_decode(key, sizeof key, s + 5, 64) != 0) return -1;
            found = 1;
        } else if (ts_json_skip(&j, &t) != 0) {
            return -1;
        }
    }
    if (ts_json_next(&j, &t) != TS_JSON_END || !found) return -1;
    memcpy(pub, key, sizeof key);
    return 0;
}

static int lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

static int name_is(const char *p, size_t n, const char *want)
{
    size_t i;
    if (strlen(want) != n) return 0;
    for (i = 0; i < n; i++)
        if (lower((unsigned char)p[i]) != want[i]) return 0;
    return 1;
}

/* Header field-name characters (RFC 9110 token). */
static int tchar(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

int ts_http1_response(const char *buf, size_t len, int eof,
                      int *status, size_t *body_off, size_t *body_len)
{
    size_t pos = 0, hdr_end = 0, cl = 0;
    int have_cl = 0, line = 0, st = 0;

    *status = 0;
    *body_off = 0;
    *body_len = 0;
    /* Walk complete lines until the empty one. */
    for (;;) {
        const char *nl = memchr(buf + pos, '\n', len - pos);
        size_t end, n;
        const char *p = buf + pos;
        if (nl == NULL) return eof ? -1 : 1;
        end = (size_t)(nl - buf);
        n = end - pos;
        if (n > 0 && p[n - 1] == '\r') n--;
        pos = end + 1;
        if (line++ == 0) {
            /* "HTTP/1.x NNN" then a space and reason, or nothing. */
            if (n < 12 || memcmp(p, "HTTP/1.", 7) != 0 || (p[7] != '0' && p[7] != '1') ||
                p[8] != ' ' || p[9] < '1' || p[9] > '5' || p[10] < '0' || p[10] > '9' ||
                p[11] < '0' || p[11] > '9' || (n > 12 && p[12] != ' '))
                return -1;
            st = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
            continue;
        }
        if (n == 0) { hdr_end = pos; break; }
        {
            size_t c = 0, v, ve;
            while (c < n && tchar((unsigned char)p[c])) c++;
            if (c == 0 || c >= n || p[c] != ':') return -1;   /* also refuses folding */
            v = c + 1;
            while (v < n && (p[v] == ' ' || p[v] == '\t')) v++;
            ve = n;
            while (ve > v && (p[ve - 1] == ' ' || p[ve - 1] == '\t')) ve--;
            if (name_is(p, c, "transfer-encoding")) return -1;
            if (name_is(p, c, "content-length")) {
                size_t i, x = 0;
                if (ve == v) return -1;
                for (i = v; i < ve; i++) {
                    if (p[i] < '0' || p[i] > '9') return -1;
                    x = x * 10 + (size_t)(p[i] - '0');
                    if (x > TS_KEYFETCH_MAX) return -1;
                }
                if (have_cl && x != cl) return -1;
                have_cl = 1;
                cl = x;
            }
        }
    }
    *status = st;
    *body_off = hdr_end;
    if (st != 200) return 0;
    if (have_cl) {
        if (len - hdr_end < cl) return eof ? -1 : 1;
        if (len - hdr_end > cl) return -1;
        *body_len = cl;
        return 0;
    }
    if (!eof) return 1;
    *body_len = len - hdr_end;
    return 0;
}

static void cleanup(ts_keyfetch *k)
{
    ts_resolve_cancel(&k->res);
    if (k->fd >= 0) close(k->fd);
    k->fd = -1;
    ts_tls_wipe(&k->tls);
}

static int fail(ts_keyfetch *k, const char *what, const char *why)
{
    snprintf(k->err, sizeof k->err, "%s%s%s", what, why ? ": " : "", why ? why : "");
    cleanup(k);
    k->state = KF_FAILED;
    return -1;
}

static int start_connect(ts_keyfetch *k, const char *ip)
{
    k->fd = ts_tcp_start(ip, 443);
    if (k->fd < 0) return fail(k, "cannot connect to port 443", NULL);
    if (k->fd >= FD_SETSIZE) return fail(k, "too many open descriptors", NULL);
    k->state = KF_CONNECT;
    return 1;
}

int ts_keyfetch_start(ts_keyfetch *k, const char *host, int capver)
{
    struct in_addr a;
    int n;

    k->state = KF_IDLE;
    k->fd = -1;
    k->res.pid = -1;
    k->res.fd = -1;
    k->res.len = 0;
    memset(&k->tls, 0, sizeof k->tls);
    k->tls.fd = -1;
    k->reqoff = 0;
    k->resplen = 0;
    k->tls_suite = 0;
    k->tls_curve = 0;
    k->err[0] = '\0';
    if (!ts_host_name_ok(host)) return fail(k, "invalid control host name", NULL);
    /* TLS needs a name to send and to check against the certificate. */
    if (inet_pton(AF_INET, host, &a) == 1) return fail(k, "control host must be a name, not an address", NULL);
    if (capver <= 0 || capver > 99999) return fail(k, "invalid capability version", NULL);
    memcpy(k->host, host, strlen(host) + 1);
    n = snprintf(k->req, sizeof k->req,
                 "GET /key?v=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: tsppc\r\n"
                 "Accept: application/json\r\nConnection: close\r\n\r\n", capver, host);
    if (n <= 0 || (size_t)n >= sizeof k->req) return fail(k, "request too long", NULL);
    k->reqlen = (size_t)n;

    if (ts_resolve_start(&k->res, host) != 0) return fail(k, "cannot start DNS lookup", NULL);
    if (k->res.fd >= FD_SETSIZE) return fail(k, "too many open descriptors", NULL);
    k->state = KF_RESOLVE;
    return 0;
}

static void add(int fd, fd_set *s, int *maxfd)
{
    FD_SET(fd, s);
    if (fd > *maxfd) *maxfd = fd;
}

int ts_keyfetch_fds(const ts_keyfetch *k, fd_set *r, fd_set *w, int *maxfd)
{
    int want;
    switch (k->state) {
    case KF_RESOLVE:
        add(k->res.fd, r, maxfd);
        return 0;
    case KF_CONNECT:
        add(k->fd, w, maxfd);
        return 0;
    case KF_TLS:
    case KF_SEND:
    case KF_RECV:
        want = ts_tls_want(&k->tls);
        if (want & TS_TLS_WANT_READ) add(k->fd, r, maxfd);
        if (want & TS_TLS_WANT_WRITE) add(k->fd, w, maxfd);
        return 0;
    default:
        return -1;
    }
}

static int writable_now(int fd)
{
    fd_set w;
    struct timeval tv = { 0, 0 };
    FD_ZERO(&w);
    FD_SET(fd, &w);
    return select(fd + 1, NULL, &w, NULL, &tv) == 1;
}

/* A complete response is in resp[0..resplen). */
static int finish(ts_keyfetch *k, uint8_t pub[32], int rc, int st, size_t off, size_t blen)
{
    char why[32];
    if (rc != 0) return fail(k, "malformed HTTP response from the control server", NULL);
    if (st != 200) {
        snprintf(why, sizeof why, "HTTP status %d", st);
        return fail(k, "control server refused the key request", why);
    }
    if (ts_control_key_parse(k->pub, k->resp + off, blen) != 0)
        return fail(k, "malformed key in the control server's response", NULL);
    memcpy(pub, k->pub, 32);
    cleanup(k);
    k->state = KF_DONE;
    return 0;
}

int ts_keyfetch_step(ts_keyfetch *k, uint8_t pub[32])
{
    char ip[INET_ADDRSTRLEN];
    int rc, st, n;
    size_t off, blen;

    for (;;) {
        switch (k->state) {
        case KF_RESOLVE:
            rc = ts_resolve_finish(&k->res, ip, sizeof ip);
            if (rc == 1) return 1;
            if (rc != 0) return fail(k, "DNS lookup failed", k->host);
            if (start_connect(k, ip) < 0) return -1;
            break;
        case KF_CONNECT:
            if (!writable_now(k->fd)) return 1;
            if (ts_tcp_finish(k->fd) != 0) return fail(k, "cannot connect to port 443", k->host);
            if (ts_tls_start(&k->tls, k->fd, k->host) != 0) return fail(k, "cannot start TLS", NULL);
            k->state = KF_TLS;
            break;
        case KF_TLS:
            rc = ts_tls_step(&k->tls);
            if (rc < 0) return fail(k, "TLS", ts_tls_error(&k->tls));
            if (rc == 1) return 1;
            {
                br_ssl_session_parameters sp;
                br_ssl_engine_get_session_parameters(&k->tls.cc.eng, &sp);
                k->tls_suite = sp.cipher_suite;
                k->tls_curve = br_ssl_engine_get_ecdhe_curve(&k->tls.cc.eng);
            }
            k->state = KF_SEND;
            break;
        case KF_SEND:
            n = ts_tls_write(&k->tls, k->req + k->reqoff, k->reqlen - k->reqoff);
            if (n < 0) return fail(k, "TLS", ts_tls_error(&k->tls));
            k->reqoff += (size_t)n;
            if (k->reqoff < k->reqlen) return 1;
            k->state = KF_RECV;
            break;
        case KF_RECV:
            if (k->resplen == sizeof k->resp) return fail(k, "key response too large", NULL);
            n = ts_tls_read(&k->tls, k->resp + k->resplen, sizeof k->resp - k->resplen);
            if (n == 0) return 1;
            if (n == -1) return fail(k, "TLS", ts_tls_error(&k->tls));
            if (n > 0) k->resplen += (size_t)n;
            rc = ts_http1_response(k->resp, k->resplen, n == TS_TLS_CLOSED, &st, &off, &blen);
            if (rc == 1) break;   /* eof makes the parser return 0 or -1, never 1 */
            return finish(k, pub, rc, st, off, blen);
        case KF_DONE:
            memcpy(pub, k->pub, 32);
            return 0;
        default:
            return -1;
        }
    }
}

const char *ts_keyfetch_error(const ts_keyfetch *k)
{
    return k->err;
}

void ts_keyfetch_close(ts_keyfetch *k)
{
    /* Idle owns nothing: a zeroed struct, a closed one. A failed start or
     * fetch has cleaned up already (fail), so cleanup is a no-op there. */
    if (k->state == KF_IDLE) return;
    cleanup(k);
    k->state = KF_IDLE;
}
