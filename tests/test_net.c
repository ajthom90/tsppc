#include "harness.h"
#include "../src/net/sock.h"
#include "../src/net/resolve.h"
#include "../src/net/tls.h"
#include "../src/net/keyfetch.h"
#include "../src/control/noise.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "anchors_der.inc"

#define KEYHEX "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static int keyparse(uint8_t pub[32], const char *s)
{
    return ts_control_key_parse(pub, s, strlen(s));
}

static void test_key_parse(void)
{
    uint8_t pub[32];
    memset(pub, 0, sizeof pub);
    t_true("key: pretty JSON", keyparse(pub,
        "{\n  \"legacyPublicKey\" : \"mkey:" KEYHEX "\",\n"
        "  \"publicKey\"\t:\r\n \"mkey:" KEYHEX "\"\n}\n") == 0);
    t_hex("key: value", pub, 32, KEYHEX);
    t_true("key: compact, upper-case hex", keyparse(pub,
        "{\"publicKey\":\"mkey:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef\"}") == 0);
    t_hex("key: upper-case value", pub, 32, KEYHEX);
    t_true("key: other members skipped", keyparse(pub,
        "{\"x\":[1,{\"publicKey\":\"no\"}],\"publicKey\":\"mkey:" KEYHEX "\",\"y\":null}") == 0);
    t_true("key: wrong prefix", keyparse(pub, "{\"publicKey\":\"nodekey:" KEYHEX "\"}") == -1);
    t_true("key: no prefix", keyparse(pub, "{\"publicKey\":\"" KEYHEX "\"}") == -1);
    t_true("key: short", keyparse(pub, "{\"publicKey\":\"mkey:" KEYHEX "\"}") == 0 &&
           keyparse(pub, "{\"publicKey\":\"mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\"}") == -1);
    t_true("key: long", keyparse(pub, "{\"publicKey\":\"mkey:" KEYHEX "00\"}") == -1);
    t_true("key: non-hex", keyparse(pub,
        "{\"publicKey\":\"mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg\"}") == -1);
    t_true("key: missing", keyparse(pub, "{\"legacyPublicKey\":\"mkey:" KEYHEX "\"}") == -1);
    t_true("key: duplicate", keyparse(pub,
        "{\"publicKey\":\"mkey:" KEYHEX "\",\"publicKey\":\"mkey:" KEYHEX "\"}") == -1);
    t_true("key: not a string", keyparse(pub, "{\"publicKey\":7}") == -1);
    t_true("key: not an object", keyparse(pub, "[\"mkey:" KEYHEX "\"]") == -1);
    t_true("key: trailing garbage", keyparse(pub, "{\"publicKey\":\"mkey:" KEYHEX "\"} x") == -1);
    t_true("key: truncated", keyparse(pub, "{\"publicKey\":\"mkey:" KEYHEX "\"") == -1);
    t_true("key: empty", ts_control_key_parse(pub, "", 0) == -1);
}

static int http(const char *s, int eof, int *status, size_t *off, size_t *blen)
{
    return ts_http1_response(s, strlen(s), eof, status, off, blen);
}

static void test_http1(void)
{
    int st;
    size_t off, n;
    const char *r = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-length: 4\r\n\r\nabcd";
    t_true("http: complete", http(r, 0, &st, &off, &n) == 0 && st == 200 &&
           n == 4 && memcmp(r + off, "abcd", 4) == 0);
    t_true("http: body short", ts_http1_response(r, strlen(r) - 1, 0, &st, &off, &n) == 1);
    t_true("http: body short at eof", ts_http1_response(r, strlen(r) - 1, 1, &st, &off, &n) == -1);
    t_true("http: headers short", ts_http1_response(r, 20, 0, &st, &off, &n) == 1);
    t_true("http: extra bytes", http("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab", 0, &st, &off, &n) == -1);
    t_true("http: close-delimited", http("HTTP/1.1 200 OK\r\n\r\nxyz", 0, &st, &off, &n) == 1 &&
           http("HTTP/1.1 200 OK\r\n\r\nxyz", 1, &st, &off, &n) == 0 && n == 3);
    t_true("http: bare LF", http("HTTP/1.0 200 OK\nContent-Length: 2\n\nhi", 0, &st, &off, &n) == 0 && n == 2);
    t_true("http: status", http("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 0, &st, &off, &n) == 0 &&
           st == 404);
    t_true("http: non-200 needs no body", http("HTTP/1.1 503 x\r\n\r\n", 0, &st, &off, &n) == 0 && st == 503);
    t_true("http: chunked refused", http("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
                                         0, &st, &off, &n) == -1);
    t_true("http: conflicting lengths", http("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
                                             0, &st, &off, &n) == -1);
    t_true("http: bad length", http("HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\na", 0, &st, &off, &n) == -1);
    t_true("http: huge length", http("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
                                     0, &st, &off, &n) == -1);
    t_true("http: bad status line", http("HTTP/1.1 20 OK\r\n\r\n", 0, &st, &off, &n) == -1 &&
           http("HTTP/2 200 OK\r\n\r\n", 0, &st, &off, &n) == -1 &&
           http("ICY 200 OK\r\n\r\n", 0, &st, &off, &n) == -1);
    t_true("http: bad header", http("HTTP/1.1 200 OK\r\nno colon\r\n\r\n", 0, &st, &off, &n) == -1);
    t_true("http: eof in headers", http("HTTP/1.1 200 OK\r\n", 1, &st, &off, &n) == -1);
}

/* Wait for fd to become readable (rd) or writable; 1 if it did. */
static int wait_fd(int fd, int rd, int ms)
{
    fd_set s;
    struct timeval tv;
    FD_ZERO(&s);
    FD_SET(fd, &s);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(fd + 1, rd ? &s : NULL, rd ? NULL : &s, NULL, &tv) == 1;
}

static int listener(uint16_t *port)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0 ||
        getsockname(s, (struct sockaddr *)&a, &al) != 0) {
        if (s >= 0) close(s);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return s;
}

static void test_tcp(void)
{
    uint16_t port = 0;
    int l = listener(&port), fd, c, fl;
    t_true("tcp: listener", l >= 0);
    fd = ts_tcp_start("127.0.0.1", port);
    t_true("tcp: start", fd >= 0);
    fl = fcntl(fd, F_GETFL);
    t_true("tcp: non-blocking", fl >= 0 && (fl & O_NONBLOCK));
    t_true("tcp: close-on-exec", (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    t_true("tcp: writable", wait_fd(fd, 0, 5000));
    t_true("tcp: connected", ts_tcp_finish(fd) == 0);
    c = accept(l, NULL, NULL);
    t_true("tcp: accepted", c >= 0);
    if (c >= 0) close(c);
    close(fd);
    close(l);

    /* A port with nothing listening: refused. */
    fd = ts_tcp_start("127.0.0.1", port);
    if (fd >= 0) {
        t_true("tcp: refused completes", wait_fd(fd, 0, 5000));
        t_true("tcp: refused fails", ts_tcp_finish(fd) == -1);
        close(fd);
    } else {
        t_true("tcp: refused at once", 1);
    }
    t_true("tcp: bad address", ts_tcp_start("127.0.0", 443) == -1 && ts_tcp_start("::1", 443) == -1 &&
           ts_tcp_start("localhost", 443) == -1);
}

/* Run a resolve to completion; returns finish's result. */
static int resolve(const char *host, char *ip, size_t cap)
{
    ts_resolve r;
    int rc, i;
    if (ts_resolve_start(&r, host) != 0) return -2;
    for (i = 0; i < 400; i++) {
        wait_fd(ts_resolve_fd(&r), 1, 100);
        rc = ts_resolve_finish(&r, ip, cap);
        if (rc != 1) return rc;
    }
    ts_resolve_cancel(&r);
    return -3;
}

static int reaped(pid_t pid)
{
    return waitpid(pid, NULL, WNOHANG) == -1 && errno == ECHILD && kill(pid, 0) == -1 && errno == ESRCH;
}

static void test_resolve(void)
{
    char ip[16];
    ts_resolve r;
    pid_t pid;
    int p[2], fd;
    char c;

    t_true("resolve: localhost", resolve("localhost", ip, sizeof ip) == 0 && strcmp(ip, "127.0.0.1") == 0);
    t_true("resolve: literal", resolve("10.1.2.3", ip, sizeof ip) == 0 && strcmp(ip, "10.1.2.3") == 0);
    t_true("resolve: no such host", resolve("no-such-host.invalid", ip, sizeof ip) == -1);
    t_true("resolve: small buffer", resolve("localhost", ip, 9) == -1);
    t_true("resolve: bad name", ts_resolve_start(&r, "") == -1 && ts_resolve_start(&r, "a b") == -1);
    {
        char longname[TS_RESOLVE_NAME_MAX + 2];
        memset(longname, 'a', sizeof longname - 1);
        longname[sizeof longname - 1] = '\0';
        t_true("host name: valid", ts_host_name_ok("controlplane.tailscale.com") &&
               ts_host_name_ok("a-b.c9") && ts_host_name_ok(longname + 1));
        t_true("host name: invalid", !ts_host_name_ok(NULL) && !ts_host_name_ok("") &&
               !ts_host_name_ok("a_b") && !ts_host_name_ok("a/b") && !ts_host_name_ok("a:443") &&
               !ts_host_name_ok(longname));
    }

    /* The helper keeps none of our descriptors: once it has closed them, the
     * write end of this pipe has no holder left and the read end sees EOF while
     * the helper is still alive (held by the test delay). */
    t_true("resolve: pipe", pipe(p) == 0);
    ts_resolve_test_delay = 3;
    t_true("resolve: start delayed", ts_resolve_start(&r, "localhost") == 0);
    ts_resolve_test_delay = 0;
    close(p[1]);
    t_true("resolve: helper closed inherited fds", wait_fd(p[0], 1, 2000) && read(p[0], &c, 1) == 0);
    close(p[0]);
    fd = ts_resolve_fd(&r);
    t_true("resolve: fd non-blocking", (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
    t_true("resolve: fd close-on-exec", (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    t_true("resolve: still pending", ts_resolve_finish(&r, ip, sizeof ip) == 1);
    pid = r.pid;
    ts_resolve_cancel(&r);
    t_true("resolve: cancel reaps the helper", reaped(pid));
    t_true("resolve: cancel closes the pipe", fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    ts_resolve_cancel(&r);   /* second cancel is a no-op */

    t_true("resolve: start again", ts_resolve_start(&r, "localhost") == 0);
    pid = r.pid;
    while (ts_resolve_finish(&r, ip, sizeof ip) == 1) wait_fd(ts_resolve_fd(&r), 1, 100);
    t_true("resolve: finish reaps the helper", reaped(pid));
    ts_resolve_cancel(&r);   /* after finish, a no-op */
}

static void test_classify(void)
{
    const char *clock = "system clock is wrong";
    time_t built = 1700000000;
    t_true("classify: expired", strcmp(ts_tls_classify(BR_ERR_X509_EXPIRED, built + 86400, built), clock) == 0);
    t_true("classify: time unknown", strcmp(ts_tls_classify(BR_ERR_X509_TIME_UNKNOWN, built + 1, built), clock) == 0);
    t_true("classify: untrusted, clock before build",
           strcmp(ts_tls_classify(BR_ERR_X509_NOT_TRUSTED, built - 86400, built), clock) == 0);
    t_true("classify: untrusted, sane clock",
           strcmp(ts_tls_classify(BR_ERR_X509_NOT_TRUSTED, built + 86400, built), clock) != 0);
    t_true("classify: name mismatch",
           strcmp(ts_tls_classify(BR_ERR_X509_BAD_SERVER_NAME, built + 1, built), clock) != 0);
    t_true("classify: io, clock before build",
           strcmp(ts_tls_classify(BR_ERR_IO, built - 86400, built), clock) != 0);
    t_true("classify: alert", strlen(ts_tls_classify(BR_ERR_RECV_FATAL_ALERT + 40, built + 1, built)) > 0);
    {
        const char *nc = ts_tls_classify(BR_ERR_BAD_CIPHER_SUITE, built + 1, built);
        t_true("classify: no common suite", strstr(nc, "ChaCha20") != NULL);
        t_true("classify: handshake_failure alert",
               strcmp(ts_tls_classify(BR_ERR_RECV_FATAL_ALERT + 40, built + 1, built), nc) == 0);
        t_true("classify: curve not offered",
               strcmp(ts_tls_classify(BR_ERR_INVALID_ALGORITHM, built + 1, built), nc) == 0);
        t_true("classify: local misconfiguration is not blamed on the server",
               strcmp(ts_tls_classify(BR_ERR_BAD_PARAM, built + 1, built), nc) != 0);
    }
    t_true("classify: unknown", strlen(ts_tls_classify(9999, built + 1, built)) > 0);
}

/* Find TLS extension `type` in a ClientHello record; returns its body or NULL. */
static const uint8_t *hello_ext(const uint8_t *m, size_t n, unsigned type, size_t *len,
                                const uint8_t **suites, size_t *nsuites)
{
    size_t p = 5 + 4 + 2 + 32, end, l;
    if (n < p + 1 || m[0] != 22 || m[5] != 1) return NULL;
    p += 1 + m[p];                                  /* session id */
    if (p + 2 > n) return NULL;
    l = ((size_t)m[p] << 8) | m[p + 1];
    *suites = m + p + 2;
    *nsuites = l / 2;
    p += 2 + l;
    if (p + 1 > n) return NULL;
    p += 1 + m[p];                                  /* compression */
    if (p + 2 > n) return NULL;
    end = p + 2 + (((size_t)m[p] << 8) | m[p + 1]);
    if (end > n) return NULL;
    p += 2;
    while (p + 4 <= end) {
        unsigned t = ((unsigned)m[p] << 8) | m[p + 1];
        l = ((size_t)m[p + 2] << 8) | m[p + 3];
        if (p + 4 + l > end) return NULL;
        if (t == type) { *len = l; return m + p + 4; }
        p += 4 + l;
    }
    return NULL;
}

/* The engine hands its own EC code (X25519, no ECDSA) to its ECDSA verifier.
 * The installed verifier must still check a P-256 signature. The key is a
 * fixed test value. */
static void check_ske_verifier(const br_ssl_engine_context *e)
{
    static const unsigned char x[32] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };
    br_ec_private_key sk = { BR_EC_secp256r1, (unsigned char *)x, sizeof x };
    unsigned char q[BR_EC_KBUF_PUB_MAX_SIZE], sig[80], hash[32];
    br_ec_public_key pk;
    size_t qlen, slen;
    int ok;

    memset(hash, 0x42, sizeof hash);
    qlen = br_ec_compute_pub(&br_ec_all_m31, NULL, q, &sk);
    pk.curve = BR_EC_secp256r1;
    pk.q = q;
    pk.qlen = qlen;
    slen = br_ecdsa_i31_sign_asn1(&br_ec_all_m31, &br_sha256_vtable, hash, &sk, sig);
    ok = qlen == 65 && slen > 0 && e->iecdsa != NULL &&
         e->iecdsa(e->iec, hash, sizeof hash, &pk, sig, slen) == 1;
    t_true("tls: SKE ECDSA verify works with the X25519 engine", ok);
    hash[0] ^= 1;
    t_true("tls: SKE ECDSA verify rejects a bad signature",
           e->iecdsa != NULL && e->iecdsa(e->iec, hash, sizeof hash, &pk, sig, slen) == 0);
}

static void test_tls_config(void)
{
    static ts_tls t;
    static uint8_t hello[4096];
    const br_ssl_engine_context *e = &t.cc.eng;
    const uint8_t *g, *suites = NULL;
    size_t gl = 0, ns = 0;
    ssize_t n;
    int sp[2], i, ok;

    t_true("tls: socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    t_true("tls: start", ts_tls_start(&t, sp[0], "controlplane.example") == 0);
    t_true("tls: TLS 1.2 only", e->version_min == BR_TLS12 && e->version_max == BR_TLS12);
    t_true("tls: two ChaCha20 suites", e->suites_num == 2 &&
           e->suites_buf[0] == BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 &&
           e->suites_buf[1] == BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    t_true("tls: X25519 engine", e->iec == &br_ec_c25519_m31 &&
           e->iec->supported_curves == ((uint32_t)1 << BR_EC_curve25519));
    t_true("tls: ctmul32 Poly1305", e->ipoly == &br_poly1305_ctmul32_run);
    t_true("tls: ct ChaCha20", e->ichacha == &br_chacha20_ct_run);
    t_true("tls: no GCM, CBC, CCM or DES", e->ighash == 0 && e->igcm_in == 0 && e->igcm_out == 0 &&
           e->icbc_in == 0 && e->icbc_out == 0 && e->iccm_in == 0 && e->iaes_ctr == 0 &&
           e->iaes_cbcenc == 0 && e->iaes_cbcdec == 0 && e->iaes_ctrcbc == 0 &&
           e->ides_cbcenc == 0 && e->ides_cbcdec == 0);
    t_true("tls: i31 RSA verify", e->irsavrfy == &br_rsa_i31_pkcs1_vrfy &&
           t.xc.irsa == &br_rsa_i31_pkcs1_vrfy);
    t_true("tls: x509 ECDSA on the general curves", t.xc.iec == &br_ec_all_m31 &&
           t.xc.iecdsa == &br_ecdsa_i31_vrfy_asn1);
    check_ske_verifier(e);
    t_true("tls: wants to write the hello", (ts_tls_want(&t) & TS_TLS_WANT_WRITE) != 0);
    t_true("tls: step sends the hello", ts_tls_step(&t) == 1);
    t_true("tls: then waits to read", ts_tls_want(&t) == TS_TLS_WANT_READ);

    n = read(sp[1], hello, sizeof hello);
    g = n > 0 ? hello_ext(hello, (size_t)n, 10, &gl, &suites, &ns) : NULL;
    t_true("tls: hello offers the two suites only", suites != NULL && ns == 2 &&
           suites[0] == 0xcc && suites[1] == 0xa9 && suites[2] == 0xcc && suites[3] == 0xa8);
    t_true("tls: hello offers X25519 only", g != NULL && gl == 4 && g[0] == 0 && g[1] == 2 &&
           g[2] == 0 && g[3] == 29);
    g = n > 0 ? hello_ext(hello, (size_t)n, 0, &gl, &suites, &ns) : NULL;
    t_true("tls: hello carries the server name", g != NULL && gl == 5 + 20 &&
           memcmp(g + 5, "controlplane.example", 20) == 0);

    close(sp[1]);
    ok = 0;
    for (i = 0; i < 10 && !ok; i++) ok = ts_tls_step(&t) == -1;
    t_true("tls: peer close fails the handshake", ok);
    t_true("tls: error text", strlen(ts_tls_error(&t)) > 0);
    t_true("tls: read fails", ts_tls_read(&t, hello, sizeof hello) == -1);
    t_true("tls: write fails", ts_tls_write(&t, "x", 1) == -1);
    ts_tls_wipe(&t);
    t_true("tls: IPv4 literal host refused", ts_tls_start(&t, sp[0], "192.0.2.1") == -1);
    t_true("tls: IPv6 literal host refused", ts_tls_start(&t, sp[0], "2001:db8::1") == -1);
    t_true("tls: empty host refused", ts_tls_start(&t, sp[0], "") == -1);
    ts_tls_wipe(&t);
    close(sp[0]);
}

typedef struct { uint8_t dn[1024]; size_t len; int over; } dnbuf;

static void dn_append(void *ctx, const void *buf, size_t len)
{
    dnbuf *d = (dnbuf *)ctx;
    if (d->len + len > sizeof d->dn) { d->over = 1; return; }
    memcpy(d->dn + d->len, buf, len);
    d->len += len;
}

static int same(const unsigned char *a, size_t al, const unsigned char *b, size_t bl)
{
    return al == bl && memcmp(a, b, al) == 0;
}

/* BearSSL's own decoder must agree with the generated anchors. */
static void test_anchors(void)
{
    char name[96];
    size_t i;

    t_true("anchors: fixture covers every anchor", ANCHOR_FIXTURES == TS_ANCHOR_COUNT);
    for (i = 0; i < TS_ANCHOR_COUNT && i < ANCHOR_FIXTURES; i++) {
        br_x509_decoder_context d;
        const br_x509_trust_anchor *a = &ts_anchors[i];
        const br_x509_pkey *k;
        dnbuf dn;
        int ok;
        memset(&dn, 0, sizeof dn);
        br_x509_decoder_init(&d, dn_append, &dn);
        br_x509_decoder_push(&d, anchor_der[i], anchor_der_len[i]);
        k = br_x509_decoder_get_pkey(&d);
        ok = k != NULL && br_x509_decoder_last_error(&d) == 0 && br_x509_decoder_isCA(&d) &&
             !dn.over && same(dn.dn, dn.len, a->dn.data, a->dn.len) && a->flags == BR_X509_TA_CA &&
             k->key_type == a->pkey.key_type;
        if (ok && k->key_type == BR_KEYTYPE_RSA)
            ok = same(k->key.rsa.n, k->key.rsa.nlen, a->pkey.key.rsa.n, a->pkey.key.rsa.nlen) &&
                 same(k->key.rsa.e, k->key.rsa.elen, a->pkey.key.rsa.e, a->pkey.key.rsa.elen);
        else if (ok)
            ok = k->key.ec.curve == a->pkey.key.ec.curve &&
                 same(k->key.ec.q, k->key.ec.qlen, a->pkey.key.ec.q, a->pkey.key.ec.qlen);
        snprintf(name, sizeof name, "anchors: %s matches BearSSL's decoding", anchor_name[i]);
        t_true(name, ok);
    }
    t_true("anchors: X1 is RSA-4096", ts_anchors[0].pkey.key_type == BR_KEYTYPE_RSA &&
           ts_anchors[0].pkey.key.rsa.nlen == 512);
    t_true("anchors: X2 is P-384", ts_anchors[1].pkey.key_type == BR_KEYTYPE_EC &&
           ts_anchors[1].pkey.key.ec.curve == BR_EC_secp384r1);
    t_true("anchors: YR is RSA-4096", ts_anchors[2].pkey.key_type == BR_KEYTYPE_RSA &&
           ts_anchors[2].pkey.key.rsa.nlen == 512);
    t_true("anchors: YE is P-384", ts_anchors[3].pkey.key_type == BR_KEYTYPE_EC &&
           ts_anchors[3].pkey.key.ec.curve == BR_EC_secp384r1);
    t_true("anchors: build time set", ts_build_time > 1700000000);
}

static void test_keyfetch_args(void)
{
    static ts_keyfetch k;   /* zero-initialised: fd 0 in every descriptor field */
    int fd0 = fcntl(0, F_GETFD) != -1 ? 0 : open("/dev/null", O_RDONLY);

    /* Closing a zeroed struct must not close descriptor 0. */
    ts_keyfetch_close(&k);
    ts_keyfetch_close(&k);
    t_true("keyfetch: close of a zeroed struct leaves fd 0 open", fd0 == 0 && fcntl(0, F_GETFD) != -1);
    t_true("keyfetch: address literal refused", ts_keyfetch_start(&k, "192.0.2.1", TS_CAPVER) == -1 &&
           strlen(ts_keyfetch_error(&k)) > 0);
    ts_keyfetch_close(&k);
    ts_keyfetch_close(&k);
    t_true("keyfetch: bad host", ts_keyfetch_start(&k, "bad host", TS_CAPVER) == -1 &&
           strlen(ts_keyfetch_error(&k)) > 0);
    ts_keyfetch_close(&k);
    t_true("keyfetch: bad capver", ts_keyfetch_start(&k, "example.com", 0) == -1);
    ts_keyfetch_close(&k);
}

/* ---- ts_tls over a local socketpair --------------------------------------
 * A BearSSL server in this process, with a fresh P-256 key; the client's
 * certificate check is replaced by that known key (no certificate here could
 * chain to the real anchors). Everything else is ts_tls as the daemon uses it. */

static int srv_pump(br_ssl_engine_context *e, int fd)
{
    int progress = 0;
    for (;;) {
        unsigned st = br_ssl_engine_current_state(e);
        unsigned char *b;
        size_t len;
        ssize_t n;
        int moved = 0;
        if (st & BR_SSL_CLOSED) return progress;
        if (st & BR_SSL_SENDREC) {
            b = br_ssl_engine_sendrec_buf(e, &len);
            n = send(fd, b, len, 0);
            if (n > 0) {
                br_ssl_engine_sendrec_ack(e, (size_t)n);
                moved = 1;
            }
        }
        b = br_ssl_engine_recvrec_buf(e, &len);
        if (b && len) {
            n = recv(fd, b, len, 0);
            if (n > 0) {
                br_ssl_engine_recvrec_ack(e, (size_t)n);
                moved = 1;
            }
        }
        if (!moved) return progress;
        progress = 1;
    }
}

static void test_tls_loopback(void)
{
    static br_ssl_server_context sc;
    static unsigned char sbuf[BR_SSL_BUFSIZE_BIDI];
    static ts_tls c;
    static unsigned char rbuf[8000];
    br_hmac_drbg_context rng;
    br_ec_private_key sk;
    br_ec_public_key pk;
    br_x509_knownkey_context kk;
    br_x509_certificate chain;
    unsigned char kbuf[BR_EC_KBUF_PRIV_MAX_SIZE], pbuf[BR_EC_KBUF_PUB_MAX_SIZE], seed[32], dummy[1] = { 0x30 };
    int sv[2], rc = 1, i, got = 0, pending_seen = 0, want_read_seen = 0, n;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        t_true("tls loop: socketpair", 0);
        return;
    }
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    memset(seed, 7, sizeof seed);
    br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof seed);
    t_true("tls loop: server key", br_ec_keygen(&rng.vtable, &br_ec_all_m31, &sk, kbuf, BR_EC_secp256r1) > 0 &&
           br_ec_compute_pub(&br_ec_all_m31, &pk, pbuf, &sk) > 0);
    chain.data = dummy;
    chain.data_len = sizeof dummy;
    br_ssl_server_init_full_ec(&sc, &chain, 1, BR_KEYTYPE_EC, &sk);
    br_ssl_engine_set_buffer(&sc.eng, sbuf, sizeof sbuf, 1);
    br_ssl_server_reset(&sc);

    t_true("tls loop: client start", ts_tls_start(&c, sv[0], "control.example.test") == 0);
    br_x509_knownkey_init_ec(&kk, &pk, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN);
    br_ssl_engine_set_x509(&c.cc.eng, &kk.vtable);
    t_true("tls loop: nothing pending before the handshake", ts_tls_pending(&c) == 0);

    for (i = 0; i < 200 && rc == 1; i++) {
        rc = ts_tls_step(&c);
        srv_pump(&sc.eng, sv[1]);
    }
    t_true("tls loop: handshake", rc == 0);

    /* The server sends more than one small read takes. */
    {
        unsigned char *b;
        size_t room, off = 0;
        static unsigned char msg[6000];
        for (i = 0; i < (int)sizeof msg; i++) msg[i] = (unsigned char)i;
        while (off < sizeof msg) {
            b = br_ssl_engine_sendapp_buf(&sc.eng, &room);
            if (!b) break;
            if (room > sizeof msg - off) room = sizeof msg - off;
            memcpy(b, msg + off, room);
            br_ssl_engine_sendapp_ack(&sc.eng, room);
            br_ssl_engine_flush(&sc.eng, 0);
            off += room;
            for (i = 0; i < 50; i++) {
                srv_pump(&sc.eng, sv[1]);
                n = ts_tls_read(&c, rbuf + got, 10);   /* small reads leave data in the engine */
                if (n > 0) got += n;
                if (ts_tls_pending(&c)) {
                    pending_seen = 1;
                    if (ts_tls_want(&c) & TS_TLS_WANT_READ) want_read_seen = 1;
                }
            }
        }
        t_true("tls loop: data left after a small read is reported pending", pending_seen);
        (void)want_read_seen;   /* ts_tls_want may or may not ask for more: pending is what counts */
        for (i = 0; i < 2000 && got < (int)sizeof msg; i++) {
            srv_pump(&sc.eng, sv[1]);
            n = ts_tls_read(&c, rbuf + got, sizeof rbuf - got);
            if (n > 0) got += n;
        }
        t_true("tls loop: all data read", got == (int)sizeof msg && memcmp(rbuf, msg, sizeof msg) == 0);
        t_true("tls loop: nothing pending once drained", ts_tls_pending(&c) == 0);
    }
    ts_tls_wipe(&c);
    close(sv[0]);
    close(sv[1]);
}

void test_net(void)
{
    signal(SIGPIPE, SIG_IGN);
    test_key_parse();
    test_http1();
    test_tcp();
    test_resolve();
    test_classify();
    test_tls_config();
    test_anchors();
    test_keyfetch_args();
    test_tls_loopback();
}
