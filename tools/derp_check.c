/*
 * Live check of the DERP client against a real relay: TCP, ts_tls, the DERP
 * upgrade and handshake, then one ping. Needs network access. Not installed.
 *
 *   build/ppc-test/derp_check <host> <ipv4> [port]     (built by make ppc-test)
 *   make derp-check && build/test/derp_check <host> <ipv4> [port]
 *
 * host is the relay's name (TLS ServerName and Host), ipv4 its address (no DNS
 * lookup), port defaults to 443. A fresh random key is used, never a node key,
 * and no tailnet state is read. Prints
 *   derp-check: ok handshake <ms> ms, pong <ms> ms
 * (handshake from the TCP connect to a verified ServerInfo; pong is the
 * ping round trip) and exits 0, or prints the failing phase and exits 1.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include "src/core/bytes.h"
#include "src/crypto/random.h"
#include "src/derp/derp.h"
#include "src/net/sock.h"
#include "src/net/tls.h"

#define LIMIT_MS 180000   /* an emulated G4 needs a while for the RSA checks */

static ts_tls tls;
static ts_derp derp;
static uint8_t outq[2 * (5 + 32 + TS_DERP_MAX_PACKET)];
static size_t outq_n, outq_over;
static uint8_t ping_data[8];
static int got_pong;

static int64_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void cb_send(void *user, const uint8_t *p, size_t n)
{
    (void)user;
    if (n > sizeof outq - outq_n) {
        outq_over = 1;
        return;
    }
    memcpy(outq + outq_n, p, n);
    outq_n += n;
}

static void cb_recv(void *user, const uint8_t src[32], const uint8_t *p, size_t n)
{
    (void)user;
    (void)src;
    (void)p;
    (void)n;
}

static void cb_gone(void *user, const uint8_t key[32])
{
    (void)user;
    (void)key;
}

static void cb_health(void *user, const char *text)
{
    (void)user;
    if (text[0]) printf("derp-check: relay health: %s\n", text);
}

static void cb_pong(void *user, const uint8_t data[8])
{
    (void)user;
    if (memcmp(data, ping_data, 8) == 0) got_pong = 1;
}

static const ts_derp_io IO = { cb_send, cb_recv, cb_gone, cb_health, cb_pong };

static int fail(const char *phase, const char *why, int64_t t0)
{
    int br = br_ssl_engine_last_error(&tls.cc.eng);
    printf("derp-check: FAIL %s: %s (BearSSL error %d) after %ld ms\n", phase, why, br,
           (long)(now_ms() - t0));
    return 1;
}

int main(int argc, char **argv)
{
    const char *host, *ip;
    unsigned long port = 443;
    char hosthdr[TS_DERP_HOST_MAX + 1];
    uint8_t priv[32], buf[16384];
    int64_t t0, t_ready = 0, t_ping = 0;
    int fd, rc, tls_done = 0, pinged = 0;

    signal(SIGPIPE, SIG_IGN);
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: derp_check <host> <ipv4> [port]\n");
        return 1;
    }
    host = argv[1];
    ip = argv[2];
    if (argc == 4) {
        char *end;
        port = strtoul(argv[3], &end, 10);
        if (*end || port == 0 || port > 65535) {
            fprintf(stderr, "derp_check: bad port\n");
            return 1;
        }
    }
    if (port == 443)
        snprintf(hosthdr, sizeof hosthdr, "%s", host);
    else
        snprintf(hosthdr, sizeof hosthdr, "%s:%lu", host, port);
    if (ts_random_bytes(priv, sizeof priv) != 0 || ts_random_bytes(ping_data, 8) != 0) {
        printf("derp-check: FAIL no randomness\n");
        return 1;
    }

    t0 = now_ms();
    memset(&tls, 0, sizeof tls);
    fd = ts_tcp_start(ip, (uint16_t)port);
    if (fd < 0 || fd >= FD_SETSIZE) return fail("tcp", "cannot connect", t0);
    for (;;) {
        fd_set w;
        struct timeval tv = { 1, 0 };
        FD_ZERO(&w);
        FD_SET(fd, &w);
        if (select(fd + 1, NULL, &w, NULL, &tv) == 1) break;
        if (now_ms() - t0 > LIMIT_MS) return fail("tcp", "timed out", t0);
    }
    if (ts_tcp_finish(fd) != 0) return fail("tcp", "connect failed", t0);
    if (ts_tls_start(&tls, fd, host) != 0) return fail("tls", "cannot start TLS", t0);

    for (;;) {
        fd_set r, w;
        int want;
        struct timeval tv = { 0, 200000 };

        if (now_ms() - t0 > LIMIT_MS)
            return fail(!tls_done ? "tls" : t_ready ? "pong" : "handshake", "timed out", t0);
        if (!tls_done) {
            rc = ts_tls_step(&tls);
            if (rc < 0) return fail("tls", ts_tls_error(&tls), t0);
            if (rc == 0) {
                br_ssl_session_parameters sp;
                br_ssl_engine_get_session_parameters(&tls.cc.eng, &sp);
                printf("derp-check: tls %ld ms, suite 0x%04x, curve %d\n", (long)(now_ms() - t0),
                       (unsigned)sp.cipher_suite, br_ssl_engine_get_ecdhe_curve(&tls.cc.eng));
                tls_done = 1;
                ts_derp_init(&derp, hosthdr, priv, 0, &IO, NULL);
                ts_wipe(priv, sizeof priv);
                ts_derp_start(&derp, now_ms());
            }
        }
        if (tls_done) {
            int n;
            /* Read everything decrypted so far into the DERP client. */
            while ((n = ts_tls_read(&tls, buf, sizeof buf)) > 0)
                if (ts_derp_feed(&derp, buf, (size_t)n, now_ms()) != 0)
                    return fail(t_ready ? "pong" : "handshake", derp.err, t0);
            if (n == TS_TLS_CLOSED) return fail(t_ready ? "pong" : "handshake", "relay closed the connection", t0);
            if (n < 0) return fail(t_ready ? "pong" : "handshake", ts_tls_error(&tls), t0);
            if (ts_derp_tick(&derp, now_ms()) != 0)
                return fail(t_ready ? "pong" : "handshake", derp.err, t0);
            if (ts_derp_ready(&derp) && !t_ready) t_ready = now_ms();
            if (t_ready && !pinged) {
                if (ts_derp_ping(&derp, ping_data) != 0) return fail("pong", "cannot ping", t0);
                t_ping = now_ms();
                pinged = 1;
            }
            if (got_pong) {
                int64_t t = now_ms();
                printf("derp-check: ok handshake %ld ms, pong %ld ms\n", (long)(t_ready - t0),
                       (long)(t - t_ping));
                ts_derp_free(&derp);
                ts_tls_wipe(&tls);
                close(fd);
                return 0;
            }
            if (outq_over) return fail("handshake", "send queue overflow", t0);
            /* Write what the client queued. */
            while (outq_n > 0) {
                n = ts_tls_write(&tls, outq, outq_n);
                if (n < 0) return fail(t_ready ? "pong" : "handshake", ts_tls_error(&tls), t0);
                if (n == 0) break;
                memmove(outq, outq + n, outq_n - (size_t)n);
                outq_n -= (size_t)n;
            }
            if (ts_tls_pending(&tls)) continue;
        }
        want = ts_tls_want(&tls);
        FD_ZERO(&r);
        FD_ZERO(&w);
        if (want & TS_TLS_WANT_READ) FD_SET(fd, &r);
        if ((want & TS_TLS_WANT_WRITE) || outq_n > 0) FD_SET(fd, &w);
        (void)select(fd + 1, &r, &w, NULL, &tv);
    }
}
