/*
 * Live check of the TLS client: fetch the control server's Noise key with
 * ts_keyfetch and report the negotiated cipher suite and curve. Needs network
 * access. Not installed.
 *
 *   build/ppc-test/keyfetch_check [host]     (built by make ppc-test)
 *   make keyfetch-check && build/test/keyfetch_check [host]
 *
 * host defaults to controlplane.tailscale.com. Prints one line and exits 0 on
 * success, 1 on failure. Only the first 8 hex digits of the (public) key are
 * shown.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#include "src/control/noise.h"
#include "src/net/keyfetch.h"
#include "src/proto/encoding.h"

#define LIMIT_SEC 180   /* an emulated G4 needs a while for the RSA checks */

static ts_keyfetch kf;

static const char *suite_name(unsigned s)
{
    switch (s) {
    case BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: return "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    case BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: return "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    default: return "unexpected";
    }
}

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "controlplane.tailscale.com";
    uint8_t pub[32];
    char hex[65];
    time_t t0 = time(NULL);
    int rc;

    signal(SIGPIPE, SIG_IGN);
    if (ts_keyfetch_start(&kf, host, TS_CAPVER) != 0) {
        printf("keyfetch_check: FAIL %s\n", ts_keyfetch_error(&kf));
        ts_keyfetch_close(&kf);
        return 1;
    }
    while ((rc = ts_keyfetch_step(&kf, pub)) == 1) {
        fd_set r, w;
        int maxfd = -1;
        struct timeval tv = { 1, 0 };
        if (time(NULL) - t0 > LIMIT_SEC) {
            printf("keyfetch_check: FAIL timed out after %d s\n", LIMIT_SEC);
            ts_keyfetch_close(&kf);
            return 1;
        }
        FD_ZERO(&r);
        FD_ZERO(&w);
        if (ts_keyfetch_fds(&kf, &r, &w, &maxfd) != 0) break;
        (void)select(maxfd + 1, &r, &w, NULL, &tv);
    }
    if (rc != 0) {
        printf("keyfetch_check: FAIL %s (suite 0x%04x, curve %d)\n", ts_keyfetch_error(&kf),
               (unsigned)kf.tls_suite, kf.tls_curve);
        ts_keyfetch_close(&kf);
        return 1;
    }
    ts_hex_encode(hex, sizeof hex, pub, sizeof pub);
    hex[8] = '\0';
    printf("keyfetch_check: PASS key mkey:%s... suite 0x%04x %s, curve %d%s, %ld s\n", hex,
           (unsigned)kf.tls_suite, suite_name(kf.tls_suite), kf.tls_curve,
           kf.tls_curve == BR_EC_curve25519 ? " (X25519)" : " (unexpected)", (long)(time(NULL) - t0));
    ts_keyfetch_close(&kf);
    return 0;
}
