/* tsppc: the command-line client of tsppcd.
 *
 *   tsppc up       log in and connect; prints the login URL when one is needed
 *   tsppc status   state, tailnet IP, any problem, and the peers
 *   tsppc ip       the tailnet IPv4 address
 *   tsppc down     disconnect, stay logged in (tsppc up connects again)
 *   tsppc logout   expire this node's key at control and forget the login
 *
 * Exit status: 0 done, 1 failed or tsppcd not reachable, 2 usage.
 * Everything the daemon sends is cleaned of control bytes before it is shown. */
#include <errno.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include "src/daemon/ipc.h"
#include "src/daemon/ipc_reply.h"

#define REPLY_TIMEOUT_MS 10000
#define UP_TIMEOUT_S 900        /* up gives up waiting after this (tsppcd keeps going) */
#define LOGOUT_TIMEOUT_S 90
#define POLL_MS 1000

/* ts_reply and its peers are large: kept off the stack. */
static char *rbuf;
static size_t rlen;          /* bytes in rbuf */
static ts_reply R;
static ts_reply_peer *peers;
static mach_timebase_info_data_t tb;

/* Monotonic seconds, for timeouts (mach_absolute_time exists from 10.0 on). */
static long mono_s(void)
{
    uint64_t t = mach_absolute_time();
    uint64_t ns = (t / tb.denom) * tb.numer + (t % tb.denom) * tb.numer / tb.denom;
    return (long)(ns / 1000000000u);
}

static void usage(void)
{
    fprintf(stderr, "usage: tsppc <up|down|status|ip|logout>\n");
}

static void sleep_ms(int ms)
{
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)select(0, NULL, NULL, NULL, &tv);
}

/* Send one request and parse the reply into R. 0, or -1 (message printed). */
static int request(ts_ipc_cmd cmd)
{
    const char *path = ts_ipc_socket_path();
    size_t len = 0;
    char safe[256];
    rlen = 0;
    ts_req_result rc;

    errno = 0;
    rc = ts_ipc_request(path, cmd, REPLY_TIMEOUT_MS, rbuf, TS_IPC_RESP_MAX, &len);

    switch (rc) {
    case TS_REQ_OK:
        break;
    case TS_REQ_NO_DAEMON:
    case TS_REQ_DENIED:
        ts_ipc_clean(safe, sizeof safe, path, strlen(path), 0);
        fprintf(stderr, "tsppc: cannot reach tsppcd at %s: %s\n", safe, strerror(errno));
        return -1;
    case TS_REQ_TIMEOUT:
        fprintf(stderr, "tsppc: tsppcd did not answer\n");
        return -1;
    default:
        fprintf(stderr, "tsppc: cannot talk to tsppcd: %s\n", errno ? strerror(errno) : "failed");
        return -1;
    }
    if (len == 0) {
        fprintf(stderr, "tsppc: tsppcd closed the connection (busy?)\n");
        return -1;
    }
    rlen = len;
    if (ts_reply_parse(&R, peers, rbuf, len) != 0) {
        fprintf(stderr, "tsppc: unexpected reply from tsppcd\n");
        return -1;
    }
    return 0;
}

/* The request went through and the daemon said ok; else say why not. */
static int check_ok(void)
{
    if (R.ok) return 0;
    if (R.error[0]) fprintf(stderr, "tsppc: %s\n", R.error);
    else fprintf(stderr, "tsppc: unexpected reply from tsppcd\n");   /* an "error" line with no text */
    return -1;
}

static void fmt_ip(char *out, size_t cap, uint32_t a)
{
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)(a >> 24), (unsigned)(a >> 16 & 255),
             (unsigned)(a >> 8 & 255), (unsigned)(a & 255));
}

/* The status keys ts_reply_parse leaves out: relay, tunnel, filter, names, and one
 * path line per peer with a WireGuard peer. Lines are taken from the reply
 * as received; values are cleaned before they are printed. */
typedef struct {
    char relay[TS_IPC_VALUE_MAX], tunnel[TS_IPC_VALUE_MAX], filter[TS_IPC_VALUE_MAX], names[TS_IPC_VALUE_MAX];
    int have_relay, have_tunnel, have_filter, have_names;
} extra_keys;

static void scan_extras(extra_keys *x, const char *buf, size_t len)
{
    size_t pos = 0;
    memset(x, 0, sizeof *x);
    while (pos < len) {
        const char *line = buf + pos;
        size_t n = 0, klen, voff;
        while (pos + n < len && line[n] != '\n') n++;
        pos += n + 1;
        if (ts_ipc_split(line, n, &klen, &voff) != 0) continue;
        if (klen == 5 && memcmp(line, "relay", 5) == 0 && !x->have_relay) {
            ts_ipc_clean(x->relay, sizeof x->relay, line + voff, n - voff, 0);
            x->have_relay = 1;
        } else if (klen == 6 && memcmp(line, "tunnel", 6) == 0 && !x->have_tunnel) {
            ts_ipc_clean(x->tunnel, sizeof x->tunnel, line + voff, n - voff, 0);
            x->have_tunnel = 1;
        } else if (klen == 6 && memcmp(line, "filter", 6) == 0 && !x->have_filter) {
            ts_ipc_clean(x->filter, sizeof x->filter, line + voff, n - voff, 0);
            x->have_filter = 1;
        } else if (klen == 5 && memcmp(line, "names", 5) == 0 && !x->have_names) {
            ts_ipc_clean(x->names, sizeof x->names, line + voff, n - voff, 0);
            x->have_names = 1;
        }
    }
}

/* "relay <code>  rx <n> tx <n>" for the peer at ip (a.b.c.d), from its path
 * line, or "" when there is none or no session yet (a handshake age of "-"). */
static void peer_path(char *out, size_t cap, const char *buf, size_t len, const char *ip)
{
    size_t pos = 0, iplen = strlen(ip);
    out[0] = 0;
    while (pos < len) {
        const char *line = buf + pos;
        size_t n = 0, klen, voff;
        char val[TS_IPC_VALUE_MAX], code[40], age[24], addr[24];
        unsigned long long rx, tx;
        while (pos + n < len && line[n] != '\n') n++;
        pos += n + 1;
        if (ts_ipc_split(line, n, &klen, &voff) != 0 || klen != 4 || memcmp(line, "path", 4) != 0) continue;
        ts_ipc_clean(val, sizeof val, line + voff, n - voff, 0);
        if (strncmp(val, ip, iplen) != 0 || val[iplen] != ' ') continue;
        if (sscanf(val, "%23s %39s %llu %llu %23s", addr, code, &rx, &tx, age) != 5) continue;
        if (strcmp(age, "-") == 0) return;
        snprintf(out, cap, "  relay %s  rx %llu tx %llu", code, rx, tx);
        return;
    }
}

static int cmd_status(void)
{
    size_t i;
    int down;
    extra_keys x;
    if (request(TS_IPC_STATUS) != 0 || check_ok() != 0) return 1;
    down = strcmp(R.wanted, "down") == 0 && strcmp(R.login, "yes") == 0;
    if (down) printf("Disconnected (tsppc up to connect)\n");
    else if (R.status[0]) printf("%s\n", R.status);
    if (R.url[0]) printf("Log in at: %s\n", R.url);
    if (R.problem[0]) printf("Problem: %s\n", R.problem);
    scan_extras(&x, rbuf, rlen);
    if (R.have_ipv4) {
        char ip[16];
        fmt_ip(ip, sizeof ip, R.ipv4);
        printf("Tailnet IP: %s\n", ip);
    }
    if (x.have_relay) printf("relay: %s\n", x.relay);
    if (x.have_tunnel) printf("tunnel: %s\n", x.tunnel);
    if (x.have_filter) printf("filter: %s\n", x.filter);
    if (x.have_names) printf("names: %s\n", x.names);
    if (R.npeers) printf("Peers:\n");
    for (i = 0; i < R.npeers; i++) {
        char ip[16] = "-", path[128] = "";
        if (R.peers[i].have_ipv4) {
            fmt_ip(ip, sizeof ip, R.peers[i].ipv4);
            peer_path(path, sizeof path, rbuf, rlen, ip);
        }
        printf("  %-15s  %-7s  %s%s\n", ip, R.peers[i].online ? "online" : "offline", R.peers[i].name, path);
    }
    if (R.truncated) printf("(list truncated)\n");
    return 0;
}

static int cmd_ip(void)
{
    if (request(TS_IPC_IP) != 0 || check_ok() != 0) return 1;
    if (R.have_ipv4) {
        char ip[16];
        fmt_ip(ip, sizeof ip, R.ipv4);
        printf("%s\n", ip);
        return 0;
    }
    fprintf(stderr, "tsppc: no tailnet IP yet (%s)\n", R.state[0] ? R.state : "unknown state");
    return 1;
}

static int cmd_up(void)
{
    char last[32] = "", shown[TS_IPC_VALUE_MAX] = "", lastprob[TS_IPC_VALUE_MAX] = "";
    long until = mono_s() + UP_TIMEOUT_S;
    if (request(TS_IPC_UP) != 0 || check_ok() != 0) return 1;
    for (;;) {
        const char *st = R.state;
        if (strcmp(st, "RUNNING") == 0) {
            printf("Logged in and connected.\n");
            return 0;
        }
        if (strcmp(st, "AWAIT_APPROVAL") == 0) {
            printf("Logged in. This device is waiting for approval in the admin console;\n"
                   "it connects by itself once approved (see tsppc status).\n");
            return 0;
        }
        if (strcmp(st, "FAILED") == 0) {
            fprintf(stderr, "tsppc: %s\n", R.status);
            return 1;
        }
        if (R.url[0] && strcmp(R.url, shown) != 0) {
            printf("\nTo log in, visit:\n\n\t%s\n\n", R.url);
            fflush(stdout);
            memcpy(shown, R.url, sizeof shown);
        } else if (strcmp(st, last) != 0 && strcmp(st, "NEED_LOGIN") != 0) {
            printf("%s\n", strcmp(st, "BACKOFF") == 0 ? "Waiting to reconnect..." : "Connecting...");
            fflush(stdout);
        }
        if (R.problem[0] && strcmp(R.problem, lastprob) != 0) {
            fprintf(stderr, "tsppc: %s\n", R.problem);
            memcpy(lastprob, R.problem, sizeof lastprob);
        }
        memcpy(last, st, sizeof last);
        if (mono_s() > until) {
            fprintf(stderr, "tsppc: still not logged in; tsppcd keeps trying (see tsppc status)\n");
            return 1;
        }
        sleep_ms(POLL_MS);
        if (request(TS_IPC_STATUS) != 0 || check_ok() != 0) return 1;
    }
}

static int cmd_down(void)
{
    /* A failed first save comes back as an error: nothing was changed. */
    if (request(TS_IPC_DOWN) != 0 || check_ok() != 0) return 1;
    printf("Disconnected. Run tsppc up to connect again.\n");
    return 0;
}

static int cmd_logout(void)
{
    long until = mono_s() + LOGOUT_TIMEOUT_S;
    /* A failed first save comes back as an error: nothing was changed. */
    if (request(TS_IPC_LOGOUT) != 0 || check_ok() != 0) return 1;
    for (;;) {
        const char *login = R.login, *st = R.state, *status = R.status, *prob = R.problem;
        if (strcmp(login, "no") == 0) {
            /* Anything but a plain logout is shown as the daemon put it. */
            if (prob[0]) printf("%s\n", status);
            else printf("Logged out.\n");
            return strcmp(st, "FAILED") == 0 ? 1 : 0;
        }
        if (strcmp(login, "leaving") == 0 && (strcmp(st, "FAILED") == 0 || strstr(status, "logout saved"))) {
            /* Saved, and control not reachable yet (no control key) or no
             * randomness: the key never logs in again; tsppcd finishes later. */
            printf("%s\n", status);
            return strcmp(st, "FAILED") == 0 ? 1 : 0;
        }
        if (mono_s() > until) {
            fprintf(stderr, "tsppc: logout not finished yet; tsppcd keeps going (%s)\n", status);
            return 1;
        }
        sleep_ms(POLL_MS);
        if (request(TS_IPC_STATUS) != 0 || check_ok() != 0) return 1;
    }
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    mach_timebase_info(&tb);
    if (argc != 2) {
        usage();
        return 2;
    }
    rbuf = (char *)malloc(TS_IPC_RESP_MAX);
    peers = (ts_reply_peer *)malloc(TS_MAX_PEERS * sizeof *peers);
    if (!rbuf || !peers) {
        fprintf(stderr, "tsppc: out of memory\n");
        return 1;
    }
    if (strcmp(argv[1], "status") == 0) return cmd_status();
    if (strcmp(argv[1], "ip") == 0) return cmd_ip();
    if (strcmp(argv[1], "up") == 0) return cmd_up();
    if (strcmp(argv[1], "down") == 0) return cmd_down();
    if (strcmp(argv[1], "logout") == 0) return cmd_logout();
    usage();
    return 2;
}
