/* tsppc: the command-line client of tsppcd.
 *
 *   tsppc up       log in and connect; prints the login URL when one is needed
 *   tsppc status   state, tailnet IP, any problem, and the peers
 *   tsppc ip       the tailnet IPv4 address
 *   tsppc logout   expire this node's key at control and forget the login
 *
 * Exit status: 0 done, 1 failed or tsppcd not reachable, 2 usage.
 * Everything the daemon sends is cleaned of control bytes before it is shown. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "src/daemon/ipc.h"

#define REPLY_TIMEOUT_S 30
#define UP_TIMEOUT_S 900        /* up gives up waiting after this (tsppcd keeps going) */
#define LOGOUT_TIMEOUT_S 90
#define POLL_MS 1000

typedef struct {
    char *buf;                  /* the reply, NUL-terminated */
    size_t len;
} reply;

static char *rbuf;

static void usage(void)
{
    fprintf(stderr, "usage: tsppc <up|status|ip|logout>\n");
}

static void sleep_ms(int ms)
{
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)select(0, NULL, NULL, NULL, &tv);
}

/* Send one request and read the whole reply. 0, or -1 (message printed). */
static int request(ts_ipc_cmd cmd, reply *r)
{
    const char *path = ts_ipc_socket_path();
    const char *line = ts_ipc_cmd_line(cmd);
    time_t until = time(NULL) + REPLY_TIMEOUT_S;
    size_t off = 0, n = strlen(line);
    int fd = ts_ipc_connect(path);
    char safe[256];

    r->buf = rbuf;
    r->len = 0;
    rbuf[0] = 0;
    if (fd < 0) {
        ts_ipc_clean(safe, sizeof safe, path, strlen(path), 0);
        fprintf(stderr, "tsppc: cannot reach tsppcd at %s: %s\n", safe, strerror(errno));
        return -1;
    }
    while (off < n) {
        ssize_t w = write(fd, line + off, n - off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            fprintf(stderr, "tsppc: cannot send to tsppcd\n");
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    for (;;) {
        fd_set rs;
        struct timeval tv = { 1, 0 };
        ssize_t k;
        if (time(NULL) > until) {
            fprintf(stderr, "tsppc: tsppcd did not answer\n");
            close(fd);
            return -1;
        }
        FD_ZERO(&rs);
        FD_SET(fd, &rs);
        if (select(fd + 1, &rs, NULL, NULL, &tv) <= 0) continue;
        if (r->len == TS_IPC_RESP_MAX) break;   /* the daemon never sends more */
        k = read(fd, rbuf + r->len, TS_IPC_RESP_MAX - r->len);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        r->len += (size_t)k;
    }
    close(fd);
    rbuf[r->len] = 0;
    if (r->len == 0) {
        fprintf(stderr, "tsppc: tsppcd closed the connection (busy?)\n");
        return -1;
    }
    return 0;
}

/* Iterate the reply's lines: on each call, the next line with key and value
 * (both cleaned into the caller's buffers). Returns 0 at the end. Malformed
 * lines are skipped. */
static int next_line(const reply *r, size_t *pos, char *key, size_t kcap, char *val, size_t vcap)
{
    while (*pos < r->len) {
        const char *l = r->buf + *pos;
        const char *nl = memchr(l, '\n', r->len - *pos);
        size_t n = nl ? (size_t)(nl - l) : r->len - *pos, k, v;
        *pos += n + (nl ? 1 : 0);
        if (ts_ipc_split(l, n, &k, &v) != 0) continue;
        ts_ipc_clean(key, kcap, l, k, 0);
        ts_ipc_clean(val, vcap, l + v, n - v, 0);
        return 1;
    }
    return 0;
}

/* The value of the first line with this key, cleaned, or "" if none. */
static int field(const reply *r, const char *want, char *val, size_t vcap)
{
    size_t pos = 0;
    char key[32];
    while (next_line(r, &pos, key, sizeof key, val, vcap))
        if (strcmp(key, want) == 0) return 1;
    val[0] = 0;
    return 0;
}

static int check_ok(const reply *r)
{
    char v[256];
    if (field(r, "ok", v, sizeof v)) return 0;
    if (field(r, "error", v, sizeof v)) fprintf(stderr, "tsppc: %s\n", v);
    else fprintf(stderr, "tsppc: unexpected reply from tsppcd\n");
    return -1;
}

static int cmd_status(void)
{
    reply r;
    size_t pos = 0;
    char key[32], val[1500];
    int peers = 0;
    if (request(TS_IPC_STATUS, &r) != 0 || check_ok(&r) != 0) return 1;
    while (next_line(&r, &pos, key, sizeof key, val, sizeof val)) {
        if (strcmp(key, "status") == 0) printf("%s\n", val);
        else if (strcmp(key, "ip") == 0) printf("Tailnet IP: %s\n", val);
        else if (strcmp(key, "problem") == 0) printf("Problem: %s\n", val);
        else if (strcmp(key, "url") == 0) printf("Log in at: %s\n", val);
        else if (strcmp(key, "truncated") == 0) printf("(list truncated)\n");
        else if (strcmp(key, "peer") == 0) {
            char ip[32], on[16];
            const char *name;
            if (!peers++) printf("Peers:\n");
            if (sscanf(val, "%31s %15s", ip, on) != 2) continue;
            name = strchr(val, ' ');
            name = name ? strchr(name + 1, ' ') : NULL;
            printf("  %-15s  %-7s  %s\n", ip, on, name ? name + 1 : "");
        }
    }
    return 0;
}

static int cmd_ip(void)
{
    reply r;
    char v[64], st[32];
    if (request(TS_IPC_IP, &r) != 0 || check_ok(&r) != 0) return 1;
    if (field(&r, "ip", v, sizeof v)) {
        printf("%s\n", v);
        return 0;
    }
    field(&r, "state", st, sizeof st);
    fprintf(stderr, "tsppc: no tailnet IP yet (%s)\n", st[0] ? st : "unknown state");
    return 1;
}

static int cmd_up(void)
{
    reply r;
    char st[32], last[32] = "", status[1400], url[1100], shown[1100] = "", prob[512], lastprob[512] = "";
    time_t until = time(NULL) + UP_TIMEOUT_S;
    if (request(TS_IPC_UP, &r) != 0 || check_ok(&r) != 0) return 1;
    for (;;) {
        field(&r, "state", st, sizeof st);
        field(&r, "status", status, sizeof status);
        field(&r, "problem", prob, sizeof prob);
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
            fprintf(stderr, "tsppc: %s\n", status);
            return 1;
        }
        if (field(&r, "url", url, sizeof url) && strcmp(url, shown) != 0) {
            printf("\nTo log in, visit:\n\n\t%s\n\n", url);
            fflush(stdout);
            memcpy(shown, url, sizeof shown);
        } else if (strcmp(st, last) != 0 && strcmp(st, "NEED_LOGIN") != 0) {
            printf("%s\n", strcmp(st, "BACKOFF") == 0 ? "Waiting to reconnect..." : "Connecting...");
            fflush(stdout);
        }
        if (prob[0] && strcmp(prob, lastprob) != 0) {
            fprintf(stderr, "tsppc: %s\n", prob);
            memcpy(lastprob, prob, sizeof lastprob);
        }
        memcpy(last, st, sizeof last);
        if (time(NULL) > until) {
            fprintf(stderr, "tsppc: still not logged in; tsppcd keeps trying (see tsppc status)\n");
            return 1;
        }
        sleep_ms(POLL_MS);
        if (request(TS_IPC_STATUS, &r) != 0 || check_ok(&r) != 0) return 1;
    }
}

static int cmd_logout(void)
{
    reply r;
    char login[32], status[1400];
    time_t until = time(NULL) + LOGOUT_TIMEOUT_S;
    if (request(TS_IPC_LOGOUT, &r) != 0 || check_ok(&r) != 0) return 1;
    for (;;) {
        field(&r, "login", login, sizeof login);
        if (strcmp(login, "no") == 0) {
            printf("Logged out.\n");
            return 0;
        }
        if (time(NULL) > until) {
            field(&r, "status", status, sizeof status);
            fprintf(stderr, "tsppc: logout not confirmed by control yet; tsppcd keeps trying (%s)\n", status);
            return 1;
        }
        sleep_ms(POLL_MS);
        if (request(TS_IPC_STATUS, &r) != 0 || check_ok(&r) != 0) return 1;
    }
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc != 2) {
        usage();
        return 2;
    }
    rbuf = (char *)malloc(TS_IPC_RESP_MAX + 1);
    if (!rbuf) {
        fprintf(stderr, "tsppc: out of memory\n");
        return 1;
    }
    if (strcmp(argv[1], "status") == 0) return cmd_status();
    if (strcmp(argv[1], "ip") == 0) return cmd_ip();
    if (strcmp(argv[1], "up") == 0) return cmd_up();
    if (strcmp(argv[1], "logout") == 0) return cmd_logout();
    usage();
    return 2;
}
