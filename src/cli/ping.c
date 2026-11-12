#include "src/cli/ping.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "src/daemon/ipc.h"

/* ---- Flags ------------------------------------------------------------- */

/* Go's strconv.ParseBool. 0 or -1. */
static int parse_bool(const char *s, int *out)
{
    static const char *const t[] = { "1", "t", "T", "TRUE", "true", "True" };
    static const char *const f[] = { "0", "f", "F", "FALSE", "false", "False" };
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (strcmp(s, t[i]) == 0) {
            *out = 1;
            return 0;
        }
        if (strcmp(s, f[i]) == 0) {
            *out = 0;
            return 0;
        }
    }
    return -1;
}

/* A decimal integer with an optional sign, fitting a long. 0 or -1. */
static int parse_long(const char *s, long *out)
{
    char *end;
    long v;
    if (!s[0] || s[0] == ' ' || s[0] == '\t') return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || *end != 0 || end == s) return -1;
    *out = v;
    return 0;
}

int ts_ping_parse_duration(const char *s, uint32_t *ms)
{
    const uint64_t max_us = 10ull * 60 * 1000000;   /* 10 minutes */
    uint64_t total = 0;
    if (strcmp(s, "0") == 0) {
        *ms = 0;
        return 0;
    }
    if (!s[0]) return -1;
    while (*s) {
        uint64_t whole = 0, frac = 0, scale = 1, unit;
        int wd = 0, fd = 0;
        while (*s >= '0' && *s <= '9') {
            if (++wd > 9) return -1;
            whole = whole * 10 + (uint64_t)(*s++ - '0');
        }
        if (*s == '.') {
            s++;
            while (*s >= '0' && *s <= '9') {
                if (fd < 9) {
                    frac = frac * 10 + (uint64_t)(*s - '0');
                    scale *= 10;
                }
                fd++;
                s++;
            }
        }
        if (wd == 0 && fd == 0) return -1;
        if (s[0] == 'm' && s[1] == 's') {
            unit = 1000;
            s += 2;
        } else if (s[0] == 's') {
            unit = 1000000;
            s += 1;
        } else if (s[0] == 'm') {
            unit = 60000000;
            s += 1;
        } else {
            return -1;   /* no unit, or one not taken here */
        }
        total += whole * unit + frac * unit / scale;
        if (total > max_us) return -1;
    }
    *ms = (uint32_t)(total / 1000);
    return 0;
}

int ts_ping_parse_args(int argc, char **argv, ts_ping_opts *o, char *err, size_t errcap)
{
    int i;
    o->count = 10;
    o->timeout_ms = 5000;
    o->until_direct = 1;
    o->target = NULL;
    if (errcap) err[0] = 0;
    for (i = 0; i < argc; i++) {
        const char *a = argv[i], *name, *eq, *val = NULL;
        char nm[32];
        size_t nl;
        if (a[0] != '-' || a[1] == 0) break;          /* the first non-flag, or "-" */
        if (strcmp(a, "--") == 0) {
            i++;
            break;
        }
        name = a + (a[1] == '-' ? 2 : 1);
        if (!name[0] || name[0] == '-' || name[0] == '=') {
            snprintf(err, errcap, "bad flag syntax: %.40s", a);
            return -1;
        }
        eq = strchr(name, '=');
        nl = eq ? (size_t)(eq - name) : strlen(name);
        if (nl >= sizeof nm) nl = sizeof nm - 1;
        memcpy(nm, name, nl);
        nm[nl] = 0;
        if (eq) val = eq + 1;
        if (strcmp(nm, "until-direct") == 0) {
            if (!val) o->until_direct = 1;
            else if (parse_bool(val, &o->until_direct) != 0) {
                snprintf(err, errcap, "invalid boolean value for -until-direct: %.40s", val);
                return -1;
            }
            continue;
        }
        if (strcmp(nm, "c") != 0 && strcmp(nm, "timeout") != 0) {
            snprintf(err, errcap, "flag provided but not defined: -%s", nm);
            return -1;
        }
        if (!val) {
            if (i + 1 >= argc) {
                snprintf(err, errcap, "flag needs an argument: -%s", nm);
                return -1;
            }
            val = argv[++i];
        }
        if (nm[0] == 'c') {
            if (parse_long(val, &o->count) != 0) {
                snprintf(err, errcap, "invalid value for -c: %.40s", val);
                return -1;
            }
        } else {
            uint32_t ms;
            if (ts_ping_parse_duration(val, &ms) != 0) {
                snprintf(err, errcap, "invalid duration for -timeout: %.40s", val);
                return -1;
            }
            if (ms < TS_IPC_PING_MIN_MS || ms > TS_IPC_PING_MAX_MS) {
                snprintf(err, errcap, "-timeout must be from 100ms to 10s");
                return -1;
            }
            o->timeout_ms = ms;
        }
    }
    if (argc - i != 1 || !argv[i][0]) {
        snprintf(err, errcap, "usage: tsppc ping [-c N] [--timeout DUR (100ms to 10s)] [--until-direct=BOOL] <name|IP>");
        return -1;
    }
    o->target = argv[i];
    return 0;
}

/* ---- Output ------------------------------------------------------------- */

void ts_ping_duration(char *out, size_t cap, uint64_t latency_us)
{
    uint64_t ms = (latency_us + 500) / 1000;
    unsigned long h, m, s, f;
    char frac[8] = "", hm[48] = "";
    size_t k;
    if (cap == 0) return;
    if (ms == 0) {
        snprintf(out, cap, "0s");
        return;
    }
    if (ms < 1000) {
        snprintf(out, cap, "%lums", (unsigned long)ms);
        return;
    }
    h = (unsigned long)(ms / 3600000);
    m = (unsigned long)(ms / 60000 % 60);
    s = (unsigned long)(ms / 1000 % 60);
    f = (unsigned long)(ms % 1000);
    if (f) {
        snprintf(frac, sizeof frac, ".%03lu", f);
        for (k = strlen(frac); frac[k - 1] == '0'; k--) frac[k - 1] = 0;
    }
    if (h) snprintf(hm, sizeof hm, "%luh%lum", h, m);
    else if (m) snprintf(hm, sizeof hm, "%lum", m);
    snprintf(out, cap, "%s%lu%ss", hm, s, frac);
}

void ts_ping_first_label(char *out, size_t cap, const char *name)
{
    size_t n = strcspn(name, ".");
    if (cap == 0) return;
    if (n >= cap) n = cap - 1;
    memcpy(out, name, n);
    out[n] = 0;
}

static void fmt_ip(char *out, size_t cap, uint32_t a)
{
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)(a >> 24), (unsigned)(a >> 16 & 255), (unsigned)(a >> 8 & 255),
             (unsigned)(a & 255));
}

void ts_ping_pong_line(char *out, size_t cap, const char *label, uint32_t ip, const char *code,
                       uint32_t latency_us)
{
    char ips[16], d[32];
    fmt_ip(ips, sizeof ips, ip);
    ts_ping_duration(d, sizeof d, latency_us);
    snprintf(out, cap, "pong from %s (%s) via DERP(%s) in %s", label[0] ? label : ips, ips,
             strcmp(code, "-") == 0 ? "" : code, d);
}

/* ---- Status ------------------------------------------------------------- */

int ts_ping_not_running(const ts_reply *r, char *out, size_t cap)
{
    const char *st = r->state;
    if (strcmp(r->login, "yes") != 0 || strcmp(st, "NEED_LOGIN") == 0) {
        if (r->url[0]) snprintf(out, cap, "Logged out.\nLog in at: %s", r->url);
        else snprintf(out, cap, "Logged out.");
        return 1;
    }
    if (strcmp(r->wanted, "up") != 0) {
        snprintf(out, cap, "Tailscale is stopped.");
        return 1;
    }
    if (strcmp(st, "AWAIT_APPROVAL") == 0) {
        snprintf(out, cap, "Machine is not yet approved by tailnet admin.");
        return 1;
    }
    if (strcmp(st, "RUNNING") == 0 || strcmp(st, "CONNECTING") == 0 || strcmp(st, "BACKOFF") == 0 ||
        strcmp(st, "IDLE") == 0) {
        if (cap) out[0] = 0;
        return 0;
    }
    snprintf(out, cap, "unexpected state: %s", st);
    return 1;
}

/* arg names this DNS name: the whole name (with or without its trailing
 * dot) or its first label, ignoring case. */
static int name_matches(const char *arg, const char *name)
{
    size_t al = strlen(arg), nl = strlen(name), ll = strcspn(name, ".");
    if (al == 0 || nl == 0) return 0;
    if (al == nl && strncasecmp(arg, name, nl) == 0) return 1;
    if (name[nl - 1] == '.' && al == nl - 1 && strncasecmp(arg, name, al) == 0) return 1;
    return ll > 0 && al == ll && strncasecmp(arg, name, ll) == 0;
}

int ts_ping_resolve(const ts_reply *r, const char *arg, uint32_t *ip, char *msg, size_t cap)
{
    struct in6_addr a6;
    size_t i;
    char safe[128];
    if (cap) msg[0] = 0;
    if (ts_ipc_parse_ipv4(arg, strlen(arg), ip) == 0)
        return r->have_ipv4 && r->ipv4 == *ip ? TS_PING_SELF : TS_PING_PEER;
    if (strchr(arg, ':') && inet_pton(AF_INET6, arg, &a6) == 1) {
        snprintf(msg, cap, "IPv6 addresses are not supported");
        return TS_PING_NOT_FOUND;
    }
    for (i = 0; i < r->npeers; i++) {
        const ts_reply_peer *p = &r->peers[i];
        if (!name_matches(arg, p->name)) continue;
        if (!p->have_ipv4) {
            snprintf(msg, cap, "node found but lacks an IP");
            return TS_PING_NOT_FOUND;
        }
        *ip = p->ipv4;
        return TS_PING_PEER;
    }
    if (name_matches(arg, r->self) && r->have_ipv4) {
        *ip = r->ipv4;
        return TS_PING_SELF;
    }
    ts_ipc_clean(safe, sizeof safe, arg, strlen(arg), 0);
    snprintf(msg, cap, "no peer named \"%s\"", safe);
    return TS_PING_NOT_FOUND;
}

void ts_ping_peer_label(const ts_reply *r, uint32_t ip, char *out, size_t cap)
{
    size_t i;
    if (cap) out[0] = 0;
    for (i = 0; i < r->npeers; i++) {
        if (r->peers[i].have_ipv4 && r->peers[i].ipv4 == ip) {
            ts_ping_first_label(out, cap, r->peers[i].name);
            return;
        }
    }
}
