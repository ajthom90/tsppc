#include "src/daemon/ipc_reply.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#else
#include <time.h>
#endif

/* ---- Parsing ---------------------------------------------------------- */

/* a.b.c.d with each part 1 to 3 digits, at most 255, no leading zero (so
 * "01" is not read as octal by anyone), nothing else. */
static int parse_ipv4(const char *s, size_t n, uint32_t *out)
{
    uint32_t a = 0, part = 0;
    size_t i, digits = 0;
    int dots = 0;
    for (i = 0; i < n; i++) {
        if (s[i] >= '0' && s[i] <= '9') {
            if (digits == 1 && part == 0) return -1;
            part = part * 10 + (uint32_t)(s[i] - '0');
            if (++digits > 3 || part > 255) return -1;
        } else if (s[i] == '.') {
            if (digits == 0 || ++dots > 3) return -1;
            a = a << 8 | part;
            part = 0;
            digits = 0;
        } else {
            return -1;
        }
    }
    if (dots != 3 || digits == 0) return -1;
    *out = a << 8 | part;
    return 0;
}

static void copy_clean(char *dst, size_t cap, const char *v, size_t n)
{
    ts_ipc_clean(dst, cap, v, n, 0);
}

/* "<ip|-> <online|offline> <name>" (value already cleaned). */
static void add_peer(ts_reply *r, const char *v, size_t n)
{
    const char *sp1, *sp2;
    size_t iplen, stlen;
    ts_reply_peer p;
    int online;

    sp1 = memchr(v, ' ', n);
    if (!sp1) return;
    iplen = (size_t)(sp1 - v);
    sp2 = memchr(sp1 + 1, ' ', n - iplen - 1);
    if (!sp2) return;
    stlen = (size_t)(sp2 - sp1 - 1);
    if (stlen == 6 && memcmp(sp1 + 1, "online", 6) == 0) online = 1;
    else if (stlen == 7 && memcmp(sp1 + 1, "offline", 7) == 0) online = 0;
    else return;
    memset(&p, 0, sizeof p);
    if (iplen == 1 && v[0] == '-') p.have_ipv4 = 0;
    else if (parse_ipv4(v, iplen, &p.ipv4) == 0) p.have_ipv4 = 1;
    else return;
    p.online = online;
    copy_clean(p.name, sizeof p.name, sp2 + 1, (size_t)(v + n - (sp2 + 1)));
    if (r->npeers >= TS_MAX_PEERS) {
        r->truncated = 1;
        return;
    }
    r->peers[r->npeers++] = p;
}

int ts_reply_parse(ts_reply *r, ts_reply_peer *peers, const char *buf, size_t len)
{
    size_t pos = 0;
    int have_error = 0, seen_state = 0, seen_status = 0, seen_url = 0, seen_problem = 0, seen_login = 0,
        seen_wanted = 0, seen_self = 0;
    char val[TS_NODE_NAME_MAX + 64];

    memset(r, 0, sizeof *r);
    r->peers = peers;
    while (pos < len) {
        const char *l = buf + pos;
        const char *nl = memchr(l, '\n', len - pos);
        size_t n = nl ? (size_t)(nl - l) : len - pos, k, v;
        pos += n + (nl ? 1 : 0);
        if (ts_ipc_split(l, n, &k, &v) != 0) continue;
        if (k == 2 && memcmp(l, "ok", 2) == 0) r->ok = 1;
        else if (k == 5 && memcmp(l, "error", 5) == 0) {
            if (!have_error) copy_clean(r->error, sizeof r->error, l + v, n - v);
            have_error = 1;
        } else if (k == 5 && memcmp(l, "state", 5) == 0) {
            if (!seen_state) copy_clean(r->state, sizeof r->state, l + v, n - v);
            seen_state = 1;
        } else if (k == 6 && memcmp(l, "status", 6) == 0) {
            if (!seen_status) copy_clean(r->status, sizeof r->status, l + v, n - v);
            seen_status = 1;
        } else if (k == 3 && memcmp(l, "url", 3) == 0) {
            if (!seen_url) copy_clean(r->url, sizeof r->url, l + v, n - v);
            seen_url = 1;
        } else if (k == 7 && memcmp(l, "problem", 7) == 0) {
            if (!seen_problem) copy_clean(r->problem, sizeof r->problem, l + v, n - v);
            seen_problem = 1;
        } else if (k == 5 && memcmp(l, "login", 5) == 0) {
            if (!seen_login) copy_clean(r->login, sizeof r->login, l + v, n - v);
            seen_login = 1;
        } else if (k == 6 && memcmp(l, "wanted", 6) == 0) {
            if (!seen_wanted) copy_clean(r->wanted, sizeof r->wanted, l + v, n - v);
            seen_wanted = 1;
        } else if (k == 4 && memcmp(l, "self", 4) == 0) {
            if (!seen_self) copy_clean(r->self, sizeof r->self, l + v, n - v);
            seen_self = 1;
        } else if (k == 2 && memcmp(l, "ip", 2) == 0) {
            uint32_t a;
            if (!r->have_ipv4 && parse_ipv4(l + v, n - v, &a) == 0) {
                r->ipv4 = a;
                r->have_ipv4 = 1;
            }
        } else if (k == 9 && memcmp(l, "truncated", 9) == 0) {
            r->truncated = 1;
        } else if (k == 4 && memcmp(l, "peer", 4) == 0) {
            size_t cl = ts_ipc_clean(val, sizeof val, l + v, n - v, 0);
            add_peer(r, val, cl);
        }
    }
    return (r->ok || have_error) ? 0 : -1;
}

/* ---- The request ------------------------------------------------------ */

static int64_t mono_ms(void)
{
#ifdef __APPLE__
    static mach_timebase_info_data_t tb;
    uint64_t t = mach_absolute_time();
    if (tb.denom == 0) mach_timebase_info(&tb);
    return (int64_t)(((t / tb.denom) * tb.numer + (t % tb.denom) * tb.numer / tb.denom) / 1000000u);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/* Wait until fd is readable (rd) or writable, for at most the time left.
 * 1 ready, 0 timed out, -1 error. */
static int wait_fd(int fd, int rd, int64_t deadline)
{
    for (;;) {
        fd_set s;
        struct timeval tv;
        int64_t left = deadline - mono_ms();
        int rc;
        if (left <= 0) return 0;
        tv.tv_sec = (long)(left / 1000);
        tv.tv_usec = (int)(left % 1000) * 1000;
        FD_ZERO(&s);
        FD_SET(fd, &s);
        rc = select(fd + 1, rd ? &s : NULL, rd ? NULL : &s, NULL, &tv);
        if (rc > 0) return 1;
        if (rc < 0 && errno != EINTR) return -1;
        if (rc == 0) return 0;
    }
}

static ts_req_result connect_result(int e)
{
    if (e == ENOENT || e == ECONNREFUSED) return TS_REQ_NO_DAEMON;
    if (e == EACCES || e == EPERM) return TS_REQ_DENIED;
    return TS_REQ_FAILED;
}

ts_req_result ts_ipc_request(const char *path, ts_ipc_cmd cmd, int timeout_ms, char *buf, size_t cap, size_t *len)
{
    struct sockaddr_un a;
    const char *line = ts_ipc_cmd_line(cmd);
    size_t off = 0, n = strlen(line);
    int64_t deadline = mono_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    ts_req_result res = TS_REQ_FAILED;
    int fd, e;

    *len = 0;
    if (cap == 0) return TS_REQ_FAILED;
    memset(&a, 0, sizeof a);
    if (strlen(path) >= sizeof a.sun_path) {
        errno = ENAMETOOLONG;
        return TS_REQ_FAILED;
    }
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, path, strlen(path) + 1);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return TS_REQ_FAILED;
    if (fd >= FD_SETSIZE) {
        close(fd);
        errno = EMFILE;
        return TS_REQ_FAILED;
    }
#ifdef SO_NOSIGPIPE
    {
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);   /* a closed peer gives EPIPE, not SIGPIPE */
    }
#endif
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) != 0) goto fail_errno;

    for (;;) {
        if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) break;
        if (errno == EINTR) continue;
        e = errno;
        close(fd);
        errno = e;
        return connect_result(e);
    }

    while (off < n) {
        ssize_t w = write(fd, line + off, n - off);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && errno == EAGAIN) {
            int rc = wait_fd(fd, 0, deadline);
            if (rc == 0) {
                res = TS_REQ_TIMEOUT;
                goto fail;
            }
            if (rc < 0) goto fail_errno;
            continue;
        }
        goto fail_errno;
    }

    for (;;) {
        ssize_t k;
        int rc;
        if (*len == cap) {          /* the rest is dropped: truncated but OK */
            close(fd);
            return TS_REQ_OK;
        }
        rc = wait_fd(fd, 1, deadline);
        if (rc == 0) {
            res = TS_REQ_TIMEOUT;
            goto fail;
        }
        if (rc < 0) goto fail_errno;
        k = read(fd, buf + *len, cap - *len);
        if (k > 0) {
            *len += (size_t)k;
            continue;
        }
        if (k == 0) {
            close(fd);
            return TS_REQ_OK;
        }
        if (errno == EINTR || errno == EAGAIN) continue;
        goto fail_errno;
    }

fail_errno:
    res = TS_REQ_FAILED;
fail:
    e = errno;
    close(fd);
    errno = e;
    return res;
}
