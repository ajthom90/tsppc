#include "ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define STALE_TRIES 5
#define STALE_WAIT_US 200000

static const char *const cmd_lines[] = { "status\n", "up\n", "ip\n", "logout\n", "down\n" };
#define NCMDS (sizeof cmd_lines / sizeof cmd_lines[0])

const char *ts_ipc_socket_path(void)
{
#ifdef TS_TEST_HOOKS
    const char *e = getenv("TSPPC_SOCKET");
    if (e && e[0]) return e;
#endif
    return TS_IPC_PATH;
}

int ts_ipc_parse_ipv4(const char *s, size_t n, uint32_t *out)
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

/* "<a.b.c.d> <timeout>" (after "ping ", before the newline). */
static int parse_ping_args(const char *s, size_t n, ts_ipc_args *args)
{
    const char *sp = memchr(s, ' ', n);
    size_t i, iplen, tlen;
    uint32_t ip, t = 0;
    if (!sp) return -1;
    iplen = (size_t)(sp - s);
    tlen = n - iplen - 1;
    if (ts_ipc_parse_ipv4(s, iplen, &ip) != 0) return -1;
    if (tlen == 0 || tlen > 5 || sp[1] == '0') return -1;
    for (i = 0; i < tlen; i++) {
        if (sp[1 + i] < '0' || sp[1 + i] > '9') return -1;
        t = t * 10 + (uint32_t)(sp[1 + i] - '0');
    }
    if (t < TS_IPC_PING_MIN_MS || t > TS_IPC_PING_MAX_MS) return -1;
    args->ip = ip;
    args->timeout_ms = t;
    return 0;
}

int ts_ipc_parse_request(const char *line, size_t len, ts_ipc_cmd *out, ts_ipc_args *args)
{
    size_t i;
    ts_ipc_args a;
    if (len == 0 || len > TS_IPC_LINE_MAX) return -1;
    memset(&a, 0, sizeof a);
    for (i = 0; i < NCMDS; i++) {
        if (strlen(cmd_lines[i]) == len && memcmp(cmd_lines[i], line, len) == 0) {
            *out = (ts_ipc_cmd)i;
            *args = a;
            return 0;
        }
    }
    if (len > 6 && memcmp(line, "ping ", 5) == 0 && line[len - 1] == '\n' &&
        parse_ping_args(line + 5, len - 6, &a) == 0) {
        *out = TS_IPC_PING;
        *args = a;
        return 0;
    }
    return -1;
}

const char *ts_ipc_cmd_line(ts_ipc_cmd cmd)
{
    return (size_t)cmd < NCMDS ? cmd_lines[cmd] : "";
}

int ts_ipc_ping_line(char *out, size_t cap, uint32_t ip, uint32_t timeout_ms)
{
    int n;
    if (timeout_ms < TS_IPC_PING_MIN_MS || timeout_ms > TS_IPC_PING_MAX_MS || cap == 0) return -1;
    n = snprintf(out, cap, "ping %u.%u.%u.%u %u\n", (unsigned)(ip >> 24), (unsigned)(ip >> 16 & 255),
                 (unsigned)(ip >> 8 & 255), (unsigned)(ip & 255), (unsigned)timeout_ms);
    if (n < 0 || (size_t)n >= cap) {
        out[0] = 0;
        return -1;
    }
    return n;
}

size_t ts_ipc_clean(char *out, size_t cap, const char *in, size_t n, int keep_newline)
{
    size_t i, o = 0;
    if (cap == 0) return 0;
    for (i = 0; i < n && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\n' && keep_newline) out[o++] = '\n';
        else out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[o] = 0;
    return o;
}

int ts_ipc_split(const char *line, size_t len, size_t *klen, size_t *voff)
{
    size_t i;
    for (i = 0; i < len && line[i] != ' '; i++)
        if (line[i] < 'a' || line[i] > 'z') return -1;
    if (i == 0) return -1;
    *klen = i;
    *voff = i < len ? i + 1 : i;
    return 0;
}

static void seterr(char *err, size_t cap, const char *what, const char *path, int e)
{
    if (cap == 0) return;
    if (e) snprintf(err, cap, "%s %s: %s", what, path, strerror(e));
    else snprintf(err, cap, "%s %s", what, path);
}

static int fill_addr(struct sockaddr_un *a, const char *path)
{
    memset(a, 0, sizeof *a);
    if (strlen(path) >= sizeof a->sun_path) return -1;
    a->sun_family = AF_UNIX;
    memcpy(a->sun_path, path, strlen(path) + 1);
    return 0;
}

static void no_sigpipe(int fd)
{
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#else
    (void)fd;
#endif
}

int ts_ipc_connect(const char *path)
{
    struct sockaddr_un a;
    int fd, e;
    if (fill_addr(&a, path) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    no_sigpipe(fd);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int ts_ipc_listen(const char *path, gid_t gid, dev_t *dev, ino_t *ino, char *err, size_t errcap)
{
    struct sockaddr_un a;
    struct stat sb;
    mode_t old;
    int fd, rc, e, i;

    if (errcap) err[0] = 0;
    if (fill_addr(&a, path) != 0) {
        seterr(err, errcap, "socket path too long:", path, 0);
        return -1;
    }
    if (lstat(path, &sb) == 0) {
        if (!S_ISSOCK(sb.st_mode)) {
            seterr(err, errcap, "refusing to replace a non-socket at", path, 0);
            return -1;
        }
        /* A socket: a running daemon answers, a crashed one's refuses. A
         * live daemon with a full backlog also refuses, so only a socket that
         * refuses every time over about a second is taken as stale. */
        for (i = 0; i < STALE_TRIES; i++) {
            fd = ts_ipc_connect(path);
            if (fd >= 0) {
                close(fd);
                seterr(err, errcap, "tsppcd is already running on", path, 0);
                return -1;
            }
            if (errno != ECONNREFUSED) {
                seterr(err, errcap, "cannot check the old socket", path, errno);
                return -1;
            }
            if (i + 1 < STALE_TRIES) {
                struct timeval tv = { 0, STALE_WAIT_US };
                (void)select(0, NULL, NULL, NULL, &tv);
            }
        }
        if (unlink(path) != 0 && errno != ENOENT) {
            seterr(err, errcap, "cannot remove the stale socket", path, errno);
            return -1;
        }
    } else if (errno != ENOENT) {
        seterr(err, errcap, "cannot check", path, errno);
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        seterr(err, errcap, "cannot create a socket for", path, errno);
        return -1;
    }
    /* listen at once after bind: between the two a client is refused, and
     * another daemon starting then would take the socket for stale. */
    old = umask(077);
    rc = bind(fd, (struct sockaddr *)&a, sizeof a);
    e = errno;
    umask(old);
    if (rc != 0) {
        close(fd);
        seterr(err, errcap, "cannot bind", path, e);
        return -1;
    }
    if (listen(fd, 16) != 0) {
        e = errno;
        goto fail;
    }
    if (lstat(path, &sb) != 0 || !S_ISSOCK(sb.st_mode)) {
        e = errno;
        close(fd);
        seterr(err, errcap, "socket vanished:", path, e);
        return -1;
    }
    if (geteuid() == 0) {
        if (chown(path, 0, gid) != 0) {
            e = errno;
            goto fail;
        }
    } else {
        (void)chown(path, (uid_t)-1, gid);   /* tests: our own group if we may */
    }
    if (chmod(path, 0660) != 0) {
        e = errno;
        goto fail;
    }
    if ((rc = fcntl(fd, F_GETFL)) < 0 || fcntl(fd, F_SETFL, rc | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        e = errno;
        goto fail;
    }
    *dev = sb.st_dev;
    *ino = sb.st_ino;
    return fd;
fail:
    close(fd);
    (void)unlink(path);
    seterr(err, errcap, "cannot set up", path, e);
    return -1;
}

void ts_ipc_unlink(const char *path, dev_t dev, ino_t ino)
{
    struct stat sb;
    if (lstat(path, &sb) == 0 && S_ISSOCK(sb.st_mode) && sb.st_dev == dev && sb.st_ino == ino)
        (void)unlink(path);
}
