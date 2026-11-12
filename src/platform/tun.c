#include "tun.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int ts_tun_open(char ifname[16])
{
    int unit, e = ENOENT;
    for (unit = 0; unit <= TS_TUN_MAX_UNIT; unit++) {
        char path[32];
        int fd, fl;
        snprintf(path, sizeof path, "/dev/tun%d", unit);
        fd = open(path, O_RDWR);
        if (fd < 0) {
            /* Busy units (EBUSY) are skipped; ENOENT everywhere means no driver. */
            if (errno != ENOENT || e == ENOENT) e = errno;
            continue;
        }
        if ((fl = fcntl(fd, F_GETFL)) < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            e = errno;
            close(fd);
            continue;
        }
        snprintf(ifname, 16, "tun%d", unit);
        return fd;
    }
    errno = e;
    return -1;
}

/* "tun" and 1 or more digits, at most 15 bytes. */
static int ifname_ok(const char *n)
{
    size_t i, len = strlen(n);
    if (len < 4 || len > 15 || memcmp(n, "tun", 3) != 0) return 0;
    for (i = 3; i < len; i++)
        if (n[i] < '0' || n[i] > '9') return 0;
    return 1;
}

typedef struct {
    const char **argv;
    size_t max, n;
    char *buf;
    size_t cap, used;
    int bad;
} builder;

static void b_init(builder *b, const char **argv, size_t max, char *buf, size_t cap)
{
    b->argv = argv;
    b->max = max;
    b->n = 0;
    b->buf = buf;
    b->cap = cap;
    b->used = 0;
    b->bad = 0;
}

/* Append one argument (copied into buf), or a NULL separator for s == NULL. */
static void b_add(builder *b, const char *s)
{
    size_t len;
    if (b->bad) return;
    if (b->n + 1 >= b->max) {   /* keep room for the terminating NULL */
        b->bad = 1;
        return;
    }
    if (!s) {
        b->argv[b->n++] = NULL;
        return;
    }
    len = strlen(s) + 1;
    if (len > b->cap - b->used) {
        b->bad = 1;
        return;
    }
    memcpy(b->buf + b->used, s, len);
    b->argv[b->n++] = b->buf + b->used;
    b->used += len;
}

static int b_end(builder *b)
{
    if (b->bad || b->n >= b->max) return -1;
    b->argv[b->n] = NULL;
    return (int)b->n;
}

static void fmt_ip(char *out, size_t cap, uint32_t a)
{
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)(a >> 24), (unsigned)(a >> 16 & 255), (unsigned)(a >> 8 & 255),
             (unsigned)(a & 255));
}

int ts_tun_cmd_ifconfig_up(const char **argv, size_t max, char *buf, size_t cap, const char *ifname, uint32_t ip)
{
    builder b;
    char a[16], mtu[8];
    if (!ifname_ok(ifname)) return -1;
    fmt_ip(a, sizeof a, ip);
    snprintf(mtu, sizeof mtu, "%d", TS_TUN_MTU);
    b_init(&b, argv, max, buf, cap);
    b_add(&b, "/sbin/ifconfig");
    b_add(&b, ifname);
    b_add(&b, "inet");
    b_add(&b, a);
    b_add(&b, a);
    b_add(&b, "netmask");
    b_add(&b, "255.255.255.255");
    b_add(&b, "mtu");
    b_add(&b, mtu);
    b_add(&b, "up");
    return b_end(&b);
}

int ts_tun_cmd_route_add(const char **argv, size_t max, char *buf, size_t cap, const char *ifname)
{
    builder b;
    if (!ifname_ok(ifname)) return -1;
    b_init(&b, argv, max, buf, cap);
    b_add(&b, "/sbin/route");
    b_add(&b, "-n");
    b_add(&b, "add");
    b_add(&b, "-net");
    b_add(&b, TS_TAILNET_NET);
    b_add(&b, "-interface");
    b_add(&b, ifname);
    return b_end(&b);
}

int ts_tun_cmd_route_delete(const char **argv, size_t max, char *buf, size_t cap)
{
    builder b;
    b_init(&b, argv, max, buf, cap);
    b_add(&b, "/sbin/route");
    b_add(&b, "-n");
    b_add(&b, "delete");
    b_add(&b, "-net");
    b_add(&b, TS_TAILNET_NET);
    return b_end(&b);
}

int ts_tun_cmd_ifconfig_down(const char **argv, size_t max, char *buf, size_t cap, const char *ifname, uint32_t ip)
{
    builder b;
    char a[16];
    if (!ifname_ok(ifname)) return -1;
    fmt_ip(a, sizeof a, ip);
    b_init(&b, argv, max, buf, cap);
    b_add(&b, "/sbin/ifconfig");
    b_add(&b, ifname);
    b_add(&b, "inet");
    b_add(&b, a);
    b_add(&b, "delete");
    b_add(&b, NULL);
    b_add(&b, "/sbin/ifconfig");
    b_add(&b, ifname);
    b_add(&b, "down");
    return b_end(&b);
}

static int64_t mono_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);   /* only to bound a wait: a clock step shortens or stretches it */
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int ts_run(const char *const *argv)
{
    pid_t pid, r;
    int st, waited = 0;
    int64_t until;

    if (!argv || !argv[0] || argv[0][0] != '/') return -1;
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int fd, max = getdtablesize(), nul;
        sigset_t none;
        for (fd = 3; fd < max; fd++) close(fd);
        nul = open("/dev/null", O_RDWR);
        if (nul >= 0) {
            dup2(nul, 0);
            dup2(nul, 1);
            dup2(nul, 2);
            if (nul > 2) close(nul);
        }
        signal(SIGPIPE, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    until = mono_ms() + TS_RUN_LIMIT_MS;
    for (;;) {
        struct timeval tv;
        r = waitpid(pid, &st, WNOHANG);
        if (r == pid) break;
        if (r < 0 && errno != EINTR) return -1;
        if (mono_ms() >= until) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
            return -1;
        }
        /* Short naps first: the commands usually finish in milliseconds. */
        tv.tv_sec = 0;
        tv.tv_usec = waited < 20 ? 5000 : 50000;
        waited++;
        select(0, NULL, NULL, NULL, &tv);
    }
    if (!WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}
