#include "hostinfo.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

#define VERSION_MAX 31
#define SWVERS_TIMEOUT_MS 5000

const char *ts_hostinfo_goarch(void)
{
#if defined(__ppc__) || defined(__powerpc__)
    return "ppc";
#elif defined(__i386__)
    return "386";
#elif defined(__x86_64__)
    return "amd64";
#elif defined(__aarch64__) || defined(__arm64__)
    return "arm64";
#else
#error "unsupported architecture: add its Go name"
#endif
}

int ts_hostinfo_version_ok(const char *s)
{
    size_t i, n = strlen(s);
    if (n == 0 || n > VERSION_MAX) return 0;
    if (s[0] < '0' || s[0] > '9') return 0;
    for (i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || s[i] == '.')) return 0;
    return 1;
}

/* Trim trailing and leading whitespace in place. */
static void trim(char *s)
{
    size_t n = strlen(s), a = 0;
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
    while (s[a] == ' ' || s[a] == '\t') a++;
    if (a) memmove(s, s + a, n - a + 1);
}

/* Milliseconds from a monotonic-enough clock (wall clock; only differences are used). */
static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Move fd to a descriptor number of 3 or more, so the child's dup2 calls onto
 * 0, 1 and 2 cannot clobber one another even if the daemon started with some
 * of them closed. Returns the new fd, or -1 (fd closed). */
static int high_fd(int fd)
{
    int n;
    if (fd >= 3) return fd;
    n = fcntl(fd, F_DUPFD, 3);
    close(fd);
    return n;
}

/* Run sw_vers directly (no shell). stdin and stderr go to /dev/null: on some
 * systems it warns on stderr. Returns 0 with the validated version in out. */
static int run_sw_vers(char *out, size_t cap)
{
    int pfd[2], nul, i, maxfd;
    pid_t pid;
    char buf[64];
    size_t got = 0;
    int eof = 0, rc = -1, status;
    long long deadline;
    static char *const env[] = { (char *)"PATH=/usr/bin:/bin", NULL };

    if (cap < 2) return -1;
    nul = open("/dev/null", O_RDWR);
    if (nul < 0) return -1;
    nul = high_fd(nul);
    if (nul < 0) return -1;
    if (pipe(pfd) != 0) { close(nul); return -1; }
    pfd[0] = high_fd(pfd[0]);
    if (pfd[0] < 0) { close(nul); close(pfd[1]); return -1; }
    pfd[1] = high_fd(pfd[1]);
    if (pfd[1] < 0) { close(nul); close(pfd[0]); return -1; }
    maxfd = getdtablesize();
    if (maxfd > 65536) maxfd = 65536;
    pid = fork();
    if (pid < 0) { close(nul); close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        /* Child: async-signal-safe calls only. All three fds are >= 3. */
        if (dup2(nul, 0) < 0 || dup2(pfd[1], 1) < 0 || dup2(nul, 2) < 0) _exit(127);
        for (i = 3; i < maxfd; i++) close(i);
        execle("/usr/bin/sw_vers", "sw_vers", "-productVersion", (char *)NULL, env);
        _exit(127);
    }
    close(nul);
    close(pfd[1]);
    deadline = now_ms() + SWVERS_TIMEOUT_MS;
    while (got < sizeof buf - 1) {
        struct pollfd p;
        ssize_t r;
        int pr;
        long long left = deadline - now_ms();
        if (left <= 0) break;
        p.fd = pfd[0];
        p.events = POLLIN;
        p.revents = 0;
        pr = poll(&p, 1, (int)left);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) break;
        r = read(pfd[0], buf + got, sizeof buf - 1 - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) { eof = 1; break; }
        got += (size_t)r;
    }
    buf[got] = 0;
    close(pfd[0]);
    if (!eof) kill(pid, SIGKILL);   /* any exit other than EOF: do not wait for it */
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (eof) {
        trim(buf);
        if (ts_hostinfo_version_ok(buf) && strlen(buf) < cap) {
            memcpy(out, buf, strlen(buf) + 1);
            rc = 0;
        }
    }
    return rc;
}

int ts_hostinfo_parse_plist_version(const char *buf, size_t len, char *out, size_t cap)
{
    static const char key[] = "<key>ProductVersion</key>";
    static const char open_[] = "<string>";
    size_t klen = sizeof key - 1, olen = sizeof open_ - 1, i, j, n;
    char v[VERSION_MAX + 2];

    if (cap == 0) return -1;
    out[0] = 0;
    for (i = 0; i + klen <= len; i++) {
        if (memcmp(buf + i, key, klen) != 0) continue;
        j = i + klen;
        while (j < len && (buf[j] == ' ' || buf[j] == '\t' || buf[j] == '\n' || buf[j] == '\r')) j++;
        if (j + olen > len || memcmp(buf + j, open_, olen) != 0) return -1;
        j += olen;
        for (n = 0; j + n < len && buf[j + n] != '<'; n++) {
            if (n >= VERSION_MAX) return -1;
            v[n] = buf[j + n];
        }
        if (j + n >= len) return -1;
        v[n] = 0;
        if (!ts_hostinfo_version_ok(v) || n >= cap) return -1;
        memcpy(out, v, n + 1);
        return 0;
    }
    return -1;
}

static int read_plist_version(char *out, size_t cap)
{
    char buf[4096];
    size_t got = 0;
    int fd = open("/System/Library/CoreServices/SystemVersion.plist", O_RDONLY);
    if (fd < 0) return -1;
    while (got < sizeof buf) {
        ssize_t r = read(fd, buf + got, sizeof buf - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    return ts_hostinfo_parse_plist_version(buf, got, out, cap);
}

int ts_hostinfo_map_darwin(const char *darwin, char *out, size_t cap)
{
    unsigned long m = 0, n = 0;
    size_t i = 0;
    char v[24];
    if (cap == 0) return -1;
    out[0] = 0;
    if (!ts_hostinfo_version_ok(darwin)) return -1;
    if (darwin[i] < '0' || darwin[i] > '9') return -1;
    for (; darwin[i] >= '0' && darwin[i] <= '9'; i++) {
        m = m * 10 + (unsigned long)(darwin[i] - '0');
        if (m > 1000) return -1;
    }
    if (darwin[i++] != '.') return -1;
    if (darwin[i] < '0' || darwin[i] > '9') return -1;
    for (; darwin[i] >= '0' && darwin[i] <= '9'; i++) {
        n = n * 10 + (unsigned long)(darwin[i] - '0');
        if (n > 1000) return -1;
    }
    if (darwin[i] != 0 && darwin[i] != '.') return -1;
    if (m < 8 || m > 10) return -1;
    snprintf(v, sizeof v, "10.%lu.%lu", m - 4, n);
    if (strlen(v) >= cap) return -1;
    memcpy(out, v, strlen(v) + 1);
    return 0;
}

void ts_hostinfo_os_version(char *out, size_t cap)
{
    if (cap == 0) return;
    out[0] = 0;
    if (run_sw_vers(out, cap) == 0) return;
    out[0] = 0;
    if (read_plist_version(out, cap) == 0) return;
    out[0] = 0;
#ifdef __APPLE__
    {
        /* Last resort: derive the Mac OS X 10.x version from the Darwin release. */
        char b[64];
        size_t n = sizeof b - 1;
        memset(b, 0, sizeof b);
        if (sysctlbyname("kern.osrelease", b, &n, NULL, 0) == 0) {
            b[sizeof b - 1] = 0;
            trim(b);
            if (ts_hostinfo_map_darwin(b, out, cap) != 0) out[0] = 0;
        }
    }
#endif
}

/* Append the JSON-escaped form of s to out at *pos. Returns -1 if it does not fit.
 * Bytes at or above 0x80 are dropped (a hostname that is not ASCII is not
 * trusted to be valid UTF-8). */
static int put_esc(char *out, size_t cap, size_t *pos, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        char tmp[8];
        size_t n;
        if (c >= 0x80) continue;
        if (c == '"' || c == '\\') { tmp[0] = '\\'; tmp[1] = (char)c; n = 2; }
        else if (c < 0x20 || c == 0x7f) { snprintf(tmp, sizeof tmp, "\\u%04x", c); n = 6; }
        else { tmp[0] = (char)c; n = 1; }
        if (*pos + n >= cap) return -1;
        memcpy(out + *pos, tmp, n);
        *pos += n;
    }
    return 0;
}

static int put_raw(char *out, size_t cap, size_t *pos, const char *s)
{
    size_t n = strlen(s);
    if (*pos + n >= cap) return -1;
    memcpy(out + *pos, s, n);
    *pos += n;
    return 0;
}

int ts_hostinfo_json(char *out, size_t cap)
{
    char host[256], ver[VERSION_MAX + 1];
    size_t pos = 0;
    char *dot;

    if (cap == 0) return -1;
    memset(host, 0, sizeof host);
    if (gethostname(host, sizeof host - 1) != 0) host[0] = 0;
    host[sizeof host - 1] = 0;
    dot = strchr(host, '.');
    if (dot) *dot = 0;
    if (host[0] == 0) snprintf(host, sizeof host, "localhost");
    ts_hostinfo_os_version(ver, sizeof ver);

    if (put_raw(out, cap, &pos, "{\"IPNVersion\":\"" TS_IPN_VERSION "\",\"Hostname\":\"") ||
        put_esc(out, cap, &pos, host) ||
        put_raw(out, cap, &pos, "\",\"OS\":\"macOS\",\"OSVersion\":\"") ||
        put_esc(out, cap, &pos, ver) ||
        put_raw(out, cap, &pos, "\",\"GoArch\":\"") ||
        put_raw(out, cap, &pos, ts_hostinfo_goarch()) ||
        put_raw(out, cap, &pos, "\"}")) {
        out[0] = 0;
        return -1;
    }
    out[pos] = 0;
    return (int)pos;
}
