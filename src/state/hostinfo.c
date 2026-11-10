#include "hostinfo.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
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
    return "unknown";
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

/* Run sw_vers directly (no shell). stdin and stderr go to /dev/null: on some
 * systems it warns on stderr. Returns 0 with the validated version in out. */
static int run_sw_vers(char *out, size_t cap)
{
    int pfd[2], nul, i;
    pid_t pid;
    char buf[64];
    size_t got = 0;
    int timed_out = 0, rc = -1, status;
    static char *const env[] = { (char *)"PATH=/usr/bin:/bin", NULL };

    if (cap < 2) return -1;
    nul = open("/dev/null", O_RDWR);
    if (nul < 0) return -1;
    if (pipe(pfd) != 0) { close(nul); return -1; }
    pid = fork();
    if (pid < 0) { close(nul); close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        /* Child: async-signal-safe calls only. */
        if (dup2(nul, 0) < 0 || dup2(pfd[1], 1) < 0 || dup2(nul, 2) < 0) _exit(127);
        for (i = 3; i < 256; i++) close(i);
        execle("/usr/bin/sw_vers", "sw_vers", "-productVersion", (char *)NULL, env);
        _exit(127);
    }
    close(nul);
    close(pfd[1]);
    while (got < sizeof buf - 1) {
        struct pollfd p;
        ssize_t r;
        int pr;
        p.fd = pfd[0];
        p.events = POLLIN;
        p.revents = 0;
        pr = poll(&p, 1, SWVERS_TIMEOUT_MS);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) { timed_out = 1; break; }
        r = read(pfd[0], buf + got, sizeof buf - 1 - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    buf[got] = 0;
    close(pfd[0]);
    if (timed_out || got >= sizeof buf - 1) kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (!timed_out && got < sizeof buf - 1) {
        trim(buf);
        if (ts_hostinfo_version_ok(buf) && strlen(buf) < cap) {
            memcpy(out, buf, strlen(buf) + 1);
            rc = 0;
        }
    }
    return rc;
}

void ts_hostinfo_os_version(char *out, size_t cap)
{
    if (cap == 0) return;
    out[0] = 0;
    if (run_sw_vers(out, cap) == 0) return;
    out[0] = 0;
#ifdef __APPLE__
    {
        char b[64];
        size_t n = sizeof b - 1;
        memset(b, 0, sizeof b);
        /* The Darwin release, not the marketing version, but better than nothing. */
        if (sysctlbyname("kern.osrelease", b, &n, NULL, 0) == 0) {
            b[sizeof b - 1] = 0;
            trim(b);
            if (ts_hostinfo_version_ok(b) && strlen(b) < cap) memcpy(out, b, strlen(b) + 1);
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
