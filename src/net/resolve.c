#include "resolve.h"
#include "sock.h"

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef TS_TEST_HOOKS
unsigned ts_resolve_test_delay;
#endif

int ts_host_name_ok(const char *h)
{
    size_t n = 0;
    if (h == NULL) return 0;
    for (; h[n] != '\0'; n++) {
        char c = h[n];
        if (n >= TS_RESOLVE_NAME_MAX) return 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-'))
            return 0;
    }
    return n > 0;
}

/* The helper. Never returns: every path ends in _exit. */
static void helper(int wfd, const char *host)
{
    struct addrinfo hints, *res = NULL, *p;
    struct sigaction sa;
    sigset_t none;
    char ip[INET_ADDRSTRLEN];
    int fd, max = getdtablesize();

    /* Keep only the pipe: the daemon's sockets, tun device and state files
     * must not stay open in a process that outlives a cancel. */
    for (fd = 0; fd < max; fd++)
        if (fd != wfd) close(fd);

    /* Inherited handlers or a blocked SIGALRM would defeat the time limit. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);
    alarm(TS_RESOLVE_TIMEOUT);

#ifdef TS_TEST_HOOKS
    if (ts_resolve_test_delay) sleep(ts_resolve_test_delay);
#endif

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;          /* no AI_ADDRCONFIG: it differs on 10.4 */
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) _exit(1);
    for (p = res; p != NULL; p = p->ai_next) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)p->ai_addr;
        if (p->ai_family != AF_INET || p->ai_addr == NULL || p->ai_addrlen < sizeof *sin) continue;
        if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip) == NULL) continue;
        if (write(wfd, ip, strlen(ip)) == (ssize_t)strlen(ip)) _exit(0);
        _exit(1);
    }
    _exit(1);
}

int ts_resolve_start(ts_resolve *r, const char *host)
{
    int p[2];
    pid_t pid;

    r->pid = -1;
    r->fd = -1;
    r->len = 0;
    if (!ts_host_name_ok(host)) return -1;
    if (pipe(p) != 0) return -1;
    pid = fork();
    if (pid == 0) {
        helper(p[1], host);
        _exit(1);  /* not reached */
    }
    close(p[1]);
    if (pid < 0 || ts_fd_nonblock(p[0]) != 0) {
        close(p[0]);
        if (pid > 0) {
            kill(pid, SIGKILL);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        }
        return -1;
    }
    r->pid = pid;
    r->fd = p[0];
    return 0;
}

int ts_resolve_fd(const ts_resolve *r)
{
    return r->fd;
}

void ts_resolve_cancel(ts_resolve *r)
{
    if (r->fd >= 0) close(r->fd);
    r->fd = -1;
    if (r->pid > 0) {
        /* SIGKILL ends it promptly whatever state it is in; then reap it. */
        kill(r->pid, SIGKILL);
        while (waitpid(r->pid, NULL, 0) < 0 && errno == EINTR) {}
    }
    r->pid = -1;
    r->len = 0;
}

int ts_resolve_finish(ts_resolve *r, char *ip_out, size_t cap)
{
    struct in_addr a;
    ssize_t n;

    if (cap > 0) ip_out[0] = '\0';
    if (r->fd < 0) return -1;
    for (;;) {
        if (r->len == sizeof r->buf) {    /* more than any dotted quad */
            ts_resolve_cancel(r);
            return -1;
        }
        n = read(r->fd, r->buf + r->len, sizeof r->buf - r->len);
        if (n > 0) { r->len += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EAGAIN) return 1;
        break;  /* EOF: the helper has exited (or failed); n < 0 is an error */
    }
    if (n < 0 || r->len == 0 || r->len >= INET_ADDRSTRLEN || r->len + 1 > cap) {
        ts_resolve_cancel(r);
        return -1;
    }
    r->buf[r->len] = '\0';
    if (inet_pton(AF_INET, r->buf, &a) != 1) {
        ts_resolve_cancel(r);
        return -1;
    }
    memcpy(ip_out, r->buf, r->len + 1);
    ts_resolve_cancel(r);
    return 0;
}
