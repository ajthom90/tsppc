/* tsppcd: the daemon. Runs in the foreground (no launchd yet) as root.
 *
 * One select() loop over the control connection, the DNS helper's pipe, the
 * control key fetch, the local socket and its clients, and a signal pipe.
 * SIGTERM and SIGINT close everything and remove the socket. Logs go to
 * stderr and never hold keys or the login URL.
 *
 * Start: load (or create) the node state, compute Hostinfo, listen on the
 * socket, fetch control's Noise key (retried with backoff; status shows why it
 * fails, "system clock is wrong" included), then run the control session. The
 * session is started at once if the saved state is logged in, as upstream's
 * daemon does; otherwise it waits for `tsppc up`.
 *
 * In builds with -DTS_TEST_HOOKS only, TSPPC_CONTROL ("host" or "host:port";
 * with a port every control connection goes there, without TLS),
 * TSPPC_STATE_DIR and TSPPC_SOCKET override the defaults. */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "ipc.h"
#include "src/control/noise.h"
#include "src/control/session.h"
#include "src/core/bytes.h"
#include "src/crypto/random.h"
#include "src/net/keyfetch.h"
#include "src/net/resolve.h"
#include "src/net/sock.h"
#include "src/net/tls.h"
#include "src/state/hostinfo.h"
#include "src/state/store.h"

#define OUT_MAX (256 * 1024)        /* bytes queued for control before the connection counts as lost */
#define READ_CHUNK 16384
#define READS_PER_TURN 16           /* reads from control per loop turn, so clients are not starved */
#define KF_TIMEOUT_MS 180000        /* an emulated G4 needs a while for the RSA checks */
#define KF_BACKOFF_MIN_MS 1000
#define KF_BACKOFF_MAX_MS 60000
#define HOSTINFO_MAX 4096
#define LOOP_MS 1000                /* the session needs a tick at least every second */
#define TEXT_MAX 512

enum { C_NONE, C_RESOLVE, C_TCP, C_TLS, C_OPEN };

typedef struct {
    int fd;                         /* -1: free */
    int64_t deadline;
    char in[TS_IPC_LINE_MAX + 1];
    size_t inlen;
    char *out;                      /* the reply, once the request is in */
    size_t outlen, outoff;
} client;

static struct {
    const char *state_dir;
    char host[TS_SESS_HOST_MAX + 1];
    uint16_t port_override;
    int host_override;
    ts_state st;                    /* until the session exists; then the session's copy rules */
    char hostinfo[HOSTINFO_MAX];

    /* Control key. */
    int have_key;
    uint8_t control_pub[32];
    int kf_active;
    int64_t kf_started, kf_retry_at, kf_backoff;
    char kf_err[TEXT_MAX];

    /* Session and what the operator asked for. */
    ts_sess *sess;
    int want_up;
    int logout_req;

    /* The control connection. */
    int cphase;
    unsigned gen;                   /* changes whenever the connection is replaced or closed */
    ts_resolve res;
    int fd;
    uint16_t port;
    int use_tls;
    char chost[TS_SESS_HOST_MAX + 1];
    ts_tls *tls;
    uint8_t *out;
    size_t outlen;
    int64_t conn_t0;

    /* Local socket. */
    const char *sock_path;
    int lfd;
    dev_t ldev;
    ino_t lino;
    client cl[TS_IPC_MAX_CLIENTS];

    int sigpipe[2];
    char logged_state[32];
    char logged_reason[TEXT_MAX];
} D;

static ts_keyfetch KF;              /* about 100 KiB: not on the stack */
static uint8_t rbuf[READ_CHUNK];
static mach_timebase_info_data_t tb;
static volatile sig_atomic_t got_signal;

/* ---- Time and logging --------------------------------------------------- */

/* Monotonic milliseconds (mach_absolute_time exists from 10.0 on). */
static int64_t now_ms(void)
{
    uint64_t t = mach_absolute_time();
    uint64_t ns = (t / tb.denom) * tb.numer + (t % tb.denom) * tb.numer / tb.denom;
    return (int64_t)(ns / 1000000u);
}

static int64_t t_start;

/* Log a line. Callers never pass keys or the login URL. */
static void logline(const char *fmt, ...)
{
    char msg[TEXT_MAX + 128], safe[TEXT_MAX + 128];
    int64_t t = now_ms() - t_start;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    ts_ipc_clean(safe, sizeof safe, msg, strlen(msg), 0);
    fprintf(stderr, "tsppcd: [%5ld.%03ld] %s\n", (long)(t / 1000), (long)(t % 1000), safe);
}

/* ---- The control connection (the session's I/O) ------------------------- */

static void conn_close(void)
{
    ts_resolve_cancel(&D.res);
    if (D.tls) {
        ts_tls_wipe(D.tls);
        free(D.tls);
        D.tls = NULL;
    }
    if (D.fd >= 0) close(D.fd);
    D.fd = -1;
    D.outlen = 0;
    D.cphase = C_NONE;
    D.gen++;
}

/* The I/O layer found the connection dead: close it, then tell the session. */
static void conn_fail(const char *why)
{
    logline("control connection on port %u failed: %s", (unsigned)D.port, why);
    conn_close();
    ts_sess_disconnected(D.sess, why);
}

static int io_connect(void *user, const char *host, uint16_t port)
{
    (void)user;
    conn_close();
    D.port = port;
    D.use_tls = port == 443;
    if (D.port_override) {
        D.port = D.port_override;
        D.use_tls = 0;
    }
    snprintf(D.chost, sizeof D.chost, "%s", host);
    if (ts_resolve_start(&D.res, host) != 0) {
        logline("cannot start the DNS lookup for control");
        return -1;
    }
    D.cphase = C_RESOLVE;
    D.conn_t0 = now_ms();
    logline("connecting to control on port %u%s", (unsigned)D.port, D.use_tls ? " (TLS)" : "");
    return 0;
}

static int io_send(void *user, const uint8_t *p, size_t n)
{
    (void)user;
    if (D.cphase != C_OPEN) return -1;
    if (n > OUT_MAX - D.outlen) {
        logline("control is not reading: %lu bytes queued", (unsigned long)D.outlen);
        return -1;
    }
    memcpy(D.out + D.outlen, p, n);
    D.outlen += n;
    return 0;
}

static void io_disconnect(void *user)
{
    (void)user;
    conn_close();
}

static int io_save(void *user, const ts_state *st)
{
    char err[256];
    (void)user;
    if (ts_state_save(st, D.state_dir, err, sizeof err) != 0) {
        logline("cannot save the node state: %s", err);
        return -1;
    }
    D.st = *st;
    return 0;
}

static int io_random(void *user, uint8_t *out, size_t n)
{
    (void)user;
    return ts_random_bytes(out, n);
}

static const ts_sess_io sess_io = { io_connect, io_send, io_disconnect, io_save, io_random };

static void conn_connected(void)
{
    D.cphase = C_OPEN;
    logline("connected to control on port %u after %ld ms", (unsigned)D.port, (long)(now_ms() - D.conn_t0));
    ts_sess_connected(D.sess);
}

/* Write what is queued. */
static void conn_flush(void)
{
    if (D.cphase != C_OPEN || D.outlen == 0) return;
    while (D.outlen > 0) {
        ssize_t n;
        if (D.tls) {
            int k = ts_tls_write(D.tls, D.out, D.outlen);
            if (k < 0) {
                conn_fail(ts_tls_error(D.tls));
                return;
            }
            n = k;
        } else {
            n = write(D.fd, D.out, D.outlen);
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) return;
                conn_fail("sending to control failed");
                return;
            }
        }
        if (n == 0) return;
        memmove(D.out, D.out + n, D.outlen - (size_t)n);
        D.outlen -= (size_t)n;
    }
}

/* Read from control and hand it to the session. */
static void conn_read(void)
{
    unsigned g = D.gen;
    int i;
    for (i = 0; i < READS_PER_TURN && D.gen == g && D.cphase == C_OPEN && ts_sess_want_read(D.sess); i++) {
        ssize_t n;
        if (D.tls) {
            int k = ts_tls_read(D.tls, rbuf, sizeof rbuf);
            if (k == 0) return;
            if (k == TS_TLS_CLOSED) {
                conn_fail("control closed the connection");
                return;
            }
            if (k < 0) {
                conn_fail(ts_tls_error(D.tls));
                return;
            }
            n = k;
        } else {
            n = read(D.fd, rbuf, sizeof rbuf);
            if (n == 0) {
                conn_fail("control closed the connection");
                return;
            }
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) return;
                conn_fail("reading from control failed");
                return;
            }
        }
        ts_sess_recv(D.sess, rbuf, (size_t)n);
    }
}

static void conn_fds(fd_set *r, fd_set *w, int *maxfd)
{
    int fd = -1, rd = 0, wr = 0, want;
    switch (D.cphase) {
    case C_RESOLVE:
        fd = ts_resolve_fd(&D.res);
        rd = 1;
        break;
    case C_TCP:
        fd = D.fd;
        wr = 1;
        break;
    case C_TLS:
    case C_OPEN:
        fd = D.fd;
        if (D.tls) {
            want = ts_tls_want(D.tls);
            rd = (want & TS_TLS_WANT_READ) && (D.cphase == C_TLS || ts_sess_want_read(D.sess));
            wr = (want & TS_TLS_WANT_WRITE) != 0;
        } else {
            rd = ts_sess_want_read(D.sess);
            wr = D.outlen > 0;
        }
        break;
    default:
        return;
    }
    if (fd < 0) return;
    if (rd) FD_SET(fd, r);
    if (wr) FD_SET(fd, w);
    if ((rd || wr) && fd > *maxfd) *maxfd = fd;
}

/* After select. Every session call can replace the connection (the session
 * may disconnect and reconnect inside it), so stop at any change of gen. */
static void conn_events(fd_set *r, fd_set *w, unsigned gen_at_select)
{
    char ip[24];
    int rc;
    if (D.gen != gen_at_select) return;
    switch (D.cphase) {
    case C_RESOLVE:
        if (!FD_ISSET(ts_resolve_fd(&D.res), r)) return;
        rc = ts_resolve_finish(&D.res, ip, sizeof ip);
        if (rc == 1) return;
        if (rc != 0) {
            conn_fail("DNS lookup of the control server failed");
            return;
        }
        D.fd = ts_tcp_start(ip, D.port);
        if (D.fd < 0) {
            conn_fail("cannot connect to control");
            return;
        }
        D.cphase = C_TCP;
        return;
    case C_TCP:
        if (!FD_ISSET(D.fd, w)) return;
        if (ts_tcp_finish(D.fd) != 0) {
            conn_fail("cannot connect to control");
            return;
        }
        if (!D.use_tls) {
            conn_connected();
            return;
        }
        D.tls = (ts_tls *)calloc(1, sizeof *D.tls);
        if (!D.tls || ts_tls_start(D.tls, D.fd, D.chost) != 0) {
            conn_fail("cannot start TLS");
            return;
        }
        D.cphase = C_TLS;
        /* fall through: send the ClientHello now */
    case C_TLS:
        rc = ts_tls_step(D.tls);
        if (rc < 0) {
            conn_fail(ts_tls_error(D.tls));
            return;
        }
        if (rc == 1) return;
        conn_connected();
        if (D.gen != gen_at_select) return;
        conn_read();   /* data may already sit in the TLS engine */
        return;
    case C_OPEN:
        if (D.tls) {
            conn_read();   /* TLS may hold decrypted data whatever select said */
        } else if (FD_ISSET(D.fd, r)) {
            conn_read();
        }
        if (D.gen == gen_at_select && FD_ISSET(D.fd, w)) conn_flush();
        return;
    default:
        return;
    }
}

/* ---- Control key and session ----------------------------------------- */

static void session_start(void)
{
    D.sess = (ts_sess *)calloc(1, sizeof *D.sess);
    if (!D.sess) {
        logline("out of memory for the session");
        exit(1);
    }
    ts_sess_init(D.sess, &D.st, &sess_io, NULL, D.control_pub, D.hostinfo);
    ts_sess_tick(D.sess, (uint64_t)now_ms());
    if (D.host_override && ts_sess_set_host(D.sess, D.host) != 0) logline("control host override refused");
    if (D.logout_req) ts_sess_logout(D.sess);
    else if (D.want_up) ts_sess_up(D.sess);
}

static void kf_fail(const char *why)
{
    int64_t d = D.kf_backoff ? D.kf_backoff : KF_BACKOFF_MIN_MS;
    uint8_t r[2];
    ts_ipc_clean(D.kf_err, sizeof D.kf_err, why, strlen(why), 0);
    ts_keyfetch_close(&KF);
    D.kf_active = 0;
    D.kf_backoff = d * 2 > KF_BACKOFF_MAX_MS ? KF_BACKOFF_MAX_MS : d * 2;
    if (ts_random_bytes(r, 2) == 0) d -= d * (int64_t)ts_get_be16(r) / 65536 / 4;
    D.kf_retry_at = now_ms() + d;
    logline("fetching the control key failed: %s; retrying in %ld ms", D.kf_err, (long)d);
}

static void kf_tick(void)
{
    int64_t now = now_ms();
    if (D.have_key) return;
    if (D.kf_active && now - D.kf_started > KF_TIMEOUT_MS) {
        kf_fail("timed out fetching the control key");
        return;
    }
    if (D.kf_active || now < D.kf_retry_at) return;
    memset(&KF, 0, sizeof KF);
    D.kf_started = now;
    logline("fetching the control key");
    if (ts_keyfetch_start(&KF, D.host, TS_CAPVER) != 0) {
        kf_fail(ts_keyfetch_error(&KF));
        return;
    }
    D.kf_active = 1;
}

static void kf_events(void)
{
    int rc;
    if (!D.kf_active) return;
    rc = ts_keyfetch_step(&KF, D.control_pub);
    if (rc == 1) return;
    if (rc != 0) {
        kf_fail(ts_keyfetch_error(&KF));
        return;
    }
    ts_keyfetch_close(&KF);
    D.kf_active = 0;
    D.have_key = 1;
    D.kf_err[0] = 0;
    logline("control key fetched after %ld ms", (long)(now_ms() - D.kf_started));
    session_start();
}

/* ---- What status shows ------------------------------------------------ */

typedef struct {
    const char *name;
    char status[TS_SESS_URL_MAX + 512];
    char problem[TEXT_MAX];
} view;

static void get_view(view *v)
{
    v->problem[0] = 0;
    if (D.sess) {
        ts_sess_state s = ts_sess_get_state(D.sess);
        v->name = ts_sess_state_name(s);
        ts_sess_status(D.sess, v->status, sizeof v->status);
        if (s == TS_SESS_BACKOFF || s == TS_SESS_FAILED)
            snprintf(v->problem, sizeof v->problem, "%s", D.sess->reason);
        else if (s == TS_SESS_NEED_LOGIN && !ts_sess_login_url(D.sess)) {
            const char *c = strchr(v->status, ':');
            snprintf(v->problem, sizeof v->problem, "%s", c ? c + 2 : v->status);
            if ((c = strstr(v->problem, "; "))) v->problem[c - v->problem] = 0;
        }
    } else if (D.kf_active) {
        v->name = "CONNECTING";
        snprintf(v->status, sizeof v->status, "CONNECTING: fetching the control key");
    } else {
        int64_t ms = D.kf_retry_at - now_ms();
        v->name = "BACKOFF";
        snprintf(v->status, sizeof v->status, "BACKOFF: %s; retrying in %ld s", D.kf_err,
                 (long)((ms < 0 ? 0 : ms + 999) / 1000));
        snprintf(v->problem, sizeof v->problem, "%s", D.kf_err);
    }
    /* The wall clock, for this check only: no correct clock is before the build. */
    if (time(NULL) < ts_build_time && !strstr(v->problem, "system clock is wrong")) {
        size_t n = strlen(v->problem);
        snprintf(v->problem + n, sizeof v->problem - n, "%ssystem clock is wrong", n ? "; " : "");
    }
}

static int have_login(void)
{
    return D.sess ? ts_sess_node_state(D.sess)->have_login : D.st.have_login;
}

/* ---- Replies ---------------------------------------------------------- */

typedef struct {
    char *p;
    size_t len, cap;
    int full;
} rbuild;

/* Append "key value\n", with control bytes in the value replaced. */
static void put(rbuild *b, const char *key, const char *val)
{
    size_t kl = strlen(key), vl = val ? strlen(val) : 0, need = kl + (val ? 1 + vl : 0) + 1;
    if (b->full) return;
    if (need > b->cap - b->len - 16) {   /* keep room for the marker */
        memcpy(b->p + b->len, "truncated\n", 10);
        b->len += 10;
        b->full = 1;
        return;
    }
    memcpy(b->p + b->len, key, kl);
    b->len += kl;
    if (val) {
        b->p[b->len++] = ' ';
        b->len += ts_ipc_clean(b->p + b->len, vl + 1, val, vl, 0);
    }
    b->p[b->len++] = '\n';
}

static void fmt_ip(char *out, size_t cap, uint32_t a)
{
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)(a >> 24), (unsigned)(a >> 16 & 255),
             (unsigned)(a >> 8 & 255), (unsigned)(a & 255));
}

static void build_status(rbuild *b)
{
    view v;
    char line[TS_NODE_NAME_MAX + 64], ip[16];
    const char *url;
    get_view(&v);
    put(b, "ok", NULL);
    put(b, "state", v.name);
    put(b, "status", v.status);
    put(b, "login", have_login() ? (D.logout_req ? "leaving" : "yes") : "no");
    if (D.sess && (url = ts_sess_login_url(D.sess)) != NULL) put(b, "url", url);
    if (v.problem[0]) put(b, "problem", v.problem);
    if (D.sess) {
        const ts_netmap *nm = ts_sess_netmap(D.sess);
        size_t i;
        if (nm->have_self && nm->self.have_ipv4) {
            fmt_ip(ip, sizeof ip, nm->self.ipv4);
            put(b, "ip", ip);
        }
        for (i = 0; i < nm->npeers; i++) {
            const ts_node *p = &nm->peers[i];
            if (p->have_ipv4) fmt_ip(ip, sizeof ip, p->ipv4);
            else snprintf(ip, sizeof ip, "-");
            snprintf(line, sizeof line, "%s %s %s", ip, p->online ? "online" : "offline", p->name);
            put(b, "peer", line);
        }
    }
}

static void do_request(client *c, ts_ipc_cmd cmd)
{
    rbuild b;
    switch (cmd) {
    case TS_IPC_UP:
        D.want_up = 1;
        D.logout_req = 0;
        if (D.sess) ts_sess_up(D.sess);
        else if (!D.kf_active) {
            D.kf_backoff = 0;           /* an operator's request retries now */
            D.kf_retry_at = now_ms();
            kf_tick();
        }
        logline("up requested");
        break;
    case TS_IPC_LOGOUT:
        D.want_up = 0;
        D.logout_req = 1;
        if (D.sess) ts_sess_logout(D.sess);
        logline("logout requested");
        break;
    default:
        break;
    }
    b.p = c->out;
    b.len = 0;
    b.cap = TS_IPC_RESP_MAX;
    b.full = 0;
    build_status(&b);
    c->outlen = b.len;
}

/* ---- Local clients --------------------------------------------------- */

static void client_close(client *c)
{
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    free(c->out);
    c->out = NULL;
    c->inlen = c->outlen = c->outoff = 0;
}

static void client_error(client *c, const char *text)
{
    int n = snprintf(c->out, TS_IPC_RESP_MAX, "error %s\n", text);
    c->outlen = n > 0 ? (size_t)n : 0;
}

static void accept_clients(void)
{
    for (;;) {
        int fd = accept(D.lfd, NULL, NULL), i, fl;
        client *c = NULL;
#ifdef SO_NOSIGPIPE
        int one = 1;
#endif
        if (fd < 0) return;
        for (i = 0; i < TS_IPC_MAX_CLIENTS; i++)
            if (D.cl[i].fd < 0) {
                c = &D.cl[i];
                break;
            }
        if (!c || (fl = fcntl(fd, F_GETFL)) < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            close(fd);   /* busy: turned away, not queued */
            continue;
        }
#ifdef SO_NOSIGPIPE
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        c->out = (char *)malloc(TS_IPC_RESP_MAX);
        if (!c->out) {
            close(fd);
            continue;
        }
        c->fd = fd;
        c->inlen = c->outlen = c->outoff = 0;
        c->deadline = now_ms() + TS_IPC_CLIENT_TIMEOUT_MS;
    }
}

static void client_read(client *c)
{
    ssize_t n = read(c->fd, c->in + c->inlen, sizeof c->in - c->inlen);
    char *nl;
    ts_ipc_cmd cmd;
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
    if (n <= 0) {
        client_close(c);
        return;
    }
    c->inlen += (size_t)n;
    nl = memchr(c->in, '\n', c->inlen);
    if (nl) {
        if (ts_ipc_parse_request(c->in, (size_t)(nl - c->in) + 1, &cmd) == 0) do_request(c, cmd);
        else client_error(c, "unknown request");
    } else if (c->inlen > TS_IPC_LINE_MAX) {
        client_error(c, "request too long");
    }
    if (c->outlen) shutdown(c->fd, SHUT_RD);
}

static void client_write(client *c)
{
    ssize_t n = write(c->fd, c->out + c->outoff, c->outlen - c->outoff);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
    if (n <= 0) {
        client_close(c);
        return;
    }
    c->outoff += (size_t)n;
    if (c->outoff == c->outlen) client_close(c);
}

/* ---- Main loop ---------------------------------------------------------- */

static void on_signal(int sig)
{
    int e = errno;
    char b = 1;
    (void)sig;
    got_signal = 1;
    (void)write(D.sigpipe[1], &b, 1);
    errno = e;
}

static void log_state(void)
{
    view v;
    get_view(&v);
    if (strcmp(v.name, D.logged_state) != 0 || strcmp(v.problem, D.logged_reason) != 0) {
        if (v.problem[0]) logline("state %s: %s", v.name, v.problem);
        else logline("state %s", v.name);
        snprintf(D.logged_state, sizeof D.logged_state, "%s", v.name);
        snprintf(D.logged_reason, sizeof D.logged_reason, "%s", v.problem);
    }
}

static void shutdown_all(void)
{
    int i;
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) client_close(&D.cl[i]);
    if (D.lfd >= 0) {
        close(D.lfd);
        ts_ipc_unlink(D.sock_path, D.ldev, D.lino);
    }
    conn_close();
    ts_keyfetch_close(&KF);
    if (D.sess) {
        ts_sess_free(D.sess);
        ts_wipe(D.sess, sizeof *D.sess);
        free(D.sess);
        D.sess = NULL;
    }
    ts_wipe(&D.st, sizeof D.st);
    free(D.out);
}

static int setup_control_host(void)
{
    snprintf(D.host, sizeof D.host, "%s", TS_CONTROL_HOST);
#ifdef TS_TEST_HOOKS
    {
        const char *e = getenv("TSPPC_CONTROL");
        if (e && e[0]) {
            const char *colon = strchr(e, ':');
            size_t n = colon ? (size_t)(colon - e) : strlen(e);
            if (n == 0 || n > TS_SESS_HOST_MAX) return -1;
            memcpy(D.host, e, n);
            D.host[n] = 0;
            if (colon) {
                long p = strtol(colon + 1, NULL, 10);
                if (p < 1 || p > 65535) return -1;
                D.port_override = (uint16_t)p;
            }
            D.host_override = 1;
        }
    }
#endif
    return 0;
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    struct group *gr;
    char err[512];
    int i, code = 0;
    gid_t gid = TS_IPC_GROUP_GID;

    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: tsppcd (runs in the foreground)\n");
        return 2;
    }
    memset(&D, 0, sizeof D);
    D.fd = D.lfd = -1;
    D.res.fd = -1;
    D.res.pid = -1;
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) D.cl[i].fd = -1;
    mach_timebase_info(&tb);
    t_start = now_ms();

    signal(SIGPIPE, SIG_IGN);
    if (pipe(D.sigpipe) != 0 || ts_fd_nonblock(D.sigpipe[0]) != 0 || ts_fd_nonblock(D.sigpipe[1]) != 0) {
        fprintf(stderr, "tsppcd: cannot create the signal pipe\n");
        return 1;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    D.out = (uint8_t *)malloc(OUT_MAX);
    if (!D.out) {
        fprintf(stderr, "tsppcd: out of memory\n");
        return 1;
    }
    if (setup_control_host() != 0) {
        fprintf(stderr, "tsppcd: bad control host override\n");
        return 1;
    }
    D.state_dir = ts_state_default_dir();
    D.sock_path = ts_ipc_socket_path();
    if ((gr = getgrnam(TS_IPC_GROUP)) != NULL) gid = gr->gr_gid;
    D.lfd = ts_ipc_listen(D.sock_path, gid, &D.ldev, &D.lino, err, sizeof err);
    if (D.lfd < 0) {
        fprintf(stderr, "tsppcd: %s\n", err);
        return 1;
    }
    if (ts_state_load_or_create(&D.st, D.state_dir, err, sizeof err) != 0) {
        fprintf(stderr, "tsppcd: node state: %s\n", err);
        close(D.lfd);
        ts_ipc_unlink(D.sock_path, D.ldev, D.lino);
        return 1;
    }
    if (ts_hostinfo_json(D.hostinfo, sizeof D.hostinfo) < 0) {
        fprintf(stderr, "tsppcd: cannot build Hostinfo\n");
        shutdown_all();
        return 1;
    }
    D.want_up = D.st.have_login;
    logline("started (%s)", D.st.have_login ? "logged in: connecting" : "logged out: waiting for tsppc up");

    while (!got_signal) {
        fd_set r, w;
        struct timeval tv;
        int maxfd = D.sigpipe[0], kfmax = -1;
        unsigned gen;

        if (D.sess) {
            ts_sess_tick(D.sess, (uint64_t)now_ms());
            if (ts_sess_exit_requested(D.sess, &code)) {
                logline("control asked this client to exit (code %d)", code);
                break;
            }
        }
        kf_tick();
        conn_flush();
        log_state();

        FD_ZERO(&r);
        FD_ZERO(&w);
        FD_SET(D.sigpipe[0], &r);
        FD_SET(D.lfd, &r);
        if (D.lfd > maxfd) maxfd = D.lfd;
        for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) {
            client *c = &D.cl[i];
            if (c->fd < 0) continue;
            if (c->outlen) FD_SET(c->fd, &w);
            else FD_SET(c->fd, &r);
            if (c->fd > maxfd) maxfd = c->fd;
        }
        if (D.sess) conn_fds(&r, &w, &maxfd);
        if (D.kf_active && ts_keyfetch_fds(&KF, &r, &w, &kfmax) == 0 && kfmax > maxfd) maxfd = kfmax;
        gen = D.gen;
        tv.tv_sec = LOOP_MS / 1000;
        tv.tv_usec = (LOOP_MS % 1000) * 1000;
        if (select(maxfd + 1, &r, &w, NULL, &tv) < 0) {
            if (errno == EINTR) continue;
            logline("select failed: %s", strerror(errno));
            code = 1;
            break;
        }
        if (FD_ISSET(D.sigpipe[0], &r)) {
            char b[16];
            while (read(D.sigpipe[0], b, sizeof b) > 0) {}
        }
        if (got_signal) break;
        if (D.sess) {
            ts_sess_tick(D.sess, (uint64_t)now_ms());
            conn_events(&r, &w, gen);
        }
        kf_events();
        for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) {
            client *c = &D.cl[i];
            if (c->fd < 0) continue;
            if (c->outlen && FD_ISSET(c->fd, &w)) client_write(c);
            else if (!c->outlen && FD_ISSET(c->fd, &r)) client_read(c);
            if (c->fd >= 0 && now_ms() > c->deadline) client_close(c);
        }
        if (FD_ISSET(D.lfd, &r)) accept_clients();
    }
    logline(got_signal ? "stopping on a signal" : "stopping");
    shutdown_all();
    return code & 0xff;
}
