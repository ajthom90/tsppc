/* tsppcd: the daemon. Runs in the foreground as root (launchd runs it with
 * -l <logfile>: stderr goes to that file, capped by logfile.c; tsppcd --cleanup
 * removes what a crash left, and exits 1 if a daemon is running).
 *
 * One select() loop over the control connection, the DNS helper's pipe, the
 * control key fetch, the local socket and its clients, and a signal pipe.
 * SIGTERM and SIGINT close everything and remove the socket. Logs go to
 * stderr and never hold keys or the login URL.
 *
 * Start: load (or create) the node state, compute Hostinfo, listen on the
 * socket, fetch control's Noise key (retried with backoff; status shows why it
 * fails, "system clock is wrong" included), then run the control session. The
 * session is started at once if the saved state is logged in and not down
 * (ts_sess_down), as upstream's daemon does; otherwise it waits for `tsppc up`.
 *
 * Logout follows ts_sess_logout: the intent (logout_pending) is saved first,
 * also before the control key is in, and the key is expired at control once
 * a session can run; a restart mid-logout finishes it and never logs in with
 * that key.
 *
 * In builds with -DTS_TEST_HOOKS only, TSPPC_CONTROL ("host" or "host:port";
 * with a port every control connection goes there, with TLS if it is 443),
 * TSPPC_CONTROL_KEY (control's public key in hex: no key fetch),
 * TSPPC_STATE_DIR and TSPPC_SOCKET override the defaults; TSPPC_NO_TUN and
 * TSPPC_DERP_PLAIN are the data plane's (dataplane_io.h), TSPPC_HOSTS_FILE
 * the hosts file's (names_io.h).
 *
 * The data plane (tun device, relays, home selection) runs from
 * dataplane_io.c, synced with the session once per loop turn; while it runs
 * the loop wakes at least every TS_DPIO_TICK_MS.
 *
 * Peer names go into a tsppc block of /etc/hosts (names_io.c) while the data
 * plane runs; the block is removed when it stops, at exit, and at the next
 * start after a crash.
 *
 * A ping request (ipc.h) holds its client open with no reply until the data
 * plane reports the ping (pong, timeout, or stopped: down, logout, a restart
 * of the data plane); its deadline is then the ping timeout plus
 * TS_IPC_PING_MARGIN_MS. A client that closes or sends more cancels its
 * ping. At most TS_IPC_MAX_PINGS clients wait at once, so status and the
 * menu bar always have a slot. Only refused pings are logged.
 *
 * Sleep and network changes (conditions.h): each turn, after the data plane
 * sync, the wall clock (gettimeofday) is compared with the monotonic one; a
 * jump of TS_WAKE_JUMP_MS or more means the Mac slept (or the clock was
 * stepped). Every TS_NET_POLL_MS the IPv4 addresses and default route are
 * fingerprinted (netinfo.h); a failed snapshot is ignored. Either asks for a
 * rebind, at most one per TS_REBIND_MIN_GAP_MS: the control connection, if
 * any, is closed and the session told (its own backoff then decides when it
 * reconnects), and the relays are redialed with a new home probe round
 * (ts_dpio_rebind). WireGuard sessions are reset only when a forward wake was
 * seen since the last rebind; a clock stepped back or a network change keeps
 * them. The loop never sleeps longer than LOOP_MS, so a wake is seen within a
 * second. In test builds SIGUSR1 stands for a wake and SIGUSR2 for a network
 * change. */
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

#include "conditions.h"
#include "dataplane_io.h"
#include "ipc.h"
#include "ipc_reply.h"
#include "logfile.h"
#include "names_io.h"
#include "src/control/noise.h"
#include "src/control/session.h"
#include "src/core/bytes.h"
#include "src/data/dataplane.h"
#include "src/crypto/random.h"
#include "src/net/keyfetch.h"
#include "src/net/resolve.h"
#include "src/net/sock.h"
#include "src/net/tls.h"
#include "src/proto/encoding.h"
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
#define ACCEPT_PAUSE_MS 1000        /* after accept fails for lack of descriptors */

/* A status line (with a login URL) must fit a reply value the CLI reads. */
typedef char status_fits_cli[TS_IPC_VALUE_MAX >= TS_SESS_URL_MAX + 512 ? 1 : -1];

enum { C_NONE, C_RESOLVE, C_TCP, C_TLS, C_OPEN };

typedef struct {
    int fd;                         /* -1: free */
    int64_t deadline;
    char in[TS_IPC_LINE_MAX + 1];
    size_t inlen;
    char *out;                      /* the reply, once the request is in */
    size_t outlen, outoff;
    /* A ping request waiting for its result (ts_dpio_ping). The result is
     * buffered by on_ping_result and the reply built by finish_pings, outside
     * the data plane's calls. */
    int ping;                       /* 1: pending */
    uint64_t cookie;
    int ping_done, ping_status, ping_region;
    uint32_t ping_lat;
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
    int64_t accept_paused_until;
    client cl[TS_IPC_MAX_CLIENTS];
    uint64_t ping_seq;              /* the last ping cookie handed out */

    int fed;                        /* bytes reached the session this turn (the map may have changed) */

    /* Sleep and network changes. */
    ts_wake wake;
    ts_rebind_gate gate;
    int rebind_reset;               /* a forward wake was seen since the last rebind */
    int net_primed;
    uint64_t net_fp;
    int64_t net_next;

    int sigpipe[2];
    char logged_state[32];
    char logged_reason[TEXT_MAX];
} D;

static ts_keyfetch KF;              /* about 100 KiB: not on the stack */
static uint8_t rbuf[READ_CHUNK];
static mach_timebase_info_data_t tb;
static volatile sig_atomic_t got_signal;
#ifdef TS_TEST_HOOKS
static volatile sig_atomic_t got_test_wake, got_test_net;
#endif

/* ---- Time and logging --------------------------------------------------- */

/* Monotonic milliseconds (mach_absolute_time exists from 10.0 on). */
static int64_t now_ms(void)
{
    uint64_t t = mach_absolute_time();
    uint64_t ns = (t / tb.denom) * tb.numer + (t % tb.denom) * tb.numer / tb.denom;
    return (int64_t)(ns / 1000000u);
}

static int64_t t_start;
static int g_logfile;   /* -l: check the log file's size after each line */

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
    if (g_logfile) ts_logfile_check();
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
    D.port = D.port_override ? D.port_override : port;
    D.use_tls = D.port == 443;
    snprintf(D.chost, sizeof D.chost, "%s", host);
    if (ts_resolve_start(&D.res, host) != 0) {
        logline("cannot start the DNS lookup for control");
        return -1;
    }
    if (ts_resolve_fd(&D.res) >= FD_SETSIZE) {
        ts_resolve_cancel(&D.res);
        logline("out of descriptors for select");
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
        D.fed = 1;
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
        if (D.fd >= FD_SETSIZE) {
            conn_fail("out of descriptors for select");
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
        if (D.gen != gen_at_select || !FD_ISSET(D.fd, w)) return;
        conn_flush();
        /* TLS records may wait to be sent with nothing queued here (or while
         * the session pauses reading): push them, or select spins. */
        if (D.gen == gen_at_select && D.tls && ts_tls_step(D.tls) < 0) conn_fail(ts_tls_error(D.tls));
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
    /* A logout saved before the key was in (or before a restart) is told to
     * control now; ts_sess_up would also finish it first. */
    if (D.want_up) ts_sess_up(D.sess);
    else if (D.st.logout_pending) (void)ts_sess_logout(D.sess);
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
    if (KF.fd >= FD_SETSIZE || KF.res.fd >= FD_SETSIZE) {
        kf_fail("out of descriptors for select");
        return;
    }
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
        snprintf(v->problem, sizeof v->problem, "%s", ts_sess_problem(D.sess));
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
    if (D.sess && D.want_up) {
        ts_dpio_view dv;
        ts_dpio_get_view(&dv);
        if (dv.running && dv.problem[0]) {
            size_t n = strlen(v->problem);
            snprintf(v->problem + n, sizeof v->problem - n, "%s%s", n ? "; " : "", dv.problem);
        }
    }
    if (!D.sess && D.st.logout_pending) {
        size_t n = strlen(v->status);
        snprintf(v->status + n, sizeof v->status - n,
                 "; logout saved; control will be told once the control key is fetched");
    }
    /* The wall clock, for this check only: no correct clock is before the build. */
    if (time(NULL) < ts_build_time && !strstr(v->problem, "system clock is wrong")) {
        size_t n = strlen(v->problem);
        snprintf(v->problem + n, sizeof v->problem - n, "%ssystem clock is wrong", n ? "; " : "");
    }
}

/* Logout before the session exists (no control key yet): save the intent, as
 * ts_sess_logout does first. The session tells control once the key is in.
 * Returns 0, or -1 if the save failed (nothing changed). */
static int logout_before_session(void)
{
    ts_state n;
    char err[256];
    int rc;
    if (!D.st.have_login || D.st.logout_pending) return 0;
    n = D.st;
    n.have_login = 0;
    n.down = 0;
    n.logout_pending = 1;
    rc = ts_state_save(&n, D.state_dir, err, sizeof err);
    if (rc == 0) D.st = n;
    else logline("cannot save the node state: %s", err);
    ts_wipe(&n, sizeof n);
    return rc;
}

/* "yes", "no" or "leaving" (a logout saved and not finished). */
static const char *login_word(void)
{
    const ts_state *st = D.sess ? ts_sess_node_state(D.sess) : &D.st;
    return st->have_login ? "yes" : st->logout_pending ? "leaving" : "no";
}

/* Down before the session exists (no control key yet): save it, as
 * ts_sess_down does first. Returns 0, or -1 if the save failed (nothing
 * changed). With no login, or a logout pending, there is nothing to save. */
static int down_before_session(void)
{
    ts_state n;
    char err[256];
    int rc;
    if (!D.st.have_login || D.st.down || D.st.logout_pending) return 0;
    n = D.st;
    n.down = 1;
    rc = ts_state_save(&n, D.state_dir, err, sizeof err);
    if (rc == 0) D.st = n;
    else logline("cannot save the node state: %s", err);
    ts_wipe(&n, sizeof n);
    return rc;
}

/* Up before the session exists (no control key yet): clear a saved down
 * first, so a restart before the key is in still connects. Returns 0, or -1
 * if the save failed (nothing changed). With no login, no saved down, or a
 * logout pending, there is nothing to save. (The session's ts_sess_up
 * connects even when its save fails; here nothing is connected yet, so a
 * failed save is the reply instead.) */
static int up_before_session(void)
{
    ts_state n;
    char err[256];
    int rc;
    if (!D.st.have_login || !D.st.down || D.st.logout_pending) return 0;
    n = D.st;
    n.down = 0;
    rc = ts_state_save(&n, D.state_dir, err, sizeof err);
    if (rc == 0) D.st = n;
    else logline("cannot save the node state: %s", err);
    ts_wipe(&n, sizeof n);
    return rc;
}

/* Down, with the session if there is one. Returns 0, or -1 if the first
 * save failed (nothing changed). */
static int do_down(void)
{
    if (!D.sess) return down_before_session();
    return ts_sess_down(D.sess);
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

/* A region's code for status: "-" when the map has none. */
static const char *region_code(const ts_netmap *nm, int id)
{
    size_t i;
    for (i = 0; i < nm->nregions; i++)
        if (nm->regions[i].id == id) return nm->regions[i].code[0] ? nm->regions[i].code : "-";
    return "-";
}

/* The data plane's filter state as one word. */
static const char *filter_word(const char *f)
{
    if (strcmp(f, "ok") == 0) return "ok";
    if (strcmp(f, "too large") == 0) return "too-large";
    if (strcmp(f, "invalid") == 0) return "invalid";
    return "none";
}

static void build_status(rbuild *b)
{
    view v;
    char line[TS_NODE_NAME_MAX + 64], ip[16];
    const char *url;
    char names[160];
    ts_dpio_view dv;
    get_view(&v);
    ts_names_status(names, sizeof names);
    put(b, "ok", NULL);
    put(b, "state", v.name);
    put(b, "status", v.status);
    put(b, "login", login_word());
    put(b, "wanted", D.want_up ? "up" : "down");
    if (D.sess && (url = ts_sess_login_url(D.sess)) != NULL) put(b, "url", url);
    if (v.problem[0]) put(b, "problem", v.problem);
    put(b, "names", names);
    /* Wanted down: the session keeps its last map, which is stale. */
    if (D.sess && D.want_up) {
        const ts_netmap *nm = ts_sess_netmap(D.sess);
        size_t i;
        if (nm->have_self && nm->self.name[0]) put(b, "self", nm->self.name);
        if (nm->have_self && nm->self.have_ipv4) {
            fmt_ip(ip, sizeof ip, nm->self.ipv4);
            put(b, "ip", ip);
        }
        ts_dpio_get_view(&dv);
        if (dv.running) {
            if (dv.home > 0) {
                snprintf(line, sizeof line, "%d %s %s", dv.home, region_code(nm, dv.home),
                         dv.home_up ? "connected" : dv.home_down ? "down" : "connecting");
                put(b, "relay", line);
            }
            snprintf(line, sizeof line, "%s%s%s", dv.tun_open ? dv.ifname : "off", dv.problem[0] ? " " : "", dv.problem);
        } else {
            snprintf(line, sizeof line, "off");
        }
        put(b, "tunnel", line);
        if (dv.running) {
            snprintf(line, sizeof line, "%s dropped %lu", filter_word(dv.filter), dv.filtered);
            put(b, "filter", line);
        }
        for (i = 0; i < nm->npeers; i++) {
            const ts_node *p = &nm->peers[i];
            if (p->have_ipv4) fmt_ip(ip, sizeof ip, p->ipv4);
            else snprintf(ip, sizeof ip, "-");
            snprintf(line, sizeof line, "%s %s %s", ip, p->online ? "online" : "offline", p->name);
            put(b, "peer", line);
        }
        /* After the peers: the menu bar needs them, these are for the CLI. */
        if (dv.running) {
            int64_t now = now_ms();
            for (i = 0; i < nm->npeers; i++) {
                const ts_node *p = &nm->peers[i];
                ts_wg_stats ws;
                char age[24] = "-";
                int region = -1;
                if (!p->have_ipv4 || ts_dpio_peer_status(p->ipv4, &ws, &region) != 0) continue;
                if (ws.last_handshake_ms >= 0) {
                    int64_t a = (now - ws.last_handshake_ms) / 1000;
                    snprintf(age, sizeof age, "%lu", (unsigned long)(a > 0 ? a : 0));
                }
                fmt_ip(ip, sizeof ip, p->ipv4);
                snprintf(line, sizeof line, "%s %s %lu %lu %s", ip, region > 0 ? region_code(nm, region) : "-",
                         (unsigned long)ws.rx_packets, (unsigned long)ws.tx_packets, age);
                put(b, "path", line);
            }
        }
    }
}

static void client_error(client *c, const char *text)
{
    int n = snprintf(c->out, TS_IPC_RESP_MAX, "error %s\n", text);
    c->outlen = n > 0 ? (size_t)n : 0;
}

/* Upstream's texts where it has one: no node with that IP is the engine's
 * "no matching peer"; a peer with no disco key has no magicsock endpoint
 * upstream, so "unknown peer"; an expired one is ipnlocal's text. "peer has
 * no home relay" is ours (upstream would just time out). */
static const char *ping_error_text(int rc)
{
    switch (rc) {
    case TS_DP_PING_UNKNOWN: return "no matching peer";
    case TS_DP_PING_EXPIRED: return "peer's node key has expired";
    case TS_DP_PING_NO_DISCO: return "unknown peer";
    case TS_DP_PING_NO_HOME: return "peer has no home relay";
    case TS_DP_PING_BUSY: return "too many pings in flight";
    case TS_DP_PING_DOWN: return "not connected";
    default: return "ping failed";
    }
}

/* Start a ping for c: on success no reply yet (finish_pings builds it). */
static void start_ping(client *c, const ts_ipc_args *a)
{
    int rc, i, pending = 0;
    uint64_t cookie = ++D.ping_seq;
    char ip[16];
    if (!D.sess || !D.want_up) {
        client_error(c, ping_error_text(TS_DP_PING_DOWN));
        return;
    }
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++)
        if (D.cl[i].fd >= 0 && D.cl[i].ping) pending++;
    if (pending >= TS_IPC_MAX_PINGS) {
        client_error(c, "too many pings in progress");
        return;
    }
    rc = ts_dpio_ping(a->ip, a->timeout_ms, cookie, now_ms());
    if (rc != 0) {
        /* Only failures are logged: a ping loop (tsppc ping -c 0) would
         * otherwise add a line a second. */
        fmt_ip(ip, sizeof ip, a->ip);
        logline("ping %s refused: %s", ip, ping_error_text(rc));
        client_error(c, ping_error_text(rc));
        return;
    }
    c->ping = 1;
    c->cookie = cookie;
    c->ping_done = 0;
    c->deadline = now_ms() + (int64_t)a->timeout_ms + TS_IPC_PING_MARGIN_MS;
}

/* The data plane's report on a ping (inside its calls: only recorded). */
static void on_ping_result(void *user, uint64_t cookie, int status, uint32_t latency_us, int region_id)
{
    int i;
    (void)user;
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) {
        client *c = &D.cl[i];
        if (c->fd < 0 || !c->ping || c->ping_done || c->cookie != cookie) continue;
        c->ping_done = 1;
        c->ping_status = status;
        c->ping_lat = latency_us;
        c->ping_region = region_id;
        return;
    }
}

/* Build the replies of the pings that ended. */
static void finish_pings(void)
{
    int i;
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) {
        client *c = &D.cl[i];
        rbuild b;
        char line[96];
        if (c->fd < 0 || !c->ping || !c->ping_done) continue;
        c->ping = 0;
        if (c->ping_status == TS_DP_PONG) {
            const char *code = D.sess ? region_code(ts_sess_netmap(D.sess), c->ping_region) : "-";
            b.p = c->out;
            b.len = 0;
            b.cap = TS_IPC_RESP_MAX;
            b.full = 0;
            snprintf(line, sizeof line, "pong %lu %d %.40s", (unsigned long)c->ping_lat, c->ping_region, code);
            put(&b, "ok", NULL);
            put(&b, "ping", line);
            c->outlen = b.len;
        } else if (c->ping_status == TS_DP_PING_TIMEOUT) {
            c->outlen = (size_t)snprintf(c->out, TS_IPC_RESP_MAX, "ok\nping timeout\n");
        } else {
            client_error(c, ping_error_text(TS_DP_PING_DOWN));
        }
        shutdown(c->fd, SHUT_RD);
        /* Time to write it, even if the loop was held past the ping's
         * deadline (a blocking command) and the check below runs now. */
        c->deadline = now_ms() + TS_IPC_CLIENT_TIMEOUT_MS;
    }
}

static void do_request(client *c, ts_ipc_cmd cmd, const ts_ipc_args *args)
{
    rbuild b;
    switch (cmd) {
    case TS_IPC_PING:
        start_ping(c, args);
        return;
    case TS_IPC_UP:
        if (!D.sess && up_before_session() != 0) {
            logline("up failed: the node state could not be saved");
            client_error(c, "up failed: the node state could not be saved; nothing was changed");
            return;
        }
        D.want_up = 1;
        if (D.sess) ts_sess_up(D.sess);
        else if (!D.kf_active) {
            D.kf_backoff = 0;           /* an operator's request retries now */
            D.kf_retry_at = now_ms();
            kf_tick();
        }
        logline("up requested");
        break;
    case TS_IPC_LOGOUT:
        logline("logout requested");
        if ((D.sess ? ts_sess_logout(D.sess) : logout_before_session()) != 0) {
            logline("logout failed: the node state could not be saved");
            client_error(c, "logout failed: the node state could not be saved; nothing was changed");
            return;
        }
        D.want_up = 0;
        break;
    case TS_IPC_DOWN:
        logline("down requested");
        if (do_down() != 0) {
            logline("down failed: the node state could not be saved");
            client_error(c, "down failed: the node state could not be saved; nothing was changed");
            return;
        }
        D.want_up = 0;
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
    if (c->ping && !c->ping_done) ts_dpio_ping_cancel(c->cookie);
    c->ping = c->ping_done = 0;
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    free(c->out);
    c->out = NULL;
    c->inlen = c->outlen = c->outoff = 0;
}

static void accept_clients(void)
{
    for (;;) {
        int fd = accept(D.lfd, NULL, NULL), i, fl;
        client *c = NULL;
#ifdef SO_NOSIGPIPE
        int one = 1;
#endif
        if (fd < 0) {
            if (errno == EMFILE || errno == ENFILE) {
                /* Out of descriptors: stop polling the listener for a while
                 * rather than spin on it. */
                D.accept_paused_until = now_ms() + ACCEPT_PAUSE_MS;
                logline("out of descriptors: not accepting clients for a moment");
            }
            return;
        }
        if (fd >= FD_SETSIZE) {
            close(fd);
            continue;
        }
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
        c->ping = c->ping_done = 0;
        c->deadline = now_ms() + TS_IPC_CLIENT_TIMEOUT_MS;
    }
}

static void client_read(client *c)
{
    ssize_t n;
    char *nl;
    ts_ipc_cmd cmd;
    ts_ipc_args args;
    if (c->ping) {
        /* Waiting for a ping: the client closing, or sending anything,
         * cancels it. */
        char b[16];
        n = read(c->fd, b, sizeof b);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
        client_close(c);
        return;
    }
    n = read(c->fd, c->in + c->inlen, sizeof c->in - c->inlen);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
    if (n <= 0) {
        client_close(c);
        return;
    }
    c->inlen += (size_t)n;
    nl = memchr(c->in, '\n', c->inlen);
    if (nl) {
        size_t len = (size_t)(nl - c->in) + 1;
        char extra;
        /* One line and nothing after it, here or already waiting. */
        if (len != c->inlen || read(c->fd, &extra, 1) > 0) client_error(c, "unexpected bytes after the request");
        else if (ts_ipc_parse_request(c->in, len, &cmd, &args) == 0) do_request(c, cmd, &args);
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

#ifdef TS_TEST_HOOKS
/* SIGUSR1: act as after a wake; SIGUSR2: as after a network change. */
static void on_test_signal(int sig)
{
    int e = errno;
    char b = 1;
    if (sig == SIGUSR1) got_test_wake = 1;
    else got_test_net = 1;
    (void)write(D.sigpipe[1], &b, 1);
    errno = e;
}
#endif

/* Wall clock milliseconds, for spotting a sleep only. */
static int64_t wall_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Notice a wake or a network change, and rebind when the gate allows. From
 * the loop body only (ts_dpio_rebind is not for callbacks). */
static void check_conditions(void)
{
    int64_t now = now_ms(), jump;
    char why[64];

    jump = ts_wake_check(&D.wake, wall_ms(), now);
    if (jump != 0) {
        logline("woke from sleep (wall clock jumped %ld s)", (long)(jump / 1000));
        ts_rebind_request(&D.gate, "woke from sleep", now);
        if (jump > 0) D.rebind_reset = 1;
    }
#ifdef TS_TEST_HOOKS
    if (got_test_wake) {
        got_test_wake = 0;
        logline("woke from sleep (test signal)");
        ts_rebind_request(&D.gate, "woke from sleep", now);
        D.rebind_reset = 1;
    }
    if (got_test_net) {
        got_test_net = 0;
        logline("network changed (test signal)");
        ts_rebind_request(&D.gate, "network changed", now);
    }
#endif
    if (now >= D.net_next) {
        /* More than the fingerprint keeps: it sorts, then cuts. */
        ts_ifaddr a[2 * TS_NET_MAX_ADDRS];
        size_t n = 0;
        uint32_t gw = 0;
        char gw_if[16];
        D.net_next = now + TS_NET_POLL_MS;
        if (ts_net_snapshot(a, sizeof a / sizeof a[0], &n, &gw, gw_if) == 0) {
            uint64_t fp = ts_net_fingerprint(a, n, gw, gw_if);
            if (!D.net_primed) {
                D.net_primed = 1;
                D.net_fp = fp;
            } else if (fp != D.net_fp) {
                D.net_fp = fp;
                logline("network changed");
                ts_rebind_request(&D.gate, "network changed", now);
            }
        }
    }
    if (ts_rebind_due(&D.gate, now, why)) {
        int reset = D.rebind_reset;
        D.rebind_reset = 0;
        if (D.cphase != C_NONE) {
            logline("closing the control connection (%s)", why);
            conn_close();
            if (D.sess) ts_sess_disconnected(D.sess, why);
        }
        ts_dpio_rebind(why, 1, reset);
    }
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
    ts_dpio_shutdown();
    ts_names_shutdown();
    /* Pending pings were just ended (stopped): one try to tell them. */
    finish_pings();
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) {
        client *c = &D.cl[i];
        if (c->fd >= 0 && c->outlen > c->outoff) (void)write(c->fd, c->out + c->outoff, c->outlen - c->outoff);
        client_close(c);
    }
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
        e = getenv("TSPPC_CONTROL_KEY");
        if (e && e[0]) {
            if (ts_hex_decode(D.control_pub, 32, e, strlen(e)) != 0) return -1;
            D.have_key = 1;
        }
    }
#endif
    return 0;
}

/* tsppcd --cleanup, for the uninstaller: with no daemon answering on the
 * control socket, remove the route and the /etc/hosts block a crash left.
 * Loads no state, keys or network. */
static int run_cleanup(void)
{
    char buf[TS_IPC_RESP_MAX];
    size_t len = 0;

    mach_timebase_info(&tb);
    t_start = now_ms();
    /* Only "nothing there" (no socket, or a stale one) means no daemon. */
    if (ts_ipc_request(ts_ipc_socket_path(), TS_IPC_STATUS, 3000, buf, sizeof buf, &len) != TS_REQ_NO_DAEMON) {
        fprintf(stderr, "tsppcd is running; stop it first\n");
        return 1;
    }
    if (ts_dpio_init(logline, now_ms) != 0) {
        fprintf(stderr, "tsppcd: out of memory\n");
        return 1;
    }
    ts_dpio_cleanup_route();
    ts_names_init(logline);
    ts_names_cleanup();
    ts_dpio_shutdown();
    ts_names_shutdown();
    return 0;
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    struct group *gr;
    char err[512];
    int i, code = 0;
    gid_t gid = TS_IPC_GROUP_GID;

    const char *logpath = NULL;
    int cleanup = 0;

    if (argc == 1) {
    } else if (argc == 2 && strcmp(argv[1], "--cleanup") == 0) {
        cleanup = 1;
    } else if (argc == 3 && strcmp(argv[1], "-l") == 0 && argv[2][0]) {
        logpath = argv[2];
    } else {
        fprintf(stderr, "usage: tsppcd [-l <logfile>] | --cleanup\n");
        return 2;
    }
    if (cleanup) return run_cleanup();
    if (logpath) {
        if (ts_logfile_open(logpath, err, sizeof err) != 0) {
            fprintf(stderr, "tsppcd: %s\n", err);
            return 1;
        }
        g_logfile = 1;
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
#ifdef TS_TEST_HOOKS
    sa.sa_handler = on_test_signal;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
#endif

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
    /* After the socket: a second tsppcd, refused above, must not touch the
     * running one's route. */
    if (ts_dpio_init(logline, now_ms) != 0) {
        fprintf(stderr, "tsppcd: out of memory\n");
        close(D.lfd);
        ts_ipc_unlink(D.sock_path, D.ldev, D.lino);
        return 1;
    }
    ts_dpio_cleanup_route();
    ts_dpio_set_ping_cb(on_ping_result, NULL);
    ts_names_init(logline);
    ts_names_cleanup();
    if (ts_state_load_or_create(&D.st, D.state_dir, err, sizeof err) != 0) {
        fprintf(stderr, "tsppcd: node state: %s\n", err);
        ts_dpio_shutdown();
        ts_names_shutdown();
        close(D.lfd);
        ts_ipc_unlink(D.sock_path, D.ldev, D.lino);
        return 1;
    }
    if (ts_hostinfo_json(D.hostinfo, sizeof D.hostinfo) < 0) {
        fprintf(stderr, "tsppcd: cannot build Hostinfo\n");
        shutdown_all();
        return 1;
    }
    D.want_up = D.st.have_login && !D.st.down;
    if (D.have_key) session_start();   /* test hook: key given */
    logline("started (%s)", D.want_up ? "logged in: connecting"
                            : D.st.have_login ? "logged in: disconnected (down)"
                            : "logged out: waiting for tsppc up");

    while (!got_signal) {
        fd_set r, w;
        struct timeval tv;
        int maxfd = D.sigpipe[0], kfmax = -1;
        unsigned gen;
        int64_t tmo = LOOP_MS;

        if (D.sess) {
            ts_sess_tick(D.sess, (uint64_t)now_ms());
            if (ts_sess_exit_requested(D.sess, &code)) {
                logline("control asked this client to exit (code %d)", code);
                break;
            }
        }
        kf_tick();
        conn_flush();
        ts_dpio_sync(D.sess, D.want_up, D.fed, now_ms());
        check_conditions();
        finish_pings();
        {
            ts_dpio_view dv;
            ts_dpio_get_view(&dv);
            ts_names_sync(D.sess ? ts_sess_netmap(D.sess) : NULL, dv.running, dv.tun_open, D.fed, now_ms());
        }
        D.fed = 0;
        log_state();

        FD_ZERO(&r);
        FD_ZERO(&w);
        FD_SET(D.sigpipe[0], &r);
        if (now_ms() >= D.accept_paused_until) {
            FD_SET(D.lfd, &r);
            if (D.lfd > maxfd) maxfd = D.lfd;
        }
        for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) {
            client *c = &D.cl[i];
            if (c->fd < 0) continue;
            if (c->outlen) FD_SET(c->fd, &w);
            else FD_SET(c->fd, &r);
            if (c->fd > maxfd) maxfd = c->fd;
        }
        if (D.sess) conn_fds(&r, &w, &maxfd);
        if (D.kf_active && KF.fd < FD_SETSIZE && KF.res.fd < FD_SETSIZE &&
            ts_keyfetch_fds(&KF, &r, &w, &kfmax) == 0 && kfmax > maxfd)
            maxfd = kfmax;
        ts_dpio_fds(&r, &w, &maxfd, &tmo);
        gen = D.gen;
        tv.tv_sec = (long)(tmo / 1000);
        tv.tv_usec = (int)(tmo % 1000) * 1000;
        /* Decrypted data already in the TLS engine shows on no descriptor:
         * do not sleep on it. */
        if (D.sess && D.cphase == C_OPEN && D.tls && ts_sess_want_read(D.sess) && ts_tls_pending(D.tls))
            tv.tv_sec = tv.tv_usec = 0;
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
        ts_dpio_events(&r, &w, now_ms());
        finish_pings();
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
