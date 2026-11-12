/* The daemon's data-plane I/O. See dataplane_io.h. */
#include "dataplane_io.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "src/core/bytes.h"
#include "src/crypto/random.h"
#include "src/crypto/x25519.h"
#include "src/data/dataplane.h"
#include "src/derp/derp.h"
#include "src/net/sock.h"
#include "src/net/tls.h"
#include "src/platform/tun.h"

#define OUT_MAX (4 * (5 + 32 + TS_DERP_MAX_PACKET))   /* bytes queued for one relay */
#define READ_CHUNK 16384

enum { R_NONE, R_TCP, R_TLS, R_UP };

typedef struct {
    int phase;
    int fd;
    ts_tls *tls;
    int64_t deadline;          /* TCP and TLS must be done by then */
    unsigned gen;              /* changes whenever the slot is closed or dialed */
    unsigned sel_gen;          /* gen when the descriptors were collected */
    int region;                /* 0 if the node is not in the map we have */
    char host[254];
    uint8_t *out;
    size_t outlen, outcap;
    const char *fail;          /* a failure found inside a callback, reported later */
} rslot;

typedef struct {
    int fd;                    /* -1: free */
    size_t idx;                /* into the probe round's regions */
    int64_t t0;
} probe;

static struct {
    ts_dpio_log_fn log;
    ts_dp *dp;
    int no_tun, plain;
    int64_t now;

    /* The running data plane and what it was started with. */
    int running;
    uint32_t self_ip;
    uint8_t node_priv[32];
    int last_state;
    int up_logged;             /* the home region last logged connected, 0 none */
    int home;                  /* the home chosen by the last probe round (kept across restarts) */
    int cur;                   /* the home the data plane has now (ts_dp_set_home), 0 none */
    int stopping;
    int home_fails;            /* home connection failures with the home never up in between */
    int64_t start_retry_at;

    /* The tun device. */
    int tun_fd;
    char ifname[16];
    int tun_err;               /* errno of the last failed open, 0 if none */
    char tun_problem[128];
    int64_t tun_retry_at;
    unsigned long tun_dropped;

    rslot s[TS_DP_MAX_CONNS];

    /* Home probes. */
    int probe_want;
    int probing;
    int probe_done;
    uint32_t probe_gen;        /* derp_gen of the map the round measured */
    int64_t next_probe_at;
    ts_derp_region *pr;        /* the round's copy of the regions */
    size_t pn, pnext;
    int plat[TS_DERP_MAX_REGIONS];
    probe pa[TS_DPIO_PROBES_AT_ONCE];
} G;

static uint8_t rbuf[READ_CHUNK];
static uint8_t tbuf[TS_DPIO_TUN_BUF];

/* ---- Relay slots ---------------------------------------------------------- */

static void fmt_ip(char *out, size_t cap, uint32_t a)
{
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)(a >> 24), (unsigned)(a >> 16 & 255), (unsigned)(a >> 8 & 255),
             (unsigned)(a & 255));
}

static void slot_close(rslot *s)
{
    if (s->tls) {
        ts_tls_wipe(s->tls);
        free(s->tls);
        s->tls = NULL;
    }
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    if (s->out) {
        ts_wipe(s->out, s->outlen);
        free(s->out);
    }
    s->out = NULL;
    s->outlen = s->outcap = 0;
    s->phase = R_NONE;
    s->fail = NULL;
    s->region = 0;
    s->gen++;
}

/* A home connection failed (never counted while stopping). */
static void note_home_fail(int region)
{
    if (G.running && !G.stopping && region > 0 && region == G.cur) G.home_fails++;
}

/* The region holding this node in the netmap the data plane was last given.
 * Its DERP map is a copy of the netmap's, so the same node is there. */
static const ts_netmap *g_nm;

static int region_of(const ts_derp_node *node)
{
    size_t i, j;
    if (!g_nm) return 0;
    for (i = 0; i < g_nm->nregions; i++)
        for (j = 0; j < g_nm->regions[i].nnodes; j++) {
            const ts_derp_node *n = &g_nm->regions[i].nodes[j];
            if (n->ipv4 == node->ipv4 && n->port == node->port && strcmp(n->host, node->host) == 0)
                return g_nm->regions[i].id;
        }
    return 0;
}

static int io_dial(void *user, int i, const ts_derp_node *node)
{
    rslot *s = &G.s[i];
    char ip[16];
    (void)user;
    slot_close(s);
    s->region = region_of(node);
    fmt_ip(ip, sizeof ip, node->ipv4);
    s->fd = ts_tcp_start(ip, node->port ? node->port : 443);
    if (s->fd < 0 || s->fd >= FD_SETSIZE) {
        int region = s->region;
        slot_close(s);
        note_home_fail(region);
        G.log("relay region %d: cannot connect", region);
        return -1;
    }
    snprintf(s->host, sizeof s->host, "%s", node->host);
    s->phase = R_TCP;
    s->deadline = G.now + TS_DPIO_CONNECT_TIMEOUT_MS;
    return 0;
}

static void io_conn_send(void *user, int i, const uint8_t *p, size_t n)
{
    rslot *s = &G.s[i];
    (void)user;
    if (s->phase != R_UP || s->fail) return;
    if (n > OUT_MAX - s->outlen) {
        s->fail = "the relay is not reading";   /* a whole frame or nothing */
        return;
    }
    if (s->outlen + n > s->outcap) {
        size_t nc = s->outcap ? s->outcap : 8192;
        uint8_t *nb;
        while (nc < s->outlen + n) nc *= 2;
        if (nc > OUT_MAX) nc = OUT_MAX;
        nb = (uint8_t *)malloc(nc);
        if (!nb) {
            s->fail = "out of memory";
            return;
        }
        if (s->outlen) memcpy(nb, s->out, s->outlen);
        if (s->out) {
            ts_wipe(s->out, s->outlen);
            free(s->out);
        }
        s->out = nb;
        s->outcap = nc;
    }
    memcpy(s->out + s->outlen, p, n);
    s->outlen += n;
}

/* The data plane ends a stream: a failure it found (a DERP error or
 * timeout), an idle connection, or a stop. */
static void io_conn_close(void *user, int i)
{
    int region = G.s[i].region;
    (void)user;
    slot_close(&G.s[i]);
    note_home_fail(region);
}

static void io_tun_write(void *user, const uint8_t *ip, size_t n)
{
    (void)user;
    if (G.tun_fd < 0 || write(G.tun_fd, ip, n) != (ssize_t)n) G.tun_dropped++;
}

static int io_random(void *user, uint8_t *out, size_t n)
{
    (void)user;
    return ts_random_bytes(out, n);
}

static int64_t io_wall(void *user, uint32_t *nsec)
{
    struct timeval tv;
    (void)user;
    gettimeofday(&tv, NULL);
    if (nsec) *nsec = (uint32_t)tv.tv_usec * 1000u;
    return (int64_t)tv.tv_sec;
}

static const ts_dp_io DP_IO = { io_dial, io_conn_send, io_conn_close, io_tun_write, io_random, io_wall };

/* The connection failed (outside any data plane call): close it, then tell
 * the data plane. */
static void slot_fail(int i, const char *why)
{
    rslot *s = &G.s[i];
    int region = s->region;
    slot_close(s);
    note_home_fail(region);
    G.log("relay region %d: %s", region, why);
    ts_dp_conn_down(G.dp, i, why);
}

static void slot_flush(int i)
{
    rslot *s = &G.s[i];
    unsigned g = s->gen;
    while (s->gen == g && s->phase == R_UP && s->outlen > 0) {
        ssize_t n;
        if (s->tls) {
            int k = ts_tls_write(s->tls, s->out, s->outlen);
            if (k < 0) {
                slot_fail(i, ts_tls_error(s->tls));
                return;
            }
            n = k;
        } else {
            n = write(s->fd, s->out, s->outlen);
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) return;
                slot_fail(i, "sending to the relay failed");
                return;
            }
        }
        if (n == 0) return;
        memmove(s->out, s->out + n, s->outlen - (size_t)n);
        s->outlen -= (size_t)n;
    }
}

static void slot_read(int i)
{
    rslot *s = &G.s[i];
    unsigned g = s->gen;
    int k;
    for (k = 0; k < TS_DPIO_READS && s->gen == g && s->phase == R_UP && !s->fail; k++) {
        ssize_t n;
        if (s->tls) {
            int r = ts_tls_read(s->tls, rbuf, sizeof rbuf);
            if (r == 0) return;
            if (r == TS_TLS_CLOSED) {
                slot_fail(i, "the relay closed the connection");
                return;
            }
            if (r < 0) {
                slot_fail(i, ts_tls_error(s->tls));
                return;
            }
            n = r;
        } else {
            n = read(s->fd, rbuf, sizeof rbuf);
            if (n == 0) {
                slot_fail(i, "the relay closed the connection");
                return;
            }
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) return;
                slot_fail(i, "reading from the relay failed");
                return;
            }
        }
        ts_dp_conn_recv(G.dp, i, rbuf, (size_t)n);
    }
}

static void slot_up(int i)
{
    rslot *s = &G.s[i];
    unsigned g = s->gen;
    s->phase = R_UP;
    ts_dp_conn_up(G.dp, i);   /* queues the upgrade request */
    if (s->gen != g) return;
    slot_flush(i);
    if (s->gen == g) slot_read(i);   /* data may already sit in the TLS engine */
}

static void slot_events(int i, fd_set *r, fd_set *w)
{
    rslot *s = &G.s[i];
    unsigned g = s->gen;
    int rc;
    if (s->gen != s->sel_gen || s->phase == R_NONE) return;
    if (s->fail) {
        slot_fail(i, s->fail);
        return;
    }
    if ((s->phase == R_TCP || s->phase == R_TLS) && G.now > s->deadline) {
        slot_fail(i, "timed out connecting to the relay");
        return;
    }
    switch (s->phase) {
    case R_TCP:
        if (!FD_ISSET(s->fd, w)) return;
        if (ts_tcp_finish(s->fd) != 0) {
            slot_fail(i, "cannot connect to the relay");
            return;
        }
        if (G.plain) {
            slot_up(i);
            return;
        }
        s->tls = (ts_tls *)calloc(1, sizeof *s->tls);
        if (!s->tls || ts_tls_start(s->tls, s->fd, s->host) != 0) {
            slot_fail(i, "cannot start TLS to the relay");
            return;
        }
        s->phase = R_TLS;
        /* fall through: send the ClientHello now */
    case R_TLS:
        rc = ts_tls_step(s->tls);
        if (rc < 0) {
            slot_fail(i, ts_tls_error(s->tls));
            return;
        }
        if (rc == 0) slot_up(i);
        return;
    case R_UP:
        if (s->tls || FD_ISSET(s->fd, r)) slot_read(i);
        if (s->gen != g || s->fail) return;
        slot_flush(i);
        if (s->gen == g && s->tls && FD_ISSET(s->fd, w) && ts_tls_step(s->tls) < 0) slot_fail(i, ts_tls_error(s->tls));
        return;
    default:
        return;
    }
}

/* ---- The tun device ------------------------------------------------------- */

static int run_cmd(const char *const *argv, const char *what)
{
    int rc = ts_run(argv);
    if (rc != 0) G.log("%s failed (status %d)", what, rc);
    return rc;
}

static void route_delete(int quiet)
{
    const char *argv[8];
    char buf[128];
    if (ts_tun_cmd_route_delete(argv, 8, buf, sizeof buf) < 0) return;
    if (quiet) (void)ts_run(argv);
    else (void)run_cmd(argv, "deleting the tailnet route");
}

static void tun_close(void)
{
    const char *argv[16];
    char buf[256];
    if (G.tun_fd < 0) return;
    route_delete(0);
    if (ts_tun_cmd_ifconfig_down(argv, 16, buf, sizeof buf, G.ifname, G.self_ip) > 0) {
        (void)run_cmd(argv, "removing the tunnel address");
        (void)run_cmd(argv + 6, "taking the tunnel interface down");
    }
    close(G.tun_fd);
    G.tun_fd = -1;
}

static void tun_problem(const char *p)
{
    if (strcmp(p, G.tun_problem) != 0 && p[0]) G.log("tunnel: %s", p);
    snprintf(G.tun_problem, sizeof G.tun_problem, "%s", p);
}

/* Open the tun device and give it our address and the tailnet route. */
static void tun_open(void)
{
    const char *argv[16];
    char buf[256];
    int fd;
    if (G.no_tun || G.tun_fd >= 0) return;
    G.tun_retry_at = G.now + TS_DPIO_TUN_RETRY_MS;
    fd = ts_tun_open(G.ifname);
    if (fd < 0) {
        G.tun_err = errno;
        if (errno == ENOENT) tun_problem("tunnel driver not loaded");
        else if (errno == EBUSY) tun_problem("every tunnel device is in use");
        else tun_problem("cannot open the tunnel device");
        return;
    }
    if (fd >= FD_SETSIZE) {
        close(fd);
        tun_problem("out of descriptors for the tunnel device");
        return;
    }
    G.tun_fd = fd;
    if (ts_tun_cmd_ifconfig_up(argv, 16, buf, sizeof buf, G.ifname, G.self_ip) < 0 ||
        run_cmd(argv, "configuring the tunnel interface") != 0) {
        close(G.tun_fd);
        G.tun_fd = -1;
        tun_problem("cannot configure the tunnel interface");
        return;
    }
    if (ts_tun_cmd_route_add(argv, 16, buf, sizeof buf, G.ifname) < 0 || ts_run(argv) != 0) {
        route_delete(1);   /* a stale route from another interface */
        if (run_cmd(argv, "adding the tailnet route") != 0) {
            tun_problem("cannot add the tailnet route");
            return;   /* kept open: retried on the next start */
        }
    }
    G.tun_err = 0;
    tun_problem("");
    G.log("tunnel %s up", G.ifname);
}

static void tun_events(fd_set *r)
{
    int k;
    if (G.tun_fd < 0 || !FD_ISSET(G.tun_fd, r)) return;
    for (k = 0; k < TS_DPIO_TUN_READS && G.running && G.tun_fd >= 0; k++) {
        ssize_t n = read(G.tun_fd, tbuf, sizeof tbuf);
        if (n <= 0) return;   /* EAGAIN: nothing more */
        ts_dp_from_tun(G.dp, tbuf, (size_t)n);
    }
}

/* ---- Home probes ---------------------------------------------------------- */

static void probes_cancel(void)
{
    int k;
    for (k = 0; k < TS_DPIO_PROBES_AT_ONCE; k++) {
        if (G.pa[k].fd >= 0) close(G.pa[k].fd);
        G.pa[k].fd = -1;
    }
    G.probing = 0;
    G.probe_done = 0;
}

static int probe_eligible(const ts_derp_region *r)
{
    return r->nnodes > 0 && !r->avoid && !r->no_home;
}

/* Start probes until TS_DPIO_PROBES_AT_ONCE run or none is left. */
static void probes_fill(void)
{
    int k, active = 0;
    for (k = 0; k < TS_DPIO_PROBES_AT_ONCE; k++) {
        while (G.pa[k].fd < 0 && G.pnext < G.pn) {
            const ts_derp_region *r = &G.pr[G.pnext];
            char ip[16];
            int fd;
            size_t idx = G.pnext++;
            if (!probe_eligible(r)) continue;
            fmt_ip(ip, sizeof ip, r->nodes[0].ipv4);
            fd = ts_tcp_start(ip, r->nodes[0].port ? r->nodes[0].port : 443);
            if (fd < 0) continue;
            if (fd >= FD_SETSIZE) {
                close(fd);
                continue;
            }
            G.pa[k].fd = fd;
            G.pa[k].idx = idx;
            G.pa[k].t0 = G.now;
        }
        if (G.pa[k].fd >= 0) active++;
    }
    if (!active && G.pnext >= G.pn) {
        G.probing = 0;
        G.probe_done = 1;
    }
}

static void probes_start(const ts_netmap *nm)
{
    size_t i;
    probes_cancel();
    if (nm->nregions == 0) return;   /* wait for a DERP map */
    G.pn = nm->nregions < TS_DERP_MAX_REGIONS ? nm->nregions : TS_DERP_MAX_REGIONS;
    memcpy(G.pr, nm->regions, G.pn * sizeof *G.pr);
    for (i = 0; i < G.pn; i++) G.plat[i] = -1;
    G.pnext = 0;
    G.probe_gen = nm->derp_gen;
    G.probing = 1;
    G.probe_want = 0;
    G.next_probe_at = G.now + TS_DPIO_REPROBE_MS;
    probes_fill();
}

static void probe_events(fd_set *w)
{
    int k;
    if (!G.probing) return;
    for (k = 0; k < TS_DPIO_PROBES_AT_ONCE; k++) {
        probe *p = &G.pa[k];
        if (p->fd < 0) continue;
        if (FD_ISSET(p->fd, w)) {
            if (ts_tcp_finish(p->fd) == 0) G.plat[p->idx] = (int)(G.now - p->t0);
        } else if (G.now - p->t0 < TS_DPIO_PROBE_TIMEOUT_MS) {
            continue;
        }
        close(p->fd);
        p->fd = -1;
    }
    probes_fill();
}

/* A finished round: choose the home and tell the data plane and control. */
static void probes_apply(ts_sess *sess, const ts_netmap *nm)
{
    uint8_t rb[4];
    uint32_t r32 = 0;
    int cur = G.cur, pick;
    size_t i;
    G.probe_done = 0;
    if (nm->derp_gen != G.probe_gen) {   /* the map changed meanwhile: measure again */
        G.probe_want = 1;
        return;
    }
    if (ts_random_bytes(rb, 4) == 0) r32 = ts_get_be32(rb);
    pick = ts_dp_pick_home(G.pr, G.pn, G.plat, cur > 0 ? cur : G.home, r32);
    if (pick != cur) {
        int ms = -1;
        for (i = 0; i < G.pn; i++)
            if (G.pr[i].id == pick) ms = G.plat[i];
        if (ms >= 0) G.log("home relay: region %d (%d ms)", pick, ms);
        else G.log("home relay: region %d (no measurement)", pick);
        ts_dp_set_home(G.dp, pick);
        G.cur = pick;
    }
    G.home = pick;
    G.home_fails = 0;
    (void)ts_sess_set_preferred_derp(sess, pick);
}

/* ---- Lifecycle ------------------------------------------------------------ */

static void dp_stop(const char *why)
{
    int i;
    if (!G.running) return;
    G.stopping = 1;
    ts_dp_stop(G.dp);
    G.stopping = 0;
    G.cur = 0;
    for (i = 0; i < TS_DP_MAX_CONNS; i++) slot_close(&G.s[i]);
    probes_cancel();
    tun_close();
    ts_wipe(G.node_priv, sizeof G.node_priv);
    G.running = 0;
    G.self_ip = 0;
    G.up_logged = 0;
    G.home_fails = 0;
    G.tun_problem[0] = 0;
    g_nm = NULL;
    G.log("data plane stopped (%s)", why);
}

static void dp_start(const ts_netmap *nm, const ts_state *st)
{
    uint8_t disco_pub[32];
    if (G.now < G.start_retry_at) return;
    ts_x25519_public(disco_pub, st->disco_priv);
    ts_dp_tick(G.dp, G.now);
    if (ts_dp_start(G.dp, st->node_priv, disco_pub, nm->self.ipv4) != 0) {
        G.log("cannot start the data plane: out of memory");
        G.start_retry_at = G.now + TS_DPIO_TUN_RETRY_MS;
        return;
    }
    ts_dp_tick(G.dp, G.now);
    memcpy(G.node_priv, st->node_priv, 32);
    G.self_ip = nm->self.ipv4;
    G.running = 1;
    g_nm = nm;
    G.log("data plane started");
    ts_dp_set_netmap(G.dp, nm);
    G.cur = 0;
    if (G.home > 0) {   /* the last choice, until probes say otherwise */
        ts_dp_set_home(G.dp, G.home);
        G.cur = G.home;
    }
    G.probe_want = 1;
    G.home_fails = 0;
    tun_open();
}

void ts_dpio_sync(ts_sess *sess, int want_up, int map_changed, int64_t now_ms)
{
    ts_sess_state state;
    const ts_netmap *nm;
    const ts_state *st;
    ts_dp_status ds;

    G.now = now_ms;
    if (!sess || !G.dp) return;
    state = ts_sess_get_state(sess);
    nm = ts_sess_netmap(sess);
    st = ts_sess_node_state(sess);
    if ((int)state != G.last_state) {
        map_changed = 1;
        G.last_state = (int)state;
    }
    if (G.running) {
        if (!want_up || (state != TS_SESS_RUNNING && state != TS_SESS_CONNECTING && state != TS_SESS_BACKOFF))
            dp_stop(want_up ? ts_sess_state_name(state) : "down");
        else if (memcmp(st->node_priv, G.node_priv, 32) != 0)
            dp_stop("node key changed");
        else if (state == TS_SESS_RUNNING && (!nm->have_self || !nm->self.have_ipv4 || nm->self.ipv4 != G.self_ip))
            dp_stop("address changed");
    }
    if (!G.running && want_up && state == TS_SESS_RUNNING && nm->have_self && nm->self.have_ipv4 &&
        nm->self.ipv4 != 0) {
        dp_start(nm, st);
        map_changed = 0;   /* just given */
    }
    if (!G.running) return;

    ts_dp_tick(G.dp, now_ms);
    if (map_changed && state == TS_SESS_RUNNING) {
        g_nm = nm;
        ts_dp_set_netmap(G.dp, nm);
    }
    if (!G.no_tun && G.tun_fd < 0 && now_ms >= G.tun_retry_at) tun_open();

    /* Home probes. */
    if (now_ms >= G.next_probe_at) G.probe_want = 1;
    if (G.home_fails >= TS_DPIO_HOME_FAILS) {
        G.log("home relay failed %d times: measuring the regions again", G.home_fails);
        G.home_fails = 0;
        G.probe_want = 1;
    }
    if (G.probing) probes_fill();   /* timeouts are seen in probe_events */
    if (G.probe_done) probes_apply(sess, nm);
    if (G.probe_want && !G.probing && state == TS_SESS_RUNNING) probes_start(nm);

    ts_dp_get_status(G.dp, &ds);
    if (ds.home_up) G.home_fails = 0;
    if (ds.home_up && ds.home != G.up_logged) G.log("relay region %d connected (home)", ds.home);
    G.up_logged = ds.home_up ? ds.home : 0;
}

void ts_dpio_fds(fd_set *r, fd_set *w, int *maxfd, int64_t *timeout_ms)
{
    int i, k;
    if (!G.running) return;
    if (*timeout_ms > TS_DPIO_TICK_MS) *timeout_ms = TS_DPIO_TICK_MS;
    for (i = 0; i < TS_DP_MAX_CONNS; i++) {
        rslot *s = &G.s[i];
        int rd = 0, wr = 0;
        if (s->phase == R_UP) slot_flush(i);
        s->sel_gen = s->gen;
        if (s->fail) {
            *timeout_ms = 0;
            continue;
        }
        switch (s->phase) {
        case R_TCP:
            wr = 1;
            break;
        case R_TLS:
        case R_UP:
            if (s->tls) {
                int want = ts_tls_want(s->tls);
                rd = (want & TS_TLS_WANT_READ) != 0;
                wr = (want & TS_TLS_WANT_WRITE) != 0;
                if (s->phase == R_UP && ts_tls_pending(s->tls)) *timeout_ms = 0;
            } else {
                rd = 1;
                wr = s->outlen > 0;
            }
            break;
        default:
            continue;
        }
        if (s->fd < 0) continue;
        if (rd) FD_SET(s->fd, r);
        if (wr) FD_SET(s->fd, w);
        if ((rd || wr) && s->fd > *maxfd) *maxfd = s->fd;
    }
    if (G.tun_fd >= 0) {
        FD_SET(G.tun_fd, r);
        if (G.tun_fd > *maxfd) *maxfd = G.tun_fd;
    }
    for (k = 0; G.probing && k < TS_DPIO_PROBES_AT_ONCE; k++) {
        if (G.pa[k].fd < 0) continue;
        FD_SET(G.pa[k].fd, w);
        if (G.pa[k].fd > *maxfd) *maxfd = G.pa[k].fd;
    }
}

void ts_dpio_events(fd_set *r, fd_set *w, int64_t now_ms)
{
    int i;
    G.now = now_ms;
    if (!G.running) return;
    for (i = 0; i < TS_DP_MAX_CONNS && G.running; i++) slot_events(i, r, w);
    if (G.running) tun_events(r);
    if (G.running) probe_events(w);
}

int ts_dpio_init(ts_dpio_log_fn logf)
{
    int i;
    memset(&G, 0, sizeof G);
    G.log = logf;
    G.tun_fd = -1;
    G.last_state = -1;
    for (i = 0; i < TS_DP_MAX_CONNS; i++) G.s[i].fd = -1;
    for (i = 0; i < TS_DPIO_PROBES_AT_ONCE; i++) G.pa[i].fd = -1;
#ifdef TS_TEST_HOOKS
    {
        const char *e = getenv("TSPPC_NO_TUN");
        G.no_tun = e && strcmp(e, "1") == 0;
        e = getenv("TSPPC_DERP_PLAIN");
        G.plain = e && strcmp(e, "1") == 0;
    }
#endif
    G.pr = (ts_derp_region *)calloc(TS_DERP_MAX_REGIONS, sizeof *G.pr);
    G.dp = ts_dp_new(&DP_IO, NULL);
    if (!G.pr || !G.dp) {
        free(G.pr);
        G.pr = NULL;
        if (G.dp) ts_dp_free(G.dp);
        G.dp = NULL;
        return -1;
    }
    return 0;
}

void ts_dpio_cleanup_route(void)
{
    if (!G.no_tun) route_delete(1);
}

void ts_dpio_shutdown(void)
{
    if (!G.dp) return;
    dp_stop("shutting down");
    ts_dp_free(G.dp);
    G.dp = NULL;
    free(G.pr);
    G.pr = NULL;
}

void ts_dpio_get_view(ts_dpio_view *v)
{
    ts_dp_status ds;
    memset(v, 0, sizeof *v);
    v->tun_dropped = G.tun_dropped;
    if (!G.running) return;
    ts_dp_get_status(G.dp, &ds);
    v->running = 1;
    v->home = ds.home;
    v->home_up = ds.home_up;
    v->home_down = ds.home > 0 && !ds.home_up && strncmp(ds.problem, "home relay", 10) == 0;
    snprintf(v->filter, sizeof v->filter, "%s", ds.filter);
    v->tun_open = G.tun_fd >= 0;
    snprintf(v->ifname, sizeof v->ifname, "%s", v->tun_open ? G.ifname : "");
    snprintf(v->problem, sizeof v->problem, "%s%s%s", G.tun_problem, G.tun_problem[0] && ds.problem[0] ? "; " : "",
             ds.problem);
}

int ts_dpio_peer_status(uint32_t ipv4, ts_wg_stats *st, int *region)
{
    if (!G.running || !G.dp) return -1;
    return ts_dp_peer_status(G.dp, ipv4, st, region);
}
