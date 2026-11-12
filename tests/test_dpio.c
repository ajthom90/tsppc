#include "harness.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/control/session.h"
#include "../src/daemon/dataplane_io.h"
#include "../src/data/dataplane.h"

#include "fake_control.inc"

/* The daemon's data-plane I/O with a fake tun device (one end of a socket
 * pair) and fake commands: never the real /dev/tun, ifconfig or route. A
 * session made RUNNING by the fake control server gives the map; its DERP
 * regions point at a local listening socket, so probes connect for real. The
 * clock is fake: each command can be made to take run_cost ms of it. */

#define HA "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HB "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define HD "1111111111111111222222222222222233333333333333334444444444444444"

static fake F;
static ts_sess *S;
static char g_map[2048];
static int64_t g_clock;
static int64_t run_cost;
static int route_fail;            /* route adds still to fail */
static int n_open, n_run;
static int tun_peer = -1;         /* the test's end of the fake tun */
static char cmds[16384];
static char logbuf[16384];
static int g_peer_disco;          /* the peer has a DiscoKey in the map */
static int n_res, res_status, res_region;
static uint64_t res_cookie;

static int64_t fake_clock(void)
{
    return g_clock;
}

static void fake_log(const char *fmt, ...)
{
    size_t n = strlen(logbuf);
    va_list ap;
    va_start(ap, fmt);
    if (n + 2 < sizeof logbuf) vsnprintf(logbuf + n, sizeof logbuf - n - 1, fmt, ap);
    va_end(ap);
    n = strlen(logbuf);
    if (n + 1 < sizeof logbuf) {
        logbuf[n] = '\n';
        logbuf[n + 1] = 0;
    }
}

static int fake_tun_open(char ifname[16])
{
    int sv[2], fl;
    n_open++;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    fl = fcntl(sv[0], F_GETFL);
    fcntl(sv[0], F_SETFL, fl | O_NONBLOCK);
    if (tun_peer >= 0) close(tun_peer);
    tun_peer = sv[1];
    fl = fcntl(sv[1], F_GETFL);
    fcntl(sv[1], F_SETFL, fl | O_NONBLOCK);   /* the test never blocks on it */
    snprintf(ifname, 16, "tun9");
    return sv[0];
}

static int fake_run(const char *const *argv)
{
    size_t n = strlen(cmds);
    int i, is_route_add = 0;
    n_run++;
    g_clock += run_cost;
    for (i = 0; argv[i]; i++) {
        if (n + strlen(argv[i]) + 2 < sizeof cmds) {
            memcpy(cmds + n, argv[i], strlen(argv[i]));
            n += strlen(argv[i]);
            cmds[n++] = argv[i + 1] ? ' ' : '\n';
            cmds[n] = 0;
        }
        if (strcmp(argv[i], "add") == 0 && strcmp(argv[0], "/sbin/route") == 0) is_route_add = 1;
    }
    if (is_route_add && route_fail > 0) {
        route_fail--;
        return 1;
    }
    return 0;
}

static void handler(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) {
        fk_reply(f, r, 200, "{\"MachineAuthorized\":true}");
    } else if (strcmp(r->path, "/machine/map") == 0 && r->body && strstr(r->body, "\"Stream\":false")) {
        fk_reply(f, r, 200, "");
    } else if (strcmp(r->path, "/machine/map") == 0) {
        fk_headers(f, r, 200, NULL, 0, 0);
        fk_map_msg(f, r, g_map);
    }
}

static int listen_local(uint16_t *port)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(fd, 64) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return fd;
}

#define REGION(id, port) \
    "\"" #id "\":{\"RegionID\":" #id ",\"RegionCode\":\"r" #id "\",\"Nodes\":[{\"Name\":\"" #id "a\"," \
    "\"HostName\":\"r" #id ".derp.test\",\"IPv4\":\"127.0.0.1\",\"DERPPort\":%u}]}"

static void make_map(unsigned port)
{
    snprintf(g_map, sizeof g_map,
             "{\"Node\":{\"ID\":1,\"Name\":\"self.example.test.\",\"Key\":\"nodekey:" HA "\","
             "\"Addresses\":[\"100.64.0.1/32\"],\"MachineAuthorized\":true},"
             "\"Peers\":[{\"ID\":2,\"Name\":\"p.example.test.\",\"Key\":\"nodekey:" HB "\",%s"
             "\"Addresses\":[\"100.64.0.2/32\"],\"HomeDERP\":7,\"Online\":true,\"MachineAuthorized\":true}],"
             "\"DERPMap\":{\"Regions\":{" REGION(7, port) "," REGION(8, port) "}}}",
             g_peer_disco ? "\"DiscoKey\":\"discokey:" HD "\"," : "", port, port);
}

/* One loop turn as the daemon's: sync, select (briefly, for real), events. */
static void turn(int fed)
{
    fd_set r, w;
    struct timeval tv;
    int maxfd = -1;
    int64_t tmo = 1000;
    ts_dpio_sync(S, 1, fed, g_clock);
    FD_ZERO(&r);
    FD_ZERO(&w);
    ts_dpio_fds(&r, &w, &maxfd, &tmo);
    tv.tv_sec = 0;
    tv.tv_usec = 20000;
    if (maxfd >= 0) select(maxfd + 1, &r, &w, NULL, &tv);
    else FD_ZERO(&r), FD_ZERO(&w);
    g_clock += 5;   /* a connect to localhost takes about this */
    ts_dpio_events(&r, &w, g_clock);
    fk_pump(&F);
}

static int lfd = -1;

/* A RUNNING session and a fresh data-plane I/O. */
static int begin(void)
{
    uint16_t port = 0;
    S = (ts_sess *)calloc(1, sizeof *S);
    if (!S) return -1;
    lfd = listen_local(&port);
    if (lfd < 0) return -1;
    make_map(port);
    fk_init(&F, S, "{}");
    F.handler = handler;
    fk_start(&F, "{}");
    ts_sess_up(S);
    fk_pump(&F);
    if (ts_sess_get_state(S) != TS_SESS_RUNNING) return -1;
    g_clock = 5000000;
    run_cost = 0;
    route_fail = 0;
    n_open = n_run = 0;
    cmds[0] = logbuf[0] = 0;
    ts_dpio_test_tun_open = fake_tun_open;
    ts_dpio_test_run = fake_run;
    return ts_dpio_init(fake_log, fake_clock);
}

static void end(void)
{
    ts_dpio_shutdown();
    ts_dpio_test_tun_open = NULL;
    ts_dpio_test_run = NULL;
    fk_free(&F);
    free(S);
    S = NULL;
    if (lfd >= 0) close(lfd);
    lfd = -1;
    if (tun_peer >= 0) close(tun_peer);
    tun_peer = -1;
}

static int has(const char *s, const char *sub)
{
    return strstr(s, sub) != NULL;
}

/* The ms of the last "home relay: region N (M ms)" line, or -1. */
static long home_ms(void)
{
    const char *p = logbuf, *q, *last = NULL;
    long ms;
    while ((q = strstr(p, "home relay: region ")) != NULL) {
        last = q;
        p = q + 1;
    }
    if (!last || !(q = strchr(last, '(')) || sscanf(q, "(%ld ms)", &ms) != 1) return -1;
    return ms;
}

static int run_until_home(int turns)
{
    int i;
    ts_dpio_view v;
    for (i = 0; i < turns; i++) {
        turn(0);
        ts_dpio_get_view(&v);
        if (has(logbuf, "home relay: region ")) return 1;
    }
    return 0;
}

/* Probes are timed after the blocking interface and route commands. */
static void test_dpio_probe_clock(void)
{
    long ms;
    if (begin() != 0) {
        t_true("probe clock: setup", 0);
        end();
        return;
    }
    run_cost = 10000;   /* each command blocks 10 s */
    turn(1);
    t_true("probe clock: the tunnel came up (commands ran)", has(logbuf, "tunnel tun9 up") && n_run >= 2);
    run_cost = 0;
    t_true("probe clock: a home was chosen", run_until_home(50));
    ms = home_ms();
    t_true("probe clock: the probe is not timed across the commands", ms >= 0 && ms < 1000);
    end();
}

/* A failed route add tears the tunnel down; it is retried after 30 s. */
static void test_dpio_route_fail(void)
{
    ts_dpio_view v;
    char b[8];
    int64_t t0;
    if (begin() != 0) {
        t_true("route fail: setup", 0);
        end();
        return;
    }
    route_fail = 2;   /* the add and its retry */
    turn(1);
    t0 = g_clock;
    ts_dpio_get_view(&v);
    t_true("route fail: no tunnel", v.running && !v.tun_open);
    t_true("route fail: status says why", has(v.problem, "cannot add the tailnet route"));
    t_true("route fail: the address was removed and the interface taken down",
           has(cmds, "/sbin/ifconfig tun9 inet 100.64.0.1 delete\n") && has(cmds, "/sbin/ifconfig tun9 down\n"));
    t_true("route fail: the device was closed", read(tun_peer, b, sizeof b) == 0);
    while (g_clock < t0 + 29000) {
        g_clock += 1000;
        turn(0);
    }
    t_true("route fail: not reopened before 30 s", n_open == 1);
    g_clock = t0 + 30500;
    turn(0);
    ts_dpio_get_view(&v);
    t_true("route fail: reopened after 30 s", n_open == 2 && v.tun_open && v.problem[0] == 0);
    t_true("route fail: the log says up", has(logbuf, "tunnel tun9 up"));
    end();
}

/* A tun read that returns end of file closes the device instead of
 * spinning, and it is reopened after 30 s. */
static void test_dpio_tun_eof(void)
{
    ts_dpio_view v;
    int i, runs;
    int64_t t0;
    if (begin() != 0) {
        t_true("tun eof: setup", 0);
        end();
        return;
    }
    turn(1);
    ts_dpio_get_view(&v);
    t_true("tun eof: tunnel up", v.tun_open && n_open == 1);
    close(tun_peer);
    tun_peer = -1;
    turn(0);
    t0 = g_clock;
    ts_dpio_get_view(&v);
    t_true("tun eof: device closed", !v.tun_open);
    t_true("tun eof: status says why", has(v.problem, "the tunnel device failed"));
    t_true("tun eof: route and address removed",
           has(cmds, "/sbin/route -n delete -net 100.64.0.0/10\n") && has(cmds, "/sbin/ifconfig tun9 down\n"));
    runs = n_run;
    for (i = 0; i < 20; i++) turn(0);
    t_true("tun eof: nothing more happens meanwhile", n_run == runs && n_open == 1);
    g_clock = t0 + 30500;
    turn(0);
    ts_dpio_get_view(&v);
    t_true("tun eof: reopened after 30 s", n_open == 2 && v.tun_open);
    end();
}

/* A DERP map without the current home region starts a probe round at once. */
static void test_dpio_home_gone(void)
{
    ts_dpio_view v;
    fk_req *r;
    char msg[1024];
    int home, other, i, picked = 0;
    unsigned port = 0;
    if (begin() != 0) {
        t_true("home gone: setup", 0);
        end();
        return;
    }
    turn(1);
    t_true("home gone: a home was chosen", run_until_home(50));
    ts_dpio_get_view(&v);
    home = v.home;
    other = home == 7 ? 8 : 7;
    t_true("home gone: home is 7 or 8", home == 7 || home == 8);
    sscanf(strstr(g_map, "\"DERPPort\":") + 11, "%u", &port);
    if (other == 7)
        snprintf(msg, sizeof msg, "{\"DERPMap\":{\"Regions\":{" REGION(7, port) "}}}", port);
    else
        snprintf(msg, sizeof msg, "{\"DERPMap\":{\"Regions\":{" REGION(8, port) "}}}", port);
    r = NULL;
    {
        int k;   /* the streaming map request */
        for (k = F.nreq - 1; k >= 0 && !r; k--)
            if (strcmp(F.req[k].path, "/machine/map") == 0 && F.req[k].body &&
                strstr(F.req[k].body, "\"Stream\":true") && !F.req[k].closed)
                r = &F.req[k];
    }
    t_true("home gone: the map stream is open", r != NULL);
    if (r) {
        logbuf[0] = 0;
        fk_map_msg(&F, r, msg);
        fk_pump(&F);
        turn(1);
        t_true("home gone: noticed at once", has(logbuf, "is no longer in the map"));
        for (i = 0; i < 50 && !picked; i++) {
            ts_dpio_get_view(&v);
            picked = v.home == other;
            if (!picked) turn(0);
        }
        t_true("home gone: the other region is the new home within seconds", picked);
    }
    end();
}

static int ping_from_cb;           /* the callback tries a ping on STOPPED */
static int ping_from_cb_rc;

static void on_ping(void *user, uint64_t cookie, int status, uint32_t latency_us, int region_id)
{
    (void)latency_us;
    if (user != &n_res) return;
    if (ping_from_cb && status == TS_DP_PING_STOPPED)
        ping_from_cb_rc = ts_dpio_ping(0x64400002u, 5000, 999, g_clock);   /* misuse: must be refused */
    n_res++;
    res_cookie = cookie;
    res_status = status;
    res_region = region_id;
}

/* ts_dpio_ping reaches the data plane with the state's disco key; results
 * come through the registered callback, timeouts seen by ts_dpio_events
 * alone (it ticks the data plane). The relay never answers here. */
static void test_dpio_ping(void)
{
    int i;
    n_res = 0;
    ts_dpio_set_ping_cb(on_ping, &n_res);
    g_peer_disco = 1;
    if (begin() != 0) {
        t_true("dpio ping: setup", 0);
        end();
        g_peer_disco = 0;
        return;
    }
    t_true("dpio ping: not running", ts_dpio_ping(0x64400002u, 1000, 1, g_clock) == TS_DP_PING_DOWN);
    turn(1);
    turn(0);
    t_true("dpio ping: unknown peer", ts_dpio_ping(0x64400003u, 1000, 1, g_clock) == TS_DP_PING_UNKNOWN);
    /* With no ping outstanding, events do not tick the data plane. */
    {
        fd_set r, w;
        unsigned long t0 = ts_dpio_test_event_ticks;
        FD_ZERO(&r);
        FD_ZERO(&w);
        for (i = 0; i < 5; i++) {
            g_clock += 10;
            ts_dpio_events(&r, &w, g_clock);
        }
        t_true("dpio ping: no extra tick with no ping outstanding", ts_dpio_test_event_ticks == t0);
    }
    t_true("dpio ping: sent", ts_dpio_ping(0x64400002u, 300, 77, g_clock) == 0);
    for (i = 0; i < 100 && n_res == 0; i++) {
        fd_set r, w;
        FD_ZERO(&r);
        FD_ZERO(&w);
        g_clock += 10;
        ts_dpio_events(&r, &w, g_clock);
    }
    t_true("dpio ping: events tick while a ping is outstanding", ts_dpio_test_event_ticks > 0);
    t_true("dpio ping: timeout through the callback, from events alone",
           n_res == 1 && res_cookie == 77 && res_status == TS_DP_PING_TIMEOUT && res_region == 7 && i >= 29 && i <= 31);
    /* The loop's sleep ends at the earliest ping deadline. */
    {
        fd_set r, w;
        int maxfd = -1;
        int64_t tmo = 1000;
        FD_ZERO(&r);
        FD_ZERO(&w);
        ts_dpio_fds(&r, &w, &maxfd, &tmo);
        t_true("dpio ping: no ping, the tick bounds the sleep", tmo == TS_DPIO_TICK_MS);
        t_true("dpio ping: a 120 ms ping", ts_dpio_ping(0x64400002u, 120, 80, g_clock) == 0);
        t_true("dpio ping: a 100 ms ping", ts_dpio_ping(0x64400002u, 100, 81, g_clock) == 0);
        tmo = 1000;
        ts_dpio_fds(&r, &w, &maxfd, &tmo);
        t_true("dpio ping: the sleep ends at the earliest deadline", tmo == 100);
        g_clock += 40;
        tmo = 1000;
        ts_dpio_fds(&r, &w, &maxfd, &tmo);
        t_true("dpio ping: the time left to it", tmo == 60);
        g_clock += 100;
        tmo = 1000;
        ts_dpio_fds(&r, &w, &maxfd, &tmo);
        t_true("dpio ping: a passed deadline means no sleep", tmo == 0);
        FD_ZERO(&r);
        FD_ZERO(&w);
        n_res = 0;
        ts_dpio_events(&r, &w, g_clock);
        t_true("dpio ping: both time out at once", n_res == 2 && res_status == TS_DP_PING_TIMEOUT);
        tmo = 1000;
        ts_dpio_fds(&r, &w, &maxfd, &tmo);
        t_true("dpio ping: none left, the tick again", tmo == TS_DPIO_TICK_MS);
        n_res = 1;
    }
    /* A cancelled ping is never reported and frees its place. */
    {
        int busy = 0;
        for (i = 0; i < TS_DP_MAX_PINGS + 1; i++) {
            if (ts_dpio_ping(0x64400002u, 5000, 1000 + (uint64_t)i, g_clock) != 0) busy++;
            ts_dpio_ping_cancel(1000 + (uint64_t)i);
        }
        t_true("dpio ping: cancelled pings free their places", busy == 0);
        t_true("dpio ping: cancelling an unknown cookie is harmless", (ts_dpio_ping_cancel(424242), 1));
        g_clock += 6000;
        turn(0);
        t_true("dpio ping: cancelled pings are never reported", n_res == 1);
    }
    t_true("dpio ping: sent again", ts_dpio_ping(0x64400002u, 5000, 78, g_clock) == 0);
    ping_from_cb = 1;
    ping_from_cb_rc = 12345;
    end();
    ping_from_cb = 0;
    t_true("dpio ping: shutdown ends it", n_res == 2 && res_cookie == 78 && res_status == TS_DP_PING_STOPPED);
    t_true("dpio ping: a ping from the STOPPED callback is refused", ping_from_cb_rc == TS_DP_PING_DOWN);
    t_true("dpio ping: after shutdown", ts_dpio_ping(0x64400002u, 1000, 1, g_clock) == TS_DP_PING_DOWN);
    ts_dpio_set_ping_cb(NULL, NULL);
    g_peer_disco = 0;

    /* No DiscoKey for the peer. */
    if (begin() != 0) {
        t_true("dpio ping: setup 2", 0);
        end();
        return;
    }
    turn(1);
    turn(0);
    t_true("dpio ping: no disco key", ts_dpio_ping(0x64400002u, 1000, 1, g_clock) == TS_DP_PING_NO_DISCO);
    end();
}

void test_dpio(void)
{
    test_dpio_probe_clock();
    test_dpio_route_fail();
    test_dpio_tun_eof();
    test_dpio_home_gone();
    test_dpio_ping();
}
