#ifndef TS_DAEMON_DATAPLANE_IO_H
#define TS_DAEMON_DATAPLANE_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>

#include "src/control/session.h"
#include "src/wg/device.h"

/* The daemon's data-plane I/O: the tun device and its address and route, the
 * relay connections' TCP and TLS, the home relay probes, and when the data
 * plane (src/data/dataplane.h) runs. Single-threaded, driven from the
 * daemon's select loop; never calls the session or the data plane from inside
 * their callbacks.
 *
 * Lifecycle (ts_dpio_sync after the session's calls each loop turn):
 * - Runs (tun open, address set, route added, ts_dp_start) once the session
 *   is RUNNING, the self node has an IPv4 address and the node is wanted up.
 * - Keeps running through CONNECTING and BACKOFF (the map is only read while
 *   RUNNING: a reconnect empties it until the new map arrives).
 * - Stops (ts_dp_stop, route delete, address delete, interface down, tun
 *   closed) on IDLE, NEED_LOGIN, AWAIT_APPROVAL, FAILED, not wanted up, or a
 *   node key, disco key or self address change (then starts again);
 *   ts_dpio_shutdown on SIGTERM and SIGINT.
 * - If no /dev/tunN opens, relays and home selection still run, packets for
 *   the tun device are dropped (counted), status shows "tunnel driver not
 *   loaded", and opening is retried every TS_DPIO_TUN_RETRY_MS. The same
 *   happens when the address or the tailnet route cannot be set (the device
 *   is then taken down and closed first: no half-configured tunnel is left)
 *   and when a read from the device fails or returns end of file.
 * - The interface and route commands block (up to 10 s each): the clock is
 *   read again after them, and a home probe round they interrupted starts
 *   over, so no probe is timed across them. Other blocking commands (the
 *   names cache flush, names_io.c) say so with ts_dpio_note_blocked and are
 *   covered the same way.
 * - A new DERP map without the current home region (or with no usable node
 *   in it) starts a probe round at once.
 *
 * Relays: each slot is a non-blocking TCP connect to the node's IPv4 and port,
 * then TLS with the node's name (unless TSPPC_DERP_PLAIN in test builds);
 * TS_DPIO_CONNECT_TIMEOUT_MS for both. Home probes: a TCP connect to the
 * first node of each eligible region (not Avoid, not NoMeasureNoHome),
 * TS_DPIO_PROBES_AT_ONCE at once, TS_DPIO_PROBE_TIMEOUT_MS each; when the
 * data plane starts, every TS_DPIO_REPROBE_MS, and after
 * TS_DPIO_HOME_FAILS home connection failures with the home never up in
 * between. The result goes through ts_dp_pick_home to ts_dp_set_home and
 * ts_sess_set_preferred_derp.
 *
 * Test builds (-DTS_TEST_HOOKS): TSPPC_NO_TUN=1 opens no tun and runs no
 * command (tun writes are only counted); TSPPC_DERP_PLAIN=1 skips TLS on
 * relay connections. */

#define TS_DPIO_CONNECT_TIMEOUT_MS 60000
#define TS_DPIO_PROBE_TIMEOUT_MS 5000
#define TS_DPIO_PROBES_AT_ONCE 8
#define TS_DPIO_REPROBE_MS (30 * 60 * 1000)
#define TS_DPIO_HOME_FAILS 3
#define TS_DPIO_TUN_RETRY_MS 30000
#define TS_DPIO_TICK_MS 250            /* the data plane's tick, the loop's longest sleep while it runs */
#define TS_DPIO_TUN_BUF 2048
#define TS_DPIO_TUN_READS 64           /* packets read from tun per loop turn */
#define TS_DPIO_READS 16               /* reads per relay connection per loop turn */

typedef void (*ts_dpio_log_fn)(const char *fmt, ...);
typedef int64_t (*ts_dpio_clock_fn)(void);   /* monotonic ms, as the now_ms arguments */

/* Set up (no I/O). 0, or -1 if out of memory. */
int ts_dpio_init(ts_dpio_log_fn logf, ts_dpio_clock_fn clock);
/* A command outside this file blocked the loop (up to TS_RUN_LIMIT_MS):
 * read the clock again and start over a home probe round in flight, at the
 * next sync or events call. */
void ts_dpio_note_blocked(void);
/* At start: delete a route left by a crash, quietly. */
void ts_dpio_cleanup_route(void);
/* After the session's calls each loop turn: start, stop or restart the data
 * plane, hand it the map when map_changed (bytes reached the session) or the
 * session state changed, and act on finished probes. sess may be NULL. */
void ts_dpio_sync(ts_sess *sess, int want_up, int map_changed, int64_t now_ms);
/* Descriptors to wait on; *timeout_ms is lowered to what the data plane
 * needs (TS_DPIO_TICK_MS while running, 0 with decrypted data waiting). */
void ts_dpio_fds(fd_set *r, fd_set *w, int *maxfd, int64_t *timeout_ms);
/* After select. */
void ts_dpio_events(fd_set *r, fd_set *w, int64_t now_ms);
/* Stop everything (signals, exit) and free. */
void ts_dpio_shutdown(void);

/* For status. */
typedef struct {
    int running;
    int home;                 /* region, 0 none */
    int home_up;              /* the home relay is connected and verified */
    int home_down;            /* not up, and the data plane says why (no usable relay, a failed connection) */
    char filter[16];          /* "none", "ok", "too large" or "invalid" */
    unsigned long filtered;   /* inbound packets the filter dropped */
    int tun_open;
    char ifname[16];
    char problem[256];        /* "" or a short reason ("tunnel driver not loaded", the data plane's) */
    unsigned long tun_dropped;  /* packets for a tun device that is not open */
} ts_dpio_view;
void ts_dpio_get_view(ts_dpio_view *v);
/* ts_dp_peer_status of the running data plane; -1 when it is not running. */
int ts_dpio_peer_status(uint32_t ipv4, ts_wg_stats *st, int *region);

/* Disco pings (src/data/dataplane.h, ts_dp_ping). ts_dpio_ping returns
 * ts_dp_ping's result, or TS_DP_PING_DOWN when the data plane is not running.
 * Every ping that returned 0 is reported exactly once through the callback
 * set with ts_dpio_set_ping_cb (kept across ts_dpio_init; NULL: none): its
 * pong, its timeout, or TS_DP_PING_STOPPED when the data plane stops first
 * (down, logout, a key or address change, ts_dpio_shutdown). The callback
 * runs inside ts_dpio_sync, ts_dpio_events or ts_dpio_shutdown and must not
 * call any ts_dpio_ function. */
typedef void (*ts_dpio_ping_fn)(void *user, uint64_t cookie, int status, uint32_t latency_us, int region_id);
void ts_dpio_set_ping_cb(ts_dpio_ping_fn fn, void *user);
int ts_dpio_ping(uint32_t peer_ip, uint32_t timeout_ms, uint64_t cookie, int64_t now_ms);

#ifdef TS_TEST_HOOKS
/* Replace the tun device and the commands (NULL: the real ones). */
extern int (*ts_dpio_test_tun_open)(char ifname[16]);
extern int (*ts_dpio_test_run)(const char *const *argv);
#endif

#endif
