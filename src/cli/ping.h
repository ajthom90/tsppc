#ifndef TS_CLI_PING_H
#define TS_CLI_PING_H

#include <stddef.h>
#include <stdint.h>

#include "src/daemon/ipc_reply.h"

/* The pure parts of `tsppc ping` (src/cli/main.c runs the loop), after
 * upstream's cmd/tailscale/cli/ping.go at tailscale@9476be9:
 *
 *   tsppc ping [-c N] [--timeout DUR] [--until-direct=BOOL] <name|IP>
 *
 * Flags as Go's flag package takes them: "-x" or "--x", a value as the next
 * argument or after "=", bool flags only with "=" (or alone for true);
 * flags end at the first argument that is not one, or after "--". */

typedef struct {
    long count;                /* -c: pings to send, 0 (or less) for no limit; default 10 */
    uint32_t timeout_ms;       /* --timeout: per ping; default 5000 */
    int until_direct;          /* --until-direct; default 1 */
    const char *target;        /* the name or IP (points into argv) */
} ts_ping_opts;

/* Parse the arguments after "ping" (argv[0] is the first of them). 0, or -1
 * with a one-line reason in err (unknown flag, bad value, a timeout outside
 * TS_IPC_PING_MIN_MS..TS_IPC_PING_MAX_MS, not exactly one target). */
int ts_ping_parse_args(int argc, char **argv, ts_ping_opts *o, char *err, size_t errcap);

/* A Go duration ("5s", "500ms", "1.5s", "0"; units ms, s and m; a decimal
 * fraction allowed) in whole milliseconds, any part below 1 ms dropped.
 * 0, or -1 (no unit, unknown unit, more than 10 minutes, junk). */
int ts_ping_parse_duration(const char *s, uint32_t *ms);

/* latency_us rounded to the millisecond (half away from zero, as Go's
 * Duration.Round) and printed as Go's Duration.String: "0s", "23ms",
 * "999ms", "1s", "1.5s", "12.345s", "1m0.5s", "1h0m0s". */
void ts_ping_duration(char *out, size_t cap, uint64_t latency_us);

/* The first label of a DNS name ("peer" of "peer.example.ts.net."). */
void ts_ping_first_label(char *out, size_t cap, const char *name);

/* `pong from <label> (<ip>) via DERP(<code>) in <latency>` (no newline). A
 * code of "-" (the daemon knows none) prints as "" (upstream's empty code). */
void ts_ping_pong_line(char *out, size_t cap, const char *label, uint32_t ip, const char *code,
                       uint32_t latency_us);

/* Upstream's isRunningOrStarting on a status reply: 0 when the node is
 * running or starting (RUNNING, CONNECTING, BACKOFF, wanted up), else 1 with
 * upstream's description in out ("Tailscale is stopped.", "Logged out.",
 * "Machine is not yet approved by tailnet admin.", "unexpected state: X"). */
int ts_ping_not_running(const ts_reply *r, char *out, size_t cap);

#define TS_PING_PEER 0
#define TS_PING_SELF 1
#define TS_PING_NOT_FOUND (-1)

/* Resolve the target as upstream's tailscaleIPFromArg does, from a status
 * reply: an IPv4 literal is taken as it is (TS_PING_SELF if it is our own
 * address); otherwise the first peer whose full name (with or without the
 * trailing dot) or first label equals it ignoring case, then the self name
 * (TS_PING_SELF). *ip is set for PEER and SELF; for NOT_FOUND, msg says why
 * (no DNS fallback here). */
int ts_ping_resolve(const ts_reply *r, const char *arg, uint32_t *ip, char *msg, size_t cap);

/* The first label of the name of the peer at ip in a status reply, "" if
 * there is none. */
void ts_ping_peer_label(const ts_reply *r, uint32_t ip, char *out, size_t cap);

#endif
