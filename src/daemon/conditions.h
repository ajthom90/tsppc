#ifndef TS_DAEMON_CONDITIONS_H
#define TS_DAEMON_CONDITIONS_H

/* Pure decisions for the daemon's reaction to the world changing: a wake from
 * sleep or a clock step, a change of the machine's IPv4 network, and a gate
 * that keeps rebinds from storming. No I/O here; the daemon feeds in times
 * and the platform snapshot (src/platform/netinfo.h). */

#include <stddef.h>
#include <stdint.h>

#include "src/platform/netinfo.h"

#define TS_WAKE_JUMP_MS 15000
#define TS_NET_POLL_MS 5000
#define TS_REBIND_MIN_GAP_MS 10000
#define TS_NET_MAX_ADDRS 32

typedef struct {
    int primed;
    int64_t wall, mono;
} ts_wake;

/* The difference between how far the wall clock and the monotonic clock moved
 * since the last call, in ms, when its absolute value is at least
 * TS_WAKE_JUMP_MS (positive: slept or stepped forward; negative: stepped
 * back); else 0. The first call only primes. Every call re-primes. */
int64_t ts_wake_check(ts_wake *w, int64_t wall_ms, int64_t mono_ms);

/* FNV-1a 64 over the entries (without lo*, tun*, tap*, utun*, gif*,
 * 100.64.0.0/10 and 169.254.0.0/16), sorted by name and address and cut at TS_NET_MAX_ADDRS,
 * plus the default gateway and its interface. Independent of entry order. */
uint64_t ts_net_fingerprint(const ts_ifaddr *a, size_t n, uint32_t gw, const char *gw_if);

/* Use only through the API: last is stored encoded, never set it by hand. */
typedef struct {
    int64_t last;               /* 0: none yet; else the time of the last rebind + 1 */
    int pending;
    char why[64];
} ts_rebind_gate;

/* Notes that a rebind is wanted. The earliest pending reason is kept. */
void ts_rebind_request(ts_rebind_gate *g, const char *why, int64_t now_ms);

/* 1 (and why filled, pending cleared, last recorded) when a request is pending
 * and either no rebind happened before or TS_REBIND_MIN_GAP_MS has passed. */
int ts_rebind_due(ts_rebind_gate *g, int64_t now_ms, char why[64]);

#endif
