#ifndef TS_DAEMON_NAMES_IO_H
#define TS_DAEMON_NAMES_IO_H

#include <stddef.h>
#include <stdint.h>

#include "src/control/netmap.h"
#include "src/daemon/dataplane_io.h"

/* The daemon's tsppc block in /etc/hosts (src/names/hosts.h builds and merges
 * it; src/platform/hostsfile.h reads and replaces the file).
 *
 * - While the data plane runs and the map has a self node without the
 *   disable-hosts-file-updates capability, the block lists the tailnet's
 *   names. It is built when the map changed (and on entering that state), and
 *   written only when it differs from the last block written, at most once
 *   every TS_NAMES_MIN_GAP_MS: a change inside the gap stays pending and the
 *   latest map is written when the gap has passed. Each write re-reads the
 *   file and merges into its current text; every line outside the block
 *   survives byte for byte.
 * - Running with no self node (a reconnect empties the map): nothing changes.
 * - Not running, or the capability set: the block is removed once (no gap).
 * - Any failure (read, write, a begin marker without an end, a file that is
 *   not a regular file or is too large) leaves the file as it is, shows in
 *   status as "hosts file: <reason>", and is retried after TS_NAMES_RETRY_MS.
 * - The resolver cache is flushed after each change to the file, never when
 *   the file was not changed.
 * - Buffers (about 2.3 MB) are allocated on first use and freed by
 *   ts_names_shutdown; without memory nothing is written.
 *
 * Test builds (-DTS_TEST_HOOKS): TSPPC_HOSTS_FILE=<path> replaces /etc/hosts,
 * and TSPPC_NO_TUN=1 also skips the cache flush. Both are read by
 * ts_names_init. */

#define TS_NAMES_PATH "/etc/hosts"
#define TS_NAMES_MIN_GAP_MS 5000
#define TS_NAMES_RETRY_MS 30000

/* No I/O. */
void ts_names_init(ts_dpio_log_fn logf);
/* At start (after the listen check) and from ts_names_shutdown: removes a
 * tsppc block if there is one, flushing the cache only if it removed one. */
void ts_names_cleanup(void);
/* After ts_dpio_sync each loop turn. nm is ts_sess_netmap (NULL without a
 * session), running the data plane's, map_changed when bytes reached the
 * session this turn. */
void ts_names_sync(const ts_netmap *nm, int running, int map_changed, int64_t now_ms);
/* Removes the block (SIGTERM, SIGINT, exit) and frees the buffers. */
void ts_names_shutdown(void);
/* "off", "disabled by tailnet", "<n> names" (", <m> skipped"), or
 * "hosts file: <reason>". */
void ts_names_status(char *out, size_t cap);

#ifdef TS_TEST_HOOKS
/* Files written and cache flushes (counted even when TSPPC_NO_TUN skips them). */
extern unsigned long ts_names_test_writes, ts_names_test_flushes;
#endif

#endif
