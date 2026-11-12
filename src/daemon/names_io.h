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
 *   names. When the map changed (and on entering that state), at most once
 *   every TS_NAMES_MIN_GAP_MS after the last write (a change inside the gap
 *   stays pending, and the latest map is used when the gap has passed), the
 *   file is re-read, the block built against its current text and merged in,
 *   and the file written only if the merged text differs from it. So an
 *   unchanged map rewrites nothing, and a block the owner deleted by hand
 *   comes back at the next map change. Every line outside the block
 *   survives byte for byte.
 * - Running with no self node (a reconnect empties the map): nothing changes.
 * - Not running, or the capability set: the block is removed once (no gap).
 * - Any failure (read, write, a begin marker without an end, a file that is
 *   not a regular file or is too large) leaves the file as it is, shows in
 *   status as "hosts file: <reason>", and is retried after TS_NAMES_RETRY_MS.
 * - The resolver cache is flushed after each change to the file, never when
 *   the file was not changed; the flush blocks (ts_run), so it is reported
 *   with ts_dpio_note_blocked.
 * - Buffers (about 2.2 MB) are allocated on first use and freed by
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
/* At start (after the listen check): removes leftover temp files of a crashed
 * write (ts_hostsfile_remove_temps), then a tsppc block if there is one,
 * flushing the cache only if it removed one. ts_names_shutdown removes the
 * block the same way. */
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
