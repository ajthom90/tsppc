#ifndef TS_DAEMON_NAMES_IO_H
#define TS_DAEMON_NAMES_IO_H

#include <stddef.h>
#include <stdint.h>

#include "src/control/netmap.h"
#include "src/daemon/dataplane_io.h"

/* The daemon's tsppc block in /etc/hosts (src/names/hosts.h builds and merges
 * it; src/platform/hostsfile.h reads and replaces the file).
 *
 * - While the data plane runs with the tun device open and the map has a
 *   self node without the disable-hosts-file-updates capability, the block
 *   lists the tailnet's names (ts_hosts_build: only full names in self's
 *   suffix or ts.net; a peer's short name equal to this Mac's host name,
 *   from gethostname, is withheld). When the map changed (and on entering that state), at most once
 *   every TS_NAMES_MIN_GAP_MS after the last write (a change inside the gap
 *   stays pending, and the latest map is used when the gap has passed), the
 *   file is re-read, the block built against its current text and merged in,
 *   and the file written only if the merged text differs from it. So an
 *   unchanged map rewrites nothing, and a block the owner deleted by hand
 *   comes back at the next map change. Every line outside the block
 *   survives byte for byte.
 * - Nothing is even read when nothing could have changed: the map's
 *   nodes_gen, the host name and the file's dev, inode, size, mtime and
 *   ctime all as at the last successful apply.
 * - Running with no self node (a reconnect empties the map): nothing changes.
 * - Not running, the tunnel not open, or the capability set: the block is
 *   removed once (no gap).
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
 * and TSPPC_NO_TUN=1 also skips the cache flush and counts the tunnel as
 * open (no tun device then). Both are read by ts_names_init. */

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
 * session), running and tun_open the data plane's (ts_dpio_view),
 * map_changed when bytes reached the session this turn. */
void ts_names_sync(const ts_netmap *nm, int running, int tun_open, int map_changed, int64_t now_ms);
/* Removes the block (SIGTERM, SIGINT, exit) and frees the buffers. */
void ts_names_shutdown(void);
/* "off", "disabled by tailnet", "<n> names" (", <m> skipped"), or
 * "hosts file: <reason>". */
void ts_names_status(char *out, size_t cap);

#ifdef TS_TEST_HOOKS
/* Files written, cache flushes (counted even when TSPPC_NO_TUN skips them)
 * and hosts file reads. */
extern unsigned long ts_names_test_writes, ts_names_test_flushes, ts_names_test_reads;
/* Replaces the cache flush (NULL: the real one, or none with TSPPC_NO_TUN). */
extern void (*ts_names_test_flush)(void);
#endif

#endif
