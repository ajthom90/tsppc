/* The daemon's tsppc block in /etc/hosts. See names_io.h. */
#include "names_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/names/hosts.h"
#include "src/platform/hostsfile.h"

enum { M_NONE, M_OFF, M_DISABLED, M_ON };

#define OUT_CAP (TS_HOSTS_FILE_MAX + TS_HOSTS_BLOCK_MAX + 1)

static struct {
    ts_dpio_log_fn log;
    char path[1024];
    int no_flush;
    char *file;                 /* the file as read (TS_HOSTS_FILE_MAX) */
    size_t filelen;
    char *out;                  /* the merged text (OUT_CAP) */
    char *blk;                  /* the block just built (TS_HOSTS_BLOCK_MAX) */
    int mode;
    int dirty;                  /* M_ON: build, merge, and write if the file changes */
    int remove_wanted;          /* M_OFF, M_DISABLED: the block is to go */
    int64_t last_write;         /* of a block, for the gap */
    int have_last_write;
    int failed;                 /* the last attempt failed: wait for retry_at */
    int64_t retry_at;
    char err[128];              /* "" or why the last attempt failed */
    size_t nentries, nskipped;
} N;

#ifdef TS_TEST_HOOKS
unsigned long ts_names_test_writes, ts_names_test_flushes;
#define COUNT(x) ((x)++)
#else
#define COUNT(x) ((void)0)
#endif

static void free_bufs(void)
{
    free(N.file);
    free(N.out);
    free(N.blk);
    N.file = N.out = N.blk = NULL;
}

static int alloc_bufs(void)
{
    if (N.file) return 0;
    N.file = (char *)malloc(TS_HOSTS_FILE_MAX);
    N.out = (char *)malloc(OUT_CAP);
    N.blk = (char *)malloc(TS_HOSTS_BLOCK_MAX);
    if (N.file && N.out && N.blk) return 0;
    free_bufs();
    return -1;
}

void ts_names_init(ts_dpio_log_fn logf)
{
    free_bufs();
    memset(&N, 0, sizeof N);
    N.log = logf;
    snprintf(N.path, sizeof N.path, "%s", TS_NAMES_PATH);
#ifdef TS_TEST_HOOKS
    {
        const char *e = getenv("TSPPC_HOSTS_FILE");
        if (e && e[0]) snprintf(N.path, sizeof N.path, "%s", e);
        e = getenv("TSPPC_NO_TUN");
        N.no_flush = e && strcmp(e, "1") == 0;
    }
#endif
}

static void fail(const char *why, int64_t retry_at)
{
    if (strcmp(N.err, why) != 0 && N.log) N.log("hosts file: %s (left as it is)", why);
    snprintf(N.err, sizeof N.err, "%s", why);
    N.failed = 1;
    N.retry_at = retry_at;
}

static void succeeded(void)
{
    N.err[0] = 0;
    N.failed = 0;
}

static void flush(void)
{
    COUNT(ts_names_test_flushes);
    if (N.no_flush) return;
    ts_hostsfile_flush_cache();
    ts_dpio_note_blocked();   /* up to TS_RUN_LIMIT_MS: no probe is timed across it */
}

static int read_file(int64_t retry_at)
{
    char err[128];
    if (alloc_bufs() != 0) {
        fail("out of memory", retry_at);
        return -1;
    }
    if (ts_hostsfile_read(N.path, N.file, TS_HOSTS_FILE_MAX, &N.filelen, err, sizeof err) != 0) {
        fail(err, retry_at);
        return -1;
    }
    return 0;
}

/* Merges block into the file just read and writes it if that changes it.
 * 1 written, 0 nothing to change, -1 failed. */
static int merge_write(const char *block, size_t blocklen, int64_t retry_at)
{
    char err[128];
    int n = ts_hosts_merge(N.out, OUT_CAP, N.file, N.filelen, block, blocklen);
    if (n == -2) {
        fail("broken tsppc section (a begin line without an end line)", retry_at);
        return -1;
    }
    if (n < 0) {
        fail("too large", retry_at);
        return -1;
    }
    if ((size_t)n == N.filelen && memcmp(N.out, N.file, N.filelen) == 0) return 0;
    if (ts_hostsfile_write(N.path, N.out, (size_t)n, err, sizeof err) != 0) {
        fail(err, retry_at);
        return -1;
    }
    COUNT(ts_names_test_writes);
    return 1;
}

/* 0 when the file has no block (now), -1 failed. */
static int remove_block(int64_t retry_at)
{
    int r;
    if (read_file(retry_at) != 0) return -1;
    r = merge_write(NULL, 0, retry_at);
    if (r < 0) return -1;
    succeeded();
    if (r > 0) {
        if (N.log) N.log("hosts file: peer names removed");
        flush();
    }
    return 0;
}

static void apply(const ts_netmap *nm, int64_t now)
{
    size_t ne = 0, ns = 0;
    int n, r;
    if (read_file(now + TS_NAMES_RETRY_MS) != 0) return;
    n = ts_hosts_build(N.blk, TS_HOSTS_BLOCK_MAX, nm, N.file, N.filelen, &ne, &ns);
    if (n < 0) {
        fail("block too large", now + TS_NAMES_RETRY_MS);
        return;
    }
    N.nentries = ne;
    N.nskipped = ns;
    /* Written only if the merged text differs from the file: an unchanged map
     * rewrites nothing, and a block deleted by hand comes back. */
    r = merge_write(N.blk, (size_t)n, now + TS_NAMES_RETRY_MS);
    if (r < 0) return;
    N.dirty = 0;
    succeeded();
    if (r > 0) {
        N.last_write = now;
        N.have_last_write = 1;
        if (N.log) N.log("hosts file: %lu peer names written", (unsigned long)ne);
        flush();
    }
}

void ts_names_cleanup(void)
{
    int n = ts_hostsfile_remove_temps(N.path);
    if (n > 0 && N.log) N.log("hosts file: %d leftover temp file%s removed", n, n == 1 ? "" : "s");
    (void)remove_block(0);
}

void ts_names_sync(const ts_netmap *nm, int running, int map_changed, int64_t now_ms)
{
    int target;
    if (!running) target = M_OFF;
    else if (!nm || !nm->have_self) return;   /* a reconnect emptied the map: keep what is there */
    else if (nm->self.no_hosts_file) target = M_DISABLED;
    else target = M_ON;

    if (target != N.mode) {
        N.mode = target;
        N.dirty = target == M_ON;
        N.remove_wanted = target != M_ON;
        N.failed = 0;   /* a new state is tried at once */
    }
    if (target == M_ON && map_changed) N.dirty = 1;
    if (N.failed && now_ms < N.retry_at) return;
    if (target == M_ON) {
        if (N.dirty && (!N.have_last_write || now_ms - N.last_write >= TS_NAMES_MIN_GAP_MS)) apply(nm, now_ms);
    } else if (N.remove_wanted) {
        if (remove_block(now_ms + TS_NAMES_RETRY_MS) == 0) N.remove_wanted = 0;
    }
}

void ts_names_shutdown(void)
{
    (void)remove_block(0);
    free_bufs();
}

void ts_names_status(char *out, size_t cap)
{
    if (N.err[0]) snprintf(out, cap, "hosts file: %s", N.err);
    else if (N.mode == M_ON && N.nskipped)
        snprintf(out, cap, "%lu names, %lu skipped", (unsigned long)N.nentries, (unsigned long)N.nskipped);
    else if (N.mode == M_ON) snprintf(out, cap, "%lu names", (unsigned long)N.nentries);
    else if (N.mode == M_DISABLED) snprintf(out, cap, "disabled by tailnet");
    else snprintf(out, cap, "off");
}
