/* The daemon's /etc/hosts writer (src/daemon/names_io.c) and the platform
 * file code under it (src/platform/hostsfile.c), against files in a temp
 * directory (TSPPC_HOSTS_FILE). TSPPC_NO_TUN=1 skips the cache flush; the
 * counters still count it. */
#include "harness.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/daemon/names_io.h"
#include "../src/names/hosts.h"
#include "../src/platform/hostsfile.h"

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static char dir[64], path[128], other[128];
static char logbuf[4096];
static const char ORIG[] = "##\n# Host Database\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n10.0.0.1 nas\n";

static void nlog(const char *fmt, ...)
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

static void put_file(const char *p, const char *text, mode_t mode)
{
    FILE *f;
    unlink(p);
    f = fopen(p, "w");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
    chmod(p, mode);
}

/* The whole file as a NUL-terminated string (static buffer), or NULL. */
static const char *get_file(const char *p)
{
    static char buf[16384];
    size_t n;
    FILE *f = fopen(p, "r");
    if (!f) return NULL;
    n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    return buf;
}

static int file_is(const char *p, const char *want)
{
    const char *got = get_file(p);
    return got && strcmp(got, want) == 0;
}

static ino_t inode_of(const char *p)
{
    struct stat sb;
    return lstat(p, &sb) == 0 ? sb.st_ino : 0;
}

/* No temp file of ours is left in dir. */
static int no_temp_left(void)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int found = 0;
    if (!d) return 0;
    while ((e = readdir(d)) != NULL)
        if (strncmp(e->d_name, ".hosts.tsppc.", 13) == 0) found = 1;
    closedir(d);
    return !found;
}

static void setname(ts_node *n, const char *name, uint32_t ip)
{
    memset(n, 0, sizeof *n);
    strcpy(n->name, name);
    n->ipv4 = ip;
    n->have_ipv4 = ip != 0;
}

/* orig followed by the block for nm (built against orig), in want. */
static void expect(char *want, size_t cap, const ts_netmap *nm, const char *orig)
{
    static char block[TS_HOSTS_BLOCK_MAX];
    int n = ts_hosts_build(block, sizeof block, nm, orig, strlen(orig), NULL, NULL);
    size_t ol = strlen(orig);
    want[0] = 0;
    if (n < 0 || ol + (size_t)n + 1 > cap) return;
    memcpy(want, orig, ol);
    memcpy(want + ol, block, (size_t)n);
    want[ol + (size_t)n] = 0;
}

static int status_is(const char *want)
{
    char s[128];
    ts_names_status(s, sizeof s);
    return strcmp(s, want) == 0;
}

static int status_starts(const char *want)
{
    char s[128];
    ts_names_status(s, sizeof s);
    return strncmp(s, want, strlen(want)) == 0;
}

static void test_hostsfile(void)
{
    static char buf[TS_HOSTS_FILE_MAX + 2];
    char err[128];
    size_t len = 99;
    struct stat sb;
    FILE *f;

    /* missing: empty, not an error */
    unlink(path);
    t_true("hostsfile: missing reads empty", ts_hostsfile_read(path, buf, sizeof buf, &len, err, sizeof err) == 0 && len == 0);
    put_file(path, ORIG, 0640);
    t_true("hostsfile: read", ts_hostsfile_read(path, buf, sizeof buf, &len, err, sizeof err) == 0 && len == strlen(ORIG) &&
                                  memcmp(buf, ORIG, len) == 0);

    /* write keeps the mode and owner, replaces atomically (a new inode) */
    {
        ino_t before = inode_of(path);
        t_true("hostsfile: write", ts_hostsfile_write(path, "1.2.3.4 x\n", 10, err, sizeof err) == 0);
        t_true("hostsfile: written text", file_is(path, "1.2.3.4 x\n"));
        t_true("hostsfile: mode kept", lstat(path, &sb) == 0 && (sb.st_mode & 07777) == 0640);
        t_true("hostsfile: owner kept", sb.st_uid == geteuid());
        t_true("hostsfile: new inode", sb.st_ino != before);
        t_true("hostsfile: no temp left", no_temp_left());
    }
    /* a missing file is created 0644 (root:wheel when root) */
    unlink(path);
    t_true("hostsfile: write creates", ts_hostsfile_write(path, "a\n", 2, err, sizeof err) == 0 && file_is(path, "a\n"));
    t_true("hostsfile: created 0644", lstat(path, &sb) == 0 && (sb.st_mode & 07777) == 0644);
    if (geteuid() == 0) t_true("hostsfile: created root:wheel", sb.st_uid == 0 && sb.st_gid == 0);

    /* a symlink is not a regular file: refused both ways, left as it is */
    put_file(other, "target\n", 0644);
    unlink(path);
    t_true("hostsfile: symlink made", symlink(other, path) == 0);
    err[0] = 0;
    t_true("hostsfile: symlink read refused", ts_hostsfile_read(path, buf, sizeof buf, &len, err, sizeof err) == -1 &&
                                                  strstr(err, "not a regular file") != NULL);
    err[0] = 0;
    t_true("hostsfile: symlink write refused", ts_hostsfile_write(path, "x\n", 2, err, sizeof err) == -1 &&
                                                   strstr(err, "not a regular file") != NULL);
    t_true("hostsfile: symlink kept", lstat(path, &sb) == 0 && S_ISLNK(sb.st_mode) && file_is(other, "target\n"));
    t_true("hostsfile: no temp left after refusal", no_temp_left());
    unlink(path);

    /* a directory is not a regular file either */
    t_true("hostsfile: dir made", mkdir(path, 0755) == 0);
    t_true("hostsfile: dir read refused", ts_hostsfile_read(path, buf, sizeof buf, &len, err, sizeof err) == -1 &&
                                              strstr(err, "not a regular file") != NULL);
    rmdir(path);

    /* too large: one byte over the limit */
    f = fopen(path, "w");
    if (f) {
        static char big[TS_HOSTS_FILE_MAX + 1];
        memset(big, '#', sizeof big);
        fwrite(big, 1, sizeof big, f);
        fclose(f);
    }
    err[0] = 0;
    t_true("hostsfile: too large refused", ts_hostsfile_read(path, buf, sizeof buf, &len, err, sizeof err) == -1 &&
                                               strstr(err, "too large") != NULL);
    /* exactly the limit is fine */
    t_true("hostsfile: limit ok", truncate(path, TS_HOSTS_FILE_MAX) == 0 &&
                                      ts_hostsfile_read(path, buf, sizeof buf, &len, err, sizeof err) == 0 &&
                                      len == TS_HOSTS_FILE_MAX);
    unlink(path);

    /* a write that cannot happen leaves the original alone */
    {
        char missing[160];
        snprintf(missing, sizeof missing, "%s/nodir/hosts", dir);
        err[0] = 0;
        t_true("hostsfile: write into a missing dir fails", ts_hostsfile_write(missing, "x\n", 2, err, sizeof err) == -1 &&
                                                                err[0] != 0);
    }
    if (geteuid() != 0) {
        put_file(path, ORIG, 0644);
        chmod(dir, 0555);
        t_true("hostsfile: read-only dir write fails", ts_hostsfile_write(path, "x\n", 2, err, sizeof err) == -1);
        chmod(dir, 0755);
        t_true("hostsfile: original untouched", file_is(path, ORIG));
        t_true("hostsfile: no temp after failure", no_temp_left());
    }
    unlink(other);
    unlink(path);
}

static void test_sync(void)
{
    static ts_node peers[4];
    static char want[16384], want2[16384];
    ts_netmap nm;
    struct stat sb;
    unsigned long w0, f0;
    int64_t t = 1000000;

    memset(&nm, 0, sizeof nm);
    nm.peers = peers;
    nm.have_self = 1;
    setname(&nm.self, "self.example.ts.net.", IP(100, 64, 0, 1));
    setname(&peers[0], "peer-a.example.ts.net.", IP(100, 64, 0, 2));
    setname(&peers[1], "nas.example.ts.net.", IP(100, 64, 0, 3));   /* "nas" is the owner's: no short name */
    setname(&peers[2], "bad name.example.ts.net.", IP(100, 64, 0, 4));
    nm.npeers = 3;

    put_file(path, ORIG, 0640);
    ts_names_init(nlog);
    t_true("sync: off before anything", status_is("off"));
    w0 = ts_names_test_writes;
    f0 = ts_names_test_flushes;

    /* not running: nothing to remove, no write */
    ts_names_sync(&nm, 0, 1, t);
    t_true("sync: not running writes nothing", ts_names_test_writes == w0 && file_is(path, ORIG));

    /* running with a map: block appended, the rest kept, mode kept */
    ts_names_sync(&nm, 1, 1, t);
    expect(want, sizeof want, &nm, ORIG);
    t_true("sync: block written", ts_names_test_writes == w0 + 1 && want[0] && file_is(path, want));
    t_true("sync: owner's name not shadowed", strstr(want, "nas.example.ts.net\n") != NULL &&
                                                  strstr(want, "nas.example.ts.net nas") == NULL);
    t_true("sync: flushed", ts_names_test_flushes == f0 + 1);
    t_true("sync: mode kept", lstat(path, &sb) == 0 && (sb.st_mode & 07777) == 0640);
    t_true("sync: status counts", status_is("3 names, 1 skipped"));
    t_true("sync: logged", strstr(logbuf, "hosts") != NULL);

    /* the same map again (a keep-alive): no rewrite */
    ts_names_sync(&nm, 1, 1, t + 1000);
    ts_names_sync(&nm, 1, 0, t + 1500);
    t_true("sync: unchanged map not rewritten", ts_names_test_writes == w0 + 1 && ts_names_test_flushes == f0 + 1);

    /* a change within 5 s waits for the gap, then is written */
    setname(&peers[2], "peer-c.example.ts.net.", IP(100, 64, 0, 4));
    ts_names_sync(&nm, 1, 1, t + 2000);
    t_true("sync: change within the gap waits", ts_names_test_writes == w0 + 1 && file_is(path, want));
    ts_names_sync(&nm, 1, 0, t + TS_NAMES_MIN_GAP_MS - 1);
    t_true("sync: still waiting just before the gap", ts_names_test_writes == w0 + 1);
    ts_names_sync(&nm, 1, 0, t + TS_NAMES_MIN_GAP_MS);
    expect(want2, sizeof want2, &nm, ORIG);
    t_true("sync: pending change written after the gap", ts_names_test_writes == w0 + 2 && file_is(path, want2));
    t_true("sync: status after change", status_is("4 names"));
    t += TS_NAMES_MIN_GAP_MS;

    /* change and change back within the gap: nothing to write */
    setname(&peers[2], "peer-d.example.ts.net.", IP(100, 64, 0, 4));
    ts_names_sync(&nm, 1, 1, t + 1000);
    setname(&peers[2], "peer-c.example.ts.net.", IP(100, 64, 0, 4));
    ts_names_sync(&nm, 1, 1, t + 2000);
    ts_names_sync(&nm, 1, 0, t + TS_NAMES_MIN_GAP_MS + 1);
    t_true("sync: change undone within the gap not written", ts_names_test_writes == w0 + 2 && file_is(path, want2));

    /* the owner edits the file: their lines survive the next write */
    {
        char edited[16384];
        snprintf(edited, sizeof edited, "%s10.0.0.2 printer\n", want2);
        put_file(path, edited, 0640);
        setname(&peers[2], "peer-e.example.ts.net.", IP(100, 64, 0, 4));
        t += 20000;
        ts_names_sync(&nm, 1, 1, t);
        t_true("sync: owner's later line kept", ts_names_test_writes == w0 + 3 &&
                                                    strstr(get_file(path), "10.0.0.2 printer\n") != NULL &&
                                                    strstr(get_file(path), "peer-e.example.ts.net") != NULL);
        put_file(path, want2, 0640);   /* back to a known text; the block is stale now */
        ts_names_sync(&nm, 0, 0, t + 100);
        t_true("sync: down removes the block from the edited file", file_is(path, ORIG));
    }

    /* running with no self (a reconnect emptied the map): nothing changes */
    t += 20000;
    ts_names_sync(&nm, 1, 1, t);
    expect(want, sizeof want, &nm, ORIG);
    t_true("sync: up again writes the block", file_is(path, want));
    w0 = ts_names_test_writes;
    nm.have_self = 0;
    ts_names_sync(&nm, 1, 1, t + 20000);
    ts_names_sync(NULL, 1, 1, t + 40000);
    t_true("sync: no self keeps the block", ts_names_test_writes == w0 && file_is(path, want));
    nm.have_self = 1;
    ts_names_sync(&nm, 1, 1, t + 60000);
    t_true("sync: self back, same block, no write", ts_names_test_writes == w0);
    t += 60000;

    /* not running: the block goes at once (no gap), once */
    f0 = ts_names_test_flushes;
    ts_names_sync(&nm, 0, 0, t + 1);
    t_true("sync: not running removes the block", file_is(path, ORIG) && ts_names_test_writes == w0 + 1);
    t_true("sync: removal flushed", ts_names_test_flushes == f0 + 1);
    t_true("sync: status off", status_is("off"));
    {
        ino_t ino = inode_of(path);
        ts_names_sync(&nm, 0, 1, t + 2);
        ts_names_sync(&nm, 0, 0, t + 50000);
        t_true("sync: removed once only", ts_names_test_writes == w0 + 1 && inode_of(path) == ino);
    }
    t += 50000;

    /* up again: the same block is written again */
    ts_names_sync(&nm, 1, 0, t);
    t_true("sync: up writes the block again (no map change needed)", file_is(path, want) && ts_names_test_writes == w0 + 2);

    /* the capability: the block goes, status says why */
    nm.self.no_hosts_file = 1;
    ts_names_sync(&nm, 1, 1, t + 100);
    t_true("sync: capability removes the block", file_is(path, ORIG) && ts_names_test_writes == w0 + 3);
    t_true("sync: status disabled", status_is("disabled by tailnet"));
    ts_names_sync(&nm, 1, 1, t + 30000);
    t_true("sync: capability, no more writes", ts_names_test_writes == w0 + 3);
    nm.self.no_hosts_file = 0;
    ts_names_sync(&nm, 1, 1, t + 40000);
    t_true("sync: capability cleared writes again", file_is(path, want) && ts_names_test_writes == w0 + 4);
    t += 40000;
    ts_names_shutdown();
    t_true("sync: shutdown removes the block", file_is(path, ORIG));
    t_true("sync: no temp left", no_temp_left());
}

static void test_broken_and_refused(void)
{
    static ts_node peers[2];
    static char broken[4096], want[16384];
    ts_netmap nm;
    unsigned long w0;
    int64_t t = 5000000;
    struct stat sb;

    memset(&nm, 0, sizeof nm);
    nm.peers = peers;
    nm.have_self = 1;
    setname(&nm.self, "self.example.ts.net.", IP(100, 64, 0, 1));
    setname(&peers[0], "peer-a.example.ts.net.", IP(100, 64, 0, 2));
    nm.npeers = 1;

    /* a begin marker without an end: never written, status says so */
    snprintf(broken, sizeof broken, "%s%s\n100.64.9.9\told.example.ts.net\n10.0.0.5 owner-line\n", ORIG, TS_HOSTS_BEGIN);
    put_file(path, broken, 0644);
    ts_names_init(nlog);
    w0 = ts_names_test_writes;
    ts_names_sync(&nm, 1, 1, t);
    t_true("broken: not written", ts_names_test_writes == w0 && file_is(path, broken));
    t_true("broken: status says so", status_starts("hosts file: ") && status_starts("hosts file: broken tsppc section"));
    /* fixed by the owner: not retried before TS_NAMES_RETRY_MS, then written */
    put_file(path, ORIG, 0644);
    ts_names_sync(&nm, 1, 1, t + 1000);
    t_true("broken: no retry before the delay", ts_names_test_writes == w0 && file_is(path, ORIG));
    ts_names_sync(&nm, 1, 0, t + TS_NAMES_RETRY_MS);
    expect(want, sizeof want, &nm, ORIG);
    t_true("broken: retried after the delay", ts_names_test_writes == w0 + 1 && file_is(path, want));
    t_true("broken: status recovered", status_is("2 names"));
    t += TS_NAMES_RETRY_MS;

    /* broken while removing: removal refused too, file kept */
    put_file(path, broken, 0644);
    ts_names_sync(&nm, 0, 0, t + 1);
    t_true("broken: removal refused", file_is(path, broken) && status_starts("hosts file: broken tsppc section"));
    ts_names_cleanup();
    t_true("broken: cleanup refused", file_is(path, broken));
    ts_names_shutdown();
    t_true("broken: shutdown refused", file_is(path, broken));

    /* a symlink is refused and left alone */
    put_file(other, ORIG, 0644);
    unlink(path);
    t_true("refused: symlink made", symlink(other, path) == 0);
    ts_names_init(nlog);
    w0 = ts_names_test_writes;
    ts_names_sync(&nm, 1, 1, t + 100000);
    t_true("refused: symlink not written", ts_names_test_writes == w0 && file_is(other, ORIG) &&
                                               lstat(path, &sb) == 0 && S_ISLNK(sb.st_mode));
    t_true("refused: status not a regular file", status_is("hosts file: not a regular file"));
    ts_names_shutdown();
    unlink(path);
    unlink(other);
    t_true("refused: no temp left", no_temp_left());
}

static void test_cleanup(void)
{
    static char stale[4096];
    unsigned long w0, f0;
    ino_t ino;

    ts_names_init(nlog);
    /* no block: untouched (same inode), no flush */
    put_file(path, ORIG, 0644);
    ino = inode_of(path);
    w0 = ts_names_test_writes;
    f0 = ts_names_test_flushes;
    ts_names_cleanup();
    t_true("cleanup: no block, untouched", inode_of(path) == ino && file_is(path, ORIG) && ts_names_test_writes == w0 &&
                                               ts_names_test_flushes == f0);
    /* missing: not created */
    unlink(path);
    ts_names_cleanup();
    t_true("cleanup: missing file not created", inode_of(path) == 0 && ts_names_test_writes == w0);
    /* a stale block from a crash: removed, the rest kept, flushed */
    snprintf(stale, sizeof stale, "%s%s\n100.64.0.2\tpeer-a.example.ts.net peer-a\n%s\n", ORIG, TS_HOSTS_BEGIN, TS_HOSTS_END);
    put_file(path, stale, 0640);
    ts_names_cleanup();
    t_true("cleanup: stale block removed", file_is(path, ORIG) && ts_names_test_writes == w0 + 1 &&
                                               ts_names_test_flushes == f0 + 1);
    {
        struct stat sb;
        t_true("cleanup: mode kept", lstat(path, &sb) == 0 && (sb.st_mode & 07777) == 0640);
    }
    ts_names_shutdown();
    unlink(path);
}

void test_names_io(void)
{
    snprintf(dir, sizeof dir, "/tmp/tsppc-n.XXXXXX");
    if (!mkdtemp(dir)) {
        t_true("names_io: temp dir", 0);
        return;
    }
    snprintf(path, sizeof path, "%s/hosts", dir);
    snprintf(other, sizeof other, "%s/other", dir);
    setenv("TSPPC_HOSTS_FILE", path, 1);
    setenv("TSPPC_NO_TUN", "1", 1);
    test_hostsfile();
    test_sync();
    test_broken_and_refused();
    test_cleanup();
    /* Other tests read TSPPC_NO_TUN (dataplane_io.c). */
    unsetenv("TSPPC_HOSTS_FILE");
    unsetenv("TSPPC_NO_TUN");
    unlink(path);
    unlink(other);
    rmdir(dir);
}
