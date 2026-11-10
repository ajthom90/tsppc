#include "store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../core/bytes.h"
#include "../crypto/blake2s.h"
#include "../crypto/random.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define PATH_MAX_STATE 1024

const char *ts_state_default_dir(void)
{
#ifdef TS_TEST_HOOKS
    const char *e = getenv("TSPPC_STATE_DIR");
    if (e && e[0]) return e;
#endif
    return TS_STATE_DIR;
}

static void seterr(char *err, size_t cap, const char *fmt, ...)
{
    va_list ap;
    if (!err || cap == 0) return;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* ---- Format -------------------------------------------------------------- */

void ts_state_encode(uint8_t out[TS_STATE_FILE_LEN], const ts_state *s)
{
    uint16_t flags = (uint16_t)((s->have_old_node ? 1 : 0) | (s->have_login ? 2 : 0));
    memcpy(out, "TSPS", 4);
    ts_put_be16(out + 4, TS_STATE_VERSION);
    ts_put_be16(out + 6, flags);
    memcpy(out + 8, s->machine_priv, 32);
    memcpy(out + 40, s->node_priv, 32);
    if (s->have_old_node) memcpy(out + 72, s->old_node_priv, 32);
    else memset(out + 72, 0, 32);
    memcpy(out + 104, s->disco_priv, 32);
    ts_blake2s(out + 136, out, 136);
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int ts_state_parse(ts_state *s, const uint8_t *buf, size_t len)
{
    uint8_t sum[32];
    uint16_t flags;
    size_t i;
    uint8_t z = 0;

    memset(s, 0, sizeof *s);
    if (len != TS_STATE_FILE_LEN) return -1;
    if (memcmp(buf, "TSPS", 4) != 0) return -1;
    if (ts_get_be16(buf + 4) != TS_STATE_VERSION) return -1;
    ts_blake2s(sum, buf, 136);
    if (!ct_equal(sum, buf + 136, 32)) return -1;
    flags = ts_get_be16(buf + 6);
    if (flags & ~(uint16_t)3) return -1;
    for (i = 0; i < 32; i++) z |= buf[72 + i];
    if (!(flags & 1) && z != 0) return -1;
    memcpy(s->machine_priv, buf + 8, 32);
    memcpy(s->node_priv, buf + 40, 32);
    memcpy(s->old_node_priv, buf + 72, 32);
    memcpy(s->disco_priv, buf + 104, 32);
    s->have_old_node = (flags & 1) ? 1 : 0;
    s->have_login = (flags & 2) ? 1 : 0;
    return 0;
}

/* ---- Files --------------------------------------------------------------- */

/* Check that st describes something we may trust: owned by us, no group or
 * other bits (dir), or exactly mode 0600 (file). */
static int check_dir(const char *dir, char *err, size_t cap)
{
    struct stat st;
    if (lstat(dir, &st) != 0) {
        seterr(err, cap, "state directory: %s", strerror(errno));
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        seterr(err, cap, "state directory is a symbolic link, refusing it");
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        seterr(err, cap, "state path is not a directory");
        return -1;
    }
    if (st.st_uid != geteuid()) {
        seterr(err, cap, "state directory is owned by the wrong user, refusing it");
        return -1;
    }
    if (st.st_mode & 077) {
        seterr(err, cap, "state directory mode %03o gives group or other access, refusing it (need 0700)",
               (unsigned)(st.st_mode & 0777));
        return -1;
    }
    return 0;
}

/* Make sure dir exists and is acceptable, creating it (0700) if absent. */
static int ensure_dir(const char *dir, char *err, size_t cap)
{
    struct stat st;
    if (!dir || !dir[0] || strlen(dir) > PATH_MAX_STATE - 64) {
        seterr(err, cap, "state directory path is empty or too long");
        return -1;
    }
    if (lstat(dir, &st) != 0 && errno == ENOENT) {
        if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
            seterr(err, cap, "cannot create state directory: %s", strerror(errno));
            return -1;
        }
        (void)chmod(dir, 0700);   /* a restrictive umask must not leave it unusable */
    }
    return check_dir(dir, err, cap);
}

static int fsync_dir(const char *dir)
{
    int fd = open(dir, O_RDONLY);
    int r;
    if (fd < 0) return -1;
    r = fsync(fd);
    close(fd);
    return r;
}

static int write_all(int fd, const uint8_t *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int file_path(char *out, size_t cap, const char *dir)
{
    int n = snprintf(out, cap, "%s/%s", dir, TS_STATE_FILE);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

int ts_state_save(const ts_state *s, const char *dir, char *err, size_t errcap)
{
    char tmpl[PATH_MAX_STATE], path[PATH_MAX_STATE];
    uint8_t buf[TS_STATE_FILE_LEN];
    int fd, n;

    if (ensure_dir(dir, err, errcap) != 0) return -1;
    if (file_path(path, sizeof path, dir) != 0) {
        seterr(err, errcap, "state path too long");
        return -1;
    }
    n = snprintf(tmpl, sizeof tmpl, "%s/.state.XXXXXX", dir);
    if (n <= 0 || (size_t)n >= sizeof tmpl) {
        seterr(err, errcap, "state path too long");
        return -1;
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        seterr(err, errcap, "cannot create temporary state file: %s", strerror(errno));
        return -1;
    }
    ts_state_encode(buf, s);
    if (fchmod(fd, 0600) != 0 || write_all(fd, buf, sizeof buf) != 0 || fsync(fd) != 0) {
        seterr(err, errcap, "cannot write state file: %s", strerror(errno));
        ts_wipe(buf, sizeof buf);
        close(fd);
        unlink(tmpl);
        return -1;
    }
    ts_wipe(buf, sizeof buf);
    if (close(fd) != 0) {
        seterr(err, errcap, "cannot write state file: %s", strerror(errno));
        unlink(tmpl);
        return -1;
    }
    if (rename(tmpl, path) != 0) {
        seterr(err, errcap, "cannot install state file: %s", strerror(errno));
        unlink(tmpl);
        return -1;
    }
    if (fsync_dir(dir) != 0) {
        seterr(err, errcap, "cannot sync state directory: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Clamp as X25519 requires; the crypto module clamps again when it uses the key. */
static int new_key(uint8_t k[32])
{
    if (ts_random_bytes(k, 32) != 0) return -1;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return 0;
}

int ts_state_load_or_create(ts_state *s, const char *dir, char *err, size_t errcap)
{
    char path[PATH_MAX_STATE];
    struct stat lst, st;
    uint8_t buf[TS_STATE_FILE_LEN + 1];
    size_t got = 0;
    int fd, rc = -1;

    memset(s, 0, sizeof *s);
    if (ensure_dir(dir, err, errcap) != 0) return -1;
    if (file_path(path, sizeof path, dir) != 0) {
        seterr(err, errcap, "state path too long");
        return -1;
    }

    if (lstat(path, &lst) != 0) {
        if (errno != ENOENT) {
            seterr(err, errcap, "state file: %s", strerror(errno));
            return -1;
        }
        if (new_key(s->machine_priv) != 0 || new_key(s->node_priv) != 0 || new_key(s->disco_priv) != 0) {
            seterr(err, errcap, "cannot read the random source");
            ts_wipe(s, sizeof *s);
            return -1;
        }
        if (ts_state_save(s, dir, err, errcap) != 0) {
            ts_wipe(s, sizeof *s);
            return -1;
        }
        return 0;
    }
    if (S_ISLNK(lst.st_mode)) {
        seterr(err, errcap, "state file is a symbolic link, refusing it");
        return -1;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        seterr(err, errcap, "cannot open state file: %s", strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_dev != lst.st_dev || st.st_ino != lst.st_ino) {
        seterr(err, errcap, "state file is not a regular file, refusing it");
        goto out;
    }
    if (st.st_uid != geteuid()) {
        seterr(err, errcap, "state file is owned by the wrong user, refusing it");
        goto out;
    }
    if ((st.st_mode & 0777) != 0600) {
        seterr(err, errcap, "state file mode %03o is not 0600, refusing it", (unsigned)(st.st_mode & 0777));
        goto out;
    }
    while (got < sizeof buf) {
        ssize_t r = read(fd, buf + got, sizeof buf - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            seterr(err, errcap, "cannot read state file: %s", strerror(errno));
            goto out;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    if (ts_state_parse(s, buf, got) != 0) {
        seterr(err, errcap, "state file is truncated, corrupt or of an unknown version; not overwriting it");
        goto out;
    }
    rc = 0;
out:
    close(fd);
    ts_wipe(buf, sizeof buf);
    if (rc != 0) ts_wipe(s, sizeof *s);
    return rc;
}
