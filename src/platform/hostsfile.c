/* The hosts file on disk. See hostsfile.h. */
#include "hostsfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "src/names/hosts.h"
#include "tun.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static void seterr(char *err, size_t errcap, const char *what, int e)
{
    if (!err || errcap == 0) return;
    if (e) snprintf(err, errcap, "%s: %s", what, strerror(e));
    else snprintf(err, errcap, "%s", what);
}

int ts_hostsfile_read(const char *path, char *buf, size_t cap, size_t *len, char *err, size_t errcap)
{
    struct stat ls, fs;
    size_t got = 0, max = cap < TS_HOSTS_FILE_MAX ? cap : TS_HOSTS_FILE_MAX;
    int fd;

    *len = 0;
    if (lstat(path, &ls) != 0) {
        if (errno == ENOENT) return 0;
        seterr(err, errcap, "cannot read", errno);
        return -1;
    }
    if (!S_ISREG(ls.st_mode)) {
        seterr(err, errcap, "not a regular file", 0);
        return -1;
    }
    if (ls.st_size > (off_t)max) {
        seterr(err, errcap, "too large", 0);
        return -1;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        seterr(err, errcap, "cannot read", errno);
        return -1;
    }
    if (fstat(fd, &fs) != 0 || !S_ISREG(fs.st_mode) || fs.st_dev != ls.st_dev || fs.st_ino != ls.st_ino) {
        close(fd);
        seterr(err, errcap, "not a regular file", 0);
        return -1;
    }
    for (;;) {
        char extra;
        ssize_t n;
        if (got == max) {
            /* Grown past the limit since lstat? */
            n = read(fd, &extra, 1);
            if (n < 0 && errno == EINTR) continue;
            if (n > 0) {
                close(fd);
                seterr(err, errcap, "too large", 0);
                return -1;
            }
            if (n < 0) {
                int e = errno;
                close(fd);
                seterr(err, errcap, "cannot read", e);
                return -1;
            }
            break;
        }
        n = read(fd, buf + got, max - got);
        if (n < 0) {
            int e = errno;
            if (e == EINTR) continue;
            close(fd);
            seterr(err, errcap, "cannot read", e);
            return -1;
        }
        if (n == 0) break;
        got += (size_t)n;
    }
    close(fd);
    *len = got;
    return 0;
}

int ts_hostsfile_write(const char *path, const char *buf, size_t len, char *err, size_t errcap)
{
    struct stat ls;
    char tmp[1024];
    const char *slash = strrchr(path, '/');
    mode_t mode = 0644;
    uid_t uid = 0;
    gid_t gid = 0;
    int exists, fd, e;
    size_t off = 0;

    if (lstat(path, &ls) == 0) {
        if (!S_ISREG(ls.st_mode)) {
            seterr(err, errcap, "not a regular file", 0);
            return -1;
        }
        exists = 1;
        mode = ls.st_mode & 07777;
        uid = ls.st_uid;
        gid = ls.st_gid;
    } else if (errno == ENOENT) {
        exists = 0;
    } else {
        seterr(err, errcap, "cannot write", errno);
        return -1;
    }
    if (!slash) {
        snprintf(tmp, sizeof tmp, ".hosts.tsppc.XXXXXX");
    } else if ((size_t)(slash - path) + 21 > sizeof tmp) {
        seterr(err, errcap, "path too long", 0);
        return -1;
    } else {
        snprintf(tmp, sizeof tmp, "%.*s/.hosts.tsppc.XXXXXX", (int)(slash - path), path);
    }
    fd = mkstemp(tmp);
    if (fd < 0) {
        seterr(err, errcap, "cannot write", errno);
        return -1;
    }
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            goto fail;
        }
        off += (size_t)n;
    }
    if (fchmod(fd, mode) != 0) goto fail;
    /* Root sets any owner; anyone else can only keep their own, which the
     * temp file already has when the file is theirs. */
    if ((exists || geteuid() == 0) && fchown(fd, uid, gid) != 0) {
        struct stat ts;
        if (fstat(fd, &ts) != 0 || ts.st_uid != uid || ts.st_gid != gid) goto fail;
    }
    if (fsync(fd) != 0) goto fail;
    if (close(fd) != 0) {
        fd = -1;
        goto fail;
    }
    fd = -1;
    if (rename(tmp, path) != 0) goto fail;
    return 0;
fail:
    e = errno;
    if (fd >= 0) close(fd);
    unlink(tmp);
    seterr(err, errcap, "cannot write", e);
    return -1;
}

void ts_hostsfile_flush_cache(void)
{
    static const char *const ds[] = { "/usr/bin/dscacheutil", "-flushcache", NULL };
    static const char *const lu[] = { "/usr/sbin/lookupd", "-flushcache", NULL };
    if (access(ds[0], X_OK) == 0) (void)ts_run(ds);
    else if (access(lu[0], X_OK) == 0) (void)ts_run(lu);
}
