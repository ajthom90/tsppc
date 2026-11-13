/* The daemon's log file (logfile.h). No allocation: the path has a fixed
 * buffer. */
#include "logfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PATH_CAP 1024

static char g_path[PATH_CAP];
static int g_open;
static time_t g_failed_at;   /* when rotation last failed (0: it has not) */

static void fail(char *err, size_t cap, const char *what, int e)
{
    if (cap == 0) return;
    if (e) snprintf(err, cap, "log file: %s: %s", what, strerror(e));
    else snprintf(err, cap, "log file: %s", what);
}

/* Open path for appending; returns the descriptor or -1. Tiger's kernel
 * ignores O_NOFOLLOW, so links are refused by lstat first: an existing path
 * must be a regular file and the opened file the same one (device and
 * inode); a missing one is created with O_EXCL, which never follows a link.
 * O_NONBLOCK keeps a FIFO from blocking the open; it is cleared once the
 * file is known to be a regular one. */
static int open_regular(const char *path, char *err, size_t cap)
{
    struct stat ls, sb;
    int fd, existed;
    if (lstat(path, &ls) == 0) {
        if (!S_ISREG(ls.st_mode)) {
            fail(err, cap, "not a regular file", 0);
            return -1;
        }
        existed = 1;
        fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_NONBLOCK);
    } else if (errno == ENOENT) {
        existed = 0;
        fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK, 0644);
    } else {
        fail(err, cap, "cannot open", errno);
        return -1;
    }
    if (fd < 0) {
        fail(err, cap, "cannot open", errno);
        return -1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
        (existed && (sb.st_dev != ls.st_dev || sb.st_ino != ls.st_ino))) {
        close(fd);
        fail(err, cap, "not a regular file", 0);
        return -1;
    }
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    return fd;
}

static int attach(int fd)
{
    if (fd != STDERR_FILENO) {
        if (dup2(fd, STDERR_FILENO) < 0) {
            close(fd);
            return -1;
        }
        close(fd);
    }
    return 0;
}

int ts_logfile_open(const char *path, char *err, size_t cap)
{
    int fd;
    if (strlen(path) >= PATH_CAP) {
        fail(err, cap, "path too long", 0);
        return -1;
    }
    fd = open_regular(path, err, cap);
    if (fd < 0) return -1;
    if (attach(fd) != 0) {
        fail(err, cap, "cannot use it as stderr", errno);
        return -1;
    }
    memcpy(g_path, path, strlen(path) + 1);
    g_open = 1;
    g_failed_at = 0;
    return 0;
}

/* Rotate. 0, or -1 with errno set. */
static int rotate(void)
{
    char old[PATH_CAP + 3];
    int fd;
    snprintf(old, sizeof old, "%s.1", g_path);
    if (rename(g_path, old) != 0) return -1;
    fd = open_regular(g_path, NULL, 0);
    if (fd < 0) return -1;   /* errno is open's, or 0 for a non-regular file */
    return attach(fd);
}

void ts_logfile_check(void)
{
    struct stat sb;
    time_t now;
    char msg[160];
    int e;
    if (!g_open) return;
    if (fstat(STDERR_FILENO, &sb) != 0 || sb.st_size < TS_LOG_MAX) return;
    now = time(NULL);
    /* After a failure, rotation is tried again at most once a second. */
    if (g_failed_at == 0 || now - g_failed_at >= 1 || now < g_failed_at) {
        errno = 0;
        if (rotate() == 0) {
            g_failed_at = 0;
            return;
        }
        e = errno;
        g_failed_at = now;
    } else {
        e = 0;
    }
    /* Still at the cap: start the file over (O_APPEND writes at the end). */
    if (ftruncate(STDERR_FILENO, 0) == 0) {
        snprintf(msg, sizeof msg, "tsppcd: log reset because rotation failed%s%s\n", e ? ": " : "",
                 e ? strerror(e) : "");
        (void)!write(STDERR_FILENO, msg, strlen(msg));
    }
}
