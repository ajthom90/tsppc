/* The daemon's log file (logfile.h). No allocation: the path has a fixed
 * buffer. */
#include "logfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH_CAP 1024

static char g_path[PATH_CAP];
static int g_open;

static void fail(char *err, size_t cap, const char *what, int e)
{
    if (cap == 0) return;
    if (e) snprintf(err, cap, "log file: %s: %s", what, strerror(e));
    else snprintf(err, cap, "log file: %s", what);
}

/* Open path for appending; returns the descriptor or -1. O_NONBLOCK keeps a
 * FIFO from blocking the open; it is cleared once the file is known to be a
 * regular one. */
static int open_regular(const char *path, char *err, size_t cap)
{
    struct stat sb;
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0644);
    if (fd < 0) {
        fail(err, cap, "cannot open", errno);
        return -1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
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
    if (strlen(path) + 3 > PATH_CAP) {
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
    return 0;
}

void ts_logfile_check(void)
{
    struct stat sb;
    char old[PATH_CAP + 3];
    int fd;
    if (!g_open) return;
    if (fstat(STDERR_FILENO, &sb) != 0 || sb.st_size < TS_LOG_MAX) return;
    snprintf(old, sizeof old, "%s.1", g_path);
    (void)rename(g_path, old);
    fd = open_regular(g_path, NULL, 0);
    if (fd >= 0) (void)attach(fd);   /* on failure the old file just goes on growing */
}
