/* The daemon's log file: rotation by size, and refusing a symlink. */
#include "harness.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/daemon/logfile.h"

#define LINE 100

/* Every line of path is LINE bytes with its number; returns the lines, -1 if
 * one is split or malformed. *first gets the first number. */
static long check_file(const char *path, long *first)
{
    FILE *f = fopen(path, "r");
    char buf[LINE + 8];
    long n = 0, prev = -1;
    if (!f) return -1;
    while (fgets(buf, sizeof buf, f)) {
        long v;
        if (strlen(buf) != LINE || buf[LINE - 1] != '\n' || sscanf(buf, "L%ld ", &v) != 1) {
            fclose(f);
            return -1;
        }
        if (prev >= 0 && v != prev + 1) {
            fclose(f);
            return -1;
        }
        if (n == 0) *first = v;
        prev = v;
        n++;
    }
    fclose(f);
    return n;
}

static void test_rotates(void)
{
    char dir[64] = "/tmp/tsppc-log-XXXXXX", path[128], old[136], err[200], line[LINE + 1];
    int saved = dup(STDERR_FILENO), i, total = (3 * TS_LOG_MAX / 2) / LINE;
    struct stat a, b;
    long f1 = 0, f2 = 0, n1, n2;

    if (!mkdtemp(dir) || saved < 0) {
        t_true("logfile: rotates (setup)", 0);
        return;
    }
    umask(022);
    snprintf(path, sizeof path, "%s/log", dir);
    snprintf(old, sizeof old, "%s.1", path);
    t_true("logfile: check with no file open does nothing", (ts_logfile_check(), 1));
    t_true("logfile: open", ts_logfile_open(path, err, sizeof err) == 0);
    for (i = 0; i < total; i++) {
        int n = snprintf(line, sizeof line, "L%d ", i);
        memset(line + n, 'x', LINE - 1 - n);
        line[LINE - 1] = '\n';
        (void)!write(STDERR_FILENO, line, LINE);
        ts_logfile_check();
    }
    dup2(saved, STDERR_FILENO);
    close(saved);
    t_true("logfile: rotated file exists", stat(old, &a) == 0 && S_ISREG(a.st_mode));
    t_true("logfile: current file exists and is below the cap plus a line",
           stat(path, &b) == 0 && b.st_size > 0 && b.st_size < TS_LOG_MAX + LINE);
    t_true("logfile: mode 0644", (b.st_mode & 0777) == 0644);
    n1 = check_file(old, &f1);
    n2 = check_file(path, &f2);
    t_true("logfile: no line split across the files", n1 > 0 && n2 > 0 && f2 == f1 + n1 && f2 + n2 == total);
    unlink(path);
    unlink(old);
    rmdir(dir);
}

static void test_symlink(void)
{
    char dir[64] = "/tmp/tsppc-log-XXXXXX", path[128], target[128], err[200];
    int saved = dup(STDERR_FILENO), fd;
    struct stat sb;

    if (!mkdtemp(dir) || saved < 0) {
        t_true("logfile: refuses symlink (setup)", 0);
        return;
    }
    snprintf(path, sizeof path, "%s/log", dir);
    snprintf(target, sizeof target, "%s/target", dir);
    fd = open(target, O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) close(fd);
    t_true("logfile: symlink made", symlink(target, path) == 0);
    t_true("logfile: refuses symlink", ts_logfile_open(path, err, sizeof err) == -1 && err[0]);
    t_true("logfile: stderr untouched by the refusal", fstat(STDERR_FILENO, &sb) == 0);
    unlink(path);
    t_true("logfile: refuses a directory", mkdir(path, 0700) == 0 && ts_logfile_open(path, err, sizeof err) == -1);
    rmdir(path);
    dup2(saved, STDERR_FILENO);
    close(saved);
    unlink(target);
    rmdir(dir);
}

/* <path>.1 is a non-empty directory: the rename never works. The log must
 * still stay within the cap. */
static void test_rotation_fails(void)
{
    char dir[64] = "/tmp/tsppc-log-XXXXXX", path[128], old[136], inner[160], err[200], line[LINE + 1];
    int saved = dup(STDERR_FILENO), i, total = (3 * TS_LOG_MAX / 2) / LINE, fd;
    struct stat sb;
    off_t big = 0;

    if (!mkdtemp(dir) || saved < 0) {
        t_true("logfile: failed rotation (setup)", 0);
        return;
    }
    snprintf(path, sizeof path, "%s/log", dir);
    snprintf(old, sizeof old, "%s.1", path);
    snprintf(inner, sizeof inner, "%s/x", old);
    mkdir(old, 0700);
    fd = open(inner, O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) close(fd);
    t_true("logfile: failed rotation: open", ts_logfile_open(path, err, sizeof err) == 0);
    for (i = 0; i < total; i++) {
        int n = snprintf(line, sizeof line, "L%d ", i);
        memset(line + n, 'x', LINE - 1 - n);
        line[LINE - 1] = '\n';
        (void)!write(STDERR_FILENO, line, LINE);
        ts_logfile_check();
        if (fstat(STDERR_FILENO, &sb) == 0 && sb.st_size > big) big = sb.st_size;
    }
    dup2(saved, STDERR_FILENO);
    close(saved);
    t_true("logfile: failed rotation: the file never exceeds the cap plus a line", big > 0 && big <= TS_LOG_MAX + LINE);
    {
        FILE *f = fopen(path, "r");
        char buf[256];
        int seen = 0;
        while (f && fgets(buf, sizeof buf, f)) if (strstr(buf, "log reset because rotation failed")) seen = 1;
        if (f) fclose(f);
        t_true("logfile: failed rotation: the reset is logged", seen);
    }
    unlink(inner);
    rmdir(old);
    unlink(path);
    rmdir(dir);
}

void test_logfile(void)
{
    test_rotation_fails();
    test_rotates();
    test_symlink();
}
