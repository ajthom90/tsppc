#include "harness.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/daemon/ipc.h"
#include "../src/state/store.h"

/* Where the Makefile put tsppcd and tsppc for this target. */
#ifndef TS_BIN_DIR
#define TS_BIN_DIR "build/test"
#endif

static int parse(const char *s, size_t n, ts_ipc_cmd *c)
{
    char *b = (char *)malloc(n ? n : 1);   /* exact size, so ASan sees overreads */
    int rc;
    if (!b) abort();
    memcpy(b, s, n);
    rc = ts_ipc_parse_request(b, n, c);
    free(b);
    return rc;
}

static void test_parse(void)
{
    ts_ipc_cmd c = TS_IPC_LOGOUT;
    char longline[80];
    t_true("ipc: status", parse("status\n", 7, &c) == 0 && c == TS_IPC_STATUS);
    t_true("ipc: up", parse("up\n", 3, &c) == 0 && c == TS_IPC_UP);
    t_true("ipc: ip", parse("ip\n", 3, &c) == 0 && c == TS_IPC_IP);
    t_true("ipc: logout", parse("logout\n", 7, &c) == 0 && c == TS_IPC_LOGOUT);
    t_true("ipc: unknown", parse("down\n", 5, &c) == -1);
    t_true("ipc: prefix of a command", parse("stat\n", 5, &c) == -1);
    t_true("ipc: command with more", parse("statusx\n", 8, &c) == -1);
    t_true("ipc: trailing space", parse("status \n", 8, &c) == -1);
    t_true("ipc: no newline", parse("status", 6, &c) == -1);
    t_true("ipc: two lines", parse("up\nup\n", 6, &c) == -1);
    t_true("ipc: CRLF", parse("up\r\n", 4, &c) == -1);
    t_true("ipc: upper case", parse("UP\n", 3, &c) == -1);
    t_true("ipc: embedded NUL", parse("up\0\n", 4, &c) == -1);
    t_true("ipc: NUL after a command", parse("status\n\0", 8, &c) == -1);
    t_true("ipc: empty", parse("", 0, &c) == -1 && parse("\n", 1, &c) == -1);
    memset(longline, ' ', sizeof longline);
    memcpy(longline, "status", 6);
    longline[64] = '\n';
    t_true("ipc: 65 bytes", parse(longline, 65, &c) == -1);
    t_true("ipc: 64 bytes, still unknown", parse(longline + 1, 64, &c) == -1);
    t_true("ipc: cmd lines round trip",
           parse(ts_ipc_cmd_line(TS_IPC_UP), strlen(ts_ipc_cmd_line(TS_IPC_UP)), &c) == 0 && c == TS_IPC_UP &&
           parse(ts_ipc_cmd_line(TS_IPC_LOGOUT), strlen(ts_ipc_cmd_line(TS_IPC_LOGOUT)), &c) == 0 &&
           c == TS_IPC_LOGOUT);
}

static void test_clean(void)
{
    char out[64];
    const char in[] = "a\x1b[31mb\nc\x7f\xc3\xa9\td";
    size_t n = ts_ipc_clean(out, sizeof out, in, sizeof in - 1, 1);
    t_true("clean: escapes and high bytes replaced, newline kept",
           strcmp(out, "a?[31mb\nc????d") == 0 && n == strlen(out));
    ts_ipc_clean(out, sizeof out, in, sizeof in - 1, 0);
    t_true("clean: newline replaced when not kept", strcmp(out, "a?[31mb?c????d") == 0);
    n = ts_ipc_clean(out, 4, "abcdef", 6, 0);
    t_true("clean: truncated, terminated", n == 3 && strcmp(out, "abc") == 0);
    ts_ipc_clean(out, sizeof out, "x\0y", 3, 0);
    t_true("clean: NUL replaced", strcmp(out, "x?y") == 0);
}

static void test_split(void)
{
    size_t k, v;
    t_true("split: key and value", ts_ipc_split("state RUNNING", 13, &k, &v) == 0 && k == 5 && v == 6);
    t_true("split: key only", ts_ipc_split("ok", 2, &k, &v) == 0 && k == 2 && v == 2);
    t_true("split: value with spaces", ts_ipc_split("peer - online a b", 17, &k, &v) == 0 && k == 4 && v == 5);
    t_true("split: empty key", ts_ipc_split(" x", 2, &k, &v) == -1 && ts_ipc_split("", 0, &k, &v) == -1);
    t_true("split: bad key byte", ts_ipc_split("St x", 4, &k, &v) == -1 && ts_ipc_split("a\x1b x", 4, &k, &v) == -1);
}

/* ---- The listening socket ----------------------------------------------- */

static char tmpdir[64];

static int make_tmpdir(void)
{
    snprintf(tmpdir, sizeof tmpdir, "/tmp/tsppc-t.XXXXXX");
    return mkdtemp(tmpdir) ? 0 : -1;
}

static void test_listen(void)
{
    char path[128], other[128], err[256];
    dev_t dev;
    ino_t ino;
    struct stat sb;
    int fd, fd2, c, f;
    if (make_tmpdir() != 0) {
        t_true("listen: temp dir", 0);
        return;
    }
    snprintf(path, sizeof path, "%s/s", tmpdir);
    fd = ts_ipc_listen(path, getegid(), &dev, &ino, err, sizeof err);
    t_true("listen: created", fd >= 0);
    t_true("listen: a socket, mode 0660", lstat(path, &sb) == 0 && S_ISSOCK(sb.st_mode) &&
           (sb.st_mode & 0777) == 0660 && sb.st_ino == ino);
    c = ts_ipc_connect(path);
    t_true("listen: connectable", c >= 0);
    if (c >= 0) close(c);
    fd2 = ts_ipc_listen(path, getegid(), &dev, &ino, err, sizeof err);
    t_true("listen: a live daemon's socket is refused", fd2 < 0 && strstr(err, "running") != NULL);
    if (fd2 >= 0) close(fd2);
    if (fd >= 0) close(fd);   /* as a crash leaves it: the file stays */
    t_true("listen: stale socket left", lstat(path, &sb) == 0 && S_ISSOCK(sb.st_mode));
    fd = ts_ipc_listen(path, getegid(), &dev, &ino, err, sizeof err);
    t_true("listen: stale socket replaced", fd >= 0);
    ts_ipc_unlink(path, dev, ino);
    t_true("listen: unlink removes our socket", lstat(path, &sb) != 0 && errno == ENOENT);
    if (fd >= 0) close(fd);

    /* A regular file, a symlink and a directory at the path are refused. */
    f = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (f >= 0) close(f);
    fd = ts_ipc_listen(path, getegid(), &dev, &ino, err, sizeof err);
    t_true("listen: regular file refused and kept", fd < 0 && lstat(path, &sb) == 0 && S_ISREG(sb.st_mode));
    if (fd >= 0) close(fd);
    unlink(path);
    snprintf(other, sizeof other, "%s/target", tmpdir);
    t_true("listen: symlink made", symlink(other, path) == 0);
    fd = ts_ipc_listen(path, getegid(), &dev, &ino, err, sizeof err);
    t_true("listen: symlink refused and kept", fd < 0 && lstat(path, &sb) == 0 && S_ISLNK(sb.st_mode));
    if (fd >= 0) close(fd);
    unlink(path);
    t_true("listen: directory made", mkdir(path, 0700) == 0);
    fd = ts_ipc_listen(path, getegid(), &dev, &ino, err, sizeof err);
    t_true("listen: directory refused", fd < 0);
    if (fd >= 0) close(fd);
    rmdir(path);

    /* ts_ipc_unlink leaves a path that is no longer our socket. */
    fd = ts_ipc_listen(path, getegid(), &dev, &ino, err, sizeof err);
    if (fd >= 0) close(fd);
    unlink(path);
    f = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (f >= 0) close(f);
    ts_ipc_unlink(path, dev, ino);
    t_true("listen: unlink keeps what is not ours", lstat(path, &sb) == 0 && S_ISREG(sb.st_mode));
    unlink(path);

    /* A path longer than sun_path. */
    {
        char lp[200];
        memset(lp, 'a', sizeof lp - 1);
        lp[0] = '/';
        lp[sizeof lp - 1] = 0;
        fd = ts_ipc_listen(lp, getegid(), &dev, &ino, err, sizeof err);
        t_true("listen: over-long path refused", fd < 0);
        errno = 0;
        t_true("connect: over-long path refused", ts_ipc_connect(lp) < 0 && errno == ENAMETOOLONG);
    }
    rmdir(tmpdir);
}

/* ---- The daemon and CLI, run as programs --------------------------------- */

static int64_t mono_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);   /* test timing only */
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void nap_ms(int ms)
{
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    select(0, NULL, NULL, NULL, &tv);
}

/* Run tsppc with one argument; its stdout goes to out. Returns its exit status
 * (-1 if it did not exit normally within 60 s). */
static int run_cli(const char *arg, char *out, size_t cap)
{
    int p[2], st;
    size_t len = 0;
    pid_t pid;
    int64_t until = mono_ms() + 60000;
    out[0] = 0;
    if (pipe(p) != 0) return -1;
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        dup2(p[1], 1);
        close(p[0]);
        close(p[1]);
        execl(TS_BIN_DIR "/tsppc", "tsppc", arg, (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    for (;;) {
        ssize_t n;
        fd_set r;
        struct timeval tv = { 1, 0 };
        if (mono_ms() > until) break;
        FD_ZERO(&r);
        FD_SET(p[0], &r);
        if (select(p[0] + 1, &r, NULL, NULL, &tv) <= 0) continue;
        n = read(p[0], out + len, cap - 1 - len);
        if (n <= 0) break;
        len += (size_t)n;
        if (len == cap - 1) break;
    }
    out[len] = 0;
    close(p[0]);
    if (mono_ms() > until) kill(pid, SIGKILL);
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

/* Start tsppcd with the test overrides. stderr goes to logpath. */
static pid_t start_daemon(const char *statedir, const char *sock, const char *logpath)
{
    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            close(fd);
        }
        setenv("TSPPC_STATE_DIR", statedir, 1);
        setenv("TSPPC_SOCKET", sock, 1);
        setenv("TSPPC_CONTROL", "127.0.0.1:1", 1);
        execl(TS_BIN_DIR "/tsppcd", "tsppcd", (char *)NULL);
        _exit(127);
    }
    return pid;
}

/* Wait for a socket at sock other than inode old (0: any). */
static int wait_socket_new(const char *sock, pid_t pid, int ms, ino_t old)
{
    struct stat sb;
    int64_t until = mono_ms() + ms;
    int st;
    while (mono_ms() < until) {
        if (lstat(sock, &sb) == 0 && S_ISSOCK(sb.st_mode) && sb.st_ino != old) return 0;
        if (waitpid(pid, &st, WNOHANG) == pid) return -1;
        nap_ms(50);
    }
    return -1;
}

static int wait_socket(const char *sock, pid_t pid, int ms)
{
    return wait_socket_new(sock, pid, ms, 0);
}

/* Exit status of pid within ms, or -1 (then it is killed). */
static int wait_exit(pid_t pid, int ms)
{
    int64_t until = mono_ms() + ms;
    int st;
    while (mono_ms() < until) {
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        nap_ms(50);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    return -1;
}

/* Send raw bytes, return what the daemon answered before closing. */
static void raw_request(const char *sock, const char *req, size_t n, char *out, size_t cap)
{
    int fd = ts_ipc_connect(sock);
    size_t len = 0;
    int64_t until = mono_ms() + 30000;
    out[0] = 0;
    if (fd < 0) return;
    if (n) (void)write(fd, req, n);
    while (len + 1 < cap && mono_ms() < until) {
        fd_set r;
        struct timeval tv = { 1, 0 };
        ssize_t k;
        FD_ZERO(&r);
        FD_SET(fd, &r);
        if (select(fd + 1, &r, NULL, NULL, &tv) <= 0) continue;
        k = read(fd, out + len, cap - 1 - len);
        if (k <= 0) break;
        len += (size_t)k;
    }
    out[len] = 0;
    close(fd);
}

static void test_daemon(void)
{
    char statedir[128], sock[128], logpath[128], out[4096], longreq[100];
    ts_state saved, after;
    struct stat sb;
    pid_t pid;
    int rc, i, idle[TS_IPC_MAX_CLIENTS];
    int64_t until;

    if (access(TS_BIN_DIR "/tsppcd", X_OK) != 0 || access(TS_BIN_DIR "/tsppc", X_OK) != 0) {
        printf("SKIP: daemon tests (no " TS_BIN_DIR "/tsppcd or tsppc here)\n");
        return;
    }
    if (make_tmpdir() != 0) {
        t_true("daemon: temp dir", 0);
        return;
    }
    snprintf(statedir, sizeof statedir, "%s/state", tmpdir);
    snprintf(sock, sizeof sock, "%s/sock", tmpdir);
    snprintf(logpath, sizeof logpath, "%s/log", tmpdir);
    setenv("TSPPC_SOCKET", sock, 1);

    /* A saved login with an old key, for the logout check below. */
    {
        char err[256];
        rc = ts_state_load_or_create(&saved, statedir, err, sizeof err);
        saved.have_login = 1;
        saved.have_old_node = 1;
        memset(saved.old_node_priv, 0x42, 32);
        t_true("daemon: saved login written", rc == 0 && ts_state_save(&saved, statedir, err, sizeof err) == 0);
    }

    /* A path held by a regular file: refused, file kept. */
    rc = open(sock, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (rc >= 0) close(rc);
    pid = start_daemon(statedir, sock, logpath);
    t_true("daemon: refuses a socket path held by a file", wait_exit(pid, 60000) == 1);
    t_true("daemon: the file is kept", lstat(sock, &sb) == 0 && S_ISREG(sb.st_mode));
    unlink(sock);

    pid = start_daemon(statedir, sock, logpath);
    t_true("daemon: socket appears", wait_socket(sock, pid, 120000) == 0);

    /* The key fetch cannot reach 127.0.0.1:1, so status reports BACKOFF. */
    until = mono_ms() + 60000;
    do {
        rc = run_cli("status", out, sizeof out);
        if (strstr(out, "BACKOFF")) break;
        nap_ms(200);
    } while (mono_ms() < until);
    t_true("daemon: status reports BACKOFF", rc == 0 && strstr(out, "BACKOFF") != NULL);
    t_true("daemon: status has a problem line", strstr(out, "Problem:") != NULL);
    rc = run_cli("ip", out, sizeof out);
    t_true("daemon: ip without an address fails", rc == 1);
    rc = run_cli("bogus", out, sizeof out);
    t_true("daemon: CLI rejects an unknown command", rc == 2);

    /* Idle clients fill every slot; they must not block the loop, and the
     * next client is turned away rather than queued. */
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++) idle[i] = ts_ipc_connect(sock);
    nap_ms(300);
    raw_request(sock, "status\n", 7, out, sizeof out);
    t_true("daemon: a client over the limit is turned away", strstr(out, "state ") == NULL);
    for (i = 0; i < TS_IPC_MAX_CLIENTS; i++)
        if (idle[i] >= 0) close(idle[i]);
    nap_ms(300);
    raw_request(sock, "status\n", 7, out, sizeof out);
    t_true("daemon: raw status reply", strncmp(out, "ok\nstate BACKOFF\n", 17) == 0);
    memset(longreq, 'x', sizeof longreq);
    raw_request(sock, longreq, sizeof longreq, out, sizeof out);
    t_true("daemon: an over-long request is an error", strncmp(out, "error ", 6) == 0 && !strstr(out, "state"));
    raw_request(sock, "down\n", 5, out, sizeof out);
    t_true("daemon: an unknown request is an error", strncmp(out, "error ", 6) == 0);
    raw_request(sock, "st\0us\n", 6, out, sizeof out);
    t_true("daemon: a request with a NUL is an error", strncmp(out, "error ", 6) == 0);

    /* A client that never sends is dropped after the timeout. */
    {
        int fd = ts_ipc_connect(sock);
        int64_t t0 = mono_ms();
        raw_request(sock, "", 0, out, sizeof out);   /* waits for the close */
        t_true("daemon: a silent client is closed after the timeout",
               mono_ms() - t0 >= TS_IPC_CLIENT_TIMEOUT_MS - 1000 && mono_ms() - t0 < TS_IPC_CLIENT_TIMEOUT_MS + 20000);
        if (fd >= 0) close(fd);
    }

    /* Logout while control cannot be reached (no control key): the login is
     * forgotten here at once, and the CLI says control was not reached. */
    raw_request(sock, "status\n", 7, out, sizeof out);
    t_true("daemon: saved login shown", strstr(out, "\nlogin yes\n") != NULL);
    rc = run_cli("logout", out, sizeof out);
    t_true("daemon: logout without control succeeds", rc == 0 && strstr(out, "not reached") != NULL);
    {
        char err[256];
        t_true("daemon: logout cleared the saved state",
               ts_state_load_or_create(&after, statedir, err, sizeof err) == 0 && !after.have_login &&
               !after.have_old_node && memcmp(after.node_priv, saved.node_priv, 32) != 0 &&
               memcmp(after.machine_priv, saved.machine_priv, 32) == 0);
    }

    kill(pid, SIGTERM);
    t_true("daemon: SIGTERM exits cleanly", wait_exit(pid, 60000) == 0);
    t_true("daemon: SIGTERM removes the socket", lstat(sock, &sb) != 0 && errno == ENOENT);
    t_true("daemon: CLI reports no daemon", run_cli("status", out, sizeof out) == 1);

    /* Started again over a socket left by a crash. */
    pid = start_daemon(statedir, sock, logpath);
    t_true("daemon: restarts", wait_socket(sock, pid, 120000) == 0);
    kill(pid, SIGKILL);
    wait_exit(pid, 60000);
    t_true("daemon: crash leaves the socket", lstat(sock, &sb) == 0 && S_ISSOCK(sb.st_mode));
    pid = start_daemon(statedir, sock, logpath);
    t_true("daemon: replaces a stale socket", wait_socket_new(sock, pid, 120000, sb.st_ino) == 0 &&
           run_cli("status", out, sizeof out) == 0);
    kill(pid, SIGINT);
    t_true("daemon: SIGINT exits cleanly", wait_exit(pid, 60000) == 0 && lstat(sock, &sb) != 0);

    /* The log names no keys. */
    {
        FILE *f = fopen(logpath, "r");
        char line[512];
        int bad = 0;
        while (f && fgets(line, sizeof line, f))
            if (strstr(line, "key:") || strstr(line, "privkey")) bad = 1;
        if (f) fclose(f);
        t_true("daemon: log holds no keys", !bad);
    }

    unsetenv("TSPPC_SOCKET");
    unlink(logpath);
    unlink(sock);
    {
        char p[160];
        snprintf(p, sizeof p, "%s/%s", statedir, "state.bin");
        unlink(p);
    }
    rmdir(statedir);
    rmdir(tmpdir);
}

void test_ipc(void)
{
    test_parse();
    test_clean();
    test_split();
    test_listen();
    test_daemon();
}
