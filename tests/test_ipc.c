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
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/control/session.h"
#include "../src/daemon/ipc.h"
#include "../src/core/bytes.h"
#include "../src/crypto/nacl.h"
#include "../src/crypto/x25519.h"
#include "../src/derp/derp.h"
#include "../src/disco/disco.h"
#include "../src/names/hosts.h"
#include "../src/proto/encoding.h"
#include "../src/state/store.h"

#include "fake_control.inc"
#include "fake_relay.inc"

/* Where the Makefile put tsppcd and tsppc for this target. */
#ifndef TS_BIN_DIR
#define TS_BIN_DIR "build/test"
#endif

static ts_ipc_args g_args;

static int parse(const char *s, size_t n, ts_ipc_cmd *c)
{
    char *b = (char *)malloc(n ? n : 1);   /* exact size, so ASan sees overreads */
    int rc;
    if (!b) abort();
    memcpy(b, s, n);
    memset(&g_args, 0x5a, sizeof g_args);
    rc = ts_ipc_parse_request(b, n, c, &g_args);
    free(b);
    return rc;
}

static int pp(const char *s)
{
    ts_ipc_cmd c = TS_IPC_STATUS;
    return parse(s, strlen(s), &c) == 0 && c == TS_IPC_PING ? 0 : -1;
}

/* The ping request: a dotted quad and a timeout, nothing else. */
static void test_parse_ping(void)
{
    char line[80];
    int n;
    ts_ipc_cmd c;
    uint32_t a;
    t_true("ipc ping: valid", pp("ping 100.64.0.2 5000\n") == 0 && g_args.ip == 0x64400002u &&
           g_args.timeout_ms == 5000);
    t_true("ipc ping: bounds of the timeout", pp("ping 1.2.3.4 100\n") == 0 && g_args.timeout_ms == 100 &&
           pp("ping 1.2.3.4 10000\n") == 0 && g_args.timeout_ms == 10000);
    t_true("ipc ping: timeout out of range", pp("ping 1.2.3.4 99\n") == -1 && pp("ping 1.2.3.4 10001\n") == -1 &&
           pp("ping 1.2.3.4 0\n") == -1 && pp("ping 1.2.3.4 99999999999999999999\n") == -1 &&
           pp("ping 1.2.3.4 -100\n") == -1 && pp("ping 1.2.3.4 +100\n") == -1);
    t_true("ipc ping: timeout with a leading zero", pp("ping 1.2.3.4 0100\n") == -1 && pp("ping 1.2.3.4 05000\n") == -1);
    t_true("ipc ping: edge addresses", pp("ping 0.0.0.0 100\n") == 0 && g_args.ip == 0 &&
           pp("ping 255.255.255.255 100\n") == 0 && g_args.ip == 0xffffffffu);
    t_true("ipc ping: bad addresses", pp("ping 256.1.1.1 100\n") == -1 && pp("ping 1.2.3 100\n") == -1 &&
           pp("ping 1.2.3.4.5 100\n") == -1 && pp("ping 1..2.3 100\n") == -1 && pp("ping .1.2.3 100\n") == -1 &&
           pp("ping 1.2.3. 100\n") == -1 && pp("ping 1.2.3.4a 100\n") == -1 && pp("ping ::1 100\n") == -1 &&
           pp("ping peer 100\n") == -1 && pp("ping 1000.1.1.1 100\n") == -1);
    t_true("ipc ping: leading zeros in the address", pp("ping 01.2.3.4 100\n") == -1 &&
           pp("ping 1.2.3.04 100\n") == -1 && pp("ping 1.00.3.4 100\n") == -1);
    t_true("ipc ping: spaces", pp("ping  1.2.3.4 100\n") == -1 && pp("ping 1.2.3.4  100\n") == -1 &&
           pp("ping 1.2.3.4 100 \n") == -1 && pp(" ping 1.2.3.4 100\n") == -1 && pp("ping\t1.2.3.4 100\n") == -1 &&
           pp("ping 1.2.3.4\n") == -1 && pp("ping\n") == -1 && pp("ping 1.2.3.4 100 7\n") == -1);
    t_true("ipc ping: no newline, CRLF, NUL", parse("ping 1.2.3.4 100", 16, &c) == -1 &&
           pp("ping 1.2.3.4 100\r\n") == -1 && parse("ping 1.2.3.4 100\n\0", 18, &c) == -1 &&
           parse("ping 1.2.3.4\0" "100\n", 17, &c) == -1 && pp("PING 1.2.3.4 100\n") == -1);
    /* Over-long: padded with digits past TS_IPC_LINE_MAX. */
    memset(line, '1', sizeof line);
    memcpy(line, "ping 1.2.3.4 ", 13);
    line[64] = '\n';
    t_true("ipc ping: over-long", parse(line, 65, &c) == -1);
    t_true("ipc ping: the other commands zero the arguments",
           parse("status\n", 7, &c) == 0 && g_args.ip == 0 && g_args.timeout_ms == 0);
    n = ts_ipc_ping_line(line, sizeof line, 0x64400002u, 5000);
    t_true("ipc ping: line format", n == 21 && strcmp(line, "ping 100.64.0.2 5000\n") == 0);
    n = ts_ipc_ping_line(line, sizeof line, 0xffffffffu, 10000);
    t_true("ipc ping: longest line fits the limit", n > 0 && (size_t)n <= TS_IPC_LINE_MAX &&
           pp(line) == 0 && g_args.ip == 0xffffffffu && g_args.timeout_ms == 10000);
    t_true("ipc ping: line refuses a bad timeout or a small buffer",
           ts_ipc_ping_line(line, sizeof line, 1, 99) == -1 && ts_ipc_ping_line(line, sizeof line, 1, 10001) == -1 &&
           ts_ipc_ping_line(line, 10, 1, 100) == -1);
    t_true("ipc ping: cmd line for ping is empty", strcmp(ts_ipc_cmd_line(TS_IPC_PING), "") == 0);
    t_true("ipv4: parse", ts_ipc_parse_ipv4("100.64.0.2", 10, &a) == 0 && a == 0x64400002u &&
           ts_ipc_parse_ipv4("100.64.0.25", 10, &a) == 0 && a == 0x64400002u &&
           ts_ipc_parse_ipv4("", 0, &a) == -1 && ts_ipc_parse_ipv4("1.2.3.04", 8, &a) == -1);
}

static void test_parse(void)
{
    ts_ipc_cmd c = TS_IPC_LOGOUT;
    char longline[80];
    t_true("ipc: status", parse("status\n", 7, &c) == 0 && c == TS_IPC_STATUS);
    t_true("ipc: up", parse("up\n", 3, &c) == 0 && c == TS_IPC_UP);
    t_true("ipc: ip", parse("ip\n", 3, &c) == 0 && c == TS_IPC_IP);
    t_true("ipc: logout", parse("logout\n", 7, &c) == 0 && c == TS_IPC_LOGOUT);
    t_true("ipc: down", parse("down\n", 5, &c) == 0 && c == TS_IPC_DOWN);
    t_true("ipc: unknown", parse("sideways\n", 9, &c) == -1);
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

/* Run tsppc with arguments (NULL-terminated, after the program name); its
 * stdout and stderr go to out. Returns its exit status (-1 if it did not
 * exit normally within 60 s). */
static int run_cli_v(const char *const *args, char *out, size_t cap)
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
        dup2(p[1], 2);   /* messages are checked too, and kept out of the test output */
        close(p[0]);
        close(p[1]);
        {
            char *v[16];
            int k = 0;
            v[k++] = (char *)"tsppc";
            while (args[k - 1] && k < 15) {
                v[k] = (char *)args[k - 1];
                k++;
            }
            v[k] = NULL;
            execv(TS_BIN_DIR "/tsppc", v);
        }
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

static int run_cli(const char *arg, char *out, size_t cap)
{
    const char *v[2];
    v[0] = arg;
    v[1] = NULL;
    return run_cli_v(v, out, cap);
}

/* Start tsppcd with the test overrides: control at localhost:1 (refused), and
 * control's key given (no key fetch) when key is not NULL. Its output is
 * appended to logpath. */
static int g_ctl_port = 1;

static pid_t start_daemon(const char *statedir, const char *sock, const char *logpath, const char *key)
{
    char ctl[64], hosts[128];
    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            close(fd);
        }
        setenv("TSPPC_STATE_DIR", statedir, 1);
        setenv("TSPPC_SOCKET", sock, 1);
        snprintf(ctl, sizeof ctl, "localhost:%d", g_ctl_port);
        setenv("TSPPC_CONTROL", ctl, 1);
        /* Never the real tun, route or ifconfig, even as root on the VM; relays
         * in these tests are plain TCP. */
        setenv("TSPPC_NO_TUN", "1", 1);
        setenv("TSPPC_DERP_PLAIN", "1", 1);
        /* Never the real /etc/hosts either. */
        snprintf(hosts, sizeof hosts, "%s/hosts", tmpdir);
        setenv("TSPPC_HOSTS_FILE", hosts, 1);
        if (key) setenv("TSPPC_CONTROL_KEY", key, 1);
        else unsetenv("TSPPC_CONTROL_KEY");
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

/* Wait until a raw status reply contains want. */
static int wait_status(const char *sock, const char *want, char *out, size_t cap, int ms)
{
    int64_t until = mono_ms() + ms;
    do {
        raw_request(sock, "status\n", 7, out, cap);
        if (strstr(out, want)) return 1;
        nap_ms(200);
    } while (mono_ms() < until);
    return 0;
}

static int load_state(const char *dir, ts_state *st)
{
    char err[256];
    return ts_state_load_or_create(st, dir, err, sizeof err);
}

/* The log holds none of these private keys, in hex. */
static int log_has_key(const char *logpath, const uint8_t *const *keys, int n)
{
    FILE *f = fopen(logpath, "r");
    char line[1024], hex[65];
    int i, bad = 0;
    while (f && fgets(line, sizeof line, f)) {
        if (strstr(line, "privkey")) bad = 1;
        for (i = 0; i < n; i++) {
            ts_hex_encode(hex, sizeof hex, keys[i], 32);
            if (strstr(line, hex)) bad = 1;
        }
    }
    if (f) fclose(f);
    return bad;
}

#define FAKE_CONTROL_KEY "4c3d1a8e0f2b7c6d5e4f30211203f4e5d6c7b8a99a8b7c6d5e4f3021120314e5"


/* ---- A fake control server on a real socket --------------------------- */

#define SELFNAME "self.example.test"
#define HA "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define MAP_JSON "{\"Node\":{\"ID\":1,\"Name\":\"" SELFNAME ".\",\"Key\":\"nodekey:" HA "\"," \
    "\"Addresses\":[\"100.64.0.1/32\"],\"MachineAuthorized\":true},\"Peers\":[{\"ID\":2,\"Name\":\"peer.example.test.\"," \
    "\"Key\":\"nodekey:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"," \
    "\"Addresses\":[\"100.64.0.2/32\"],\"Online\":true,\"MachineAuthorized\":true}]}"

static void fk_handler(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) fk_reply(f, r, 200, "{\"MachineAuthorized\":true}");
    else if (strcmp(r->path, "/machine/map") == 0) {
        fk_headers(f, r, 200, NULL, 0, 0);
        fk_map_msg(f, r, MAP_JSON);
    }
}

/* The server child: one connection at a time on lfd, each answered by the
 * fake (plain TCP: the daemon uses TLS only on port 443). Every accepted
 * connection appends a byte to countpath. */
static void fake_server(int lfd, fake *f, const char *countpath)
{
    int nul = open("/dev/null", O_RDWR);
    /* Never hold the test's stdout open if the test dies: no orphan. */
    if (nul >= 0) {
        dup2(nul, 1);
        dup2(nul, 2);
        if (nul > 2) close(nul);
    }
    alarm(600);
    for (;;) {
        int fd = accept(lfd, NULL, NULL), cf;
        if (fd < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (getppid() == 1) return;
        cf = open(countpath, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (cf >= 0) {
            (void)write(cf, "x", 1);
            close(cf);
        }
        f->up = 1;
        f->conn++;
        fk_conn_reset(f);
        f->nreq = 0;
        for (;;) {
            uint8_t buf[4096];
            ssize_t n = read(fd, buf, sizeof buf);
            if (n <= 0) break;
            fk_append(&f->c2s, &f->c2s_len, &f->c2s_cap, buf, (size_t)n);
            while (fk_process(f)) {}
            if (f->s2c_len) {
                size_t off = 0;
                while (off < f->s2c_len) {
                    ssize_t w = write(fd, f->s2c + off, f->s2c_len - off);
                    if (w <= 0) break;
                    off += (size_t)w;
                }
                fk_consume(f->s2c, &f->s2c_len, f->s2c_len);
            }
        }
        close(fd);
    }
}

static long file_size(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0 ? (long)sb.st_size : 0;
}

static void remove_test_files(const char *statedir, const char *sock, const char *logpath, const char *countpath)
{
    char p[160];
    unlink(logpath);
    unlink(countpath);
    unlink(sock);
    snprintf(p, sizeof p, "%s/%s", statedir, "state.bin");
    unlink(p);
    snprintf(p, sizeof p, "%s/hosts", tmpdir);
    unlink(p);
    rmdir(statedir);
    rmdir(tmpdir);
}

/* up, down and what status says about it, against the fake control server. */
static void test_daemon_down(void)
{
    static fake f;
    char statedir[128], sock[128], logpath[128], countpath[128], key[65], out[8192], out2[8192], err[256];
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    ts_state st, after;
    pid_t pid, srv;
    int lfd, rc;
    long conns;

    if (access(TS_BIN_DIR "/tsppcd", X_OK) != 0 || access(TS_BIN_DIR "/tsppc", X_OK) != 0) {
        printf("SKIP: down tests (no " TS_BIN_DIR "/tsppcd or tsppc here)\n");
        return;
    }
    if (make_tmpdir() != 0) {
        t_true("down: temp dir", 0);
        return;
    }
    snprintf(statedir, sizeof statedir, "%s/state", tmpdir);
    snprintf(sock, sizeof sock, "%s/sock", tmpdir);
    snprintf(logpath, sizeof logpath, "%s/log", tmpdir);
    snprintf(countpath, sizeof countpath, "%s/conns", tmpdir);
    setenv("TSPPC_SOCKET", sock, 1);

    rc = load_state(statedir, &st);
    st.have_login = 1;
    t_true("down: saved login written", rc == 0 && ts_state_save(&st, statedir, err, sizeof err) == 0);

    fk_init(&f, NULL, "");
    f.handler = fk_handler;
    ts_hex_encode(key, sizeof key, f.control_pub, 32);
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(lfd, 4) != 0 ||
        getsockname(lfd, (struct sockaddr *)&sa, &sl) != 0) {
        t_true("down: fake control listens", 0);
        if (lfd >= 0) close(lfd);
        unsetenv("TSPPC_SOCKET");
        remove_test_files(statedir, sock, logpath, countpath);
        return;
    }
    g_ctl_port = ntohs(sa.sin_port);
    srv = fork();
    if (srv == 0) {
        fake_server(lfd, &f, countpath);
        _exit(0);
    }
    close(lfd);

    pid = start_daemon(statedir, sock, logpath, key);
    t_true("down: socket appears", wait_socket(sock, pid, 120000) == 0);
    t_true("down: logged in, connects and runs", wait_status(sock, "state RUNNING\n", out, sizeof out, 120000));
    t_true("down: running, wanted up", strstr(out, "\nwanted up\n") != NULL);
    t_true("down: status has the self name", strstr(out, "\nself " SELFNAME ".\n") != NULL);
    t_true("down: no url while running", strstr(out, "\nurl ") == NULL);
    t_true("down: running shows ip and peer", strstr(out, "\nip 100.64.0.1\n") != NULL &&
           strstr(out, "\npeer 100.64.0.2 online peer.example.test.\n") != NULL);

    rc = run_cli("down", out, sizeof out);
    t_true("down: the command says so and exits 0", rc == 0 && strstr(out, "Disconnected. Run tsppc up to connect again.") != NULL);
    t_true("down: goes IDLE", wait_status(sock, "state IDLE\n", out, sizeof out, 60000));
    t_true("down: wanted down, still logged in", strstr(out, "\nwanted down\n") && strstr(out, "\nlogin yes\n"));
    rc = run_cli("status", out, sizeof out);
    t_true("down: tsppc status says disconnected", rc == 0 && strstr(out, "Disconnected (tsppc up to connect)") != NULL);
    t_true("down: saved as down", load_state(statedir, &after) == 0 && after.have_login && after.down);
    t_true("down: no stale self, ip or peer", !strstr(out, "\nself ") && !strstr(out, "\nip ") && !strstr(out, "\npeer "));
    rc = run_cli("status", out, sizeof out);
    t_true("down: tsppc status shows no address or peers", rc == 0 && !strstr(out, "Tailnet IP") && !strstr(out, "Peers:"));
    rc = run_cli("ip", out, sizeof out);
    t_true("down: tsppc ip has no address", rc == 1 && strstr(out, "no tailnet IP") != NULL && !strstr(out, "100.64.0.1"));

    kill(pid, SIGTERM);
    t_true("down: daemon exits", wait_exit(pid, 60000) == 0);
    conns = file_size(countpath);
    pid = start_daemon(statedir, sock, logpath, key);
    t_true("down: restart", wait_socket(sock, pid, 120000) == 0);
    t_true("down: restart stays down", wait_status(sock, "state IDLE\n", out, sizeof out, 60000) &&
           strstr(out, "\nwanted down\n") && strstr(out, "\nlogin yes\n"));
    nap_ms(1500);
    t_true("down: restart makes no connection", file_size(countpath) == conns);

    raw_request(sock, "up\n", 3, out, sizeof out);
    t_true("down: up accepted", strncmp(out, "ok\n", 3) == 0);
    t_true("down: up reaches RUNNING", wait_status(sock, "state RUNNING\n", out, sizeof out, 120000));
    t_true("down: up shows wanted up and no url", strstr(out, "\nwanted up\n") && !strstr(out, "\nurl "));
    t_true("down: up cleared the saved down", load_state(statedir, &after) == 0 && after.have_login && !after.down);

    kill(pid, SIGTERM);
    wait_exit(pid, 60000);
    /* A failed save of down: an error, still wanted up, nothing saved. (Root
     * writes to a read-only directory anyway.) */
    if (geteuid() != 0) {
        pid = start_daemon(statedir, sock, logpath, key);
        t_true("down: restart for the failed save", wait_socket(sock, pid, 120000) == 0);
        t_true("down: running again", wait_status(sock, "state RUNNING\n", out, sizeof out, 120000));
        chmod(statedir, 0500);
        raw_request(sock, "down\n", 5, out, sizeof out);
        rc = run_cli("down", out2, sizeof out2);
        chmod(statedir, 0700);
        t_true("down: a failed save is an error line", strncmp(out, "error ", 6) == 0 && strstr(out, "down failed"));
        t_true("down: tsppc down exits 1 and says so", rc == 1 && strstr(out2, "down failed"));
        raw_request(sock, "status\n", 7, out, sizeof out);
        t_true("down: failed save left it up", strstr(out, "\nwanted up\n") && strstr(out, "\nstate RUNNING\n"));
        t_true("down: failed save saved nothing", load_state(statedir, &after) == 0 && after.have_login && !after.down);
        kill(pid, SIGTERM);
        wait_exit(pid, 60000);
    } else {
        printf("SKIP: failed-save down (root)\n");
    }

    kill(srv, SIGKILL);
    waitpid(srv, NULL, 0);
    ts_wipe(&st, sizeof st);
    ts_wipe(&after, sizeof after);
    unsetenv("TSPPC_SOCKET");
    remove_test_files(statedir, sock, logpath, countpath);
}

/* ---- The data plane: a fake relay and home selection --------------------- */

#define RELAY_REGION 7
#define DEAD_REGION 9
static char g_relay_map[2048];   /* the map, with the fake relay's port */
static char g_lites_path[128];   /* the fake control appends each lite update's body here */

/* Like fk_handler, but lite map updates (Stream false) are recorded and
 * answered 200, and the stream gets g_relay_map. */
static void fk_relay_handler(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) {
        fk_reply(f, r, 200, "{\"MachineAuthorized\":true}");
    } else if (strcmp(r->path, "/machine/map") == 0 && r->body && strstr(r->body, "\"Stream\":false")) {
        int fd = open(g_lites_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            (void)write(fd, r->body, strlen(r->body));
            (void)write(fd, "\n", 1);
            close(fd);
        }
        fk_reply(f, r, 200, "");
    } else if (strcmp(r->path, "/machine/map") == 0) {
        fk_headers(f, r, 200, NULL, 0, 0);
        fk_map_msg(f, r, g_relay_map);
    }
}

static void note(const char *path, const char *what)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        (void)write(fd, what, strlen(what));
        close(fd);
    }
}

/* The fake relay (fake_relay.inc) in a child process; events are appended
 * to evpath: 'u' upgraded, 'r' ServerInfo sent, 'P'/'p' NotePreferred 1/0,
 * 'e' closed after the upgrade, 'b' a broken ClientInfo. */
/* The peer the fake relay plays (test_daemon_ping): SendPackets to its node
 * key that hold a disco ping sealed to its disco key get a pong back from it. */
static int g_relay_answers;
static uint8_t g_ans_node[32], g_ans_disco_priv[32], g_ans_disco_pub[32];

static void relay_answer(void *ctx, int fd, const uint8_t *body, size_t len)
{
    ts_disco_shared sh;
    ts_disco_msg m;
    uint8_t out[32 + TS_DISCO_PONG_LEN], nonce[24];
    static const uint8_t src[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 3, 3, 40 };
    const uint8_t *pkt = body + 32;
    size_t n = len - 32;
    int k;
    (void)ctx;
    if (!g_relay_answers || len < 32 || memcmp(body, g_ans_node, 32) != 0 || !ts_disco_looks_like(pkt, n)) return;
    ts_disco_shared_init(&sh, g_ans_disco_priv, ts_disco_sender(pkt));
    if (ts_disco_open(&m, pkt, n, &sh) != 0 || m.type != TS_DISCO_PING) return;
    memset(nonce, 0x77, sizeof nonce);
    memcpy(out, g_ans_node, 32);
    k = ts_disco_seal_pong(out + 32, sizeof out - 32, g_ans_disco_pub, &sh, nonce, m.txid, src, RELAY_REGION);
    if (k > 0) fr_frame(fd, TS_DERP_RECV_PACKET, out, 32 + (size_t)k);
}

static void relay_note(void *ctx, char e)
{
    char s[2];
    s[0] = e;
    s[1] = 0;
    note((const char *)ctx, s);
}

static void relay_server(int lfd, const char *evpath)
{
    fr_sink sink;
    sink.event = relay_note;
    sink.on_send = relay_answer;
    sink.ctx = (void *)evpath;
    fr_server(lfd, &sink);
}

static int listen_local(uint16_t *port)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(fd, 8) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return fd;
}

static int file_has(const char *path, const char *want)
{
    char buf[16384];
    FILE *f = fopen(path, "r");
    size_t n = 0;
    if (!f) return 0;
    n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, want) != NULL;
}

static int wait_file_has(const char *path, const char *want, int ms)
{
    int64_t until = mono_ms() + ms;
    do {
        if (file_has(path, want)) return 1;
        nap_ms(100);
    } while (mono_ms() < until);
    return 0;
}

/* The daemon runs the data plane once RUNNING: probes pick the reachable
 * region, the relay connection comes up as home, control hears the region in
 * a lite update, and down stops it all. */
static void test_daemon_relay(void)
{
    static fake f;
    char statedir[128], sock[128], logpath[128], countpath[128], evpath[128], key[65], out[8192], out2[8192], err[256];
    char hostspath[128];
    ts_state st;
    pid_t pid, srv, rsrv;
    int lfd, rfd, rc;
    uint16_t cport, rport;

    if (access(TS_BIN_DIR "/tsppcd", X_OK) != 0 || access(TS_BIN_DIR "/tsppc", X_OK) != 0) {
        printf("SKIP: relay tests (no " TS_BIN_DIR "/tsppcd or tsppc here)\n");
        return;
    }
    if (make_tmpdir() != 0) {
        t_true("relay: temp dir", 0);
        return;
    }
    snprintf(statedir, sizeof statedir, "%s/state", tmpdir);
    snprintf(sock, sizeof sock, "%s/sock", tmpdir);
    snprintf(logpath, sizeof logpath, "%s/log", tmpdir);
    snprintf(countpath, sizeof countpath, "%s/conns", tmpdir);
    snprintf(evpath, sizeof evpath, "%s/relay", tmpdir);
    snprintf(g_lites_path, sizeof g_lites_path, "%s/lites", tmpdir);
    snprintf(hostspath, sizeof hostspath, "%s/hosts", tmpdir);
    setenv("TSPPC_SOCKET", sock, 1);
    {
        FILE *hf = fopen(hostspath, "w");
        if (hf) {
            fputs("127.0.0.1\tlocalhost\n10.0.0.1 nas\n", hf);
            fclose(hf);
        }
    }

    rc = load_state(statedir, &st);
    st.have_login = 1;
    t_true("relay: saved login written", rc == 0 && ts_state_save(&st, statedir, err, sizeof err) == 0);

    rfd = listen_local(&rport);
    lfd = listen_local(&cport);
    if (rfd < 0 || lfd < 0) {
        t_true("relay: fake servers listen", 0);
        if (rfd >= 0) close(rfd);
        if (lfd >= 0) close(lfd);
        unsetenv("TSPPC_SOCKET");
        remove_test_files(statedir, sock, logpath, countpath);
        return;
    }
    /* Region 9's only node refuses connections: its probe fails. */
    snprintf(g_relay_map, sizeof g_relay_map,
             "{\"Node\":{\"ID\":1,\"Name\":\"" SELFNAME ".\",\"Key\":\"nodekey:" HA "\","
             "\"Addresses\":[\"100.64.0.1/32\"],\"MachineAuthorized\":true},"
             "\"Peers\":[{\"ID\":2,\"Name\":\"peer.example.test.\","
             "\"Key\":\"nodekey:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\","
             "\"Addresses\":[\"100.64.0.2/32\"],\"HomeDERP\":%d,\"Online\":true,\"MachineAuthorized\":true}],"
             "\"DERPMap\":{\"Regions\":{"
             "\"%d\":{\"RegionID\":%d,\"RegionCode\":\"tst\",\"Nodes\":[{\"Name\":\"%da\",\"RegionID\":%d,"
             "\"HostName\":\"derp.example.test\",\"IPv4\":\"127.0.0.1\",\"DERPPort\":%u}]},"
             "\"%d\":{\"RegionID\":%d,\"RegionCode\":\"dead\",\"Nodes\":[{\"Name\":\"%da\",\"RegionID\":%d,"
             "\"HostName\":\"dead.example.test\",\"IPv4\":\"127.0.0.1\",\"DERPPort\":1}]}}}}",
             RELAY_REGION, RELAY_REGION, RELAY_REGION, RELAY_REGION, RELAY_REGION, (unsigned)rport, DEAD_REGION,
             DEAD_REGION, DEAD_REGION, DEAD_REGION);

    fk_init(&f, NULL, "");
    f.handler = fk_relay_handler;
    ts_hex_encode(key, sizeof key, f.control_pub, 32);
    g_ctl_port = cport;
    srv = fork();
    if (srv == 0) {
        close(rfd);
        fake_server(lfd, &f, countpath);
        _exit(0);
    }
    rsrv = fork();
    if (rsrv == 0) {
        close(lfd);
        relay_server(rfd, evpath);
        _exit(0);
    }
    close(lfd);
    close(rfd);

    pid = start_daemon(statedir, sock, logpath, key);
    t_true("relay: socket appears", wait_socket(sock, pid, 120000) == 0);
    t_true("relay: RUNNING", wait_status(sock, "state RUNNING\n", out, sizeof out, 120000));
    t_true("relay: status shows the home region connected",
           wait_status(sock, "\nrelay 7 tst connected\n", out, sizeof out, 60000));
    t_true("relay: no tunnel problem with TSPPC_NO_TUN", !strstr(out, "tunnel driver"));
    t_true("relay: status has tunnel off, filter none and a path line for the peer",
           strstr(out, "\ntunnel off\n") && strstr(out, "\nfilter none dropped 0\n") &&
               strstr(out, "\npath 100.64.0.2 - 0 0 -\n"));
    t_true("relay: the path line follows the peer line",
           strstr(out, "\npeer 100.64.0.2 online peer.example.test.\n") < strstr(out, "\npath "));
    rc = run_cli("status", out2, sizeof out2);
    t_true("relay: tsppc status prints relay, tunnel and filter lines",
           rc == 0 && strstr(out2, "relay: 7 tst connected\n") && strstr(out2, "tunnel: off\n") &&
               strstr(out2, "filter: none dropped 0\n"));
    t_true("relay: tsppc status peer line has no counters without a session",
           strstr(out2, "peer.example.test.\n") && !strstr(out2, "rx "));
    t_true("relay: the relay saw the handshake and NotePreferred 1",
           wait_file_has(evpath, "u", 1000) && file_has(evpath, "r") && wait_file_has(evpath, "P", 10000));
    t_true("relay: control got a lite update with the region",
           wait_file_has(g_lites_path, "\"PreferredDERP\":7}", 30000));
    t_true("relay: the dead region was not reported", !file_has(g_lites_path, "\"PreferredDERP\":9}"));
    t_true("relay: the log names the home region", wait_file_has(logpath, "home relay: region 7", 1000));
    t_true("relay: the log notes the relay up", file_has(logpath, "relay region 7 connected"));
    /* Peer names: the hosts file (TSPPC_HOSTS_FILE, kept lines) gets the block. */
    t_true("relay: hosts file has the peer's names",
           wait_file_has(hostspath, "\n100.64.0.2\tpeer.example.test peer\n", 10000) &&
               file_has(hostspath, "10.0.0.1 nas\n" TS_HOSTS_BEGIN "\n") &&
               file_has(hostspath, "\t" SELFNAME " self\n"));
    t_true("relay: status says how many names", wait_status(sock, "\nnames 2 names\n", out, sizeof out, 10000));
    rc = run_cli("status", out2, sizeof out2);
    t_true("relay: tsppc status prints the names line after filter",
           rc == 0 && strstr(out2, "filter: none dropped 0\nnames: 2 names\n"));

    rc = run_cli("down", out, sizeof out);
    t_true("relay: down accepted", rc == 0);
    t_true("relay: down goes IDLE", wait_status(sock, "state IDLE\n", out, sizeof out, 60000));
    t_true("relay: down shows no relay, tunnel, filter or path",
           !strstr(out, "\nrelay ") && !strstr(out, "\ntunnel") && !strstr(out, "\nfilter") && !strstr(out, "\npath "));
    t_true("relay: down closes the relay connection", wait_file_has(evpath, "e", 10000));
    t_true("relay: the log says the data plane stopped", wait_file_has(logpath, "data plane stopped", 1000));
    t_true("relay: down removes the names, keeps the rest",
           wait_file_has(hostspath, "10.0.0.1 nas\n", 1000) && !file_has(hostspath, "tsppc") &&
               wait_status(sock, "\nnames off\n", out, sizeof out, 10000));

    /* up again: a fresh data plane, the same home, a new relay connection. */
    raw_request(sock, "up\n", 3, out, sizeof out);
    t_true("relay: up again accepted", strncmp(out, "ok\n", 3) == 0);
    t_true("relay: up again connects the home relay", wait_status(sock, "\nrelay 7 tst connected\n", out, sizeof out, 120000));
    t_true("relay: a second relay connection", wait_file_has(evpath, "eu", 5000));
    t_true("relay: up again writes the names again",
           wait_file_has(hostspath, "\n100.64.0.2\tpeer.example.test peer\n", 10000));
    rc = run_cli("logout", out, sizeof out);
    t_true("relay: logout accepted", rc == 0);
    t_true("relay: logout removes the names, keeps the rest",
           wait_status(sock, "\nlogin no\n", out2, sizeof out2, 60000) &&
               wait_status(sock, "\nnames off\n", out2, sizeof out2, 10000) &&
               file_has(hostspath, "10.0.0.1 nas\n") && !file_has(hostspath, "tsppc"));
    if (rc != 0) printf("  logout said: %s\n", out);

    kill(pid, SIGTERM);
    t_true("relay: daemon exits", wait_exit(pid, 60000) == 0);
    t_true("relay: exit removes the names, keeps the rest",
           file_has(hostspath, "10.0.0.1 nas\n") && !file_has(hostspath, "tsppc"));
    {
        const uint8_t *keys[3];
        keys[0] = st.node_priv;
        keys[1] = st.machine_priv;
        keys[2] = st.disco_priv;
        t_true("relay: log holds no private keys", !log_has_key(logpath, keys, 3));
    }
    kill(srv, SIGKILL);
    waitpid(srv, NULL, 0);
    kill(rsrv, SIGKILL);
    waitpid(rsrv, NULL, 0);
    ts_wipe(&st, sizeof st);
    unsetenv("TSPPC_SOCKET");
    unlink(evpath);
    unlink(g_lites_path);
    remove_test_files(statedir, sock, logpath, countpath);
}

/* Read what the daemon sends on fd until it closes, for at most ms. Returns
 * the time it took. */
static int64_t read_until_close(int fd, char *out, size_t cap, int ms)
{
    size_t len = 0;
    int64_t t0 = mono_ms(), until = t0 + ms;
    out[0] = 0;
    while (len + 1 < cap && mono_ms() < until) {
        fd_set r;
        struct timeval tv = { 0, 50000 };
        ssize_t k;
        FD_ZERO(&r);
        FD_SET(fd, &r);
        if (select(fd + 1, &r, NULL, NULL, &tv) <= 0) continue;
        k = read(fd, out + len, cap - 1 - len);
        if (k <= 0) break;
        len += (size_t)k;
    }
    out[len] = 0;
    return mono_ms() - t0;
}

/* Send a request and leave the connection open: the descriptor, or -1. */
static int send_only(const char *sock, const char *req)
{
    int fd = ts_ipc_connect(sock);
    if (fd >= 0 && write(fd, req, strlen(req)) != (ssize_t)strlen(req)) {
        close(fd);
        return -1;
    }
    return fd;
}

#define PEER2_KEY "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define PEER3_KEY "2222222222222222333333333333333344444444444444445555555555555555"
#define PEER4_KEY "6666666666666666777777777777777788888888888888889999999999999999"
#define PEER5_KEY "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"

/* tsppcd answers ping requests, through the fake relay playing peer 2: a
 * pong; a silent peer 3: a timeout, also at 10 s; errors for an unknown
 * address and a peer with no disco key; cancels on an early close; down and
 * SIGTERM answer a pending ping. tsppc ping prints upstream's lines. */
static void test_daemon_ping(void)
{
    static fake f;
    char statedir[128], sock[128], logpath[128], countpath[128], evpath[128], key[65], out[8192], err[256];
    char d3hex[65], d2hex[65];
    uint8_t d3priv[32], d3pub[32];
    ts_state st;
    pid_t pid, srv, rsrv;
    int lfd, rfd, rc, i, fd;
    uint16_t cport, rport;
    int64_t t0, dt;

    if (access(TS_BIN_DIR "/tsppcd", X_OK) != 0 || access(TS_BIN_DIR "/tsppc", X_OK) != 0) {
        printf("SKIP: ping tests (no " TS_BIN_DIR "/tsppcd or tsppc here)\n");
        return;
    }
    if (make_tmpdir() != 0) {
        t_true("dping: temp dir", 0);
        return;
    }
    snprintf(statedir, sizeof statedir, "%s/state", tmpdir);
    snprintf(sock, sizeof sock, "%s/sock", tmpdir);
    snprintf(logpath, sizeof logpath, "%s/log", tmpdir);
    snprintf(countpath, sizeof countpath, "%s/conns", tmpdir);
    snprintf(evpath, sizeof evpath, "%s/relay", tmpdir);
    snprintf(g_lites_path, sizeof g_lites_path, "%s/lites", tmpdir);
    setenv("TSPPC_SOCKET", sock, 1);

    rc = load_state(statedir, &st);
    st.have_login = 1;
    t_true("dping: saved login written", rc == 0 && ts_state_save(&st, statedir, err, sizeof err) == 0);

    /* Made-up disco keys for peers 2 and 3. */
    for (i = 0; i < 32; i++) {
        g_ans_disco_priv[i] = (uint8_t)(0x11 + 3 * i);
        d3priv[i] = (uint8_t)(0x52 + 5 * i);
    }
    ts_state_clamp_key(g_ans_disco_priv);
    ts_state_clamp_key(d3priv);
    ts_x25519_public(g_ans_disco_pub, g_ans_disco_priv);
    ts_x25519_public(d3pub, d3priv);
    ts_hex_encode(d2hex, sizeof d2hex, g_ans_disco_pub, 32);
    ts_hex_encode(d3hex, sizeof d3hex, d3pub, 32);
    t_true("dping: peer key", ts_hex_decode(g_ans_node, 32, PEER2_KEY, 64) == 0);
    g_relay_answers = 1;

    rfd = listen_local(&rport);
    lfd = listen_local(&cport);
    if (rfd < 0 || lfd < 0) {
        t_true("dping: fake servers listen", 0);
        if (rfd >= 0) close(rfd);
        if (lfd >= 0) close(lfd);
        unsetenv("TSPPC_SOCKET");
        remove_test_files(statedir, sock, logpath, countpath);
        g_relay_answers = 0;
        return;
    }
    snprintf(g_relay_map, sizeof g_relay_map,
             "{\"Node\":{\"ID\":1,\"Name\":\"" SELFNAME ".\",\"Key\":\"nodekey:" HA "\","
             "\"Addresses\":[\"100.64.0.1/32\"],\"MachineAuthorized\":true},"
             "\"Peers\":[{\"ID\":2,\"Name\":\"peer.example.test.\",\"Key\":\"nodekey:" PEER2_KEY "\","
             "\"DiscoKey\":\"discokey:%s\","
             "\"Addresses\":[\"100.64.0.2/32\"],\"HomeDERP\":%d,\"Online\":true,\"MachineAuthorized\":true},"
             "{\"ID\":3,\"Name\":\"quiet.example.test.\",\"Key\":\"nodekey:" PEER3_KEY "\","
             "\"DiscoKey\":\"discokey:%s\","
             "\"Addresses\":[\"100.64.0.3/32\"],\"HomeDERP\":%d,\"Online\":true,\"MachineAuthorized\":true},"
             "{\"ID\":4,\"Name\":\"nodisco.example.test.\",\"Key\":\"nodekey:" PEER4_KEY "\","
             "\"Addresses\":[\"100.64.0.4/32\"],\"HomeDERP\":%d,\"Online\":true,\"MachineAuthorized\":true},"
             "{\"ID\":5,\"Name\":\"old.example.test.\",\"Key\":\"nodekey:" PEER5_KEY "\",\"Expired\":true,"
             "\"Addresses\":[\"100.64.0.5/32\"],\"HomeDERP\":%d,\"Online\":true,\"MachineAuthorized\":true}],"
             "\"DERPMap\":{\"Regions\":{"
             "\"%d\":{\"RegionID\":%d,\"RegionCode\":\"tst\",\"Nodes\":[{\"Name\":\"%da\",\"RegionID\":%d,"
             "\"HostName\":\"derp.example.test\",\"IPv4\":\"127.0.0.1\",\"DERPPort\":%u}]}}}}",
             d2hex, RELAY_REGION, d3hex, RELAY_REGION, RELAY_REGION, RELAY_REGION, RELAY_REGION, RELAY_REGION, RELAY_REGION,
             RELAY_REGION, (unsigned)rport);

    fk_init(&f, NULL, "");
    f.handler = fk_relay_handler;
    ts_hex_encode(key, sizeof key, f.control_pub, 32);
    g_ctl_port = cport;
    srv = fork();
    if (srv == 0) {
        close(rfd);
        fake_server(lfd, &f, countpath);
        _exit(0);
    }
    rsrv = fork();
    if (rsrv == 0) {
        close(lfd);
        relay_server(rfd, evpath);
        _exit(0);
    }
    close(lfd);
    close(rfd);

    pid = start_daemon(statedir, sock, logpath, key);
    t_true("dping: socket appears", wait_socket(sock, pid, 120000) == 0);
    t_true("dping: home relay connected", wait_status(sock, "\nrelay 7 tst connected\n", out, sizeof out, 120000));

    raw_request(sock, "ping 100.64.0.2 5000\n", 21, out, sizeof out);
    t_true("dping: a peer that answers gives a pong", strncmp(out, "ok\nping pong ", 13) == 0 &&
           strstr(out, " 7 tst\n") != NULL);
    if (strncmp(out, "ok\nping pong ", 13) != 0) printf("  ping said: %s\n", out);
    t0 = mono_ms();
    raw_request(sock, "ping 100.64.0.3 1000\n", 21, out, sizeof out);
    dt = mono_ms() - t0;
    t_true("dping: a silent peer times out on time", strcmp(out, "ok\nping timeout\n") == 0 && dt >= 900 && dt < 3000);
    raw_request(sock, "ping 100.64.0.99 1000\n", 22, out, sizeof out);
    t_true("dping: an unknown address", strcmp(out, "error no matching peer\n") == 0);
    raw_request(sock, "ping 100.64.0.4 1000\n", 21, out, sizeof out);
    t_true("dping: a peer with no disco key", strcmp(out, "error unknown peer\n") == 0);
    raw_request(sock, "ping 100.64.0.5 1000\n", 21, out, sizeof out);
    t_true("dping: an expired peer", strcmp(out, "error peer's node key has expired\n") == 0);
    raw_request(sock, "ping 100.64.0.2 99\n", 19, out, sizeof out);
    t_true("dping: a bad request", strcmp(out, "error unknown request\n") == 0);

    /* A 10 s ping outlives the usual 10 s client deadline. */
    t0 = mono_ms();
    raw_request(sock, "ping 100.64.0.3 10000\n", 22, out, sizeof out);
    dt = mono_ms() - t0;
    t_true("dping: a 10 s ping is answered, not cut off", strcmp(out, "ok\nping timeout\n") == 0 &&
           dt >= 9900 && dt < 10000 + TS_IPC_PING_MARGIN_MS);

    /* Clients that close early cancel their pings: more than the data
     * plane holds at once, then a ping still goes out. */
    for (i = 0; i < 17; i++) {
        fd = send_only(sock, "ping 100.64.0.3 10000\n");
        nap_ms(100);
        if (fd >= 0) close(fd);
    }
    nap_ms(300);
    raw_request(sock, "ping 100.64.0.2 5000\n", 21, out, sizeof out);
    t_true("dping: early closes cancelled their pings", strncmp(out, "ok\nping pong ", 13) == 0);

    /* At most TS_IPC_MAX_PINGS clients wait for a ping; status still works. */
    {
        int held[TS_IPC_MAX_PINGS];
        for (i = 0; i < TS_IPC_MAX_PINGS; i++) held[i] = send_only(sock, "ping 100.64.0.3 5000\n");
        nap_ms(300);
        t0 = mono_ms();
        raw_request(sock, "ping 100.64.0.2 5000\n", 21, out, sizeof out);
        dt = mono_ms() - t0;
        t_true("dping: one ping over the limit is refused at once",
               strcmp(out, "error too many pings in progress\n") == 0 && dt < 2000);
        raw_request(sock, "status\n", 7, out, sizeof out);
        t_true("dping: status works with the pings pending", strncmp(out, "ok\nstate RUNNING\n", 17) == 0);
        for (i = 0; i < TS_IPC_MAX_PINGS; i++)
            if (held[i] >= 0) close(held[i]);
        nap_ms(300);
        raw_request(sock, "ping 100.64.0.2 5000\n", 21, out, sizeof out);
        t_true("dping: room again once they close", strncmp(out, "ok\nping pong ", 13) == 0);
    }

    /* tsppc ping. */
    {
        const char *a1[] = { "ping", "-c", "1", "peer", NULL };
        const char *a2[] = { "ping", "-c", "1", "--until-direct=false", "PEER.example.test", NULL };
        const char *a3[] = { "ping", "-c", "1", "--timeout", "500ms", "quiet", NULL };
        const char *a4[] = { "ping", "self", NULL };
        const char *a5[] = { "ping", "100.64.0.1", NULL };
        const char *a6[] = { "ping", "100.64.0.99", NULL };
        const char *a7[] = { "ping", "nobody", NULL };
        const char *a8[] = { "ping", NULL };
        const char *a9[] = { "ping", "-c", "2", "--timeout=200ms", "--until-direct=false", "quiet", NULL };
        const char *a10[] = { "ping", "--timeout=30s", "peer", NULL };
        const char *a11[] = { "ping", "nodisco", NULL };
        rc = run_cli_v(a1, out, sizeof out);
        t_true("cli ping: a pong, then no direct connection",
               rc == 1 && strncmp(out, "pong from peer (100.64.0.2) via DERP(tst) in ", 45) == 0 &&
                   strstr(out, "\ndirect connection not established\n") != NULL);
        if (rc != 1) printf("  tsppc ping said (%d): %s\n", rc, out);
        t0 = mono_ms();
        rc = run_cli_v(a2, out, sizeof out);
        dt = mono_ms() - t0;
        t_true("cli ping: --until-direct=false exits 0 after the pause",
               rc == 0 && strncmp(out, "pong from peer (100.64.0.2) via DERP(tst) in ", 45) == 0 && dt >= 1000);
        rc = run_cli_v(a3, out, sizeof out);
        t_true("cli ping: timed out, no reply", rc == 1 && strcmp(out, "ping \"100.64.0.3\" timed out\nno reply\n") == 0);
        rc = run_cli_v(a9, out, sizeof out);
        t_true("cli ping: two timeouts, no pause", rc == 1 &&
               strcmp(out, "ping \"100.64.0.3\" timed out\nping \"100.64.0.3\" timed out\nno reply\n") == 0);
        rc = run_cli_v(a4, out, sizeof out);
        t_true("cli ping: our own name", rc == 0 && strcmp(out, "100.64.0.1 is local Tailscale IP\n") == 0);
        rc = run_cli_v(a5, out, sizeof out);
        t_true("cli ping: our own IP", rc == 0 && strcmp(out, "100.64.0.1 is local Tailscale IP\n") == 0);
        rc = run_cli_v(a6, out, sizeof out);
        t_true("cli ping: an unknown IP", rc == 1 && strcmp(out, "no matching peer\n") == 0);
        rc = run_cli_v(a7, out, sizeof out);
        t_true("cli ping: an unknown name", rc == 1 && strcmp(out, "no peer named \"nobody\"\n") == 0);
        rc = run_cli_v(a11, out, sizeof out);
        t_true("cli ping: a peer with no disco key", rc == 1 && strcmp(out, "unknown peer\n") == 0);
        rc = run_cli_v(a8, out, sizeof out);
        t_true("cli ping: no target is usage", rc == 2);
        rc = run_cli_v(a10, out, sizeof out);
        t_true("cli ping: a timeout over 10 s is usage", rc == 2 && strstr(out, "timeout") != NULL);
    }

    /* down answers a pending ping. */
    fd = send_only(sock, "ping 100.64.0.3 10000\n");
    nap_ms(300);
    raw_request(sock, "down\n", 5, out, sizeof out);
    t_true("dping: down accepted", strncmp(out, "ok\n", 3) == 0);
    if (fd >= 0) {
        dt = read_until_close(fd, out, sizeof out, 8000);
        t_true("dping: down answers the pending ping", strcmp(out, "error not connected\n") == 0 && dt < 5000);
        close(fd);
    }
    {
        const char *a[] = { "ping", "peer", NULL };
        rc = run_cli_v(a, out, sizeof out);
        t_true("cli ping: down is stopped", rc == 1 && strcmp(out, "Tailscale is stopped.\n") == 0);
    }

    /* logout answers a pending ping too. */
    raw_request(sock, "up\n", 3, out, sizeof out);
    t_true("dping: up for logout", wait_status(sock, "\nrelay 7 tst connected\n", out, sizeof out, 120000));
    fd = send_only(sock, "ping 100.64.0.3 10000\n");
    nap_ms(300);
    raw_request(sock, "logout\n", 7, out, sizeof out);
    t_true("dping: logout accepted", strncmp(out, "ok\n", 3) == 0);
    if (fd >= 0) {
        dt = read_until_close(fd, out, sizeof out, 8000);
        t_true("dping: logout answers the pending ping", strcmp(out, "error not connected\n") == 0 && dt < 5000);
        close(fd);
    }

    /* SIGTERM with a ping pending: an error or EOF, at once. */
    raw_request(sock, "up\n", 3, out, sizeof out);
    t_true("dping: up again", wait_status(sock, "\nrelay 7 tst connected\n", out, sizeof out, 120000));
    /* The log names no ping that went out fine. */
    t_true("dping: pings sent are not logged", !file_has(logpath, "ping 100.64.0.2"));
    fd = send_only(sock, "ping 100.64.0.3 10000\n");
    nap_ms(300);
    kill(pid, SIGTERM);
    if (fd >= 0) {
        dt = read_until_close(fd, out, sizeof out, 8000);
        t_true("dping: SIGTERM answers or closes the pending ping",
               (strcmp(out, "error not connected\n") == 0 || out[0] == 0) && dt < 5000);
        close(fd);
    }
    t_true("dping: daemon exits", wait_exit(pid, 60000) == 0);
    {
        const uint8_t *keys[3];
        keys[0] = st.node_priv;
        keys[1] = st.machine_priv;
        keys[2] = st.disco_priv;
        t_true("dping: log holds no private keys", !log_has_key(logpath, keys, 3));
    }
    kill(srv, SIGKILL);
    waitpid(srv, NULL, 0);
    kill(rsrv, SIGKILL);
    waitpid(rsrv, NULL, 0);
    g_relay_answers = 0;
    ts_wipe(&st, sizeof st);
    ts_wipe(g_ans_disco_priv, sizeof g_ans_disco_priv);
    ts_wipe(d3priv, sizeof d3priv);
    unsetenv("TSPPC_SOCKET");
    unlink(evpath);
    unlink(g_lites_path);
    remove_test_files(statedir, sock, logpath, countpath);
}

/* tsppc against a fake daemon that answers every request with reply. */
static int cli_against(const char *sock, const char *reply, const char *arg, char *out, size_t cap)
{
    struct sockaddr_un a;
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0), rc, st;
    pid_t srv;
    if (lfd < 0) return -1;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", sock);
    unlink(sock);
    if (bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 4) != 0) {
        close(lfd);
        return -1;
    }
    srv = fork();
    if (srv == 0) {
        for (;;) {
            char line[128];
            int c = accept(lfd, NULL, NULL);
            if (c < 0) _exit(0);
            if (read(c, line, sizeof line) < 0) {}
            if (write(c, reply, strlen(reply)) < 0) {}
            close(c);
        }
    }
    close(lfd);
    rc = run_cli(arg, out, cap);
    kill(srv, SIGKILL);
    waitpid(srv, &st, 0);
    unlink(sock);
    return rc;
}

static void test_cli_replies(void)
{
    char sock[128], out[1024];
    int rc;
    if (access(TS_BIN_DIR "/tsppc", X_OK) != 0) {
        printf("SKIP: CLI reply tests (no " TS_BIN_DIR "/tsppc here)\n");
        return;
    }
    snprintf(sock, sizeof sock, "/tmp/tsppc-c.%d", (int)getpid());
    setenv("TSPPC_SOCKET", sock, 1);
    rc = cli_against(sock, "error \n", "status", out, sizeof out);
    t_true("cli: an empty error says the reply was unexpected", rc == 1 &&
           strcmp(out, "tsppc: unexpected reply from tsppcd\n") == 0);
    rc = cli_against(sock, "error\n", "down", out, sizeof out);
    t_true("cli: an error key alone, the same", rc == 1 && strcmp(out, "tsppc: unexpected reply from tsppcd\n") == 0);
    rc = cli_against(sock, "error busy now\n", "ip", out, sizeof out);
    t_true("cli: an error with text prints it", rc == 1 && strcmp(out, "tsppc: busy now\n") == 0);
    rc = cli_against(sock,
                     "ok\nstate RUNNING\nstatus up\nlogin yes\nwanted up\nip 100.64.0.1\n"
                     "relay 7 tst connected\ntunnel utun3 tunnel driver\x01 odd\nfilter too-large\n"
                     "peer 100.64.0.2 online a.example.test.\npeer 100.64.0.3 online b.example.test.\n"
                     "peer 100.64.0.4 offline c.example.test.\n"
                     "path 100.64.0.2 nyc 12 34 7\npath 100.64.0.3 - 0 0 -\n",
                     "status", out, sizeof out);
    t_true("cli: status prints relay, tunnel (cleaned) and filter lines",
           rc == 0 && strstr(out, "relay: 7 tst connected\n") && strstr(out, "tunnel: utun3 tunnel driver? odd\n") &&
               strstr(out, "filter: too-large\n"));
    t_true("cli: a peer with a session shows its relay and packet counts",
           strstr(out, "online   a.example.test.  relay nyc  rx 12 tx 34\n") != NULL);
    t_true("cli: a peer without a session, or a path line, shows none",
           strstr(out, "b.example.test.\n") && strstr(out, "c.example.test.\n") && !strstr(out, "path"));
    unsetenv("TSPPC_SOCKET");
}

static void test_daemon(void)
{
    char statedir[128], sock[128], logpath[128], out[8192], longreq[100];
    ts_state saved, mid, after;
    struct stat sb;
    pid_t pid;
    int rc, i, idle[TS_IPC_MAX_CLIENTS];

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

    /* A saved login with an old key. */
    {
        char err[256];
        rc = load_state(statedir, &saved);
        saved.have_login = 1;
        saved.have_old_node = 1;
        memset(saved.old_node_priv, 0x42, 32);
        t_true("daemon: saved login written", rc == 0 && ts_state_save(&saved, statedir, err, sizeof err) == 0);
    }

    /* A path held by a regular file: refused, file kept. */
    rc = open(sock, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (rc >= 0) close(rc);
    pid = start_daemon(statedir, sock, logpath, NULL);
    t_true("daemon: refuses a socket path held by a file", wait_exit(pid, 60000) == 1);
    t_true("daemon: the file is kept", lstat(sock, &sb) == 0 && S_ISREG(sb.st_mode));
    unlink(sock);

    /* The key fetch resolves localhost and is refused on 443: BACKOFF. */
    pid = start_daemon(statedir, sock, logpath, NULL);
    t_true("daemon: socket appears", wait_socket(sock, pid, 120000) == 0);
    t_true("daemon: key fetch failing, BACKOFF", wait_status(sock, "state BACKOFF\n", out, sizeof out, 60000));
    t_true("daemon: saved login shown", strstr(out, "\nlogin yes\n") != NULL);
    rc = run_cli("status", out, sizeof out);
    t_true("daemon: status reports BACKOFF and a problem", rc == 0 && strstr(out, "BACKOFF") && strstr(out, "Problem:"));
    rc = run_cli("ip", out, sizeof out);
    t_true("daemon: ip without an address fails", rc == 1 && strstr(out, "no tailnet IP"));
    rc = run_cli("bogus", out, sizeof out);
    t_true("daemon: CLI rejects an unknown command", rc == 2);

    /* down and up before the session (no control key): each is saved at once,
     * so a restart before the key is in keeps it. */
    rc = run_cli("down", out, sizeof out);
    t_true("daemon: down before the key exits 0", rc == 0 && strstr(out, "Disconnected.") != NULL);
    t_true("daemon: down before the key is saved", load_state(statedir, &mid) == 0 && mid.have_login && mid.down);
    raw_request(sock, "status\n", 7, out, sizeof out);
    t_true("daemon: down before the key: wanted down", strstr(out, "\nwanted down\n") != NULL);
    if (geteuid() != 0) {
        chmod(statedir, 0500);
        raw_request(sock, "up\n", 3, out, sizeof out);
        chmod(statedir, 0700);
        t_true("daemon: up before the key, failed save: an error line",
               strncmp(out, "error ", 6) == 0 && strstr(out, "up failed") && !strstr(out, "\nstate "));
        t_true("daemon: failed up saved nothing", load_state(statedir, &mid) == 0 && mid.have_login && mid.down);
        raw_request(sock, "status\n", 7, out, sizeof out);
        t_true("daemon: failed up left it down", strstr(out, "\nwanted down\n") != NULL);
    } else {
        printf("SKIP: failed-save up before the key (root)\n");
    }
    raw_request(sock, "up\n", 3, out, sizeof out);
    t_true("daemon: up before the key accepted, wanted up", strncmp(out, "ok\n", 3) == 0 && strstr(out, "\nwanted up\n"));
    t_true("daemon: up before the key cleared the saved down", load_state(statedir, &mid) == 0 && mid.have_login &&
           !mid.down && memcmp(mid.node_priv, saved.node_priv, 32) == 0);
    kill(pid, SIGTERM);
    t_true("daemon: exits for the restart after up", wait_exit(pid, 60000) == 0);
    pid = start_daemon(statedir, sock, logpath, NULL);
    t_true("daemon: restarts after up", wait_socket(sock, pid, 120000) == 0);
    t_true("daemon: restart after up before the key: wanted up",
           wait_status(sock, "\nlogin yes\n", out, sizeof out, 60000) && strstr(out, "\nwanted up\n") != NULL);

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
    /* BACKOFF, or CONNECTING while a key fetch retry runs. */
    t_true("daemon: raw status reply", strncmp(out, "ok\nstate BACKOFF\n", 17) == 0 ||
           strncmp(out, "ok\nstate CONNECTING\n", 20) == 0);
    memset(longreq, 'x', sizeof longreq);
    raw_request(sock, longreq, sizeof longreq, out, sizeof out);
    t_true("daemon: an over-long request is an error", strncmp(out, "error ", 6) == 0 && !strstr(out, "state"));
    raw_request(sock, "sideways\n", 9, out, sizeof out);
    t_true("daemon: an unknown request is an error", strncmp(out, "error ", 6) == 0);
    raw_request(sock, "st\0us\n", 6, out, sizeof out);
    t_true("daemon: a request with a NUL is an error", strncmp(out, "error ", 6) == 0);
    raw_request(sock, "status\nstatus\n", 14, out, sizeof out);
    t_true("daemon: bytes after the request are an error", strncmp(out, "error ", 6) == 0);

    /* A client that never sends is dropped after the timeout. */
    {
        int fd = ts_ipc_connect(sock);
        int64_t t0 = mono_ms();
        raw_request(sock, "", 0, out, sizeof out);   /* waits for the close */
        t_true("daemon: a silent client is closed after the timeout",
               mono_ms() - t0 >= TS_IPC_CLIENT_TIMEOUT_MS - 1000 && mono_ms() - t0 < TS_IPC_CLIENT_TIMEOUT_MS + 20000);
        if (fd >= 0) close(fd);
    }

    /* The logout's first save fails: it fails, and nothing changes. (Root
     * writes to a read-only directory anyway.) */
    if (geteuid() != 0) {
        chmod(statedir, 0500);
        rc = run_cli("logout", out, sizeof out);
        chmod(statedir, 0700);
        t_true("daemon: logout with a failed save exits 1 and says so", rc == 1 && strstr(out, "logout failed"));
        t_true("daemon: failed logout changed nothing", load_state(statedir, &mid) == 0 && mid.have_login &&
               !mid.logout_pending && memcmp(mid.node_priv, saved.node_priv, 32) == 0);
        raw_request(sock, "status\n", 7, out, sizeof out);
        t_true("daemon: still logged in after a failed logout", strstr(out, "\nlogin yes\n") != NULL);
    } else {
        printf("SKIP: failed-save logout (root)\n");
    }

    /* Logout during the key fetch: the intent is saved, control is told later. */
    rc = run_cli("logout", out, sizeof out);
    t_true("daemon: logout during the key fetch is saved", rc == 0 && strstr(out, "logout saved") != NULL);
    t_true("daemon: state holds logout_pending and the same key", load_state(statedir, &mid) == 0 &&
           !mid.have_login && mid.logout_pending && memcmp(mid.node_priv, saved.node_priv, 32) == 0);
    raw_request(sock, "status\n", 7, out, sizeof out);
    t_true("daemon: login leaving", strstr(out, "\nlogin leaving\n") != NULL);

    kill(pid, SIGTERM);
    t_true("daemon: SIGTERM exits cleanly", wait_exit(pid, 60000) == 0);
    t_true("daemon: SIGTERM removes the socket", lstat(sock, &sb) != 0 && errno == ENOENT);
    t_true("daemon: CLI reports no daemon", run_cli("status", out, sizeof out) == 1);

    /* Restart mid-logout, still no key: the logout stays pending, no login. */
    pid = start_daemon(statedir, sock, logpath, NULL);
    t_true("daemon: restarts", wait_socket(sock, pid, 120000) == 0);
    t_true("daemon: restart keeps the logout pending", wait_status(sock, "state BACKOFF\n", out, sizeof out, 60000) &&
           strstr(out, "\nlogin leaving\n") != NULL);
    kill(pid, SIGKILL);
    wait_exit(pid, 60000);
    t_true("daemon: crash leaves the socket", lstat(sock, &sb) == 0 && S_ISSOCK(sb.st_mode));

    /* Restart with control's key: the session tries to tell control (refused
     * on both tries), then finishes the logout with a new key. */
    pid = start_daemon(statedir, sock, logpath, FAKE_CONTROL_KEY);
    t_true("daemon: replaces a stale socket", wait_socket_new(sock, pid, 120000, sb.st_ino) == 0);
    t_true("daemon: pending logout finished", wait_status(sock, "\nlogin no\n", out, sizeof out, 120000));
    t_true("daemon: says control was not reached", strstr(out, "not reached") != NULL);
    t_true("daemon: key rotated, nothing pending", load_state(statedir, &after) == 0 && !after.logout_pending &&
           !after.have_login && !after.have_old_node && memcmp(after.node_priv, saved.node_priv, 32) != 0 &&
           memcmp(after.machine_priv, saved.machine_priv, 32) == 0);
    rc = run_cli("logout", out, sizeof out);
    t_true("daemon: logout again succeeds, note kept", rc == 0 && strstr(out, "logged out here") != NULL);

    /* up: the session goes through DNS and TCP to localhost:1 and backs off. */
    raw_request(sock, "up\n", 3, out, sizeof out);
    t_true("daemon: up accepted", strncmp(out, "ok\n", 3) == 0);
    t_true("daemon: session backs off when control refuses",
           wait_status(sock, "state BACKOFF\n", out, sizeof out, 120000) && strstr(out, "\nproblem ") != NULL);
    {
        FILE *f = fopen(logpath, "r");
        char line[512];
        int saw = 0;
        while (f && fgets(line, sizeof line, f))
            if (strstr(line, "connecting to control on port 1")) saw = 1;
        if (f) fclose(f);
        t_true("daemon: the session's connection ran", saw);
    }
    kill(pid, SIGINT);
    t_true("daemon: SIGINT exits cleanly", wait_exit(pid, 60000) == 0 && lstat(sock, &sb) != 0);

    {
        const uint8_t *keys[5];
        keys[0] = saved.node_priv;
        keys[1] = saved.machine_priv;
        keys[2] = saved.disco_priv;
        keys[3] = after.node_priv;
        keys[4] = saved.old_node_priv;
        t_true("daemon: log holds no private keys", !log_has_key(logpath, keys, 5));
    }

    ts_wipe(&saved, sizeof saved);
    ts_wipe(&mid, sizeof mid);
    ts_wipe(&after, sizeof after);
    unsetenv("TSPPC_SOCKET");
    unlink(logpath);
    unlink(sock);
    {
        char p[160];
        snprintf(p, sizeof p, "%s/%s", statedir, "state.bin");
        unlink(p);
        snprintf(p, sizeof p, "%s/hosts", tmpdir);
        unlink(p);
    }
    rmdir(statedir);
    rmdir(tmpdir);
}

void test_ipc(void)
{
    test_parse();
    test_parse_ping();
    test_clean();
    test_split();
    test_listen();
    test_cli_replies();
    test_daemon();
    test_daemon_down();
    test_daemon_relay();
    test_daemon_ping();
}
