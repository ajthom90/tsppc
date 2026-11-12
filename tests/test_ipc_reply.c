#include "harness.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/daemon/ipc_reply.h"

/* ts_reply and its peer array are large: static, never on the stack. */
static ts_reply g_r;
static ts_reply_peer g_peers[TS_MAX_PEERS];

static int parse(const char *s)
{
    size_t n = strlen(s);
    char *b = (char *)malloc(n ? n : 1);   /* exact size, so ASan sees overreads */
    int rc;
    if (!b) abort();
    memcpy(b, s, n);
    rc = ts_reply_parse(&g_r, g_peers, b, n);
    free(b);
    return rc;
}

static void test_parse(void)
{
    static char big[TS_MAX_PEERS * 80 + 400];
    size_t off, i;
    int rc = parse("ok\nstate RUNNING\nstatus connected; 3 peers\nlogin yes\nwanted up\n"
                   "self host.example.test.\nip 100.64.0.1\n"
                   "peer 100.64.0.10 online p10.example.test.\n"
                   "peer - offline p11.example.test.\n"
                   "peer 100.64.0.12 offline name with spaces\n");
    t_true("reply: full reply parses", rc == 0 && g_r.ok == 1 && g_r.error[0] == 0);
    t_true("reply: scalar fields", strcmp(g_r.state, "RUNNING") == 0 && strcmp(g_r.status, "connected; 3 peers") == 0 &&
           strcmp(g_r.login, "yes") == 0 && strcmp(g_r.wanted, "up") == 0 &&
           strcmp(g_r.self, "host.example.test.") == 0 && g_r.url[0] == 0 && g_r.problem[0] == 0);
    t_true("reply: own address", g_r.have_ipv4 == 1 && g_r.ipv4 == 0x64400001u);
    t_true("reply: three peers", g_r.npeers == 3 && g_r.peers == g_peers && g_r.truncated == 0);
    t_true("reply: peer 0", g_peers[0].have_ipv4 && g_peers[0].ipv4 == 0x6440000Au && g_peers[0].online &&
           strcmp(g_peers[0].name, "p10.example.test.") == 0);
    t_true("reply: dash is no address", !g_peers[1].have_ipv4 && g_peers[1].ipv4 == 0 && !g_peers[1].online &&
           strcmp(g_peers[1].name, "p11.example.test.") == 0);
    t_true("reply: a name may hold spaces", g_peers[2].have_ipv4 && strcmp(g_peers[2].name, "name with spaces") == 0);

    rc = parse("ok\nurl https://login.example.test/a/x\nproblem system clock is wrong\n");
    t_true("reply: url and problem", rc == 0 && strcmp(g_r.url, "https://login.example.test/a/x") == 0 &&
           strcmp(g_r.problem, "system clock is wrong") == 0 && g_r.npeers == 0 && !g_r.have_ipv4);

    {
        static const char nopeers[] = "ok\npeer 100.64.0.10 online a.example.test.\n";
        rc = ts_reply_parse(&g_r, NULL, nopeers, sizeof nopeers - 1);
        t_true("reply: NULL peers stores nothing and marks truncated", rc == 0 && g_r.peers == NULL &&
               g_r.npeers == 0 && g_r.truncated == 1);
        rc = ts_reply_parse(&g_r, NULL, "ok\npeer bad line\n", 17);
        t_true("reply: NULL peers, an invalid peer line is just skipped", rc == 0 && g_r.npeers == 0 && g_r.truncated == 0);
    }

    rc = parse("ok\nexitnode x\nState FOO\nstate A\nstate B\nbad line here\n\n \nPeer 100.64.0.1 online x\nstatus s\n");
    t_true("reply: unknown and upper-case keys skipped, first state wins",
           rc == 0 && strcmp(g_r.state, "A") == 0 && strcmp(g_r.status, "s") == 0 && g_r.npeers == 0);

    rc = parse("ok\nstate RUNNING\nip 100.64.0.1\nrelay 7 tst connected\ntunnel off tunnel driver not loaded\n"
               "filter ok dropped 3\npeer 100.64.0.2 online a.example.test.\npath 100.64.0.2 tst 1 2 3\n");
    t_true("reply: relay, tunnel, filter and path lines are ignored, the model unchanged",
           rc == 0 && strcmp(g_r.state, "RUNNING") == 0 && g_r.have_ipv4 && g_r.ipv4 == 0x64400001u &&
               g_r.npeers == 1 && g_peers[0].ipv4 == 0x64400002u && g_peers[0].online &&
               strcmp(g_peers[0].name, "a.example.test.") == 0 && !g_r.truncated);

    rc = parse("ok\nstate RUNNING\npeer 100.64.0.1 online a\x1b[2Jb\x07\n");
    t_true("reply: control byte in a name becomes ?", rc == 0 && g_r.npeers == 1 &&
           strcmp(g_peers[0].name, "a?[2Jb?") == 0);
    rc = parse("ok\nstatus x\x01y\nurl u\x7f\n");
    t_true("reply: control bytes in values", strcmp(g_r.status, "x?y") == 0 && strcmp(g_r.url, "u?") == 0);

    rc = parse("ok\ntruncated\n");
    t_true("reply: truncated line", rc == 0 && g_r.truncated == 1);

    off = 0;
    off += (size_t)snprintf(big + off, sizeof big - off, "ok\n");
    for (i = 0; i < TS_MAX_PEERS + 1; i++)
        off += (size_t)snprintf(big + off, sizeof big - off, "peer 100.64.%u.%u online n%u.example.test.\n",
                                (unsigned)(i / 256), (unsigned)(i % 256), (unsigned)i);
    rc = ts_reply_parse(&g_r, g_peers, big, off);
    t_true("reply: 257 peers keep 256 and set truncated", rc == 0 && g_r.npeers == TS_MAX_PEERS && g_r.truncated == 1);
    t_true("reply: the 256th peer is intact", strcmp(g_peers[TS_MAX_PEERS - 1].name, "n255.example.test.") == 0);
    rc = ts_reply_parse(&g_r, g_peers, big, off - strlen("peer 100.64.1.0 online n256.example.test.\n"));
    t_true("reply: exactly 256 peers is not truncated", rc == 0 && g_r.npeers == TS_MAX_PEERS && g_r.truncated == 0);

    rc = parse("ok\npeer 100.64.0.1 online\npeer 100.64.0.2 online \npeer 100.64.0.3\npeer\npeer 1.2.3 online x\n"
               "peer 256.0.0.1 online x\npeer 1.2.3.4.5 online x\npeer 01.2.3.4 online x\npeer 1..2.3 online x\n"
               "peer 1.2.3.4 maybe x\npeer 100.64.0.9 online good\n");
    t_true("reply: bad peer lines skipped, an empty name kept", rc == 0 && g_r.npeers == 2 && g_peers[0].name[0] == 0 &&
           g_peers[0].ipv4 == 0x64400002u && strcmp(g_peers[1].name, "good") == 0);

    rc = parse("ok\nip 1.2.3\nip 300.1.1.1\n");
    t_true("reply: bad own address ignored", rc == 0 && !g_r.have_ipv4);

    rc = parse("error request too long\n");
    t_true("reply: error only", rc == 0 && g_r.ok == 0 && strcmp(g_r.error, "request too long") == 0);
    rc = parse("error\n");
    t_true("reply: bare error line counts", rc == 0 && g_r.ok == 0 && g_r.error[0] == 0);
    t_true("reply: no ok or error", parse("state RUNNING\nip 100.64.0.1\n") == -1);
    t_true("reply: empty", parse("") == -1);
    t_true("reply: garbage", parse("\x01\x02\xff\n\n\n") == -1);
    rc = parse("ok");
    t_true("reply: last line without a newline", rc == 0 && g_r.ok == 1);

    {   /* a value longer than its field is cut, still terminated */
        static char longv[TS_IPC_VALUE_MAX * 3];
        size_t n = (size_t)snprintf(longv, sizeof longv, "ok\nstate ");
        memset(longv + n, 'x', 100);
        n += 100;
        longv[n++] = '\n';
        rc = ts_reply_parse(&g_r, g_peers, longv, n);
        t_true("reply: long state cut to its field", rc == 0 && strlen(g_r.state) == sizeof g_r.state - 1);
    }
}

/* ---- ts_ipc_request --------------------------------------------------- */

static int64_t mono_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int listen_at(const char *path, int backlog)
{
    struct sockaddr_un a;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* A serving child: accepts, reads the request line, then does what mode says. */
static pid_t serve(const char *path, int mode, int lfd)
{
    pid_t pid = fork();
    (void)path;
    if (pid != 0) return pid;
    for (;;) {
        char line[128], chunk[4096];
        int c = accept(lfd, NULL, NULL), i;
        if (c < 0) _exit(0);
        if (read(c, line, sizeof line) < 0) {}
        if (mode == 0) {
            /* stall: never answer, never close */
            sleep(30);
        } else if (mode == 1) {
            if (write(c, "ok\nstate IDLE\n", 14) < 0) {}
            close(c);
        } else if (mode == 2) {
            /* a reply of 200000 bytes */
            memset(chunk, 'a', sizeof chunk);
            for (i = 0; i < 50; i++)
                if (write(c, chunk, sizeof chunk) < 0) break;
            close(c);
        } else if (mode == 3) {
            /* a partial reply, then a stall */
            if (write(c, "ok\nsta", 6) < 0) {}
            sleep(30);
        } else {
            close(c);   /* closes with no reply */
        }
        if (mode == 0 || mode == 3) _exit(0);
    }
}

static void stop(pid_t pid, int lfd)
{
    int st;
    kill(pid, SIGKILL);
    (void)waitpid(pid, &st, 0);
    close(lfd);
}

static void test_request(void)
{
    static char buf[TS_IPC_RESP_MAX];
    char path[128], *small;
    size_t len = 99;
    ts_req_result rc;
    int lfd;
    pid_t pid;
    int64_t t0, dt;

    snprintf(path, sizeof path, "/tmp/tsppc-r.%d", (int)getpid());
    unlink(path);
    rc = ts_ipc_request(path, TS_IPC_STATUS, 1000, buf, sizeof buf, &len);
    t_true("request: missing socket is NO_DAEMON", rc == TS_REQ_NO_DAEMON && len == 0);

    lfd = listen_at(path, 4);
    t_true("request: test socket up", lfd >= 0);
    if (lfd < 0) return;

    pid = serve(path, 1, lfd);
    rc = ts_ipc_request(path, TS_IPC_STATUS, 5000, buf, sizeof buf, &len);
    t_true("request: reply read to close", rc == TS_REQ_OK && len == 14 && memcmp(buf, "ok\nstate IDLE\n", 14) == 0);
    stop(pid, lfd);

    lfd = listen_at(path, 4);
    pid = serve(path, 2, lfd);
    small = (char *)malloc(1000);
    rc = ts_ipc_request(path, TS_IPC_STATUS, 5000, small, 1000, &len);
    t_true("request: a reply over cap is cut to cap and OK", rc == TS_REQ_OK && len == 1000 && small[0] == 'a');
    free(small);
    stop(pid, lfd);

    lfd = listen_at(path, 4);
    pid = serve(path, 4, lfd);
    rc = ts_ipc_request(path, TS_IPC_STATUS, 5000, buf, sizeof buf, &len);
    t_true("request: closed with no reply is OK with 0 bytes", rc == TS_REQ_OK && len == 0);
    stop(pid, lfd);

    lfd = listen_at(path, 4);
    pid = serve(path, 0, lfd);
    t0 = mono_ms();
    rc = ts_ipc_request(path, TS_IPC_STATUS, 400, buf, sizeof buf, &len);
    dt = mono_ms() - t0;
    t_true("request: a silent daemon times out", rc == TS_REQ_TIMEOUT && len == 0);
    t_true("request: within timeout_ms + 200", dt >= 390 && dt <= 400 + 200);
    stop(pid, lfd);

    lfd = listen_at(path, 4);
    pid = serve(path, 3, lfd);
    t0 = mono_ms();
    rc = ts_ipc_request(path, TS_IPC_STATUS, 400, buf, sizeof buf, &len);
    dt = mono_ms() - t0;
    t_true("request: a stall mid-reply times out, bytes so far kept", rc == TS_REQ_TIMEOUT && len == 6 &&
           memcmp(buf, "ok\nsta", 6) == 0 && dt <= 400 + 200);
    stop(pid, lfd);

    /* A daemon that drops the connection before reading: no SIGPIPE, no crash. */
    lfd = listen_at(path, 4);
    pid = fork();
    if (pid == 0) {
        for (;;) {
            int c = accept(lfd, NULL, NULL);
            if (c < 0) _exit(0);
            close(c);
        }
    }
    {
        int i, bad = 0;
        for (i = 0; i < 50; i++) {
            rc = ts_ipc_request(path, TS_IPC_STATUS, 2000, buf, sizeof buf, &len);
            if (rc != TS_REQ_OK && rc != TS_REQ_FAILED) bad++;
        }
        t_true("request: an instantly closed connection is not fatal", bad == 0);
    }
    stop(pid, lfd);

    /* Mode 0000, made by this user: DENIED. Root ignores permissions. */
    lfd = listen_at(path, 4);
    if (geteuid() == 0) {
        printf("SKIP: request: denied test (running as root)\n");
    } else {
        t_true("request: chmod 0", chmod(path, 0) == 0);
        rc = ts_ipc_request(path, TS_IPC_STATUS, 1000, buf, sizeof buf, &len);
        t_true("request: no permission is DENIED", rc == TS_REQ_DENIED);
    }
    close(lfd);

    /* A path that is a plain file, and one too long. */
    {
        FILE *f;
        unlink(path);
        f = fopen(path, "w");
        if (f) fclose(f);
        rc = ts_ipc_request(path, TS_IPC_STATUS, 1000, buf, sizeof buf, &len);
        t_true("request: a plain file is FAILED", rc == TS_REQ_FAILED);
        unlink(path);
        {
            char longp[300];
            memset(longp, 'a', sizeof longp - 1);
            longp[0] = '/';
            longp[sizeof longp - 1] = 0;
            rc = ts_ipc_request(longp, TS_IPC_STATUS, 1000, buf, sizeof buf, &len);
            t_true("request: a path too long is FAILED", rc == TS_REQ_FAILED);
        }
    }
    unlink(path);
}

void test_ipc_reply(void)
{
    test_parse();
    test_request();
}
