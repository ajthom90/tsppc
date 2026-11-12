#include "fuzz.h"
#include "../src/daemon/ipc_reply.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Never on the stack: a reply and its peers are large. */
static ts_reply g_r;
static ts_reply_peer g_peers[TS_MAX_PEERS];

static int printable(const char *s, size_t cap)
{
    size_t i;
    for (i = 0; i < cap; i++) {
        if (s[i] == 0) return 1;
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] >= 0x7f) return 0;
    }
    return 0;   /* not terminated */
}

/* The reply parser on arbitrary bytes: bounded, terminated, printable. */
static void target(const uint8_t *data, size_t len)
{
    size_t i;
    char *b = (char *)malloc(len ? len : 1);   /* exact size, so ASan sees overreads */
    int rc;
    if (!b) abort();
    memcpy(b, data, len);
    rc = ts_reply_parse(&g_r, g_peers, b, len);
    free(b);
    TS_FUZZ_ASSERT(rc == 0 || rc == -1);
    TS_FUZZ_ASSERT(g_r.npeers <= TS_MAX_PEERS && g_r.peers == g_peers);
    if (rc == -1) TS_FUZZ_ASSERT(!g_r.ok && g_r.error[0] == 0);
    TS_FUZZ_ASSERT(printable(g_r.error, sizeof g_r.error) && printable(g_r.state, sizeof g_r.state));
    TS_FUZZ_ASSERT(printable(g_r.status, sizeof g_r.status) && printable(g_r.url, sizeof g_r.url));
    TS_FUZZ_ASSERT(printable(g_r.problem, sizeof g_r.problem) && printable(g_r.login, sizeof g_r.login));
    TS_FUZZ_ASSERT(printable(g_r.wanted, sizeof g_r.wanted) && printable(g_r.self, sizeof g_r.self));
    TS_FUZZ_ASSERT(printable(g_r.ping_code, sizeof g_r.ping_code));
    TS_FUZZ_ASSERT(g_r.ping == TS_REPLY_PING_NONE || g_r.ping == TS_REPLY_PONG || g_r.ping == TS_REPLY_PING_TIMEOUT);
    if (g_r.ping == TS_REPLY_PONG) TS_FUZZ_ASSERT(g_r.ping_region > 0 && g_r.ping_code[0] != 0);
    else TS_FUZZ_ASSERT(g_r.ping_latency_us == 0 && g_r.ping_region == 0 && g_r.ping_code[0] == 0);
    for (i = 0; i < g_r.npeers; i++) {
        TS_FUZZ_ASSERT(printable(g_peers[i].name, sizeof g_peers[i].name));
        TS_FUZZ_ASSERT(g_peers[i].have_ipv4 || g_peers[i].ipv4 == 0);
    }
}

/* Over 256 peers and a value longer than its field, for the cut paths. */
static char g_big[8192];   /* the harness inputs are at most 8192 bytes */

void ts_fuzz_ipc_reply(void)
{
    static const char *const s[] = {
        ("ok\nstate RUNNING\nstatus connected\nlogin yes\nwanted up\nself host.example.test.\nip 100.64.0.1\n"
         "peer 100.64.0.10 online p10.example.test.\npeer - offline p11.example.test.\n"),
        "ok\nstate NEED_LOGIN\nurl https://login.example.test/a/x\nproblem system clock is wrong\ntruncated\n",
        "error request too long\n",
        "ok\nexitnode x\nPeer 1.2.3.4 online x\npeer 1.2.3 online x\npeer 256.0.0.1 offline \x1b[2Jq\npeer\n",
        "ok\nping pong 23456 7 nyc\n",
        "ok\nping timeout\nping pong 4294967295 2147483647 \x1b[2Jq\n",
        "error peer's node key has expired\n",
    };
    const uint8_t *seeds[8];
    size_t lens[8], i, n;
    for (i = 0; i < 7; i++) {
        seeds[i] = (const uint8_t *)s[i];
        lens[i] = strlen(s[i]);
    }
    n = (size_t)snprintf(g_big, sizeof g_big, "ok\nstate RUNNING\nstatus ");
    memset(g_big + n, 's', 40);
    n += 40;
    n += (size_t)snprintf(g_big + n, sizeof g_big - n, "\nlogin yes\nproblem ");
    memset(g_big + n, 'p', 2100);
    n += 2100;
    n += (size_t)snprintf(g_big + n, sizeof g_big - n, "\n");
    for (i = 0; i < TS_MAX_PEERS + 1; i++)
        n += (size_t)snprintf(g_big + n, sizeof g_big - n, "peer %s online n\n", i & 1 ? "-" : "9.9.9.9");
    seeds[7] = (const uint8_t *)g_big;
    lens[7] = n;
    ts_fuzz_run("ipc_reply", target, seeds, lens, 8, TS_FUZZ_DEFAULT_ITERS);
}
