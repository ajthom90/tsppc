#include "fuzz.h"
#include "../src/daemon/ipc_reply.h"

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
    for (i = 0; i < g_r.npeers; i++) {
        TS_FUZZ_ASSERT(printable(g_peers[i].name, sizeof g_peers[i].name) && g_peers[i].name[0]);
        TS_FUZZ_ASSERT(g_peers[i].have_ipv4 || g_peers[i].ipv4 == 0);
    }
}

void ts_fuzz_ipc_reply(void)
{
    static const char *const s[] = {
        ("ok\nstate RUNNING\nstatus connected\nlogin yes\nwanted up\nself host.example.test.\nip 100.64.0.1\n"
         "peer 100.64.0.10 online p10.example.test.\npeer - offline p11.example.test.\n"),
        "ok\nstate NEED_LOGIN\nurl https://login.example.test/a/x\nproblem system clock is wrong\ntruncated\n",
        "error request too long\n",
        "ok\nexitnode x\nPeer 1.2.3.4 online x\npeer 1.2.3 online x\npeer 256.0.0.1 offline \x1b[2Jq\npeer\n",
    };
    const uint8_t *seeds[4];
    size_t lens[4], i;
    for (i = 0; i < 4; i++) {
        seeds[i] = (const uint8_t *)s[i];
        lens[i] = strlen(s[i]);
    }
    ts_fuzz_run("ipc_reply", target, seeds, lens, 4, TS_FUZZ_DEFAULT_ITERS);
}
