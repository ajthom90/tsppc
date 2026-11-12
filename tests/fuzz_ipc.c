#include "fuzz.h"
#include "../src/daemon/ipc.h"

#include <stdlib.h>
#include <string.h>

/* The daemon's request parser and the CLI's reply handling (split each line,
 * clean it for the terminal) on arbitrary bytes. */
static void target(const uint8_t *data, size_t len)
{
    const char *p = (const char *)data;
    ts_ipc_cmd c;
    ts_ipc_args a;
    char out[256];
    size_t i, start, n, k, v;

    /* A request that parses is canonical: formatting it again gives the
     * same bytes. */
    if (ts_ipc_parse_request(p, len, &c, &a) == 0) {
        TS_FUZZ_ASSERT(len <= TS_IPC_LINE_MAX);
        if (c == TS_IPC_PING) {
            int m = ts_ipc_ping_line(out, sizeof out, a.ip, a.timeout_ms);
            TS_FUZZ_ASSERT(a.timeout_ms >= TS_IPC_PING_MIN_MS && a.timeout_ms <= TS_IPC_PING_MAX_MS);
            TS_FUZZ_ASSERT(m > 0 && (size_t)m == len && memcmp(out, p, len) == 0);
        } else {
            const char *want = ts_ipc_cmd_line(c);
            TS_FUZZ_ASSERT(a.ip == 0 && a.timeout_ms == 0);
            TS_FUZZ_ASSERT(strlen(want) == len && memcmp(want, p, len) == 0);
        }
    }

    for (start = 0, i = 0; i <= len; i++) {
        if (i < len && p[i] != '\n') continue;
        n = i - start;
        if (ts_ipc_split(p + start, n, &k, &v) == 0) {
            TS_FUZZ_ASSERT(k > 0 && k <= n && v <= n && v >= k);
            TS_FUZZ_ASSERT(v == k || (v == k + 1 && p[start + k] == ' '));
        }
        k = ts_ipc_clean(out, sizeof out, p + start, n, 0);
        TS_FUZZ_ASSERT(k < sizeof out && out[k] == 0 && strlen(out) == k);
        for (v = 0; v < k; v++)
            TS_FUZZ_ASSERT((unsigned char)out[v] >= 0x20 && (unsigned char)out[v] < 0x7f);
        start = i + 1;
    }
    k = ts_ipc_clean(out, 8, p, len, 1);
    TS_FUZZ_ASSERT(k < 8 && out[k] == 0);
}

void ts_fuzz_ipc(void)
{
    static const char *const s[] = {
        "status\n", "up\n", "ip\n", "logout\n",
        ("ok\nstate NEED_LOGIN\nstatus NEED_LOGIN: visit https://login.example.test/a/x; 0 peers\n"
         "url https://login.example.test/a/x\n"),
        "ok\nstate RUNNING\nip 100.64.0.1\npeer 100.64.0.10 online p10.example.test.\npeer - offline \x1b[2Jq\n",
        "error request too long\n",
        "ping 100.64.0.2 5000\n",
        "ping 255.255.255.255 10000\n",
        "ok\nping pong 23456 7 nyc\n",
        "ok\nping timeout\n",
    };
    const uint8_t *seeds[11];
    size_t lens[11], i;
    for (i = 0; i < 11; i++) {
        seeds[i] = (const uint8_t *)s[i];
        lens[i] = strlen(s[i]);
    }
    ts_fuzz_run("ipc", target, seeds, lens, 11, TS_FUZZ_DEFAULT_ITERS);
}
