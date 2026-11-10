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
    char out[256];
    size_t i, start, n, k, v;

    if (ts_ipc_parse_request(p, len, &c) == 0) {
        const char *want = ts_ipc_cmd_line(c);
        TS_FUZZ_ASSERT(len <= TS_IPC_LINE_MAX);
        TS_FUZZ_ASSERT(strlen(want) == len && memcmp(want, p, len) == 0);
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
    };
    const uint8_t *seeds[7];
    size_t lens[7], i;
    for (i = 0; i < 7; i++) {
        seeds[i] = (const uint8_t *)s[i];
        lens[i] = strlen(s[i]);
    }
    ts_fuzz_run("ipc", target, seeds, lens, 7, TS_FUZZ_DEFAULT_ITERS);
}
