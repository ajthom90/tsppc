#include "fuzz.h"
#include "../src/net/keyfetch.h"

#include <string.h>

/* The /key response: the HTTP/1.x framing over every prefix and with or
 * without end of stream, and the JSON body of a complete response. */
static void target(const uint8_t *data, size_t len)
{
    const char *s = (const char *)data;
    uint8_t pub[32], before[32];
    int st, rc, eof;
    size_t off, blen, cut;

    for (eof = 0; eof <= 1; eof++) {
        rc = ts_http1_response(s, len, eof, &st, &off, &blen);
        TS_FUZZ_ASSERT(rc >= -1 && rc <= 1);
        TS_FUZZ_ASSERT(!(eof && rc == 1));
        if (rc != 0) continue;
        TS_FUZZ_ASSERT(st >= 100 && st <= 599);
        TS_FUZZ_ASSERT(off <= len && blen <= len - off);
        TS_FUZZ_ASSERT(st == 200 || blen == 0);
        TS_FUZZ_ASSERT(blen <= TS_KEYFETCH_MAX);
        /* A complete response is never complete earlier without end of
         * stream, apart from a non-200 status, which needs only headers. */
        for (cut = off; cut < len && st == 200; cut += 1 + cut / 8) {
            int r2, st2;
            size_t o2, b2;
            r2 = ts_http1_response(s, cut, 0, &st2, &o2, &b2);
            TS_FUZZ_ASSERT(r2 != 0);
        }
        memset(pub, 0xa5, sizeof pub);
        memcpy(before, pub, sizeof pub);
        if (ts_control_key_parse(pub, s + off, blen) != 0)
            TS_FUZZ_ASSERT(memcmp(pub, before, sizeof pub) == 0);
    }

    memset(pub, 0x5a, sizeof pub);
    memcpy(before, pub, sizeof pub);
    if (ts_control_key_parse(pub, s, len) != 0)
        TS_FUZZ_ASSERT(memcmp(pub, before, sizeof pub) == 0);
}

void ts_fuzz_keyfetch(void)
{
    static const char *const docs[] = {
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 175\r\n\r\n"
        "{\"legacyPublicKey\":\"mkey:0000000000000000000000000000000000000000000000000000000000000000\","
        "\"publicKey\":\"mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}",
        "HTTP/1.0 200 OK\n\n{ \"publicKey\" : \"mkey:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef\" }\n",
        "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "{\"x\":[1,{\"publicKey\":2}],\"publicKey\":\"mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}",
    };
    enum { NSEED = sizeof docs / sizeof docs[0] };
    const uint8_t *seeds[NSEED];
    size_t lens[NSEED], i;
    for (i = 0; i < NSEED; i++) {
        seeds[i] = (const uint8_t *)docs[i];
        lens[i] = strlen(docs[i]);
    }
    ts_fuzz_run("keyfetch", target, seeds, lens, NSEED, TS_FUZZ_DEFAULT_ITERS);
}
