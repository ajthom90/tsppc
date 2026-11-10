#include "fuzz.h"
#include "../src/proto/json.h"

#include <stdlib.h>
#include <string.h>

static void check_string(const ts_json_tok *t)
{
    size_t cap = t->rawlen + 1;
    char *out = (char *)malloc(cap);
    char *exact;
    int r;
    TS_FUZZ_ASSERT(out != NULL);
    r = ts_json_string(out, cap, t);
    TS_FUZZ_ASSERT(r >= 0);                       /* next() validated it */
    TS_FUZZ_ASSERT(strlen(out) == (size_t)r);
    exact = (char *)malloc((size_t)r + 1);
    TS_FUZZ_ASSERT(exact != NULL);
    TS_FUZZ_ASSERT(ts_json_string(exact, (size_t)r + 1, t) == r);
    TS_FUZZ_ASSERT(strcmp(exact, out) == 0);
    free(exact);
    exact = (char *)malloc(r > 0 ? (size_t)r : 1);
    TS_FUZZ_ASSERT(exact != NULL);
    TS_FUZZ_ASSERT(ts_json_string(exact, (size_t)r, t) == -1);
    free(exact);
    free(out);
}

static void target(const uint8_t *data, size_t len)
{
    ts_json j, k;
    ts_json_tok t, u;
    ts_json_type ty;
    int64_t v;
    size_t guard = 0;

    ts_json_init(&j, (const char *)data, len);
    while ((ty = ts_json_next(&j, &t)) != TS_JSON_END && ty != TS_JSON_ERROR) {
        TS_FUZZ_ASSERT(++guard <= len + 1);        /* must consume input */
        if (ty == TS_JSON_STRING || ty == TS_JSON_KEY) check_string(&t);
        else if (ty == TS_JSON_NUMBER) (void)ts_json_int64(&v, &t);
        if (ty == TS_JSON_KEY || ty == TS_JSON_OBJ_START || ty == TS_JSON_ARR_START) {
            k = j;   /* skip on a copy so the walk continues */
            u = t;
            (void)ts_json_skip(&k, &u);
        }
    }
    /* Whole-document skip from the start as well. */
    ts_json_init(&j, (const char *)data, len);
    if (ts_json_next(&j, &t) != TS_JSON_ERROR) (void)ts_json_skip(&j, &t);
}

void ts_fuzz_json(void)
{
    static const char *const docs[] = {
        "{\"a\":[1,true,null,\"x\\n\"],\"b\":{}}",
        ("{\"Node\":{\"ID\":12,\"Name\":\"h\\u00e9\\ud83d\\ude00\",\"Addrs\":[\"100.64.0.1/32\"],\"Online\":false},"
        "\"Peers\":[{\"Key\":\"nodekey:00\",\"Cap\":-9223372036854775808,\"X\":1.5e-3}]}"),
        " [ [ [ ] , { } ] , \"\\\\\\/\\b\\f\\r\\t\" , 0 , -0.0 , 1E+9 ] ",
        "\"\\ud83d\\ude00\\u00e9\"",
        "tru", "nullx", "{\"a\":", "[1,]",
    };
    enum { NDOC = sizeof docs / sizeof docs[0], NDEEP = 7, NSEED = NDOC + NDEEP };
    static char deep[NDEEP][512];
    const uint8_t *seeds[NSEED];
    size_t lens[NSEED];
    static const int levels[3] = { 31, 32, 33 };
    size_t i, d;

    /* Depth seeds: 31, 32, 33 levels of arrays and of {"a": objects, and a
     * mixed {"a":[{"a":[... seed of 32 levels, to sit on the depth limit. */
    for (d = 0; d < NDEEP; d++) {
        char *p = deep[d];
        int n = d < 6 ? levels[d % 3] : 32;
        char closers[40];
        int c = 0, lv;
        for (lv = 0; lv < n; lv++) {
            int obj = d < 3 ? 0 : d < 6 ? 1 : (lv % 2 == 0);
            if (obj) { memcpy(p, "{\"a\":", 5); p += 5; closers[c++] = '}'; }
            else { *p++ = '['; closers[c++] = ']'; }
        }
        *p++ = '1';
        while (c > 0) *p++ = closers[--c];
        *p = 0;
    }
    for (i = 0; i < NSEED; i++) {
        const char *src = i < NDOC ? docs[i] : deep[i - NDOC];
        seeds[i] = (const uint8_t *)src;
        lens[i] = strlen(src);
    }
    ts_fuzz_run("json", target, seeds, lens, NSEED, TS_FUZZ_DEFAULT_ITERS);
}
