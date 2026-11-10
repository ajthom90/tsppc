#include "fuzz.h"
#include "../src/proto/json.h"

#include <string.h>

static void target(const uint8_t *data, size_t len)
{
    ts_json j;
    ts_json_tok t;
    ts_json_type ty;
    char s[24];
    int64_t v;
    size_t guard = 0;

    ts_json_init(&j, (const char *)data, len);
    while ((ty = ts_json_next(&j, &t)) != TS_JSON_END && ty != TS_JSON_ERROR) {
        if (++guard > len + 1) __builtin_trap();   /* must consume input */
        if (ty == TS_JSON_STRING || ty == TS_JSON_KEY) {
            (void)ts_json_string(s, sizeof s, &t);
            (void)ts_json_string(s, 1, &t);
        } else if (ty == TS_JSON_NUMBER) {
            (void)ts_json_int64(&v, &t);
        } else if ((ty == TS_JSON_OBJ_START || ty == TS_JSON_ARR_START) && guard % 3 == 0) {
            if (ts_json_skip(&j, &t) != 0) break;
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
    const uint8_t *seeds[sizeof docs / sizeof docs[0]];
    size_t lens[sizeof docs / sizeof docs[0]];
    size_t i;
    for (i = 0; i < sizeof docs / sizeof docs[0]; i++) {
        seeds[i] = (const uint8_t *)docs[i];
        lens[i] = strlen(docs[i]);
    }
    ts_fuzz_run("json", target, seeds, lens, sizeof docs / sizeof docs[0], TS_FUZZ_DEFAULT_ITERS);
}
