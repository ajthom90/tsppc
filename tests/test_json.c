#include "harness.h"
#include "../src/proto/json.h"

#include <string.h>

/* Walk a whole document; returns the final token type (END or ERROR). */
static ts_json_type walk(const char *s, int *ntok)
{
    ts_json j;
    ts_json_tok t;
    ts_json_type ty;
    int n = 0;
    ts_json_init(&j, s, strlen(s));
    while ((ty = ts_json_next(&j, &t)) != TS_JSON_END && ty != TS_JSON_ERROR) n++;
    if (ntok) *ntok = n;
    return ty;
}

static int bad(const char *s) { return walk(s, NULL) == TS_JSON_ERROR; }
static int good(const char *s) { return walk(s, NULL) == TS_JSON_END; }

static void test_sequence(void)
{
    static const ts_json_type want[] = {
        TS_JSON_OBJ_START, TS_JSON_KEY, TS_JSON_ARR_START, TS_JSON_NUMBER,
        TS_JSON_TRUE, TS_JSON_NUL, TS_JSON_STRING, TS_JSON_ARR_END,
        TS_JSON_KEY, TS_JSON_OBJ_START, TS_JSON_OBJ_END, TS_JSON_OBJ_END,
        TS_JSON_END
    };
    const char *doc = "{\"a\":[1,true,null,\"x\\n\"],\"b\":{}}";
    ts_json j;
    ts_json_tok t;
    size_t i;
    int ok = 1;
    char s[8];
    ts_json_init(&j, doc, strlen(doc));
    for (i = 0; i < sizeof want / sizeof want[0]; i++) {
        ts_json_type ty = ts_json_next(&j, &t);
        if (ty != want[i] || t.type != ty) ok = 0;
        if (ty == TS_JSON_STRING) {
            t_true("string decode", ts_json_string(s, sizeof s, &t) == 2 && strcmp(s, "x\n") == 0);
        }
        if (ty == TS_JSON_KEY && i == 1) t_true("key raw", t.rawlen == 1 && t.raw[0] == 'a');
    }
    t_true("token sequence", ok);
    t_true("end is sticky", ts_json_next(&j, &t) == TS_JSON_END);
    t_true("false literal", walk("false", NULL) == TS_JSON_END);
    t_true("whitespace", good(" \t\r\n{ \n\"a\" \t:\r [ 1 , 2 ] , \"b\" : { } } \n"));
    t_true("scalar top", good("42") && good("\"x\"") && good("null"));
}

static void test_strings(void)
{
    ts_json j;
    ts_json_tok t;
    char out[16];
    const char *d;

    d = "\"\\u00e9\"";
    ts_json_init(&j, d, strlen(d)); ts_json_next(&j, &t);
    t_true("u00e9 len", ts_json_string(out, sizeof out, &t) == 2);
    t_hex("u00e9", (const uint8_t *)out, 2, "c3a9");

    d = "\"\\ud83d\\ude00\"";
    ts_json_init(&j, d, strlen(d)); ts_json_next(&j, &t);
    t_true("surrogate len", ts_json_string(out, sizeof out, &t) == 4);
    t_hex("surrogate pair", (const uint8_t *)out, 4, "f09f9880");

    d = "\"a\\\"\\\\\\/\\b\\f\\n\\r\\tz\\u20ac\"";
    ts_json_init(&j, d, strlen(d)); ts_json_next(&j, &t);
    t_true("escapes len", ts_json_string(out, sizeof out, &t) == 13);
    t_hex("escapes", (const uint8_t *)out, 13, "61225c2f080c0a0d097ae282ac");

    d = "\"abcdef\"";
    ts_json_init(&j, d, strlen(d)); ts_json_next(&j, &t);
    memset(out, 'x', sizeof out);
    t_true("fits exactly", ts_json_string(out, 7, &t) == 6 && strcmp(out, "abcdef") == 0);
    memset(out, 'x', sizeof out);
    t_true("too big", ts_json_string(out, 6, &t) == -1);
    t_true("too big no overrun", out[6] == 'x' && out[7] == 'x');
    t_true("cap zero", ts_json_string(out, 0, &t) == -1);

    d = "\"\\u0000\"";
    ts_json_init(&j, d, strlen(d)); ts_json_next(&j, &t);
    t_true("nul escape refused", ts_json_string(out, sizeof out, &t) == -1);
    t_true("string on number", ts_json_string(out, sizeof out, &(ts_json_tok){ TS_JSON_NUMBER, "1", 1 }) == -1);
}

static void test_int64(void)
{
    ts_json_tok t;
    int64_t v = 0;
#define NUM(s) (t.type = TS_JSON_NUMBER, t.raw = (s), t.rawlen = strlen(s), &t)
    t_true("int 0", ts_json_int64(&v, NUM("0")) == 0 && v == 0);
    t_true("int -17", ts_json_int64(&v, NUM("-17")) == 0 && v == -17);
    t_true("int max", ts_json_int64(&v, NUM("9223372036854775807")) == 0 && v == INT64_MAX);
    t_true("int min", ts_json_int64(&v, NUM("-9223372036854775808")) == 0 && v == INT64_MIN);
    t_true("int overflow", ts_json_int64(&v, NUM("9223372036854775808")) == -1);
    t_true("int underflow", ts_json_int64(&v, NUM("-9223372036854775809")) == -1);
    t_true("int frac", ts_json_int64(&v, NUM("1.5")) == -1);
    t_true("int exp", ts_json_int64(&v, NUM("1e3")) == -1);
    t_true("int empty", ts_json_int64(&v, NUM("")) == -1);
    t_true("int minus only", ts_json_int64(&v, NUM("-")) == -1);
    t_true("int leading zero", ts_json_int64(&v, NUM("01")) == -1);
    t_true("int not number", ts_json_int64(&v, &(ts_json_tok){ TS_JSON_STRING, "1", 1 }) == -1);
#undef NUM
}

static void test_skip(void)
{
    const char *d = "{\"a\":{\"b\":[1,[2,3],{}]},\"c\":7}";
    ts_json j;
    ts_json_tok t;
    int64_t v = 0;
    ts_json_init(&j, d, strlen(d));
    ts_json_next(&j, &t);                    /* { */
    ts_json_next(&j, &t);                    /* "a" */
    ts_json_next(&j, &t);                    /* { of a's value */
    t_true("skip object", ts_json_skip(&j, &t) == 0);
    t_true("after skip key", ts_json_next(&j, &t) == TS_JSON_KEY);
    t_true("after skip number", ts_json_next(&j, &t) == TS_JSON_NUMBER && ts_json_int64(&v, &t) == 0 && v == 7);
    t_true("skip scalar", ts_json_skip(&j, &t) == 0);
    t_true("after skip close", ts_json_next(&j, &t) == TS_JSON_OBJ_END);
    t_true("skip end refused", ts_json_skip(&j, &t) == -1);

    d = "[1,[2,";
    ts_json_init(&j, d, strlen(d));
    ts_json_next(&j, &t);
    t_true("skip truncated", ts_json_skip(&j, &t) == -1);
}

static void test_errors(void)
{
    char deep[128];
    size_t i;
    t_true("trailing comma obj", bad("{\"a\":1,}"));
    t_true("trailing comma arr", bad("[1,]"));
    t_true("leading comma", bad("[,1]"));
    t_true("double comma", bad("[1,,2]"));
    t_true("missing colon", bad("{\"a\" 1}"));
    t_true("missing value", bad("{\"a\":}"));
    t_true("key not string", bad("{1:2}"));
    t_true("missing comma", bad("[1 2]"));
    t_true("mismatched close", bad("[1}") && bad("{\"a\":1]"));
    t_true("unterminated string", bad("\"abc") && bad("[\"abc"));
    t_true("unterminated escape", bad("\"abc\\") && bad("\"\\u12\""));
    t_true("unterminated doc", bad("{") && bad("[1") && bad("{\"a\":1") && bad(""));
    t_true("raw control char", bad("\"a\tb\"") && bad("\"a\nb\""));
    t_true("raw control 0x01", bad("\"a\x01" "b\""));
    t_true("bad escape", bad("\"\\x\"") && bad("\"\\u12g4\""));
    t_true("lone high surrogate", bad("\"\\ud83d\"") && bad("\"\\ud83dx\""));
    t_true("lone low surrogate", bad("\"\\ude00\""));
    t_true("high then non-low", bad("\"\\ud83d\\u0041\""));
    t_true("trailing garbage", bad("1 2") && bad("{} x") && bad("[] ]"));
    t_true("bad literals", bad("tru") && bad("nul") && bad("falsey") && bad("True"));
    t_true("bad numbers", bad("01") && bad("-") && bad("1.") && bad(".5") && bad("1e") && bad("+1") && bad("1e+"));
    t_true("good numbers", good("-0") && good("1.5e10") && good("0.25") && good("[1E-3]"));

    /* Depth: 32 nested arrays pass, 33 fail. */
    for (i = 0; i < 32; i++) deep[i] = '[';
    for (i = 0; i < 32; i++) deep[32 + i] = ']';
    deep[64] = 0;
    t_true("depth 32 ok", good(deep));
    for (i = 0; i < 33; i++) deep[i] = '[';
    for (i = 0; i < 33; i++) deep[33 + i] = ']';
    deep[66] = 0;
    t_true("depth 33 error", bad(deep));
    for (i = 0; i < 40; i++) deep[i] = '[';
    deep[40] = 0;
    t_true("depth 40 unclosed error", bad(deep));
    {
        ts_json j;
        ts_json_tok t;
        ts_json_init(&j, "{\"a\"", 4);
        ts_json_next(&j, &t); ts_json_next(&j, &t);
        t_true("error is sticky", ts_json_next(&j, &t) == TS_JSON_ERROR && ts_json_next(&j, &t) == TS_JSON_ERROR);
    }
    /* A length shorter than the buffer is respected (no NUL needed). */
    {
        ts_json j;
        ts_json_tok t;
        ts_json_init(&j, "[1,2]xyz", 5);
        t_true("len honoured", ts_json_next(&j, &t) == TS_JSON_ARR_START);
    }
}

void test_json(void)
{
    test_sequence();
    test_strings();
    test_int64();
    test_skip();
    test_errors();
}
