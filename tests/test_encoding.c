#include "harness.h"
#include "../src/proto/encoding.h"

#include <string.h>

void test_encoding(void)
{
    char out[64];
    uint8_t raw[8];
    const uint8_t ff[2] = { 0x00, 0xff };

    t_true("hex enc len", ts_hex_encode(out, sizeof out, ff, 2) == 4);
    t_true("hex enc", strcmp(out, "00ff") == 0);
    t_true("hex enc empty", ts_hex_encode(out, sizeof out, ff, 0) == 0 && out[0] == 0);
    memset(out, 'x', sizeof out);
    t_true("hex enc too small", ts_hex_encode(out, 4, ff, 2) == 0);
    t_true("hex enc too small untouched", out[4] == 'x' && out[5] == 'x');

    t_true("hex dec ok", ts_hex_decode(raw, 2, "00fF", 4) == 0);
    t_hex("hex dec value", raw, 2, "00ff");
    t_true("hex dec odd", ts_hex_decode(raw, 2, "00f", 3) == -1);
    t_true("hex dec short", ts_hex_decode(raw, 2, "00", 2) == -1);
    t_true("hex dec long", ts_hex_decode(raw, 2, "00ff00", 6) == -1);
    t_true("hex dec nonhex", ts_hex_decode(raw, 2, "00fg", 4) == -1);
    t_true("hex dec empty", ts_hex_decode(raw, 0, "", 0) == 0);

    t_true("b64 hello", ts_b64_encode(out, sizeof out, (const uint8_t *)"hello", 5) == 8);
    t_true("b64 hello str", strcmp(out, "aGVsbG8=") == 0);
    t_true("b64 empty", ts_b64_encode(out, sizeof out, (const uint8_t *)"", 0) == 0 && out[0] == 0);
    t_true("b64 1", ts_b64_encode(out, sizeof out, (const uint8_t *)"f", 1) == 4 && strcmp(out, "Zg==") == 0);
    t_true("b64 2", ts_b64_encode(out, sizeof out, (const uint8_t *)"fo", 2) == 4 && strcmp(out, "Zm8=") == 0);
    t_true("b64 3", ts_b64_encode(out, sizeof out, (const uint8_t *)"foo", 3) == 4 && strcmp(out, "Zm9v") == 0);
    t_true("b64 high", ts_b64_encode(out, sizeof out, (const uint8_t *)"\xfb\xff\xbf", 3) == 4 && strcmp(out, "+/+/") == 0);
    memset(out, 'x', sizeof out);
    t_true("b64 too small", ts_b64_encode(out, 8, (const uint8_t *)"hello", 5) == 0);
    t_true("b64 too small untouched", out[8] == 'x');
}
