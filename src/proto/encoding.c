#include "encoding.h"

size_t ts_hex_encode(char *out, size_t cap, const uint8_t *in, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    if (n > (SIZE_MAX - 1) / 2 || cap < 2 * n + 1) {
        if (cap > 0) out[0] = 0;
        return 0;
    }
    for (i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * n] = 0;
    return 2 * n;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int ts_hex_decode(uint8_t *out, size_t want, const char *hex, size_t hexlen)
{
    size_t i;
    if (want > SIZE_MAX / 2 || hexlen != 2 * want) return -1;
    for (i = 0; i < want; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

size_t ts_b64_encode(char *out, size_t cap, const uint8_t *in, size_t n)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t groups = n / 3 + (n % 3 ? 1 : 0);
    size_t need, i, o = 0;
    if (groups > (SIZE_MAX - 1) / 4) need = SIZE_MAX;
    else need = groups * 4 + 1;
    if (cap < need) {
        if (cap > 0) out[0] = 0;
        return 0;
    }
    for (i = 0; i + 3 <= n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = tbl[v >> 18];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = tbl[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = tbl[v >> 18];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = tbl[v >> 18];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = 0;
    return o;
}
