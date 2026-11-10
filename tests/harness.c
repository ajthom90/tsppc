#include "harness.h"

#include <stdio.h>
#include <string.h>

static int g_checks;
static int g_failed;

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void t_unhex(uint8_t *out, const char *hex)
{
    size_t i, n = strlen(hex) / 2;
    for (i = 0; i < n; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        out[i] = (uint8_t)(((hi < 0 ? 0 : hi) << 4) | (lo < 0 ? 0 : lo));
    }
}

void t_true(const char *name, int cond)
{
    g_checks++;
    if (!cond) {
        g_failed++;
        printf("FAIL: %s\n", name);
    }
}

void t_hex(const char *name, const uint8_t *got, size_t n, const char *want_hex)
{
    static const char digits[] = "0123456789abcdef";
    char buf[2049];
    size_t i, m = n > 1024 ? 1024 : n;
    int ok;

    for (i = 0; i < m; i++) {
        buf[2 * i] = digits[got[i] >> 4];
        buf[2 * i + 1] = digits[got[i] & 15];
    }
    buf[2 * m] = 0;
    ok = (m == n) && strlen(want_hex) == 2 * n && strcmp(buf, want_hex) == 0;
    g_checks++;
    if (!ok) {
        g_failed++;
        printf("FAIL: %s\n  got:  %s\n  want: %s\n", name, buf, want_hex);
    }
}

int t_summary(void)
{
    if (g_failed == 0) {
        printf("RESULT: all passed (%d checks)\n", g_checks);
        return 0;
    }
    printf("RESULT: %d FAILED\n", g_failed);
    return 1;
}
