#include "upgrade.h"

#include <string.h>

#include "../core/bytes.h"
#include "../proto/encoding.h"
#include "../proto/json.h"

static const char UPGRADE_VALUE[] = "tailscale-control-protocol";
static const uint8_t EARLY_MAGIC[5] = { 0xff, 0xff, 0xff, 'T', 'S' };

/* Append s[0..n) at *at if it fits below cap (leaving room for a NUL). */
static int put(char *out, size_t cap, size_t *at, const char *s, size_t n)
{
    if (n >= cap - *at) return -1;
    memcpy(out + *at, s, n);
    *at += n;
    return 0;
}

size_t ts_upgrade_request(char *out, size_t cap, const char *host,
                          const uint8_t init[TS_NOISE_INIT_LEN])
{
    static const char l1[] = "POST /ts2021 HTTP/1.1\r\nHost: ";
    static const char l2[] = "\r\nUpgrade: tailscale-control-protocol\r\n"
                             "Connection: upgrade\r\n"
                             "Content-Length: 0\r\n"
                             "X-Tailscale-Handshake: ";
    static const char l3[] = "\r\n\r\n";
    char b64[4 * ((TS_NOISE_INIT_LEN + 2) / 3) + 1];
    size_t at = 0, hl, bl, i;

    if (cap > 0) out[0] = 0;
    if (cap == 0) return 0;
    hl = strlen(host);
    if (hl == 0) return 0;
    for (i = 0; i < hl; i++)
        if ((unsigned char)host[i] <= ' ' || (unsigned char)host[i] > '~') return 0;
    bl = ts_b64_encode(b64, sizeof b64, init, TS_NOISE_INIT_LEN);
    if (bl == 0 ||
        put(out, cap, &at, l1, sizeof l1 - 1) || put(out, cap, &at, host, hl) ||
        put(out, cap, &at, l2, sizeof l2 - 1) || put(out, cap, &at, b64, bl) ||
        put(out, cap, &at, l3, sizeof l3 - 1)) {
        out[0] = 0;
        return 0;
    }
    out[at] = 0;
    return at;
}

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int ieq(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (lower((unsigned char)a[i]) != lower((unsigned char)b[i])) return 0;
    return 1;
}

static int is_ows(char c) { return c == ' ' || c == '\t'; }

/* Index of the first "\r\n" at or after from, or len if none. */
static size_t find_crlf(const char *buf, size_t len, size_t from)
{
    size_t i;
    for (i = from; i + 1 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
    return len;
}

/* Status line "HTTP/1.x NNN[ reason]" in buf[0..end). Returns the code or -1. */
static int status_code(const char *buf, size_t end)
{
    int code = 0;
    size_t i;
    if (end < 12 || memcmp(buf, "HTTP/1.", 7) != 0 || (buf[7] != '0' && buf[7] != '1') ||
        buf[8] != ' ')
        return -1;
    for (i = 9; i < 12; i++) {
        if (buf[i] < '0' || buf[i] > '9') return -1;
        code = code * 10 + (buf[i] - '0');
    }
    if (end > 12 && buf[12] != ' ') return -1;
    return code;
}

int ts_upgrade_response(const char *buf, size_t len, size_t *consumed)
{
    return ts_http_upgrade_response(buf, len, UPGRADE_VALUE, consumed);
}

int ts_http_upgrade_response(const char *buf, size_t len, const char *proto, size_t *consumed)
{
    size_t plen = strlen(proto);
    size_t scan = len < TS_UPGRADE_HEADER_MAX ? len : TS_UPGRADE_HEADER_MAX;
    size_t eol, at;
    int upgrade_ok = 0, upgrade_seen = 0;

    *consumed = 0;
    /* Decide on the status line as soon as it is complete. */
    eol = find_crlf(buf, scan, 0);
    if (eol == scan) return len < TS_UPGRADE_HEADER_MAX ? 1 : -1;
    if (status_code(buf, eol) != 101) return -1;

    /* Header lines until the empty one. */
    at = eol + 2;
    for (;;) {
        size_t colon, vs, ve;
        eol = find_crlf(buf, scan, at);
        if (eol == scan) return len < TS_UPGRADE_HEADER_MAX ? 1 : -1;
        if (eol == at) break;
        for (colon = at; colon < eol && buf[colon] != ':'; colon++) {}
        if (colon == eol || colon == at) return -1;
        /* The first Upgrade header decides, as Go's Header.Get does. */
        if (!upgrade_seen && colon - at == 7 && ieq(buf + at, "upgrade", 7)) {
            upgrade_seen = 1;
            for (vs = colon + 1; vs < eol && is_ows(buf[vs]); vs++) {}
            for (ve = eol; ve > vs && is_ows(buf[ve - 1]); ve--) {}
            upgrade_ok = ve - vs == plen && ieq(buf + vs, proto, plen);
        }
        at = eol + 2;
    }
    if (!upgrade_ok) return -1;
    *consumed = eol + 2;
    return 0;
}

/* One complete JSON value, optionally surrounded by whitespace. */
static int is_json(const char *p, size_t n)
{
    ts_json j;
    ts_json_tok t;
    ts_json_type ty;

    ts_json_init(&j, p, n);
    do ty = ts_json_next(&j, &t);
    while (ty != TS_JSON_END && ty != TS_JSON_ERROR);
    return ty == TS_JSON_END;
}

int ts_early_payload(const uint8_t *buf, size_t len, size_t *consumed)
{
    size_t n = len < sizeof EARLY_MAGIC ? len : sizeof EARLY_MAGIC;
    uint32_t plen;

    *consumed = 0;
    if (len == 0) return 1;
    if (memcmp(buf, EARLY_MAGIC, n) != 0) return 0;
    if (len < 9) return 1;
    plen = ts_get_be32(buf + 5);
    if (plen > TS_EARLY_PAYLOAD_MAX) return -1;
    if (len - 9 < plen) return 1;
    if (!is_json((const char *)buf + 9, plen)) return -1;
    *consumed = 9 + (size_t)plen;
    return 0;
}
