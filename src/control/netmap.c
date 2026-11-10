#include "netmap.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../core/bytes.h"
#include "../proto/encoding.h"
#include "../proto/json.h"

#define STR_(x) #x
#define STR(x) STR_(x)

/* ---- small value parsers ------------------------------------------------ */

/* Decode a KEY token into a short buffer; "" if it does not fit (an unknown
 * key, then, since every key we know is short). */
static void key_name(char *out, size_t cap, const ts_json_tok *t)
{
    if (ts_json_string(out, cap, t) < 0) out[0] = 0;
}

static int is_key(const char *k, const char *want)
{
    return strcmp(k, want) == 0;
}

/* 1 for true, 0 for false, -1 for anything else. null is handled by callers. */
static int tok_bool(const ts_json_tok *t)
{
    if (t->type == TS_JSON_TRUE) return 1;
    if (t->type == TS_JSON_FALSE) return 0;
    return -1;
}

static int tok_int(const ts_json_tok *t, int *out)
{
    int64_t v;
    if (t->type != TS_JSON_NUMBER || ts_json_int64(&v, t) != 0) return -1;
    if (v < INT_MIN || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}

/* "<prefix><64 hex>" into 32 bytes. */
static int parse_key(uint8_t out[32], const ts_json_tok *t, const char *prefix)
{
    char buf[80];
    size_t pl = strlen(prefix);
    int n;
    if (t->type != TS_JSON_STRING) return -1;
    n = ts_json_string(buf, sizeof buf, t);
    if (n < 0 || (size_t)n != pl + 64 || memcmp(buf, prefix, pl) != 0) return -1;
    return ts_hex_decode(out, 32, buf + pl, 64);
}

/* Unsigned decimal of 1..maxdig digits, no leading zero unless it is "0".
 * Advances *p. Returns the value, or -1. */
static long dec(const char **p, int maxdig)
{
    const char *s = *p;
    long v = 0;
    int n = 0;
    while (s[n] >= '0' && s[n] <= '9') {
        if (n == maxdig) return -1;
        v = v * 10 + (s[n] - '0');
        n++;
    }
    if (n == 0 || (n > 1 && s[0] == '0')) return -1;
    *p = s + n;
    return v;
}

/* One Addresses entry. IPv6 (any ':') is ignored without validation; an IPv4
 * prefix must be well formed. Sets *ip and *is32 for a.b.c.d/32. */
static int parse_prefix(const ts_json_tok *t, uint32_t *ip, int *is32)
{
    char buf[64];
    const char *p = buf;
    uint32_t v = 0;
    long o, bits;
    int i;
    *is32 = 0;
    if (t->type != TS_JSON_STRING || ts_json_string(buf, sizeof buf, t) < 0) return -1;
    if (strchr(buf, ':')) return 0;
    for (i = 0; i < 4; i++) {
        if (i && *p++ != '.') return -1;
        o = dec(&p, 3);
        if (o < 0 || o > 255) return -1;
        v = (v << 8) | (uint32_t)o;
    }
    if (*p++ != '/') return -1;
    bits = dec(&p, 2);
    if (bits < 0 || bits > 32 || *p != 0) return -1;
    *ip = v;
    *is32 = bits == 32;
    return 0;
}

/* Exactly n digits. */
static int fixed(const char **p, int n, int *out)
{
    int v = 0, i;
    for (i = 0; i < n; i++) {
        char c = (*p)[i];
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
    }
    *p += n;
    *out = v;
    return 0;
}

/* Days from 1970-01-01 to y-m-d (proleptic Gregorian). */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    int64_t era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* The Go zero time, 0001-01-01T00:00:00Z, in Unix seconds. */
#define GO_ZERO_TIME (-62135596800LL)

/* RFC 3339 as Go's time.Time JSON form writes it: YYYY-MM-DDTHH:MM:SS, an
 * optional fraction of 1 to 9 digits, then Z or +hh:mm / -hh:mm. The zero time
 * gives 0. */
static int parse_time(const ts_json_tok *t, int64_t *out)
{
    static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    char buf[48];
    const char *p = buf;
    int y, mo, d, h, mi, s, oh = 0, om = 0, sign = 0, dim, k;
    int64_t v;
    if (t->type != TS_JSON_STRING || ts_json_string(buf, sizeof buf, t) < 0) return -1;
    if (fixed(&p, 4, &y) || *p++ != '-' || fixed(&p, 2, &mo) || *p++ != '-' || fixed(&p, 2, &d)
        || *p++ != 'T' || fixed(&p, 2, &h) || *p++ != ':' || fixed(&p, 2, &mi) || *p++ != ':'
        || fixed(&p, 2, &s))
        return -1;
    if (*p == '.') {
        p++;
        for (k = 0; p[k] >= '0' && p[k] <= '9'; k++) ;
        if (k < 1 || k > 9) return -1;
        p += k;
    }
    if (*p == 'Z') {
        p++;
    } else if (*p == '+' || *p == '-') {
        sign = *p++ == '-' ? -1 : 1;
        if (fixed(&p, 2, &oh) || *p++ != ':' || fixed(&p, 2, &om)) return -1;
        if (oh > 23 || om > 59) return -1;
    } else {
        return -1;
    }
    if (*p != 0) return -1;
    if (mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 59) return -1;
    dim = mdays[mo - 1];
    if (mo == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) dim = 29;
    if (d < 1 || d > dim) return -1;
    v = days_from_civil(y, mo, d) * 86400 + (int64_t)h * 3600 + mi * 60 + s;
    v -= (int64_t)sign * (oh * 3600 + om * 60);
    *out = v == GO_ZERO_TIME ? 0 : v;
    return 0;
}

/* "127.3.3.40:N" (upstream's DerpMagicIP) gives region N, else 0. */
static int legacy_derp(const ts_json_tok *t)
{
    char buf[40];
    const char *p;
    long v;
    if (ts_json_string(buf, sizeof buf, t) < 0) return 0;
    if (strncmp(buf, "127.3.3.40:", 11) != 0) return 0;
    p = buf + 11;
    v = dec(&p, 9);
    if (v < 0 || *p != 0) return 0;
    return (int)v;
}

/* ---- composite parsers -------------------------------------------------- */

typedef struct {
    const char *err;   /* static text naming the field or limit */
} ctx;

static int bad(ctx *c, const char *msg)
{
    if (!c->err) c->err = msg;
    return -1;
}

/* Next token, which must begin a value. */
static int value(ts_json *r, ts_json_tok *t, ctx *c)
{
    ts_json_next(r, t);
    if (t->type == TS_JSON_ERROR || t->type == TS_JSON_END || t->type == TS_JSON_KEY
        || t->type == TS_JSON_OBJ_END || t->type == TS_JSON_ARR_END)
        return bad(c, "invalid JSON");
    return 0;
}

/* Boolean field: true/false sets *out, null leaves it. */
static int bool_field(const ts_json_tok *v, int *out, ctx *c, const char *what)
{
    int b;
    if (v->type == TS_JSON_NUL) return 0;
    b = tok_bool(v);
    if (b < 0) return bad(c, what);
    *out = b;
    return 0;
}

/* A Node object (the first token already read). Whole replacement: *n is
 * zeroed first. */
static int parse_node(ts_json *r, const ts_json_tok *first, ts_node *n, ctx *c)
{
    ts_json_tok k, v;
    char key[32];
    int legacy = 0;
    memset(n, 0, sizeof *n);
    if (first->type != TS_JSON_OBJ_START) return bad(c, "node is not an object");
    for (;;) {
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) break;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (value(r, &v, c)) return -1;
        if (is_key(key, "ID")) {
            if (v.type == TS_JSON_NUL) continue;
            if (v.type != TS_JSON_NUMBER || ts_json_int64(&n->id, &v) != 0)
                return bad(c, "node ID is not an integer");
        } else if (is_key(key, "Name")) {
            if (v.type == TS_JSON_NUL) { n->name[0] = 0; continue; }
            if (v.type != TS_JSON_STRING) return bad(c, "node Name is not a string");
            if (ts_json_string(n->name, sizeof n->name, &v) < 0)
                return bad(c, "node Name longer than " STR(TS_NODE_NAME_MAX) " bytes");
        } else if (is_key(key, "Key")) {
            if (v.type == TS_JSON_NUL) { memset(n->node_key, 0, 32); continue; }
            if (parse_key(n->node_key, &v, "nodekey:")) return bad(c, "malformed node Key");
        } else if (is_key(key, "DiscoKey")) {
            if (v.type == TS_JSON_NUL) { memset(n->disco_key, 0, 32); continue; }
            if (parse_key(n->disco_key, &v, "discokey:")) return bad(c, "malformed node DiscoKey");
        } else if (is_key(key, "Addresses")) {
            n->ipv4 = 0;
            n->have_ipv4 = 0;
            if (v.type == TS_JSON_NUL) continue;
            if (v.type != TS_JSON_ARR_START) return bad(c, "node Addresses is not an array");
            for (;;) {
                uint32_t ip;
                int is32;
                ts_json_next(r, &v);
                if (v.type == TS_JSON_ARR_END) break;
                if (parse_prefix(&v, &ip, &is32)) return bad(c, "malformed node address");
                if (is32 && !n->have_ipv4) {
                    n->ipv4 = ip;
                    n->have_ipv4 = 1;
                }
            }
        } else if (is_key(key, "HomeDERP")) {
            if (v.type == TS_JSON_NUL) { n->home_derp = 0; continue; }
            if (tok_int(&v, &n->home_derp)) return bad(c, "node HomeDERP is not an int");
        } else if (is_key(key, "DERP")) {
            if (v.type == TS_JSON_NUL) { legacy = 0; continue; }
            if (v.type != TS_JSON_STRING) return bad(c, "node DERP is not a string");
            legacy = legacy_derp(&v);
        } else if (is_key(key, "Online")) {
            if (bool_field(&v, &n->online, c, "node Online is not a bool")) return -1;
        } else if (is_key(key, "MachineAuthorized")) {
            if (bool_field(&v, &n->authorized, c, "node MachineAuthorized is not a bool")) return -1;
        } else if (is_key(key, "Expired")) {
            if (bool_field(&v, &n->expired, c, "node Expired is not a bool")) return -1;
        } else if (is_key(key, "IsJailed")) {
            if (bool_field(&v, &n->jailed, c, "node IsJailed is not a bool")) return -1;
        } else if (is_key(key, "IsWireGuardOnly")) {
            if (bool_field(&v, &n->wireguard_only, c, "node IsWireGuardOnly is not a bool")) return -1;
        } else if (is_key(key, "KeyExpiry")) {
            if (v.type == TS_JSON_NUL) { n->key_expiry = 0; continue; }
            if (parse_time(&v, &n->key_expiry)) return bad(c, "malformed node KeyExpiry");
        } else if (ts_json_skip(r, &v)) {
            return bad(c, "invalid JSON");
        }
    }
    if (n->home_derp == 0 && legacy > 0) n->home_derp = legacy;
    return 0;
}

static ts_node *find(ts_node *v, size_t n, int64_t id)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (v[i].id == id) return &v[i];
    return NULL;
}

static int upsert(ts_node *v, size_t *n, const ts_node *node, ctx *c)
{
    ts_node *p = find(v, *n, node->id);
    if (p) {
        *p = *node;
        return 0;
    }
    if (*n >= TS_MAX_PEERS) return bad(c, "more than " STR(TS_MAX_PEERS) " peers (TS_MAX_PEERS)");
    v[(*n)++] = *node;
    return 0;
}

static void remove_id(ts_node *v, size_t *n, int64_t id)
{
    ts_node *p = find(v, *n, id);
    size_t i;
    if (!p) return;
    i = (size_t)(p - v);
    if (i + 1 < *n) memmove(&v[i], &v[i + 1], (*n - i - 1) * sizeof *v);
    (*n)--;
}

/* An array of nodes, upserted into v[0..*n) when apply is set (else only
 * checked). Counts the elements in *count. null is an absent field. */
static int parse_node_list(ts_json *r, ts_node *v, size_t *n, int apply, size_t *count, ctx *c)
{
    ts_json_tok t;
    ts_node tmp;
    *count = 0;
    if (value(r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_ARR_START) return bad(c, "peer list is not an array");
    for (;;) {
        ts_json_next(r, &t);
        if (t.type == TS_JSON_ARR_END) return 0;
        if (parse_node(r, &t, &tmp, c)) return -1;
        (*count)++;
        if (apply && upsert(v, n, &tmp, c)) return -1;
    }
}

static int parse_removed(ts_json *r, ts_node *v, size_t *n, int apply, ctx *c)
{
    ts_json_tok t;
    int64_t id;
    if (value(r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_ARR_START) return bad(c, "PeersRemoved is not an array");
    for (;;) {
        ts_json_next(r, &t);
        if (t.type == TS_JSON_ARR_END) return 0;
        if (t.type == TS_JSON_NUL) continue;
        if (t.type != TS_JSON_NUMBER || ts_json_int64(&id, &t) != 0)
            return bad(c, "PeersRemoved entry is not an integer");
        if (apply) remove_id(v, n, id);
    }
}

/* A decimal node ID used as an object key: optional '-', digits, in int64 range. */
static int id_from_key(const ts_json_tok *k, int64_t *out)
{
    char buf[24];
    const char *p = buf;
    int neg = 0;
    uint64_t v = 0, lim;
    if (ts_json_string(buf, sizeof buf, k) < 0) return -1;
    if (*p == '-') { neg = 1; p++; }
    if (*p == 0) return -1;
    lim = neg ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        if (v > (lim - (uint64_t)(*p - '0')) / 10) return -1;
        v = v * 10 + (uint64_t)(*p - '0');
    }
    if (neg) *out = v == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)v;
    else *out = (int64_t)v;
    return 0;
}

static int parse_online(ts_json *r, ts_node *v, size_t n, int apply, ctx *c)
{
    ts_json_tok k, t;
    int64_t id;
    int b;
    if (value(r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_OBJ_START) return bad(c, "OnlineChange is not an object");
    for (;;) {
        ts_node *p;
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) return 0;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        if (id_from_key(&k, &id)) return bad(c, "OnlineChange key is not a node ID");
        if (value(r, &t, c)) return -1;
        if (t.type == TS_JSON_NUL) continue;
        b = tok_bool(&t);
        if (b < 0) return bad(c, "OnlineChange value is not a bool");
        if (apply && (p = find(v, n, id)) != NULL) p->online = b;
    }
}

static int parse_patches(ts_json *r, ts_node *v, size_t n, int apply, ctx *c)
{
    ts_json_tok t, k;
    char key[32];
    if (value(r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_ARR_START) return bad(c, "PeersChangedPatch is not an array");
    for (;;) {
        int64_t id = 0, expiry = 0;
        int derp = 0, online = 0, have_key = 0, have_disco = 0, have_online = 0, have_expiry = 0;
        uint8_t nk[32], dk[32];
        ts_node *p;
        ts_json_next(r, &t);
        if (t.type == TS_JSON_ARR_END) return 0;
        if (t.type != TS_JSON_OBJ_START) return bad(c, "PeersChangedPatch entry is not an object");
        for (;;) {
            ts_json_next(r, &k);
            if (k.type == TS_JSON_OBJ_END) break;
            if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
            key_name(key, sizeof key, &k);
            if (value(r, &t, c)) return -1;
            if (t.type == TS_JSON_NUL) {
                /* null is absent; for a pointer field that also undoes an earlier one */
                if (is_key(key, "Key")) have_key = 0;
                else if (is_key(key, "DiscoKey")) have_disco = 0;
                else if (is_key(key, "Online")) have_online = 0;
                else if (is_key(key, "KeyExpiry")) have_expiry = 0;
                else if (is_key(key, "DERPRegion")) derp = 0;
                continue;
            }
            if (is_key(key, "NodeID")) {
                if (t.type != TS_JSON_NUMBER || ts_json_int64(&id, &t) != 0)
                    return bad(c, "patch NodeID is not an integer");
            } else if (is_key(key, "DERPRegion")) {
                if (tok_int(&t, &derp)) return bad(c, "patch DERPRegion is not an int");
            } else if (is_key(key, "Key")) {
                if (parse_key(nk, &t, "nodekey:")) return bad(c, "malformed patch Key");
                have_key = 1;
            } else if (is_key(key, "DiscoKey")) {
                if (parse_key(dk, &t, "discokey:")) return bad(c, "malformed patch DiscoKey");
                have_disco = 1;
            } else if (is_key(key, "Online")) {
                if ((online = tok_bool(&t)) < 0) return bad(c, "patch Online is not a bool");
                have_online = 1;
            } else if (is_key(key, "KeyExpiry")) {
                if (parse_time(&t, &expiry)) return bad(c, "malformed patch KeyExpiry");
                have_expiry = 1;
            } else if (ts_json_skip(r, &t)) {
                return bad(c, "invalid JSON");
            }
        }
        if (!apply || (p = find(v, n, id)) == NULL) continue;
        if (derp != 0) p->home_derp = derp;
        if (have_key) memcpy(p->node_key, nk, 32);
        if (have_disco) memcpy(p->disco_key, dk, 32);
        if (have_online) p->online = online;
        if (have_expiry) p->key_expiry = expiry;
    }
}

/* PingRequest into *p; *got is set when it is usable (non-empty URL, both
 * strings within their limits). */
static int parse_ping(ts_json *r, ts_ping_req *p, int *got, ctx *c)
{
    ts_json_tok t, k;
    char key[32];
    int drop = 0;
    memset(p, 0, sizeof *p);
    *got = 0;
    if (value(r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_OBJ_START) return bad(c, "PingRequest is not an object");
    for (;;) {
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) break;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (value(r, &t, c)) return -1;
        if (is_key(key, "URL") && t.type != TS_JSON_NUL) {
            if (t.type != TS_JSON_STRING) return bad(c, "PingRequest URL is not a string");
            drop &= ~1;
            if (ts_json_string(p->url, sizeof p->url, &t) < 0) drop |= 1;
        } else if (is_key(key, "Types") && t.type != TS_JSON_NUL) {
            if (t.type != TS_JSON_STRING) return bad(c, "PingRequest Types is not a string");
            drop &= ~2;
            if (ts_json_string(p->types, sizeof p->types, &t) < 0) drop |= 2;
        } else if (is_key(key, "URLIsNoise")) {
            if (bool_field(&t, &p->url_is_noise, c, "PingRequest URLIsNoise is not a bool")) return -1;
        } else if (ts_json_skip(r, &t)) {
            return bad(c, "invalid JSON");
        }
    }
    if (drop || p->url[0] == 0) {
        memset(p, 0, sizeof *p);
        return 0;
    }
    p->pending = 1;
    *got = 1;
    return 0;
}

static int parse_sleep(const ts_json_tok *t, uint32_t *ms)
{
    char buf[128];
    double d;
    char *end;
    if (t->type != TS_JSON_NUMBER || t->rawlen >= sizeof buf) return -1;
    memcpy(buf, t->raw, t->rawlen);
    buf[t->rawlen] = 0;
    d = strtod(buf, &end);
    if (*end != 0) return -1;
    /* Clamp while still a double: NaN and non-positive give 0, inf the cap. */
    if (!(d > 0)) *ms = 0;
    else if (d >= TS_MAP_SLEEP_MAX_MS / 1000.0) *ms = TS_MAP_SLEEP_MAX_MS;
    else *ms = (uint32_t)(d * 1000.0);
    return 0;
}

static int parse_debug(ts_json *r, int *have_exit, int *exit_code, uint32_t *sleep_ms, ctx *c)
{
    ts_json_tok t, k;
    char key[32];
    if (value(r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_OBJ_START) return bad(c, "Debug is not an object");
    for (;;) {
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) return 0;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (value(r, &t, c)) return -1;
        if (is_key(key, "Exit")) {
            if (t.type == TS_JSON_NUL) { *have_exit = 0; *exit_code = 0; continue; }
            if (tok_int(&t, exit_code)) return bad(c, "Debug Exit is not an int");
            *have_exit = 1;
        } else if (is_key(key, "SleepSeconds")) {
            if (t.type == TS_JSON_NUL) { *sleep_ms = 0; continue; }
            if (parse_sleep(&t, sleep_ms)) return bad(c, "Debug SleepSeconds is not a number");
        } else if (ts_json_skip(r, &t)) {
            return bad(c, "invalid JSON");
        }
    }
}

/* TKAInfo: *present set if not null, *disabled from Disabled. */
static int parse_tka(ts_json *r, int *present, int *disabled, ctx *c)
{
    ts_json_tok t, k;
    char key[32];
    *present = 0;
    *disabled = 0;
    if (value(r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_OBJ_START) return bad(c, "TKAInfo is not an object");
    *present = 1;
    for (;;) {
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) return 0;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (value(r, &t, c)) return -1;
        if (is_key(key, "Disabled")) {
            if (bool_field(&t, disabled, c, "TKAInfo Disabled is not a bool")) return -1;
        } else if (ts_json_skip(r, &t)) {
            return bad(c, "invalid JSON");
        }
    }
}

/* ---- apply ---------------------------------------------------------------- */

enum { F_KEEPALIVE, F_NODE, F_PEERS, F_REMOVED, F_CHANGED, F_ONLINE, F_PATCH,
       F_DEBUG, F_TKA, F_PING, F_COUNT };

static const char *const field_names[F_COUNT] = {
    "KeepAlive", "Node", "Peers", "PeersRemoved", "PeersChanged", "OnlineChange",
    "PeersChangedPatch", "Debug", "TKAInfo", "PingRequest"
};

/* A reader positioned just after a known top-level key, so its value can be
 * read later in the order the semantics need. */
typedef struct {
    int have;
    ts_json r;
} slot;

static void set_error(ts_netmap *m, const char *msg)
{
    size_t n = strlen(msg);
    if (n >= sizeof m->last_error) n = sizeof m->last_error - 1;
    memcpy(m->last_error, msg, n);
    m->last_error[n] = 0;
}

static int apply_inner(ts_netmap *m, const char *json, size_t len, ctx *c)
{
    ts_json j;
    ts_json_tok t;
    slot f[F_COUNT];
    char key[32];
    int i, keepalive = 0, tka_present = 0, tka_disabled = 0;
    int have_exit = 0, exit_code = 0, got_ping = 0;
    uint32_t sleep_ms = 0;
    ts_node self;
    int have_node = 0;
    ts_ping_req ping;
    size_t sn = 0, count = 0;
    int full;

    /* Pass 1: syntax of the whole document, and where each known field is. */
    memset(f, 0, sizeof f);
    ts_json_init(&j, json, len);
    ts_json_next(&j, &t);
    if (t.type != TS_JSON_OBJ_START) return bad(c, "map message is not a JSON object");
    for (;;) {
        ts_json_next(&j, &t);
        if (t.type == TS_JSON_OBJ_END) break;
        if (t.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &t);
        for (i = 0; i < F_COUNT; i++)
            if (is_key(key, field_names[i])) {
                f[i].have = 1;      /* last one wins */
                f[i].r = j;
            }
        if (ts_json_skip(&j, &t)) return bad(c, "invalid JSON");
    }
    if (ts_json_next(&j, &t) != TS_JSON_END) return bad(c, "invalid JSON");

    /* Pass 2: values, in semantic order, all staged. */
    if (f[F_KEEPALIVE].have) {
        ts_json r = f[F_KEEPALIVE].r;
        if (value(&r, &t, c)) return -1;
        if (t.type != TS_JSON_NUL && (keepalive = tok_bool(&t)) < 0)
            return bad(c, "KeepAlive is not a bool");
    }
    if (f[F_PING].have) {
        ts_json r = f[F_PING].r;
        if (parse_ping(&r, &ping, &got_ping, c)) return -1;
    }
    if (f[F_NODE].have) {
        ts_json r = f[F_NODE].r;
        if (value(&r, &t, c)) return -1;
        if (t.type != TS_JSON_NUL) {
            if (parse_node(&r, &t, &self, c)) return -1;
            have_node = 1;
        }
    }
    if (f[F_DEBUG].have) {
        ts_json r = f[F_DEBUG].r;
        if (parse_debug(&r, &have_exit, &exit_code, &sleep_ms, c)) return -1;
    }
    if (f[F_TKA].have) {
        ts_json r = f[F_TKA].r;
        if (parse_tka(&r, &tka_present, &tka_disabled, c)) return -1;
    }

    /* Peers: a non-empty list replaces the set and precludes the deltas. */
    if (f[F_PEERS].have) {
        ts_json r = f[F_PEERS].r;
        if (parse_node_list(&r, m->stage, &sn, 1, &count, c)) return -1;
    }
    full = count > 0;
    if (!full) {
        sn = m->npeers;
        if (sn) memcpy(m->stage, m->peers, sn * sizeof *m->stage);
    }
    if (f[F_REMOVED].have) {
        ts_json r = f[F_REMOVED].r;
        if (parse_removed(&r, m->stage, &sn, !full, c)) return -1;
    }
    if (f[F_CHANGED].have) {
        ts_json r = f[F_CHANGED].r;
        if (parse_node_list(&r, m->stage, &sn, !full, &count, c)) return -1;
    }
    if (f[F_ONLINE].have) {
        ts_json r = f[F_ONLINE].r;
        if (parse_online(&r, m->stage, sn, !full, c)) return -1;
    }
    if (f[F_PATCH].have) {
        ts_json r = f[F_PATCH].r;
        if (parse_patches(&r, m->stage, sn, !full, c)) return -1;
    }

    if (!keepalive && !m->have_self && !have_node)
        return bad(c, "initial MapResponse lacked Node");

    /* Commit. */
    if (got_ping) m->ping = ping;
    if (keepalive) {
        m->have_exit = 0;
        m->exit_code = 0;
        m->sleep_ms = 0;
        return 0;
    }
    if (have_node) {
        m->self = self;
        m->have_self = 1;
    }
    {
        ts_node *tmp = m->peers;
        m->peers = m->stage;
        m->stage = tmp;
        m->npeers = sn;
    }
    if (tka_present) m->tka_enabled = !tka_disabled;
    m->have_exit = have_exit;
    m->exit_code = exit_code;
    m->sleep_ms = sleep_ms;
    return 0;
}

int ts_netmap_apply(ts_netmap *m, const char *json, size_t len)
{
    ctx c;
    c.err = NULL;
    if (!m->peers || !m->stage) {
        set_error(m, "netmap not initialised");
        return -1;
    }
    if (!json) len = 0;
    if (apply_inner(m, json ? json : "", len, &c) != 0) {
        set_error(m, c.err ? c.err : "invalid map message");
        return -1;
    }
    m->last_error[0] = 0;
    return 0;
}

int ts_netmap_init(ts_netmap *m)
{
    memset(m, 0, sizeof *m);
    m->peers = (ts_node *)calloc(TS_MAX_PEERS, sizeof(ts_node));
    m->stage = (ts_node *)calloc(TS_MAX_PEERS, sizeof(ts_node));
    if (!m->peers || !m->stage) {
        ts_netmap_free(m);
        return -1;
    }
    return 0;
}

void ts_netmap_free(ts_netmap *m)
{
    free(m->peers);
    free(m->stage);
    memset(m, 0, sizeof *m);
}

void ts_netmap_reset(ts_netmap *m)
{
    ts_node *p = m->peers, *s = m->stage;
    memset(m, 0, sizeof *m);
    m->peers = p;
    m->stage = s;
}

const ts_node *ts_netmap_peer(const ts_netmap *m, int64_t id)
{
    return m->peers ? find(m->peers, m->npeers, id) : NULL;
}

/* ---- stream framing ------------------------------------------------------- */

#define STREAM_KEEP_MAX 65536   /* free the buffer after a message larger than this */

void ts_map_stream_init(ts_map_stream *s, void (*msg)(void *, const char *, size_t), void *user)
{
    memset(s, 0, sizeof *s);
    s->msg = msg;
    s->user = user;
}

void ts_map_stream_free(ts_map_stream *s)
{
    free(s->buf);
    s->buf = NULL;
    s->cap = 0;
}

int ts_map_stream_feed(ts_map_stream *s, const uint8_t *in, size_t n)
{
    if (s->failed) return -1;
    while (n > 0) {
        size_t take;
        if (!s->in_body) {
            uint32_t want;
            take = 4 - s->hdr_have;
            if (take > n) take = n;
            memcpy(s->hdr + s->hdr_have, in, take);
            s->hdr_have += take;
            in += take;
            n -= take;
            if (s->hdr_have < 4) break;
            s->hdr_have = 0;
            want = ts_get_le32(s->hdr);
            if (want > TS_MAP_MSG_MAX) {
                s->failed = TS_MAP_STREAM_TOO_BIG;
                return -1;
            }
            if (want == 0) {
                s->msg(s->user, "", 0);
                continue;
            }
            s->want = want;
            s->have = 0;
            s->in_body = 1;
            continue;
        }
        take = s->want - s->have;
        if (take > n) take = n;
        if (s->have + take > s->cap) {
            size_t nc = s->cap * 2;
            uint8_t *nb;
            if (nc < s->have + take) nc = s->have + take;
            if (nc < 4096) nc = 4096;
            if (nc > s->want) nc = s->want;
            nb = (uint8_t *)realloc(s->buf, nc);
            if (!nb) {
                s->failed = TS_MAP_STREAM_NOMEM;
                return -1;
            }
            s->buf = nb;
            s->cap = nc;
        }
        memcpy(s->buf + s->have, in, take);
        s->have += take;
        in += take;
        n -= take;
        if (s->have == s->want) {
            s->in_body = 0;
            s->msg(s->user, (const char *)s->buf, s->want);
            if (s->cap > STREAM_KEEP_MAX) ts_map_stream_free(s);
        }
    }
    return 0;
}
