#include "netmap.h"

#include <float.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../core/bytes.h"
#include "../net/resolve.h"
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
 * gives 0, the Unix epoch itself -1. */
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
    /* 0 means no expiry, so the zero time maps to it, and a real expiry at
     * the epoch becomes -1 (one second earlier; both are long past). */
    if (v == GO_ZERO_TIME) v = 0;
    else if (v == 0) v = -1;
    *out = v;
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
    int limit;         /* err is a limit control will hit again (TS_MAX_PEERS, filters) */
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
    if (*n >= TS_MAX_PEERS) {
        if (!c->err) c->limit = 1;
        return bad(c, "more than " STR(TS_MAX_PEERS) " peers (TS_MAX_PEERS)");
    }
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

/* A reader positioned just after a known top-level key, so its value can be
 * read later in the order the semantics need. */
typedef struct {
    int have;
    ts_json r;
} slot;

/* ---- DERP map ------------------------------------------------------------- */

#define MAX_REGION_ID 9007199254740991LL   /* 1<<53 - 1, upstream's valid range */

static int over(ctx *c, const char *msg)
{
    if (!c->err) c->limit = 1;
    return bad(c, msg);
}

/* A region ID used as an object key (Regions, RegionScore): 1..2^53-1. */
static int region_id(const ts_json_tok *k, int64_t *id)
{
    if (id_from_key(k, id) || *id < 1 || *id > MAX_REGION_ID) return -1;
    return 0;
}

/* A STRING into a fixed field whose unused bytes are all zero ("" if it
 * does not fit), so the containing struct compares with memcmp. */
static void str_field(char *dst, size_t cap, const ts_json_tok *t)
{
    int n = ts_json_string(dst, cap, t);
    if (n < 0) n = 0;
    memset(dst + n, 0, cap - (size_t)n);
}

/* A dotted quad, nothing else (no leading zeros, as Go's netip). */
static int parse_ipv4(const char *s, uint32_t *out)
{
    const char *p = s;
    uint32_t v = 0;
    long o;
    int i;
    for (i = 0; i < 4; i++) {
        if (i && *p++ != '.') return -1;
        o = dec(&p, 3);
        if (o < 0 || o > 255) return -1;
        v = (v << 8) | (uint32_t)o;
    }
    if (*p != 0) return -1;
    *out = v;
    return 0;
}

static int parse_double(const ts_json_tok *t, double *out)
{
    char buf[128];
    char *end;
    double d;
    if (t->type != TS_JSON_NUMBER || t->rawlen >= sizeof buf) return -1;
    memcpy(buf, t->raw, t->rawlen);
    buf[t->rawlen] = 0;
    d = strtod(buf, &end);
    if (*end != 0 || d > DBL_MAX || d < -DBL_MAX) return -1;   /* Go refuses out of range */
    *out = d;
    return 0;
}

/* One DERPNode (first token already read) into *out, zeroed first. *usable
 * says whether it passes the rules in netmap.h. */
static int parse_derp_node(ts_json *r, const ts_json_tok *first, ts_derp_node *out, int *usable, ctx *c)
{
    ts_json_tok k, v;
    char key[32], host[254], cert[254], ip[32];
    const char *tls;
    int hn = 0, cn = 0, in = 0, stun = 0, insecure = 0;
    int64_t port = 0;
    uint32_t a = 0;

    memset(out, 0, sizeof *out);
    host[0] = cert[0] = ip[0] = 0;
    *usable = 0;
    if (first->type != TS_JSON_OBJ_START) return bad(c, "DERPMap node is not an object");
    for (;;) {
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) break;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (value(r, &v, c)) return -1;
        if (is_key(key, "Name")) {
            if (v.type != TS_JSON_NUL && v.type != TS_JSON_STRING) return bad(c, "DERPMap node Name is not a string");
            if (v.type == TS_JSON_NUL) memset(out->name, 0, sizeof out->name);
            else str_field(out->name, sizeof out->name, &v);
        } else if (is_key(key, "HostName")) {
            if (v.type == TS_JSON_NUL) { hn = 0; host[0] = 0; continue; }
            if (v.type != TS_JSON_STRING) return bad(c, "DERPMap node HostName is not a string");
            hn = ts_json_string(host, sizeof host, &v);   /* -1: does not fit */
        } else if (is_key(key, "CertName")) {
            if (v.type == TS_JSON_NUL) { cn = 0; cert[0] = 0; continue; }
            if (v.type != TS_JSON_STRING) return bad(c, "DERPMap node CertName is not a string");
            cn = ts_json_string(cert, sizeof cert, &v);   /* -1: does not fit */
        } else if (is_key(key, "IPv4")) {
            if (v.type == TS_JSON_NUL) { in = 0; ip[0] = 0; continue; }
            if (v.type != TS_JSON_STRING) return bad(c, "DERPMap node IPv4 is not a string");
            in = ts_json_string(ip, sizeof ip, &v);   /* -1: does not fit */
        } else if (is_key(key, "STUNOnly")) {
            if (bool_field(&v, &stun, c, "DERPMap node STUNOnly is not a bool")) return -1;
        } else if (is_key(key, "InsecureForTests")) {
            if (bool_field(&v, &insecure, c, "DERPMap node InsecureForTests is not a bool")) return -1;
        } else if (is_key(key, "DERPPort")) {
            if (v.type == TS_JSON_NUL) { port = 0; continue; }
            if (v.type != TS_JSON_NUMBER || ts_json_int64(&port, &v) != 0)
                return bad(c, "DERPMap node DERPPort is not an integer");
        } else if (ts_json_skip(r, &v)) {
            return bad(c, "invalid JSON");
        }
    }
    if (stun || insecure || port < 0 || port > 65535) return 0;
    if (in <= 0 || parse_ipv4(ip, &a) != 0) return 0;
    if (cn != 0) {
        if (cn < 0 || strncmp(cert, "sha256-raw:", 11) == 0) return 0;
        tls = cert;
    } else {
        if (hn <= 0) return 0;
        tls = host;
    }
    if (!ts_host_name_ok(tls)) return 0;
    memcpy(out->host, tls, strlen(tls));   /* <= 253 bytes; the rest stays zero */
    out->ipv4 = a;
    out->port = (uint16_t)(port ? port : 443);
    *usable = 1;
    return 0;
}

/* One DERPRegion (first token already read) into *g, zeroed first. */
static int parse_region(ts_json *r, const ts_json_tok *first, ts_derp_region *g, ctx *c)
{
    ts_json_tok k, v;
    char key[32];
    ts_derp_node node;
    int usable;

    memset(g, 0, sizeof *g);
    if (first->type != TS_JSON_OBJ_START) return bad(c, "DERPMap region is not an object");
    for (;;) {
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) return 0;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (value(r, &v, c)) return -1;
        if (is_key(key, "RegionCode")) {
            if (v.type != TS_JSON_NUL && v.type != TS_JSON_STRING)
                return bad(c, "DERPMap RegionCode is not a string");
            if (v.type == TS_JSON_NUL) memset(g->code, 0, sizeof g->code);
            else str_field(g->code, sizeof g->code, &v);
        } else if (is_key(key, "Avoid")) {
            if (bool_field(&v, &g->avoid, c, "DERPMap region Avoid is not a bool")) return -1;
        } else if (is_key(key, "NoMeasureNoHome")) {
            if (bool_field(&v, &g->no_home, c, "DERPMap region NoMeasureNoHome is not a bool")) return -1;
        } else if (is_key(key, "Nodes")) {
            memset(g->nodes, 0, sizeof g->nodes);
            g->nnodes = 0;
            if (v.type == TS_JSON_NUL) continue;
            if (v.type != TS_JSON_ARR_START) return bad(c, "DERPMap region Nodes is not an array");
            for (;;) {
                ts_json_next(r, &v);
                if (v.type == TS_JSON_ARR_END) break;
                if (v.type == TS_JSON_NUL) continue;
                if (parse_derp_node(r, &v, &node, &usable, c)) return -1;
                if (usable && g->nnodes < TS_DERP_MAX_NODES) memcpy(&g->nodes[g->nnodes++], &node, sizeof node);
            }
        } else if (ts_json_skip(r, &v)) {
            return bad(c, "invalid JSON");
        }
    }
}

/* Sorted (by id) insert into v[0..*n), at most TS_DERP_MAX_REGIONS: the same
 * ID is replaced, and when full the highest ID is dropped. */
static void region_put(ts_derp_region *v, size_t *n, const ts_derp_region *g)
{
    size_t i = 0;
    while (i < *n && v[i].id < g->id) i++;
    if (i < *n && v[i].id == g->id) {
        memcpy(&v[i], g, sizeof *g);
        return;
    }
    if (i == TS_DERP_MAX_REGIONS) return;
    if (*n == TS_DERP_MAX_REGIONS) (*n)--;
    if (i < *n) memmove(&v[i + 1], &v[i], (*n - i) * sizeof *v);
    memcpy(&v[i], g, sizeof *g);
    (*n)++;
}

static void region_del(ts_derp_region *v, size_t *n, int id)
{
    size_t i;
    for (i = 0; i < *n; i++)
        if (v[i].id == id) {
            if (i + 1 < *n) memmove(&v[i], &v[i + 1], (*n - i - 1) * sizeof *v);
            (*n)--;
            return;
        }
}

/* The same for the score table (TS_DERP_SCORES_MAX). */
static void score_put(ts_derp_score *v, size_t *n, int id, double score)
{
    ts_derp_score e;
    size_t i = 0;
    memset(&e, 0, sizeof e);
    e.id = id;
    e.score = score;
    while (i < *n && v[i].id < id) i++;
    if (i < *n && v[i].id == id) {
        memcpy(&v[i], &e, sizeof e);
        return;
    }
    if (i == TS_DERP_SCORES_MAX) return;
    if (*n == TS_DERP_SCORES_MAX) (*n)--;
    if (i < *n) memmove(&v[i + 1], &v[i], (*n - i) * sizeof *v);
    memcpy(&v[i], &e, sizeof e);
    (*n)++;
}

static void score_del(ts_derp_score *v, size_t *n, int id)
{
    size_t i;
    for (i = 0; i < *n; i++)
        if (v[i].id == id) {
            if (i + 1 < *n) memmove(&v[i], &v[i + 1], (*n - i - 1) * sizeof *v);
            (*n)--;
            return;
        }
}

/* Upstream multiplies by a score only when it is > 0. */
static double score_of(const ts_derp_score *v, size_t n, int id)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (v[i].id == id) return v[i].score > 0 ? v[i].score : 1.0;
    return 1.0;
}

typedef struct {
    int present;        /* a non-null DERPMap */
    int changed;        /* the staged regions differ from m->regions */
    size_t nreg;        /* m->derp_stage[0..nreg) */
    size_t nsc;         /* m->score_stage[0..nsc) */
} dstage;

/* Advance r past the object's keys, leaving *at just after the last
 * occurrence of key want (*found set). The object start is already read. */
static int find_last(ts_json *r, const char *want, ts_json *at, int *found, ctx *c)
{
    ts_json_tok k;
    char key[32];
    *found = 0;
    for (;;) {
        ts_json_next(r, &k);
        if (k.type == TS_JSON_OBJ_END) return 0;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (is_key(key, want)) {
            *found = 1;
            *at = *r;
        }
        if (ts_json_skip(r, &k)) return bad(c, "invalid JSON");
    }
}

/* Stage the DERPMap at r into m->derp_stage and m->score_stage. */
static int stage_derp(ts_netmap *m, ts_json r, dstage *d, ctx *c)
{
    ts_json rr, hr, sr, scan;
    ts_json_tok t, k, v;
    ts_derp_region tmp;
    char key[32];
    int have_regions = 0, have_home = 0, have_scores = 0, have_rs = 0;
    int64_t id;
    double x;
    size_t i;

    memset(d, 0, sizeof *d);
    if (value(&r, &t, c)) return -1;
    if (t.type == TS_JSON_NUL) return 0;
    if (t.type != TS_JSON_OBJ_START) return bad(c, "DERPMap is not an object");
    d->present = 1;
    rr = hr = sr = r;
    for (;;) {
        ts_json_next(&r, &k);
        if (k.type == TS_JSON_OBJ_END) break;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        key_name(key, sizeof key, &k);
        if (is_key(key, "Regions")) { have_regions = 1; rr = r; }
        else if (is_key(key, "HomeParams")) { have_home = 1; hr = r; }
        if (ts_json_skip(&r, &k)) return bad(c, "invalid JSON");
    }

    if (have_regions) {
        if (value(&rr, &t, c)) return -1;
        if (t.type == TS_JSON_NUL) have_regions = 0;
        else if (t.type != TS_JSON_OBJ_START) return bad(c, "DERPMap Regions is not an object");
    }
    if (have_regions) {
        for (;;) {
            ts_json_next(&rr, &k);
            if (k.type == TS_JSON_OBJ_END) break;
            if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
            if (region_id(&k, &id)) return bad(c, "DERPMap region ID is not 1..2^53-1");
            if (value(&rr, &v, c)) return -1;
            if (v.type == TS_JSON_NUL) {
                if (id <= INT_MAX) region_del(m->derp_stage, &d->nreg, (int)id);
                continue;
            }
            if (parse_region(&rr, &v, &tmp, c)) return -1;
            if (id > INT_MAX) continue;      /* valid, but no peer can name it */
            tmp.id = (int)id;
            region_put(m->derp_stage, &d->nreg, &tmp);
        }
    } else if (!m->derp_fresh && m->nregions) {
        d->nreg = m->nregions;
        memcpy(m->derp_stage, m->regions, d->nreg * sizeof *m->regions);
    }

    if (have_home) {
        if (value(&hr, &t, c)) return -1;
        if (t.type != TS_JSON_NUL) {
            if (t.type != TS_JSON_OBJ_START) return bad(c, "DERPMap HomeParams is not an object");
            scan = hr;
            if (find_last(&scan, "RegionScore", &sr, &have_rs, c)) return -1;
            if (have_rs) {
                if (value(&sr, &t, c)) return -1;
                if (t.type != TS_JSON_NUL) {
                    if (t.type != TS_JSON_OBJ_START) return bad(c, "DERPMap RegionScore is not an object");
                    have_scores = 1;
                }
            }
        }
    }
    if (have_scores) {
        for (;;) {
            ts_json_next(&sr, &k);
            if (k.type == TS_JSON_OBJ_END) break;
            if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
            if (region_id(&k, &id)) return bad(c, "DERPMap RegionScore key is not 1..2^53-1");
            if (value(&sr, &v, c)) return -1;
            if (v.type == TS_JSON_NUL) {
                if (id <= INT_MAX) score_del(m->score_stage, &d->nsc, (int)id);
                continue;
            }
            if (parse_double(&v, &x)) return bad(c, "DERPMap RegionScore value is not a number");
            if (id <= INT_MAX) score_put(m->score_stage, &d->nsc, (int)id, x);
        }
    } else if (!m->derp_fresh && m->nscores) {
        d->nsc = m->nscores;
        memcpy(m->score_stage, m->scores, d->nsc * sizeof *m->scores);
    }

    for (i = 0; i < d->nreg; i++)
        m->derp_stage[i].score = score_of(m->score_stage, d->nsc, m->derp_stage[i].id);
    d->changed = d->nreg != m->nregions
        || (d->nreg && memcmp(m->derp_stage, m->regions, d->nreg * sizeof *m->regions) != 0);
    return 0;
}

/* ---- packet filters ------------------------------------------------------- */

typedef struct {
    char name[TS_FILTER_NAME_MAX + 1];
    const char *text;   /* into the message or the stored filters; NULL: a delete op */
    size_t len;
} fent;

typedef struct {
    int present;        /* a non-null PacketFilter or PacketFilters */
    int changed;        /* differs from the stored filters (or have_filter was 0) */
    size_t n;
    fent e[TS_FILTER_NAMES_MAX];        /* sorted by name */
    char *names[TS_FILTER_NAMES_MAX];   /* copies made before commit */
    char *texts[TS_FILTER_NAMES_MAX];
} fstage;

#define FILTER_COUNT_ERR "more than " STR(TS_FILTER_NAMES_MAX) " packet filters (TS_FILTER_NAMES_MAX)"

static int fset_find(const fstage *fs, const char *name)
{
    size_t i;
    for (i = 0; i < fs->n; i++)
        if (strcmp(fs->e[i].name, name) == 0) return (int)i;
    return -1;
}

static int fset_put(fstage *fs, const char *name, const char *text, size_t len, ctx *c)
{
    size_t i = 0;
    while (i < fs->n && strcmp(fs->e[i].name, name) < 0) i++;
    if (i == fs->n || strcmp(fs->e[i].name, name) != 0) {
        if (fs->n == TS_FILTER_NAMES_MAX) return over(c, FILTER_COUNT_ERR);
        if (i < fs->n) memmove(&fs->e[i + 1], &fs->e[i], (fs->n - i) * sizeof fs->e[0]);
        fs->n++;
        memset(&fs->e[i], 0, sizeof fs->e[i]);
        memcpy(fs->e[i].name, name, strlen(name));   /* <= TS_FILTER_NAME_MAX */
    }
    fs->e[i].text = text;
    fs->e[i].len = len;
    return 0;
}

static void fset_del(fstage *fs, const char *name)
{
    int i = fset_find(fs, name);
    if (i < 0) return;
    if ((size_t)i + 1 < fs->n) memmove(&fs->e[i], &fs->e[i + 1], (fs->n - (size_t)i - 1) * sizeof fs->e[0]);
    fs->n--;
}

/* The array value starting at v: its exact text. */
static int filter_text(ts_json *r, const ts_json_tok *v, const char **text, size_t *len, ctx *c,
                       const char *what)
{
    if (v->type != TS_JSON_ARR_START) return bad(c, what);
    if (ts_json_skip(r, v)) return bad(c, "invalid JSON");
    *text = v->raw;
    *len = (size_t)(r->buf + r->pos - v->raw);
    return 0;
}

/* The PacketFilters object (start already read at b) onto fs. Each name's
 * last occurrence counts; a null "*" clears first; deletes go before sets,
 * so the limits apply to the result. */
static int stage_named(fstage *fs, ts_json b, ctx *c)
{
    fent ops[2 * TS_FILTER_NAMES_MAX];
    size_t nops = 0, nsets = 0, i;
    ts_json r = b;
    ts_json_tok k, v;
    char name[TS_FILTER_NAME_MAX + 1];
    int star_null = 0;

    for (;;) {
        ts_json_next(&r, &k);
        if (k.type == TS_JSON_OBJ_END) break;
        if (k.type != TS_JSON_KEY) return bad(c, "invalid JSON");
        if (ts_json_string(name, sizeof name, &k) < 0)
            return over(c, "packet filter name longer than " STR(TS_FILTER_NAME_MAX) " bytes");
        if (value(&r, &v, c)) return -1;
        if (v.type == TS_JSON_NUL) {
            if (strcmp(name, "*") == 0) star_null = 1;
            continue;
        }
        if (v.type != TS_JSON_ARR_START) return bad(c, "PacketFilters value is not an array");
        if (strcmp(name, "*") == 0) star_null = 0;
        if (ts_json_skip(&r, &v)) return bad(c, "invalid JSON");
    }
    if (star_null) fs->n = 0;

    r = b;
    for (;;) {
        int j = -1, in_set;
        ts_json_next(&r, &k);
        if (k.type == TS_JSON_OBJ_END) break;
        ts_json_string(name, sizeof name, &k);   /* checked above */
        if (value(&r, &v, c)) return -1;
        if (strcmp(name, "*") == 0) {
            if (ts_json_skip(&r, &v)) return bad(c, "invalid JSON");
            continue;
        }
        for (i = 0; i < nops; i++)
            if (strcmp(ops[i].name, name) == 0) { j = (int)i; break; }
        in_set = fset_find(fs, name) >= 0;
        if (v.type == TS_JSON_NUL) {
            if (j >= 0) {
                if (ops[j].text) nsets--;
                ops[j].text = NULL;
                if (!in_set) ops[j] = ops[--nops];   /* nothing to delete */
            } else if (in_set) {
                memset(&ops[nops], 0, sizeof ops[nops]);
                memcpy(ops[nops].name, name, strlen(name));
                nops++;
            }
        } else {
            const char *tx = NULL;
            size_t ln = 0;
            if (filter_text(&r, &v, &tx, &ln, c, "PacketFilters value is not an array")) return -1;
            /* Each live set ends up in the result, so more than the limit is final. */
            if ((j < 0 || !ops[j].text) && ++nsets > TS_FILTER_NAMES_MAX) return over(c, FILTER_COUNT_ERR);
            if (j < 0) {
                j = (int)nops++;
                memset(&ops[j], 0, sizeof ops[j]);
                memcpy(ops[j].name, name, strlen(name));
            }
            ops[j].text = tx;
            ops[j].len = ln;
        }
    }
    /* nops <= nsets + deletes of names in fs (<= TS_FILTER_NAMES_MAX each). */
    for (i = 0; i < nops; i++)
        if (!ops[i].text) fset_del(fs, ops[i].name);
    for (i = 0; i < nops; i++)
        if (ops[i].text && fset_put(fs, ops[i].name, ops[i].text, ops[i].len, c)) return -1;
    return 0;
}

static int stage_filters(const ts_netmap *m, const slot *pf_slot, const slot *pfs_slot, fstage *fs, ctx *c)
{
    ts_json a, b;
    ts_json_tok pf, pfs;
    int has_pf = 0, has_pfs = 0;
    size_t i, total = 0;

    memset(fs, 0, sizeof *fs);
    a = pf_slot->r;     /* (initialised for older compilers' warnings) */
    b = pfs_slot->r;
    pf.type = pfs.type = TS_JSON_NUL;
    if (pf_slot->have) {
        if (value(&a, &pf, c)) return -1;
        has_pf = pf.type != TS_JSON_NUL;
    }
    if (pfs_slot->have) {
        if (value(&b, &pfs, c)) return -1;
        has_pfs = pfs.type != TS_JSON_NUL;
    }
    if (!has_pf && !has_pfs) return 0;
    fs->present = 1;
    if (!m->filter_fresh) {
        for (i = 0; i < m->nfilters; i++) {
            memcpy(fs->e[i].name, m->filter_name[i], strlen(m->filter_name[i]));
            fs->e[i].text = m->filter_json[i];
            fs->e[i].len = m->filter_len[i];
        }
        fs->n = m->nfilters;
    }
    if (has_pf) {
        const char *tx = NULL;
        size_t ln = 0;
        if (filter_text(&a, &pf, &tx, &ln, c, "PacketFilter is not an array")) return -1;
        if (fset_put(fs, "base", tx, ln, c)) return -1;
    }
    if (has_pfs) {
        if (pfs.type != TS_JSON_OBJ_START) return bad(c, "PacketFilters is not an object");
        if (stage_named(fs, b, c)) return -1;
    }
    for (i = 0; i < fs->n; i++) total += fs->e[i].len;
    if (total > TS_FILTER_JSON_MAX)
        return over(c, "packet filters over " STR(TS_FILTER_JSON_MAX) " bytes (TS_FILTER_JSON_MAX)");

    fs->changed = !m->have_filter || fs->n != m->nfilters;
    for (i = 0; !fs->changed && i < fs->n; i++)
        fs->changed = strcmp(fs->e[i].name, m->filter_name[i]) != 0 || fs->e[i].len != m->filter_len[i]
            || memcmp(fs->e[i].text, m->filter_json[i], fs->e[i].len) != 0;
    return 0;
}

static void fstage_free(fstage *fs)
{
    size_t i;
    for (i = 0; i < TS_FILTER_NAMES_MAX; i++) {
        free(fs->names[i]);
        free(fs->texts[i]);
        fs->names[i] = fs->texts[i] = NULL;
    }
}

/* Copies of the staged filters, so commit cannot fail. 0 or -1 (none left). */
static int fstage_alloc(fstage *fs)
{
    size_t i, nl;
    for (i = 0; i < fs->n; i++) {
        nl = strlen(fs->e[i].name);
        fs->names[i] = (char *)malloc(nl + 1);
        fs->texts[i] = (char *)malloc(fs->e[i].len + 1);
        if (!fs->names[i] || !fs->texts[i]) {
            fstage_free(fs);
            return -1;
        }
        memcpy(fs->names[i], fs->e[i].name, nl + 1);
        memcpy(fs->texts[i], fs->e[i].text, fs->e[i].len);
        fs->texts[i][fs->e[i].len] = 0;
    }
    return 0;
}

static void filters_drop(ts_netmap *m)
{
    size_t i;
    for (i = 0; i < m->nfilters; i++) {
        free(m->filter_name[i]);
        free(m->filter_json[i]);
        m->filter_name[i] = m->filter_json[i] = NULL;
        m->filter_len[i] = 0;
    }
    m->nfilters = 0;
}

/* ---- apply ---------------------------------------------------------------- */

enum { F_KEEPALIVE, F_NODE, F_PEERS, F_REMOVED, F_CHANGED, F_ONLINE, F_PATCH,
       F_DEBUG, F_TKA, F_PING, F_DERPMAP, F_PFILTER, F_PFILTERS, F_COUNT };

static const char *const field_names[F_COUNT] = {
    "KeepAlive", "Node", "Peers", "PeersRemoved", "PeersChanged", "OnlineChange",
    "PeersChangedPatch", "Debug", "TKAInfo", "PingRequest", "DERPMap", "PacketFilter",
    "PacketFilters"
};

static void set_error(ts_netmap *m, const char *msg)
{
    size_t n = strlen(msg);
    if (n >= sizeof m->last_error) n = sizeof m->last_error - 1;
    memcpy(m->last_error, msg, n);
    m->last_error[n] = 0;
}

static int apply_inner(ts_netmap *m, const char *json, size_t len, fstage *fs, ctx *c)
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
    dstage d;

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

    /* DERP map and filters, staged (and checked) even for a KeepAlive. */
    memset(&d, 0, sizeof d);
    if (f[F_DERPMAP].have && stage_derp(m, f[F_DERPMAP].r, &d, c)) return -1;
    if (stage_filters(m, &f[F_PFILTER], &f[F_PFILTERS], fs, c)) return -1;

    if (!keepalive && !m->have_self && !have_node)
        return bad(c, "initial MapResponse lacked Node");
    /* The last step that can fail: after it, commit cannot. */
    if (!keepalive && fs->present && fs->changed && fstage_alloc(fs))
        return bad(c, "out of memory for the packet filters");

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
    if (d.present) {
        ts_derp_score *sc = m->scores;
        if (d.changed) {
            ts_derp_region *tmp = m->regions;
            m->regions = m->derp_stage;
            m->derp_stage = tmp;
            m->nregions = d.nreg;
            m->derp_gen++;
        }
        m->scores = m->score_stage;
        m->score_stage = sc;
        m->nscores = d.nsc;
        m->derp_fresh = 0;
    }
    if (fs->present) {
        if (fs->changed) {
            size_t i;
            filters_drop(m);
            for (i = 0; i < fs->n; i++) {
                m->filter_name[i] = fs->names[i];
                m->filter_json[i] = fs->texts[i];
                m->filter_len[i] = fs->e[i].len;
                fs->names[i] = fs->texts[i] = NULL;
            }
            m->nfilters = fs->n;
            m->have_filter = 1;
            m->filter_gen++;
        }
        m->filter_fresh = 0;
    }
    m->have_exit = have_exit;
    m->exit_code = exit_code;
    m->sleep_ms = sleep_ms;
    return 0;
}

int ts_netmap_apply(ts_netmap *m, const char *json, size_t len)
{
    ctx c;
    fstage fs;
    int rc;
    c.err = NULL;
    c.limit = 0;
    m->last_limit = 0;
    if (!m->peers || !m->stage || !m->regions || !m->derp_stage || !m->scores || !m->score_stage) {
        set_error(m, "netmap not initialised");
        return -1;
    }
    if (!json) len = 0;
    memset(&fs, 0, sizeof fs);
    rc = apply_inner(m, json ? json : "", len, &fs, &c);
    fstage_free(&fs);   /* copies left over (none after a commit) */
    if (rc != 0) {
        set_error(m, c.err ? c.err : "invalid map message");
        m->last_limit = c.limit;
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
    m->regions = (ts_derp_region *)calloc(TS_DERP_MAX_REGIONS, sizeof(ts_derp_region));
    m->derp_stage = (ts_derp_region *)calloc(TS_DERP_MAX_REGIONS, sizeof(ts_derp_region));
    m->scores = (ts_derp_score *)calloc(TS_DERP_SCORES_MAX, sizeof(ts_derp_score));
    m->score_stage = (ts_derp_score *)calloc(TS_DERP_SCORES_MAX, sizeof(ts_derp_score));
    if (!m->peers || !m->stage || !m->regions || !m->derp_stage || !m->scores || !m->score_stage) {
        ts_netmap_free(m);
        return -1;
    }
    m->derp_fresh = m->filter_fresh = 1;
    return 0;
}

void ts_netmap_free(ts_netmap *m)
{
    filters_drop(m);
    free(m->peers);
    free(m->stage);
    free(m->regions);
    free(m->derp_stage);
    free(m->scores);
    free(m->score_stage);
    memset(m, 0, sizeof *m);
}

void ts_netmap_reset(ts_netmap *m)
{
    ts_netmap keep = *m;
    size_t i;
    memset(m, 0, sizeof *m);
    m->peers = keep.peers;
    m->stage = keep.stage;
    /* The DERP map and filters stay readable; the next session's first
     * DERPMap / PacketFilter(s) starts from nothing (see netmap.h). */
    m->regions = keep.regions;
    m->derp_stage = keep.derp_stage;
    m->nregions = keep.nregions;
    m->derp_gen = keep.derp_gen;
    m->scores = keep.scores;
    m->score_stage = keep.score_stage;
    m->nscores = keep.nscores;
    for (i = 0; i < TS_FILTER_NAMES_MAX; i++) {
        m->filter_name[i] = keep.filter_name[i];
        m->filter_json[i] = keep.filter_json[i];
        m->filter_len[i] = keep.filter_len[i];
    }
    m->nfilters = keep.nfilters;
    m->have_filter = keep.have_filter;
    m->filter_gen = keep.filter_gen;
    m->derp_fresh = m->filter_fresh = 1;
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
