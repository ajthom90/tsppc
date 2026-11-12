#include "filter.h"

#include <stdlib.h>
#include <string.h>

#include "../proto/json.h"

/* ---- the compiled filter ----------------------------------------------- */

typedef struct {
    uint32_t lo, hi;
} range;

typedef struct {
    uint32_t lo, hi;
    uint16_t first, last;
} dst_ent;

typedef struct {
    size_t s0, ns;            /* srcs[s0 .. s0+ns) */
    size_t d0, nd;            /* dsts[d0 .. d0+nd) */
    uint8_t protos[32];       /* bit n: IP protocol n listed */
} rule;

struct ts_filter {
    uint32_t local;           /* 0: nothing is local */
    size_t nrules, nsrcs, ndsts;
    rule rules[TS_FILTER_MAX_MATCHES];
    range srcs[TS_FILTER_MAX_SRCS];
    dst_ent dsts[TS_FILTER_MAX_DSTS];
};

/* ---- errors -------------------------------------------------------------- */

#define E_SYNTAX "filter: not a JSON array of filter rules"
#define E_TYPE "filter: a rule field has the wrong type or range"
#define E_DUP "filter: a rule field appears twice"
#define E_RULES "filter: over the limit of rules"
#define E_SRCS "filter: over the limit of source ranges"
#define E_DSTS "filter: over the limit of destination entries"
#define E_OOM "filter: out of memory"
#define W_ENTRY "filter: a bad address entry was skipped"
#define W_LEGACY "filter: legacy SrcBits or Bits present; the filter matches nothing"

static void set_err(char *err, size_t cap, const char *msg)
{
    size_t n;
    if (!err || cap == 0) return;
    n = strlen(msg);
    if (n >= cap) n = cap - 1;
    memcpy(err, msg, n);
    err[n] = 0;
}

typedef struct {
    ts_filter *f;
    ts_json j;
    int legacy;
    const char *warn;
    const char *err;
} cctx;

/* rc helpers: 0 ok, -1 reject, -2 over a limit. */
static int fail(cctx *c, const char *msg)
{
    c->err = msg;
    return -1;
}

static int over(cctx *c, const char *msg)
{
    c->err = msg;
    return -2;
}

/* ---- keys ---------------------------------------------------------------- */

/* Go's encoding/json matches a key to a field name with bytes.EqualFold:
 * ASCII case, plus U+017F (long s) for s and U+212A (Kelvin) for k, the only
 * non-ASCII simple folds of ASCII letters. */
static int key_is(const char *k, const char *want)
{
    const unsigned char *s = (const unsigned char *)k;
    for (; *want; want++) {
        char w = *want;
        char lw = (char)(w >= 'A' && w <= 'Z' ? w + 32 : w);
        if (*s < 0x80) {
            char ls = (char)(*s >= 'A' && *s <= 'Z' ? *s + 32 : *s);
            if (*s == 0 || ls != lw) return 0;
            s++;
        } else if (lw == 's' && s[0] == 0xc5 && s[1] == 0xbf) {
            s += 2;
        } else if (lw == 'k' && s[0] == 0xe2 && s[1] == 0x84 && s[2] == 0xaa) {
            s += 3;
        } else {
            return 0;
        }
    }
    return *s == 0;
}

static int key_index(const ts_json_tok *t, const char *const *names, int n)
{
    char buf[48];
    int i;
    if (ts_json_string(buf, sizeof buf, t) < 0) return -1;
    for (i = 0; i < n; i++)
        if (key_is(buf, names[i])) return i;
    return -1;
}

/* A seen-key check: a key repeated in one object rejects the filter. */
static int mark(cctx *c, unsigned *seen, int k)
{
    if (*seen & (1u << k)) return fail(c, E_DUP);
    *seen |= 1u << k;
    return 0;
}

/* ---- numbers ------------------------------------------------------------- */

/* A JSON integer as Go decodes into uint16 (no sign, fraction or exponent). */
static int tok_u16(const ts_json_tok *t, uint16_t *out)
{
    int64_t v;
    if (t->type != TS_JSON_NUMBER || t->rawlen == 0 || t->raw[0] == '-') return -1;
    if (ts_json_int64(&v, t) != 0 || v < 0 || v > 65535) return -1;
    *out = (uint16_t)v;
    return 0;
}

/* ---- address entries (parseIPSet) ----------------------------------------- */

/* 1 to 3 digits, no leading zero unless "0". Advances *p. -1 if none. */
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

/* A dotted IPv4 address as netip.ParseAddr accepts it, the whole of s[0..n). */
static int ipv4(const char *s, size_t n, uint32_t *out)
{
    char buf[16];
    const char *p = buf;
    uint32_t v = 0;
    long o;
    int i;
    if (n == 0 || n >= sizeof buf) return -1;
    memcpy(buf, s, n);
    buf[n] = 0;
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

enum { IPS_BAD = -1, IPS_NONE = 0, IPS_V4 = 1, IPS_CAP = 2 };

/* One SrcIPs or DstPorts IP entry, tested in upstream's order: "*", "cap:",
 * a prefix (contains '/'), a range (exactly one '-'), a single address.
 * IPS_V4 sets [*lo, *hi]; IPS_NONE is IPv6 (ignored); IPS_CAP a capability. */
static int parse_ipset(const ts_json_tok *t, uint32_t *lo, uint32_t *hi)
{
    char buf[128];
    const char *slash, *dash;
    int n = ts_json_string(buf, sizeof buf, t);
    uint32_t a, b;
    size_t i, ndash = 0;

    if (n < 0) return IPS_BAD;
    if (strcmp(buf, "*") == 0) {
        *lo = 0;
        *hi = 0xffffffffu;
        return IPS_V4;
    }
    if (strncmp(buf, "cap:", 4) == 0) return IPS_CAP;
    if (strchr(buf, ':')) return IPS_NONE;     /* IPv6 (or invalid): never stored */
    slash = strchr(buf, '/');
    if (slash) {
        const char *p = slash + 1;
        long bits = dec(&p, 2);
        uint32_t mask;
        if (bits < 0 || bits > 32 || *p != 0) return IPS_BAD;
        if (ipv4(buf, (size_t)(slash - buf), &a) != 0) return IPS_BAD;
        mask = bits == 0 ? 0 : 0xffffffffu << (32 - bits);
        if (a & ~mask) return IPS_BAD;          /* non-network bits set */
        *lo = a;
        *hi = a | ~mask;
        return IPS_V4;
    }
    for (i = 0; i < (size_t)n; i++) ndash += buf[i] == '-';
    if (ndash == 1) {
        dash = strchr(buf, '-');
        if (ipv4(buf, (size_t)(dash - buf), &a) != 0) return IPS_BAD;
        if (ipv4(dash + 1, strlen(dash + 1), &b) != 0) return IPS_BAD;
        if (a > b) return IPS_BAD;
        *lo = a;
        *hi = b;
        return IPS_V4;
    }
    if (ipv4(buf, (size_t)n, &a) != 0) return IPS_BAD;
    *lo = *hi = a;
    return IPS_V4;
}

/* ---- rules ----------------------------------------------------------------- */

static int next(cctx *c, ts_json_tok *t)
{
    if (ts_json_next(&c->j, t) == TS_JSON_ERROR) return fail(c, E_SYNTAX);
    return 0;
}

static int skip_value(cctx *c, const ts_json_tok *first)
{
    if (ts_json_skip(&c->j, first) != 0) return fail(c, E_SYNTAX);
    return 0;
}

static int parse_srcs(cctx *c, rule *r)
{
    ts_json_tok t;
    ts_filter *f = c->f;
    uint32_t lo, hi;
    int rc;
    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_ARR_END) return 0;
        if (t.type == TS_JSON_NUL) {            /* Go: "", an invalid entry */
            c->warn = W_ENTRY;
            continue;
        }
        if (t.type != TS_JSON_STRING) return fail(c, E_TYPE);
        switch (parse_ipset(&t, &lo, &hi)) {
        case IPS_V4:
            if (f->nsrcs >= TS_FILTER_MAX_SRCS) return over(c, E_SRCS);
            f->srcs[f->nsrcs].lo = lo;
            f->srcs[f->nsrcs].hi = hi;
            f->nsrcs++;
            r->ns++;
            break;
        case IPS_BAD:
            c->warn = W_ENTRY;
            break;
        default:                                /* IPv6, cap: never match */
            break;
        }
    }
}

/* Ports {First, Last}. */
static int parse_ports(cctx *c, uint16_t *first, uint16_t *last)
{
    static const char *const K[] = { "First", "Last" };
    ts_json_tok t, v;
    unsigned seen = 0;
    int rc, k;
    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_OBJ_END) return 0;
        k = key_index(&t, K, 2);
        if (k >= 0 && (rc = mark(c, &seen, k)) != 0) return rc;
        if ((rc = next(c, &v)) != 0) return rc;
        if (k < 0) {
            if ((rc = skip_value(c, &v)) != 0) return rc;
            continue;
        }
        if (v.type == TS_JSON_NUL) continue;    /* Go leaves the field unchanged */
        if (tok_u16(&v, k == 0 ? first : last) != 0) return fail(c, E_TYPE);
    }
}

/* One NetPortRange {IP, Bits, Ports}. */
static int parse_npr(cctx *c, rule *r)
{
    static const char *const K[] = { "IP", "Bits", "Ports" };
    ts_json_tok t, v, ip;
    ts_filter *f = c->f;
    unsigned seen = 0;
    uint16_t first = 0, last = 0;
    int rc, k, have_ip = 0;
    uint32_t lo, hi;
    int64_t bits;

    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_OBJ_END) break;
        k = key_index(&t, K, 3);
        if (k >= 0 && (rc = mark(c, &seen, k)) != 0) return rc;
        if ((rc = next(c, &v)) != 0) return rc;
        if (k < 0) {
            if ((rc = skip_value(c, &v)) != 0) return rc;
            continue;
        }
        if (v.type == TS_JSON_NUL) continue;
        if (k == 0) {
            if (v.type != TS_JSON_STRING) return fail(c, E_TYPE);
            ip = v;
            have_ip = 1;
        } else if (k == 1) {
            if (v.type != TS_JSON_NUMBER || ts_json_int64(&bits, &v) != 0) return fail(c, E_TYPE);
            c->legacy = 1;                      /* any non-null Bits */
        } else {
            if (v.type != TS_JSON_OBJ_START) return fail(c, E_TYPE);
            if ((rc = parse_ports(c, &first, &last)) != 0) return rc;
        }
    }
    if (!have_ip) {                             /* Go: "", an invalid entry */
        c->warn = W_ENTRY;
        return 0;
    }
    switch (parse_ipset(&ip, &lo, &hi)) {
    case IPS_V4:
        if (f->ndsts >= TS_FILTER_MAX_DSTS) return over(c, E_DSTS);
        f->dsts[f->ndsts].lo = lo;
        f->dsts[f->ndsts].hi = hi;
        f->dsts[f->ndsts].first = first;
        f->dsts[f->ndsts].last = last;
        f->ndsts++;
        r->nd++;
        break;
    case IPS_NONE:
        break;
    default:                                    /* bad, or cap: in DstPorts */
        c->warn = W_ENTRY;
        break;
    }
    return 0;
}

static int parse_dsts(cctx *c, rule *r)
{
    ts_json_tok t;
    int rc;
    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_ARR_END) return 0;
        if (t.type == TS_JSON_NUL) {
            c->warn = W_ENTRY;
            continue;
        }
        if (t.type != TS_JSON_OBJ_START) return fail(c, E_TYPE);
        if ((rc = parse_npr(c, r)) != 0) return rc;
    }
}

/* SrcBits: any element makes the whole filter match nothing. */
static int parse_srcbits(cctx *c)
{
    ts_json_tok t;
    int64_t v;
    int rc;
    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_ARR_END) return 0;
        if (t.type != TS_JSON_NUL && (t.type != TS_JSON_NUMBER || ts_json_int64(&v, &t) != 0))
            return fail(c, E_TYPE);
        c->legacy = 1;
    }
}

/* IPProto: ints; 0..255 kept. *count gets the number of elements. */
static int parse_protos(cctx *c, rule *r, size_t *count)
{
    ts_json_tok t;
    int64_t v;
    int rc;
    *count = 0;
    memset(r->protos, 0, sizeof r->protos);
    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_ARR_END) return 0;
        (*count)++;
        if (t.type == TS_JSON_NUL) {
            v = 0;                              /* Go leaves the element 0 */
        } else if (t.type != TS_JSON_NUMBER || ts_json_int64(&v, &t) != 0) {
            return fail(c, E_TYPE);
        }
        if (v >= 0 && v <= 255) r->protos[v >> 3] |= (uint8_t)(1u << (v & 7));
    }
}

static void default_protos(rule *r)
{
    static const uint8_t def[] = { 6, 17, 1, 58 };   /* TCP, UDP, ICMPv4, ICMPv6 */
    size_t i;
    memset(r->protos, 0, sizeof r->protos);
    for (i = 0; i < sizeof def; i++) r->protos[def[i] >> 3] |= (uint8_t)(1u << (def[i] & 7));
}

static int parse_rule(cctx *c)
{
    static const char *const K[] = { "SrcIPs", "SrcBits", "DstPorts", "IPProto", "CapGrant" };
    ts_filter *f = c->f;
    ts_json_tok t, v;
    unsigned seen = 0;
    size_t nproto = 0;
    rule *r;
    int rc, k;

    if (f->nrules >= TS_FILTER_MAX_MATCHES) return over(c, E_RULES);
    r = &f->rules[f->nrules];
    memset(r, 0, sizeof *r);
    r->s0 = f->nsrcs;
    r->d0 = f->ndsts;
    f->nrules++;

    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_OBJ_END) break;
        k = key_index(&t, K, 5);
        if (k >= 0 && (rc = mark(c, &seen, k)) != 0) return rc;
        if ((rc = next(c, &v)) != 0) return rc;
        if (k < 0 || k == 4) {                  /* unknown, CapGrant: ignored */
            if ((rc = skip_value(c, &v)) != 0) return rc;
            continue;
        }
        if (v.type == TS_JSON_NUL) continue;
        if (v.type != TS_JSON_ARR_START) return fail(c, E_TYPE);
        switch (k) {
        case 0: rc = parse_srcs(c, r); break;
        case 1: rc = parse_srcbits(c); break;
        case 2: rc = parse_dsts(c, r); break;
        default: rc = parse_protos(c, r, &nproto); break;
        }
        if (rc != 0) return rc;
    }
    if (nproto == 0) default_protos(r);         /* absent, null or [] */
    return 0;
}

static int parse_text(cctx *c, const char *json, size_t len)
{
    ts_json_tok t;
    int rc;
    ts_json_init(&c->j, json ? json : "", json ? len : 0);
    if ((rc = next(c, &t)) != 0) return rc;
    if (t.type != TS_JSON_ARR_START) return fail(c, E_SYNTAX);
    for (;;) {
        if ((rc = next(c, &t)) != 0) return rc;
        if (t.type == TS_JSON_ARR_END) break;
        if (t.type == TS_JSON_NUL) continue;    /* Go: a zero rule, matching nothing */
        if (t.type != TS_JSON_OBJ_START) return fail(c, E_SYNTAX);
        if ((rc = parse_rule(c)) != 0) return rc;
    }
    if ((rc = next(c, &t)) != 0) return rc;
    if (t.type != TS_JSON_END) return fail(c, E_SYNTAX);
    return 0;
}

int ts_filter_compile(ts_filter **out, const char *const *json, const size_t *len, size_t n,
                      uint32_t local_ip, char *err, size_t errcap)
{
    cctx c;
    size_t i;
    int rc = 0;

    *out = NULL;
    set_err(err, errcap, "");
    memset(&c, 0, sizeof c);
    c.f = (ts_filter *)calloc(1, sizeof(ts_filter));
    if (!c.f) {
        set_err(err, errcap, E_OOM);
        return -2;
    }
    c.f->local = local_ip;
    for (i = 0; i < n && rc == 0; i++) rc = parse_text(&c, json[i], len[i]);
    if (rc != 0) {
        set_err(err, errcap, c.err);
        free(c.f);
        return rc;
    }
    if (c.legacy) {
        /* MatchesFromFilterRules returns nil: no rules at all. */
        c.f->nrules = c.f->nsrcs = c.f->ndsts = 0;
        c.warn = W_LEGACY;
    }
    if (c.warn) set_err(err, errcap, c.warn);
    *out = c.f;
    return 0;
}

void ts_filter_free(ts_filter *f)
{
    free(f);
}

/* ---- matching -------------------------------------------------------------- */

static int src_in(const ts_filter *f, const rule *r, uint32_t a)
{
    size_t i;
    for (i = 0; i < r->ns; i++) {
        const range *s = &f->srcs[r->s0 + i];
        if (a >= s->lo && a <= s->hi) return 1;
    }
    return 0;
}

static int proto_in(const rule *r, uint8_t p)
{
    return (r->protos[p >> 3] >> (p & 7)) & 1;
}

/* matches.match: protocol listed, source, and a destination with the port. */
static int match(const ts_filter *f, const ts_pkt *p)
{
    size_t i, k;
    for (i = 0; i < f->nrules; i++) {
        const rule *r = &f->rules[i];
        if (!proto_in(r, p->proto) || !src_in(f, r, p->src)) continue;
        for (k = 0; k < r->nd; k++) {
            const dst_ent *d = &f->dsts[r->d0 + k];
            if (p->dst >= d->lo && p->dst <= d->hi && p->dport >= d->first && p->dport <= d->last)
                return 1;
        }
    }
    return 0;
}

/* matches.matchIPsOnly: protocols and ports ignored. */
static int match_ips_only(const ts_filter *f, const ts_pkt *p)
{
    size_t i, k;
    for (i = 0; i < f->nrules; i++) {
        const rule *r = &f->rules[i];
        if (!src_in(f, r, p->src)) continue;
        for (k = 0; k < r->nd; k++) {
            const dst_ent *d = &f->dsts[r->d0 + k];
            if (p->dst >= d->lo && p->dst <= d->hi) return 1;
        }
    }
    return 0;
}

/* matches.matchProtoAndIPsOnlyIfAllPorts. */
static int match_all_ports(const ts_filter *f, const ts_pkt *p)
{
    size_t i, k;
    for (i = 0; i < f->nrules; i++) {
        const rule *r = &f->rules[i];
        if (!proto_in(r, p->proto) || !src_in(f, r, p->src)) continue;
        for (k = 0; k < r->nd; k++) {
            const dst_ent *d = &f->dsts[r->d0 + k];
            if (d->first != 0 || d->last != 65535) continue;
            if (p->dst >= d->lo && p->dst <= d->hi) return 1;
        }
    }
    return 0;
}

/* ---- flows ----------------------------------------------------------------- */

void ts_flows_init(ts_flows *fl)
{
    memset(fl, 0, sizeof *fl);
}

static ts_flow *flow_find(ts_flows *fl, uint8_t proto, uint32_t src, uint16_t sport, uint32_t dst,
                          uint16_t dport)
{
    size_t i;
    for (i = 0; i < fl->n; i++) {
        ts_flow *e = &fl->e[i];
        if (e->proto == proto && e->src == src && e->sport == sport && e->dst == dst && e->dport == dport)
            return e;
    }
    return NULL;
}

static void flow_add(ts_flows *fl, uint8_t proto, uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport)
{
    ts_flow *e = flow_find(fl, proto, src, sport, dst, dport);
    size_t i;
    if (!e) {
        if (fl->n < TS_FLOW_MAX) {
            e = &fl->e[fl->n++];
        } else {
            e = &fl->e[0];
            for (i = 1; i < TS_FLOW_MAX; i++)
                if (fl->e[i].used < e->used) e = &fl->e[i];
        }
        e->proto = proto;
        e->src = src;
        e->sport = sport;
        e->dst = dst;
        e->dport = dport;
    }
    e->used = ++fl->clock;
}

/* ---- verdicts -------------------------------------------------------------- */

static int is_multicast(uint32_t a)
{
    return (a >> 28) == 0xe;                    /* 224.0.0.0/4 */
}

static int is_link_local(uint32_t a)
{
    /* 169.254.0.0/16, except 169.254.169.254 (upstream's gcpDNSAddr). */
    return (a >> 16) == 0xa9fe && a != 0xa9fea9feu;
}

static int verdict(int v, const char *reason, const char **why)
{
    if (why) *why = reason;
    return v;
}

int ts_filter_in(const ts_filter *f, ts_flows *fl, const ts_pkt *p, const char **why)
{
    ts_flow *e;

    /* No filter yet: drop every packet, before pre() (upstream's tstun drops
     * when its filter is nil, before the filter runs). */
    if (!f) return verdict(0, "no filter", why);
    if (is_multicast(p->dst)) return verdict(0, "multicast", why);
    if (is_link_local(p->dst)) return verdict(0, "link-local-unicast", why);
    if (p->frag == TS_PKT_LATER_FRAG) return verdict(1, "fragment", why);
    if (f->local == 0 || p->dst != f->local) return verdict(0, "destination not allowed", why);

    switch (p->proto) {
    case TS_IPPROTO_ICMP:
        if ((p->icmp_type == 0 && p->icmp_code == 0) || p->icmp_type == 3 || p->icmp_type == 11 ||
            p->icmp_type == 18)
            return verdict(1, "icmp response ok", why);
        if (match_ips_only(f, p)) return verdict(1, "icmp ok", why);
        break;
    case TS_IPPROTO_TCP:
        if ((p->tcp_flags & 0x12) != 0x02) return verdict(1, "tcp non-syn", why);
        if (match(f, p)) return verdict(1, "tcp ok", why);
        break;
    case TS_IPPROTO_UDP:
    case TS_IPPROTO_SCTP:
        if (fl) {
            e = flow_find(fl, p->proto, p->src, p->sport, p->dst, p->dport);
            if (e) {
                e->used = ++fl->clock;
                return verdict(1, "udp cached", why);
            }
        }
        if (match(f, p)) return verdict(1, "udp ok", why);
        break;
    case TS_IPPROTO_TSMP:
        return verdict(1, "tsmp ok", why);
    default:
        if (match_all_ports(f, p)) return verdict(1, "other-portless ok", why);
        break;
    }
    return verdict(0, "no rule", why);
}

void ts_filter_out(ts_flows *fl, const ts_pkt *p)
{
    if (!fl || !p) return;
    if (p->proto != TS_IPPROTO_UDP && p->proto != TS_IPPROTO_SCTP) return;
    if (p->frag == TS_PKT_LATER_FRAG || is_multicast(p->dst) || is_link_local(p->dst)) return;
    flow_add(fl, p->proto, p->dst, p->dport, p->src, p->sport);   /* reversed */
}
