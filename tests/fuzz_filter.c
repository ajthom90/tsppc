#include "fuzz.h"
#include "../src/core/bytes.h"
#include "../src/filter/filter.h"
#include "../src/filter/packet.h"

#include <stdlib.h>
#include <string.h>

/* Input: a BE16 length L, then L bytes of rules JSON, then a packet.
 *
 * Oracles, for each input:
 * - ts_pkt_parse: 0 gives len <= the buffer and a known frag value; -1 a
 *   zeroed packet;
 * - ts_filter_compile returns 0, -1 or -2; *out is NULL exactly when it fails;
 *   err is NUL-terminated within errcap (a small cap, so truncation runs);
 * - compiled twice, with local_ip the packet's dst (so the rules are reached)
 *   and a fixed address, it gives the same verdicts as itself (deterministic);
 * - a NULL filter drops every packet;
 * - whatever "[]" accepts, the compiled filter accepts (rules only add);
 * - after ts_filter_out of the packet, its reverse (UDP or SCTP, not a later
 *   fragment, not multicast or link-local) is accepted, even under "[]";
 * - the flow table stays within TS_FLOW_MAX. */

static ts_flows FL;

static void check_err(const char *err, size_t cap)
{
    TS_FUZZ_ASSERT(memchr(err, 0, cap) != NULL);
}

static ts_filter *compile(const char *json, size_t len, uint32_t local, size_t cap)
{
    char err[48];
    ts_filter *f = (ts_filter *)1;
    int rc;
    memset(err, 'x', sizeof err);
    rc = ts_filter_compile(&f, &json, &len, 1, local, err, cap);
    TS_FUZZ_ASSERT(rc == 0 || rc == -1 || rc == -2);
    TS_FUZZ_ASSERT((rc == 0) == (f != NULL));
    if (cap) check_err(err, cap);
    if (rc != 0) TS_FUZZ_ASSERT(err[0] != 0 || cap <= 1);
    return f;
}

static void target(const uint8_t *data, size_t len)
{
    size_t rl, pl, cap;
    const char *rules;
    const uint8_t *pkt;
    ts_pkt p, r;
    ts_filter *f, *g, *e;
    int ok, vf, vg, ve, vn;
    const char *why;
    char *two[2];
    size_t lens[2];

    if (len < 2) return;
    rl = ts_get_be16(data);
    if (rl > len - 2) rl = len - 2;
    rules = (const char *)data + 2;
    pkt = data + 2 + rl;
    pl = len - 2 - rl;

    ok = ts_pkt_parse(&p, pkt, pl) == 0;
    if (ok) {
        TS_FUZZ_ASSERT(p.len <= pl && p.len >= 20);
        TS_FUZZ_ASSERT(p.frag == TS_PKT_WHOLE || p.frag == TS_PKT_FIRST_FRAG || p.frag == TS_PKT_LATER_FRAG);
        TS_FUZZ_ASSERT(p.proto != 0 || p.frag == TS_PKT_LATER_FRAG);
    } else {
        ts_pkt z;
        memset(&z, 0, sizeof z);
        TS_FUZZ_ASSERT(memcmp(&p, &z, sizeof z) == 0);
        memset(&p, 0, sizeof p);
        p.proto = (uint8_t)(len & 0xff);
        p.dst = 0x64400001u;
        p.src = 0x64656667u;
        p.dport = (uint16_t)len;
        p.tcp_flags = (uint8_t)(len >> 3);
        p.len = 20;
    }

    cap = len % 3 == 0 ? 5 : 48;
    f = compile(rules, rl, p.dst, cap);
    g = compile(rules, rl, p.dst, 48);
    e = compile("[]", 2, p.dst, 48);
    TS_FUZZ_ASSERT(e != NULL);
    TS_FUZZ_ASSERT((f == NULL) == (g == NULL));

    ts_flows_init(&FL);
    vn = ts_filter_in(NULL, &FL, &p, &why);
    TS_FUZZ_ASSERT(why != NULL);
    TS_FUZZ_ASSERT(vn == 0 && strcmp(why, "no filter") == 0);
    ve = ts_filter_in(e, &FL, &p, NULL);
    if (f) {
        vf = ts_filter_in(f, &FL, &p, &why);
        vg = ts_filter_in(g, NULL, &p, NULL);
        TS_FUZZ_ASSERT(vf == vg);
        TS_FUZZ_ASSERT(vf == 0 || vf == 1);
        if (ve) TS_FUZZ_ASSERT(vf);
    }

    /* outbound, then the reply */
    ts_filter_out(&FL, &p);
    TS_FUZZ_ASSERT(FL.n <= TS_FLOW_MAX);
    r = p;
    r.src = p.dst;
    r.dst = p.src;
    r.sport = p.dport;
    r.dport = p.sport;
    if ((p.proto == TS_IPPROTO_UDP || p.proto == TS_IPPROTO_SCTP) && p.frag != TS_PKT_LATER_FRAG &&
        (p.dst >> 28) != 0xe && !((p.dst >> 16) == 0xa9fe && p.dst != 0xa9fea9feu) &&
        (r.dst >> 28) != 0xe && !((r.dst >> 16) == 0xa9fe && r.dst != 0xa9fea9feu) && r.dst != 0) {
        ts_filter *er = compile("[]", 2, r.dst, 48);
        TS_FUZZ_ASSERT(er != NULL);
        TS_FUZZ_ASSERT(ts_filter_in(er, &FL, &r, NULL) == 1);
        ts_filter_free(er);
    }
    /* many flows: bounded */
    if (len % 5 == 0) {
        unsigned i;
        for (i = 0; i < TS_FLOW_MAX + 3; i++) {
            ts_pkt q = p;
            q.proto = TS_IPPROTO_UDP;
            q.frag = TS_PKT_WHOLE;
            q.sport = (uint16_t)i;
            ts_filter_out(&FL, &q);
        }
        TS_FUZZ_ASSERT(FL.n <= TS_FLOW_MAX);
    }

    /* the rules split into two texts compile like a concatenation would or fail */
    if (rl > 4) {
        two[0] = (char *)"[]";
        lens[0] = 2;
        two[1] = (char *)rules;
        lens[1] = rl;
        {
            ts_filter *t2 = NULL;
            char err[48];
            int rc = ts_filter_compile(&t2, (const char *const *)two, lens, 2, p.dst, err, sizeof err);
            TS_FUZZ_ASSERT((rc == 0) == (f != NULL));
            if (t2) TS_FUZZ_ASSERT(ts_filter_in(t2, NULL, &p, NULL) == ts_filter_in(g, NULL, &p, NULL));
            ts_filter_free(t2);
        }
    }

    ts_filter_free(f);
    ts_filter_free(g);
    ts_filter_free(e);
}

static const char *const RULES[] = {
    ("[{\"SrcIPs\":[\"100.101.102.103\",\"*\",\"100.64.0.0/10\",\"100.64.0.1-100.64.0.9\",\"cap:x\","
    "\"fd7a:115c:a1e0::/48\"],\"DstPorts\":[{\"IP\":\"100.64.0.1\",\"Ports\":{\"First\":80,\"Last\":90}},"
    "{\"IP\":\"*\",\"Bits\":null,\"Ports\":{\"First\":0,\"Last\":65535}}],\"IPProto\":[6,17,1,47,132]}]"),
    "[{\"SrcIPs\":[\"*\"],\"SrcBits\":[32],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
    "[]",
    ("[null,{\"srcips\":[\"*\"],\"dstports\":[{\"ip\":\"100.64.0.1/32\",\"ports\":{\"first\":1,\"last\":2}}],"
    "\"CapGrant\":[{\"Dsts\":[\"100.64.0.1/32\"],\"CapMap\":{\"a\":[{}]}}],\"IPProto\":[300]}]"),
};

static size_t mk(uint8_t *b, uint8_t proto, uint16_t fw, size_t l4n, uint8_t x)
{
    size_t tot = 20 + l4n;
    memset(b, 0, tot);
    b[0] = 0x45;
    ts_put_be16(b + 2, (uint16_t)tot);
    ts_put_be16(b + 6, fw);
    b[8] = 64;
    b[9] = proto;
    ts_put_be32(b + 12, 0x64656667u);
    ts_put_be32(b + 16, 0x64400001u);
    ts_put_be16(b + 20, 40000);
    ts_put_be16(b + 22, 80);
    if (proto == 6) b[33] = x;
    if (proto == 1) b[20] = x;
    return tot;
}

void ts_fuzz_filter(void)
{
    enum { NR = sizeof RULES / sizeof RULES[0], NP = 7 };
    uint8_t *seeds[NR * NP];
    const uint8_t *cseeds[NR * NP];
    size_t lens[NR * NP], i, k;
    uint8_t pk[NP][64];
    size_t pn[NP];

    pn[0] = mk(pk[0], 6, 0, 20, 0x02);
    pn[1] = mk(pk[1], 17, 0, 8, 0);
    pn[2] = mk(pk[2], 1, 0, 8, 8);
    pn[3] = mk(pk[3], 47, 0, 4, 0);
    pn[4] = mk(pk[4], 99, 0, 33, 0);
    pn[5] = mk(pk[5], 6, 0x2000 | 10, 8, 0);
    pn[6] = mk(pk[6], 132, 0x2000, 12, 0);
    for (i = 0; i < NR; i++) {
        size_t rl = strlen(RULES[i]);
        for (k = 0; k < NP; k++) {
            size_t n = 2 + rl + pn[k], at = i * NP + k;
            seeds[at] = (uint8_t *)malloc(n);
            TS_FUZZ_ASSERT(seeds[at] != NULL);
            ts_put_be16(seeds[at], (uint16_t)rl);
            memcpy(seeds[at] + 2, RULES[i], rl);
            memcpy(seeds[at] + 2 + rl, pk[k], pn[k]);
            cseeds[at] = seeds[at];
            lens[at] = n;
        }
    }
    ts_fuzz_run("filter", target, cseeds, lens, NR * NP, TS_FUZZ_DEFAULT_ITERS);
    for (i = 0; i < NR * NP; i++) free(seeds[i]);
}
