#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/bytes.h"
#include "../src/filter/filter.h"
#include "../src/filter/packet.h"

/* Test addresses only (100.64.0.0/10 test values). */
#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define LOCAL IP(100, 64, 0, 1)
#define PEER IP(100, 101, 102, 103)
#define PEER2 IP(100, 101, 102, 104)
#define OTHER IP(100, 64, 0, 9)

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_ACK 0x10

/* An IPv4 packet: ihl words of header (options zero), then l4. fragword is
 * the flags and fragment offset field. Returns the total length. */
static size_t mkpkt(uint8_t *b, int ihl, uint8_t proto, uint32_t src, uint32_t dst,
                    uint16_t fragword, const uint8_t *l4, size_t l4n)
{
    size_t h = (size_t)ihl * 4, tot = h + l4n;
    memset(b, 0, h);
    b[0] = (uint8_t)(0x40 | ihl);
    ts_put_be16(b + 2, (uint16_t)tot);
    ts_put_be16(b + 6, fragword);
    b[8] = 64;
    b[9] = proto;
    ts_put_be32(b + 12, src);
    ts_put_be32(b + 16, dst);
    ts_put_be16(b + 10, ts_ip_checksum(b, h));
    if (l4n) memcpy(b + h, l4, l4n);
    return tot;
}

/* Transport headers: TCP (20 bytes), UDP (8), ICMP (8), other (8 of zero). */
static size_t mkl4(uint8_t *l4, uint8_t proto, uint16_t sport, uint16_t dport, uint8_t x, uint8_t code)
{
    memset(l4, 0, 20);
    if (proto == TS_IPPROTO_TCP) {
        ts_put_be16(l4, sport);
        ts_put_be16(l4 + 2, dport);
        l4[12] = 0x50;
        l4[13] = x;
        return 20;
    }
    if (proto == TS_IPPROTO_UDP || proto == TS_IPPROTO_SCTP) {
        ts_put_be16(l4, sport);
        ts_put_be16(l4 + 2, dport);
        ts_put_be16(l4 + 4, 8);
        return proto == TS_IPPROTO_SCTP ? 12 : 8;
    }
    if (proto == TS_IPPROTO_ICMP) {
        l4[0] = x;
        l4[1] = code;
        return 8;
    }
    return 8;
}

static int build(ts_pkt *p, uint8_t proto, uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
                 uint8_t x, uint8_t code)
{
    uint8_t l4[20], b[64];
    size_t l4n = mkl4(l4, proto, sport, dport, x, code);
    size_t n = mkpkt(b, 5, proto, src, dst, 0, l4, l4n);
    return ts_pkt_parse(p, b, n);
}

static void test_pkt_parse(void)
{
    uint8_t b[128], l4[20];
    ts_pkt p;
    size_t n;

    /* TCP */
    n = mkpkt(b, 5, 6, PEER, LOCAL, 0, l4, mkl4(l4, 6, 1234, 80, F_SYN | F_ACK, 0));
    t_true("pkt tcp parses", ts_pkt_parse(&p, b, n) == 0);
    t_true("pkt tcp fields", p.proto == 6 && p.src == PEER && p.dst == LOCAL && p.sport == 1234 &&
                             p.dport == 80 && p.tcp_flags == (F_SYN | F_ACK) && p.frag == TS_PKT_WHOLE &&
                             p.len == 40);
    /* UDP */
    n = mkpkt(b, 5, 17, PEER, LOCAL, 0, l4, mkl4(l4, 17, 5353, 53, 0, 0));
    t_true("pkt udp", ts_pkt_parse(&p, b, n) == 0 && p.proto == 17 && p.sport == 5353 && p.dport == 53 &&
                      p.len == 28 && p.tcp_flags == 0);
    /* ICMP */
    n = mkpkt(b, 5, 1, PEER, LOCAL, 0, l4, mkl4(l4, 1, 0, 0, 8, 3));
    t_true("pkt icmp", ts_pkt_parse(&p, b, n) == 0 && p.proto == 1 && p.icmp_type == 8 &&
                       p.icmp_code == 3 && p.sport == 0 && p.dport == 0);
    /* ICMP under 8 bytes of header: dropped (stricter than upstream's 4) */
    n = mkpkt(b, 5, 1, PEER, LOCAL, 0, l4, 7);
    t_true("pkt icmp short", ts_pkt_parse(&p, b, n) == -1);
    /* IHL 7, options before TCP */
    n = mkpkt(b, 7, 6, PEER, LOCAL, 0, l4, mkl4(l4, 6, 4321, 22, F_SYN, 0));
    t_true("pkt ihl options", ts_pkt_parse(&p, b, n) == 0 && p.sport == 4321 && p.dport == 22 &&
                              p.tcp_flags == F_SYN && p.len == 48);
    /* IHL under 5 */
    n = mkpkt(b, 5, 6, PEER, LOCAL, 0, l4, mkl4(l4, 6, 1, 2, F_SYN, 0));
    b[0] = 0x44;
    t_true("pkt ihl 4", ts_pkt_parse(&p, b, n) == -1);
    /* total length shorter than the buffer: trimmed */
    n = mkpkt(b, 5, 17, PEER, LOCAL, 0, l4, mkl4(l4, 17, 1, 2, 0, 0));
    memset(b + n, 0xee, 10);
    t_true("pkt trailing bytes trimmed", ts_pkt_parse(&p, b, n + 10) == 0 && p.len == n);
    /* total length longer than the buffer */
    t_true("pkt cut short", ts_pkt_parse(&p, b, n - 1) == -1);
    /* total length under the header */
    ts_put_be16(b + 2, 19);
    t_true("pkt total under header", ts_pkt_parse(&p, b, n) == -1);
    /* under 20 bytes */
    t_true("pkt 19 bytes", ts_pkt_parse(&p, b, 19) == -1);
    t_true("pkt 0 bytes", ts_pkt_parse(&p, b, 0) == -1);
    /* version 6 and 5 */
    n = mkpkt(b, 5, 17, PEER, LOCAL, 0, l4, mkl4(l4, 17, 1, 2, 0, 0));
    b[0] = 0x65;
    t_true("pkt version 6", ts_pkt_parse(&p, b, n) == -1);
    b[0] = 0x55;
    t_true("pkt version 5", ts_pkt_parse(&p, b, n) == -1);
    /* a first fragment too short for its L4 header */
    n = mkpkt(b, 5, 6, PEER, LOCAL, 0x2000, l4, 16);
    t_true("pkt first frag short tcp", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 17, PEER, LOCAL, 0x2000, l4, 7);
    t_true("pkt first frag short udp", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 17, PEER, LOCAL, 0x2000, l4, mkl4(l4, 17, 7, 9, 0, 0));
    t_true("pkt first frag ok", ts_pkt_parse(&p, b, n) == 0 && p.frag == TS_PKT_FIRST_FRAG && p.dport == 9);
    /* whole packet too short too */
    n = mkpkt(b, 5, 6, PEER, LOCAL, 0, l4, 19);
    t_true("pkt short tcp", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 132, PEER, LOCAL, 0, l4, 11);
    t_true("pkt short sctp", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 132, PEER, LOCAL, 0, l4, mkl4(l4, 132, 5, 6, 0, 0));
    t_true("pkt sctp ports", ts_pkt_parse(&p, b, n) == 0 && p.sport == 5 && p.dport == 6);
    n = mkpkt(b, 5, 2, PEER, LOCAL, 0, l4, 7);
    t_true("pkt short igmp", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 47, PEER, LOCAL, 0, l4, 0);
    t_true("pkt other proto, no payload", ts_pkt_parse(&p, b, n) == 0 && p.proto == 47);
    /* protocols 0 and 255 */
    n = mkpkt(b, 5, 0, PEER, LOCAL, 0, l4, 8);
    t_true("pkt proto 0", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 255, PEER, LOCAL, 0, l4, 8);
    t_true("pkt proto 255", ts_pkt_parse(&p, b, n) == -1);
    /* later fragments at offsets 9 and 10 blocks */
    n = mkpkt(b, 5, 6, PEER, LOCAL, 9, l4, 8);
    t_true("pkt later frag 9", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 6, PEER, LOCAL, 10, l4, 8);
    t_true("pkt later frag 10", ts_pkt_parse(&p, b, n) == 0 && p.frag == TS_PKT_LATER_FRAG &&
                                p.proto == 6 && p.sport == 0 && p.dport == 0 && p.tcp_flags == 0);
    n = mkpkt(b, 5, 255, PEER, LOCAL, 0x2000 | 200, l4, 0);
    t_true("pkt later frag any proto", ts_pkt_parse(&p, b, n) == 0 && p.frag == TS_PKT_LATER_FRAG);
    /* TSMP with MF set; without; too short */
    n = mkpkt(b, 5, 99, PEER, LOCAL, 0x2000, l4, 8);
    t_true("pkt tsmp MF", ts_pkt_parse(&p, b, n) == -1);
    n = mkpkt(b, 5, 99, PEER, LOCAL, 0x4000, l4, 7);
    t_true("pkt tsmp DF ok", ts_pkt_parse(&p, b, n) == 0 && p.proto == 99 && p.frag == TS_PKT_WHOLE);
    n = mkpkt(b, 5, 99, PEER, LOCAL, 0, l4, 6);
    t_true("pkt tsmp short", ts_pkt_parse(&p, b, n) == -1);
}

static void test_tsmp_disco(void)
{
    uint8_t out[53], key[32];
    char want[256];
    size_t i, n;
    ts_pkt p;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0xa0 + i);
    n = ts_pkt_tsmp_disco(out, LOCAL, PEER, key);
    t_true("tsmp length", n == 53);
    t_true("tsmp checksum verifies", ts_ip_checksum(out, 20) == 0);
    snprintf(want, sizeof want,
             "450000350000000040%02x%02x%02x%s%s61%s", 0x63, out[10], out[11],
             "64400001", "64656667",
             "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    t_hex("tsmp bytes", out, 53, want);
    /* The checksum computed independently: 0x4500+0x0035+0x4063+addresses. */
    {
        uint32_t s = 0x4500 + 0x0035 + 0x4063 + 0x6440 + 0x0001 + 0x6465 + 0x6667;
        while (s >> 16) s = (s & 0xffff) + (s >> 16);
        t_true("tsmp checksum value", ts_get_be16(out + 10) == (uint16_t)~s);
    }
    t_true("tsmp parses", ts_pkt_parse(&p, out, 53) == 0 && p.proto == 99 && p.src == LOCAL &&
                          p.dst == PEER && p.len == 53);
    /* odd length checksum */
    {
        static const uint8_t odd[3] = { 0x12, 0x34, 0x56 };
        t_true("checksum odd", ts_ip_checksum(odd, 3) == (uint16_t)~(0x1234 + 0x5600));
    }
}

static ts_filter *compile1(const char *json, uint32_t local)
{
    ts_filter *f = NULL;
    size_t len = strlen(json);
    char err[96];
    if (ts_filter_compile(&f, &json, &len, 1, local, err, sizeof err) != 0) return NULL;
    return f;
}

#define DST_ALL "\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]"
#define DST_80 "\"DstPorts\":[{\"IP\":\"100.64.0.1\",\"Ports\":{\"First\":80,\"Last\":90}}]"
#define RULE(src) "[{\"SrcIPs\":[" src "]," DST_80 "}]"
#define R_PEER RULE("\"100.101.102.103\"")
#define NULL_FILTER "<null>"

typedef struct {
    const char *rules;
    uint8_t proto;
    uint32_t src, dst;
    uint16_t dport;
    uint8_t x, code;     /* TCP flags, or ICMP type and code */
    int want;
} row;

static const row ROWS[] = {
    /* source forms */
    { R_PEER, 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    { R_PEER, 6, PEER2, LOCAL, 80, F_SYN, 0, 0 },
    { RULE("\"*\""), 6, PEER2, LOCAL, 80, F_SYN, 0, 1 },
    { RULE("\"0.0.0.0/0\""), 6, PEER2, LOCAL, 80, F_SYN, 0, 1 },
    { RULE("\"100.101.102.0/24\""), 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    { RULE("\"100.101.102.103/32\""), 6, PEER2, LOCAL, 80, F_SYN, 0, 0 },
    { RULE("\"100.101.102.1/24\""), 6, PEER, LOCAL, 80, F_SYN, 0, 0 },       /* host bits */
    { RULE("\"100.101.102.0/024\""), 6, PEER, LOCAL, 80, F_SYN, 0, 0 },      /* leading zero */
    { RULE("\"100.101.102.0103\""), 6, PEER, LOCAL, 80, F_SYN, 0, 0 },       /* leading zero */
    { RULE("\"100.101.102.100-100.101.102.103\""), 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    { RULE("\"100.101.102.103-100.101.102.200\""), 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    { RULE("\"100.101.102.100-100.101.102.103\""), 6, PEER2, LOCAL, 80, F_SYN, 0, 0 },
    { RULE("\"100.101.102.200-100.101.102.100\""), 6, PEER, LOCAL, 80, F_SYN, 0, 0 },   /* a > b */
    { RULE("\"100.101.102.1-fd7a::1\""), 6, PEER, LOCAL, 80, F_SYN, 0, 0 },             /* mixed */
    { RULE("\"bogus\",\"100.101.102.103\""), 6, PEER, LOCAL, 80, F_SYN, 0, 1 },        /* skipped */
    { RULE("\"cap:https://example.test/cap\""), 6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { RULE("\"fd7a:115c:a1e0::1\""), 6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"fd7a:115c:a1e0::1\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
      6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"cap:x\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
      6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    /* port edges (First 80, Last 90) */
    { R_PEER, 6, PEER, LOCAL, 79, F_SYN, 0, 0 },
    { R_PEER, 6, PEER, LOCAL, 90, F_SYN, 0, 1 },
    { R_PEER, 6, PEER, LOCAL, 91, F_SYN, 0, 0 },
    /* default IPProto */
    { R_PEER, 17, PEER, LOCAL, 85, 0, 0, 1 },
    { R_PEER, 1, PEER, LOCAL, 0, 8, 0, 1 },
    { R_PEER, 132, PEER, LOCAL, 85, 0, 0, 0 },
    { R_PEER, 47, PEER, LOCAL, 0, 0, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[]," DST_80 "}]", 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":null," DST_80 "}]", 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    /* explicit IPProto 17 only */
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[17]," DST_80 "}]", 17, PEER, LOCAL, 80, 0, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[17]," DST_80 "}]", 6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[17]," DST_80 "}]", 1, PEER, LOCAL, 0, 8, 0, 1 },  /* IPs only */
    /* out-of-range IPProto: the list is left empty */
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[300,-1]," DST_80 "}]", 6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[300]," DST_80 "}]", 1, PEER, LOCAL, 0, 8, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[132]," DST_80 "}]", 132, PEER, LOCAL, 80, 0, 0, 1 },
    /* TCP SYN versus SYN+ACK versus ACK, with no rules */
    { "[]", 6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[]", 6, PEER, LOCAL, 80, F_SYN | F_ACK, 0, 1 },
    { "[]", 6, PEER, LOCAL, 80, F_ACK, 0, 1 },
    { "[]", 6, PEER, LOCAL, 80, F_RST, 0, 1 },
    { "[]", 6, PEER, LOCAL, 80, F_SYN | F_FIN, 0, 0 },
    /* ICMP echo request versus reply versus errors */
    { "[]", 1, PEER, LOCAL, 0, 8, 0, 0 },
    { "[]", 1, PEER, LOCAL, 0, 0, 0, 1 },
    { "[]", 1, PEER, LOCAL, 0, 0, 1, 0 },    /* echo reply needs code 0 */
    { "[]", 1, PEER, LOCAL, 0, 3, 1, 1 },
    { "[]", 1, PEER, LOCAL, 0, 11, 0, 1 },
    { "[]", 1, PEER, LOCAL, 0, 18, 0, 1 },   /* upstream ICMP4ParamProblem = 0x12 */
    { "[]", 1, PEER, LOCAL, 0, 12, 0, 0 },
    { R_PEER, 1, PEER, LOCAL, 0, 12, 0, 1 },
    { R_PEER, 1, PEER2, LOCAL, 0, 8, 0, 0 },
    /* "*" destination IP, all ports, any protocol listed */
    { "[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", 6, PEER, LOCAL, 65535, F_SYN, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", 6, PEER, OTHER, 80, F_SYN, 0, 0 },   /* not local */
    { "[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", 6, PEER, OTHER, 80, F_ACK, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", 1, PEER, OTHER, 0, 0, 0, 0 },
    /* other protocols need every port */
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[47]," DST_ALL "}]", 47, PEER, LOCAL, 0, 0, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[47],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65534}}]}]",
      47, PEER, LOCAL, 0, 0, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[47],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":1,\"Last\":65535}}]}]",
      47, PEER, LOCAL, 0, 0, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", 47, PEER, LOCAL, 0, 0, 0, 0 },     /* 47 not default */
    /* TSMP is accepted */
    { "[]", 99, PEER, LOCAL, 0, 0, 0, 1 },
    /* legacy bits: the whole filter matches nothing */
    { "[{\"SrcIPs\":[\"*\"]," DST_ALL "},{\"SrcIPs\":[\"*\"],\"SrcBits\":[32]," DST_ALL "}]",
      6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"SrcBits\":[32]," DST_ALL "}]", 6, PEER, LOCAL, 80, F_ACK, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"SrcBits\":[32]," DST_ALL "}]", 1, PEER, LOCAL, 0, 8, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"SrcBits\":[]," DST_ALL "}]", 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Bits\":0,\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
      6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Bits\":null,\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
      6, PEER, LOCAL, 80, F_SYN, 0, 1 },
    /* empty filter, NULL filter */
    { "[]", 17, PEER, LOCAL, 53, 0, 0, 0 },
    { NULL_FILTER, 6, PEER, LOCAL, 80, F_ACK, 0, 0 },
    { NULL_FILTER, 1, PEER, LOCAL, 0, 0, 0, 0 },
    { NULL_FILTER, 99, PEER, LOCAL, 0, 0, 0, 0 },
    /* CapGrant-only, null rule, ports First > Last (ICMP still matches IPs) */
    { "[{\"SrcIPs\":[\"*\"],\"CapGrant\":[{\"Dsts\":[\"100.64.0.1/32\"],\"CapMap\":{\"x\":[1]}}]}]",
      1, PEER, LOCAL, 0, 8, 0, 0 },
    { "[null]", 6, PEER, LOCAL, 80, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":90,\"Last\":80}}]}]",
      6, PEER, LOCAL, 85, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":90,\"Last\":80}}]}]",
      1, PEER, LOCAL, 0, 8, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\"}]}]", 6, PEER, LOCAL, 0, F_SYN, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\"}]}]", 6, PEER, LOCAL, 1, F_SYN, 0, 0 },
    /* keys match as Go's decoder does: case and the Unicode folds of s and k */
    { "[{\"srcips\":[\"*\"],\"dstports\":[{\"ip\":\"*\",\"PORTS\":{\"first\":0,\"last\":65535}}]}]",
      6, PEER, LOCAL, 1000, F_SYN, 0, 1 },
    { "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"Fir\\u017ft\":100,\"Last\":200}}]}]",
      6, PEER, LOCAL, 99, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"IPProto\":[17],\"Src\\u212a\":1,\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":9}}]}]",
      6, PEER, LOCAL, 5, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"Src\\u0042its\":[1],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":9}}]}]",
      6, PEER, LOCAL, 5, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"Src\\u0062it\\u017f\":[1],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":9}}]}]",
      6, PEER, LOCAL, 5, F_SYN, 0, 0 },
    { "[{\"SrcIPs\":[\"*\"],\"Unknown\":{\"a\":[1,2]}," DST_80 "}]", 6, PEER, LOCAL, 80, F_SYN, 0, 1 },
};

static void test_filter_rules(void)
{
    size_t i;
    for (i = 0; i < sizeof ROWS / sizeof ROWS[0]; i++) {
        const row *r = &ROWS[i];
        ts_filter *f = NULL;
        ts_flows fl;
        ts_pkt p;
        const char *why = NULL;
        char name[64];
        int got;
        ts_flows_init(&fl);
        snprintf(name, sizeof name, "filter row %u compiles", (unsigned)i);
        if (strcmp(r->rules, NULL_FILTER) != 0) {
            f = compile1(r->rules, LOCAL);
            t_true(name, f != NULL);
            if (!f) continue;
        }
        snprintf(name, sizeof name, "filter row %u packet", (unsigned)i);
        t_true(name, build(&p, r->proto, r->src, r->dst, 40000, r->dport, r->x, r->code) == 0);
        got = ts_filter_in(f, &fl, &p, &why);
        snprintf(name, sizeof name, "filter row %u verdict", (unsigned)i);
        t_true(name, got == r->want);
        if (got != r->want) printf("  row %u: got %d (%s)\n", (unsigned)i, got, why ? why : "?");
        snprintf(name, sizeof name, "filter row %u why", (unsigned)i);
        t_true(name, why != NULL && why[0] != 0);
        ts_filter_free(f);
    }
    t_true("filter rows >= 40", sizeof ROWS / sizeof ROWS[0] >= 40);
}

/* pre(): multicast, link-local, fragments, local_ip 0, why NULL. */
static void test_filter_pre(void)
{
    uint8_t b[64], l4[20];
    ts_filter *f = compile1("[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", IP(224, 0, 0, 5));
    ts_filter *g = compile1("[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", IP(169, 254, 1, 1));
    ts_filter *h = compile1("[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", IP(169, 254, 169, 254));
    ts_filter *z = compile1("[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", 0);
    ts_filter *e = compile1("[]", LOCAL);
    ts_pkt p;
    size_t n;
    const char *why;

    t_true("pre compiles", f && g && h && z && e);
    t_true("pre multicast drop", build(&p, 6, PEER, IP(224, 0, 0, 5), 1, 80, F_ACK, 0) == 0 &&
                                 ts_filter_in(f, NULL, &p, NULL) == 0);
    t_true("pre link-local drop", build(&p, 6, PEER, IP(169, 254, 1, 1), 1, 80, F_ACK, 0) == 0 &&
                                  ts_filter_in(g, NULL, &p, NULL) == 0);
    t_true("pre 169.254.169.254 passes pre", build(&p, 6, PEER, IP(169, 254, 169, 254), 1, 80, F_ACK, 0) == 0 &&
                                             ts_filter_in(h, NULL, &p, NULL) == 1);
    t_true("pre local 0 drops dst 0", build(&p, 6, PEER, 0, 1, 80, F_ACK, 0) == 0 &&
                                      ts_filter_in(z, NULL, &p, &why) == 0 &&
                                      strcmp(why, "destination not allowed") == 0);
    t_true("pre local 0 drops all", build(&p, 1, PEER, LOCAL, 0, 0, 0, 0) == 0 &&
                                    ts_filter_in(z, NULL, &p, NULL) == 0);
    /* later fragments: accepted before the local check; no filter drops them */
    n = mkpkt(b, 5, 6, PEER, OTHER, 10, l4, 8);
    t_true("pre later frag", ts_pkt_parse(&p, b, n) == 0);
    t_true("pre later frag accepted", ts_filter_in(e, NULL, &p, NULL) == 1);
    t_true("pre later frag dropped, no filter", ts_filter_in(NULL, NULL, &p, &why) == 0 &&
                                                strcmp(why, "no filter") == 0);
    {
        ts_pkt q = p;
        q.dst = LOCAL;
        t_true("pre later frag to local dropped, no filter", ts_filter_in(NULL, NULL, &q, NULL) == 0);
    }
    n = mkpkt(b, 5, 6, PEER, IP(224, 1, 1, 1), 10, l4, 8);
    t_true("pre later frag multicast", ts_pkt_parse(&p, b, n) == 0 && ts_filter_in(NULL, NULL, &p, NULL) == 0);
    /* first fragments go through the rules */
    n = mkpkt(b, 5, 6, PEER, LOCAL, 0x2000, l4, mkl4(l4, 6, 1, 80, F_SYN, 0));
    t_true("pre first frag ruled", ts_pkt_parse(&p, b, n) == 0 && ts_filter_in(e, NULL, &p, NULL) == 0);
    t_true("pre no filter why", build(&p, 6, PEER, LOCAL, 1, 80, F_ACK, 0) == 0 &&
                                ts_filter_in(NULL, NULL, &p, &why) == 0 && strcmp(why, "no filter") == 0);
    t_true("pre tcp non-syn why", ts_filter_in(e, NULL, &p, &why) == 1 && strcmp(why, "tcp non-syn") == 0);
    ts_filter_free(f);
    ts_filter_free(g);
    ts_filter_free(h);
    ts_filter_free(z);
    ts_filter_free(e);
    ts_filter_free(NULL);
}

static int compile_rc(const char *json, char *err, size_t cap, ts_filter **out)
{
    size_t len = strlen(json);
    *out = (ts_filter *)1;
    return ts_filter_compile(out, &json, &len, 1, LOCAL, err, cap);
}

static void test_filter_compile(void)
{
    static const char *const BAD[] = {
        "", "{}", "null", "[1]", "[\"x\"]", "[[]]", "[] x", "[{}", "[{\"SrcIPs\":\"*\"}]",
        "[{\"SrcIPs\":[1]}]", "[{\"IPProto\":[\"6\"]}]", "[{\"IPProto\":[6.5]}]",
        "[{\"IPProto\":[99999999999999999999]}]", "[{\"IPProto\":{}}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":70000,\"Last\":1}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":-1,\"Last\":1}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":\"1\",\"Last\":1}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":1.5,\"Last\":1}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":[]}]}]", "[{\"DstPorts\":[{\"IP\":5}]}]",
        "[{\"DstPorts\":[1]}]", "[{\"DstPorts\":{}}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Bits\":\"x\"}]}]", "[{\"SrcBits\":[\"x\"]}]",
        "[{\"SrcIPs\":[\"*\"],\"srcips\":[\"*\"]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"IP\":\"*\"}]}]",
        "[{\"DstPorts\":[{\"Ports\":{\"First\":1,\"First\":2}}]}]",
    };
    char err[64];
    ts_filter *f;
    size_t i;
    int rc;

    for (i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        char name[64];
        rc = compile_rc(BAD[i], err, sizeof err, &f);
        snprintf(name, sizeof name, "compile bad %u", (unsigned)i);
        t_true(name, rc == -1 && f == NULL && err[0] != 0 && strlen(err) < sizeof err);
        if (rc != -1) printf("  bad %u: rc %d\n", (unsigned)i, rc);
    }
    /* never echoes input */
    rc = compile_rc("[{\"SrcIPs\":[\"secretthing\"],\"IPProto\":[\"secretthing\"]}]", err, sizeof err, &f);
    t_true("compile err no echo", rc == -1 && strstr(err, "secretthing") == NULL);
    /* err NULL and tiny */
    {
        const char *j = "[1]";
        size_t l = 3;
        char tiny[4];
        f = NULL;
        t_true("compile err NULL", ts_filter_compile(&f, &j, &l, 1, LOCAL, NULL, 0) == -1 && f == NULL);
        t_true("compile err tiny", ts_filter_compile(&f, &j, &l, 1, LOCAL, tiny, sizeof tiny) == -1 &&
                                   strlen(tiny) == 3);
    }
    /* ok: warnings for skipped entries and legacy bits */
    rc = compile_rc("[{\"SrcIPs\":[\"bogus\"]}]", err, sizeof err, &f);
    t_true("compile skipped entry warns", rc == 0 && f != NULL && err[0] != 0);
    ts_filter_free(f);
    rc = compile_rc("[{\"SrcIPs\":[\"*\"]," DST_ALL "}]", err, sizeof err, &f);
    t_true("compile clean", rc == 0 && f != NULL && err[0] == 0);
    ts_filter_free(f);
    /* several texts; a bad later text rejects all; legacy bits in any text */
    {
        const char *j[3];
        size_t l[3];
        ts_pkt p;
        j[0] = "[]";
        j[1] = "[{\"SrcIPs\":[\"*\"]," DST_ALL "}]";
        j[2] = "[{\"SrcIPs\":[\"100.101.102.104\"]," DST_80 "}]";
        for (i = 0; i < 3; i++) l[i] = strlen(j[i]);
        f = NULL;
        t_true("compile 3 texts", ts_filter_compile(&f, j, l, 3, LOCAL, err, sizeof err) == 0 && f);
        t_true("compile 3 texts match", build(&p, 6, PEER, LOCAL, 1, 7, F_SYN, 0) == 0 &&
                                        ts_filter_in(f, NULL, &p, NULL) == 1);
        ts_filter_free(f);
        j[2] = "[{}";
        l[2] = strlen(j[2]);
        t_true("compile bad 3rd text", ts_filter_compile(&f, j, l, 3, LOCAL, err, sizeof err) == -1 && !f);
        j[2] = "[{\"SrcIPs\":[\"*\"],\"SrcBits\":[1]}]";
        l[2] = strlen(j[2]);
        t_true("compile bits in 3rd text", ts_filter_compile(&f, j, l, 3, LOCAL, err, sizeof err) == 0 && f &&
                                           err[0] != 0);
        t_true("compile bits in 3rd text matches nothing", ts_filter_in(f, NULL, &p, NULL) == 0);
        ts_filter_free(f);
        /* a later syntax error still wins over legacy bits */
        j[1] = "[{\"SrcBits\":[1]}]";
        l[1] = strlen(j[1]);
        j[2] = "[1]";
        l[2] = 3;
        t_true("compile bits then bad", ts_filter_compile(&f, j, l, 3, LOCAL, err, sizeof err) == -1 && !f);
        t_true("compile n=0", ts_filter_compile(&f, j, l, 0, LOCAL, err, sizeof err) == 0 && f);
        t_true("compile n=0 drops syn", ts_filter_in(f, NULL, &p, NULL) == 0);
        ts_filter_free(f);
    }
}

static void test_filter_flows(void)
{
    ts_flows *fl = (ts_flows *)malloc(sizeof *fl);
    ts_filter *f = compile1("[]", LOCAL), *g;
    ts_pkt out, in;
    const char *why;
    unsigned i;

    if (!fl || !f) { t_true("flows setup", 0); free(fl); ts_filter_free(f); return; }
    ts_flows_init(fl);
    /* outbound A:1000 -> B:53 */
    t_true("flows out", build(&out, 17, LOCAL, PEER, 1000, 53, 0, 0) == 0);
    t_true("flows in before", build(&in, 17, PEER, LOCAL, 53, 1000, 0, 0) == 0 &&
                              ts_filter_in(f, fl, &in, NULL) == 0);
    ts_filter_out(fl, &out);
    t_true("flows reply accepted", ts_filter_in(f, fl, &in, &why) == 1 && strcmp(why, "udp cached") == 0);
    {
        ts_pkt other = in;
        other.sport = 54;
        t_true("flows other port dropped", ts_filter_in(f, fl, &other, NULL) == 0);
        other = in;
        other.proto = 132;
        t_true("flows other proto dropped", ts_filter_in(f, fl, &other, NULL) == 0);
        other = in;
        other.dst = OTHER;
        t_true("flows other dst dropped", ts_filter_in(f, fl, &other, NULL) == 0);
    }
    /* TCP and later fragments are not recorded */
    {
        ts_pkt t = out, ti = in;
        t.proto = 6;
        ti.proto = 6;
        ti.tcp_flags = F_SYN;
        ts_filter_out(fl, &t);
        t_true("flows tcp not recorded", ts_filter_in(f, fl, &ti, NULL) == 0);
        t = out;
        t.dport = 54;
        t.frag = TS_PKT_LATER_FRAG;
        ts_filter_out(fl, &t);
        ti = in;
        ti.sport = 54;
        t_true("flows later frag not recorded", ts_filter_in(f, fl, &ti, NULL) == 0);
        t = out;
        t.dst = IP(224, 0, 0, 251);
        ts_filter_out(fl, &t);
        t_true("flows multicast not recorded", fl->n == 1);
    }
    /* the flows survive a recompile */
    g = compile1("[{\"SrcIPs\":[\"100.64.0.9\"]," DST_80 "}]", LOCAL);
    t_true("flows recompile", g && ts_filter_in(g, fl, &in, NULL) == 1);
    ts_filter_free(g);
    /* 513 other flows push the first out (LRU) */
    for (i = 0; i < 513; i++) {
        ts_pkt o = out;
        o.sport = (uint16_t)(2000 + i);
        ts_filter_out(fl, &o);
    }
    t_true("flows table bounded", fl->n == TS_FLOW_MAX);
    t_true("flows first evicted", ts_filter_in(f, fl, &in, NULL) == 0);
    /* a lookup refreshes: the oldest is kept if it was just used */
    ts_flows_init(fl);
    ts_filter_out(fl, &out);
    for (i = 0; i < TS_FLOW_MAX - 1; i++) {
        ts_pkt o = out;
        o.sport = (uint16_t)(3000 + i);
        ts_filter_out(fl, &o);
    }
    t_true("flows refresh hit", ts_filter_in(f, fl, &in, NULL) == 1);
    {
        ts_pkt o = out;
        o.sport = 9999;
        ts_filter_out(fl, &o);     /* evicts 3000, not the refreshed entry */
    }
    t_true("flows refreshed survives", ts_filter_in(f, fl, &in, NULL) == 1);
    {
        ts_pkt r = in;
        r.dport = 3000;
        t_true("flows oldest evicted", ts_filter_in(f, fl, &r, NULL) == 0);
        r.dport = 3001;
        t_true("flows next kept", ts_filter_in(f, fl, &r, NULL) == 1);
    }
    /* re-adding an existing flow does not grow the table */
    ts_flows_init(fl);
    ts_filter_out(fl, &out);
    ts_filter_out(fl, &out);
    t_true("flows readd", fl->n == 1);
    ts_filter_out(NULL, &out);
    t_true("flows NULL fl", ts_filter_in(f, NULL, &in, NULL) == 0);
    ts_filter_free(f);
    free(fl);
}

/* n sources (as single IPs, one per rule entry, rules of up to 64 sources);
 * dsts destination entries in one extra rule. */
static char *gen(unsigned nsrc, unsigned ndst, unsigned nrules_extra)
{
    size_t cap = (size_t)nsrc * 24 + (size_t)ndst * 64 + (size_t)nrules_extra * 16 + 256, o = 0;
    char *s = (char *)malloc(cap);
    unsigned i;
    if (!s) return NULL;
    o += (size_t)snprintf(s + o, cap - o, "[");
    for (i = 0; i < nsrc; i++) {
        if (i % 64 == 0) o += (size_t)snprintf(s + o, cap - o, "%s{\"SrcIPs\":[", i ? "]}," : "");
        o += (size_t)snprintf(s + o, cap - o, "%s\"10.%u.%u.1\"", i % 64 ? "," : "", (i >> 8) & 255, i & 255);
    }
    if (nsrc) o += (size_t)snprintf(s + o, cap - o, "]}");
    if (ndst) {
        o += (size_t)snprintf(s + o, cap - o, "%s{\"SrcIPs\":[\"*\"],\"DstPorts\":[", nsrc ? "," : "");
        for (i = 0; i < ndst; i++)
            o += (size_t)snprintf(s + o, cap - o, "%s{\"IP\":\"*\",\"Ports\":{\"First\":%u,\"Last\":%u}}",
                                  i ? "," : "", i % 65536, i % 65536);
        o += (size_t)snprintf(s + o, cap - o, "]}");
    }
    for (i = 0; i < nrules_extra; i++)
        o += (size_t)snprintf(s + o, cap - o, "%s{}", (nsrc || ndst || i) ? "," : "");
    snprintf(s + o, cap - o, "]");
    return s;
}

static void limit_case(const char *name, unsigned nsrc, unsigned ndst, unsigned extra, int want)
{
    char *s = gen(nsrc, ndst, extra);
    char err[64];
    ts_filter *f = NULL;
    int rc;
    if (!s) { t_true(name, 0); return; }
    rc = compile_rc(s, err, sizeof err, &f);
    t_true(name, rc == want && (rc == 0 ? f != NULL : f == NULL) && (rc == 0 || err[0] != 0));
    if (rc != want) printf("  %s: rc %d (%s)\n", name, rc, err);
    ts_filter_free(f);
    free(s);
}

static void test_filter_limits(void)
{
    unsigned srules = (TS_FILTER_MAX_SRCS + 63) / 64;   /* rules used by the sources */
    limit_case("limits srcs at max", TS_FILTER_MAX_SRCS, 0, 0, 0);
    limit_case("limits srcs over", TS_FILTER_MAX_SRCS + 1, 0, 0, -2);
    limit_case("limits dsts at max", 0, TS_FILTER_MAX_DSTS, 0, 0);
    limit_case("limits dsts over", 0, TS_FILTER_MAX_DSTS + 1, 0, -2);
    limit_case("limits rules at max", 0, 0, TS_FILTER_MAX_MATCHES, 0);
    limit_case("limits rules over", 0, 0, TS_FILTER_MAX_MATCHES + 1, -2);
    limit_case("limits all at max", TS_FILTER_MAX_SRCS - 1, TS_FILTER_MAX_DSTS,
               TS_FILTER_MAX_MATCHES - srules - 1, 0);
    /* the last source still matches when at the limit */
    {
        char *s = gen(TS_FILTER_MAX_SRCS - 1, 1, 0);   /* plus the "*" of the dst rule */
        ts_filter *f = s ? compile1(s, LOCAL) : NULL;
        ts_pkt p;
        t_true("limits srcs compile with dst", f != NULL);
        /* sources only rules have no DstPorts; the dst rule has "*" source */
        t_true("limits match", f && build(&p, 6, PEER, LOCAL, 1, 0, F_SYN, 0) == 0 &&
                               ts_filter_in(f, NULL, &p, NULL) == 1);
        ts_filter_free(f);
        free(s);
    }
}

void test_filter(void)
{
    test_pkt_parse();
    test_tsmp_disco();
    test_filter_rules();
    test_filter_pre();
    test_filter_compile();
    test_filter_flows();
    test_filter_limits();
}
