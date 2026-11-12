#include "packet.h"

#include <string.h>

#include "../core/bytes.h"

/* Upstream minFragBlks: the largest IPv4 header plus a basic TCP header, in
 * 8-byte fragment blocks. A later fragment below it could overwrite a
 * transport header. */
#define MIN_FRAG_BLKS ((60 + 20) / 8)

#define ICMP_MIN 8      /* upstream 4; 8 for the echo-reply and error checks */
#define IGMP_MIN 8
#define TCP_MIN 20
#define UDP_MIN 8
#define SCTP_MIN 12
#define TSMP_MIN 7

static int refuse(ts_pkt *p)
{
    memset(p, 0, sizeof *p);
    return -1;
}

int ts_pkt_parse(ts_pkt *p, const uint8_t *b, size_t n)
{
    size_t tot, hl, l4n;
    uint16_t fw, ofs;
    int mf;
    const uint8_t *l4;

    memset(p, 0, sizeof *p);
    if (n < 20 || (b[0] >> 4) != 4) return refuse(p);
    hl = (size_t)(b[0] & 0x0f) * 4;
    tot = ts_get_be16(b + 2);
    if (hl < 20 || tot > n || hl > tot) return refuse(p);

    p->proto = b[9];
    p->src = ts_get_be32(b + 12);
    p->dst = ts_get_be32(b + 16);
    p->len = tot;
    l4 = b + hl;
    l4n = tot - hl;

    fw = ts_get_be16(b + 6);
    mf = (fw & 0x2000) != 0;
    ofs = (uint16_t)(fw & 0x1fff);
    if (ofs != 0) {
        if (ofs < MIN_FRAG_BLKS) return refuse(p);
        p->frag = TS_PKT_LATER_FRAG;
        return 0;
    }
    p->frag = mf ? TS_PKT_FIRST_FRAG : TS_PKT_WHOLE;

    switch (p->proto) {
    case 0:
    case 255:
        return refuse(p);
    case TS_IPPROTO_ICMP:
        if (l4n < ICMP_MIN) return refuse(p);
        p->icmp_type = l4[0];
        p->icmp_code = l4[1];
        break;
    case TS_IPPROTO_IGMP:
        if (l4n < IGMP_MIN) return refuse(p);
        break;
    case TS_IPPROTO_TCP:
        if (l4n < TCP_MIN) return refuse(p);
        p->sport = ts_get_be16(l4);
        p->dport = ts_get_be16(l4 + 2);
        p->tcp_flags = l4[13];
        break;
    case TS_IPPROTO_UDP:
        if (l4n < UDP_MIN) return refuse(p);
        p->sport = ts_get_be16(l4);
        p->dport = ts_get_be16(l4 + 2);
        break;
    case TS_IPPROTO_SCTP:
        if (l4n < SCTP_MIN) return refuse(p);
        p->sport = ts_get_be16(l4);
        p->dport = ts_get_be16(l4 + 2);
        break;
    case TS_IPPROTO_TSMP:
        if (mf || l4n < TSMP_MIN) return refuse(p);
        break;
    default:
        break;
    }
    return 0;
}

uint16_t ts_ip_checksum(const uint8_t *b, size_t n)
{
    uint32_t s = 0;
    size_t i;
    for (i = 0; i + 1 < n; i += 2) {
        s += ts_get_be16(b + i);
        s = (s & 0xffff) + (s >> 16);
    }
    if (n & 1) {
        s += (uint32_t)b[n - 1] << 8;
        s = (s & 0xffff) + (s >> 16);
    }
    s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

size_t ts_pkt_tsmp_disco(uint8_t out[53], uint32_t src, uint32_t dst, const uint8_t disco_pub[32])
{
    memset(out, 0, 20);
    out[0] = 0x45;
    ts_put_be16(out + 2, 53);
    out[8] = 64;
    out[9] = TS_IPPROTO_TSMP;
    ts_put_be32(out + 12, src);
    ts_put_be32(out + 16, dst);
    ts_put_be16(out + 10, ts_ip_checksum(out, 20));
    out[20] = 'a';
    memcpy(out + 21, disco_pub, 32);
    return 53;
}
