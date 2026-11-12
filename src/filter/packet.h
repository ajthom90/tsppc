#ifndef TS_FILTER_PACKET_H
#define TS_FILTER_PACKET_H

#include <stddef.h>
#include <stdint.h>

/* IPv4 packet parsing for the packet filter, after upstream's
 * net/packet Parsed.decode4. ts_pkt_parse returns -1 (drop) for everything
 * upstream classes as IPProto Unknown:
 *
 * - under 20 bytes, a version other than 4 (IPv6 included), a total length
 *   over the buffer or under the header length;
 * - protocol 0 or 255 in a first fragment;
 * - a first fragment (offset 0, whole packets included) too short for its
 *   transport header: ICMP 8 bytes, IGMP 8, TCP 20, UDP 8, SCTP 12, TSMP 7;
 * - TSMP (99) with More Fragments set;
 * - a later fragment whose offset is under 10 blocks of 8 bytes.
 *
 * Stricter than upstream, by design (each only drops more):
 * - an IHL under 5 is refused (upstream reads the transport header from
 *   inside the IP header);
 * - transport headers are bounded by the IPv4 total length, not the buffer;
 * - ICMP needs 8 bytes, not 4: ts_pkt has no transport length, and upstream's
 *   echo-reply and error checks need 8.
 *
 * A later fragment at offset 10 blocks or more parses with frag
 * TS_PKT_LATER_FRAG, proto set to byte 9 and ports, flags and ICMP fields 0. */

enum { TS_PKT_WHOLE, TS_PKT_FIRST_FRAG, TS_PKT_LATER_FRAG };

#define TS_IPPROTO_ICMP 1
#define TS_IPPROTO_IGMP 2
#define TS_IPPROTO_TCP 6
#define TS_IPPROTO_UDP 17
#define TS_IPPROTO_TSMP 99
#define TS_IPPROTO_SCTP 132

typedef struct {
    uint8_t proto;            /* IP protocol: 1 ICMP, 6 TCP, 17 UDP, 99 TSMP, ... */
    uint32_t src, dst;        /* host byte order */
    uint16_t sport, dport;    /* TCP/UDP (and SCTP, as upstream); 0 otherwise */
    uint8_t tcp_flags;        /* TCP only */
    uint8_t icmp_type, icmp_code;
    int frag;                 /* TS_PKT_* */
    size_t len;               /* IPv4 total length (<= the buffer) */
} ts_pkt;

/* 0, or -1: drop. On -1, *p is zeroed. */
int ts_pkt_parse(ts_pkt *p, const uint8_t *b, size_t n);

/* The Internet checksum (RFC 1071) of b[0..n): the one's complement of the
 * one's-complement sum, an odd final byte padded with zero. A header holding
 * a correct checksum gives 0. */
uint16_t ts_ip_checksum(const uint8_t *b, size_t n);

/* The TSMP disco key advertisement (upstream TSMPDiscoKeyAdvertisement):
 * a 20-byte IPv4 header (45 00 0035, ID 0, no flags, TTL 64, proto 99,
 * checksum, src, dst), then 'a' and the 32-byte disco public key.
 * Returns 53, the bytes written. */
size_t ts_pkt_tsmp_disco(uint8_t out[53], uint32_t src, uint32_t dst, const uint8_t disco_pub[32]);

#endif
