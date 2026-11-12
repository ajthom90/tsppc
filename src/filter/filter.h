#ifndef TS_FILTER_FILTER_H
#define TS_FILTER_FILTER_H

#include <stddef.h>
#include <stdint.h>

#include "packet.h"

/* The inbound packet filter, after upstream's wgengine/filter (IPv4 only).
 *
 * Rules (tailcfg.FilterRule, MatchesFromFilterRules, parseIPSet):
 * - SrcIPs and DstPorts[].IP entries: "*", a CIDR (host bits clear), a single
 *   IP, or an inclusive range "a-b" (exactly one '-'). Each is stored as an
 *   IPv4 [lo, hi] range. IPv6 entries are ignored. Leading zeros, host bits,
 *   a > b or mixed families make a bad entry, which is skipped while the rest
 *   of the rule applies. "cap:" sources never match (no capability test).
 * - A non-empty SrcBits, or a non-null DstPorts[].Bits, anywhere in any of
 *   the texts makes the whole filter match nothing (as "[]": the per-protocol
 *   defaults below still apply). "SrcBits":[] and "Bits":null are harmless.
 * - IPProto absent, null or [] means TCP, UDP, ICMP (and ICMPv6). Otherwise
 *   values outside 0..255 are dropped, and a list left empty matches nothing
 *   (except ICMP, which ignores protocols: see below).
 * - Ports {First, Last} are inclusive; absent means 0..0.
 * - CapGrant is ignored, so a CapGrant-only rule matches nothing.
 * - Keys match as Go's encoding/json does (case-insensitive, with the Unicode
 *   folds of s and k). Unknown keys are skipped. A known key repeated in one
 *   object, a known field of the wrong JSON type, or Ports outside 0..65535
 *   rejects the whole filter (-1), as upstream's decoder rejects the message.
 *
 * Inbound (pre() and runIn4), in order:
 * - a packet ts_pkt_parse refused never gets here (the caller drops it);
 * - no filter (f NULL): drop every packet, later fragments included
 *   ("no filter"), as upstream's tstun does with a nil filter;
 * - multicast destination (224/4): drop;
 * - link-local destination (169.254/16, except 169.254.169.254): drop;
 * - a later fragment (TS_PKT_LATER_FRAG): accept;
 * - a destination that isn't local_ip (or local_ip 0): drop;
 * - ICMP: echo reply (type 0 code 0) or error (types 3, 11 and 18, as
 *   upstream's ICMP4ParamProblem = 0x12) accepts; else any rule whose source
 *   and destination match, whatever its protocols and ports;
 * - TCP: not a SYN without ACK accepts ("tcp non-syn"); else a rule match;
 * - UDP and SCTP: a cached flow accepts; else a rule match;
 * - TSMP (99): accept;
 * - other protocols: the protocol is listed and a destination with ports
 *   exactly 0..65535 covers dst.
 *
 * Outbound (ts_filter_out) never blocks. It records the reversed tuple of a
 * UDP or SCTP packet in the flow LRU, except a later fragment or a multicast
 * or link-local destination, which upstream's pre() stops first. */

#define TS_FILTER_MAX_MATCHES 1024    /* rules after expansion; more: over limit */
#define TS_FILTER_MAX_SRCS 8192       /* source ranges, all rules */
#define TS_FILTER_MAX_DSTS 8192       /* destination (range, ports) entries, all rules */
#define TS_FLOW_MAX 512

typedef struct ts_filter ts_filter;   /* opaque, heap */

typedef struct {
    uint64_t used;            /* LRU stamp: higher is more recent */
    uint32_t src, dst;
    uint16_t sport, dport;
    uint8_t proto;
} ts_flow;

/* Fixed LRU of TS_FLOW_MAX UDP (and SCTP) tuples; caller storage, so it
 * survives a filter recompile. Lookups and adds refresh an entry; adding to a
 * full table evicts the least recently used. */
typedef struct {
    ts_flow e[TS_FLOW_MAX];
    size_t n;                 /* entries e[0..n) are in use */
    uint64_t clock;
} ts_flows;

/* Compile the concatenation of n FilterRule JSON arrays (named filters in
 * sorted-name order). local_ip is our tailnet IPv4 (Appendix B E3 "local4").
 * 0: ok. -1: a text is not a JSON array of objects (whole filter rejected).
 * -2: over a TS_FILTER_MAX_* limit. err says which, never echoing input. */
/* On 0, err holds "" or a warning (a skipped entry, legacy bits). On any
 * other return *out is NULL. err may be NULL or errcap 0; it is a static
 * text, always NUL-terminated when errcap > 0. */
int ts_filter_compile(ts_filter **out, const char *const *json, const size_t *len, size_t n,
                      uint32_t local_ip, char *err, size_t errcap);
void ts_filter_free(ts_filter *f);
void ts_flows_init(ts_flows *fl);
/* f NULL means "no filter yet": drop every packet (later fragments too).
 * fl may be NULL (no flow cache). why, if not NULL, gets a static reason. */
int ts_filter_in(const ts_filter *f, ts_flows *fl, const ts_pkt *p, const char **why); /* 1 accept, 0 drop */
void ts_filter_out(ts_flows *fl, const ts_pkt *p);   /* records UDP flows; never blocks */

#endif
