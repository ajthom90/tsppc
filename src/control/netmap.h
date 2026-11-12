#ifndef TS_CONTROL_NETMAP_H
#define TS_CONTROL_NETMAP_H

#include <stddef.h>
#include <stdint.h>

/* The network map: our own node and our peers, built from the stream of
 * MapResponse messages that control sends on the long poll.
 *
 * Semantics follow upstream's controlclient (tailcfg.MapResponse, map.go):
 *
 * - "KeepAlive": true. Nothing in the map changes; Debug and TKAInfo are not
 *   acted on. Only PingRequest is taken from such a message.
 * - "Node" replaces self as a whole. Absent (or null) means self is unchanged.
 *   The first non-KeepAlive message after ts_netmap_init/ts_netmap_reset must
 *   carry Node ("initial MapResponse lacked Node"), as upstream requires.
 * - "Peers", when it is a non-empty array, replaces the whole peer set, and the
 *   delta fields of that message are then ignored (still syntax-checked).
 *   An absent, null or empty Peers never clears peers.
 * - Otherwise the deltas are applied in this order, whatever the key order in
 *   the message: PeersRemoved (IDs), PeersChanged (whole-node upsert),
 *   OnlineChange ({"<id>": bool}), PeersChangedPatch. PeerSeenChange is
 *   ignored. An OnlineChange or patch for an unknown ID is ignored.
 * - A patch applies only the fields present: DERPRegion (0 means unchanged),
 *   Key, DiscoKey, Online and KeyExpiry. Its other fields are ignored.
 * - "TKAInfo" present (not null) sets tka_enabled to !Disabled; absent means
 *   unchanged. Tailnet Lock is unsupported: the session must stop with a clear
 *   message when tka_enabled is set.
 * - "DERPMap" (tailcfg.DERPMap; map.go): absent, null or {} means unchanged.
 *   A non-null "Regions" (an object keyed by decimal region ID) replaces every
 *   region; a null region entry is not kept. "HomeParams" absent or null, or a
 *   null "RegionScore", keeps the previous scores; a non-null RegionScore
 *   replaces the whole score table. Scores are held apart from the regions, so
 *   a later Regions-only map still gets them; a score that is null, 0 or less
 *   counts as 1.0 (upstream uses only score > 0). Region IDs and RegionScore
 *   keys must be 1..2^53-1, else the message is rejected; IDs above INT_MAX
 *   are valid but never stored. The lowest TS_DERP_MAX_REGIONS region IDs are
 *   kept (and the lowest TS_DERP_SCORES_MAX score IDs), sorted by ID; a
 *   duplicate key is applied in document order (last wins).
 * - A DERP node is kept only if it is not STUNOnly, not InsecureForTests, has
 *   a dotted-quad IPv4 (empty, "none" or anything else skips it: there is no
 *   DNS for relays), a DERPPort in 0..65535 (0 means 443), a CertName that is
 *   not "sha256-raw:...", and a TLS name (CertName if set, else HostName) that
 *   passes ts_host_name_ok. The first TS_DERP_MAX_NODES kept nodes are kept,
 *   in order; null entries are skipped. A region with no usable node is kept
 *   with nnodes 0. A Name or RegionCode that does not fit is stored as "".
 * - "PacketFilter" non-null sets the filter named "base". Then "PacketFilters"
 *   non-null: a null "*" (wherever it is) clears every filter first, including
 *   that base; each other key sets (array) or deletes (null) its filter, last
 *   occurrence wins; a non-null "*" is ignored. Absent or null means unchanged.
 *   Each stored text is the exact JSON array text from the message (so [] is a
 *   real, empty filter); a value that is not an array rejects the message.
 *   More than TS_FILTER_NAMES_MAX names, a name over 63 bytes, or all texts
 *   together over TS_FILTER_JSON_MAX bytes (checked on the result) rejects the
 *   message with last_limit set. have_filter is set by the first non-null
 *   PacketFilter or PacketFilters and never cleared.
 * - derp_gen and filter_gen bump only when the stored content (or have_filter)
 *   actually changes, so the data plane can skip work otherwise.
 * - ts_netmap_reset keeps the regions, scores and filters readable (the data
 *   plane keeps using the last ones), but a new session starts upstream's
 *   per-session state empty: the first non-null DERPMap after a reset applies
 *   onto nothing (no Regions means no regions, no HomeParams no scores), and
 *   the first non-null PacketFilter or PacketFilters starts from an empty set,
 *   so a stale named filter does not survive a reconnect. A reconnect map
 *   without those fields keeps what is stored.
 * - Every other field (DNSConfig, UserProfiles, SSHPolicy, ControlDialPlan,
 *   PopBrowserURL, ...) is skipped, of any type.
 *
 * Whole-node replacement means a Node, Peers or PeersChanged entry that omits
 * a field sets it to zero (for example "Online" absent means offline).
 * null is treated as absent for every field. A known field of the wrong JSON
 * type, a malformed key, address or timestamp, a name over 255 bytes, more
 * than TS_MAX_PEERS distinct peers, or invalid JSON rejects the message.
 * Keys must match exactly (upstream's Go decoder is case-insensitive; control
 * sends canonical names). A key that appears twice uses the last value.
 *
 * Apply is all-or-nothing: on error the map, the ping request and the
 * per-message fields are exactly as before the call, and last_error says why
 * (it names the field or limit, never message content).
 *
 * Caller contract:
 * - A rejected message means our view of the map may now differ from
 *   control's (a delta was lost), so the caller must end the map session and
 *   reconnect, which starts again with a full map (ts_netmap_reset first) --
 *   unless last_limit is set: a full map would be rejected again, so the
 *   caller stops instead of reconnecting.
 * - Read the per-message fields (have_exit, exit_code, sleep_ms) only after
 *   apply returned 0; after -1 they still describe the previous message.
 * - m->peers is swapped with an internal buffer by every successful apply, so
 *   the m->peers pointer and any pointer from ts_netmap_peer are valid only
 *   until the next successful ts_netmap_apply (or reset or free).
 * - m->regions and the filter_name/filter_json strings are replaced only by
 *   an apply that bumps derp_gen or filter_gen (and freed by ts_netmap_free);
 *   reset keeps them. Each filter_json[i] is NUL-terminated at filter_len[i].
 * - An all-zero node_key or disco_key means the node has none. */

#define TS_MAX_PEERS 256
#define TS_MAP_MSG_MAX 4194304          /* largest framed map message, bytes */
#define TS_NODE_NAME_MAX 255            /* longest Name kept, bytes */
#define TS_PING_URL_MAX 1023            /* longer PingRequest URLs are dropped */
#define TS_PING_TYPES_MAX 63            /* longer PingRequest Types are dropped */
#define TS_MAP_SLEEP_MAX_MS 300000u     /* Debug.SleepSeconds is clamped to 5 min */
#define TS_DERP_MAX_REGIONS 64          /* lowest IDs kept; more ignored */
#define TS_DERP_MAX_NODES 8             /* per region; more ignored */
#define TS_DERP_SCORES_MAX 256          /* RegionScore entries kept (lowest IDs) */
#define TS_FILTER_NAMES_MAX 16
#define TS_FILTER_NAME_MAX 63           /* longest filter name, bytes */
#define TS_FILTER_JSON_MAX 1048576      /* all named filters together; more: message rejected, last_limit */

typedef struct {
    int64_t id;                 /* ID */
    /* KeyExpiry in seconds since the Unix epoch; 0 when absent or the zero
     * time 0001-01-01T00:00:00Z (the key does not expire). An expiry of
     * exactly 1970-01-01T00:00:00Z is stored as -1, so 0 keeps meaning none. int64_t rather
     * than time_t, which is 32 bits on PowerPC Mac OS X. The netmap never
     * reads the clock: the caller decides expiry (non-zero and before now). */
    int64_t key_expiry;
    char name[TS_NODE_NAME_MAX + 1];   /* Name as received (FQDN with trailing dot), NUL-terminated */
    uint8_t node_key[32];       /* Key, "nodekey:<64 hex>"; zero if absent */
    uint8_t disco_key[32];      /* DiscoKey, "discokey:<64 hex>"; zero if absent */
    uint32_t ipv4;              /* first IPv4 /32 of Addresses, host byte order */
    int have_ipv4;
    int home_derp;              /* HomeDERP, else legacy "DERP":"127.3.3.40:N" */
    int online;                 /* Online true; 0 if false or absent */
    int authorized;             /* MachineAuthorized */
    int expired;                /* Expired (control's explicit flag) */
    int jailed;                 /* IsJailed */
    int wireguard_only;         /* IsWireGuardOnly */
    /* Laid out without padding, so nodes compare with memcmp. */
} ts_node;

typedef struct {
    char name[64];              /* Name ("" if it does not fit) */
    char host[254];             /* TLS name: CertName if set, else HostName (<= 253) */
    uint32_t ipv4;              /* IPv4, host byte order */
    uint16_t port;              /* DERPPort, 0 -> 443 */
} ts_derp_node;                 /* only usable nodes are kept (rules above) */

typedef struct {
    int id;                     /* region ID (the Regions key), 1..INT_MAX */
    char code[32];              /* RegionCode ("" if it does not fit) */
    int avoid, no_home;         /* Avoid, NoMeasureNoHome */
    double score;               /* HomeParams.RegionScore, 1.0 if absent or not > 0 */
    size_t nnodes;
    ts_derp_node nodes[TS_DERP_MAX_NODES];
} ts_derp_region;               /* unused bytes are zero, so regions compare with memcmp */

typedef struct {                /* internal: one RegionScore entry */
    int id;
    double score;
} ts_derp_score;

/* MapResponse.PingRequest. apply sets it (pending = 1) whenever a message,
 * KeepAlive or not, carries one with a non-empty URL of at most
 * TS_PING_URL_MAX bytes and Types of at most TS_PING_TYPES_MAX bytes; it is
 * otherwise left alone, and the session clears pending when it has acted. */
typedef struct {
    int pending;
    char url[TS_PING_URL_MAX + 1];
    int url_is_noise;           /* URLIsNoise */
    char types[TS_PING_TYPES_MAX + 1];   /* Types, "" for a plain HEAD ping */
} ts_ping_req;

typedef struct {
    ts_node self;
    int have_self;
    ts_node *peers;             /* TS_MAX_PEERS slots; peers[0..npeers) in use, unique IDs */
    size_t npeers;
    int tka_enabled;            /* Tailnet Lock on (TKAInfo present, Disabled false) */
    ts_ping_req ping;
    /* The Debug request of the message just applied: every successful apply
     * sets these from that message alone (0 when it has no Debug, and always
     * 0 for a KeepAlive, whose Debug upstream ignores). A rejected message
     * leaves them as they were. */
    int have_exit;              /* Debug.Exit present */
    int exit_code;              /* its value */
    uint32_t sleep_ms;          /* Debug.SleepSeconds, clamped to TS_MAP_SLEEP_MAX_MS; 0 if absent,
                                 * non-positive or not finite */
    /* DERP map: regions[0..nregions) sorted by ID (TS_DERP_MAX_REGIONS slots). */
    ts_derp_region *regions;
    size_t nregions;
    uint32_t derp_gen;          /* bumps on every change of the regions */
    /* Named packet filters, sorted by name (strcmp); texts are JSON arrays. */
    char *filter_name[TS_FILTER_NAMES_MAX];
    char *filter_json[TS_FILTER_NAMES_MAX];
    size_t filter_len[TS_FILTER_NAMES_MAX];
    size_t nfilters;
    int have_filter;            /* a PacketFilter(s) has been applied */
    uint32_t filter_gen;        /* bumps on every change of the filters or have_filter */
    char last_error[128];
    int last_limit;             /* the last rejection was a limit (TS_MAX_PEERS, or a filter
                                 * name, count or size limit), which control will hit again on
                                 * a fresh map */
    ts_node *stage;             /* internal: second TS_MAX_PEERS buffer for all-or-nothing apply */
    ts_derp_region *derp_stage; /* internal: second TS_DERP_MAX_REGIONS buffer */
    ts_derp_score *scores;      /* internal: RegionScore table, sorted by ID */
    ts_derp_score *score_stage; /* internal: its stage (TS_DERP_SCORES_MAX each) */
    size_t nscores;             /* internal */
    int derp_fresh;             /* internal: the next DERPMap starts from nothing (new session) */
    int filter_fresh;           /* internal: the next PacketFilter(s) starts from nothing */
} ts_netmap;

/* Allocate the peer, region and score buffers. 0, or -1 (out of memory, *m
 * left empty). */
int ts_netmap_init(ts_netmap *m);
void ts_netmap_free(ts_netmap *m);
/* Forget everything (for a new map session after reconnecting) except the
 * DERP map and the filters, which stay readable (see the contract above);
 * keeps buffers. */
void ts_netmap_reset(ts_netmap *m);

/* Apply one MapResponse JSON document. 0, or -1 with last_error set (the
 * caller then ends the session; see the contract above). */
int ts_netmap_apply(ts_netmap *m, const char *json, size_t len);

/* The peer with this ID, or NULL. Valid until the next successful apply. */
const ts_node *ts_netmap_peer(const ts_netmap *m, int64_t id);

/* Map messages on the long poll: each is a 4-byte little-endian length and
 * then that many bytes. A length of 0 delivers an empty message (which
 * ts_netmap_apply rejects as invalid JSON, as upstream's decoder would). A
 * length over TS_MAP_MSG_MAX makes feed return -1 before any allocation; any
 * error is sticky. The buffer grows as body bytes arrive, never beyond the
 * declared length, and is freed after a message over 64 KiB. */
typedef struct {
    void (*msg)(void *user, const char *data, size_t len);
    void *user;
    uint8_t hdr[4];
    size_t hdr_have;
    int in_body;
    size_t want;                /* declared length of the current message */
    size_t have;                /* body bytes received */
    uint8_t *buf;
    size_t cap;
    int failed;                 /* 0, or why feed failed (sticky): */
} ts_map_stream;

#define TS_MAP_STREAM_TOO_BIG 1  /* a declared length over TS_MAP_MSG_MAX */
#define TS_MAP_STREAM_NOMEM 2    /* the buffer could not grow */

void ts_map_stream_init(ts_map_stream *s, void (*msg)(void *, const char *, size_t), void *user);
/* 0, or -1 (length over TS_MAP_MSG_MAX, out of memory, or an earlier error;
 * s->failed says which).
 * Calls msg once per complete message, in order, from inside this call. The
 * data pointer is valid only during the callback, and msg must not call
 * ts_map_stream_feed or ts_map_stream_free on the same stream. */
int ts_map_stream_feed(ts_map_stream *s, const uint8_t *in, size_t n);
void ts_map_stream_free(ts_map_stream *s);

#endif
