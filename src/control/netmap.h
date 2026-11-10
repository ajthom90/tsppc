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
 * - Every other field (DERPMap, PacketFilter(s), DNSConfig, UserProfiles,
 *   SSHPolicy, ControlDialPlan, PopBrowserURL, ...) is skipped, of any type.
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
 * (it names the field or limit, never message content). */

#define TS_MAX_PEERS 256
#define TS_MAP_MSG_MAX 4194304          /* largest framed map message, bytes */
#define TS_NODE_NAME_MAX 255            /* longest Name kept, bytes */
#define TS_PING_URL_MAX 1023            /* longer PingRequest URLs are dropped */
#define TS_PING_TYPES_MAX 63            /* longer PingRequest Types are dropped */
#define TS_MAP_SLEEP_MAX_MS 300000u     /* Debug.SleepSeconds is clamped to 5 min */

typedef struct {
    int64_t id;                 /* ID */
    /* KeyExpiry in seconds since the Unix epoch; 0 when absent or the zero
     * time 0001-01-01T00:00:00Z (the key does not expire). int64_t rather
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
    /* From the Debug object of the last successfully applied non-KeepAlive
     * message; reset to 0 by every such message (a KeepAlive leaves them). */
    int have_exit;              /* Debug.Exit present */
    int exit_code;              /* its value */
    uint32_t sleep_ms;          /* Debug.SleepSeconds, clamped to TS_MAP_SLEEP_MAX_MS; 0 if absent,
                                 * non-positive or not finite */
    char last_error[128];
    ts_node *stage;             /* internal: second TS_MAX_PEERS buffer for all-or-nothing apply */
} ts_netmap;

/* Allocate both peer buffers. 0, or -1 (out of memory, *m left empty). */
int ts_netmap_init(ts_netmap *m);
void ts_netmap_free(ts_netmap *m);
/* Forget everything (for a new map session after reconnecting); keeps buffers. */
void ts_netmap_reset(ts_netmap *m);

/* Apply one MapResponse JSON document. 0, or -1 with last_error set. */
int ts_netmap_apply(ts_netmap *m, const char *json, size_t len);

/* The peer with this ID, or NULL. */
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
    int failed;
} ts_map_stream;

void ts_map_stream_init(ts_map_stream *s, void (*msg)(void *, const char *, size_t), void *user);
/* 0, or -1 (length over TS_MAP_MSG_MAX, out of memory, or an earlier error).
 * Calls msg once per complete message, in order, from inside this call. */
int ts_map_stream_feed(ts_map_stream *s, const uint8_t *in, size_t n);
void ts_map_stream_free(ts_map_stream *s);

#endif
