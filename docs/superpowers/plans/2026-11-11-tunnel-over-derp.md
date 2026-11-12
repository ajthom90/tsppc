# Tunnel over DERP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A real tailnet peer can ping the Mac's tailnet IP, and the Mac can ping it back, through WireGuard carried over Tailscale's DERP relays. The packet filter keeps out traffic that the tailnet's rules don't allow.

**Architecture:**
- Every protocol piece is plain, sans-I/O C, tested on the host:
  - the IPv4 packet parser and packet filter;
  - the network map's DERP map and filter fields;
  - the WireGuard handshake;
  - the WireGuard device (sessions, timers, AllowedIPs);
  - the DERP client;
  - the data plane that joins them.
- The daemon supplies the I/O:
  - the tun device (`/dev/tunN`), its address and the `100.64.0.0/10` route;
  - TCP, then TLS, to each relay;
  - relay latency probes;
  - the clock.
- The control session gains `NetInfo.PreferredDERP` and the "lite" map update that reports it.

**Tech Stack:** C (gnu99), BearSSL 0.6 (TLS), the existing crypto (X25519, ChaCha20-Poly1305, XChaCha20-Poly1305, NaCl box, BLAKE2s, HKDF), tuntaposx 20090913, GNU make 3.81, gcc-4.0 on the VMs, clang with sanitizers on the host, and Python 3 with `cryptography` on the host, used only to generate test vectors.

**Spec:** `docs/superpowers/specs/2026-11-10-tailscale-ppc-design.md`: milestone 4, plus the sections "WireGuard", "DERP", "Packet filter", "Tunnel" and "Interface and routes", Appendix A, and the anti-goals.

**Upstream reference:** `tailscale/tailscale` at `9476be94035afa8b896d1e07ee352741b35be7fb`, and `tailscale/wireguard-go` `v0.0.0-20261105205217-79ead109a81a`. The facts this plan relies on are in Appendix B below, with source files. If an implementer finds that upstream disagrees with Appendix B, upstream wins: they say so in their report, and the ruling goes in the ledger.

**Scope:** milestone 4 only. Left out:
- direct UDP paths, STUN and disco (milestone 8);
- launchd, the installer and kext installation (milestone 7). For this milestone the kext is loaded by hand with `tools/driver.sh`;
- sleep and network-change handling (milestone 7);
- `/etc/hosts` names (milestone 7);
- exit nodes (milestone 13);
- Tiger as a supported target (milestone 6). The Tiger VM is still used here, as the far end of a live test.

**Branch:** `tunnel` (already created from `main`; it holds the spec's release-scope commits). Push after each finished task. Merging needs the owner.

## Global Constraints

- **PowerPC flags:** `gcc-4.0 -std=gnu99 -arch ppc -isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4`. Binaries must run on stock 10.4.11 and 10.5.8.
- **Compiler warnings:** `-Wall -Wextra -Werror` on the host and with gcc-4.0.
- **Naming:** public symbols start with `ts_`. New `src/**.c` files are picked up by the Makefile automatically. New test files register in `tests/main.c`, and new fuzz targets are `tests/fuzz_<name>.c` defining `ts_fuzz_<name>()`.
- **Byte order:** use only the `src/core/bytes.h` helpers. Never overlay a struct on a packet.
  - WireGuard fields and nonce counters are little-endian.
  - DERP frame lengths, IPv4 and TCP/UDP fields, and TAI64N are big-endian.
- **Every network parser** (DERP frames, WireGuard messages, IPv4, filter rules, DERP map) gets host unit tests and a fuzz target under ASan and UBSan.
- **Bounded memory, set at compile time:**
  - 256 peers;
  - 8 relay connections;
  - 32 queued packets per relay connection;
  - 16 staged packets per peer;
  - a 512-entry flow table;
  - the filter limits in Task 1.
- **No key material** in logs, status, IPC replies or test fixtures. Wipe secrets with `ts_wipe` when they are dropped.
- **Fail closed:** no IP packet reaches the tun device unless:
  - the packet filter accepts it;
  - its inner IPv4 source is the sending peer's own address (AllowedIPs);
  - the peer is in the current network map, not expired, not jailed, and its WireGuard key matches the relay key it arrived from.
  - Until a filter has arrived, inbound IP packets are dropped. A filter that cannot be compiled, or that is over a limit, drops all inbound packets and shows a problem in status.
- **`TS_CAPVER` stays 150.** This milestone owns item 1 of `docs/capver-review.md` D5: the TSMP disco-key advertisement on every new keypair. It also owns item 2: drop received IP protocol 99.
- **Saved state files must still load.** The format is version 1, flags bits 0 to 3. The two VM nodes are approved, and losing them means the owner approves them again.
- **Test hooks** (`TSPPC_*` overrides) exist only with `-DTS_TEST_HOOKS`. `tools/check-release.sh` lists every new one and fails if a release binary contains it.
- **The repository is public:**
  - no peer names, tailnet names, real IPs, usernames or real keys in code, fixtures, commits or docs;
  - placeholders in recorded results;
  - never stage `spike/` or `.superpowers/`.

## Review Focus

1. **Unauthenticated relay input costs Curve25519 work.** A flood of handshake initiations, valid-looking or not, must not keep a G3 busy.
   - Initiations are checked for MAC1 before any Diffie-Hellman.
   - At most `TS_WG_HS_PER_SEC` (20) handshake messages a second, across all peers, reach a DH operation.
   - At most one initiation from the same peer is handled per 20 ms, as in wireguard-go.
   - Pinned by the Task 4 flood test.
2. **A peer is removed, expires, gets jailed, or changes its key while a session is live.** Its sessions are wiped at the next `ts_dp_set_netmap`. Packets under its old key are then dropped, and none of its staged packets are sent. Pinned by Task 7 tests.
3. **The map stream reconnects** (`ts_netmap_reset` and a fresh map). The last filter stays in force until a new one arrives. It never falls back to allow-all, and it is never lost to an empty map that only omits the field. Pinned by Task 7 tests.
4. **The daemon is killed with routes installed.** The next start deletes the stale `100.64.0.0/10` route before it adds its own. A clean stop deletes the route and takes the interface down. Pinned by Task 8 tests (the commands built) and the Task 10 live check.
5. **Relays come and go.**
   - A relay closes, never answers, or stops sending (no frame for 120 s).
   - Peers spread over more regions than there are connection slots.
   - Expected behaviour:
     - the oldest idle non-home connection is closed to make room;
     - redials back off from 1 s to 30 s with jitter;
     - queued packets are dropped, never held without a limit;
     - the home connection always comes back.
   - Pinned by Task 7 tests.

---

### Task 1: IPv4 packets and the packet filter

**Files:**
- Create: `src/filter/packet.{h,c}`, `src/filter/filter.{h,c}`.
- Tests: `tests/test_filter.c` (registered as `test_filter`), `tests/fuzz_filter.c` (rules JSON and packet parse).

**Interfaces:**
- Consumes `src/proto/json.h` and `src/core/bytes.h`.
- Produces the declarations below. Tasks 4, 7 and 8 rely on them.

```c
/* packet.h */
enum { TS_PKT_WHOLE, TS_PKT_FIRST_FRAG, TS_PKT_LATER_FRAG };
typedef struct {
    uint8_t proto;            /* IP protocol: 1 ICMP, 6 TCP, 17 UDP, 99 TSMP, ... */
    uint32_t src, dst;        /* host byte order */
    uint16_t sport, dport;    /* TCP/UDP; 0 otherwise */
    uint8_t tcp_flags;        /* TCP only */
    uint8_t icmp_type, icmp_code;
    int frag;                 /* TS_PKT_* */
    size_t len;               /* IPv4 total length (<= the buffer) */
} ts_pkt;
int ts_pkt_parse(ts_pkt *p, const uint8_t *b, size_t n);  /* 0, or -1: drop (Appendix B, E3 "Unknown") */
uint16_t ts_ip_checksum(const uint8_t *b, size_t n);
size_t ts_pkt_tsmp_disco(uint8_t out[53], uint32_t src, uint32_t dst, const uint8_t disco_pub[32]);

/* filter.h */
#define TS_FILTER_MAX_MATCHES 1024    /* rules after expansion; more: over limit */
#define TS_FILTER_MAX_SRCS 8192       /* source ranges, all rules */
#define TS_FILTER_MAX_DSTS 8192       /* destination (range, ports) entries, all rules */
#define TS_FLOW_MAX 512
typedef struct ts_filter ts_filter;   /* opaque, heap */
typedef struct { ... } ts_flows;      /* fixed LRU of TS_FLOW_MAX UDP tuples; caller storage */
/* Compile the concatenation of n FilterRule JSON arrays (named filters in
 * sorted-name order). local_ip is our tailnet IPv4 (Appendix B E3 "local4").
 * 0: ok. -1: a text is not a JSON array of objects (whole filter rejected).
 * -2: over a TS_FILTER_MAX_* limit. err says which, never echoing input. */
int ts_filter_compile(ts_filter **out, const char *const *json, const size_t *len, size_t n,
                      uint32_t local_ip, char *err, size_t errcap);
void ts_filter_free(ts_filter *f);
void ts_flows_init(ts_flows *fl);
/* f NULL means "no filter yet": drop everything that reaches the rules. */
int ts_filter_in(const ts_filter *f, ts_flows *fl, const ts_pkt *p, const char **why); /* 1 accept, 0 drop */
void ts_filter_out(ts_flows *fl, const ts_pkt *p);   /* records UDP flows; never blocks */
```

**Semantics:** they mirror upstream exactly (Appendix B, E1 to E4). Parsing:
- **Source forms:** `"*"`, a CIDR, a single IP, or an inclusive range `a-b`. All are stored as IPv4 `[lo, hi]` ranges. IPv6 entries are ignored.
- **`cap:` sources** never match.
- **A bad entry** is skipped, and the rest of the rule still applies.
- **Any `SrcBits` or `DstPorts[].Bits`** makes the whole filter match nothing.
- **`IPProto`:** empty means TCP, UDP, ICMP (and ICMPv6, ignored). Values outside 0 to 255 are dropped. A list left empty matches nothing.
- **`CapGrant`-only rules** match nothing.

Before the rules (`ts_pkt_parse` and `pre()`):
- under 20 bytes: drop;
- multicast destination: drop;
- link-local destination: drop;
- a later fragment at offset 10 blocks or more: accept;
- a destination that isn't `local_ip`: drop.

Then by protocol:
- **ICMP:** an echo reply (type 0, code 0, at least 8 bytes) or an error (types 3, 11, 12) is accepted. Anything else is accepted if some rule's source and destination match, whatever its protocol or ports.
- **TCP:** anything that isn't a SYN-without-ACK is accepted. A SYN needs a matching rule.
- **UDP:** a cached flow (`ts_filter_out` stores the reversed tuple) is accepted. Otherwise it needs a matching rule.
- **TSMP (99):** accepted. Task 7 drops it before the filter anyway.
- **Other protocols:** accepted only if the protocol is listed and a destination covers every port, 0 to 65535.

- [ ] **Step 1: Write the failing tests**
  - `test_pkt_parse`: covers
    - TCP, UDP and ICMP headers;
    - IHL over 5 with options;
    - a total length shorter than the buffer (trimmed) or longer (drop);
    - a version other than 4;
    - a first fragment too short for its L4 header (drop);
    - later fragments at offsets 9 and 10 blocks;
    - TSMP with MF set (drop).
  - `test_tsmp_disco`: `ts_pkt_tsmp_disco` gives exactly
    `45 00 00 35 00 00 00 00 40 63 <csum> <src> <dst> 61 <32 key bytes>`.
    The checksum must verify as `ts_ip_checksum(out, 20) == 0`.
  - `test_filter_rules`: one table-driven test with at least 40 rows. Each row is a rules JSON, a packet and the expected verdict. It covers:
    - every source form;
    - port edges (First, Last, First-1, Last+1);
    - default `IPProto`;
    - explicit `IPProto` 17 only;
    - TCP SYN versus SYN+ACK versus ACK;
    - ICMP echo request versus reply versus type 3;
    - `"*"` destination IP;
    - a destination other than local;
    - `SrcBits` present (all denied);
    - `cap:` source (denied);
    - an IPv6-only rule (ignored);
    - `[]` (all new flows denied);
    - a NULL filter (everything that reaches the rules denied).
  - `test_filter_flows`: an outbound UDP packet A:1000 to B:53 lets B:53 to A:1000 in, but not B:54. After 513 other flows, the first entry is gone (LRU). The flows survive a filter recompile, because the caller owns `ts_flows`.
  - `test_filter_limits`: generated JSON with `TS_FILTER_MAX_SRCS + 1` sources returns -2. Exactly the limit returns 0.

- [ ] **Step 2: Run them and see them fail.** `make test` fails to link the new symbols.
- [ ] **Step 3: Implement** in `src/filter/packet.c` and `src/filter/filter.c`. Stream the JSON with `src/proto/json.h`, as `netmap.c` does. Range lookups may be linear: the limits keep that bounded.
- [ ] **Step 4: Add `ts_fuzz_filter`.** It splits its input into a rules JSON and a packet, compiles, parses and runs both directions. `make fuzz` must run clean.
- [ ] **Step 5: Run the suites.** `make test asan ct-test` print `RESULT: all passed`.
- [ ] **Step 6: Commit and push.** "Add the IPv4 packet parser and the packet filter".

### Task 2: DERP map and packet filters in the network map

**Files:**
- Modify: `src/control/netmap.{h,c}`.
- Tests: `tests/test_netmap.c` and `tests/fuzz_netmap.c` (extend both).

**Interfaces:**
- Consumes Task 1's `ts_filter_compile`, but only in tests. The netmap stores the filter text and does not compile it.
- Produces these additions:

```c
#define TS_DERP_MAX_REGIONS 64        /* lowest IDs kept; more ignored */
#define TS_DERP_MAX_NODES 8           /* per region; more ignored */
#define TS_FILTER_NAMES_MAX 16
#define TS_FILTER_JSON_MAX 1048576    /* all named filters together; more: message rejected, last_limit */
typedef struct {
    char name[64];
    char host[254];                   /* TLS name: CertName if set, else HostName (<= 253) */
    uint32_t ipv4;                    /* host order */
    uint16_t port;                    /* DERPPort, 0 -> 443 */
} ts_derp_node;                       /* only usable nodes are kept (rules below) */
typedef struct {
    int id;
    char code[32];
    int avoid, no_home;               /* Avoid, NoMeasureNoHome */
    double score;                     /* HomeParams.RegionScore, 1.0 if absent */
    size_t nnodes;
    ts_derp_node nodes[TS_DERP_MAX_NODES];
} ts_derp_region;
/* in ts_netmap: */
ts_derp_region *regions; size_t nregions; uint32_t derp_gen;   /* gen bumps on every change */
char *filter_name[TS_FILTER_NAMES_MAX]; char *filter_json[TS_FILTER_NAMES_MAX];
size_t filter_len[TS_FILTER_NAMES_MAX]; size_t nfilters;       /* sorted by name */
int have_filter; uint32_t filter_gen;
```

**Rules:**
- **DERPMap** follows Appendix B, C:
  - a non-null `Regions` replaces every region;
  - `HomeParams`, or a null `RegionScore`, keeps the previous value;
  - a null region entry deletes that region.
- **A node is kept only if all of these hold:**
  - it is not `STUNOnly`;
  - it is not `InsecureForTests`;
  - it has a dotted-quad `IPv4` (empty or `"none"` means skip: no DNS for relays);
  - its host passes `ts_host_name_ok`;
  - its `CertName` is not `sha256-raw:`. If `CertName` is set, it replaces the TLS name.
- **A region with no usable node** is kept with `nnodes` 0. Peers may name it, and sends to them then fail.
- **Filters** follow Appendix B, E2:
  - a non-null `PacketFilter` sets the filter named `"base"`;
  - `PacketFilters` handles `"*": null` as "clear everything first", then sets or deletes each other key;
  - absent or null means unchanged;
  - `[]` is stored as a real, empty filter;
  - each stored text must be a JSON array (otherwise the message is rejected);
  - `have_filter` becomes 1 the first time any filter is set.
- **Reset and stage:** `ts_netmap_reset` keeps `regions` and the filters. Control resends them and the data plane keeps the last ones. The all-or-nothing apply covers the new fields: stage them as the peers are staged.

- [ ] **Step 1: Write the failing tests.**
  - `test_netmap_derpmap`: covers
    - a full map;
    - a replacement;
    - an inherited `HomeParams`;
    - a node with `"IPv4":"none"`, a STUNOnly node and a `sha256-raw:` CertName (all dropped);
    - `DERPPort` 0 → 443;
    - more than 64 regions (lowest 64 kept);
    - `derp_gen` bumping only on change.
  - `test_netmap_filters`: covers
    - `PacketFilter` then `PacketFilters` in one message (base first);
    - `"*": null`;
    - delete by null;
    - `[]` kept and `have_filter` set;
    - absent means unchanged;
    - a total over `TS_FILTER_JSON_MAX` rejects the message with `last_limit` set;
    - a non-array value rejects it;
    - reset keeps the filter.
  - A rejected message leaves `regions` and the filters byte-identical.
- [ ] **Step 2: Watch them fail.**
- [ ] **Step 3: Implement.** Keep `ts_node` free of padding. This task adds no field to it.
- [ ] **Step 4: Fuzz.** Extend the fuzz seeds with a DERPMap and filters. `make fuzz` must run clean.
- [ ] **Step 5: Run the suites.** `make test asan ct-test` pass.
- [ ] **Step 6: Commit and push.** "Keep the DERP map and packet filters from the map stream".

### Task 3: The WireGuard handshake, with independent vectors

**Files:**
- Create: `src/wg/handshake.{h,c}`, `tools/gen_wg_vectors.py`, `tests/wg_vectors.inc` (generated and committed).
- Tests: `tests/test_wg.c` (registered as `test_wg`), `tests/fuzz_wg_handshake.c`.

**Interfaces:**
- Consumes `ts_x25519`, `ts_aead_*`, `ts_xaead_*`, `ts_blake2s*`, `ts_hmac_blake2s`, `ts_hkdf2/3`.
- Produces:

```c
#define TS_WG_INIT_LEN 148
#define TS_WG_RESP_LEN 92
#define TS_WG_COOKIE_LEN 64
#define TS_WG_TRANSPORT_HDR 16
typedef struct { uint8_t priv[32], pub[32], mac1_key[32], cookie_key[32]; } ts_wg_static;
typedef struct { /* chaining key, hash, ephemeral, remote static, indices */ ... } ts_wg_hs;
void ts_wg_static_init(ts_wg_static *me, const uint8_t priv[32]);
void ts_wg_tai64n(uint8_t out[12], int64_t unix_sec, uint32_t nsec);   /* Appendix B, F */
/* Initiator. cookie may be NULL (mac2 zero). Returns 0, or -1 (bad peer key). */
int ts_wg_create_init(ts_wg_hs *hs, const ts_wg_static *me, const uint8_t peer_pub[32],
                      const uint8_t ss[32], uint32_t sender_index, const uint8_t eph_priv[32],
                      const uint8_t tai64n[12], const uint8_t *cookie16, uint8_t out[TS_WG_INIT_LEN]);
/* Responder, in two steps so unknown senders cost one DH:
 * 1) mac1 check, DH(e_i, s_r), decrypt the initiator's static -> peer_pub. */
int ts_wg_init_open_static(ts_wg_hs *hs, const ts_wg_static *me, const uint8_t in[TS_WG_INIT_LEN],
                           uint8_t peer_pub[32]);
/* 2) with that peer's precomputed ss = DH(s_r, s_i): decrypt the timestamp. */
int ts_wg_init_finish(ts_wg_hs *hs, const uint8_t ss[32], uint8_t tai64n_out[12], uint32_t *sender_index);
int ts_wg_create_resp(ts_wg_hs *hs, uint32_t sender_index, const uint8_t eph_priv[32],
                      const uint8_t *cookie16, uint8_t out[TS_WG_RESP_LEN]);
int ts_wg_consume_resp(ts_wg_hs *hs, const ts_wg_static *me,
                       const uint8_t in[TS_WG_RESP_LEN], uint32_t *sender_index);
/* Transport keys; wipes the handshake state. */
void ts_wg_derive(ts_wg_hs *hs, int initiator, uint8_t send[32], uint8_t recv[32]);
/* A cookie reply addressed to us: decrypts the 16-byte cookie. 0 or -1. */
int ts_wg_cookie_open(uint8_t cookie[16], const uint8_t peer_pub[32], const uint8_t last_mac1[16],
                      const uint8_t in[TS_WG_COOKIE_LEN]);
```

The construction, identifier, labels and sizes are in Appendix B, F. The preshared key is all zero: Tailscale uses none. Responders never send cookie replies, because there is no UDP. Initiators accept them and use the cookie for mac2 for 120 s.

- [ ] **Step 1: Write the vector generator.** `tools/gen_wg_vectors.py` is an independent implementation in Python. It uses `cryptography`'s X25519 and ChaCha20Poly1305, `hashlib.blake2s` and `hmac`, and imports nothing from this repo. From fixed keys, ephemerals, indices and timestamps, it emits `tests/wg_vectors.inc`, which holds:
  - the initiation;
  - the response;
  - both transport key pairs;
  - one transport message for a 3-byte payload at counter 0, padded to 16;
  - a cookie reply and the initiation that carries the resulting mac2.

  The keys are made-up test keys. Run it once: `python3 -I tools/gen_wg_vectors.py > tests/wg_vectors.inc`.
- [ ] **Step 2: Write the failing tests.**
  - `test_wg_vectors`: every message and key matches the `.inc` byte for byte, in both roles.
  - `test_wg_reject`: each of these is rejected:
    - a bad mac1;
    - one flipped bit in the encrypted static;
    - a bad timestamp tag;
    - a response to the wrong index;
    - a cookie reply with the wrong mac1.
  - `test_tai64n`: Unix second 0 gives `40 00 00 00 00 00 00 0a`, and the nanoseconds keep only bits 24 to 31.
- [ ] **Step 3: Implement** in `src/wg/handshake.c`.
- [ ] **Step 4: Fuzz.** `ts_fuzz_wg_handshake` feeds inputs to both open functions and the cookie open.
- [ ] **Step 5: Run the suites.** `make test asan ct-test` pass, and `make fuzz` runs clean.
- [ ] **Step 6: Commit and push.** "Add the WireGuard handshake with independent test vectors".

### Task 4: The WireGuard device

**Files:**
- Create: `src/wg/device.{h,c}`.
- Tests: `tests/test_wg_device.c` (registered), `tests/fuzz_wg_device.c`.

**Interfaces:**
- Consumes Task 3, `ts_pkt_parse` from Task 1, and `ts_aead_*`.
- Produces:

```c
#define TS_WG_STAGED_MAX 16
#define TS_WG_HS_PER_SEC 20
#define TS_WG_REPLAY_BITS 8128
typedef struct {
    void (*send)(void *user, const uint8_t peer[32], const uint8_t *msg, size_t n);
    void (*deliver)(void *user, const uint8_t peer[32], const uint8_t *ip, size_t n);
    int (*random)(void *user, uint8_t *out, size_t n);
    int64_t (*wall)(void *user, uint32_t *nsec);            /* Unix seconds, for TAI64N */
    size_t (*priority)(void *user, const uint8_t peer[32], uint8_t *out, size_t cap);
} ts_wg_io;
typedef struct {
    uint64_t rx_packets, tx_packets, rx_bytes, tx_bytes;
    int64_t last_handshake_ms;   /* -1 never */
    int have_session;
} ts_wg_stats;
typedef struct ts_wg_dev ts_wg_dev;
ts_wg_dev *ts_wg_new(const uint8_t node_priv[32], const ts_wg_io *io, void *user);
void ts_wg_free(ts_wg_dev *d);                  /* wipes everything */
int ts_wg_set_peer(ts_wg_dev *d, const uint8_t key[32], uint32_t ipv4);   /* add/update; 0/-1 (full) */
void ts_wg_remove_peer(ts_wg_dev *d, const uint8_t key[32]);
void ts_wg_send_packet(ts_wg_dev *d, const uint8_t key[32], const uint8_t *ip, size_t n);
void ts_wg_receive(ts_wg_dev *d, const uint8_t from[32], const uint8_t *msg, size_t n);
void ts_wg_tick(ts_wg_dev *d, int64_t now_ms);  /* call at least every 250 ms */
int ts_wg_peer_stats(const ts_wg_dev *d, const uint8_t key[32], ts_wg_stats *out);
```

**Behaviour:** this follows the WireGuard paper, section 6, with the constants in Appendix B, F.
- **Keypairs:** current, previous and next.
- **Initiator rekey:** after 120 s, or after `RekeyAfterMessages`.
- **Reject:** after 180 s, or after `RejectAfterMessages`.
- **Handshake retry:** every 5 s plus 0 to 333 ms of jitter, for up to 90 s, then the staged packets are dropped.
- **Passive keepalive:** 10 s after receiving with nothing sent.
- **Key material** is wiped after 540 s with no new handshake.
- **Replay window:** 8128 bits.
- **Padding:** plaintext is padded to a multiple of 16.
- **Handshake responses:** sent at once to the `from` key.

Additional rules:
- **Accepting a message:**
  - a message whose `from` isn't a configured peer is dropped;
  - an initiation whose decrypted static isn't `from` is dropped;
  - an initiation timestamp that isn't newer than the last accepted one from that peer is dropped;
  - more than one initiation per peer per 20 ms is dropped;
  - more than `TS_WG_HS_PER_SEC` DH-costing messages per second in total are dropped, counted before any DH.
- **Delivering:** a decrypted packet is delivered only if it is IPv4, `ts_pkt_parse` accepts it, and its `src` equals the peer's `ipv4`. Keepalives (empty) are never delivered.
- **Staging:** up to `TS_WG_STAGED_MAX` packets per peer are held while a handshake is pending. When the queue is full, the oldest is dropped.
- **Priority message** (D5, Appendix B, F/G): `io->priority` is called, and its packet sent first:
  - as initiator, right after consuming a response, followed by a keepalive;
  - as responder, on the first valid transport packet of a new keypair.
- **The static-static DH** is computed once per peer when it is set.

- [ ] **Step 1: Write the failing tests.** They use two devices joined by in-memory `send` callbacks and a fake clock.
  - `test_wgdev_ping`: A sends an IPv4 packet. The handshake runs, and B delivers the packet. The priority packet arrives before it.
  - `test_wgdev_allowedips`: B delivers nothing from A when the inner source isn't A's address. The same holds for non-IPv4 and junk.
  - `test_wgdev_timers`:
    - rekey at 120 s;
    - a session dead at 180 s with no traffic;
    - 18 retries, then the staged packets are dropped;
    - a passive keepalive at 10 s;
    - a wipe at 540 s.
  - `test_wgdev_replay`: a replayed transport message, a counter just behind the window, and out-of-order delivery inside the window.
  - `test_wgdev_flood`: 1000 initiations with random content, plus 100 valid-looking ones from an unknown key, cost at most 20 DH operations in one simulated second. Count them through a test-hook counter. A real peer's handshake still completes in the next second.
  - `test_wgdev_remove`: after `ts_wg_remove_peer`, A's old transport messages are dropped, and its staged packets are gone.
  - `test_wgdev_cookie`: a cookie reply from B is accepted, and A's next initiation carries a non-zero mac2.
- [ ] **Step 2: Watch them fail.**
- [ ] **Step 3: Implement.** Peers are looked up by key and by sender index. Linear search over 256 peers is acceptable.
- [ ] **Step 4: Fuzz.** `ts_fuzz_wg_device` feeds input as `ts_wg_receive` messages from a configured peer and from an unknown one, interleaved with ticks.
- [ ] **Step 5: Run the suites.** `make test asan ct-test` pass, and `make fuzz` runs clean.
- [ ] **Step 6: Commit and push.** "Add the WireGuard device".

### Task 5: The DERP client, and a live check against a real relay

**Files:**
- Create: `src/derp/derp.{h,c}`, `tools/derp_check.c` (built in `ppc-test` and in host `test`, like `keyfetch_check`).
- Tests: `tests/test_derp.c` (registered), `tests/fuzz_derp.c`.
- Modify: `Makefile` (the `derp_check` targets).

**Interfaces:**
- Consumes `ts_box_seal` and `ts_box_open`, `ts_x25519_public`, and the HTTP response-parsing pattern of `src/control/upgrade.c`.
- Produces:

```c
#define TS_DERP_MAX_PACKET 65536
#define TS_DERP_MAX_FRAME (1u << 20)          /* larger: fatal */
#define TS_DERP_READ_TIMEOUT_MS 120000        /* no frame this long: dead */
#define TS_DERP_HANDSHAKE_TIMEOUT_MS 30000    /* 101 + ServerKey + ServerInfo, after TLS */
typedef struct {
    void (*send)(void *user, const uint8_t *p, size_t n);   /* bytes for the TLS stream */
    void (*recv_packet)(void *user, const uint8_t src[32], const uint8_t *p, size_t n);
    void (*peer_gone)(void *user, const uint8_t key[32]);
    void (*health)(void *user, const char *text);           /* "" clears */
    void (*pong)(void *user, const uint8_t data[8]);
} ts_derp_io;
typedef struct { ... } ts_derp;
void ts_derp_init(ts_derp *d, const char *host, const uint8_t node_priv[32], int preferred,
                  const ts_derp_io *io, void *user);
void ts_derp_start(ts_derp *d, int64_t now_ms);       /* sends the upgrade request */
int ts_derp_feed(ts_derp *d, const uint8_t *in, size_t n, int64_t now_ms);   /* 0, -1 dead (d->err) */
int ts_derp_ready(const ts_derp *d);                  /* ServerInfo verified */
int ts_derp_send_packet(ts_derp *d, const uint8_t dst[32], const uint8_t *p, size_t n);   /* 0/-1 */
int ts_derp_ping(ts_derp *d, const uint8_t data[8]);
void ts_derp_note_preferred(ts_derp *d, int preferred);   /* sends only on change, once ready */
int ts_derp_tick(ts_derp *d, int64_t now_ms);         /* -1 on handshake or read timeout */
void ts_derp_free(ts_derp *d);                        /* wipes */
```

**Behaviour:** from Appendix B, A.
- **Upgrade request:** `GET /derp HTTP/1.1` with `Host`, `Upgrade: DERP` and `Connection: Upgrade`. There is no `Derp-Fast-Start`.
- **Response:** expect `101` with `Upgrade: DERP`.
- **Handshake:**
  1. Read ServerKey: at least 40 bytes, starting with the magic.
  2. Send ClientInfo: `{"version":2,"CanAckPings":true}`, boxed from the node key to the server key with a random nonce.
  3. Open ServerInfo with the same keys. TokenBucket fields are ignored.
- **When ready:** if preferred, send NotePreferred 1.
- **Server Pings** (exactly 8 bytes) get a Pong.
- **Ignored frames:** RecvPacket under 32 bytes, Restarting, KeepAlive and unknown frame types. Frames over the receive buffer are skipped as they stream past, up to `TS_DERP_MAX_FRAME`.
- **Health:** the text is passed on through `ts_ipc_clean` rules, at most 200 bytes.
- **Frame buffering:** only RecvPacket bodies of up to 32 + `TS_DERP_MAX_PACKET` bytes, and handshake frames, are buffered.

- [ ] **Step 1: Write the failing tests.** They use a fake server built in the test from the frame layout, holding its own key.
  - `test_derp_handshake`: the request bytes, then the ClientInfo box opens on the server side to exactly the JSON above.
  - `test_derp_frames`: covers
    - a RecvPacket delivered;
    - Ping answered;
    - PeerGone;
    - Health set and cleared;
    - an unknown type of 70000 bytes skipped across many feeds;
    - a 2 MiB length (fatal);
    - a ServerInfo forged with a wrong key (fatal);
    - a non-101 response (fatal);
    - a timeout at 120 s of silence, but not at 119 s.
  - `test_derp_send`: SendPacket framing, with 65536 accepted and 65537 refused; NotePreferred sent once.
- [ ] **Step 2: Watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Fuzz.** `ts_fuzz_derp` feeds a forged-key server stream to a client and checks that it never crashes.
- [ ] **Step 5: Write `tools/derp_check.c`.** Usage: `derp_check <host> <ipv4> [port]`. It:
  - uses a fresh random key, never a node key;
  - makes the TCP and `ts_tls` connection;
  - runs the DERP handshake;
  - sends `ts_derp_ping`, waits for the pong;
  - prints `derp-check: ok handshake <ms> ms, pong <ms> ms`, or the failure, and exits 0 or 1.
- [ ] **Step 6: Live checkpoint 1, on the Leopard VM.**
  - Build `make ppc-test`.
  - Run `build/ppc-test/derp_check <a DERP host> <its IPv4>`, with a node taken from the live map. Get the map with a one-off debug print in the test build, or take it from the published `https://login.tailscale.com/derpmap/default` on the host.
  - Expected: `ok`. Record the timings in the task report, not in the repo.
  - If TLS fails because the relay doesn't offer ChaCha20 with X25519, stop and report. That is a design-level blocker for the controller.
- [ ] **Step 7: Run the suites.** `make test asan ct-test` pass, and `make fuzz` runs clean.
- [ ] **Step 8: Commit and push.** "Add the DERP client and a live relay check tool".

### Task 6: Report the home relay to control

**Files:**
- Modify: `src/control/session.{h,c}`.
- Tests: `tests/test_session.c` (uses `tests/fake_control.inc`).

**Interfaces:**
- Produces:

```c
/* Our home DERP region (0 = none). Every register and map request from now on
 * carries Hostinfo with "NetInfo":{"PreferredDERP":region} (omitted when 0).
 * When it changes while the streaming map is live, the session sends one lite
 * map update on the same connection. 0, or -1 (region < 0). */
int ts_sess_set_preferred_derp(ts_sess *s, int region);
```

**The lite update** (Appendix B, D2):
- **Request:** `POST /machine/map` with
  `{"Version":150,"KeepAlive":true,"NodeKey":…,"DiscoKey":…,"Stream":false,"OmitPeers":true,"Hostinfo":{…,"NetInfo":{"PreferredDERP":N}}}`
  and the same headers as the stream.
- **Response:** status 200 means done. The body is consumed and discarded, with flow control kept moving.
- **Failure:** any other status, or a reset stream, retries after a 1 s delay that doubles to 30 s. It never ends the session. A 404 there is ignored, because the stream reports node removal.
- **One at a time:** only one update is in flight. A change during one is sent after it finishes.
- **Reconnects** carry the value in the new stream request, so a pending update is dropped.
- **Splicing:** NetInfo goes into the stored Hostinfo object before its closing brace. The stored Hostinfo is not re-parsed.

- [ ] **Step 1: Write the failing tests.** `test_sess_netinfo`, against the fake control:
  - the stream request carries NetInfo after `ts_sess_set_preferred_derp(s, 7)`;
  - a change while RUNNING produces exactly one lite request with those fields;
  - a 500 retries after 1 s, then 2 s;
  - a 200 with a body stops retrying, and the stream still works;
  - a change during an in-flight update sends a second one afterwards;
  - region 0 omits NetInfo.
- [ ] **Step 2: Watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites.** `make test asan ct-test` pass, and `make fuzz` runs clean (`fuzz_session` still covers the session).
- [ ] **Step 5: Commit and push.** "Report the home relay to control".

### Task 7: The data plane

**Files:**
- Create: `src/data/dataplane.{h,c}`.
- Tests: `tests/test_dataplane.c` (registered).

**Interfaces:**
- Consumes Tasks 1, 2, 4 and 5.
- Produces:

```c
#define TS_DP_MAX_CONNS 8
#define TS_DP_IDLE_CLOSE_MS 60000          /* non-home connection idle (last written) */
#define TS_DP_QUEUE_PER_CONN 32            /* packets queued while a relay connects */
#define TS_DP_REDIAL_MIN_MS 1000
#define TS_DP_REDIAL_MAX_MS 30000
typedef struct {
    /* Open a stream to node (TCP to node->ipv4:port, then TLS for node->host). Later
     * ts_dp_conn_up / ts_dp_conn_down report on slot. 0 started, -1 failed now. */
    int (*dial)(void *user, int slot, const ts_derp_node *node);
    void (*conn_send)(void *user, int slot, const uint8_t *p, size_t n);
    void (*conn_close)(void *user, int slot);
    void (*tun_write)(void *user, const uint8_t *ip, size_t n);
    int (*random)(void *user, uint8_t *out, size_t n);
    int64_t (*wall)(void *user, uint32_t *nsec);
} ts_dp_io;
typedef struct ts_dp ts_dp;
ts_dp *ts_dp_new(const ts_dp_io *io, void *user);
void ts_dp_free(ts_dp *dp);
/* Start with our keys and address (wipes any earlier run). */
int ts_dp_start(ts_dp *dp, const uint8_t node_priv[32], const uint8_t disco_pub[32], uint32_t self_ip);
void ts_dp_stop(ts_dp *dp);                       /* closes every connection, wipes sessions */
int ts_dp_running(const ts_dp *dp);
/* Copy what the data plane needs from the map: peers (node key, ipv4, home_derp,
 * wireguard_only, jailed, expired, online), and the DERP map and filters when
 * their gens changed. Never keeps a pointer into m. */
void ts_dp_set_netmap(ts_dp *dp, const ts_netmap *m);
void ts_dp_set_home(ts_dp *dp, int region);
void ts_dp_from_tun(ts_dp *dp, const uint8_t *ip, size_t n);
void ts_dp_conn_up(ts_dp *dp, int slot);
void ts_dp_conn_recv(ts_dp *dp, int slot, const uint8_t *p, size_t n);
void ts_dp_conn_down(ts_dp *dp, int slot, const char *why);
void ts_dp_tick(ts_dp *dp, int64_t now_ms);
/* Pick a home region from probe latencies (ms, -1 unknown), per Appendix B, B4. */
int ts_dp_pick_home(const ts_derp_region *r, size_t n, const int *lat_ms, int current,
                    uint32_t rand32);
/* Status: home region and its connection state, filter state, per-peer stats. */
typedef struct {
    int home; int home_up; const char *filter;    /* "none", "ok", "too large", "invalid" */
    char problem[200];
} ts_dp_status;
void ts_dp_get_status(const ts_dp *dp, ts_dp_status *st);
int ts_dp_peer_status(const ts_dp *dp, uint32_t ipv4, ts_wg_stats *st, int *region);
```

**Rules:**
- **Outbound path:**
  1. A tun packet is parsed (non-IPv4 is dropped).
  2. The destination is looked up among the peers by `ipv4` (no peer: drop).
  3. `ts_filter_out` records UDP flows.
  4. `ts_wg_send_packet` encrypts or stages it.
- **Relay choice for a send to a peer** (Appendix B, B1):
  - the connection for the peer's `home_derp` region if it is open;
  - otherwise the connection we last received that peer on, if it is still open;
  - otherwise dial the peer's home region.
  - If all `TS_DP_MAX_CONNS` slots are used, close the least recently written non-home connection.
  - Packets wait in that connection's queue. When the queue is full, new packets are dropped.
- **Inbound path:**
  1. Relay packets that start with the disco magic (at least 38 bytes) are dropped.
  2. An unknown source key is dropped.
  3. `ts_wg_receive` decrypts.
  4. In `deliver`: drop jailed peers; drop protocol 99; then `ts_filter_in`; then `tun_write`.
- **Priority callback:** returns `ts_pkt_tsmp_disco` when `self_ip` is set, the disco key is non-zero, and the peer has an IPv4 address and isn't WireGuard-only. Otherwise it returns 0.
- **Map changes:**
  - **Peers:**
    - A peer that disappears, has `expired` or `jailed` set, or changes its node key is removed from the device at once (`ts_wg_remove_peer`).
    - A peer with a new key is added under the new key.
    - Peers that are `wireguard_only` or have no `ipv4` are not configured.
  - **Filter:**
    - The filter is recompiled when `filter_gen` changes.
    - Compile errors and over-limit filters install a drop-all filter, with the reason in `ts_dp_status.filter` and `problem`.
    - Before the first filter, `ts_filter_in(NULL, …)` drops inbound.
    - `ts_flows` lives in the data plane and survives recompiles.
- **Home connection:**
  - It is always kept open, with `preferred` set.
  - On a home change, the old home sends NotePreferred 0 and the new one NotePreferred 1.
  - Non-home connections close after `TS_DP_IDLE_CLOSE_MS` with no writes.
  - A connection that goes down redials, but only the home connection, or one with queued packets, after a delay that starts at `TS_DP_REDIAL_MIN_MS` and doubles to `TS_DP_REDIAL_MAX_MS`, minus up to 25 percent jitter.
- **Home pick** (`ts_dp_pick_home`):
  - Eligible regions have `nnodes > 0`, `!avoid` and `!no_home`.
  - The score is `lat * score`, and the lowest wins.
  - Keep `current` if it is eligible and either `cur - best < 10 ms` or `best > cur * 2 / 3`.
  - With no latencies, keep `current` if it is set. Otherwise pick `regions[rand32 % n]` from all regions (upstream's fallback).

- [ ] **Step 1: Write the failing tests.** Two data planes, A and B, share an in-test fake relay that routes SendPacket by destination key between slots. The test plays the relay protocol with Task 5's frame layout.
  - `test_dp_ping`: a filter that allows ICMP from A to B. An echo request from A's tun appears on B's tun, and B's echo reply appears on A's tun.
  - `test_dp_filter`:
    - a TCP SYN to a denied port never reaches B's tun, while one to an allowed port does;
    - with no filter yet, nothing reaches B's tun;
    - an oversized filter means drop-all, with `filter` set to `"too large"`;
    - a netmap reset followed by a map without filter fields keeps the old filter.
  - `test_dp_spoof`: a packet B decrypts from A with an inner source of C's IP is not written.
  - `test_dp_disco_and_unknown`: covers
    - disco magic over the relay is dropped before WireGuard;
    - a source key not in the map is dropped;
    - protocol 99 inside the tunnel is dropped;
    - the TSMP advertisement is the first packet on each new keypair.
  - `test_dp_peer_change`: when A's key changes in B's map, B drops packets under the old key. Removing A wipes its sessions.
  - `test_dp_conns`:
    - peers in 10 regions use at most 8 slots, closing the least recently written;
    - idle close happens at 60 s, not 59 s;
    - a home connection drop redials at 1 s, then 2 s, then 4 s with jitter;
    - queue overflow drops.
  - `test_dp_pick_home`: the stickiness edges (9 versus 10 ms, and the 2/3 rule), `RegionScore`, avoid/no_home, and the fallback.
- [ ] **Step 2: Watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites.** `make test asan ct-test` pass, and `make fuzz` runs clean.
- [ ] **Step 5: Commit and push.** "Add the data plane".

### Task 8: The tun device, routes and the daemon

**Files:**
- Create: `src/platform/tun.{h,c}`, `src/daemon/dataplane_io.c` (the daemon's data-plane I/O; `main.c` calls into it).
- Modify: `src/daemon/main.c`, `tools/check-release.sh`, `tools/vm-test.sh` (if new binaries need copying).
- Tests: `tests/test_tun.c` (command lines only), `tests/test_ipc.c` (daemon tests with hooks).

**Interfaces:**
- Produces:

```c
#define TS_TUN_MAX_UNIT 15
#define TS_TUN_MTU 1280
#define TS_TAILNET_NET "100.64.0.0/10"
int ts_tun_open(char ifname[16]);     /* first /dev/tunN that opens; non-blocking fd, or -1 (errno) */
/* argv for the commands, built into buf; tested on the host. */
int ts_tun_cmd_ifconfig_up(const char **argv, size_t max, char *buf, size_t cap, const char *ifname, uint32_t ip);
int ts_tun_cmd_route_add(const char **argv, size_t max, char *buf, size_t cap, const char *ifname);
int ts_tun_cmd_route_delete(const char **argv, size_t max, char *buf, size_t cap);
int ts_tun_cmd_ifconfig_down(const char **argv, size_t max, char *buf, size_t cap, const char *ifname, uint32_t ip);
int ts_run(const char *const *argv);  /* fork+execv (no shell, no PATH), stdio to /dev/null, 10 s limit */
```

The commands, exactly:
- **Up:** `/sbin/ifconfig tunN inet A A netmask 255.255.255.255 mtu 1280 up`.
- **Route add:** `/sbin/route -n add -net 100.64.0.0/10 -interface tunN`.
- **Route delete:** `/sbin/route -n delete -net 100.64.0.0/10`.
- **Down:** `/sbin/ifconfig tunN inet A delete`, then `/sbin/ifconfig tunN down`.

**Daemon lifecycle:**
- **At start:** before anything else, run the route delete quietly, to clean up after a crash.
- **The data plane runs** (tun open, address set, route added, `ts_dp_start`) when all of these hold:
  - the session is RUNNING;
  - the self node has an IPv4 address;
  - the node is wanted up.
- **It keeps running** through CONNECTING and BACKOFF.
- **It stops** (`ts_dp_stop`, route delete, down, close tun) on:
  - IDLE, NEED_LOGIN, AWAIT_APPROVAL or FAILED;
  - a node key or self IP change (stop, then start);
  - SIGTERM or SIGINT.
- **If `/dev/tun*` won't open:**
  - the data plane still runs relays and home selection;
  - tun writes are dropped;
  - status shows the problem `tunnel driver not loaded`;
  - opening is retried every 30 s.
- **After each map change**, call `ts_dp_set_netmap`.

**Relay I/O:**
- **Connections:** each slot is a non-blocking `ts_tcp_start` to the node's IPv4 and port, then `ts_tls_start` with the node's TLS name. Bytes after the handshake go to `ts_dp_conn_recv`.
- **Timeouts:** 60 s for the TCP connect plus TLS. The DERP handshake timeout is `ts_derp`'s own.
- **The `select()` loop** covers the tun fd, relay fds and probe fds. Reads per turn are bounded, as with the control connection. Tun reads are 2048-byte buffers, at most 64 packets per turn.

**Home probes:**
- **What:** a TCP connect to the first node of every eligible region, at most 8 at once, with a 5 s limit each.
- **When:**
  - when the data plane starts;
  - every 30 minutes;
  - after the home connection fails 3 times in a row.
- **Result:** `ts_dp_pick_home`, then `ts_dp_set_home` and `ts_sess_set_preferred_derp`.

**Test hooks** (with `-DTS_TEST_HOOKS` only; add them to `check-release.sh`):
- `TSPPC_NO_TUN=1`: no tun and no commands. Tun writes go to a counter.
- `TSPPC_DERP_PLAIN=1`: relay connections skip TLS, for the fake relay in daemon tests.

- [ ] **Step 1: Write the failing tests.**
  - `test_tun_cmds`: the exact argv of each command above, for `tun3` and 100.101.102.103. Bad inputs are refused: an ifname over 15 bytes, or one that isn't `tun` followed by digits.
  - In `tests/test_ipc.c`, a daemon run with the fake control and `TSPPC_NO_TUN=1`:
    - the map carries a DERPMap that points at an in-test fake relay on 127.0.0.1 (`TSPPC_DERP_PLAIN=1`);
    - status then shows the home region connected;
    - control receives a lite update with that region;
    - `tsppc down` stops the data plane.
- [ ] **Step 2: Watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites and the release check.** `make test asan ct-test` pass, `make fuzz` runs clean, and `make release` with `check-release.sh` passes.
- [ ] **Step 5: Live checkpoint 2, on the Leopard VM**, with no kext loaded yet.
  1. Run `tools/vm-test.sh leopard`.
  2. Install the release build into the run directory, as in milestone 12, and restart `tsppcd` on the existing `/var/db/tsppc`.
  3. Expected:
     - status shows the problem `tunnel driver not loaded`;
     - a home region connected;
     - within a minute, the self node in the map shows `HomeDERP` equal to that region. Read it with `tsppc status` (Task 9 shows it) or a debug log line.
  4. Record the result in the task report.
- [ ] **Step 6: Commit and push.** "Run the tunnel from the daemon".

### Task 9: Status for the tunnel

**Files:**
- Modify: `src/daemon/ipc.h` (key docs), `src/daemon/main.c` (`build_status`), `src/cli/main.c`.
- Tests: `tests/test_ipc.c`, `tests/test_ipc_reply.c`.

**New reply keys:** the existing `peer` lines don't change, because the menu bar parses them.
- `tunnel <ifname|off> [problem text]`.
- `relay <region-id> <code> <connected|connecting|down>`: the home relay.
- `filter <ok|none|too-large|invalid>`.
- `path <a.b.c.d> <relay-code|-> <rx-packets> <tx-packets> <handshake-age-s|->`: one per peer with a configured WireGuard peer.

All of them are left out while wanted is down.

**CLI:** `tsppc status` prints:
- a `relay:` line;
- a `tunnel:` line;
- a `filter:` line;
- on each peer line, `relay <code>` plus packet counts when a session exists.

The menu bar shows none of this yet.

- [ ] **Step 1: Write the failing tests.**
  - The daemon reply contains the new keys, with values from a fake data-plane status.
  - `ts_reply_parse` ignores them, and the menu model is unchanged.
  - The CLI output contains the new lines.
- [ ] **Step 2: Watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites.** `make test asan ct-test` pass.
- [ ] **Step 5: Commit and push.** "Show the tunnel in status".

### Task 10: Live acceptance and the record

**Files:**
- Create: `docs/tunnel-check.md`.
- Modify: `docs/known-limits.md`, and `docs/capver-review.md` (D5: item 1 done in milestone 4).

- [ ] **Step 1: Build and install.**
  - Run `tools/vm-test.sh leopard`. It must pass every check plus check-release, check-ct and check-app.
  - Install the release `tsppcd` and `tsppc` on both VMs as in milestone 12.
  - Load the kext on both with `sudo tools/driver.sh load`, using `build/driver/tun.kext` built on each VM.
  - Restart the daemons on the existing state. Both must be RUNNING with the same nodes and no login.
- [ ] **Step 2: The tunnel comes up.** On each VM:
  - `tsppc status` shows `tunnel: tunN`, `relay: … connected` and `filter: ok`;
  - `ifconfig tunN` shows the tailnet IP and MTU 1280;
  - `netstat -rn` shows `100.64/10` on `tunN`.
- [ ] **Step 3: Pings in both directions, through tsppc.**
  - Leopard runs `ping -c 5 <Tiger's tailnet IP>`, and Tiger pings Leopard.
  - Both must succeed. Proof that tsppc carried them:
    - the `path` counters for the other VM rise on both sides;
    - `tcpdump -n -i tunN icmp` on the receiving VM shows the requests arriving on the tunnel;
    - the receiving VM can only get them through its own tsppc, because UTM's NAT doesn't deliver inbound traffic to a guest.
  - Also ask the owner to ping the Leopard VM's tailnet IP from one of their machines, or use the host Mac's own client if it is online. It must succeed, with the counter rising.
- [ ] **Step 4: The filter blocks.**
  - From `tsppc status` and the daemon log, summarise the live filter: how many rules, and whether any port from the test peers to the VM is denied. Record no rule contents.
  - If something is denied, connect to that port from a peer. tcpdump on `tunN` must show no SYN for it, and a connection to an allowed port must show its SYN.
  - If the tailnet allows everything, ask the owner whether to add a temporary rule, as the spec says. Without one, record that the live denial check couldn't run, and point to the Task 1 and Task 7 tests.
- [ ] **Step 5: Stop and crash.**
  - SIGTERM: the route and the interface address are gone, and `ping` to a peer no longer goes through `tunN`.
  - Start, then `kill -9`, then start again: the stale route is removed, then reinstalled, and pings work again.
  - `ps -o rss` of `tsppcd` while pinging: record the value. It must stay under 16 MB.
- [ ] **Step 6: Write the record.**
  - **`docs/tunnel-check.md`:** the build commit, SHA-1s, machines, commands, results and timings, with placeholders for every name and IP.
  - **`docs/known-limits.md`:**
    - home relay chosen by TCP connect time, not HTTPS latency;
    - DERP only (no direct paths until milestone 8);
    - the hybrid post-quantum handshake in Tailscale's WireGuard fork (Appendix B, F) is not implemented, and a peer that requires it will not connect;
    - TokenBucket hints from relays are ignored.
  - **`docs/capver-review.md`:** mark D5 item 1 as done.
- [ ] **Step 7: Commit and push.** "Record the tunnel check".

---

## Appendix B: upstream facts used here

Read from the upstream reference named above. The full notes, with quoted source lines, were collected for this plan. These are the parts the tasks depend on.

**A. DERP** (`derp/derp.go`, `derp/derp_client.go`, `derp/derphttp/derphttp_client.go`, `derp/derpserver/`):
- **Frame:** 1 type byte, then a BE32 length (header not included). Protocol version 2. The magic is `44 45 52 50 f0 9f 94 91`.
- **Frame types:**

  | Frame | Type | Payload |
  |---|---|---|
  | ServerKey | 0x01 | magic + 32-byte key (+ ignored bytes) |
  | ClientInfo | 0x02 | 32-byte key + 24-byte nonce + box |
  | ServerInfo | 0x03 | nonce + box |
  | SendPacket | 0x04 | destination key + packet |
  | RecvPacket | 0x05 | source key + packet |
  | KeepAlive | 0x06 | none |
  | NotePreferred | 0x07 | 1 byte |
  | PeerGone | 0x08 | key + optional reason byte |
  | PeerPresent | 0x09 | |
  | ForwardPacket | 0x0a | |
  | WatchConns | 0x10 | |
  | ClosePeer | 0x11 | |
  | Ping | 0x12 | 8 bytes |
  | Pong | 0x13 | 8 bytes |
  | Health | 0x14 | text; empty clears |
  | Restarting | 0x15 | 2×BE32 ms |

- **Packets:** a packet is at most 64 KiB. A frame over 1 MiB is fatal to the client.
- **Liveness:** the server sends a keepalive every 60 to 65 s, and the client gives up after 120 s with no frame.
- **Restarting** has no sender or consumer upstream, so ignoring it matches upstream.
- **ClientInfo** is `{"version":2,"CanAckPings":true}`. The box is NaCl `crypto_box` from the node private key to the server key, with a random nonce placed before it. The DERP identity is the node key.
- **The 101 response** carries `Upgrade: DERP`, `Derp-Version: 2` and `Derp-Public-Key`. ServerKey is always sent, even with fast start, which this client doesn't use.
- **NotePreferred(true)** is sent on connect to the home relay, and updated on a home change.

**B. Relay use in magicsock:**
- **Sends** go to the peer's home region connection. Failing that, they go to the connection the peer was last heard on. Failing that, the client dials the peer's home region. Our own home is never used as a substitute.
- **Non-home connections** close after 60 s with no writes. Upstream sets no limit on the number of connections.
- **Inbound relay packets** that start with `54 53 f0 9f 92 ac` and are at least 38 bytes long are disco. Packets from an unknown source key are dropped.
- **Home choice without UDP** times HTTPS latency. Stickiness:
  - keep the old region if the difference is under 10 ms, or the best is more than 2/3 of the old region's time;
  - with no data, keep the old home, or pick at random over all regions.
  - Flags: `NoMeasureNoHome` means never home; `Avoid` means skipped; STUNOnly nodes are skipped; nodes are tried in order.

**C. DERPMap** (`tailcfg/derpmap.go`, `control/controlclient/map.go`):
- **Shape:**
  - `Regions` is an object keyed by decimal ID.
  - A region has `RegionID`, `RegionCode`, `RegionName`, `Avoid`, `NoMeasureNoHome` and `Nodes`.
  - A node has `Name`, `RegionID`, `HostName`, `CertName`, `IPv4`, `IPv6`, `STUNPort`, `STUNOnly`, `DERPPort`, `InsecureForTests` and `CanPort80`.
  - `HomeParams.RegionScore` is a map from ID to a float.
- **Updates:** a non-null `Regions` replaces all regions, while a null `HomeParams` or `RegionScore` is inherited.

**D. NetInfo:**
- **Where it sits:** `Hostinfo.NetInfo.PreferredDERP`, where 0 means unknown.
- **Every MapRequest** carries the current Hostinfo with NetInfo.
- **A change** is sent as a separate `/machine/map` POST with `Stream:false` and `OmitPeers:true`, while the stream stays open. Only its status counts, and the body is discarded.

**E. Filter** (`wgengine/filter/`, `tailcfg`, `map.go`, `net/tstun/wrap.go`):
- **Rule fields:** `SrcIPs`, `SrcBits` (fatal), `DstPorts[{IP, Bits (fatal), Ports{First, Last}}]`, `IPProto` and `CapGrant`.
- **Source forms:** `*`, a CIDR, a range `a-b`, a single IP, or `cap:`.
- **`PacketFilter`** sets `"base"`. **`PacketFilters`** handles `"*":null` as clear, a null value as delete, and others as set. Named filters are combined in sorted name order. `[]` blocks all new inbound.
- **Inbound handling:** the per-protocol rules are as listed in Task 1. TSMP is handled before the filter.
- **Outbound** is never blocked and records reversed UDP tuples in a 512-entry LRU.
- **With no filter**, everything is dropped.

**F. WireGuard** (`tailscale/wireguard-go`):
- **Timers and limits:** RekeyAfterTime 120 s, RejectAfterTime 180 s, RekeyAttemptTime 90 s, RekeyTimeout 5 s plus up to 334 ms of jitter, KeepaliveTimeout 10 s, and CookieRefreshTime 120 s.
- **Initiations** are rate-limited to one per 20 ms per peer.
- **Counters:** RekeyAfterMessages is 2^60, and RejectAfterMessages is 2^64 − 2^13 − 1. The replay window is 8128 bits, and padding is to a multiple of 16.
- **Strings:** the construction is `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, the identifier `WireGuard v1 zx2c4 Jason@zx2c4.com`, and the labels `mac1----` and `cookie--`.
- **TAI64N:** 8-byte BE (`0x400000000000000a` + Unix seconds), then 4-byte BE nanoseconds with the low 24 bits cleared.
- **Priority message:** sent as initiator right after the response (followed by a keepalive), and as responder on the first transport packet of a new keypair.
- **Hybrid handshake:** the fork also has a hybrid ML-KEM handshake. Nothing turns it on at this commit, but a responder drops initiations whose hybrid flag doesn't match.

**G. TSMP disco advertisement:** a 53-byte IPv4 packet: `45 00 0035 0000 0000 40 63 <checksum> <src> <dst>`, then `'a'` and the 32-byte disco public key. The source is our tailnet IPv4 and the destination is the peer's first address.
