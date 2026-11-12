#ifndef TS_DERP_DERP_H
#define TS_DERP_DERP_H

#include <stddef.h>
#include <stdint.h>

#include "../control/upgrade.h"

/* Client for one DERP relay connection. Sans-I/O: the caller runs TCP and TLS
 * (ServerName = the relay's host name), passes received bytes to
 * ts_derp_feed, and writes what the send callback produces to the TLS stream.
 *
 * Protocol (tailscale derp/derp.go, derp_client.go, derphttp_client.go):
 *   - "GET /derp HTTP/1.1" with Host, Upgrade: DERP, Connection: Upgrade (no
 *     Derp-Fast-Start); the reply must be 101 with Upgrade: DERP. Bytes after
 *     its blank line are frames.
 *   - Frames: type byte, BE32 length, body. The first must be ServerKey
 *     (magic "DERP\xf0\x9f\x94\x91", 32-byte key; 40 to 1024 bytes).
 *   - We send ClientInfo: our public key, a random 24-byte nonce and a NaCl
 *     box (node key to relay key) of {"version":2,"CanAckPings":true}.
 *   - ServerInfo (nonce, box from the relay key to the node key, JSON) must
 *     be the next frame (any other is fatal: nothing is acted on before the
 *     relay is verified), open and hold valid JSON; then the connection is
 *     ready. TokenBucket
 *     fields are ignored. Any later ServerInfo is checked the same way.
 *   - Ready and preferred: NotePreferred(1).
 *   - Ping (at least 8 bytes) is answered with a Pong of its first 8 bytes.
 *     RecvPacket under 32 bytes or over 32 + TS_DERP_MAX_PACKET, Restarting,
 *     KeepAlive, PeerPresent and unknown types are skipped. Only RecvPacket
 *     bodies and handshake frames are buffered whole; Ping, Pong, PeerGone and
 *     Health keep their first 8, 8, 32 and 200 bytes; the rest of any frame is
 *     discarded as it streams past. A length over TS_DERP_MAX_FRAME is fatal.
 *   - Health text goes through ts_ipc_clean (no newline), at most 200 bytes;
 *     "" clears.
 *
 * Callbacks run inside ts_derp_feed (and send inside the other calls). The
 * pointers they get are valid only during the call. A callback may call
 * ts_derp_send_packet, ts_derp_ping and ts_derp_note_preferred, but not
 * ts_derp_free. Every send call carries whole frames (or the whole request). */

#define TS_DERP_MAX_PACKET 65536
#define TS_DERP_MAX_FRAME (1u << 20)          /* larger: fatal */
#define TS_DERP_READ_TIMEOUT_MS 120000        /* no frame this long: dead */
#define TS_DERP_HANDSHAKE_TIMEOUT_MS 30000    /* 101 + ServerKey + ServerInfo, after TLS */
#define TS_DERP_HOST_MAX 255                  /* host (may carry ":port") */
#define TS_DERP_HEALTH_MAX 200

/* Frame types (derp/derp.go). */
#define TS_DERP_SERVER_KEY 0x01
#define TS_DERP_CLIENT_INFO 0x02
#define TS_DERP_SERVER_INFO 0x03
#define TS_DERP_SEND_PACKET 0x04
#define TS_DERP_RECV_PACKET 0x05
#define TS_DERP_KEEP_ALIVE 0x06
#define TS_DERP_NOTE_PREFERRED 0x07
#define TS_DERP_PEER_GONE 0x08
#define TS_DERP_PING 0x12
#define TS_DERP_PONG 0x13
#define TS_DERP_HEALTH 0x14
#define TS_DERP_RESTARTING 0x15

typedef struct {
    void (*send)(void *user, const uint8_t *p, size_t n);   /* bytes for the TLS stream */
    void (*recv_packet)(void *user, const uint8_t src[32], const uint8_t *p, size_t n);
    void (*peer_gone)(void *user, const uint8_t key[32]);
    void (*health)(void *user, const char *text);           /* "" clears */
    void (*pong)(void *user, const uint8_t data[8]);
} ts_derp_io;

/* About 140 KiB: do not put it on a small stack. */
typedef struct {
    const ts_derp_io *io;
    void *user;
    const char *err;          /* why the connection died (no key material) */
    int state;
    int preferred;            /* wanted */
    int sent_preferred;       /* what the relay was last told */
    int64_t start_ms;         /* ts_derp_start */
    int64_t last_frame_ms;    /* last complete frame (or start) */
    char host[TS_DERP_HOST_MAX + 1];
    uint8_t priv[32], pub[32], server[32], shared[32];
    /* The 101 response, until its blank line. */
    char hdr[TS_UPGRADE_HEADER_MAX];
    size_t hdr_len;
    /* The frame being read. */
    uint8_t fh[5];
    size_t fh_len;
    uint32_t flen, fgot, keep;
    uint8_t rbuf[32 + TS_DERP_MAX_PACKET];
    uint8_t wbuf[5 + 32 + TS_DERP_MAX_PACKET];
} ts_derp;

/* host: 1 to TS_DERP_HOST_MAX bytes from '!'..'~' (else the connection is
 * dead at once, with d->err set). node_priv is copied. */
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

#endif
