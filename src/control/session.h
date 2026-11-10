#ifndef TS_CONTROL_SESSION_H
#define TS_CONTROL_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "../proto/h2.h"
#include "../state/store.h"
#include "netmap.h"
#include "noise.h"
#include "upgrade.h"

/* The control session: one connection to the control server and the login and
 * map exchanges on it, as a sans-I/O state machine.
 *
 * The caller (the daemon) owns sockets, TLS, the clock and persistence, and
 * reaches them through ts_sess_io. Per connection the session runs, on the
 * plain byte stream io->connect provides: the HTTP upgrade to the control
 * protocol, the Noise handshake, the optional early payload, then HTTP/2 over
 * Noise records. On it, POST /machine/register logs in (with a held Followup
 * while the operator visits the login URL), then POST /machine/map keeps one
 * streaming map.
 *
 * Connections go to port 80 first; a failure before the Noise handshake
 * completes there (refused, timed out, not upgraded) tries port 443 at once.
 * For 443 the I/O layer adds TLS and still hands the session plain bytes.
 * Any other failure ends the connection and waits in BACKOFF: 1 s doubling to
 * 60 s, minus up to 25 percent jitter, reset after 60 s of RUNNING. Keys are
 * kept across reconnects.
 *
 * Starting (ts_sess_up) while already logged in sends one register of the
 * current key (no Followup, OldNodeKey only if the state holds one) before
 * the map, as upstream refreshes the key on login; reconnects map directly.
 *
 * Expiry is control's decision: NodeKeyExpired in a register response, or the
 * self node's Expired flag in the map. KeyExpiry is only shown in status; the
 * session never compares it with a clock (it has none). On NodeKeyExpired the
 * session makes a new node key, keeps the old one as old_node_priv, saves the
 * state, and only then registers again with OldNodeKey. A self Expired, or a
 * map 404 (the node was deleted), moves to NEED_LOGIN until ts_sess_up, which
 * does the same key change.
 *
 * Rate limits: a 429, or a 503 with a non-empty Retry-After, on a register or
 * the map request keeps the connection and repeats the same request after the
 * given number of seconds, clamped to TS_SESS_RETRY_AFTER_MAX_MS. A
 * Retry-After that is absent, zero, over an hour or not an integer number of
 * seconds (an HTTP-date included: there is no wall clock here) waits a random
 * 5 to 10 s instead, as upstream. The reconnect backoff is not touched.
 *
 * Text from control reaches status only as printable ASCII (other bytes become
 * '?'), and a login URL is accepted only if it is "https://" followed by bytes
 * 0x21..0x7e; anything else fails the register like a bad response.
 *
 * Tailnet Lock (a map with TKAInfo, or a register response carrying a
 * NodeKeySignature) and Debug.Exit move to FAILED, which is never retried;
 * only ts_sess_up leaves it.
 *
 * Re-entrancy: io callbacks are called from inside the ts_sess_* calls and
 * must not call back into the session. Failures found while processing input
 * (from inside the Noise, HTTP/2 or map stream callbacks) are acted on after
 * that input has been processed. */

#define TS_CONTROL_HOST "controlplane.tailscale.com"
#define TS_SESS_HOST_MAX 253
#define TS_SESS_URL_MAX 1024             /* longest AuthURL kept; longer is an error */
#define TS_SESS_REG_BODY_MAX 16384       /* largest register response body */
#define TS_SESS_ERR_BODY_MAX 200         /* bytes of an error body shown */

#define TS_SESS_BACKOFF_MIN_MS 1000
#define TS_SESS_BACKOFF_MAX_MS 60000
#define TS_SESS_BACKOFF_RESET_MS 60000   /* RUNNING this long resets the backoff */
#define TS_SESS_CONNECT_TIMEOUT_MS 30000 /* connect, upgrade and handshake, per port */
#define TS_SESS_KEEPALIVE_MS 90000       /* silence before an HTTP/2 PING */
#define TS_SESS_PING_TIMEOUT_MS 30000    /* then this much more before giving up */
#define TS_SESS_FOLLOWUP_MIN_MS 2000     /* floor between register sends */
#define TS_SESS_FOLLOWUP_MAX_MS 60000    /* cap of its exponential growth */
#define TS_SESS_RETRY_AFTER_MAX_MS 300000  /* longest wait honoured */
#define TS_SESS_RETRY_AFTER_VALID_S 3600   /* a longer Retry-After is not believed */
#define TS_SESS_RETRY_DEFAULT_MS 5000      /* else wait this plus up to as much again */
#define TS_SESS_HEAD_PING_MS 15000       /* a PingRequest HEAD is cancelled after this */
#define TS_SESS_REGEN_MIN_MS 60000       /* at most one new node key per minute */

typedef enum {
    TS_SESS_IDLE,            /* not started, or logged out */
    TS_SESS_CONNECTING,      /* connecting, handshaking, or waiting for the first map */
    TS_SESS_NEED_LOGIN,      /* a login URL to visit, or an expired or removed node */
    TS_SESS_AWAIT_APPROVAL,  /* logged in, self not MachineAuthorized */
    TS_SESS_RUNNING,         /* map streaming, self authorized */
    TS_SESS_BACKOFF,         /* disconnected, waiting to reconnect */
    TS_SESS_FAILED           /* stopped; see status */
} ts_sess_state;

/* I/O provided by the caller. All are required. user is the pointer given to
 * ts_sess_init.
 *   connect     start a connection to host:port (TLS on 443). 0 if started:
 *               the caller later calls ts_sess_connected or
 *               ts_sess_disconnected. -1 if it failed at once.
 *   send        queue all n bytes on the connection: 0, or -1 (the session then
 *               treats the connection as lost and calls disconnect).
 *   disconnect  close the connection. No ts_sess_* call may report on it after.
 *   save_state  persist st durably: 0 means ok.
 *   random      fill out with n random bytes: 0, or -1. */
typedef struct {
    int (*connect)(void *user, const char *host, uint16_t port);
    int (*send)(void *user, const uint8_t *p, size_t n);
    void (*disconnect)(void *user);
    int (*save_state)(void *user, const ts_state *st);
    int (*random)(void *user, uint8_t *out, size_t n);
} ts_sess_io;

/* Response header fields of one request, gathered as they arrive and committed
 * when the response headers are known valid. Internal. */
typedef struct {
    uint32_t sid;            /* 0: none open */
    int status;              /* 0 until the final headers arrived */
    int retry_after_ms;      /* parsed Retry-After of the pending block, -1 none or invalid */
    int have_retry_after;    /* the header was present */
    char err[TS_SESS_ERR_BODY_MAX + 1];  /* start of a non-200 body */
    size_t errlen;
} ts_sess_resp;

/* A session. Large (about 110 KiB): keep it off small stacks. Treat as opaque. */
typedef struct {
    const ts_sess_io *io;
    void *user;
    ts_state st;                         /* our copy; saved through io->save_state */
    uint8_t control_pub[32];
    char host[TS_SESS_HOST_MAX + 1];
    char *hostinfo;                      /* Hostinfo JSON object */

    int64_t now;                         /* last ts_sess_tick time */
    ts_sess_state state;                 /* derived by one function after every call */
    int64_t running_since;

    /* What the operator wants and what we know about the login. */
    int goal;                            /* GOAL_* in session.c */
    int logged_in;
    int regen;                           /* make a new node key before the next register */
    int refresh;                         /* logged in at start: register the current key once */
    int have_regen;
    int64_t last_regen;                  /* when the last new node key was made */
    int save_failed;                     /* the logout's save failed (status) */
    int logout_unconfirmed;              /* logged out here without control's answer (status) */
    int relogin;                         /* RELOGIN_*: waiting for ts_sess_up */
    int reg_authorized;                  /* MachineAuthorized, from the register or the map */
    char auth_url[TS_SESS_URL_MAX + 1];  /* "" when none */
    int64_t reg_at;                      /* earliest next register send */
    int64_t last_reg_send;
    int64_t fu_interval;                 /* followup spacing, grows on quick endings */
    int64_t map_at;                      /* earliest next map request */
    int64_t sleep_until;                 /* Debug.SleepSeconds */
    int rate_limited;                    /* the wait at reg_at or map_at is a rate limit */
    int64_t rate_until;                  /* when that wait ends, for status */
    int fatal;                           /* FAILED */
    int have_exit;                       /* Debug.Exit received */
    int exit_code;
    char reason[256];                    /* why the last failure, for status */

    /* Reconnection. */
    int64_t backoff_ms;                  /* next delay before jitter, 0 = minimum */
    int retry_armed;                     /* BACKOFF: reconnect at retry_at */
    int64_t retry_at;

    /* The connection. */
    int phase;                           /* PH_* in session.c */
    uint16_t port;
    int io_closed;                       /* the I/O layer already closed it */
    int64_t conn_start;
    int64_t last_rx;
    int ping_out;                        /* HTTP/2 PING sent, no bytes since */
    int64_t ping_sent;
    int pending_fail;                    /* failure noticed inside a callback */
    int pending_kind;
    char pending_reason[256];
    char hbuf[TS_UPGRADE_HEADER_MAX];
    size_t hlen;
    uint8_t hs[3 + 256];                 /* Noise response or error frame */
    size_t hslen;
    uint8_t *early;                      /* plaintext before HTTP/2, while undecided */
    size_t earlylen, earlycap;
    ts_noise noise;
    ts_h2 h2;
    int h2_live;                         /* ts_h2_init done */
    uint8_t sbuf[TS_NOISE_MAX_MSG];

    /* Requests. */
    ts_sess_resp reg;                    /* register, followup or logout */
    int reg_kind;
    int reg_regen;                       /* the open register carried a fresh key */
    char regbody[TS_SESS_REG_BODY_MAX];
    size_t reglen;
    int reg_overflow;
    ts_sess_resp map;
    int map_live;                        /* a map message arrived on this stream */
    ts_sess_resp hp;                     /* PingRequest HEAD */
    int64_t hp_sent;
    char last_ping_url[TS_PING_URL_MAX + 1];

    ts_netmap nm;
    int nm_ok;
    ts_map_stream ms;
} ts_sess;

/* Set up s (no I/O happens): state IDLE. st is copied. control_pub is control's
 * Noise key (from /key). hostinfo_json is copied. If memory runs out the
 * session starts FAILED. The host is TS_CONTROL_HOST. */
void ts_sess_init(ts_sess *s, const ts_state *st, const ts_sess_io *io, void *user,
                  const uint8_t control_pub[32], const char *hostinfo_json);

/* Use another control host (a DNS name, at most TS_SESS_HOST_MAX bytes, bytes
 * '!'..'~' only). Call before ts_sess_up. Returns 0, or -1 (unchanged). */
int ts_sess_set_host(ts_sess *s, const char *host);

/* Release memory. The caller has closed or will close the connection. */
void ts_sess_free(ts_sess *s);

/* The connection started by io->connect is up. */
void ts_sess_connected(ts_sess *s);
/* Bytes arrived on the connection. */
void ts_sess_recv(ts_sess *s, const uint8_t *in, size_t n);
/* The connection failed or closed (why is a short reason for status). */
void ts_sess_disconnected(ts_sess *s, const char *why);
/* Advance timers. now_ms is a monotonic clock in milliseconds; call it once
 * before any other call after init (the session's time starts at 0 until
 * then), and then at least every second. */
void ts_sess_tick(ts_sess *s, uint64_t now_ms);

/* Log in and stay connected (also leaves FAILED and NEED_LOGIN; after a node
 * expiry or removal the next register uses a new node key). */
void ts_sess_up(ts_sess *s);
/* Tell control to expire the current node key (register with Expiry in the far
 * past), then forget the login: a fresh node key, no old key, have_login
 * cleared and saved, IDLE. The register is sent whenever the session is
 * logged in or the saved state holds a login (have_login), even in NEED_LOGIN
 * after the refresh at start was answered with a login URL. If it cannot be
 * delivered (no connection on port 80 or 443, or control answers with an
 * error), the login is forgotten here all the same and not retried; status
 * says control was not reached. With no login at all nothing is sent; an old
 * key or a key with a login URL out is still dropped from the saved state. */
void ts_sess_logout(ts_sess *s);

ts_sess_state ts_sess_get_state(const ts_sess *s);
const char *ts_sess_state_name(ts_sess_state st);
/* One line: state name, detail, peer count. Holds the login URL only in
 * NEED_LOGIN. Always NUL-terminated (cap >= 1). */
void ts_sess_status(const ts_sess *s, char *out, size_t cap);
/* The URL to visit in NEED_LOGIN, else NULL. */
const char *ts_sess_login_url(const ts_sess *s);
/* 0 while control asked us to pause (Debug.SleepSeconds): stop reading the
 * connection until then. */
int ts_sess_want_read(const ts_sess *s);
/* 1 with *code set if control sent Debug.Exit (the session is then FAILED; the
 * daemon should exit with code & 0xff), else 0. */
int ts_sess_exit_requested(const ts_sess *s, int *code);
/* The current network map and node state (valid until the next call). */
const ts_netmap *ts_sess_netmap(const ts_sess *s);
const ts_state *ts_sess_node_state(const ts_sess *s);

/* ---- Parsers, exposed for tests and fuzzing ---------------------------- */

typedef struct {
    char auth_url[TS_SESS_URL_MAX + 1];
    char error[TS_SESS_ERR_BODY_MAX + 1];   /* Error, truncated */
    int node_key_expired;
    int machine_authorized;
    int has_signature;                      /* non-empty NodeKeySignature */
} ts_reg_resp;

/* A RegisterResponse JSON document. Unknown members are skipped. Returns 0, or
 * -1 for invalid JSON, a known member of the wrong type, or an AuthURL over
 * TS_SESS_URL_MAX bytes. */
int ts_reg_resp_parse(ts_reg_resp *r, const char *json, size_t len);

/* A Retry-After value: an integer number of seconds from 1 to
 * TS_SESS_RETRY_AFTER_VALID_S (spaces around allowed), returned in
 * milliseconds clamped to TS_SESS_RETRY_AFTER_MAX_MS. -1 for anything else. */
int ts_retry_after_parse(const char *v, size_t n);

/* Split "http[s]://authority/path?query" into the authority and the path with
 * query ("/" if empty). Bytes must be '!'..'~', with no '@' or '#'. Returns
 * 0, or -1 (outputs then ""). */
int ts_url_split(const char *url, char *authority, size_t acap, char *path, size_t pcap);

#endif
