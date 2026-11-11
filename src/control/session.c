#include "session.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../core/bytes.h"
#include "../crypto/x25519.h"
#include "../proto/encoding.h"
#include "../proto/json.h"

/* What the operator asked for. */
enum { GOAL_NONE, GOAL_UP, GOAL_LOGOUT };

/* Why we wait for ts_sess_up although logged in. */
enum { RELOGIN_NONE, RELOGIN_EXPIRED, RELOGIN_REMOVED };

/* Connection phases, in order. */
enum { PH_NONE, PH_TCP, PH_UPGRADE, PH_NOISE, PH_EARLY, PH_H2 };

/* Kinds of register request. */
enum { REG_LOGIN, REG_FOLLOWUP, REG_LOGOUT };

/* What a failure does once the connection is closed. */
enum {
    FAIL_RETRY = 1,   /* BACKOFF and reconnect; before the handshake on port 80, try 443 first
                       * (nothing on port 80 is authenticated until the Noise response verifies,
                       * so even an answer from "control" there falls back) */
    FAIL_RETRY_HERE,  /* BACKOFF and reconnect, no port fallback (control answered) */
    FAIL_STOP,        /* FAILED, never retried */
    FAIL_QUIET        /* no retry: the goal no longer needs a connection */
};

#define TKA_TEXT "Tailnet Lock is enabled on this tailnet and is not supported by this client"
#define REMOVED_TEXT "This device has been removed from the tailnet. Log in again to reconnect"
#define EXPIRED_TEXT "node key expired, run `tsppc up`"
#define EXPIRY_ZERO "0001-01-01T00:00:00Z"
#define EXPIRY_LOGOUT "1970-01-01T00:02:03Z"   /* upstream's time.Unix(123, 0) */
#define NORAND_TEXT "logged out, but there is no randomness for a new node key; the old key stays " \
    "marked as logged out"
#define LOGOUT_SAVE_TEXT "logout failed: the node state could not be saved"
#define DOWN_SAVE_TEXT "disconnect failed: the node state could not be saved"
#define UP_SAVE_TEXT "the node state could not be saved; a restart will stay disconnected until up"
#define LOGIN_SAVE_TEXT "logged in, but the node state could not be saved; a restart will need `tsppc up`"
#define HS80_TEXT "handshake on port 80 failed; trying port 443"

static void settle(ts_sess *s);
static int forget_login(ts_sess *s);
static int save_st(ts_sess *s);

/* ---- Small helpers --------------------------------------------------- */

static int64_t max64(int64_t a, int64_t b) { return a > b ? a : b; }

/* Copy text into a status-safe form: printable ASCII only, at most cap - 1. */
static void clean_text(char *out, size_t cap, const char *in, size_t n)
{
    size_t i, o = 0;
    if (cap == 0) return;
    for (i = 0; i < n && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[o] = 0;
}

/* Record a failure. Acted on in settle(), after any input in progress. The
 * first failure wins. */
static void fail(ts_sess *s, int kind, const char *fmt, ...)
{
    va_list ap;
    if (s->pending_fail) return;
    s->pending_fail = 1;
    s->pending_kind = kind;
    va_start(ap, fmt);
    vsnprintf(s->pending_reason, sizeof s->pending_reason, fmt, ap);
    va_end(ap);
}

/* Save the node state. Any successful save also has the login on disk, so it
 * clears an earlier failed save of the login. */
static int save(ts_sess *s, const ts_state *st)
{
    if (s->io->save_state(s->user, st) != 0) return -1;
    s->login_save_failed = 0;
    s->up_save_failed = 0;   /* the file no longer holds a stale down */
    return 0;
}

/* The handshake failed before control was authenticated. On port 80 nothing
 * is authenticated until the Noise response verifies (no TLS), so the reply
 * may not be control's: fall back to 443 and show none of its text. On 443
 * the text came over TLS, so it is shown (sanitised). */
static void handshake_failed(ts_sess *s, const char *text)
{
    if (s->port == 80) fail(s, FAIL_RETRY, "%s", HS80_TEXT);
    else if (text) fail(s, FAIL_RETRY_HERE, "control rejected the handshake: %s", text);
    else fail(s, FAIL_RETRY_HERE, "the Noise handshake with control failed");
}

static void pub_hex(char out[65], const uint8_t priv[32])
{
    uint8_t pub[32];
    ts_x25519_public(pub, priv);
    ts_hex_encode(out, 65, pub, 32);
}

/* Next reconnect delay: 1 s doubling to 60 s, minus up to 25 percent. */
static int64_t next_backoff(ts_sess *s)
{
    int64_t d = s->backoff_ms ? s->backoff_ms : TS_SESS_BACKOFF_MIN_MS;
    uint8_t r[2];
    s->backoff_ms = d * 2 > TS_SESS_BACKOFF_MAX_MS ? TS_SESS_BACKOFF_MAX_MS : d * 2;
    if (s->io->random(s->user, r, 2) == 0) d -= d * (int64_t)ts_get_be16(r) / 65536 / 4;
    return d;
}

static void resp_open(ts_sess_resp *r, uint32_t sid)
{
    memset(r, 0, sizeof *r);
    r->sid = sid;
    r->retry_after_ms = -1;
}

/* Save s->st. Any successful save writes down as it is in memory, so the file
 * no longer holds a down that up cleared. */
static int save_st(ts_sess *s)
{
    return save(s, &s->st);
}

/* ---- JSON output ------------------------------------------------------ */

typedef struct {
    char *p;
    size_t len, cap;
    int err;
} jbuf;

static void jput(jbuf *b, const char *s)
{
    size_t n = strlen(s);
    if (b->err || n >= b->cap - b->len) {
        b->err = 1;
        return;
    }
    memcpy(b->p + b->len, s, n + 1);
    b->len += n;
}

static void jkey(jbuf *b, const char *pfx, const uint8_t priv[32])
{
    char hex[65];
    pub_hex(hex, priv);
    jput(b, pfx);
    jput(b, hex);
    jput(b, "\"");
}

/* A JSON string body: quotes and backslashes escaped, controls as \u00XX. */
static void jstr(jbuf *b, const char *s)
{
    char e[8];
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            e[0] = '\\';
            e[1] = (char)c;
            e[2] = 0;
        } else if (c < 0x20) {
            snprintf(e, sizeof e, "\\u%04x", c);
        } else {
            e[0] = (char)c;
            e[1] = 0;
        }
        jput(b, e);
    }
}

/* ---- Connection ------------------------------------------------------- */

/* Close the connection and forget everything tied to it. */
static void close_conn(ts_sess *s, int tell_io)
{
    if (s->phase == PH_NONE) return;
    if (s->h2_live) {
        ts_h2_free(&s->h2);
        s->h2_live = 0;
    }
    ts_noise_clear(&s->noise);
    free(s->early);
    s->early = NULL;
    s->earlylen = s->earlycap = 0;
    ts_map_stream_free(&s->ms);
    ts_map_stream_init(&s->ms, NULL, NULL);
    resp_open(&s->reg, 0);
    resp_open(&s->map, 0);
    resp_open(&s->hp, 0);
    s->map_live = 0;
    s->ping_out = 0;
    s->hlen = s->hslen = 0;
    s->phase = PH_NONE;
    if (tell_io) s->io->disconnect(s->user);
}

static void start_connect(ts_sess *s, uint16_t port)
{
    s->phase = PH_TCP;
    s->port = port;
    s->conn_start = s->now;
    s->last_rx = s->now;
    s->retry_armed = 0;
    s->io_closed = 0;
    if (s->io->connect(s->user, s->host, port) != 0) {
        s->io_closed = 1;
        fail(s, FAIL_RETRY, "cannot connect to control on port %u", (unsigned)port);
    }
}

static void apply_failure(ts_sess *s)
{
    int kind = s->pending_kind;
    int before_handshake = s->phase != PH_NONE && s->phase < PH_EARLY;
    s->pending_fail = 0;
    memcpy(s->reason, s->pending_reason, sizeof s->reason);
    close_conn(s, !s->io_closed);
    if (kind == FAIL_RETRY && before_handshake && s->port == 80 && s->goal != GOAL_NONE) {
        start_connect(s, 443);
        return;
    }
    if (s->st.logout_pending && (kind == FAIL_RETRY || kind == FAIL_RETRY_HERE)) {
        /* The logout register could not be delivered (neither port answered,
         * or control answered with an error): finish the logout here with a
         * new node key, so the state keeps nothing usable. The old key stays
         * registered at control until it expires there. Not retried. */
        int ok = forget_login(s) == 0;
        s->logout_unconfirmed = 1;
        if (!ok) {
            s->fatal = 1;
            s->retry_armed = 0;
            snprintf(s->reason, sizeof s->reason, "%s", NORAND_TEXT);
            return;
        }
        if (s->goal == GOAL_LOGOUT) {
            s->goal = GOAL_NONE;
            s->retry_armed = 0;
            return;
        }
        /* ts_sess_up came meanwhile: log in with the new key after a backoff. */
    }
    if (kind == FAIL_RETRY || kind == FAIL_RETRY_HERE) {
        s->retry_at = s->now + next_backoff(s);
        s->retry_armed = 1;
    } else if (kind == FAIL_STOP) {
        s->fatal = 1;
        s->retry_armed = 0;
    } else {
        s->retry_armed = 0;
    }
}

/* ---- Requests --------------------------------------------------------- */

static void send_register(ts_sess *s, int kind)
{
    jbuf b;
    const char *hdrs[6];
    size_t nh = 0;
    char oldlb[80], newlb[80], hex[65];
    uint32_t sid;
    int regen = 0;

    if (kind == REG_LOGIN && s->regen) {
        /* A new node key, saved before control sees it. Each one writes the
         * state to disk, so a control that keeps expiring them is not
         * followed more than once a minute. */
        uint8_t k[32];
        ts_state prev;   /* restored if the save fails; copied only once it can be */
        if (s->have_regen && s->now - s->last_regen < TS_SESS_REGEN_MIN_MS) {
            fail(s, FAIL_RETRY_HERE, "control keeps expiring new node keys");
            return;
        }
        if (s->io->random(s->user, k, 32) != 0) {
            ts_wipe(k, sizeof k);
            fail(s, FAIL_RETRY_HERE, "no randomness for a new node key");
            return;
        }
        prev = s->st;
        ts_state_clamp_key(k);
        /* The old key is the last one that completed a login (as upstream,
         * which only replaces its key once a login completes): a key that
         * never logged in does not displace it. The new key is not logged in
         * until login_done saves have_login again, so a restart registers. */
        if (s->st.have_login || !s->st.have_old_node) {
            memcpy(s->st.old_node_priv, s->st.node_priv, 32);
            s->st.have_old_node = 1;
        }
        s->st.have_login = 0;
        s->st.down = 0;
        memcpy(s->st.node_priv, k, 32);
        ts_wipe(k, sizeof k);
        if (save_st(s) != 0) {
            s->st = prev;
            fail(s, FAIL_RETRY_HERE, "could not save the node state");
            ts_wipe(&prev, sizeof prev);
            return;
        }
        ts_wipe(&prev, sizeof prev);
        s->regen = 0;
        s->have_regen = 1;
        s->last_regen = s->now;
        regen = 1;
    }

    b.cap = strlen(s->hostinfo) + 6 * TS_SESS_URL_MAX + 512;
    b.p = (char *)malloc(b.cap);
    b.len = 0;
    b.err = b.p == NULL;
    if (b.p) b.p[0] = 0;
    jput(&b, "{\"Version\":");
    {
        char v[16];
        snprintf(v, sizeof v, "%d", TS_CAPVER);
        jput(&b, v);
    }
    jkey(&b, ",\"NodeKey\":\"nodekey:", s->st.node_priv);
    if (s->st.have_old_node) jkey(&b, ",\"OldNodeKey\":\"nodekey:", s->st.old_node_priv);
    jput(&b, ",\"Expiry\":\"");
    jput(&b, kind == REG_LOGOUT ? EXPIRY_LOGOUT : EXPIRY_ZERO);
    jput(&b, "\"");
    if (kind == REG_FOLLOWUP) {
        jput(&b, ",\"Followup\":\"");
        jstr(&b, s->auth_url);
        jput(&b, "\"");
    }
    jput(&b, ",\"Hostinfo\":");
    jput(&b, s->hostinfo);
    jput(&b, ",\"Ephemeral\":false}");

    hdrs[nh++] = "Content-Type";
    hdrs[nh++] = "application/json";
    /* As upstream: a Ts-Lb for the old key, then for the new one. */
    if (s->st.have_old_node) {
        pub_hex(hex, s->st.old_node_priv);
        snprintf(oldlb, sizeof oldlb, "nodekey:%s", hex);
        hdrs[nh++] = "Ts-Lb";
        hdrs[nh++] = oldlb;
    }
    pub_hex(hex, s->st.node_priv);
    snprintf(newlb, sizeof newlb, "nodekey:%s", hex);
    hdrs[nh++] = "Ts-Lb";
    hdrs[nh++] = newlb;

    if (b.err || ts_h2_request(&s->h2, &sid, "POST", "/machine/register", s->host, hdrs, nh / 2,
                               (const uint8_t *)b.p, b.len) != 0) {
        fail(s, FAIL_RETRY_HERE, "cannot send the register request");
    } else {
        resp_open(&s->reg, sid);
        s->reg_kind = kind;
        s->reg_regen = regen;
        s->reglen = 0;
        s->reg_overflow = 0;
        s->last_reg_send = s->now;
        s->rate_limited = 0;
    }
    free(b.p);
}

static void on_map_msg(void *user, const char *json, size_t len);

static void send_map(ts_sess *s)
{
    jbuf b;
    const char *hdrs[4];
    char lb[80], hex[65], v[16];
    uint32_t sid;

    ts_netmap_reset(&s->nm);
    ts_map_stream_free(&s->ms);
    ts_map_stream_init(&s->ms, on_map_msg, s);
    s->map_live = 0;

    b.cap = strlen(s->hostinfo) + 512;
    b.p = (char *)malloc(b.cap);
    b.len = 0;
    b.err = b.p == NULL;
    if (b.p) b.p[0] = 0;
    snprintf(v, sizeof v, "%d", TS_CAPVER);
    jput(&b, "{\"Version\":");
    jput(&b, v);
    jput(&b, ",\"KeepAlive\":true");
    jkey(&b, ",\"NodeKey\":\"nodekey:", s->st.node_priv);
    jkey(&b, ",\"DiscoKey\":\"discokey:", s->st.disco_priv);
    jput(&b, ",\"Stream\":true,\"Hostinfo\":");
    jput(&b, s->hostinfo);
    jput(&b, "}");

    pub_hex(hex, s->st.node_priv);
    snprintf(lb, sizeof lb, "nodekey:%s", hex);
    hdrs[0] = "Content-Type";
    hdrs[1] = "application/json";
    hdrs[2] = "Ts-Lb";
    hdrs[3] = lb;
    if (b.err || ts_h2_request(&s->h2, &sid, "POST", "/machine/map", s->host, hdrs, 2,
                               (const uint8_t *)b.p, b.len) != 0) {
        fail(s, FAIL_RETRY_HERE, "cannot send the map request");
    } else {
        resp_open(&s->map, sid);
        s->rate_limited = 0;
    }
    free(b.p);
}

/* A plain liveness PingRequest: HEAD the URL over this connection (D1). */
static void handle_ping(ts_sess *s)
{
    ts_ping_req *pr = &s->nm.ping;
    char auth[TS_PING_URL_MAX + 1], path[TS_PING_URL_MAX + 2];
    uint32_t sid;
    if (!pr->pending) return;
    pr->pending = 0;
    if (!pr->url[0]) return;                               /* nothing to answer */
    if (strcmp(pr->url, s->last_ping_url) == 0) return;   /* duplicate */
    memcpy(s->last_ping_url, pr->url, sizeof s->last_ping_url);
    if (pr->types[0] || !pr->url_is_noise) return;       /* c2n, TSMP, disco, plain TLS: ignored */
    if (ts_url_split(pr->url, auth, sizeof auth, path, sizeof path) != 0) return;
    if (s->hp.sid) {
        ts_h2_cancel(&s->h2, s->hp.sid);
        s->hp.sid = 0;
    }
    if (ts_h2_request(&s->h2, &sid, "HEAD", path, auth, NULL, 0, NULL, 0) == 0) {
        resp_open(&s->hp, sid);
        s->hp_sent = s->now;
    }
}

/* After each applied map message: exit, ping, Tailnet Lock, sleep, expiry. */
static void on_map_msg(void *user, const char *json, size_t len)
{
    ts_sess *s = (ts_sess *)user;
    if (s->pending_fail) return;
    if (ts_netmap_apply(&s->nm, json, len) != 0) {
        /* Over the peer limit control sends the same map again on every
         * reconnect: stop until `tsppc up`. Anything else may be a lost
         * delta, which a fresh map session repairs. */
        fail(s, s->nm.last_limit ? FAIL_STOP : FAIL_RETRY_HERE, "map message rejected: %s", s->nm.last_error);
        return;
    }
    s->map_live = 1;
    if (s->nm.have_exit) {
        s->have_exit = 1;
        s->exit_code = s->nm.exit_code;
        fail(s, FAIL_STOP, "control asked this client to exit (code %d)", s->nm.exit_code);
        return;
    }
    handle_ping(s);
    if (s->nm.tka_enabled) {
        fail(s, FAIL_STOP, TKA_TEXT);
        return;
    }
    if (s->nm.sleep_ms) s->sleep_until = s->now + (int64_t)s->nm.sleep_ms;
    if (s->nm.have_self && s->nm.self.expired) {
        s->relogin = RELOGIN_EXPIRED;
        fail(s, FAIL_QUIET, EXPIRED_TEXT);
        return;
    }
    if (s->relogin == RELOGIN_REMOVED) s->relogin = RELOGIN_NONE;
    if (s->nm.have_self) s->reg_authorized = s->nm.self.authorized;
}

/* Rate limited: wait as told and repeat the same request. Without a usable
 * Retry-After, a random 5 to 10 s, as upstream (direct.go parseRateLimitError).
 * The reconnect backoff is neither advanced nor reset. */
static int rate_limit(ts_sess *s, const ts_sess_resp *r, int64_t *at)
{
    int64_t w;
    uint8_t rnd[2];
    if (r->status != 429 && !(r->status == 503 && r->have_retry_after)) return 0;
    w = r->retry_after_ms;
    if (w <= 0) {
        w = TS_SESS_RETRY_DEFAULT_MS;
        if (s->io->random(s->user, rnd, 2) == 0) w += ts_get_be16(rnd) % TS_SESS_RETRY_DEFAULT_MS;
    }
    *at = s->now + w;
    s->rate_limited = 1;
    s->rate_until = *at;
    return 1;
}

static void followup_ended(ts_sess *s)
{
    s->fu_interval *= 2;
    if (s->fu_interval > TS_SESS_FOLLOWUP_MAX_MS) s->fu_interval = TS_SESS_FOLLOWUP_MAX_MS;
    s->reg_at = s->last_reg_send + s->fu_interval;
}

static void login_done(ts_sess *s, int authorized)
{
    s->logged_in = 1;
    s->refresh = 0;
    s->auth_url[0] = 0;
    s->fu_interval = TS_SESS_FOLLOWUP_MIN_MS;
    s->reg_authorized = authorized;
    s->relogin = RELOGIN_NONE;
    if (!s->st.have_login) {
        s->st.have_login = 1;
        /* Not fatal: control has the login and this session runs on. Status
         * says so until a later save succeeds. */
        if (save_st(s) != 0) s->login_save_failed = 1;
    }
    s->map_at = s->now;
}

/* Forget the login: a fresh node key with no old one, as upstream clears its
 * persisted state, and logout_pending cleared. The machine and disco keys
 * stay. Returns -1 if there is no randomness: the node key is then kept, and
 * so is logout_pending, so that key never logs in again. If the save fails
 * the file still holds logout_pending (or no login at all); status says so. */
static int forget_login(ts_sess *s)
{
    uint8_t k[32];
    int rnd = s->io->random(s->user, k, 32) == 0;
    if (rnd) {
        ts_state_clamp_key(k);
        memcpy(s->st.node_priv, k, 32);
        ts_wipe(k, sizeof k);
        s->st.logout_pending = 0;
    }
    ts_wipe(s->st.old_node_priv, 32);
    s->st.have_old_node = 0;
    s->st.have_login = 0;
    s->st.down = 0;
    s->save_failed = save_st(s) != 0;
    s->login_save_failed = 0;   /* no login to lose any more */
    s->logged_in = 0;
    s->refresh = 0;
    s->auth_url[0] = 0;
    s->relogin = RELOGIN_NONE;
    s->regen = 0;
    s->reg_at = s->now;
    s->logout_unconfirmed = 0;
    ts_netmap_reset(&s->nm);
    return rnd ? 0 : -1;
}

/* Control confirmed the logout. */
static void logout_done(ts_sess *s)
{
    if (forget_login(s) != 0) {
        fail(s, FAIL_STOP, "%s", NORAND_TEXT);
        return;
    }
    if (s->goal == GOAL_LOGOUT) {
        s->goal = GOAL_NONE;
        fail(s, FAIL_QUIET, "logged out");
    }
    /* Else ts_sess_up came while the logout was in flight: log in again on
     * this connection. */
}

/* A login URL we will show: "https://" and then printable ASCII, no spaces. */
static int auth_url_ok(const char *u)
{
    if (strncmp(u, "https://", 8) != 0 || u[8] == 0) return 0;
    for (; *u; u++)
        if ((unsigned char)*u < 0x21 || (unsigned char)*u > 0x7e) return 0;
    return 1;
}

static void reg_end(ts_sess *s, int error)
{
    ts_reg_resp rr;
    int kind = s->reg_kind;
    char body[TS_SESS_ERR_BODY_MAX + 1];
    s->reg.sid = 0;
    if (error != TS_H2_END_OK || s->reg.status == 0) {
        if (kind == REG_FOLLOWUP) followup_ended(s);
        else fail(s, FAIL_RETRY_HERE, "the register request was reset");
        return;
    }
    if (rate_limit(s, &s->reg, &s->reg_at)) return;
    if (s->reg.status != 200) {
        clean_text(body, sizeof body, s->reg.err, s->reg.errlen);
        if (kind == REG_FOLLOWUP) followup_ended(s);
        else fail(s, FAIL_RETRY_HERE, "register failed: http %d: %s", s->reg.status, body);
        return;
    }
    if (s->reg_overflow || ts_reg_resp_parse(&rr, s->regbody, s->reglen) != 0) {
        fail(s, FAIL_RETRY_HERE, "bad register response");
        return;
    }
    if (kind == REG_LOGOUT) {
        logout_done(s);
        return;
    }
    if (rr.error[0]) {
        clean_text(body, sizeof body, rr.error, strlen(rr.error));
        fail(s, FAIL_RETRY_HERE, "control: %s", body);
        return;
    }
    if (rr.has_signature) {
        fail(s, FAIL_STOP, TKA_TEXT);
        return;
    }
    if (rr.node_key_expired) {
        if (s->reg_regen) {
            fail(s, FAIL_RETRY_HERE, "control says the new node key has expired");
            return;
        }
        s->regen = 1;
        s->logged_in = 0;
        s->auth_url[0] = 0;
        /* After a Followup, keep its growing spacing: a control that answers
         * every Followup this way must not make us cycle every 2 s. */
        if (kind == REG_FOLLOWUP) followup_ended(s);
        else s->reg_at = s->now;
        return;
    }
    if (rr.auth_url[0]) {
        if (!auth_url_ok(rr.auth_url)) {
            /* It is printed to the operator's terminal: no controls or escapes. */
            fail(s, FAIL_RETRY_HERE, "control sent an invalid login URL");
            return;
        }
        s->logged_in = 0;   /* a refresh of a logged-in key can need a login again */
        if (kind == REG_FOLLOWUP) followup_ended(s);
        else s->reg_at = s->last_reg_send + s->fu_interval;
        memcpy(s->auth_url, rr.auth_url, sizeof s->auth_url);
        return;
    }
    login_done(s, rr.machine_authorized);
}

static void map_end(ts_sess *s, int error)
{
    char body[TS_SESS_ERR_BODY_MAX + 1];
    int status = s->map.status;
    s->map.sid = 0;
    if (error != TS_H2_END_OK || status == 0) {
        fail(s, FAIL_RETRY_HERE, "the map request was reset");
    } else if (status == 200) {
        fail(s, FAIL_RETRY_HERE, "control ended the map stream");
    } else if (rate_limit(s, &s->map, &s->map_at)) {
        /* Same connection, map again later. */
    } else if (status == 404) {
        s->relogin = RELOGIN_REMOVED;
        fail(s, FAIL_RETRY_HERE, REMOVED_TEXT);
    } else {
        clean_text(body, sizeof body, s->map.err, s->map.errlen);
        fail(s, FAIL_RETRY_HERE, "map request failed: http %d: %s", status, body);
    }
}

/* ---- HTTP/2 callbacks ------------------------------------------------- */

static ts_sess_resp *resp_for(ts_sess *s, uint32_t sid)
{
    if (sid == 0) return NULL;
    if (sid == s->reg.sid) return &s->reg;
    if (sid == s->map.sid) return &s->map;
    if (sid == s->hp.sid) return &s->hp;
    return NULL;
}

static int name_is(const char *n, size_t nl, const char *want)
{
    size_t i;
    if (nl != strlen(want)) return 0;
    for (i = 0; i < nl; i++) {
        char c = n[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != want[i]) return 0;
    }
    return 1;
}

static void cb_header(void *u, uint32_t sid, const char *n, size_t nl, const char *v, size_t vl)
{
    ts_sess *s = (ts_sess *)u;
    ts_sess_resp *r = resp_for(s, sid);
    if (s->pending_fail || !r || r->status) return;   /* after status: trailers */
    /* An empty value is absent, as Go's Header.Get(...) != "". */
    if (name_is(n, nl, "retry-after") && vl > 0 && !r->have_retry_after) {
        r->have_retry_after = 1;
        r->retry_after_ms = ts_retry_after_parse(v, vl);
    }
}

static void cb_headers(void *u, uint32_t sid, int status)
{
    ts_sess *s = (ts_sess *)u;
    ts_sess_resp *r = resp_for(s, sid);
    if (s->pending_fail || !r) return;
    r->status = status;
}

static void cb_data(void *u, uint32_t sid, const uint8_t *d, size_t n)
{
    ts_sess *s = (ts_sess *)u;
    ts_sess_resp *r = resp_for(s, sid);
    if (s->pending_fail) return;
    if (r == &s->map && r->status == 200) {
        if (ts_map_stream_feed(&s->ms, d, n) != 0 && !s->pending_fail) {
            if (s->ms.failed == TS_MAP_STREAM_TOO_BIG)
                /* Control would send it again: stop until `tsppc up`. */
                fail(s, FAIL_STOP, "a map message is over the %u-byte limit", (unsigned)TS_MAP_MSG_MAX);
            else
                fail(s, FAIL_RETRY_HERE, "out of memory for a map message");
        }
    } else if (r == &s->reg && r->status == 200) {
        if (n > sizeof s->regbody - s->reglen) s->reg_overflow = 1;
        else {
            memcpy(s->regbody + s->reglen, d, n);
            s->reglen += n;
        }
    } else if (r) {
        size_t k = sizeof r->err - 1 - r->errlen;
        if (k > n) k = n;
        memcpy(r->err + r->errlen, d, k);
        r->errlen += k;
    }
    /* Return the credit at once; flush() sends any WINDOW_UPDATE. */
    if (!s->pending_fail) (void)ts_h2_consume_data(&s->h2, sid, n);
}

static void cb_end(void *u, uint32_t sid, int error)
{
    ts_sess *s = (ts_sess *)u;
    if (s->pending_fail || sid == 0) return;
    if (sid == s->reg.sid) reg_end(s, error);
    else if (sid == s->map.sid) map_end(s, error);
    else if (sid == s->hp.sid) s->hp.sid = 0;   /* the HEAD's answer is not needed */
}

static void cb_goaway(void *u, uint32_t last_sid, uint32_t code)
{
    ts_sess *s = (ts_sess *)u;
    (void)last_sid;
    fail(s, FAIL_RETRY_HERE, "control closed the connection (GOAWAY %u)", (unsigned)code);
}

static const ts_h2_cbs H2_CBS = { cb_headers, cb_header, cb_data, cb_end, cb_goaway };

/* ---- Receiving -------------------------------------------------------- */

static void h2_input(ts_sess *s, const uint8_t *p, size_t n)
{
    if (ts_h2_feed(&s->h2, p, n) != 0)
        fail(s, FAIL_RETRY_HERE, "HTTP/2 error %u from control", (unsigned)ts_h2_error(&s->h2));
}

/* Plaintext from a Noise record. */
static void deliver(void *u, const uint8_t *p, size_t n)
{
    ts_sess *s = (ts_sess *)u;
    size_t used;
    int rc;
    if (s->pending_fail) return;
    if (s->phase == PH_H2) {
        h2_input(s, p, n);
        return;
    }
    /* PH_EARLY: is there an early payload before HTTP/2? */
    if (s->earlylen + n > s->earlycap) {
        size_t nc = s->earlylen + n;
        uint8_t *nb;
        if (nc > TS_EARLY_PAYLOAD_MAX + 9 + TS_NOISE_MAX_PLAIN) {
            fail(s, FAIL_RETRY_HERE, "early payload too large");
            return;
        }
        nb = (uint8_t *)realloc(s->early, nc);
        if (!nb) {
            fail(s, FAIL_RETRY_HERE, "out of memory");
            return;
        }
        s->early = nb;
        s->earlycap = nc;
    }
    memcpy(s->early + s->earlylen, p, n);
    s->earlylen += n;
    rc = ts_early_payload(s->early, s->earlylen, &used);
    if (rc == 1) return;
    if (rc < 0) {
        fail(s, FAIL_RETRY_HERE, "bad early payload from control");
        return;
    }
    s->phase = PH_H2;
    if (used < s->earlylen) h2_input(s, s->early + used, s->earlylen - used);
    free(s->early);
    s->early = NULL;
    s->earlylen = s->earlycap = 0;
}

/* Handshake reply bytes: the 3-byte header, then the response or error text.
 * Returns the bytes used. */
static size_t handshake_input(ts_sess *s, const uint8_t *p, size_t n)
{
    size_t want, used = 0, k;
    while (s->hslen < 3 && used < n) s->hs[s->hslen++] = p[used++];
    if (s->hslen < 3) return used;
    if (s->hs[0] == 2) {
        if (ts_get_be16(s->hs + 1) != TS_NOISE_RESP_LEN - 3) {
            fail(s, FAIL_RETRY, "unexpected handshake reply from control");
            return n;
        }
        want = TS_NOISE_RESP_LEN;
    } else if (s->hs[0] == 3) {
        size_t len = ts_get_be16(s->hs + 1);
        want = 3 + (len < sizeof s->hs - 3 ? len : sizeof s->hs - 3);
    } else {
        fail(s, FAIL_RETRY, "unexpected handshake reply from control");
        return n;
    }
    k = want - s->hslen;
    if (k > n - used) k = n - used;
    memcpy(s->hs + s->hslen, p + used, k);
    s->hslen += k;
    used += k;
    if (s->hslen < want) return used;
    if (s->hs[0] == 3) {
        char text[200];
        clean_text(text, sizeof text, (const char *)s->hs + 3, s->hslen - 3);
        handshake_failed(s, text);
        return n;
    }
    if (ts_noise_read_response(&s->noise, s->hs) != 0) {
        handshake_failed(s, NULL);
        return n;
    }
    ts_h2_init(&s->h2, &H2_CBS, s);
    s->h2_live = 1;
    if (ts_h2_error(&s->h2) != TS_H2_NO_ERROR || s->h2.dead) {
        fail(s, FAIL_RETRY_HERE, "out of memory");
        return n;
    }
    s->phase = PH_EARLY;
    return used;
}

static void rx(ts_sess *s, const uint8_t *p, size_t n)
{
    while (n > 0 && !s->pending_fail) {
        if (s->phase == PH_UPGRADE) {
            size_t take = sizeof s->hbuf - s->hlen, consumed = 0;
            int rc;
            if (take > n) take = n;
            memcpy(s->hbuf + s->hlen, p, take);
            s->hlen += take;
            p += take;
            n -= take;
            rc = ts_upgrade_response(s->hbuf, s->hlen, &consumed);
            if (rc < 0 || (rc == 1 && s->hlen == sizeof s->hbuf)) {
                fail(s, FAIL_RETRY, "control did not upgrade the connection");
                return;
            }
            if (rc == 1) continue;
            s->phase = PH_NOISE;
            s->hslen = 0;
            /* Bytes after the headers already belong to the handshake. */
            rx(s, (const uint8_t *)s->hbuf + consumed, s->hlen - consumed);
            s->hlen = 0;
        } else if (s->phase == PH_NOISE) {
            size_t used = handshake_input(s, p, n);
            p += used;
            n -= used;
        } else if (s->phase == PH_EARLY || s->phase == PH_H2) {
            if (ts_noise_feed(&s->noise, p, n, deliver, s) != 0)
                fail(s, FAIL_RETRY_HERE, "bad Noise record from control");
            return;
        } else {
            return;
        }
    }
}

/* ---- Driving ---------------------------------------------------------- */

/* Send queued HTTP/2 bytes, sealed in records of at most TS_NOISE_MAX_PLAIN. */
static void flush(ts_sess *s)
{
    while (s->h2_live && !s->pending_fail) {
        const uint8_t *o;
        size_t n = ts_h2_output(&s->h2, &o), w;
        if (n == 0) break;
        if (n > TS_NOISE_MAX_PLAIN) n = TS_NOISE_MAX_PLAIN;
        w = ts_noise_seal(&s->noise, s->sbuf, sizeof s->sbuf, o, n);
        if (w == 0) {
            fail(s, FAIL_RETRY_HERE, "cannot encrypt to control");
            break;
        }
        if (s->io->send(s->user, s->sbuf, w) != 0) {
            /* The connection is still the I/O layer's: close_conn disconnects it. */
            fail(s, FAIL_RETRY, "sending to control failed");
            break;
        }
        ts_h2_consumed(&s->h2, n);
    }
}

/* Start whatever the goal needs next. */
static void drive(ts_sess *s)
{
    int want_conn;
    if (s->fatal || s->pending_fail || s->goal == GOAL_NONE) return;
    want_conn = s->goal == GOAL_LOGOUT || s->st.logout_pending || s->relogin != RELOGIN_EXPIRED;
    if (s->phase == PH_NONE) {
        if (want_conn && !s->retry_armed) start_connect(s, 80);
        return;
    }
    if (s->phase < PH_EARLY) return;
    /* A pending logout is finished before anything else, whatever the goal:
     * that key never logs in again. */
    if (s->goal == GOAL_LOGOUT || s->st.logout_pending) {
        if (s->map.sid) {
            (void)ts_h2_cancel(&s->h2, s->map.sid);
            s->map.sid = 0;
        }
        if (s->reg.sid && s->reg_kind != REG_LOGOUT) {
            (void)ts_h2_cancel(&s->h2, s->reg.sid);
            s->reg.sid = 0;
        }
        if (!s->reg.sid && s->now >= s->reg_at) send_register(s, REG_LOGOUT);
        return;
    }
    if (s->reg.sid && s->reg_kind == REG_LOGOUT) return;   /* up during a logout: let it finish */
    if (!s->logged_in) {
        if (!s->reg.sid && s->now >= s->reg_at)
            send_register(s, s->auth_url[0] ? REG_FOLLOWUP : REG_LOGIN);
    } else if (s->refresh) {
        /* Logged in at start: register the current key once before mapping,
         * as upstream's "try refreshing the current key" login. It brings
         * Hostinfo up to date and lets control answer NodeKeyExpired. */
        if (!s->reg.sid && s->now >= s->reg_at) send_register(s, REG_LOGIN);
    } else if (!s->map.sid && s->now >= s->map_at && s->now >= s->sleep_until) {
        send_map(s);
    }
}

/* The one place the state is decided, from what the session knows. */
static ts_sess_state derive_state(const ts_sess *s)
{
    if (s->fatal) return TS_SESS_FAILED;
    if (s->goal == GOAL_NONE) return TS_SESS_IDLE;
    if (s->goal == GOAL_UP) {
        if (s->relogin != RELOGIN_NONE) return TS_SESS_NEED_LOGIN;
        if (!s->logged_in && s->auth_url[0]) return TS_SESS_NEED_LOGIN;
    }
    if (s->phase == PH_NONE) return s->retry_armed ? TS_SESS_BACKOFF : TS_SESS_CONNECTING;
    if (s->goal == GOAL_UP && s->logged_in) {
        if (s->map_live && s->nm.have_self)
            return s->nm.self.authorized ? TS_SESS_RUNNING : TS_SESS_AWAIT_APPROVAL;
        if (!s->reg_authorized) return TS_SESS_AWAIT_APPROVAL;
    }
    return TS_SESS_CONNECTING;
}

static void settle(ts_sess *s)
{
    int round;
    ts_sess_state st;
    for (round = 0; round < 4; round++) {
        if (s->pending_fail) apply_failure(s);
        drive(s);
        flush(s);
        if (!s->pending_fail) break;
    }
    st = derive_state(s);
    if (st == TS_SESS_RUNNING && s->state != TS_SESS_RUNNING) s->running_since = s->now;
    s->state = st;
}

/* ---- Public calls ----------------------------------------------------- */

void ts_sess_init(ts_sess *s, const ts_state *st, const ts_sess_io *io, void *user,
                  const uint8_t control_pub[32], const char *hostinfo_json)
{
    size_t hl;
    memset(s, 0, sizeof *s);
    s->io = io;
    s->user = user;
    s->st = *st;
    memcpy(s->control_pub, control_pub, 32);
    snprintf(s->host, sizeof s->host, "%s", TS_CONTROL_HOST);
    if (!hostinfo_json || !hostinfo_json[0]) hostinfo_json = "{}";
    hl = strlen(hostinfo_json);
    s->hostinfo = (char *)malloc(hl + 1);
    if (s->hostinfo) memcpy(s->hostinfo, hostinfo_json, hl + 1);
    s->logged_in = st->have_login;
    s->reg_authorized = 1;
    s->fu_interval = TS_SESS_FOLLOWUP_MIN_MS;
    s->phase = PH_NONE;
    resp_open(&s->reg, 0);
    resp_open(&s->map, 0);
    resp_open(&s->hp, 0);
    ts_map_stream_init(&s->ms, NULL, NULL);
    s->nm_ok = ts_netmap_init(&s->nm) == 0;
    if (!s->nm_ok || !s->hostinfo) {
        s->fatal = 1;
        snprintf(s->reason, sizeof s->reason, "out of memory");
    }
    s->state = derive_state(s);
}

int ts_sess_set_host(ts_sess *s, const char *host)
{
    size_t i, n = host ? strlen(host) : 0;
    if (n == 0 || n > TS_SESS_HOST_MAX) return -1;
    for (i = 0; i < n; i++)
        if (host[i] < '!' || host[i] > '~') return -1;
    memcpy(s->host, host, n + 1);
    return 0;
}

void ts_sess_free(ts_sess *s)
{
    close_conn(s, 0);
    ts_map_stream_free(&s->ms);
    if (s->nm_ok) ts_netmap_free(&s->nm);
    free(s->hostinfo);
    ts_wipe(s, sizeof *s);
}

void ts_sess_connected(ts_sess *s)
{
    uint8_t init[TS_NOISE_INIT_LEN];
    size_t n;
    if (s->phase != PH_TCP) return;
    if (ts_noise_init(&s->noise, init, s->st.machine_priv, s->control_pub, TS_CAPVER) != 0) {
        fail(s, FAIL_RETRY_HERE, "cannot start the Noise handshake (bad control key?)");
    } else {
        n = ts_upgrade_request((char *)s->sbuf, sizeof s->sbuf, s->host, init);
        s->phase = PH_UPGRADE;
        s->hlen = 0;
        s->last_rx = s->now;
        if (n == 0) {
            fail(s, FAIL_RETRY_HERE, "cannot build the upgrade request");
        } else if (s->io->send(s->user, s->sbuf, n) != 0) {
            fail(s, FAIL_RETRY, "sending to control failed");
        }
    }
    settle(s);
}

void ts_sess_recv(ts_sess *s, const uint8_t *in, size_t n)
{
    if (s->phase < PH_UPGRADE || n == 0) return;
    s->last_rx = s->now;
    s->ping_out = 0;
    rx(s, in, n);
    settle(s);
}

void ts_sess_disconnected(ts_sess *s, const char *why)
{
    if (s->phase == PH_NONE) return;
    s->io_closed = 1;
    if (s->phase == PH_NOISE && s->hslen > 3 && s->hs[0] == 3) {
        char text[200];
        clean_text(text, sizeof text, (const char *)s->hs + 3, s->hslen - 3);
        handshake_failed(s, text);
    } else {
        char text[120];
        clean_text(text, sizeof text, why ? why : "connection closed", why ? strlen(why) : 17);
        fail(s, FAIL_RETRY, "%s", text);
    }
    settle(s);
}

void ts_sess_tick(ts_sess *s, uint64_t now_ms)
{
    s->now = (int64_t)now_ms;
    if (s->retry_armed && s->now >= s->retry_at) s->retry_armed = 0;
    if (s->phase >= PH_TCP && s->phase < PH_EARLY && s->now - s->conn_start >= TS_SESS_CONNECT_TIMEOUT_MS)
        fail(s, FAIL_RETRY, "timed out connecting to control on port %u", (unsigned)s->port);
    if (s->phase >= PH_EARLY && s->now >= s->sleep_until) {
        int64_t quiet = s->now - max64(s->last_rx, s->sleep_until);
        if (!s->ping_out && quiet >= TS_SESS_KEEPALIVE_MS) {
            ts_h2_ping(&s->h2);
            s->ping_out = 1;
            s->ping_sent = s->now;
        } else if (s->ping_out && s->now - s->ping_sent >= TS_SESS_PING_TIMEOUT_MS) {
            fail(s, FAIL_RETRY_HERE, "control stopped responding");
        }
    }
    if (s->hp.sid && s->now - s->hp_sent >= TS_SESS_HEAD_PING_MS) {
        (void)ts_h2_cancel(&s->h2, s->hp.sid);
        s->hp.sid = 0;
    }
    if (s->state == TS_SESS_RUNNING && s->now - s->running_since >= TS_SESS_BACKOFF_RESET_MS) s->backoff_ms = 0;
    settle(s);
}

void ts_sess_up(ts_sess *s)
{
    if (!s->nm_ok || !s->hostinfo) return;   /* out of memory at init: stays FAILED */
    s->fatal = 0;
    s->logout_unconfirmed = 0;
    s->logout_failed = 0;
    s->down_failed = 0;
    s->have_exit = 0;
    if (s->st.down || s->up_save_failed) {
        /* Cleared in memory whatever the save does, so it never outlives the
         * login. Not fatal: connect anyway, and say a restart would wait for
         * up again until some save succeeds. */
        s->st.down = 0;
        s->up_save_failed = save_st(s) != 0;
    }
    if (s->relogin != RELOGIN_NONE) {
        /* Expired or removed: log in again with a new node key (as upstream). */
        s->relogin = RELOGIN_NONE;
        s->logged_in = 0;
        s->regen = 1;
        s->auth_url[0] = 0;
        s->reg_at = s->now;
    }
    if (s->goal != GOAL_UP) {
        s->goal = GOAL_UP;
        if (!s->auth_url[0]) s->reg_at = s->now;
        s->map_at = s->now;
        /* Starting while logged in: one register of the current key first. */
        if (s->logged_in) s->refresh = 1;
    }
    /* An operator's request retries now. */
    s->backoff_ms = 0;
    s->retry_armed = 0;
    settle(s);
}

int ts_sess_logout(ts_sess *s)
{
    s->logout_failed = 0;
    s->down_failed = 0;
    if (!s->logged_in && !s->st.have_login && !s->st.logout_pending) {
        /* Nothing registered: forget any login in progress. A saved login
         * (have_login) is expired at control and cleared below even when the
         * session is not logged in now, for instance when the refresh at
         * start was answered with a login URL. */
        /* An old key (kept after a key change) or a key with a login URL
         * out is dropped from the saved state too. */
        if (s->st.have_old_node || s->auth_url[0] || s->regen) forget_login(s);
        s->goal = GOAL_NONE;
        s->auth_url[0] = 0;
        s->regen = 0;
        s->relogin = RELOGIN_NONE;
        s->retry_armed = 0;
        if (s->phase != PH_NONE) fail(s, FAIL_QUIET, "logged out");
        settle(s);
        return 0;
    }
    if (!s->st.logout_pending) {
        /* Persist the intent before control hears anything, as upstream
         * saves LoggedOut first: a restart from here finishes the logout and
         * never logs in with this key. If that save fails nothing changes. */
        ts_state n = s->st;
        int rc;
        n.have_login = 0;
        n.down = 0;
        n.logout_pending = 1;
        rc = save(s, &n);
        if (rc == 0) s->st = n;
        ts_wipe(&n, sizeof n);
        if (rc != 0) {
            s->logout_failed = 1;
            settle(s);
            return -1;
        }
    }
    s->logged_in = 0;
    s->refresh = 0;
    s->regen = 0;
    s->auth_url[0] = 0;
    s->relogin = RELOGIN_NONE;
    if (s->goal != GOAL_LOGOUT) {
        s->goal = GOAL_LOGOUT;
        s->reg_at = s->now;
        s->fatal = 0;
        s->backoff_ms = 0;
        s->retry_armed = 0;
    }
    settle(s);
    return 0;
}

int ts_sess_down(ts_sess *s)
{
    if (!s->nm_ok || !s->hostinfo) return 0;   /* out of memory at init: stays FAILED */
    s->down_failed = 0;
    s->logout_failed = 0;
    if (s->goal == GOAL_LOGOUT || s->st.logout_pending) {
        settle(s);   /* the logout finishes on its own and ends IDLE */
        return 0;
    }
    if (s->st.have_login && !s->st.down) {
        /* Persist it before anything changes, as ts_sess_logout does. */
        ts_state n = s->st;
        int rc;
        n.down = 1;
        rc = save(s, &n);
        if (rc == 0) s->st = n;
        ts_wipe(&n, sizeof n);
        if (rc != 0) {
            s->down_failed = 1;
            settle(s);
            return -1;
        }
    }
    s->goal = GOAL_NONE;
    s->fatal = 0;
    s->refresh = 0;
    s->auth_url[0] = 0;
    s->retry_armed = 0;
    s->rate_limited = 0;
    if (s->phase != PH_NONE) fail(s, FAIL_QUIET, "disconnected");
    settle(s);
    return 0;
}

int ts_sess_is_down(const ts_sess *s)
{
    return s->st.have_login && s->st.down;
}

ts_sess_state ts_sess_get_state(const ts_sess *s)
{
    return s->state;
}

const char *ts_sess_state_name(ts_sess_state st)
{
    switch (st) {
    case TS_SESS_IDLE: return "IDLE";
    case TS_SESS_CONNECTING: return "CONNECTING";
    case TS_SESS_NEED_LOGIN: return "NEED_LOGIN";
    case TS_SESS_AWAIT_APPROVAL: return "AWAIT_APPROVAL";
    case TS_SESS_RUNNING: return "RUNNING";
    case TS_SESS_BACKOFF: return "BACKOFF";
    case TS_SESS_FAILED: return "FAILED";
    }
    return "UNKNOWN";
}

/* Seconds since the Unix epoch to "YYYY-MM-DD HH:MM:SS" (proleptic Gregorian;
 * no time_t, which is 32 bits on PowerPC). */
static void format_utc(char *out, size_t cap, int64_t t)
{
    int64_t days = t / 86400, sec = t % 86400, z, era, doe, yoe, y, doy, mp, d, m;
    if (sec < 0) {
        sec += 86400;
        days--;
    }
    z = days + 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    snprintf(out, cap, "%04ld-%02ld-%02ld %02ld:%02ld:%02ld", (long)y, (long)m, (long)d,
             (long)(sec / 3600), (long)(sec / 60 % 60), (long)(sec % 60));
}

static long secs_until(const ts_sess *s, int64_t at)
{
    int64_t ms = at - s->now;
    if (ms < 0) ms = 0;
    return (long)((ms + 999) / 1000);
}

void ts_sess_status(const ts_sess *s, char *out, size_t cap)
{
    char detail[TS_SESS_URL_MAX + 400], extra[128];
    size_t len;
    if (cap == 0) return;
    detail[0] = 0;
    switch (s->state) {
    case TS_SESS_IDLE:
        snprintf(detail, sizeof detail, "%s", ts_sess_is_down(s) ? "logged in, disconnected (down)"
                 : s->logged_in ? "logged in, not connected"
                 : s->save_failed ? "logged out, but the node state could not be saved"
                 : s->logout_unconfirmed ? "logged out here; control was not reached, so the old key stays "
                                           "registered there until it expires"
                 : "logged out");
        break;
    case TS_SESS_CONNECTING:
        snprintf(detail, sizeof detail, "%s", s->goal == GOAL_LOGOUT ? "logging out" : "connecting to control");
        break;
    case TS_SESS_NEED_LOGIN:
        if (s->relogin == RELOGIN_EXPIRED) snprintf(detail, sizeof detail, "%s", EXPIRED_TEXT);
        else if (s->relogin == RELOGIN_REMOVED) snprintf(detail, sizeof detail, "%s", REMOVED_TEXT);
        else snprintf(detail, sizeof detail, "visit %s", s->auth_url);
        break;
    case TS_SESS_AWAIT_APPROVAL:
        snprintf(detail, sizeof detail, "logged in, waiting for device approval");
        break;
    case TS_SESS_RUNNING:
        snprintf(detail, sizeof detail, "connected");
        break;
    case TS_SESS_BACKOFF:
        snprintf(detail, sizeof detail, "%s; retrying in %ld s", s->reason, secs_until(s, s->retry_at));
        break;
    case TS_SESS_FAILED:
        snprintf(detail, sizeof detail, "%s", s->reason);
        break;
    }
    snprintf(out, cap, "%s: %s", ts_sess_state_name(s->state), detail);
    if (s->rate_limited && s->rate_until > s->now && s->phase != PH_NONE) {
        len = strlen(out);
        snprintf(out + len, cap - len, "; rate limited by control, retrying in %ld s", secs_until(s, s->rate_until));
    }
    if (s->logout_failed || s->down_failed) {
        len = strlen(out);
        snprintf(out + len, cap - len, "; %s", s->logout_failed ? LOGOUT_SAVE_TEXT : DOWN_SAVE_TEXT);
    }
    if (s->up_save_failed) {
        len = strlen(out);
        snprintf(out + len, cap - len, "; %s", UP_SAVE_TEXT);
    }
    if (s->login_save_failed) {
        len = strlen(out);
        snprintf(out + len, cap - len, "; %s", LOGIN_SAVE_TEXT);
    }
    len = strlen(out);
    snprintf(out + len, cap - len, "; %u peers", s->nm_ok ? (unsigned)s->nm.npeers : 0u);
    if (s->nm_ok && s->nm.have_self && s->nm.self.key_expiry != 0) {
        format_utc(extra, sizeof extra, s->nm.self.key_expiry == -1 ? 0 : s->nm.self.key_expiry);
        len = strlen(out);
        snprintf(out + len, cap - len, "; key expires %s UTC", extra);
    }
}

const char *ts_sess_login_url(const ts_sess *s)
{
    if (s->state != TS_SESS_NEED_LOGIN || !s->auth_url[0] || s->relogin != RELOGIN_NONE) return NULL;
    return s->auth_url;
}

/* The state's own problem; "" when it has none. */
static const char *state_problem(const ts_sess *s)
{
    switch (s->state) {
    case TS_SESS_BACKOFF:
    case TS_SESS_FAILED:
        return s->reason;
    case TS_SESS_NEED_LOGIN:
        if (s->relogin == RELOGIN_EXPIRED) return EXPIRED_TEXT;
        if (s->relogin == RELOGIN_REMOVED) return REMOVED_TEXT;
        return s->login_save_failed ? LOGIN_SAVE_TEXT : "";
    case TS_SESS_IDLE:
        if (s->save_failed) return "the node state could not be saved";
        if (s->logout_unconfirmed) return "control was not reached, so the old key stays registered there until it expires";
        return "";
    default:
        return s->login_save_failed ? LOGIN_SAVE_TEXT : "";
    }
}

/* The state's problem first (an expired key or a failure says what to do);
 * a failed logout, down or up save shows when the state has none. The status
 * line holds both. */
const char *ts_sess_problem(const ts_sess *s)
{
    const char *p = state_problem(s);
    if (p[0]) return p;
    if (s->logout_failed) return LOGOUT_SAVE_TEXT;
    if (s->down_failed) return DOWN_SAVE_TEXT;
    if (s->up_save_failed) return UP_SAVE_TEXT;
    return "";
}

int ts_sess_want_read(const ts_sess *s)
{
    return s->now >= s->sleep_until;
}

int ts_sess_exit_requested(const ts_sess *s, int *code)
{
    if (!s->have_exit) return 0;
    if (code) *code = s->exit_code;
    return 1;
}

const ts_netmap *ts_sess_netmap(const ts_sess *s)
{
    return &s->nm;
}

const ts_state *ts_sess_node_state(const ts_sess *s)
{
    return &s->st;
}

/* ---- Parsers ---------------------------------------------------------- */

static int json_bool(int *out, ts_json *j)
{
    ts_json_tok v;
    switch (ts_json_next(j, &v)) {
    case TS_JSON_TRUE: *out = 1; return 0;
    case TS_JSON_FALSE:
    case TS_JSON_NUL: *out = 0; return 0;
    default: return -1;
    }
}

int ts_reg_resp_parse(ts_reg_resp *r, const char *json, size_t len)
{
    ts_json j;
    ts_json_tok t, v;
    char key[32];
    memset(r, 0, sizeof *r);
    ts_json_init(&j, json, len);
    if (ts_json_next(&j, &t) != TS_JSON_OBJ_START) goto bad;
    for (;;) {
        ts_json_type ty = ts_json_next(&j, &t);
        if (ty == TS_JSON_OBJ_END) break;
        if (ty != TS_JSON_KEY) goto bad;
        if (ts_json_string(key, sizeof key, &t) < 0) key[0] = 0;   /* long: not one of ours */
        if (strcmp(key, "AuthURL") == 0) {
            ty = ts_json_next(&j, &v);
            if (ty == TS_JSON_NUL) r->auth_url[0] = 0;
            else if (ty != TS_JSON_STRING || ts_json_string(r->auth_url, sizeof r->auth_url, &v) < 0) goto bad;
        } else if (strcmp(key, "Error") == 0) {
            ty = ts_json_next(&j, &v);
            if (ty == TS_JSON_NUL) r->error[0] = 0;
            else if (ty != TS_JSON_STRING) goto bad;
            else if (ts_json_string(r->error, sizeof r->error, &v) < 0) {
                /* Too long to keep whole (or invalid, which the reader rejects). */
                if (v.rawlen == 0) goto bad;
                snprintf(r->error, sizeof r->error, "%.*s", (int)(v.rawlen < 120 ? v.rawlen : 120), v.raw);
            }
        } else if (strcmp(key, "NodeKeyExpired") == 0) {
            if (json_bool(&r->node_key_expired, &j) != 0) goto bad;
        } else if (strcmp(key, "MachineAuthorized") == 0) {
            if (json_bool(&r->machine_authorized, &j) != 0) goto bad;
        } else if (strcmp(key, "NodeKeySignature") == 0) {
            ty = ts_json_next(&j, &v);
            if (ty == TS_JSON_STRING) r->has_signature = v.rawlen > 0;
            else if (ty == TS_JSON_NUL) r->has_signature = 0;
            else goto bad;
        } else if (ts_json_skip(&j, &t) != 0) {
            goto bad;
        }
    }
    if (ts_json_next(&j, &t) != TS_JSON_END) goto bad;
    return 0;
bad:
    memset(r, 0, sizeof *r);
    return -1;
}

int ts_retry_after_parse(const char *v, size_t n)
{
    size_t i = 0, end = n;
    uint32_t secs = 0;
    while (i < end && (v[i] == ' ' || v[i] == '\t')) i++;
    while (end > i && (v[end - 1] == ' ' || v[end - 1] == '\t')) end--;
    if (i == end) return -1;
    for (; i < end; i++) {
        if (v[i] < '0' || v[i] > '9') return -1;
        secs = secs * 10 + (uint32_t)(v[i] - '0');
        if (secs > TS_SESS_RETRY_AFTER_VALID_S) return -1;   /* over an hour: not believed */
    }
    if (secs == 0) return -1;
    if (secs > TS_SESS_RETRY_AFTER_MAX_MS / 1000) return TS_SESS_RETRY_AFTER_MAX_MS;
    return (int)secs * 1000;
}

int ts_url_split(const char *url, char *authority, size_t acap, char *path, size_t pcap)
{
    const char *p, *a;
    size_t alen, i, rest;
    if (acap) authority[0] = 0;
    if (pcap) path[0] = 0;
    if (strncmp(url, "https://", 8) == 0) a = url + 8;
    else if (strncmp(url, "http://", 7) == 0) a = url + 7;
    else return -1;
    for (p = a; *p; p++)
        if (*p < '!' || *p > '~' || *p == '#') return -1;
    for (p = a; *p && *p != '/' && *p != '?'; p++)
        if (*p == '@') return -1;
    alen = (size_t)(p - a);
    rest = strlen(p);
    if (alen == 0 || alen >= acap) return -1;
    i = (rest == 0 || p[0] == '?') ? 1 : 0;   /* a leading '/' to add */
    if (i + rest >= pcap) return -1;
    memcpy(authority, a, alen);
    authority[alen] = 0;
    if (i) path[0] = '/';
    memcpy(path + i, p, rest + 1);
    return 0;
}
