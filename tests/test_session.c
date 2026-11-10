#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/control/session.h"
#include "../src/proto/encoding.h"

#include "fake_control.inc"

/* Invented names, keys and URLs only. */
#define HOSTINFO "{\"IPNVersion\":\"0.1.0-ppc\",\"OS\":\"macOS\",\"Hostname\":\"testhost\"}"
#define URL1 "https://login.example.test/a/one"
#define URL2 "https://login.example.test/a/two"
#define HA "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HB "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

#define SELF(auth, extra) \
    "{\"ID\":1,\"Name\":\"self.example.test.\",\"Key\":\"nodekey:" HA "\"," \
    "\"Addresses\":[\"100.64.0.1/32\"],\"MachineAuthorized\":" auth extra "}"
#define PEER(id, ip) "{\"ID\":" id ",\"Name\":\"p" id ".example.test.\",\"Key\":\"nodekey:" HB "\"," \
    "\"Addresses\":[\"" ip "/32\"],\"Online\":true,\"MachineAuthorized\":true}"
#define MAP_OK "{\"Node\":" SELF("true", "") ",\"Peers\":[" PEER("10", "100.64.0.10") "," PEER("11", "100.64.0.11") "]}"
#define MAP_UNAUTH "{\"Node\":" SELF("false", "") "}"

static fake F;
static ts_sess *S;

static void key_hex(char out[65], const uint8_t priv[32])
{
    uint8_t pub[32];
    ts_x25519_public(pub, priv);
    ts_hex_encode(out, 65, pub, 32);
}

static int has(const char *s, const char *sub)
{
    return s && strstr(s, sub) != NULL;
}

static int status_has(const char *sub)
{
    char st[512];
    ts_sess_status(S, st, sizeof st);
    return strstr(st, sub) != NULL;
}

static int is_followup(const fk_req *r) { return has(r->body, "\"Followup\""); }
static int is_logout(const fk_req *r) { return has(r->body, "1970-01-01T00:02:03Z"); }

static int reg_count(void) { return fk_count(&F, "/machine/register", NULL); }
static int followups(void) { return fk_count(&F, "/machine/register", "\"Followup\""); }
static int maps(void) { return fk_count(&F, "/machine/map", NULL); }

/* A handler for the usual login: register gives URL1, the Followup is held (or
 * approved), the map sends map_first. */
static void h_std(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) {
        if (is_logout(r)) fk_reply(f, r, 200, "{}");
        else if (is_followup(r)) {
            if (!f->hold_followup) fk_reply(f, r, 200, "{\"MachineAuthorized\":true}");
        } else fk_reply(f, r, 200, "{\"AuthURL\":\"" URL1 "\"}");
    } else if (strcmp(r->path, "/machine/map") == 0) {
        fk_headers(f, r, 200, NULL, 0, 0);
        if (f->map_first) fk_map_msg(f, r, f->map_first);
    }
}

/* Register succeeds at once; map sends map_first. */
static void h_auto(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) fk_reply(f, r, 200, "{\"MachineAuthorized\":true}");
    else if (strcmp(r->path, "/machine/map") == 0) {
        fk_headers(f, r, 200, NULL, 0, 0);
        if (f->map_first) fk_map_msg(f, r, f->map_first);
    }
}

static void begin(void (*handler)(fake *, fk_req *))
{
    fk_init(&F, S, HOSTINFO);
    F.handler = handler;
    fk_start(&F, HOSTINFO);
}

static void end(void)
{
    t_true("fake server saw no protocol violation", !F.bad);
    fk_free(&F);
}

/* Logged in, map streaming, RUNNING with two peers. */
static void begin_running(void)
{
    begin(h_auto);
    F.map_first = MAP_OK;
    ts_sess_up(S);
    fk_pump(&F);
}

static void test_register_authurl(void)
{
    char nk[65], want[128];
    fk_req *r;
    begin(h_std);
    F.hold_followup = 1;
    t_true("authurl: starts IDLE", ts_sess_get_state(S) == TS_SESS_IDLE);
    t_true("authurl: no URL yet", ts_sess_login_url(S) == NULL);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("authurl: first connect is port 80", F.nconnect == 1 && F.ports[0] == 80);
    t_true("authurl: NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    t_true("authurl: URL returned", ts_sess_login_url(S) && strcmp(ts_sess_login_url(S), URL1) == 0);
    t_true("authurl: status shows the URL", status_has(URL1) && status_has("NEED_LOGIN"));
    r = fk_last(&F, "/machine/register");
    t_true("authurl: one register", reg_count() == 1 && r != NULL);
    if (r) {
        key_hex(nk, F.st.node_priv);
        t_true("authurl: POST https", strcmp(r->method, "POST") == 0 && strcmp(r->scheme, "https") == 0);
        t_true("authurl: authority is the control host", strcmp(r->authority, TS_CONTROL_HOST) == 0);
        t_true("authurl: content-type", strcmp(r->ctype, "application/json") == 0);
        snprintf(want, sizeof want, "nodekey:%s", nk);
        t_true("authurl: one Ts-Lb with the node key", r->nlb == 1 && strcmp(r->lb[0], want) == 0);
        t_true("authurl: Version", has(r->body, "\"Version\":150"));
        snprintf(want, sizeof want, "\"NodeKey\":\"nodekey:%s\"", nk);
        t_true("authurl: NodeKey", has(r->body, want));
        t_true("authurl: zero Expiry", has(r->body, "\"Expiry\":\"0001-01-01T00:00:00Z\""));
        t_true("authurl: Hostinfo", has(r->body, "\"Hostinfo\":" HOSTINFO));
        t_true("authurl: Ephemeral false", has(r->body, "\"Ephemeral\":false"));
        t_true("authurl: no NLKey, OldNodeKey or Followup",
               !has(r->body, "NLKey") && !has(r->body, "OldNodeKey") && !has(r->body, "Followup"));
        t_true("authurl: body is one JSON object", r->body[0] == '{' && r->body[r->blen - 1] == '}');
    }
    /* The Followup waits for the 2-second floor after the register. */
    fk_advance(&F, 1900, 100);
    t_true("authurl: no Followup before the floor", followups() == 0);
    fk_advance(&F, 200, 100);
    t_true("authurl: Followup after the floor", followups() == 1);
    r = fk_last(&F, "/machine/register");
    t_true("authurl: Followup carries the URL", r && has(r->body, "\"Followup\":\"" URL1 "\""));

    /* Six hours of silence: exactly one Followup outstanding, connection kept by PINGs. */
    fk_advance(&F, 6 * 3600 * 1000LL, 5000);
    t_true("6h: still one Followup sent", followups() == 1);
    t_true("6h: and it is still open", fk_open(&F, "/machine/register") == 1);
    t_true("6h: still NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    t_true("6h: keepalive PINGs were sent", F.npings > 100);
    t_true("6h: never disconnected", F.ndisconnect == 0 && F.nconnect == 1);

    /* Approval: the held Followup returns success, and the map starts. */
    F.map_first = MAP_OK;
    r = fk_last(&F, "/machine/register");
    fk_reply(&F, r, 200, "{\"MachineAuthorized\":true}");
    fk_pump(&F);
    t_true("approved: map requested", maps() == 1);
    t_true("approved: RUNNING", ts_sess_get_state(S) == TS_SESS_RUNNING);
    t_true("approved: login saved", F.nsave >= 1 && F.saved.have_login == 1);
    t_true("approved: URL gone", ts_sess_login_url(S) == NULL);
    end();
}

/* Followups that end at once are spaced by the floor, doubling to the cap. */
static void h_quick(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) fk_reply(f, r, 200, "{\"AuthURL\":\"" URL1 "\"}");
}

static void test_followup_spacing(void)
{
    int64_t times[128], start;
    int i, n = 0, ok = 1, in10 = 0;
    begin(h_quick);
    ts_sess_up(S);
    fk_pump(&F);
    start = F.now;
    while (followups() < 100 && F.now - start < 10LL * 3600 * 1000) fk_advance(&F, 500, 500);
    for (i = 0; i < F.nreq && n < 128; i++)
        if (strcmp(F.req[i].path, "/machine/register") == 0) times[n++] = F.req[i].at;
    t_true("quick: 100 Followups reached", followups() == 100 && n == 101);
    for (i = 1; i < n; i++) {
        int64_t want = 2000LL << (i - 1 < 5 ? i - 1 : 5);
        if (want > TS_SESS_FOLLOWUP_MAX_MS) want = TS_SESS_FOLLOWUP_MAX_MS;
        if (times[i] - times[i - 1] < want) ok = 0;
        if (times[i] - start <= 600000) in10++;
    }
    t_true("quick: every gap at least the floor and the backoff", ok);
    /* 2+4+8+16+32 s, then one per minute: at most 5 + 9 in ten minutes. */
    t_true("quick: backoff-limited count in 10 minutes", in10 <= 14 && in10 >= 10);
    t_true("quick: one connection throughout", F.nconnect == 1);
    t_true("quick: still NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    end();
}

/* A held Followup the server resets counts as an ending too. */
static void test_followup_reset(void)
{
    int64_t t;
    begin(h_std);
    F.hold_followup = 1;
    ts_sess_up(S);
    fk_pump(&F);
    fk_advance(&F, 2000, 100);
    t_true("fu reset: one Followup", followups() == 1);
    fk_advance(&F, 10000, 1000);
    t = F.now;
    fk_rst(&F, fk_last(&F, "/machine/register"), 2);
    fk_pump(&F);
    t_true("fu reset: still NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN && ts_sess_login_url(S) != NULL);
    while (followups() < 2 && F.now - t < 60000) fk_advance(&F, 100, 100);
    t_true("fu reset: next Followup at once (the last send was long ago)", followups() == 2 && F.now - t <= 100);
    fk_rst(&F, fk_last(&F, "/machine/register"), 2);
    fk_pump(&F);
    t = F.now;
    while (followups() < 3 && F.now - t < 60000) fk_advance(&F, 100, 100);
    t_true("fu reset: a quick ending waits the doubled interval", followups() == 3 && F.now - t >= 7900 && F.now - t <= 8000);
    t_true("fu reset: same connection", F.nconnect == 1);
    end();
}

/* Every Followup answered with NodeKeyExpired: no 2-second cycle of new keys. */
static int g_nke;
static void h_followup_expired(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") != 0) return;
    if (is_followup(r)) {
        g_nke++;
        fk_reply(f, r, 200, "{\"NodeKeyExpired\":true}");
    } else {
        fk_reply(f, r, 200, "{\"AuthURL\":\"" URL1 "\"}");
    }
}

static void test_followup_expired_loop(void)
{
    int i, gaps_ok = 1;
    int64_t start;
    g_nke = 0;
    begin(h_followup_expired);
    ts_sess_up(S);
    fk_pump(&F);
    start = F.now;
    while (g_nke < 100 && F.now - start < 24LL * 3600 * 1000) fk_advance(&F, 1000, 1000);
    t_true("fu expired: 100 rounds happened", g_nke == 100);
    for (i = 1; i < F.nsave && i < 512; i++)
        if (F.save_at[i] - F.save_at[i - 1] < TS_SESS_REGEN_MIN_MS) gaps_ok = 0;
    t_true("fu expired: at most one new key a minute", gaps_ok);
    t_true("fu expired: saves bounded by the rounds", F.nsave >= 1 && F.nsave <= 100);
    /* Two register sends per round (followup, regenerated register), plus the
     * first; the rounds took at least a minute each. */
    t_true("fu expired: sends bounded", reg_count() <= 2 * 100 + 2);
    t_true("fu expired: spread over time", F.now - start >= 99LL * TS_SESS_REGEN_MIN_MS);
    /* The Followup spacing grows on its own, so the regeneration guard (which
     * drops the connection) is only reached in the first rounds. */
    t_true("fu expired: followup spacing does the pacing", F.ndisconnect <= 20);
    end();
}

/* NodeKeyExpired: a new key, saved before the register that carries OldNodeKey. */
static void h_expired(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") != 0) return;
    if (has(r->body, "OldNodeKey")) fk_reply(f, r, 200, "{\"AuthURL\":\"" URL2 "\"}");
    else fk_reply(f, r, 200, "{\"NodeKeyExpired\":true,\"User\":{\"ID\":5},\"Login\":{}}");
}

static void test_node_key_expired(void)
{
    char oldk[65], newk[65], want[128];
    fk_req *r;
    begin(h_expired);
    F.hold_followup = 1;
    ts_sess_up(S);
    fk_pump(&F);
    t_true("expired: two registers", reg_count() == 2);
    t_true("expired: state saved once", F.nsave == 1);
    t_true("expired: saved before the second register", F.reqs_at_save == 1);
    t_true("expired: old key kept", F.saved.have_old_node &&
           memcmp(F.saved.old_node_priv, F.st.node_priv, 32) == 0);
    t_true("expired: new node key", memcmp(F.saved.node_priv, F.st.node_priv, 32) != 0);
    t_true("expired: machine key unchanged", memcmp(F.saved.machine_priv, F.st.machine_priv, 32) == 0);
    t_true("expired: disco key unchanged", memcmp(F.saved.disco_priv, F.st.disco_priv, 32) == 0);
    t_true("expired: not logged in yet", F.saved.have_login == 0);
    key_hex(oldk, F.st.node_priv);
    key_hex(newk, F.saved.node_priv);
    r = fk_last(&F, "/machine/register");
    if (r) {
        snprintf(want, sizeof want, "\"OldNodeKey\":\"nodekey:%s\"", oldk);
        t_true("expired: OldNodeKey sent", has(r->body, want));
        snprintf(want, sizeof want, "\"NodeKey\":\"nodekey:%s\"", newk);
        t_true("expired: new NodeKey sent", has(r->body, want));
        snprintf(want, sizeof want, "nodekey:%s", oldk);
        t_true("expired: Ts-Lb old then new", r->nlb == 2 && strcmp(r->lb[0], want) == 0 &&
               strncmp(r->lb[1], "nodekey:", 8) == 0 && strcmp(r->lb[1] + 8, newk) == 0);
    }
    t_true("expired: NEED_LOGIN with the new URL", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN &&
           ts_sess_login_url(S) && strcmp(ts_sess_login_url(S), URL2) == 0);
    t_true("expired: same connection", F.nconnect == 1);
    end();
}

/* A server that keeps saying NodeKeyExpired does not cause a loop. */
static void h_always_expired(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) fk_reply(f, r, 200, "{\"NodeKeyExpired\":true}");
}

static void test_expired_twice(void)
{
    begin(h_always_expired);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("expired twice: two registers, then stop", reg_count() == 2);
    t_true("expired twice: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF);
    end();
}

static void test_logout(void)
{
    char nk[65], want[128];
    uint8_t before[32];
    fk_req *r;
    begin_running();
    t_true("logout: RUNNING first", ts_sess_get_state(S) == TS_SESS_RUNNING);
    memcpy(before, ts_sess_node_state(S)->node_priv, 32);
    key_hex(nk, before);
    F.handler = h_std;
    ts_sess_logout(S);
    fk_pump(&F);
    r = fk_last(&F, "/machine/register");
    t_true("logout: register sent", r != NULL && is_logout(r));
    if (r) {
        t_true("logout: far-past expiry", has(r->body, "\"Expiry\":\"1970-01-01T00:02:03Z\""));
        snprintf(want, sizeof want, "\"NodeKey\":\"nodekey:%s\"", nk);
        t_true("logout: current node key", has(r->body, want));
    }
    t_true("logout: map stream cancelled", fk_last(&F, "/machine/map") && fk_last(&F, "/machine/map")->reset);
    t_true("logout: IDLE", ts_sess_get_state(S) == TS_SESS_IDLE);
    t_true("logout: login cleared and saved", F.saved.have_login == 0 && !F.saved.have_old_node);
    t_true("logout: fresh node key", memcmp(F.saved.node_priv, before, 32) != 0);
    t_true("logout: machine key kept", memcmp(F.saved.machine_priv, F.st.machine_priv, 32) == 0);
    t_true("logout: disconnected", !F.up && F.ndisconnect == 1);
    fk_advance(&F, 120000, 1000);
    t_true("logout: stays IDLE", ts_sess_get_state(S) == TS_SESS_IDLE && F.nconnect == 1);
    end();
}

static void h_hold_logout(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0 && !is_logout(r)) fk_reply(f, r, 200, "{\"AuthURL\":\"" URL2 "\"}");
}

/* ts_sess_up while the logout is in flight: the logout completes, then a new login. */
static void test_up_during_logout(void)
{
    fk_req *r;
    begin_running();
    F.handler = h_hold_logout;
    ts_sess_logout(S);
    fk_pump(&F);
    r = fk_last(&F, "/machine/register");
    t_true("up in logout: logout sent", r && is_logout(r) && !r->closed);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("up in logout: no map meanwhile", maps() == 1);
    fk_reply(&F, r, 200, "{}");
    fk_pump(&F);
    t_true("up in logout: login cleared", F.saved.have_login == 0);
    r = fk_last(&F, "/machine/register");
    t_true("up in logout: new register on the same connection", r && !is_logout(r) && F.nconnect == 1);
    t_true("up in logout: NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN &&
           ts_sess_login_url(S) && strcmp(ts_sess_login_url(S), URL2) == 0);
    end();
}

/* A failed send closes the connection through io->disconnect. */
static void test_send_failure(void)
{
    begin_running();
    F.send_fail = 1;
    F.auto_ping_ack = 0;
    fk_advance(&F, 90000, 1000);         /* the keepalive PING is the next send */
    t_true("send fail: one disconnect", F.ndisconnect == 1 && !F.up);
    t_true("send fail: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF && status_has("sending"));
    t_true("send fail: no protocol violation", !F.bad);
    end();

    /* On port 80 before the handshake: disconnect, and only then 443. */
    begin(h_std);
    F.send_fail = 1;
    ts_sess_up(S);
    fk_pump(&F);
    t_true("send fail on 80: then 443", F.nconnect == 2 && F.ports[0] == 80 && F.ports[1] == 443);
    t_true("send fail on 80: each connection disconnected", F.ndisconnect == 2);
    t_true("send fail on 80: 443 not opened while 80 was", !F.bad);
    t_true("send fail on 80: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF);
    end();
}

static void h_err_logout(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) fk_reply(f, r, 500, "internal error");
}

/* Starting while logged in: one register of the current key, then the map. */
static void h_refresh(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) {
        if (has(r->body, "OldNodeKey")) fk_reply(f, r, 200, "{\"AuthURL\":\"" URL2 "\"}");
        else if (f->hold_followup) fk_reply(f, r, 200, "{\"NodeKeyExpired\":true}");
        else fk_reply(f, r, 200, "{\"MachineAuthorized\":true}");
    } else if (strcmp(r->path, "/machine/map") == 0) {
        fk_headers(f, r, 200, NULL, 0, 0);
        fk_map_msg(f, r, MAP_OK);
    }
}

static void test_refresh_on_start(void)
{
    char nk[65], want[128];
    fk_req *r;
    fk_init(&F, S, HOSTINFO);
    F.handler = h_refresh;
    F.st.have_login = 1;
    fk_start(&F, HOSTINFO);
    ts_sess_up(S);
    fk_pump(&F);
    key_hex(nk, F.st.node_priv);
    r = F.nreq ? &F.req[0] : NULL;
    t_true("refresh: first request is a register", r && strcmp(r->path, "/machine/register") == 0);
    if (r) {
        snprintf(want, sizeof want, "\"NodeKey\":\"nodekey:%s\"", nk);
        t_true("refresh: current key, zero expiry", has(r->body, want) && has(r->body, "\"Expiry\":\"0001-01-01T00:00:00Z\""));
        t_true("refresh: no Followup or OldNodeKey", !has(r->body, "Followup") && !has(r->body, "OldNodeKey"));
        t_true("refresh: Hostinfo sent", has(r->body, "\"Hostinfo\":" HOSTINFO));
    }
    t_true("refresh: then the map, RUNNING", reg_count() == 1 && maps() == 1 && ts_sess_get_state(S) == TS_SESS_RUNNING);
    t_true("refresh: no key change", F.nsave == 0);
    fk_close(&F, "reset");
    fk_advance(&F, 2000, 100);
    t_true("refresh: not on reconnect", reg_count() == 1 && maps() == 2 && ts_sess_get_state(S) == TS_SESS_RUNNING);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("refresh: not on up while running", reg_count() == 1);
    end();

    /* The refresh is answered NodeKeyExpired: a new key and a new login. */
    fk_init(&F, S, HOSTINFO);
    F.handler = h_refresh;
    F.hold_followup = 1;
    F.st.have_login = 1;
    fk_start(&F, HOSTINFO);
    ts_sess_up(S);
    fk_pump(&F);
    key_hex(nk, F.st.node_priv);
    r = fk_last(&F, "/machine/register");
    snprintf(want, sizeof want, "\"OldNodeKey\":\"nodekey:%s\"", nk);
    t_true("refresh expired: register with OldNodeKey", reg_count() == 2 && r && has(r->body, want));
    t_true("refresh expired: saved first, logged out", F.reqs_at_save == 1 && F.saved.have_login == 0 &&
           memcmp(F.saved.old_node_priv, F.st.node_priv, 32) == 0);
    t_true("refresh expired: NEED_LOGIN, no map", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN && maps() == 0 &&
           ts_sess_login_url(S) && strcmp(ts_sess_login_url(S), URL2) == 0);
    /* Logout now: the old (expired) key and the new key awaiting login are
     * both dropped from the saved state. */
    {
        uint8_t newkey[32];
        int saves = F.nsave;
        memcpy(newkey, ts_sess_node_state(S)->node_priv, 32);
        ts_sess_logout(S);
        fk_pump(&F);
        t_true("refresh expired logout: saved", F.nsave > saves);
        t_true("refresh expired logout: no old key kept", !F.saved.have_old_node && F.saved.have_login == 0);
        t_true("refresh expired logout: neither key kept", memcmp(F.saved.node_priv, F.st.node_priv, 32) != 0 &&
               memcmp(F.saved.node_priv, newkey, 32) != 0);
        t_true("refresh expired logout: IDLE", ts_sess_get_state(S) == TS_SESS_IDLE);
    }
    end();
}

/* Logout with a saved login while control cannot be reached on either port:
 * the login is forgotten here anyway, and nothing is retried. */
static void test_logout_unreachable(void)
{
    char st[512];
    fk_init(&F, S, HOSTINFO);
    F.handler = h_std;
    F.st.have_login = 1;
    F.refuse_all = 1;
    fk_start(&F, HOSTINFO);
    ts_sess_logout(S);
    fk_pump(&F);
    t_true("logout unreachable: tried 80 then 443", F.nconnect == 2 && F.ports[0] == 80 && F.ports[1] == 443);
    t_true("logout unreachable: login cleared and saved", F.nsave >= 1 && F.saved.have_login == 0 &&
           !F.saved.have_old_node && memcmp(F.saved.node_priv, F.st.node_priv, 32) != 0);
    t_true("logout unreachable: IDLE", ts_sess_get_state(S) == TS_SESS_IDLE);
    ts_sess_status(S, st, sizeof st);
    t_true("logout unreachable: status says control was not told", strstr(st, "not reached") != NULL);
    fk_advance(&F, 120000, 1000);
    t_true("logout unreachable: not retried", F.nconnect == 2 && ts_sess_get_state(S) == TS_SESS_IDLE);
    end();

    /* Control answers the logout with an error: also forgotten here. */
    begin_running();
    F.handler = h_err_logout;
    ts_sess_logout(S);
    fk_pump(&F);
    t_true("logout error reply: login cleared", F.saved.have_login == 0 && ts_sess_get_state(S) == TS_SESS_IDLE);
    fk_advance(&F, 120000, 1000);
    t_true("logout error reply: not retried", fk_count(&F, "/machine/register", "1970") == 1);
    end();
}

static void test_logout_not_logged_in(void)
{
    begin(h_std);
    F.hold_followup = 1;
    ts_sess_up(S);
    fk_pump(&F);
    ts_sess_logout(S);
    fk_pump(&F);
    t_true("logout before login: IDLE", ts_sess_get_state(S) == TS_SESS_IDLE);
    t_true("logout before login: nothing sent to control", fk_count(&F, "/machine/register", "1970") == 0);
    t_true("logout before login: URL forgotten", ts_sess_login_url(S) == NULL);
    end();
}

/* The refresh of a saved login is answered with an AuthURL. */
static void h_refresh_url(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) {
        if (is_logout(r)) fk_reply(f, r, 200, "{}");
        else if (!is_followup(r)) fk_reply(f, r, 200, "{\"AuthURL\":\"" URL2 "\"}");
    }
}

/* Logged in on disk, the refresh needs a login (NEED_LOGIN), then logout: the
 * saved key is still expired at control and the saved login is cleared. */
static void test_logout_after_refresh_url(void)
{
    char nk[65], want[128];
    uint8_t before[32];
    fk_req *r;
    fk_init(&F, S, HOSTINFO);
    F.handler = h_refresh_url;
    F.st.have_login = 1;
    fk_start(&F, HOSTINFO);
    memcpy(before, F.st.node_priv, 32);
    key_hex(nk, before);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("refresh url logout: NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN &&
           ts_sess_login_url(S) != NULL);
    ts_sess_logout(S);
    fk_pump(&F);
    r = fk_last(&F, "/machine/register");
    t_true("refresh url logout: logout register sent", r && is_logout(r));
    if (r) {
        snprintf(want, sizeof want, "\"NodeKey\":\"nodekey:%s\"", nk);
        t_true("refresh url logout: persisted key expired", has(r->body, want));
    }
    t_true("refresh url logout: login cleared and saved", F.nsave >= 1 && F.saved.have_login == 0 &&
           !F.saved.have_old_node && memcmp(F.saved.node_priv, before, 32) != 0);
    t_true("refresh url logout: IDLE, no URL", ts_sess_get_state(S) == TS_SESS_IDLE && ts_sess_login_url(S) == NULL);
    end();
}

/* Approval arrives through the map. */
static void h_unauth(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) fk_reply(f, r, 200, "{\"MachineAuthorized\":false}");
    else if (strcmp(r->path, "/machine/map") == 0) {
        fk_headers(f, r, 200, NULL, 0, 0);
        fk_map_msg(f, r, MAP_UNAUTH);
    }
}

static void test_approval(void)
{
    char nk[65], dk[65], want[128];
    fk_req *r;
    begin(h_unauth);
    F.rx_chunk = 7;                      /* every boundary split */
    F.early = "{\"nodeKeyChallenge\":\"chal\"}";
    ts_sess_up(S);
    fk_pump(&F);
    t_true("approval: AWAIT_APPROVAL", ts_sess_get_state(S) == TS_SESS_AWAIT_APPROVAL);
    t_true("approval: status says so", status_has("AWAIT_APPROVAL"));
    t_true("approval: login saved", F.saved.have_login == 1);
    r = fk_last(&F, "/machine/map");
    t_true("approval: one map request", maps() == 1 && r != NULL);
    if (r) {
        key_hex(nk, F.st.node_priv);
        key_hex(dk, F.st.disco_priv);
        t_true("map: POST", strcmp(r->method, "POST") == 0 && strcmp(r->ctype, "application/json") == 0);
        snprintf(want, sizeof want, "nodekey:%s", nk);
        t_true("map: Ts-Lb", r->nlb == 1 && strcmp(r->lb[0], want) == 0);
        t_true("map: Version", has(r->body, "\"Version\":150"));
        t_true("map: KeepAlive", has(r->body, "\"KeepAlive\":true"));
        t_true("map: Stream", has(r->body, "\"Stream\":true"));
        snprintf(want, sizeof want, "\"NodeKey\":\"nodekey:%s\"", nk);
        t_true("map: NodeKey", has(r->body, want));
        snprintf(want, sizeof want, "\"DiscoKey\":\"discokey:%s\"", dk);
        t_true("map: DiscoKey", has(r->body, want));
        t_true("map: Hostinfo", has(r->body, "\"Hostinfo\":" HOSTINFO));
        t_true("map: no Compress", !has(r->body, "Compress"));
        fk_map_msg(&F, r, "{\"KeepAlive\":true}");
        fk_pump(&F);
        t_true("approval: KeepAlive changes nothing", ts_sess_get_state(S) == TS_SESS_AWAIT_APPROVAL);
        fk_map_msg(&F, r, "{\"Node\":" SELF("true", "") "}");
        fk_pump(&F);
    }
    t_true("approval: RUNNING once authorized", ts_sess_get_state(S) == TS_SESS_RUNNING);
    t_true("approval: status RUNNING, 0 peers", status_has("RUNNING") && status_has("0 peers"));
    end();
}

static void test_status(void)
{
    begin_running();
    t_true("status: RUNNING", ts_sess_get_state(S) == TS_SESS_RUNNING);
    t_true("status: state name and peer count", status_has("RUNNING") && status_has("2 peers"));
    t_true("status: no key text", !status_has(HA));
    t_true("status: state names", strcmp(ts_sess_state_name(TS_SESS_AWAIT_APPROVAL), "AWAIT_APPROVAL") == 0 &&
           strcmp(ts_sess_state_name(TS_SESS_BACKOFF), "BACKOFF") == 0);
    end();
    begin(h_auto);
    F.map_first = "{\"Node\":" SELF("true", ",\"KeyExpiry\":\"2027-03-04T05:06:07Z\"") "}";
    ts_sess_up(S);
    fk_pump(&F);
    t_true("status: key expiry shown", status_has("key expires 2027-03-04 05:06:07 UTC"));
    end();
}

static void test_goaway(void)
{
    char before[65], want[128];
    fk_req *r;
    int64_t t;
    begin_running();
    key_hex(before, F.st.node_priv);
    r = fk_last(&F, "/machine/map");
    fk_goaway(&F, r->sid, 0);
    fk_pump(&F);
    t_true("goaway: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF);
    t_true("goaway: disconnected", F.ndisconnect == 1);
    t = F.now;
    while (F.nconnect < 2 && F.now - t < 5000) fk_advance(&F, 10, 10);
    t_true("goaway: reconnect after 0.75 to 1 s", F.nconnect == 2 && F.now - t >= 750 && F.now - t <= 1000);
    t_true("goaway: RUNNING again", ts_sess_get_state(S) == TS_SESS_RUNNING);
    t_true("goaway: no new register", reg_count() == 1);
    r = fk_last(&F, "/machine/map");
    snprintf(want, sizeof want, "\"NodeKey\":\"nodekey:%s\"", before);
    t_true("goaway: same node key", maps() == 2 && r && has(r->body, want) && r->conn == F.conn);
    end();
}

static void test_backoff_growth(void)
{
    int64_t t, last = 0, want = 1000;
    int i, ok = 1;
    begin(h_auto);
    F.refuse_all = 1;
    ts_sess_up(S);
    fk_pump(&F);
    t_true("backoff: 80 then 443", F.nconnect == 2 && F.ports[0] == 80 && F.ports[1] == 443);
    t_true("backoff: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF);
    t_true("backoff: status has reason and wait", status_has("BACKOFF") && status_has("refused") && status_has("retrying in"));
    for (i = 0; i < 9; i++) {
        int n = F.nconnect;
        t = F.now;
        while (F.nconnect == n && F.now - t < 120000) fk_advance(&F, 10, 10);
        last = F.now - t;
        if (last < want - want / 4 || last > want) ok = 0;
        want = want * 2 > TS_SESS_BACKOFF_MAX_MS ? TS_SESS_BACKOFF_MAX_MS : want * 2;
    }
    t_true("backoff: doubling to 60 s with jitter of at most 25%", ok);
    t_true("backoff: capped", last <= 60000 && last >= 45000);
    /* Recovery, and a reset after 60 s of RUNNING. */
    F.refuse_all = 0;
    F.map_first = MAP_OK;
    fk_advance(&F, 61000, 1000);
    t_true("backoff: RUNNING after recovery", ts_sess_get_state(S) == TS_SESS_RUNNING);
    fk_advance(&F, 61000, 1000);
    fk_close(&F, "reset by peer");
    t = F.now;
    {
        int n = F.nconnect;
        while (F.nconnect == n && F.now - t < 120000) fk_advance(&F, 10, 10);
    }
    t_true("backoff: reset to 1 s after 60 s RUNNING", F.now - t <= 1000);
    end();
}

static void test_keepalive(void)
{
    begin_running();
    F.auto_ping_ack = 0;
    fk_advance(&F, 89000, 1000);
    t_true("keepalive: no PING before 90 s", F.npings == 0);
    fk_advance(&F, 1000, 1000);
    t_true("keepalive: PING at 90 s", F.npings == 1);
    fk_advance(&F, 29000, 1000);
    t_true("keepalive: still connected at 119 s", F.ndisconnect == 0 && F.up);
    fk_advance(&F, 1000, 1000);
    t_true("keepalive: disconnect after 30 s more", F.ndisconnect == 1);
    t_true("keepalive: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF);
    t_true("keepalive: one PING only", F.npings == 1);
    end();

    /* A PING answered keeps the connection. */
    begin_running();
    fk_advance(&F, 600000, 1000);
    t_true("keepalive: answered PINGs keep it", F.ndisconnect == 0 && F.npings >= 5);
    end();
}

/* Rate limits. */
static const char *g_ra;          /* Retry-After to send, NULL for none */
static int g_ra_status;
static int g_ra_count;            /* answer this many registers with the limit */

static void h_ratelimit(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") != 0) return;
    if (g_ra_count > 0) {
        const char *h[2];
        g_ra_count--;
        h[0] = "retry-after";
        h[1] = g_ra;
        fk_headers(f, r, g_ra_status, h, g_ra ? 1 : 0, 0);
        fk_data(f, r, "slow down", 9, 1);
    } else {
        fk_reply(f, r, 200, "{\"AuthURL\":\"" URL1 "\"}");
    }
}

/* Returns the ms until the second register (or -1), checking the connection stays. */
static int64_t rl_wait(int status, const char *ra, int64_t limit)
{
    int64_t t;
    g_ra = ra;
    g_ra_status = status;
    g_ra_count = 1;
    begin(h_ratelimit);
    ts_sess_up(S);
    fk_pump(&F);
    t = F.now;
    while (reg_count() < 2 && F.now - t < limit) fk_advance(&F, 100, 100);
    return reg_count() == 2 ? F.now - t : -1;
}

static void test_rate_limits(void)
{
    int64_t w;
    g_ra = "30";
    g_ra_status = 429;
    g_ra_count = 1;
    begin(h_ratelimit);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("429: status says rate limited", status_has("rate limited by control, retrying in 30 s"));
    t_true("429: no body text in status", !status_has("slow down"));
    fk_advance(&F, 29900, 100);
    t_true("429: no retry before 30 s", reg_count() == 1);
    fk_advance(&F, 100, 100);
    t_true("429: retry at 30 s", reg_count() == 2);
    t_true("429: connection kept", F.nconnect == 1 && F.ndisconnect == 0);
    t_true("429: then NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    end();

    w = rl_wait(429, "900", 400000);
    t_true("429 900 s: waits the 300 s cap", w == 300000);
    end();
    w = rl_wait(503, "20", 100000);
    t_true("503 with Retry-After: waits 20 s", w == 20000 && F.ndisconnect == 0);
    end();
    {
        /* No usable Retry-After: a random 5 to 10 s, the connection kept, the
         * backoff untouched (upstream's parseRateLimitError). */
        static const char *const fallback[] = {
            "Wed, 21 Oct 2037 07:28:00 GMT", "0", "soon", "7200", "", NULL,
        };
        size_t i;
        for (i = 0; i < sizeof fallback / sizeof fallback[0]; i++) {
            char label[96];
            w = rl_wait(429, fallback[i], 100000);
            snprintf(label, sizeof label, "429 Retry-After \"%s\": random 5 to 10 s", fallback[i] ? fallback[i] : "(none)");
            t_true(label, w >= 5000 && w <= 10000 && F.ndisconnect == 0 && S->backoff_ms == 0);
            end();
        }
    }
    w = rl_wait(503, "", 100000);
    t_true("503 with an empty Retry-After: an ordinary failure", w >= 700 && w <= 1000 && F.ndisconnect == 1);
    end();
    w = rl_wait(503, NULL, 100000);
    t_true("503 without Retry-After: an ordinary failure", w >= 700 && w <= 1000 && F.ndisconnect == 1 && F.nconnect == 2);
    end();
}

/* Map 429 and 404. */
static int g_map_status;
static void h_map_status(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) {
        if (has(r->body, "OldNodeKey")) fk_reply(f, r, 200, "{\"AuthURL\":\"" URL2 "\"}");
        else fk_reply(f, r, 200, "{\"MachineAuthorized\":true}");
    } else if (strcmp(r->path, "/machine/map") == 0) {
        if (g_map_status == 429) {
            static const char *const h[] = { "retry-after", "12" };
            g_map_status = 200;
            fk_headers(f, r, 429, h, 1, 1);
        } else if (g_map_status == 404) {
            fk_reply(f, r, 404, "node not found");
        } else {
            fk_headers(f, r, 200, NULL, 0, 0);
            fk_map_msg(f, r, MAP_OK);
        }
    }
}

static void test_map_status(void)
{
    int64_t t;
    fk_req *r;
    g_map_status = 429;
    begin(h_map_status);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("map 429: one map", maps() == 1 && status_has("rate limited"));
    fk_advance(&F, 11900, 100);
    t_true("map 429: none before 12 s", maps() == 1);
    fk_advance(&F, 100, 100);
    t_true("map 429: retried at 12 s, RUNNING", maps() == 2 && ts_sess_get_state(S) == TS_SESS_RUNNING);
    end();

    g_map_status = 404;
    begin(h_map_status);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("map 404: NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    t_true("map 404: removed text", status_has("This device has been removed from the tailnet"));
    t_true("map 404: no URL", ts_sess_login_url(S) == NULL);
    t = F.now;
    while (maps() < 2 && F.now - t < 5000) fk_advance(&F, 100, 100);
    t_true("map 404: keeps retrying at the backoff", maps() == 2 && F.nconnect == 2);
    t_true("map 404: still NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    ts_sess_up(S);
    fk_pump(&F);
    r = fk_last(&F, "/machine/register");
    t_true("map 404 then up: register with OldNodeKey", r && has(r->body, "OldNodeKey"));
    t_true("map 404 then up: saved first", F.saved.have_old_node && F.reqs_at_save == F.nreq - 1);
    t_true("map 404 then up: NEED_LOGIN with URL", ts_sess_login_url(S) && strcmp(ts_sess_login_url(S), URL2) == 0);
    end();

    /* Removed, then control knows us again: the map recovers. */
    g_map_status = 404;
    begin(h_map_status);
    ts_sess_up(S);
    fk_pump(&F);
    g_map_status = 200;
    fk_advance(&F, 2000, 100);
    t_true("map 404 then 200: RUNNING", ts_sess_get_state(S) == TS_SESS_RUNNING);
    end();
}

static void test_port_fallback(void)
{
    begin(h_std);
    F.hold_followup = 1;
    F.refuse_port = 80;
    ts_sess_up(S);
    fk_pump(&F);
    t_true("fallback: 80 then 443", F.nconnect == 2 && F.ports[0] == 80 && F.ports[1] == 443);
    t_true("fallback: logged in over 443", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    end();
}

static void test_connect_timeout(void)
{
    begin(h_std);
    ts_sess_up(S);
    /* The connection never completes: the pump is not run. */
    F.connect_pending = 0;
    fk_advance(&F, 29000, 1000);
    t_true("timeout: still waiting on 80", F.nconnect == 1);
    fk_advance(&F, 1000, 1000);
    t_true("timeout: tries 443 after 30 s", F.nconnect == 2 && F.ports[1] == 443);
    end();
}

static void test_handshake_error(void)
{
    begin(h_std);
    F.hs_error = "client version too old";
    ts_sess_up(S);
    fk_pump(&F);
    t_true("hs error: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF);
    t_true("hs error: message in status", status_has("client version too old"));
    t_true("hs error: no fallback to 443", F.nconnect == 1);
    end();
}

static void test_ping_request(void)
{
    fk_req *m, *h;
    int i, heads;
    begin_running();
    m = fk_last(&F, "/machine/map");
    fk_map_msg(&F, m, "{\"PingRequest\":{\"URL\":\"https://ping.example.test/p/1?x=y\",\"URLIsNoise\":true}}");
    fk_pump(&F);
    h = fk_last(&F, "/p/1?x=y");
    t_true("ping: one HEAD", fk_count(&F, "/p/1?x=y", NULL) == 1 && h != NULL);
    if (h) {
        t_true("ping: HEAD over https", strcmp(h->method, "HEAD") == 0 && strcmp(h->scheme, "https") == 0);
        t_true("ping: authority from the URL", strcmp(h->authority, "ping.example.test") == 0);
        t_true("ping: no body or extra headers", h->blen == 0 && h->nfields == 0 && h->complete);
        t_true("ping: on its own stream", h->sid != m->sid);
    }
    fk_map_msg(&F, m, "{\"PingRequest\":{\"URL\":\"https://ping.example.test/p/1?x=y\",\"URLIsNoise\":true}}");
    fk_pump(&F);
    t_true("ping: same URL ignored", fk_count(&F, "/p/1?x=y", NULL) == 1);
    fk_map_msg(&F, m, "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p/2\",\"URLIsNoise\":true}}");
    fk_pump(&F);
    t_true("ping: KeepAlive carrying one answered", fk_count(&F, "/p/2", NULL) == 1);
    fk_map_msg(&F, m, "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p/3\",\"URLIsNoise\":true,\"Types\":\"c2n\"}}");
    fk_map_msg(&F, m, "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p/4\"}}");
    fk_map_msg(&F, m, "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p/5\",\"URLIsNoise\":true,\"Types\":\"TSMP\"}}");
    fk_pump(&F);
    t_true("ping: c2n, plain TLS and TSMP ignored", fk_count(&F, "/p/3", NULL) == 0 &&
           fk_count(&F, "/p/4", NULL) == 0 && fk_count(&F, "/p/5", NULL) == 0);
    t_true("ping: pending cleared", !ts_sess_netmap(S)->ping.pending);
    fk_advance(&F, 14000, 1000);
    t_true("ping: HEAD open before 15 s", fk_last(&F, "/p/2") && !fk_last(&F, "/p/2")->reset);
    fk_advance(&F, 2000, 1000);
    t_true("ping: unanswered HEAD cancelled after 15 s", fk_last(&F, "/p/2") && fk_last(&F, "/p/2")->reset);
    t_true("ping: map unaffected", ts_sess_get_state(S) == TS_SESS_RUNNING && !m->closed);
    /* An answered ping, and one per URL across a reconnect too. */
    fk_reply(&F, fk_last(&F, "/p/1?x=y"), 200, NULL);
    fk_map_msg(&F, m, "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p/6\",\"URLIsNoise\":true}}");
    fk_pump(&F);
    t_true("ping: a new URL answered", fk_count(&F, "/p/6", NULL) == 1);
    fk_reply(&F, fk_last(&F, "/p/6"), 204, NULL);
    fk_pump(&F);
    fk_close(&F, "reset");
    fk_advance(&F, 2000, 100);
    m = fk_last(&F, "/machine/map");
    t_true("ping: reconnected", F.nconnect == 2 && ts_sess_get_state(S) == TS_SESS_RUNNING);
    fk_map_msg(&F, m, "{\"KeepAlive\":true,\"PingRequest\":{\"URL\":\"https://ping.example.test/p/6\",\"URLIsNoise\":true}}");
    fk_pump(&F);
    t_true("ping: last URL survives a reconnect", fk_count(&F, "/p/6", NULL) == 1);
    heads = 0;
    for (i = 0; i < F.nreq; i++)
        if (strcmp(F.req[i].method, "HEAD") == 0) heads++;
    t_true("ping: three HEADs in all", heads == 3);
    end();
}

static void test_debug_exit(void)
{
    int code = -1;
    begin_running();
    t_true("exit: none yet", ts_sess_exit_requested(S, &code) == 0);
    fk_map_msg(&F, fk_last(&F, "/machine/map"), "{\"Debug\":{\"Exit\":3}}");
    fk_pump(&F);
    t_true("exit: FAILED", ts_sess_get_state(S) == TS_SESS_FAILED);
    t_true("exit: code given", ts_sess_exit_requested(S, &code) == 1 && code == 3);
    t_true("exit: message", status_has("FAILED") && status_has("exit"));
    t_true("exit: disconnected", F.ndisconnect == 1);
    fk_advance(&F, 600000, 5000);
    t_true("exit: no retry", F.nconnect == 1);
    end();
}

static void test_tailnet_lock(void)
{
    begin_running();
    fk_map_msg(&F, fk_last(&F, "/machine/map"), "{\"TKAInfo\":{\"Head\":\"h\"}}");
    fk_pump(&F);
    t_true("tka: FAILED", ts_sess_get_state(S) == TS_SESS_FAILED);
    t_true("tka: message", status_has("Tailnet Lock") && status_has("not supported"));
    fk_advance(&F, 600000, 5000);
    t_true("tka: no retry", F.nconnect == 1 && ts_sess_get_state(S) == TS_SESS_FAILED);
    end();
}

static void h_nks(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0) fk_reply(f, r, 200, "{\"NodeKeySignature\":\"AAEC\"}");
}

static void test_tailnet_lock_register(void)
{
    begin(h_nks);
    ts_sess_up(S);
    fk_pump(&F);
    fk_advance(&F, 120000, 5000);
    t_true("nks: FAILED without re-registering", ts_sess_get_state(S) == TS_SESS_FAILED && reg_count() == 1);
    t_true("nks: message", status_has("Tailnet Lock"));
    end();
}

static void test_rejected_message(void)
{
    begin_running();
    fk_map_msg(&F, fk_last(&F, "/machine/map"), "{\"Peers\":[{\"ID\":\"x\"}]}");
    fk_pump(&F);
    t_true("rejected: BACKOFF", ts_sess_get_state(S) == TS_SESS_BACKOFF);
    t_true("rejected: disconnected", F.ndisconnect == 1);
    fk_advance(&F, 1000, 100);
    t_true("rejected: reconnected with a fresh map", F.nconnect == 2 && maps() == 2);
    t_true("rejected: RUNNING again", ts_sess_get_state(S) == TS_SESS_RUNNING && status_has("2 peers"));
    end();
}

static void test_self_expired(void)
{
    char oldk[65], want[128];
    fk_req *r;
    begin_running();
    F.handler = h_std;
    F.hold_followup = 1;
    fk_map_msg(&F, fk_last(&F, "/machine/map"), "{\"Node\":" SELF("true", ",\"Expired\":true") "}");
    fk_pump(&F);
    t_true("self expired: NEED_LOGIN", ts_sess_get_state(S) == TS_SESS_NEED_LOGIN);
    t_true("self expired: says so", status_has("expired"));
    fk_advance(&F, 300000, 5000);
    t_true("self expired: waits for up", F.nconnect == 1 && reg_count() == 1);
    ts_sess_up(S);
    fk_pump(&F);
    r = fk_last(&F, "/machine/register");
    key_hex(oldk, F.st.node_priv);
    snprintf(want, sizeof want, "\"OldNodeKey\":\"nodekey:%s\"", oldk);
    t_true("self expired: register with OldNodeKey", reg_count() == 2 && r && has(r->body, want));
    t_true("self expired: saved before it", F.saved.have_old_node && F.reqs_at_save == F.nreq - 1 &&
           memcmp(F.saved.old_node_priv, F.st.node_priv, 32) == 0);
    t_true("self expired: NEED_LOGIN with URL", ts_sess_login_url(S) && strcmp(ts_sess_login_url(S), URL1) == 0);
    t_true("self expired: new key saved as not logged in", F.saved.have_login == 0);
    {
        /* A restart before the operator visits the URL registers again, with the
         * key that last logged in as OldNodeKey, and does not map. */
        ts_state saved = F.saved;
        end();
        fk_init(&F, S, HOSTINFO);
        F.handler = h_std;
        F.hold_followup = 1;
        key_hex(oldk, F.st.node_priv);
        F.st = saved;
        fk_start(&F, HOSTINFO);
        ts_sess_up(S);
        fk_pump(&F);
        snprintf(want, sizeof want, "\"OldNodeKey\":\"nodekey:%s\"", oldk);
        t_true("self expired restart: first request is a register with the original OldNodeKey",
               F.nreq >= 1 && strcmp(F.req[0].path, "/machine/register") == 0 && has(F.req[0].body, want));
        t_true("self expired restart: no map", maps() == 0);
    }
    end();
}

/* A login URL is shown to the operator: only https and printable ASCII. */
static const char *g_bad_url;
static void h_bad_url(fake *f, fk_req *r)
{
    char body[256];
    if (strcmp(r->path, "/machine/register") != 0) return;
    snprintf(body, sizeof body, "{\"AuthURL\":\"%s\"}", g_bad_url);
    fk_reply(f, r, 200, body);
}

static void test_bad_auth_url(void)
{
    static const char *const bad[] = {
        "https://login.example.test/a/\\u001b]2;x\\u0007", "http://login.example.test/a/b",
        "https://login.example.test/a b", "https://login.example.test/\\u00e9", "https://",
    };
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char label[80], st[512];
        size_t k;
        int clean = 1;
        g_bad_url = bad[i];
        begin(h_bad_url);
        ts_sess_up(S);
        fk_pump(&F);
        ts_sess_status(S, st, sizeof st);
        for (k = 0; st[k]; k++)
            if ((unsigned char)st[k] < 0x20 || (unsigned char)st[k] > 0x7e) clean = 0;
        snprintf(label, sizeof label, "bad auth url %u: refused, BACKOFF", (unsigned)i);
        t_true(label, ts_sess_get_state(S) == TS_SESS_BACKOFF && ts_sess_login_url(S) == NULL);
        snprintf(label, sizeof label, "bad auth url %u: reason in status, printable", (unsigned)i);
        t_true(label, status_has("invalid login URL") && clean && !status_has("login.example.test"));
        end();
    }
}

/* Control's error texts reach status only as printable ASCII. */
static void h_err_text(fake *f, fk_req *r)
{
    if (strcmp(r->path, "/machine/register") == 0)
        fk_reply(f, r, 200, "{\"Error\":\"bad\\u001b[31mthing\\u0007\"}");
}

static void test_server_text_clean(void)
{
    char st[512];
    size_t k;
    int clean = 1;
    begin(h_err_text);
    ts_sess_up(S);
    fk_pump(&F);
    ts_sess_status(S, st, sizeof st);
    for (k = 0; st[k]; k++)
        if ((unsigned char)st[k] < 0x20 || (unsigned char)st[k] > 0x7e) clean = 0;
    t_true("error text: shown without control bytes", clean && status_has("control: bad?[31mthing?"));
    end();
    begin(h_std);
    F.hs_error = "no\x1b[2Jway";
    ts_sess_up(S);
    fk_pump(&F);
    t_true("handshake text: control bytes replaced", status_has("no?[2Jway"));
    end();
}

static void test_sleep(void)
{
    begin_running();
    F.auto_ping_ack = 0;
    fk_map_msg(&F, fk_last(&F, "/machine/map"), "{\"Debug\":{\"SleepSeconds\":100}}");
    fk_pump(&F);
    t_true("sleep: stop reading", ts_sess_want_read(S) == 0);
    fk_advance(&F, 95000, 1000);
    t_true("sleep: no keepalive PING while paused", F.npings == 0 && F.ndisconnect == 0);
    fk_map_msg(&F, fk_last(&F, "/machine/map"), "{\"Peers\":[" PEER("12", "100.64.0.12") "]}");
    fk_pump(&F);
    t_true("sleep: nothing read while paused", ts_sess_netmap(S)->npeers == 2);
    fk_advance(&F, 6000, 1000);
    t_true("sleep: reading again", ts_sess_want_read(S) == 1);
    t_true("sleep: buffered message applied", ts_sess_netmap(S)->npeers == 1);
    end();
}

static void test_window_update(void)
{
    static char big[300000];
    fk_req *m;
    int i;
    begin_running();
    m = fk_last(&F, "/machine/map");
    F.nwinupd = 0;
    F.winupd_bytes = 0;
    for (i = 0; i < 6; i++) {
        size_t n = (size_t)snprintf(big, sizeof big, "{\"DERPMap\":{\"Junk\":\"");
        memset(big + n, 'a', 280000);
        n += 280000;
        snprintf(big + n, sizeof big - n, "\"},\"Peers\":[" PEER("%d", "100.64.1.%d") "]}", 20 + i, 20 + i, 20 + i);
        fk_map_msg(&F, m, big);
        fk_pump(&F);
    }
    t_true("window: more than 1 MiB sent", F.data_sent > 1600000);
    t_true("window: WINDOW_UPDATEs returned credit", F.winupd_bytes >= 1000000);
    t_true("window: all of it delivered", fk_out_slot(&F, m->sid, 0) && fk_out_slot(&F, m->sid, 0)->len == 0);
    t_true("window: last message applied", ts_sess_netmap(S)->npeers == 1 &&
           ts_sess_netmap(S)->peers[0].id == 25);
    t_true("window: RUNNING", ts_sess_get_state(S) == TS_SESS_RUNNING);
    end();
}

static void test_save_failure(void)
{
    begin(h_always_expired);
    F.save_fail = 1;
    ts_sess_up(S);
    fk_pump(&F);
    t_true("save failure: no register with an unsaved key", reg_count() == 1);
    t_true("save failure: BACKOFF with reason", ts_sess_get_state(S) == TS_SESS_BACKOFF && status_has("save"));
    t_true("save failure: key unchanged", memcmp(ts_sess_node_state(S)->node_priv, F.st.node_priv, 32) == 0);
    end();
}

static int parse_str(ts_reg_resp *r, const char *s)
{
    return ts_reg_resp_parse(r, s, strlen(s));
}

static void test_parsers(void)
{
    ts_reg_resp r;
    char a[64], p[64];
    static const char *const bad[] = {
        "", "{", "[]", "{\"AuthURL\":5}", "{\"NodeKeyExpired\":\"yes\"}", "{\"Error\":{}}",
        "{\"AuthURL\":\"x\"} x",
    };
    size_t i;
    const char *ok = "{\"User\":{\"ID\":1,\"X\":[1,2]},\"Login\":{},\"NodeKeyExpired\":false,"
                     "\"MachineAuthorized\":true,\"AuthURL\":\"https://login.example.test/a/b\\u0021\","
                     "\"NodeKeySignature\":null,\"Error\":\"\"}";
    t_true("reg parse: ok", ts_reg_resp_parse(&r, ok, strlen(ok)) == 0);
    t_true("reg parse: fields", r.machine_authorized && !r.node_key_expired && !r.has_signature &&
           strcmp(r.auth_url, "https://login.example.test/a/b!") == 0 && r.error[0] == 0);
    t_true("reg parse: signature", parse_str(&r, "{\"NodeKeySignature\":\"AA==\"}") == 0 && r.has_signature);
    t_true("reg parse: empty signature", parse_str(&r, "{\"NodeKeySignature\":\"\"}") == 0 && !r.has_signature);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char label[64];
        snprintf(label, sizeof label, "reg parse: bad %u", (unsigned)i);
        t_true(label, ts_reg_resp_parse(&r, bad[i], strlen(bad[i])) == -1);
    }
    t_true("retry-after: 30", ts_retry_after_parse("30", 2) == 30000);
    t_true("retry-after: spaces", ts_retry_after_parse(" 7 ", 3) == 7000);
    t_true("retry-after: clamped to 300 s", ts_retry_after_parse("900", 3) == TS_SESS_RETRY_AFTER_MAX_MS &&
           ts_retry_after_parse("3600", 4) == TS_SESS_RETRY_AFTER_MAX_MS);
    t_true("retry-after: 299 s kept", ts_retry_after_parse("299", 3) == 299000);
    t_true("retry-after: over an hour refused", ts_retry_after_parse("3601", 4) == -1 &&
           ts_retry_after_parse("7200", 4) == -1);
    t_true("retry-after: huge", ts_retry_after_parse("99999999999999999999999", 23) == -1);
    t_true("retry-after: zero", ts_retry_after_parse("0", 1) == -1);
    t_true("retry-after: negative", ts_retry_after_parse("-5", 2) == -1);
    t_true("retry-after: empty", ts_retry_after_parse("", 0) == -1);
    t_true("retry-after: unit", ts_retry_after_parse("30s", 3) == -1);
    t_true("retry-after: date", ts_retry_after_parse("Wed, 21 Oct 2037 07:28:00 GMT", 29) == -1);
    t_true("url: split", ts_url_split("https://ping.example.test/p?q=1", a, sizeof a, p, sizeof p) == 0 &&
           strcmp(a, "ping.example.test") == 0 && strcmp(p, "/p?q=1") == 0);
    t_true("url: port, no path", ts_url_split("http://h.example.test:8443", a, sizeof a, p, sizeof p) == 0 &&
           strcmp(a, "h.example.test:8443") == 0 && strcmp(p, "/") == 0);
    t_true("url: query only", ts_url_split("https://h?x", a, sizeof a, p, sizeof p) == 0 &&
           strcmp(a, "h") == 0 && strcmp(p, "/?x") == 0);
    t_true("url: other scheme", ts_url_split("ftp://h/", a, sizeof a, p, sizeof p) == -1 && a[0] == 0);
    t_true("url: userinfo", ts_url_split("https://u@h/", a, sizeof a, p, sizeof p) == -1);
    t_true("url: no host", ts_url_split("https:///x", a, sizeof a, p, sizeof p) == -1);
    t_true("url: space", ts_url_split("https://h/a b", a, sizeof a, p, sizeof p) == -1);
    t_true("url: too long", ts_url_split("https://h/0123456789", a, sizeof a, p, 8) == -1);
}

static void test_set_host(void)
{
    fk_init(&F, S, HOSTINFO);
    F.handler = h_std;
    F.hold_followup = 1;
    ts_sess_init(S, &F.st, &F.io, &F, F.control_pub, HOSTINFO);
    t_true("host: bad name refused", ts_sess_set_host(S, "bad host") == -1 && ts_sess_set_host(S, "") == -1);
    t_true("host: set", ts_sess_set_host(S, "control.example.test") == 0);
    ts_sess_tick(S, (uint64_t)F.now);
    ts_sess_up(S);
    fk_pump(&F);
    t_true("host: used for :authority", fk_last(&F, "/machine/register") &&
           strcmp(fk_last(&F, "/machine/register")->authority, "control.example.test") == 0);
    end();
}

void test_session(void)
{
    S = (ts_sess *)calloc(1, sizeof *S);
    if (!S) abort();
    test_parsers();
    test_register_authurl();
    test_followup_spacing();
    test_followup_reset();
    test_node_key_expired();
    test_expired_twice();
    test_logout();
    test_logout_not_logged_in();
    test_send_failure();
    test_refresh_on_start();
    test_logout_after_refresh_url();
    test_logout_unreachable();
    test_followup_expired_loop();
    test_up_during_logout();
    test_approval();
    test_status();
    test_goaway();
    test_backoff_growth();
    test_keepalive();
    test_rate_limits();
    test_map_status();
    test_port_fallback();
    test_connect_timeout();
    test_handshake_error();
    test_ping_request();
    test_debug_exit();
    test_tailnet_lock();
    test_tailnet_lock_register();
    test_rejected_message();
    test_self_expired();
    test_bad_auth_url();
    test_server_text_clean();
    test_sleep();
    test_window_update();
    test_save_failure();
    test_set_host();
    free(S);
}
