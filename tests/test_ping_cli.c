#include "harness.h"

#include <stdio.h>

#include <stdlib.h>
#include <string.h>

#include "../src/cli/ping.h"

/* The pure parts of tsppc ping: flags, Go's duration format, the pong line,
 * the not-running gate and name resolution. */

static ts_reply g_r;
static ts_reply_peer g_peers[TS_MAX_PEERS];

static int args(const char *a0, const char *a1, const char *a2, const char *a3, const char *a4, ts_ping_opts *o,
                char *err)
{
    char *v[6];
    int n = 0;
    const char *in[5];
    int i;
    in[0] = a0;
    in[1] = a1;
    in[2] = a2;
    in[3] = a3;
    in[4] = a4;
    for (i = 0; i < 5 && in[i]; i++) v[n++] = (char *)in[i];
    v[n] = NULL;
    return ts_ping_parse_args(n, v, o, err, 128);
}

static void test_flags(void)
{
    ts_ping_opts o;
    char err[128];
    t_true("ping args: defaults", args("peer", 0, 0, 0, 0, &o, err) == 0 && o.count == 10 && o.timeout_ms == 5000 &&
                                      o.until_direct == 1 && strcmp(o.target, "peer") == 0);
    t_true("ping args: -c N", args("-c", "3", "peer", 0, 0, &o, err) == 0 && o.count == 3);
    t_true("ping args: --c=0 is no limit", args("--c=0", "peer", 0, 0, 0, &o, err) == 0 && o.count == 0);
    t_true("ping args: --timeout 5s", args("--timeout", "2s", "peer", 0, 0, &o, err) == 0 && o.timeout_ms == 2000);
    t_true("ping args: --timeout=500ms", args("--timeout=500ms", "peer", 0, 0, 0, &o, err) == 0 && o.timeout_ms == 500);
    t_true("ping args: -timeout 1.5s", args("-timeout", "1.5s", "peer", 0, 0, &o, err) == 0 && o.timeout_ms == 1500);
    t_true("ping args: --until-direct=false", args("--until-direct=false", "peer", 0, 0, 0, &o, err) == 0 &&
                                                  o.until_direct == 0);
    t_true("ping args: --until-direct alone is true", args("--until-direct", "peer", 0, 0, 0, &o, err) == 0 &&
                                                         o.until_direct == 1);
    t_true("ping args: Go's bool spellings", args("--until-direct=0", "x", 0, 0, 0, &o, err) == 0 && !o.until_direct &&
                                                 args("--until-direct=TRUE", "x", 0, 0, 0, &o, err) == 0 &&
                                                 o.until_direct && args("--until-direct=f", "x", 0, 0, 0, &o, err) == 0 &&
                                                 !o.until_direct);
    t_true("ping args: all together", args("-c", "1", "--timeout=100ms", "--until-direct=false", "100.64.0.2", &o, err) == 0 &&
                                          o.count == 1 && o.timeout_ms == 100 && !o.until_direct &&
                                          strcmp(o.target, "100.64.0.2") == 0);
    t_true("ping args: -- ends the flags", args("--", "-odd", 0, 0, 0, &o, err) == 0 && strcmp(o.target, "-odd") == 0);
    t_true("ping args: no target", args(0, 0, 0, 0, 0, &o, err) == -1 && args("-c", "1", 0, 0, 0, &o, err) == -1);
    t_true("ping args: two targets", args("a", "b", 0, 0, 0, &o, err) == -1);
    t_true("ping args: a flag after the target is a second target", args("a", "-c", "1", 0, 0, &o, err) == -1);
    t_true("ping args: unknown flag", args("--verbose", "a", 0, 0, 0, &o, err) == -1 && strstr(err, "verbose"));
    t_true("ping args: -c without a value", args("-c", 0, 0, 0, 0, &o, err) == -1);
    t_true("ping args: bad counts", args("-c", "x", "a", 0, 0, &o, err) == -1 && args("-c", "1x", "a", 0, 0, &o, err) == -1 &&
                                        args("-c=", "a", 0, 0, 0, &o, err) == -1 &&
                                        args("-c", "99999999999999999999999", "a", 0, 0, &o, err) == -1);
    t_true("ping args: negative count is no limit, as Go", args("-c", "-1", "a", 0, 0, &o, err) == 0 && o.count == -1);
    t_true("ping args: timeout with no unit", args("--timeout", "5", "a", 0, 0, &o, err) == -1);
    t_true("ping args: timeout out of range", args("--timeout", "11s", "a", 0, 0, &o, err) == -1 &&
                                                  args("--timeout", "99ms", "a", 0, 0, &o, err) == -1 &&
                                                  strstr(err, "timeout"));
    t_true("ping args: timeout bounds", args("--timeout=10s", "a", 0, 0, 0, &o, err) == 0 && o.timeout_ms == 10000 &&
                                            args("--timeout=100ms", "a", 0, 0, 0, &o, err) == 0);
    t_true("ping args: bool flag with a bad value", args("--until-direct=maybe", "a", 0, 0, 0, &o, err) == -1);
    t_true("ping args: an empty target", args("", 0, 0, 0, 0, &o, err) == -1);
    t_true("ping args: a lone dash is a target", args("-", 0, 0, 0, 0, &o, err) == 0 && strcmp(o.target, "-") == 0);
}

static void test_duration_parse(void)
{
    uint32_t ms = 1;
    t_true("dur parse: 5s", ts_ping_parse_duration("5s", &ms) == 0 && ms == 5000);
    t_true("dur parse: 500ms", ts_ping_parse_duration("500ms", &ms) == 0 && ms == 500);
    t_true("dur parse: 1.5s", ts_ping_parse_duration("1.5s", &ms) == 0 && ms == 1500);
    t_true("dur parse: 0.25s", ts_ping_parse_duration("0.25s", &ms) == 0 && ms == 250);
    t_true("dur parse: .5s", ts_ping_parse_duration(".5s", &ms) == 0 && ms == 500);
    t_true("dur parse: 1m", ts_ping_parse_duration("1m", &ms) == 0 && ms == 60000);
    t_true("dur parse: 0", ts_ping_parse_duration("0", &ms) == 0 && ms == 0);
    t_true("dur parse: 1.9999ms drops the rest", ts_ping_parse_duration("1.9999ms", &ms) == 0 && ms == 1);
    t_true("dur parse: bad", ts_ping_parse_duration("5", &ms) == -1 && ts_ping_parse_duration("", &ms) == -1 &&
                                 ts_ping_parse_duration("s", &ms) == -1 && ts_ping_parse_duration("5x", &ms) == -1 &&
                                 ts_ping_parse_duration("5ss", &ms) == -1 && ts_ping_parse_duration("-5s", &ms) == -1 &&
                                 ts_ping_parse_duration("1.2.3s", &ms) == -1 && ts_ping_parse_duration(".s", &ms) == -1 &&
                                 ts_ping_parse_duration("5 s", &ms) == -1 && ts_ping_parse_duration("11m", &ms) == -1 &&
                                 ts_ping_parse_duration("99999999999999999999s", &ms) == -1 &&
                                 ts_ping_parse_duration("5h", &ms) == -1 && ts_ping_parse_duration("5us", &ms) == -1);
}

static int dur_is(uint64_t us, const char *want)
{
    char b[32];
    ts_ping_duration(b, sizeof b, us);
    if (strcmp(b, want) != 0) printf("  duration %llu us: got %s, want %s\n", (unsigned long long)us, b, want);
    return strcmp(b, want) == 0;
}

static void test_duration_format(void)
{
    t_true("dur: 0s", dur_is(0, "0s"));
    t_true("dur: under half a ms is 0s", dur_is(499, "0s"));
    t_true("dur: half a ms rounds up", dur_is(500, "1ms"));
    t_true("dur: 23ms", dur_is(23000, "23ms") && dur_is(23400, "23ms") && dur_is(22500, "23ms"));
    t_true("dur: 999ms", dur_is(999000, "999ms") && dur_is(999499, "999ms"));
    t_true("dur: 999.5 ms rounds to 1s", dur_is(999500, "1s"));
    t_true("dur: 1s", dur_is(1000000, "1s"));
    t_true("dur: 1.5s", dur_is(1500000, "1.5s"));
    t_true("dur: 1.05s", dur_is(1050000, "1.05s"));
    t_true("dur: 1.001s", dur_is(1001000, "1.001s"));
    t_true("dur: 12.345s", dur_is(12345000, "12.345s") && dur_is(12345499, "12.345s"));
    t_true("dur: 59.999s", dur_is(59999000, "59.999s"));
    t_true("dur: 1m0s", dur_is(60000000, "1m0s"));
    t_true("dur: 1m0.5s", dur_is(60500000, "1m0.5s"));
    t_true("dur: 1h0m0s", dur_is(3600000000u, "1h0m0s"));
    t_true("dur: 1h1m1.25s", dur_is(3661250000u, "1h1m1.25s"));
    t_true("dur: the largest latency", dur_is(4294967295u, "1h11m34.967s"));
    {
        char small[4];
        ts_ping_duration(small, sizeof small, 12345000);
        t_true("dur: cut to the buffer, terminated", strlen(small) == 3);
    }
}

static void test_lines(void)
{
    char b[160];
    ts_ping_first_label(b, sizeof b, "peer.example.ts.net.");
    t_true("label: first", strcmp(b, "peer") == 0);
    ts_ping_first_label(b, sizeof b, "solo");
    t_true("label: no dot", strcmp(b, "solo") == 0);
    ts_ping_first_label(b, sizeof b, "");
    t_true("label: empty", strcmp(b, "") == 0);
    ts_ping_pong_line(b, sizeof b, "peer", 0x64400002u, "nyc", 23456);
    t_true("pong line", strcmp(b, "pong from peer (100.64.0.2) via DERP(nyc) in 23ms") == 0);
    ts_ping_pong_line(b, sizeof b, "peer", 0x64400002u, "-", 1500000);
    t_true("pong line: unknown code, seconds", strcmp(b, "pong from peer (100.64.0.2) via DERP() in 1.5s") == 0);
    ts_ping_pong_line(b, sizeof b, "", 0x64400002u, "nyc", 23456);
    t_true("pong line: no label, the IP", strcmp(b, "pong from 100.64.0.2 (100.64.0.2) via DERP(nyc) in 23ms") == 0);
    ts_ping_pong_line(b, sizeof b, "p", 0x64400002u, "nyc", 200);
    t_true("pong line: 0s", strcmp(b, "pong from p (100.64.0.2) via DERP(nyc) in 0s") == 0);
}

static int parse(const char *s)
{
    return ts_reply_parse(&g_r, g_peers, s, strlen(s));
}

static int not_running(const char *reply, const char *want)
{
    char b[256];
    int rc;
    if (parse(reply) != 0) return 0;
    rc = ts_ping_not_running(&g_r, b, sizeof b);
    if (!want) return rc == 0;
    if (rc != 1 || strcmp(b, want) != 0) printf("  not running: got %d %s\n", rc, b);
    return rc == 1 && strcmp(b, want) == 0;
}

static void test_not_running(void)
{
    t_true("gate: RUNNING", not_running("ok\nstate RUNNING\nlogin yes\nwanted up\n", NULL));
    t_true("gate: CONNECTING and BACKOFF are starting", not_running("ok\nstate CONNECTING\nlogin yes\nwanted up\n", NULL) &&
                                                          not_running("ok\nstate BACKOFF\nlogin yes\nwanted up\n", NULL));
    t_true("gate: down is stopped", not_running("ok\nstate IDLE\nlogin yes\nwanted down\n", "Tailscale is stopped."));
    t_true("gate: logged out", not_running("ok\nstate IDLE\nlogin no\nwanted down\n", "Logged out."));
    t_true("gate: logged out, leaving", not_running("ok\nstate IDLE\nlogin leaving\nwanted down\n", "Logged out."));
    t_true("gate: needs login, with the URL",
           not_running("ok\nstate NEED_LOGIN\nlogin no\nwanted up\nurl https://login.example.test/a/x\n",
                       "Logged out.\nLog in at: https://login.example.test/a/x"));
    t_true("gate: awaiting approval", not_running("ok\nstate AWAIT_APPROVAL\nlogin yes\nwanted up\n",
                                                  "Machine is not yet approved by tailnet admin."));
    t_true("gate: failed", not_running("ok\nstate FAILED\nlogin yes\nwanted up\n", "unexpected state: FAILED"));
    t_true("gate: idle but wanted up is starting", not_running("ok\nstate IDLE\nlogin yes\nwanted up\n", NULL));
}

static const char STATUS[] = "ok\nstate RUNNING\nlogin yes\nwanted up\nself me.example.test.\nip 100.64.0.1\n"
                             "peer 100.64.0.2 online peer.example.test.\n"
                             "peer 100.64.0.3 offline Other.Example.Test.\n"
                             "peer - online noip.example.test.\n"
                             "peer 100.64.0.5 online peer.elsewhere.test.\n";

static int resolve(const char *arg, uint32_t *ip, char *msg)
{
    *ip = 0;
    msg[0] = 0;
    return ts_ping_resolve(&g_r, arg, ip, msg, 128);
}

static void test_resolve(void)
{
    uint32_t ip;
    char msg[128], label[64];
    t_true("resolve: status parses", parse(STATUS) == 0 && g_r.npeers == 4);
    t_true("resolve: an IP", resolve("100.64.0.9", &ip, msg) == TS_PING_PEER && ip == 0x64400009u);
    t_true("resolve: our own IP", resolve("100.64.0.1", &ip, msg) == TS_PING_SELF && ip == 0x64400001u);
    t_true("resolve: first label", resolve("peer", &ip, msg) == TS_PING_PEER && ip == 0x64400002u);
    t_true("resolve: first label, any case", resolve("PEER", &ip, msg) == TS_PING_PEER && ip == 0x64400002u);
    t_true("resolve: full name, with and without the dot",
           resolve("other.example.test.", &ip, msg) == TS_PING_PEER && ip == 0x64400003u &&
               resolve("OTHER.example.test", &ip, msg) == TS_PING_PEER && ip == 0x64400003u);
    t_true("resolve: full name picks the right one of two first labels",
           resolve("peer.elsewhere.test", &ip, msg) == TS_PING_PEER && ip == 0x64400005u);
    t_true("resolve: the self name", resolve("me", &ip, msg) == TS_PING_SELF && ip == 0x64400001u &&
                                         resolve("me.example.test.", &ip, msg) == TS_PING_SELF);
    t_true("resolve: a peer without an IP", resolve("noip", &ip, msg) == TS_PING_NOT_FOUND &&
                                                strcmp(msg, "node found but lacks an IP") == 0);
    t_true("resolve: unknown name", resolve("nobody", &ip, msg) == TS_PING_NOT_FOUND && strstr(msg, "nobody"));
    t_true("resolve: a partial label is no match", resolve("pee", &ip, msg) == TS_PING_NOT_FOUND &&
                                                       resolve("peer.example", &ip, msg) == TS_PING_NOT_FOUND);
    t_true("resolve: an IPv6 literal", resolve("fd7a:115c:a1e0::1", &ip, msg) == TS_PING_NOT_FOUND && msg[0]);
    t_true("resolve: a leading-zero address is a name, not found", resolve("100.64.0.02", &ip, msg) == TS_PING_NOT_FOUND);
    ts_ping_peer_label(&g_r, 0x64400003u, label, sizeof label);
    t_true("label of a peer by IP", strcmp(label, "Other") == 0);
    ts_ping_peer_label(&g_r, 0x64400009u, label, sizeof label);
    t_true("label of no peer is empty", label[0] == 0);
}

void test_ping_cli(void)
{
    test_flags();
    test_duration_parse();
    test_duration_format();
    test_lines();
    test_not_running();
    test_resolve();
}
