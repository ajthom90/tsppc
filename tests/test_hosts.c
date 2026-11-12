#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/names/hosts.h"

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define B TS_HOSTS_BEGIN
#define E TS_HOSTS_END

static int nameok(const char *n, const char *want_fqdn, const char *want_short)
{
    char f[254], s[64];
    int rc = ts_hosts_name_ok(n, f, sizeof f, s, sizeof s);
    if (!want_fqdn) return rc == -1;
    return rc == 0 && strcmp(f, want_fqdn) == 0 && strcmp(s, want_short) == 0;
}

static void test_name_ok(void)
{
    char f[254], s[64], big[300], lab[100];
    char fixed[8] = {'a', 0, 'b', 0, 0, 0, 0, 0};

    t_true("name fqdn with dot", nameok("peer-a.example.ts.net.", "peer-a.example.ts.net", "peer-a"));
    t_true("name fqdn no dot", nameok("peer-a.example.ts.net", "peer-a.example.ts.net", "peer-a"));
    t_true("name lowered", nameok("Peer-A.Example.TS.net.", "peer-a.example.ts.net", "peer-a"));
    t_true("name one label", nameok("host1", "host1", "host1"));
    t_true("name empty", nameok("", NULL, NULL));
    t_true("name dot", nameok(".", NULL, NULL));
    t_true("name two dots", nameok("..", NULL, NULL));
    t_true("name double trailing dot", nameok("a.b..", NULL, NULL));
    t_true("name leading dot", nameok(".a", NULL, NULL));
    t_true("name empty label", nameok("a..b", NULL, NULL));
    memset(big, 'a', sizeof big);
    memset(lab, 'a', sizeof lab);
    /* 253 bytes: 63 + . + 63 + . + 63 + . + 61 */
    memset(big, 'a', 253);
    big[63] = big[127] = big[191] = '.';
    big[253] = 0;
    t_true("name 253 ok", ts_hosts_name_ok(big, f, sizeof f, s, sizeof s) == 0 && strlen(f) == 253 && strlen(s) == 63);
    big[253] = 'a';
    big[254] = 0;
    t_true("name 254 bad", ts_hosts_name_ok(big, f, sizeof f, s, sizeof s) == -1);
    lab[63] = 0;
    t_true("name 63 label ok", nameok(lab, lab, lab));
    lab[63] = 'a';
    lab[64] = 0;
    t_true("name 64 label bad", nameok(lab, NULL, NULL));
    t_true("name newline", nameok("a\nb", NULL, NULL));
    t_true("name newline end", nameok("a\n", NULL, NULL));
    t_true("name space", nameok("a b", NULL, NULL));
    t_true("name hash", nameok("a#b", NULL, NULL));
    t_true("name underscore", nameok("a_b", NULL, NULL));
    t_true("name tab cr", nameok("a\tb", NULL, NULL) && nameok("a\rb", NULL, NULL));
    t_true("name high byte", nameok("a\xc3\xa9", NULL, NULL));
    t_true("name leading hyphen", nameok("-a", NULL, NULL));
    t_true("name trailing hyphen", nameok("a-", NULL, NULL));
    t_true("name hyphen before dot", nameok("a-.b", NULL, NULL));
    t_true("name hyphen after dot", nameok("a.-b", NULL, NULL));
    /* a NUL ends the C string: only what precedes it can ever be used */
    t_true("name nul cuts", nameok(fixed, "a", "a"));
    t_true("name small fqdn cap", ts_hosts_name_ok("abcd", f, 4, s, sizeof s) == -1);
    t_true("name fqdn cap exact", ts_hosts_name_ok("abcd", f, 5, s, sizeof s) == 0);
    t_true("name small short cap", ts_hosts_name_ok("abcd.e", f, sizeof f, s, 4) == -1);
}

static void setname(ts_node *n, const char *name, uint32_t ip)
{
    memset(n, 0, sizeof *n);
    strcpy(n->name, name);
    n->ipv4 = ip;
    n->have_ipv4 = ip != 0;
}

static int build(ts_netmap *nm, char *out, size_t cap, size_t *ne, size_t *ns)
{
    return ts_hosts_build(out, cap, nm, NULL, 0, NULL, ne, ns);
}

static int buildold(ts_netmap *nm, char *out, size_t cap, const char *old)
{
    return ts_hosts_build(out, cap, nm, old, strlen(old), NULL, NULL, NULL);
}

/* build output is not NUL-terminated: compare by length */
static int is(const char *out, int n, const char *want)
{
    return n > 0 && (size_t)n == strlen(want) && memcmp(out, want, (size_t)n) == 0;
}

/* out[0..n) holds want (memmem is not in the 10.4 SDK) */
static int has(const char *out, int n, const char *want)
{
    size_t wl = strlen(want), i;
    for (i = 0; n > 0 && i + wl <= (size_t)n; i++)
        if (memcmp(out + i, want, wl) == 0) return 1;
    return 0;
}

static void test_build(void)
{
    static ts_node peers[6];
    ts_netmap nm;
    char out[TS_HOSTS_BLOCK_MAX], out2[TS_HOSTS_BLOCK_MAX];
    size_t ne = 99, ns = 99;
    int n, n2;

    memset(&nm, 0, sizeof nm);
    nm.peers = peers;
    nm.have_self = 1;
    setname(&nm.self, "Self-Node.example.ts.net.", IP(100, 64, 0, 5));
    setname(&peers[0], "peer-b.example.ts.net.", IP(100, 64, 0, 9));
    setname(&peers[1], "peer-a.example.ts.net.", IP(100, 64, 0, 2));
    setname(&peers[2], "peer-c.example.ts.net.", 0);
    setname(&peers[3], "bad name.example.ts.net.", IP(100, 64, 0, 7));
    setname(&peers[4], "peer-d.example.ts.net.", IP(100, 64, 10, 1));
    nm.npeers = 5;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("build ok", n > 0 && memchr(out, 0, (size_t)n) == NULL);
    t_true("build counts", ne == 4 && ns == 1);
    t_true("build exact", is(out, n,
        B "\n"
        "100.64.0.2\tpeer-a.example.ts.net peer-a\n"
        "100.64.0.5\tself-node.example.ts.net self-node\n"
        "100.64.0.9\tpeer-b.example.ts.net peer-b\n"
        "100.64.10.1\tpeer-d.example.ts.net peer-d\n"
        E "\n"));
    n2 = build(&nm, out2, sizeof out2, NULL, NULL);
    t_true("build same bytes", n2 == n && memcmp(out, out2, (size_t)n) == 0);
    /* a different peer order gives the same bytes */
    {
        ts_node t = peers[0];
        peers[0] = peers[4];
        peers[4] = t;
        n2 = build(&nm, out2, sizeof out2, NULL, NULL);
        t_true("build order independent", n2 == n && memcmp(out, out2, (size_t)n) == 0);
    }
    t_true("build cap exact", build(&nm, out2, (size_t)n, NULL, NULL) == n);
    t_true("build cap short", build(&nm, out2, (size_t)n - 1, NULL, NULL) == -1);
    t_true("build cap zero", build(&nm, out2, 0, NULL, NULL) == -1);

    /* duplicate short names (same suffix, so the same fqdn) are withheld from both */
    setname(&nm.self, "me.example.ts.net.", IP(100, 64, 0, 1));
    setname(&peers[0], "dup.example.ts.net.", IP(100, 64, 0, 2));
    setname(&peers[1], "Dup.example.ts.net.", IP(100, 64, 0, 3));
    setname(&peers[2], "solo.example.ts.net.", IP(100, 64, 0, 4));
    nm.npeers = 3;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("dup short withheld", is(out, n,
        B "\n"
        "100.64.0.1\tme.example.ts.net me\n"
        "100.64.0.2\tdup.example.ts.net\n"
        "100.64.0.3\tdup.example.ts.net\n"
        "100.64.0.4\tsolo.example.ts.net solo\n"
        E "\n"));
    /* a single-label name is skipped and counted, even "localhost" */
    setname(&peers[0], "localhost", IP(100, 64, 0, 2));
    setname(&peers[1], "other", IP(100, 64, 0, 3));
    nm.npeers = 2;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("single label skipped", is(out, n, B "\n100.64.0.1\tme.example.ts.net me\n" E "\n") && ne == 1 && ns == 2);
    /* reserved short names: fqdn only */
    setname(&peers[0], "wpad.example.ts.net.", IP(100, 64, 0, 2));
    setname(&peers[1], "localhost.example.ts.net.", IP(100, 64, 0, 3));
    setname(&peers[2], "ip6-allnodes.example.ts.net.", IP(100, 64, 0, 4));
    setname(&peers[3], "ISATAP.example.ts.net.", IP(100, 64, 0, 5));
    setname(&peers[4], "broadcasthost.example.ts.net.", IP(100, 64, 0, 6));
    setname(&peers[5], "ip6x.example.ts.net.", IP(100, 64, 0, 7));
    nm.npeers = 6;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("reserved shorts withheld", is(out, n,
        B "\n"
        "100.64.0.1\tme.example.ts.net me\n"
        "100.64.0.2\twpad.example.ts.net\n"
        "100.64.0.3\tlocalhost.example.ts.net\n"
        "100.64.0.4\tip6-allnodes.example.ts.net\n"
        "100.64.0.5\tisatap.example.ts.net\n"
        "100.64.0.6\tbroadcasthost.example.ts.net\n"
        "100.64.0.7\tip6x.example.ts.net ip6x\n"
        E "\n"));
    /* a node of another tailnet gets its fqdn only; it does not steal the short name */
    setname(&peers[0], "box.other.ts.net.", IP(100, 64, 0, 2));
    setname(&peers[1], "box.example.ts.net.", IP(100, 64, 0, 3));
    nm.npeers = 2;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("shared node fqdn only", is(out, n,
        B "\n"
        "100.64.0.1\tme.example.ts.net me\n"
        "100.64.0.2\tbox.other.ts.net\n"
        "100.64.0.3\tbox.example.ts.net box\n"
        E "\n"));
    /* self single-label: no short names at all (self is skipped too) */
    setname(&nm.self, "me", IP(100, 64, 0, 1));
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("bad self no shorts", is(out, n,
        B "\n"
        "100.64.0.2\tbox.other.ts.net\n"
        "100.64.0.3\tbox.example.ts.net\n"
        E "\n") && ns == 1);
    nm.have_self = 0;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("no self no shorts", is(out, n,
        B "\n"
        "100.64.0.2\tbox.other.ts.net\n"
        "100.64.0.3\tbox.example.ts.net\n"
        E "\n") && ns == 0);
    nm.have_self = 1;
    /* the owner's own names are not shadowed */
    setname(&nm.self, "me.example.ts.net.", IP(100, 64, 0, 1));
    setname(&peers[0], "printer.example.ts.net.", IP(100, 64, 0, 2));
    setname(&peers[1], "scanner.example.ts.net.", IP(100, 64, 0, 3));
    setname(&peers[2], "nas.example.ts.net.", IP(100, 64, 0, 4));
    setname(&peers[3], "cam.example.ts.net.", IP(100, 64, 0, 5));
    nm.npeers = 4;
    n = buildold(&nm, out, sizeof out,
        "127.0.0.1 localhost\n"
        "192.168.1.5 printer # office\n"
        "192.168.1.6\tfoo\tSCANNER\r\n"
        "# 192.168.1.7 nas\n"
        B "\n100.64.0.9 cam\n" E "\n"
        "192.168.1.8 cam.example.ts.net");
    t_true("owner names kept", is(out, n,
        B "\n"
        "100.64.0.1\tme.example.ts.net me\n"
        "100.64.0.2\tprinter.example.ts.net\n"
        "100.64.0.3\tscanner.example.ts.net\n"
        "100.64.0.4\tnas.example.ts.net nas\n"
        "100.64.0.5\tcam.example.ts.net cam\n"
        E "\n"));
    /* the address token is skipped; a name as first token is not a host name */
    n = buildold(&nm, out, sizeof out, "printer 1.2.3.4\nnas\n");
    t_true("owner first token skipped", has(out, n, "printer.example.ts.net printer") &&
                                            has(out, n, "nas.example.ts.net nas"));
    t_true("old NULL", ts_hosts_build(out, sizeof out, &nm, NULL, 0, NULL, NULL, NULL) > 0);
    /* no self, no peers: markers only */
    nm.have_self = 0;
    nm.npeers = 0;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("build empty", is(out, n, B "\n" E "\n") && ne == 0 && ns == 0);
}

static int merge(const char *old, size_t ol, const char *blk, char *out, size_t cap)
{
    return ts_hosts_merge(out, cap, old, ol, blk, blk ? strlen(blk) : 0);
}

static int mergeeq(const char *name, const char *old, const char *blk, const char *want)
{
    char out[1024];
    int n = merge(old, strlen(old), blk, out, sizeof out);
    int ok = n == (int)strlen(want) && memcmp(out, want, (size_t)n) == 0;
    t_true(name, ok);
    if (!ok) printf("  got %d: [%.*s]\n", n, n > 0 ? n : 0, out);
    return ok;
}

static void test_merge(void)
{
    char out[1024];
    const char *blk = B "\n100.64.0.2\tpeer-a.example.ts.net peer-a\n" E "\n";
    const char nul[] = "127.0.0.1\tlocal\0host\n# x\0\n";
    char *huge;

    mergeeq("merge empty old", "", blk, blk);
    mergeeq("merge empty old empty block", "", "", "");
    mergeeq("merge no block adds newline", "127.0.0.1\tlocalhost", blk,
            "127.0.0.1\tlocalhost\n" B "\n100.64.0.2\tpeer-a.example.ts.net peer-a\n" E "\n");
    mergeeq("merge no block keeps newline", "127.0.0.1\tlocalhost\n", blk,
            "127.0.0.1\tlocalhost\n" B "\n100.64.0.2\tpeer-a.example.ts.net peer-a\n" E "\n");
    mergeeq("merge no block no block", "a\nb", "", "a\nb");
    mergeeq("merge middle replaced",
            "l1\nl2\n" B "\nold line\n" E "\nl3\nl4\n", blk,
            "l1\nl2\nl3\nl4\n" B "\n100.64.0.2\tpeer-a.example.ts.net peer-a\n" E "\n");
    mergeeq("merge two blocks", "a\n" B "\nx\n" E "\nb\n" B "\ny\n" E "\nc\n", "", "a\nb\nc\n");
    mergeeq("merge crlf and spaces", "a\r\n" B " \t\r\nx\r\n" E "  \r\nb\r\n", "", "a\r\nb\r\n");
    mergeeq("merge crlf no final", "a\r\n" B "\r\n" E "\r", "", "a\r\n");
    mergeeq("merge block at EOF no newline", "a\n" B "\nx\n" E, "", "a\n");
    mergeeq("merge lone end removed", "a\n" E "\nb\n", "", "a\nb\n");
    mergeeq("merge leading space not marker", " " B "\n", "", " " B "\n");
    mergeeq("merge marker as suffix kept", "x " B "\n" "y" E "\n", "", "x " B "\n" "y" E "\n");
    mergeeq("merge block removed no append", "a\n" B "\nx\n" E "\n", "", "a\n");
    mergeeq("merge begin inside section", "a\n" B "\n" B "\nx\n" E "\nb\n", "", "a\nb\n");
    t_true("merge begin no end", merge("a\n" B "\nowner line\n", strlen("a\n" B "\nowner line\n"), blk, out, sizeof out) == -2);
    t_true("merge begin no end, end before", merge(E "\n" B "\nz", strlen(E "\n" B "\nz"), blk, out, sizeof out) == -2);
    t_true("merge begin last line", merge(B, strlen(B), "", out, sizeof out) == -2);
    t_true("merge begin no end tiny cap", merge(B "\nq\n", strlen(B "\nq\n"), blk, out, 1) == -2);
    {
        int n = ts_hosts_merge(out, sizeof out, nul, sizeof nul - 1, blk, strlen(blk));
        t_true("merge nul survives", n == (int)(sizeof nul - 1 + strlen(blk)) && memcmp(out, nul, sizeof nul - 1) == 0 &&
                                         memcmp(out + sizeof nul - 1, blk, strlen(blk)) == 0);
    }
    t_true("merge cap too small", merge("abc\n", 4, blk, out, 4 + strlen(blk) - 1) == -1);
    t_true("merge cap exact", merge("abc\n", 4, blk, out, 4 + strlen(blk)) == (int)(4 + strlen(blk)));
    t_true("merge cap zero old", merge("", 0, blk, out, 0) == -1);
    t_true("merge cap zero both empty", merge("", 0, "", out, 0) == 0);
    huge = (char *)calloc(1, TS_HOSTS_FILE_MAX + 2);
    if (huge) {
        char *big = (char *)malloc(TS_HOSTS_FILE_MAX + 64);
        memset(huge, 'a', TS_HOSTS_FILE_MAX + 1);
        if (big) {
            t_true("merge file max ok", ts_hosts_merge(big, TS_HOSTS_FILE_MAX + 64, huge, TS_HOSTS_FILE_MAX, "", 0) == TS_HOSTS_FILE_MAX);
            t_true("merge over file max", ts_hosts_merge(big, TS_HOSTS_FILE_MAX + 64, huge, TS_HOSTS_FILE_MAX + 1, "", 0) == -1);
        }
        free(big);
    }
    free(huge);
}

/* Final review: full names only in self's suffix or ts.net; the Mac's own
 * host name is never a peer's short name. */
static void test_gates(void)
{
    static ts_node peers[6];
    ts_netmap nm;
    char out[TS_HOSTS_BLOCK_MAX];
    size_t ne = 99, ns = 99;
    int n;

    memset(&nm, 0, sizeof nm);
    nm.peers = peers;
    nm.have_self = 1;
    setname(&nm.self, "me.example.ts.net.", IP(100, 64, 0, 1));
    setname(&peers[0], "www.apple.com.", IP(100, 64, 0, 2));
    setname(&peers[1], "box.other.ts.net.", IP(100, 64, 0, 3));
    setname(&peers[2], "evilts.net.", IP(100, 64, 0, 4));
    setname(&peers[3], "a.evilts.net.", IP(100, 64, 0, 5));
    setname(&peers[4], "peer.example.ts.net.", IP(100, 64, 0, 6));
    setname(&peers[5], "x.notexample.ts.net.", IP(100, 64, 0, 7));
    nm.npeers = 6;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("gate: foreign names skipped", is(out, n,
        B "\n"
        "100.64.0.1\tme.example.ts.net me\n"
        "100.64.0.3\tbox.other.ts.net\n"
        "100.64.0.6\tpeer.example.ts.net peer\n"
        "100.64.0.7\tx.notexample.ts.net\n"
        E "\n") && ne == 4 && ns == 3);

    /* a custom base domain: self's suffix passes, others still need ts.net */
    setname(&nm.self, "me.corp.example.", IP(100, 64, 0, 1));
    setname(&peers[0], "node.corp.example.", IP(100, 64, 0, 2));
    setname(&peers[1], "node.xcorp.example.", IP(100, 64, 0, 3));
    setname(&peers[2], "box.other.ts.net.", IP(100, 64, 0, 4));
    setname(&peers[3], "corp.example.", IP(100, 64, 0, 5));
    nm.npeers = 4;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("gate: custom suffix kept", is(out, n,
        B "\n"
        "100.64.0.1\tme.corp.example me\n"
        "100.64.0.2\tnode.corp.example node\n"
        "100.64.0.4\tbox.other.ts.net\n"
        E "\n") && ns == 2);
    /* the suffix itself is never a node name we write */
    setname(&peers[3], "ts.net.", IP(100, 64, 0, 5));
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("gate: ts.net apex skipped", n > 0 && ns == 2 && !has(out, n, "100.64.0.5"));
    setname(&peers[3], "corp.example.", IP(100, 64, 0, 5));
    /* no valid self: only ts.net names */
    nm.have_self = 0;
    n = build(&nm, out, sizeof out, &ne, &ns);
    t_true("gate: no self, ts.net only", is(out, n,
        B "\n"
        "100.64.0.4\tbox.other.ts.net\n"
        E "\n") && ne == 1 && ns == 3);
    nm.have_self = 1;

    /* the local host name: a peer's short name equal to it is withheld, self's is not */
    setname(&nm.self, "leopard.example.ts.net.", IP(100, 64, 0, 1));
    setname(&peers[0], "tiger.example.ts.net.", IP(100, 64, 0, 2));
    setname(&peers[1], "mac.example.ts.net.", IP(100, 64, 0, 3));
    nm.npeers = 2;
    n = ts_hosts_build(out, sizeof out, &nm, NULL, 0, "mac", NULL, NULL);
    t_true("local name: peer short withheld", is(out, n,
        B "\n"
        "100.64.0.1\tleopard.example.ts.net leopard\n"
        "100.64.0.2\ttiger.example.ts.net tiger\n"
        "100.64.0.3\tmac.example.ts.net\n"
        E "\n"));
    n = ts_hosts_build(out, sizeof out, &nm, NULL, 0, "leopard", NULL, NULL);
    t_true("local name: self keeps its short", is(out, n,
        B "\n"
        "100.64.0.1\tleopard.example.ts.net leopard\n"
        "100.64.0.2\ttiger.example.ts.net tiger\n"
        "100.64.0.3\tmac.example.ts.net mac\n"
        E "\n"));
    n = ts_hosts_build(out, sizeof out, &nm, NULL, 0, "", NULL, NULL);
    t_true("local name: empty ignored", has(out, n, "mac.example.ts.net mac\n"));
}

void test_hosts(void)
{
    test_name_ok();
    test_build();
    test_gates();
    test_merge();
}
