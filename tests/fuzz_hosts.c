#include "fuzz.h"
#include "../src/names/hosts.h"

#include <stdlib.h>
#include <string.h>

/* Input: byte 0 selects the shape; the rest is split at the first 0xff.
 *
 * Oracles:
 * - name_ok on the text (as a NUL-terminated copy): a valid name gives
 *   output of only [a-z0-9.-] with no empty label, no label over 63 bytes,
 *   no label starting or ending with '-', 1..253 bytes; the short name is the
 *   first label; a node built from it yields only lines of that alphabet, and
 *   never a line the merge would take for a marker;
 * - merge of the other part as the old file: never writes past cap (the
 *   output buffer is exactly cap bytes, so ASan sees it), returns -1, -2 or a
 *   length <= cap; with no block no line of the output is the begin marker or
 *   the end marker; with a block the output ends with the block exactly, and
 *   merging that output again with the same block gives the same bytes. */

static int is_marker(const char *s, size_t len, const char *m)
{
    size_t ml = strlen(m);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r')) len--;
    return len == ml && memcmp(s, m, ml) == 0;
}

static size_t count_markers(const char *s, size_t n)
{
    size_t c = 0, pos = 0;
    while (pos < n) {
        const char *nl = memchr(s + pos, '\n', n - pos);
        size_t len = nl ? (size_t)(nl - (s + pos)) : n - pos;
        if (is_marker(s + pos, len, TS_HOSTS_BEGIN) || is_marker(s + pos, len, TS_HOSTS_END)) c++;
        pos += len + (nl ? 1 : 0);
    }
    return c;
}

static void check_name(const char *name)
{
    char f[254], s[64];
    size_t i, lab = 0, n;
    if (ts_hosts_name_ok(name, f, sizeof f, s, sizeof s) != 0) return;
    n = strlen(f);
    TS_FUZZ_ASSERT(n >= 1 && n <= 253);
    for (i = 0; i <= n; i++) {
        char c = f[i];
        if (i == n || c == '.') {
            TS_FUZZ_ASSERT(lab >= 1 && lab <= 63);
            TS_FUZZ_ASSERT(f[i - 1] != '-' && f[i - lab] != '-');
            lab = 0;
        } else {
            TS_FUZZ_ASSERT((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-');
            lab++;
        }
    }
    TS_FUZZ_ASSERT(strlen(s) >= 1 && strlen(s) <= 63);
    TS_FUZZ_ASSERT(strncmp(f, s, strlen(s)) == 0 && (f[strlen(s)] == '.' || f[strlen(s)] == 0));
}

static void target(const uint8_t *data, size_t len)
{
    static const char blk[] = TS_HOSTS_BEGIN "\n100.64.0.2\tpeer-a.example.ts.net peer-a\n" TS_HOSTS_END "\n";
    size_t split, nl, ol, cap, rc_len;
    const uint8_t *namep, *oldp;
    char *name, *out, *out2;
    int rc;
    static ts_node peers[2];
    ts_netmap nm;
    char blkout[TS_HOSTS_BLOCK_MAX];
    int bn;

    if (len < 1) return;
    for (split = 1; split < len && data[split] != 0xff; split++) {}
    namep = data + 1;
    nl = split - 1;
    oldp = data + (split < len ? split + 1 : len);
    ol = len - (oldp - data);

    name = (char *)malloc(nl + 1);
    TS_FUZZ_ASSERT(name != NULL);
    memcpy(name, namep, nl);
    name[nl] = 0;
    check_name(name);

    /* a node with that name and one with a fixed name: the block is still clean */
    memset(&nm, 0, sizeof nm);
    memset(peers, 0, sizeof peers);
    nm.peers = peers;
    nm.npeers = 2;
    nm.have_self = 1;
    strncpy(nm.self.name, name, sizeof nm.self.name - 1);
    nm.self.ipv4 = 0x64400001u;
    nm.self.have_ipv4 = 1;
    strcpy(peers[0].name, "peer-a.example.ts.net.");
    peers[0].ipv4 = 0x64400002u;
    peers[0].have_ipv4 = 1;
    strncpy(peers[1].name, name, sizeof peers[1].name - 1);
    peers[1].ipv4 = 0x64400003u;
    peers[1].have_ipv4 = 1;
    bn = ts_hosts_build(blkout, sizeof blkout, &nm, (const char *)oldp, ol, NULL, NULL, NULL);
    TS_FUZZ_ASSERT(bn > 0 && (size_t)bn <= sizeof blkout);
    TS_FUZZ_ASSERT(count_markers(blkout, (size_t)bn) == 2);
    {
        size_t i;
        for (i = 0; i < (size_t)bn; i++) TS_FUZZ_ASSERT(blkout[i] != 0 && (unsigned char)blkout[i] < 0x80);
    }
    {
        /* every entry line (between the marker lines) is [0-9a-z.\t -] and a final \n */
        size_t i, b0 = strlen(TS_HOSTS_BEGIN) + 1, e0 = (size_t)bn - strlen(TS_HOSTS_END) - 1;
        TS_FUZZ_ASSERT(e0 >= b0 && (e0 == b0 || blkout[e0 - 1] == 0x0a));
        for (i = b0; i < e0; i++) {
            char c = blkout[i];
            TS_FUZZ_ASSERT(c == '\n' || c == '\t' || c == ' ' || c == '.' || c == '-' || (c >= '0' && c <= '9') ||
                           (c >= 'a' && c <= 'z'));
        }
    }
    {
        char *twice = (char *)malloc((size_t)bn);
        TS_FUZZ_ASSERT(twice != NULL);
        TS_FUZZ_ASSERT(ts_hosts_build(twice, (size_t)bn, &nm, (const char *)oldp, ol, NULL, NULL, NULL) == bn && memcmp(twice, blkout, (size_t)bn) == 0);
        TS_FUZZ_ASSERT(ts_hosts_build(twice, (size_t)bn - 1, &nm, (const char *)oldp, ol, NULL, NULL, NULL) == -1);
        free(twice);
    }

    /* merge: the output buffer is exactly cap bytes */
    cap = ol + sizeof blk + (data[0] % 4 == 0 ? 0 : 8);
    if (data[0] % 3 == 0) cap = ol;
    out = (char *)malloc(cap ? cap : 1);
    TS_FUZZ_ASSERT(out != NULL);
    rc = ts_hosts_merge(out, cap, (const char *)oldp, ol, NULL, 0);
    TS_FUZZ_ASSERT(rc == -1 || rc == -2 || (rc >= 0 && (size_t)rc <= cap && (size_t)rc <= ol));
    if (rc >= 0) TS_FUZZ_ASSERT(count_markers(out, (size_t)rc) == 0);
    free(out);

    cap = ol + sizeof blk;
    out = (char *)malloc(cap);
    TS_FUZZ_ASSERT(out != NULL);
    rc = ts_hosts_merge(out, cap, (const char *)oldp, ol, blk, sizeof blk - 1);
    TS_FUZZ_ASSERT(rc == -2 || (rc >= 0 && (size_t)rc <= cap));
    if (rc >= 0) {
        rc_len = (size_t)rc;
        TS_FUZZ_ASSERT(rc_len >= sizeof blk - 1 && memcmp(out + rc_len - (sizeof blk - 1), blk, sizeof blk - 1) == 0);
        TS_FUZZ_ASSERT(count_markers(out, rc_len) == 2);
        out2 = (char *)malloc(rc_len + sizeof blk);
        TS_FUZZ_ASSERT(out2 != NULL);
        TS_FUZZ_ASSERT(ts_hosts_merge(out2, rc_len + sizeof blk, out, rc_len, blk, sizeof blk - 1) == rc);
        TS_FUZZ_ASSERT(memcmp(out, out2, rc_len) == 0);
        free(out2);
    }
    free(out);
    free(name);
}

void ts_fuzz_hosts(void)
{
    static const char *const S[] = {
        ("\001peer-a.example.ts.net.\377127.0.0.1\tlocalhost\n" TS_HOSTS_BEGIN "\nx\n" TS_HOSTS_END "\nrest\n"),
        ("\002Peer-A.Example.TS.net\377" TS_HOSTS_BEGIN "\r\n" TS_HOSTS_END " \r\n"),
        ("\003" "a\nb\377" TS_HOSTS_END "\n"),
        ("\004" "a#b\377" TS_HOSTS_BEGIN "\nowner\n"),
        ("\005-a.b-\3771.2.3.4 x\r\n\r\n# c"),
        ("\006" "a.b.c\377"),
    };
    enum { N = sizeof S / sizeof S[0] };
    const uint8_t *seeds[N];
    size_t lens[N], i;
    for (i = 0; i < N; i++) {
        seeds[i] = (const uint8_t *)S[i];
        lens[i] = strlen(S[i]);
    }
    ts_fuzz_run("hosts", target, seeds, lens, N, TS_FUZZ_DEFAULT_ITERS);
}
