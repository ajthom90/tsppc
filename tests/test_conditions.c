/* Wake detection, the network fingerprint and the rebind gate
 * (src/daemon/conditions.c), and the interface snapshot (src/platform/netinfo.c). */
#include "harness.h"

#include <string.h>

#include "../src/daemon/conditions.h"
#include "../src/platform/netinfo.h"

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static void set(ts_ifaddr *e, const char *name, uint32_t addr, uint32_t mask)
{
    memset(e, 0, sizeof(*e));
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->addr = addr;
    e->mask = mask;
}

static void wake_tests(void)
{
    ts_wake w;
    memset(&w, 0, sizeof(w));
    t_true("wake: first call primes", ts_wake_check(&w, 1000, 50) == 0);
    t_true("wake: normal turn", ts_wake_check(&w, 2000, 1050) == 0);
    t_true("wake: wall +15999, mono +1000", ts_wake_check(&w, 2000 + 15999, 1050 + 1000) == 0);
    memset(&w, 0, sizeof(w));
    ts_wake_check(&w, 1000, 50);
    t_true("wake: sleep", ts_wake_check(&w, 1000 + 600000, 50 + 1000) == 599000);
    t_true("wake: re-primed", ts_wake_check(&w, 1000 + 600000 + 1000, 50 + 2000) == 0);
    memset(&w, 0, sizeof(w));
    ts_wake_check(&w, 10000000, 50);
    t_true("wake: backward jump", ts_wake_check(&w, 10000000 - 3600000, 50 + 1000) == -3601000);
    memset(&w, 0, sizeof(w));
    ts_wake_check(&w, 1000, 0);
    t_true("wake: +15000 is a jump", ts_wake_check(&w, 1000 + 15000, 0) == 15000);
    t_true("wake: -15000 is a jump", ts_wake_check(&w, 1000, 0) == -15000);
    memset(&w, 0, sizeof(w));
    ts_wake_check(&w, 1000, 0);
    t_true("wake: 14999 is not", ts_wake_check(&w, 1000 + 14999, 0) == 0);
    t_true("wake: -14999 is not", ts_wake_check(&w, 1000 + 14999 - 14999, 0) == 0);
    memset(&w, 0, sizeof(w));
    ts_wake_check(&w, 10000000, 50);
    ts_wake_check(&w, 10000000 - 3600000, 50 + 1000);
    t_true("wake: re-primed after backward", ts_wake_check(&w, 10000000 - 3600000 + 1000, 50 + 2000) == 0);
}

static void fp_tests(void)
{
    ts_ifaddr a[3], b[3], c[8];
    uint64_t base;
    set(&a[0], "en0", IP(192, 168, 1, 5), IP(255, 255, 255, 0));
    set(&a[1], "en1", IP(10, 0, 0, 9), IP(255, 0, 0, 0));
    set(&a[2], "fw0", IP(172, 16, 0, 1), IP(255, 255, 0, 0));
    b[0] = a[2]; b[1] = a[0]; b[2] = a[1];
    base = ts_net_fingerprint(a, 3, IP(192, 168, 1, 1), "en0");
    t_true("fingerprint: order independent", base == ts_net_fingerprint(b, 3, IP(192, 168, 1, 1), "en0"));

    memcpy(c, a, sizeof(a));
    set(&c[3], "lo0", IP(127, 0, 0, 1), IP(255, 0, 0, 0));
    t_true("fingerprint: ignores lo0", base == ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    set(&c[3], "tun0", IP(100, 101, 102, 103), IP(255, 255, 255, 255));
    t_true("fingerprint: ignores tun0", base == ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    set(&c[3], "en1", IP(100, 64, 0, 5), IP(255, 255, 255, 0));
    t_true("fingerprint: ignores 100.64/10", base == ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    /* A link-local address (self-assigned while DHCP is pending) comes and
     * goes without the network changing. */
    set(&c[3], "en1", IP(169, 254, 12, 34), IP(255, 255, 0, 0));
    t_true("fingerprint: ignores 169.254/16", base == ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    set(&c[3], "en1", IP(169, 255, 0, 1), IP(255, 255, 0, 0));
    t_true("fingerprint: 169.255 is not link-local", base != ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    set(&c[3], "utun1", IP(10, 9, 9, 9), IP(255, 0, 0, 0));
    t_true("fingerprint: ignores utun", base == ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    set(&c[3], "gif0", IP(10, 9, 9, 9), IP(255, 0, 0, 0));
    t_true("fingerprint: ignores gif", base == ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    set(&c[3], "tap0", IP(10, 9, 9, 9), IP(255, 0, 0, 0));
    t_true("fingerprint: ignores tap", base == ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));

    set(&c[3], "en0", IP(192, 168, 1, 6), IP(255, 255, 255, 0));
    t_true("fingerprint: alias changes", base != ts_net_fingerprint(c, 4, IP(192, 168, 1, 1), "en0"));
    memcpy(c, a, sizeof(a));
    c[0].mask = IP(255, 255, 0, 0);
    t_true("fingerprint: mask changes", base != ts_net_fingerprint(c, 3, IP(192, 168, 1, 1), "en0"));
    t_true("fingerprint: gw changes", base != ts_net_fingerprint(a, 3, IP(192, 168, 1, 2), "en0"));
    t_true("fingerprint: gw_if changes", base != ts_net_fingerprint(a, 3, IP(192, 168, 1, 1), "en1"));
    t_true("fingerprint: empty ok", ts_net_fingerprint(NULL, 0, 0, "") == ts_net_fingerprint(a, 0, 0, ""));
}

static void fp_bounded(void)
{
    ts_ifaddr e[40], r[40];
    uint64_t v1, v2;
    size_t i;
    for (i = 0; i < 40; i++) {
        char nm[16];
        nm[0] = 'e'; nm[1] = 'n'; nm[2] = (char)('a' + (int)(i / 10)); nm[3] = (char)('0' + (int)(i % 10)); nm[4] = 0;
        set(&e[i], nm, IP(10, 0, 0, 1 + i), IP(255, 255, 255, 0));
    }
    for (i = 0; i < 40; i++) r[i] = e[39 - i];
    v1 = ts_net_fingerprint(e, 40, 0, "");
    v2 = ts_net_fingerprint(e, 40, 0, "");
    t_true("fingerprint: bounded stable", v1 == v2);
    t_true("fingerprint: bounded order independent", v1 == ts_net_fingerprint(r, 40, 0, ""));
    /* e[] is sorted by name: e[39] is beyond the 32nd, e[5] within. */
    e[39].addr ^= 0x100;
    t_true("fingerprint: beyond 32nd ignored", v1 == ts_net_fingerprint(e, 40, 0, ""));
    e[39].addr ^= 0x100;
    e[5].addr ^= 0x100;
    t_true("fingerprint: within 32 counts", v1 != ts_net_fingerprint(e, 40, 0, ""));
}

static void gate_tests(void)
{
    ts_rebind_gate g;
    char why[64];

    memset(&g, 0, sizeof(g));
    ts_rebind_request(&g, "wake", 0);
    t_true("rebind gate: due at t=0", ts_rebind_due(&g, 0, why) == 1);
    t_true("rebind gate: why copied", strcmp(why, "wake") == 0);
    t_true("rebind gate: cleared", ts_rebind_due(&g, 1, why) == 0);

    ts_rebind_request(&g, "net", 1000);
    t_true("rebind gate: not due at 1000", ts_rebind_due(&g, 1000, why) == 0);
    t_true("rebind gate: not due at 9999", ts_rebind_due(&g, 9999, why) == 0);
    t_true("rebind gate: due at 10000", ts_rebind_due(&g, 10000, why) == 1);
    t_true("rebind gate: why net", strcmp(why, "net") == 0);

    memset(&g, 0, sizeof(g));
    ts_rebind_request(&g, "first", 0);
    t_true("rebind gate: first goes", ts_rebind_due(&g, 0, why) == 1);
    ts_rebind_request(&g, "second", 2000);
    ts_rebind_request(&g, "third", 3000);
    t_true("rebind gate: two in the gap wait", ts_rebind_due(&g, 5000, why) == 0);
    t_true("rebind gate: one rebind", ts_rebind_due(&g, 10000, why) == 1);
    t_true("rebind gate: earliest why wins", strcmp(why, "second") == 0);
    t_true("rebind gate: then none", ts_rebind_due(&g, 30000, why) == 0);

    memset(&g, 0, sizeof(g));
    t_true("rebind gate: no request never due", ts_rebind_due(&g, 100000, why) == 0);
}

static void snapshot_test(void)
{
    ts_ifaddr e[16];
    size_t n = 99, i;
    uint32_t gw = 1;
    char gif[16];
    int bad = 0;
    int rc = ts_net_snapshot(e, 16, &n, &gw, gif);
    t_true("snapshot runs", rc == 0 && n <= 16);
    t_true("snapshot: gw implies gw_if", gw == 0 || gif[0] != 0);
    for (i = 0; i < n && i < 16; i++)
        if (strncmp(e[i].name, "lo", 2) == 0)
            bad = 1;
    t_true("snapshot skips loopback", !bad);
    t_true("snapshot: gw_if terminated", memchr(gif, 0, sizeof(gif)) != NULL);
}

void test_conditions(void)
{
    wake_tests();
    fp_tests();
    fp_bounded();
    gate_tests();
    snapshot_test();
}
