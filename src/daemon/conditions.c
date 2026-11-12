#include "conditions.h"

#include <stdlib.h>
#include <string.h>

int64_t ts_wake_check(ts_wake *w, int64_t wall_ms, int64_t mono_ms)
{
    int64_t jump = 0;
    if (w->primed) {
        int64_t d = (wall_ms - w->wall) - (mono_ms - w->mono);
        if (d >= TS_WAKE_JUMP_MS || d <= -TS_WAKE_JUMP_MS)
            jump = d;
    }
    w->primed = 1;
    w->wall = wall_ms;
    w->mono = mono_ms;
    return jump;
}

static int ignored(const ts_ifaddr *e)
{
    static const char *const pre[] = { "lo", "tun", "tap", "utun", "gif" };
    size_t i;
    for (i = 0; i < sizeof(pre) / sizeof(pre[0]); i++)
        if (strncmp(e->name, pre[i], strlen(pre[i])) == 0)
            return 1;
    /* 100.64.0.0/10: the tailnet's own addresses (and CGNAT) */
    return (e->addr & 0xFFC00000u) == 0x64400000u;
}

static int cmp(const void *x, const void *y)
{
    const ts_ifaddr *a = (const ts_ifaddr *)x, *b = (const ts_ifaddr *)y;
    int c = strncmp(a->name, b->name, sizeof(a->name));
    if (c)
        return c;
    if (a->addr != b->addr)
        return a->addr < b->addr ? -1 : 1;
    if (a->mask != b->mask)
        return a->mask < b->mask ? -1 : 1;
    return 0;
}

static uint64_t fnv(uint64_t h, const void *p, size_t n)
{
    const unsigned char *s = (const unsigned char *)p;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= s[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uint64_t fnv32(uint64_t h, uint32_t v)
{
    unsigned char b[4];
    b[0] = (unsigned char)(v >> 24);
    b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >> 8);
    b[3] = (unsigned char)v;
    return fnv(h, b, 4);
}

uint64_t ts_net_fingerprint(const ts_ifaddr *a, size_t n, uint32_t gw, const char *gw_if)
{
    ts_ifaddr kept[TS_NET_MAX_ADDRS];
    size_t i, j, k = 0;
    uint64_t h = 0xcbf29ce484222325ULL;

    /* Keep the TS_NET_MAX_ADDRS smallest by (name, addr, mask), sorted, by
     * insertion: which entries are dropped does not depend on input order. */
    for (i = 0; i < n; i++) {
        ts_ifaddr e;
        if (ignored(&a[i]))
            continue;
        e = a[i];
        e.name[sizeof(e.name) - 1] = 0;
        if (k == TS_NET_MAX_ADDRS && cmp(&e, &kept[k - 1]) >= 0)
            continue;
        j = k < TS_NET_MAX_ADDRS ? k++ : k - 1;
        while (j > 0 && cmp(&e, &kept[j - 1]) < 0) {
            kept[j] = kept[j - 1];
            j--;
        }
        kept[j] = e;
    }

    for (i = 0; i < k; i++) {
        h = fnv(h, kept[i].name, strlen(kept[i].name) + 1);
        h = fnv32(h, kept[i].addr);
        h = fnv32(h, kept[i].mask);
    }
    h = fnv32(h, gw);
    if (gw_if) {
        size_t l = 0;
        while (l < 15 && gw_if[l])
            l++;
        h = fnv(h, gw_if, l);
    }
    return h;
}

void ts_rebind_request(ts_rebind_gate *g, const char *why, int64_t now_ms)
{
    (void)now_ms;
    if (g->pending)
        return;
    g->pending = 1;
    strncpy(g->why, why ? why : "", sizeof(g->why) - 1);
    g->why[sizeof(g->why) - 1] = 0;
}

/* last holds the time of the last rebind plus 1, so that 0 (a zeroed gate)
 * means none yet, even when that rebind was at t=0. */
int ts_rebind_due(ts_rebind_gate *g, int64_t now_ms, char why[64])
{
    if (!g->pending)
        return 0;
    if (g->last != 0 && now_ms - (g->last - 1) < TS_REBIND_MIN_GAP_MS)
        return 0;
    strncpy(why, g->why, 63);
    why[63] = 0;
    g->pending = 0;
    g->last = now_ms + 1;
    return 1;
}
