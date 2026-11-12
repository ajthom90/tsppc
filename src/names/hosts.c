#include "hosts.h"

#include <string.h>

#define FQDN_CAP 254
#define SHORT_CAP 64

int ts_hosts_name_ok(const char *name, char *fqdn, size_t fqdn_cap, char *shortname, size_t short_cap)
{
    size_t n = strlen(name), i, lab = 0, first = 0;
    int have_first = 0;

    if (n > 0 && name[n - 1] == '.') n--;
    if (n < 1 || n > 253) return -1;
    if (fqdn_cap < n + 1) return -1;
    for (i = 0; i <= n; i++) {
        char c = i < n ? name[i] : '.';
        if (c == '.') {
            if (lab < 1 || lab > 63) return -1;
            if (name[i - 1] == '-' || name[i - lab] == '-') return -1;
            if (!have_first) {
                if (short_cap < lab + 1) return -1;
                first = lab;
                have_first = 1;
            }
            lab = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
            lab++;
        } else {
            return -1;
        }
    }
    for (i = 0; i < n; i++) {
        char c = name[i];
        fqdn[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    fqdn[n] = 0;
    memcpy(shortname, fqdn, first);
    shortname[first] = 0;
    return 0;
}

typedef struct {
    char *p;
    size_t cap, n;
    int over;
} wr;

static void put(wr *w, const char *s, size_t len)
{
    if (w->over || len > w->cap - w->n) {
        w->over = 1;
        return;
    }
    memcpy(w->p + w->n, s, len);
    w->n += len;
}

static void puts_(wr *w, const char *s)
{
    put(w, s, strlen(s));
}

static void put_ip(wr *w, uint32_t ip)
{
    char b[16];
    size_t n = 0;
    int k;
    for (k = 3; k >= 0; k--) {
        unsigned v = (ip >> (8 * k)) & 0xff;
        if (v >= 100) b[n++] = (char)('0' + v / 100);
        if (v >= 10) b[n++] = (char)('0' + (v / 10) % 10);
        b[n++] = (char)('0' + v % 10);
        if (k) b[n++] = '.';
    }
    put(w, b, n);
}

typedef struct {
    uint32_t ip;
    char fqdn[FQDN_CAP];
    char sh[SHORT_CAP];
} entry;

static int entry_before(const entry *a, const entry *b)
{
    if (a->ip != b->ip) return a->ip < b->ip;
    return strcmp(a->fqdn, b->fqdn) < 0;
}

int ts_hosts_build(char *out, size_t cap, const ts_netmap *nm, size_t *nentries, size_t *nskipped)
{
    entry ents[TS_MAX_PEERS + 1];
    int idx[TS_MAX_PEERS + 1];
    unsigned char hide[TS_MAX_PEERS + 1];
    size_t n = 0, skipped = 0, i, j, np = nm->npeers;
    wr w;

    if (np > TS_MAX_PEERS) np = TS_MAX_PEERS;
    for (i = 0; i < np + 1; i++) {
        const ts_node *nd;
        if (i == 0) {
            if (!nm->have_self) continue;
            nd = &nm->self;
        } else {
            nd = &nm->peers[i - 1];
        }
        if (!nd->have_ipv4) continue;
        if (ts_hosts_name_ok(nd->name, ents[n].fqdn, FQDN_CAP, ents[n].sh, SHORT_CAP) != 0) {
            skipped++;
            continue;
        }
        ents[n].ip = nd->ipv4;
        n++;
    }
    for (i = 0; i < n; i++) {
        hide[i] = 0;
        for (j = 0; j < n && !hide[i]; j++) {
            if (j != i && strcmp(ents[i].sh, ents[j].sh) == 0) hide[i] = 1;
            if (strcmp(ents[i].sh, ents[j].fqdn) == 0) hide[i] = 1;
        }
    }
    /* insertion sort of indices: stable, at most 257 of them */
    for (i = 0; i < n; i++) {
        int v = (int)i;
        for (j = i; j > 0 && entry_before(&ents[v], &ents[idx[j - 1]]); j--) idx[j] = idx[j - 1];
        idx[j] = v;
    }

    w.p = out;
    w.cap = cap;
    w.n = 0;
    w.over = 0;
    puts_(&w, TS_HOSTS_BEGIN "\n");
    for (i = 0; i < n; i++) {
        const entry *e = &ents[idx[i]];
        put_ip(&w, e->ip);
        puts_(&w, "\t");
        puts_(&w, e->fqdn);
        if (!hide[idx[i]]) {
            puts_(&w, " ");
            puts_(&w, e->sh);
        }
        puts_(&w, "\n");
    }
    puts_(&w, TS_HOSTS_END "\n");
    if (nentries) *nentries = n;
    if (nskipped) *nskipped = skipped;
    return w.over ? -1 : (int)w.n;
}

/* Does line [s, s+len) equal m once trailing spaces, tabs and '\r' are dropped? */
static int line_is(const char *s, size_t len, const char *m)
{
    size_t ml = strlen(m);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r')) len--;
    return len == ml && memcmp(s, m, ml) == 0;
}

int ts_hosts_merge(char *out, size_t cap, const char *old, size_t oldlen, const char *block, size_t blocklen)
{
    wr w;
    size_t pos = 0;
    int in_sec = 0;

    if (oldlen > TS_HOSTS_FILE_MAX) return -1;
    w.p = out;
    w.cap = cap;
    w.n = 0;
    w.over = 0;
    while (pos < oldlen) {
        const char *s = old + pos;
        const char *nl = memchr(s, '\n', oldlen - pos);
        size_t len = nl ? (size_t)(nl - s) + 1 : oldlen - pos;
        size_t body = nl ? len - 1 : len;
        pos += len;
        if (in_sec) {
            if (line_is(s, body, TS_HOSTS_END)) in_sec = 0;
            continue;
        }
        if (line_is(s, body, TS_HOSTS_BEGIN)) {
            in_sec = 1;
            continue;
        }
        if (line_is(s, body, TS_HOSTS_END)) continue;
        put(&w, s, len);
    }
    if (in_sec) return -2;
    if (blocklen > 0) {
        if (w.n > 0 && !w.over && out[w.n - 1] != '\n') put(&w, "\n", 1);
        put(&w, block, blocklen);
    }
    return w.over ? -1 : (int)w.n;
}
