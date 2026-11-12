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

/* Does line [s, s+len) equal m once trailing spaces, tabs and '\r' are dropped? */
static int line_is(const char *s, size_t len, const char *m)
{
    size_t ml = strlen(m);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r')) len--;
    return len == ml && memcmp(s, m, ml) == 0;
}

typedef struct {
    uint32_t ip;
    char fqdn[FQDN_CAP];
    char sh[SHORT_CAP];
    unsigned char shlen;
    unsigned char is_self;
} entry;

static int entry_before(const entry *a, const entry *b)
{
    if (a->ip != b->ip) return a->ip < b->ip;
    return strcmp(a->fqdn, b->fqdn) < 0;
}

/* The part of an fqdn after its first label, or NULL for a single label. */
static const char *suffix_of(const char *fqdn)
{
    const char *d = strchr(fqdn, '.');
    return d ? d + 1 : NULL;
}

/* Does fqdn end in suffix at a label boundary (or equal it)? */
static int ends_in(const char *fqdn, const char *suffix)
{
    size_t fl = strlen(fqdn), sl = strlen(suffix);
    if (sl == 0 || fl < sl || strcmp(fqdn + fl - sl, suffix) != 0) return 0;
    return fl == sl || fqdn[fl - sl - 1] == '.';
}

static int banned_short(const char *s)
{
    return strcmp(s, "localhost") == 0 || strcmp(s, "broadcasthost") == 0 || strcmp(s, "wpad") == 0 ||
           strcmp(s, "isatap") == 0 || strncmp(s, "ip6-", 4) == 0;
}

/* Marks hide[i] for every entry whose short name is a host-name token of the
 * owner's own lines (outside any tsppc section), compared case-insensitively. */
static void hide_owner_names(const char *old, size_t oldlen, const entry *ents, size_t n, unsigned char *hide)
{
    size_t pos = 0;
    int in_sec = 0;

    while (pos < oldlen) {
        const char *s = old + pos;
        const char *nl = memchr(s, '\n', oldlen - pos);
        size_t len = nl ? (size_t)(nl - s) + 1 : oldlen - pos;
        size_t body = nl ? len - 1 : len, i = 0, tok = 0;
        const char *h;
        pos += len;
        if (in_sec) {
            if (line_is(s, body, TS_HOSTS_END)) in_sec = 0;
            continue;
        }
        if (line_is(s, body, TS_HOSTS_BEGIN)) {
            in_sec = 1;
            continue;
        }
        h = memchr(s, '#', body);
        if (h) body = (size_t)(h - s);
        while (i < body) {
            size_t st, k;
            while (i < body && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r')) i++;
            st = i;
            while (i < body && s[i] != ' ' && s[i] != '\t' && s[i] != '\r') i++;
            if (i == st) break;
            if (tok++ == 0 || i - st > 63) continue;
            for (k = 0; k < n; k++) {
                size_t j;
                if (hide[k] || ents[k].shlen != i - st) continue;
                for (j = 0; j < i - st; j++) {
                    char c = s[st + j];
                    if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                    if (c != ents[k].sh[j]) break;
                }
                if (j == i - st) hide[k] = 1;
            }
        }
    }
}

int ts_hosts_build(char *out, size_t cap, const ts_netmap *nm, const char *old, size_t oldlen,
                   const char *local_short, size_t *nentries, size_t *nskipped)
{
    entry ents[TS_MAX_PEERS + 1];
    int idx[TS_MAX_PEERS + 1];
    unsigned char hide[TS_MAX_PEERS + 1];
    char selfsuf[FQDN_CAP];
    size_t n = 0, skipped = 0, i, j, np = nm->npeers;
    int have_suf = 0;
    wr w;

    if (np > TS_MAX_PEERS) np = TS_MAX_PEERS;
    if (oldlen > TS_HOSTS_FILE_MAX) oldlen = TS_HOSTS_FILE_MAX;
    if (!old) oldlen = 0;
    if (nm->have_self) {
        char f[FQDN_CAP], sh[SHORT_CAP];
        const char *suf;
        if (ts_hosts_name_ok(nm->self.name, f, FQDN_CAP, sh, SHORT_CAP) == 0 && (suf = suffix_of(f)) != NULL) {
            strcpy(selfsuf, suf);
            have_suf = 1;
        }
    }
    for (i = 0; i < np + 1; i++) {
        const ts_node *nd;
        if (i == 0) {
            if (!nm->have_self) continue;
            nd = &nm->self;
        } else {
            nd = &nm->peers[i - 1];
        }
        if (!nd->have_ipv4) continue;
        /* Only names of this tailnet (self's suffix) or of ts.net: control
         * cannot point www.example.com at a tailnet address. */
        if (ts_hosts_name_ok(nd->name, ents[n].fqdn, FQDN_CAP, ents[n].sh, SHORT_CAP) != 0 ||
            suffix_of(ents[n].fqdn) == NULL ||
            !((have_suf && ends_in(ents[n].fqdn, selfsuf)) || ends_in(ents[n].fqdn, "ts.net"))) {
            skipped++;
            continue;
        }
        ents[n].ip = nd->ipv4;
        ents[n].shlen = (unsigned char)strlen(ents[n].sh);
        ents[n].is_self = i == 0;
        n++;
    }
    /* short names: only for our own tailnet's suffix, never the reserved ones */
    for (i = 0; i < n; i++) {
        hide[i] = !have_suf || strcmp(suffix_of(ents[i].fqdn), selfsuf) != 0 || banned_short(ents[i].sh) ||
                  (!ents[i].is_self && local_short && strcmp(ents[i].sh, local_short) == 0);
    }
    {
        /* a short name held by more than one eligible node is withheld from all of them */
        unsigned char h2[TS_MAX_PEERS + 1];
        memcpy(h2, hide, n);
        for (i = 0; i < n; i++) {
            if (hide[i]) continue;
            for (j = 0; j < n; j++) {
                if (j != i && !hide[j] && strcmp(ents[i].sh, ents[j].sh) == 0) h2[i] = 1;
            }
        }
        memcpy(hide, h2, n);
    }
    hide_owner_names(old, oldlen, ents, n, hide);
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
