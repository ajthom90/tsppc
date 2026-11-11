#include "src/menubar/model.h"

#include <stdio.h>
#include <string.h>

/* ---- helpers ---- */

/* Copy s into dst (cap bytes, NUL included): bytes outside 0x20-0x7e become
 * '?', and a string that does not fit ends in "..." (three ASCII dots). */
static void clean_cut(char *dst, size_t cap, const char *s)
{
    size_t n = strlen(s), i;
    int cut = 0;
    if (n >= cap) {
        n = cap - 1 - 3;
        cut = 1;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        dst[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    if (cut) {
        dst[n++] = '.';
        dst[n++] = '.';
        dst[n++] = '.';
    }
    dst[n] = '\0';
}

static void set_title(ts_menu_item *it, const char *s)
{
    clean_cut(it->title, sizeof it->title, s);
}

static ts_menu_item *add(ts_menu *m, const char *title, ts_menu_action act, const char *arg, int enabled, int in_devices)
{
    ts_menu_item *it;
    if (m->nitems >= TS_MENU_MAX_ITEMS) return NULL;   /* cannot happen: 256 peers + at most 11 */
    it = &m->items[m->nitems++];
    set_title(it, title);
    it->action = act;
    it->arg[0] = '\0';
    if (arg) {
        size_t n = strlen(arg);
        if (n >= sizeof it->arg) n = sizeof it->arg - 1;
        memcpy(it->arg, arg, n);
        it->arg[n] = '\0';
    }
    it->enabled = enabled;
    it->in_devices = in_devices;
    return it;
}

/* prefix + name + suffix as one item. When it would not fit, only the name is
 * cut (ending in "..."), so the suffix (the ip) stays visible. */
static ts_menu_item *add_named(ts_menu *m, const char *prefix, const char *name, size_t nlen, const char *suffix,
                               ts_menu_action act, const char *arg, int enabled, int in_devices)
{
    char tmp[TS_MENU_TITLE_MAX + 8 + TS_NODE_NAME_MAX];
    size_t fixed = strlen(prefix) + strlen(suffix), room = TS_MENU_TITLE_MAX - 1;
    int cut = 0;
    if (fixed + nlen > room) {
        nlen = (room > fixed + 3) ? room - fixed - 3 : 0;
        cut = 1;
    }
    snprintf(tmp, sizeof tmp, "%s%.*s%s%s", prefix, (int)nlen, name, cut ? "..." : "", suffix);
    return add(m, tmp, act, arg, enabled, in_devices);
}

static void fmt_ip(char *out, size_t cap, unsigned long ip)
{
    snprintf(out, cap, "%lu.%lu.%lu.%lu", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

/* Short name: the text before the first '.', or all of it. Empty gives "(no name)". */
static void short_name(const char *name, const char **s, size_t *n)
{
    const char *dot = strchr(name, '.');
    size_t len = dot ? (size_t)(dot - name) : strlen(name);
    if (len == 0) {
        *s = "(no name)";
        *n = 9;
    } else {
        *s = name;
        *n = len;
    }
}

/* Byte comparison of the short names, shorter first on a common prefix. */
static int short_cmp(const char *a, const char *b)
{
    const char *sa, *sb;
    size_t na, nb, n;
    int c;
    short_name(a, &sa, &na);
    short_name(b, &sb, &nb);
    n = na < nb ? na : nb;
    c = memcmp(sa, sb, n);
    if (c) return c;
    return na < nb ? -1 : (na > nb ? 1 : 0);
}

/* Order: online first, then short name. Ties are not ordered (stable sort keeps reply order). */
static int peer_before(const ts_reply_peer *a, const ts_reply_peer *b)
{
    if (!a->online != !b->online) return a->online ? 1 : 0;
    return short_cmp(a->name, b->name) < 0;
}

static int is(const char *a, const char *b) { return strcmp(a, b) == 0; }

static void set_status(ts_menu *m, const char *line, ts_menu_icon icon)
{
    m->icon = icon;
    add(m, line, TS_ACT_NONE, NULL, 0, 0);
}

/* A NONE line whose title may be cut: the whole text goes in arg too (cleaned
 * the same way), for the tooltip. */
static void add_text(ts_menu *m, const char *text)
{
    ts_menu_item *it = add(m, text, TS_ACT_NONE, NULL, 0, 0);
    if (it) clean_cut(it->arg, sizeof it->arg, text);
}

/* ---- the build ---- */

void ts_menu_build(ts_menu *m, ts_req_result res, const ts_reply *r)
{
    char tmp[TS_NODE_NAME_MAX + TS_IPC_VALUE_MAX + 64];
    char ip[24];
    const char *sn;
    size_t snn;
    int leaving, wanted_up, login_yes, login_no;

    m->nitems = 0;
    m->ndevices_online = 0;

    if (res == TS_REQ_NO_DAEMON) {
        set_status(m, "tsppcd is not running", TS_ICON_ERROR);
    } else if (res == TS_REQ_DENIED) {
        set_status(m, "Needs an administrator account", TS_ICON_ERROR);
    } else if (res == TS_REQ_OK && r != NULL && !r->ok && r->error[0]) {
        snprintf(tmp, sizeof tmp, "tsppcd error: %s", r->error);
        m->icon = TS_ICON_ERROR;
        add_text(m, tmp);
    } else if (res != TS_REQ_OK || r == NULL || !r->ok) {
        set_status(m, "tsppcd is not responding", TS_ICON_ERROR);
    } else {
        leaving = is(r->login, "leaving");
        wanted_up = is(r->wanted, "up");
        login_yes = is(r->login, "yes");
        login_no = is(r->login, "no");

        /* status line and icon: a total function of state, login and wanted */
        if (leaving) set_status(m, "Logging out...", TS_ICON_BUSY);
        else if (is(r->state, "RUNNING")) set_status(m, "Connected", TS_ICON_ON);
        else if (is(r->state, "NEED_LOGIN")) set_status(m, "Login needed", TS_ICON_ATTENTION);
        else if (is(r->state, "AWAIT_APPROVAL")) set_status(m, "Waiting for approval in the admin console", TS_ICON_ATTENTION);
        else if (is(r->state, "FAILED")) set_status(m, "Stopped: see tsppc status", TS_ICON_ERROR);
        /* wanted down: a key fetch still running (CONNECTING/BACKOFF) is not shown */
        else if (!wanted_up && (is(r->state, "CONNECTING") || is(r->state, "BACKOFF")))
            set_status(m, login_no ? "Not logged in" : "Disconnected", TS_ICON_OFF);
        else if (is(r->state, "CONNECTING") || is(r->state, "BACKOFF")) set_status(m, "Connecting...", TS_ICON_BUSY);
        else if (is(r->state, "IDLE") && login_no) set_status(m, "Not logged in", TS_ICON_OFF);
        else if (is(r->state, "IDLE") && login_yes && !wanted_up) set_status(m, "Disconnected", TS_ICON_OFF);
        else if (wanted_up) set_status(m, "Connecting...", TS_ICON_BUSY);
        else set_status(m, "Disconnected", TS_ICON_OFF);

        if (r->problem[0]) add_text(m, r->problem);

        if (r->have_ipv4 && wanted_up) {  /* the map is stale while wanted is down (the daemon leaves it out too) */
            fmt_ip(ip, sizeof ip, r->ipv4);
            short_name(r->self, &sn, &snn);
            snprintf(tmp, sizeof tmp, " (%s)", ip);
            add_named(m, "This Mac: ", sn, snn, tmp, TS_ACT_COPY, ip, 1, 0);
        }

        /* one of Connect or Disconnect, never both, and neither while leaving */
        if (!leaving && wanted_up) {
            add(m, "Disconnect", TS_ACT_DOWN, NULL, 1, 0);
            /* Stuck until the next up: key expired or removed (NEED_LOGIN with
             * no url), or FAILED. */
            if (is(r->state, "FAILED")) add(m, "Try Again", TS_ACT_UP, NULL, 1, 0);
            else if (is(r->state, "NEED_LOGIN") && !r->url[0]) add(m, "Log In Again...", TS_ACT_UP, NULL, 1, 0);
        } else if (!leaving) {
            add(m, "Connect", TS_ACT_UP, NULL, 1, 0);
        }
        if (r->url[0]) add(m, "Log In...", TS_ACT_LOGIN, r->url, 1, 0);

        if (wanted_up && r->npeers > 0 && r->peers) {
            unsigned short order[TS_MAX_PEERS];
            size_t n = r->npeers, i, j;
            if (n > TS_MAX_PEERS) n = TS_MAX_PEERS;
            for (i = 0; i < n; i++) {
                if (r->peers[i].online) m->ndevices_online++;
                /* stable insertion sort of indexes */
                for (j = i; j > 0 && peer_before(&r->peers[i], &r->peers[order[j - 1]]); j--) order[j] = order[j - 1];
                order[j] = (unsigned short)i;
            }
            snprintf(tmp, sizeof tmp, "Devices (%lu online)", (unsigned long)m->ndevices_online);
            add(m, tmp, TS_ACT_NONE, NULL, 1, 0);
            for (i = 0; i < n; i++) {
                const ts_reply_peer *p = &r->peers[order[i]];
                short_name(p->name, &sn, &snn);
                if (p->have_ipv4) fmt_ip(ip, sizeof ip, p->ipv4);
                snprintf(tmp, sizeof tmp, "  %s%s", p->have_ipv4 ? ip : "no address", p->online ? "" : " (offline)");
                add_named(m, "", sn, snn, tmp, p->have_ipv4 ? TS_ACT_COPY : TS_ACT_NONE, p->have_ipv4 ? ip : NULL, p->have_ipv4, 1);
            }
            if (r->truncated) add(m, "More devices not shown", TS_ACT_NONE, NULL, 0, 1);
        }

        if (login_yes && !leaving) add(m, "Log Out...", TS_ACT_LOGOUT, NULL, 1, 0);
    }
    add(m, "Quit tsppc", TS_ACT_QUIT, NULL, 1, 0);
}

int ts_menu_moving(ts_req_result res, const ts_reply *r)
{
    if (res != TS_REQ_OK || r == NULL || !r->ok) return 0;
    if (is(r->login, "leaving")) return 1;
    if (!is(r->wanted, "up")) return 0;
    return is(r->state, "CONNECTING") || is(r->state, "BACKOFF") || is(r->state, "NEED_LOGIN") ||
           is(r->state, "AWAIT_APPROVAL");
}
