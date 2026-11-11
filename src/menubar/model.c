#include "src/menubar/model.h"

#include <stdio.h>
#include <string.h>

/* ---- helpers ---- */

/* Copy s into a title: bytes outside 0x20-0x7e become '?', and a string that
 * does not fit ends in "..." (three ASCII dots). */
static void set_title(ts_menu_item *it, const char *s)
{
    size_t n = strlen(s), i;
    int cut = 0;
    if (n >= TS_MENU_TITLE_MAX) {
        n = TS_MENU_TITLE_MAX - 1 - 3;
        cut = 1;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        it->title[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    if (cut) {
        it->title[n++] = '.';
        it->title[n++] = '.';
        it->title[n++] = '.';
    }
    it->title[n] = '\0';
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
    if (a->online != b->online) return a->online ? 1 : 0;
    return short_cmp(a->name, b->name) < 0;
}

static int is(const char *a, const char *b) { return strcmp(a, b) == 0; }

static void set_status(ts_menu *m, const char *line, ts_menu_icon icon)
{
    m->icon = icon;
    add(m, line, TS_ACT_NONE, NULL, 0, 0);
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
        else if (is(r->state, "CONNECTING") || (is(r->state, "BACKOFF") && wanted_up)) set_status(m, "Connecting...", TS_ICON_BUSY);
        else if (is(r->state, "IDLE") && login_no) set_status(m, "Not logged in", TS_ICON_OFF);
        else if (is(r->state, "IDLE") && login_yes && !wanted_up) set_status(m, "Disconnected", TS_ICON_OFF);
        else if (wanted_up) set_status(m, "Connecting...", TS_ICON_BUSY);
        else set_status(m, "Disconnected", TS_ICON_OFF);

        if (r->problem[0]) add(m, r->problem, TS_ACT_NONE, NULL, 0, 0);

        if (r->have_ipv4) {
            fmt_ip(ip, sizeof ip, r->ipv4);
            short_name(r->self, &sn, &snn);
            snprintf(tmp, sizeof tmp, "This Mac: %.*s (%s)", (int)snn, sn, ip);
            add(m, tmp, TS_ACT_COPY, ip, 1, 0);
        }

        if (!leaving && ((login_yes && !wanted_up) || login_no)) add(m, "Connect", TS_ACT_UP, NULL, 1, 0);
        if (!leaving && wanted_up) add(m, "Disconnect", TS_ACT_DOWN, NULL, 1, 0);
        if (r->url[0]) add(m, "Log In...", TS_ACT_LOGIN, r->url, 1, 0);

        if (r->npeers > 0 && r->peers) {
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
                snprintf(tmp, sizeof tmp, "%.*s  %s%s", (int)snn, sn, p->have_ipv4 ? ip : "no address", p->online ? "" : " (offline)");
                add(m, tmp, p->have_ipv4 ? TS_ACT_COPY : TS_ACT_NONE, p->have_ipv4 ? ip : NULL, p->have_ipv4, 1);
            }
            if (r->truncated) add(m, "More devices not shown", TS_ACT_NONE, NULL, 0, 1);
        }

        if (login_yes && !leaving) add(m, "Log Out...", TS_ACT_LOGOUT, NULL, 1, 0);
    }
    add(m, "Quit tsppc", TS_ACT_QUIT, NULL, 1, 0);
}
