#include "harness.h"

#include <stdio.h>
#include <string.h>

#include "../src/menubar/model.h"

/* ts_menu and ts_reply are large: static, never on the stack. */
static ts_menu g_m;
static ts_reply g_r;
static ts_reply_peer g_peers[TS_MAX_PEERS];

static void reset(const char *state, const char *login, const char *wanted)
{
    memset(&g_r, 0, sizeof g_r);
    g_r.ok = 1;
    g_r.peers = g_peers;
    snprintf(g_r.state, sizeof g_r.state, "%s", state);
    snprintf(g_r.login, sizeof g_r.login, "%s", login);
    snprintf(g_r.wanted, sizeof g_r.wanted, "%s", wanted);
}

static void add_peer(const char *name, int online, int have_ip, unsigned ip)
{
    ts_reply_peer *p = &g_peers[g_r.npeers++];
    memset(p, 0, sizeof *p);
    snprintf(p->name, sizeof p->name, "%s", name);
    p->online = online;
    p->have_ipv4 = have_ip;
    p->ipv4 = ip;
}

/* Index of the first item with this exact title, or -1. */
static int find(const char *title)
{
    size_t i;
    for (i = 0; i < g_m.nitems; i++)
        if (strcmp(g_m.items[i].title, title) == 0) return (int)i;
    return -1;
}

static int find_act(ts_menu_action a)
{
    size_t i;
    for (i = 0; i < g_m.nitems; i++)
        if (g_m.items[i].action == a) return (int)i;
    return -1;
}

static void build(void) { ts_menu_build(&g_m, TS_REQ_OK, &g_r); }

static void check_status(const char *name, const char *want, ts_menu_icon icon)
{
    t_true(name, g_m.nitems >= 2 && strcmp(g_m.items[0].title, want) == 0 && g_m.items[0].action == TS_ACT_NONE &&
                     !g_m.items[0].enabled && g_m.icon == icon);
}

static void state_case(const char *name, const char *state, const char *login, const char *wanted, const char *want, ts_menu_icon icon)
{
    reset(state, login, wanted);
    build();
    check_status(name, want, icon);
}

static void test_status_table(void)
{
    ts_menu_build(&g_m, TS_REQ_NO_DAEMON, NULL);
    t_true("no daemon", g_m.nitems == 2 && strcmp(g_m.items[0].title, "tsppcd is not running") == 0 && g_m.icon == TS_ICON_ERROR &&
                            g_m.items[1].action == TS_ACT_QUIT && strcmp(g_m.items[1].title, "Quit tsppc") == 0 && g_m.items[1].enabled);
    ts_menu_build(&g_m, TS_REQ_DENIED, NULL);
    t_true("denied", g_m.nitems == 2 && strcmp(g_m.items[0].title, "Needs an administrator account") == 0 && g_m.icon == TS_ICON_ERROR);
    ts_menu_build(&g_m, TS_REQ_TIMEOUT, NULL);
    t_true("timeout", g_m.nitems == 2 && strcmp(g_m.items[0].title, "tsppcd is not responding") == 0 && g_m.icon == TS_ICON_ERROR);
    ts_menu_build(&g_m, TS_REQ_FAILED, NULL);
    t_true("failed", g_m.nitems == 2 && strcmp(g_m.items[0].title, "tsppcd is not responding") == 0 && g_m.icon == TS_ICON_ERROR);
    reset("RUNNING", "yes", "up");
    g_r.ok = 0;
    snprintf(g_r.error, sizeof g_r.error, "bad command");
    ts_menu_build(&g_m, TS_REQ_OK, &g_r);
    t_true("error reply shows the error", g_m.nitems == 2 && strcmp(g_m.items[0].title, "tsppcd error: bad command") == 0 && g_m.icon == TS_ICON_ERROR);
    g_r.error[0] = '\0';
    ts_menu_build(&g_m, TS_REQ_OK, &g_r);
    t_true("ok result without ok reply", g_m.nitems == 2 && strcmp(g_m.items[0].title, "tsppcd is not responding") == 0);
    ts_menu_build(&g_m, TS_REQ_OK, NULL);
    t_true("ok result with no reply", g_m.nitems == 2 && g_m.icon == TS_ICON_ERROR);

    state_case("running", "RUNNING", "yes", "up", "Connected", TS_ICON_ON);
    state_case("need login", "NEED_LOGIN", "no", "up", "Login needed", TS_ICON_ATTENTION);
    state_case("await approval", "AWAIT_APPROVAL", "yes", "up", "Waiting for approval in the admin console", TS_ICON_ATTENTION);
    state_case("connecting", "CONNECTING", "yes", "up", "Connecting...", TS_ICON_BUSY);
    state_case("backoff up", "BACKOFF", "yes", "up", "Connecting...", TS_ICON_BUSY);
    state_case("idle yes down", "IDLE", "yes", "down", "Disconnected", TS_ICON_OFF);
    state_case("idle no", "IDLE", "no", "down", "Not logged in", TS_ICON_OFF);
    state_case("failed", "FAILED", "yes", "up", "Stopped: see tsppc status", TS_ICON_ERROR);
}

static void test_total(void)
{
    state_case("backoff down", "BACKOFF", "yes", "down", "Disconnected", TS_ICON_OFF);
    state_case("idle yes up", "IDLE", "yes", "up", "Connecting...", TS_ICON_BUSY);
    state_case("unknown state up", "WEIRD", "yes", "up", "Connecting...", TS_ICON_BUSY);
    state_case("unknown state down", "WEIRD", "yes", "down", "Disconnected", TS_ICON_OFF);
    state_case("empty everything", "", "", "", "Disconnected", TS_ICON_OFF);
    state_case("connecting wanted down", "CONNECTING", "yes", "down", "Disconnected", TS_ICON_OFF);
    state_case("connecting wanted down, no login", "CONNECTING", "no", "down", "Not logged in", TS_ICON_OFF);
    state_case("backoff wanted down, no login", "BACKOFF", "no", "down", "Not logged in", TS_ICON_OFF);
    state_case("backoff wanted unknown", "BACKOFF", "yes", "", "Disconnected", TS_ICON_OFF);
    state_case("leaving idle", "IDLE", "leaving", "down", "Logging out...", TS_ICON_BUSY);
    state_case("leaving running", "RUNNING", "leaving", "up", "Logging out...", TS_ICON_BUSY);
    reset("RUNNING", "leaving", "up");
    g_r.have_ipv4 = 1;
    g_r.ipv4 = 0x64400001u;
    build();
    t_true("leaving has no connect, disconnect or logout",
           find("Connect") < 0 && find("Disconnect") < 0 && find_act(TS_ACT_UP) < 0 && find_act(TS_ACT_DOWN) < 0 && find_act(TS_ACT_LOGOUT) < 0);
    t_true("leaving still has quit and copy", find("Quit tsppc") >= 0 && find_act(TS_ACT_COPY) >= 0);
}

static void test_items_table(void)
{
    int i;
    reset("RUNNING", "yes", "up");
    build();
    t_true("up: Disconnect, no Connect", find("Disconnect") >= 0 && find("Connect") < 0 && g_m.items[find("Disconnect")].action == TS_ACT_DOWN);
    t_true("yes: Log Out", find("Log Out...") >= 0 && g_m.items[find("Log Out...")].action == TS_ACT_LOGOUT && g_m.items[find("Log Out...")].enabled);
    t_true("no problem line, no url, no ip, no devices", g_m.nitems == 4 && find("Log In...") < 0 && find_act(TS_ACT_COPY) < 0 &&
                                                         g_m.items[g_m.nitems - 1].action == TS_ACT_QUIT);

    reset("IDLE", "yes", "down");
    build();
    t_true("yes+down: Connect", find("Connect") >= 0 && g_m.items[find("Connect")].action == TS_ACT_UP && find("Disconnect") < 0);
    reset("NEED_LOGIN", "no", "up");
    build();
    t_true("NEED_LOGIN no+up, no url: Disconnect and Log In Again...", find("Connect") < 0 && find("Disconnect") >= 0 &&
           find("Log In Again...") >= 0 && find("Log Out...") < 0);
    reset("IDLE", "no", "down");
    build();
    t_true("login no wanted down: Connect only", find("Connect") >= 0 && find("Disconnect") < 0 && find("Log Out...") < 0);

    reset("NEED_LOGIN", "no", "up");
    snprintf(g_r.url, sizeof g_r.url, "https://login.example.test/a/abc123");
    build();
    i = find("Log In...");
    t_true("url: Log In... with arg", i >= 0 && g_m.items[i].action == TS_ACT_LOGIN && g_m.items[i].enabled &&
                                          strcmp(g_m.items[i].arg, "https://login.example.test/a/abc123") == 0);

    reset("FAILED", "yes", "up");
    snprintf(g_r.problem, sizeof g_r.problem, "control server unreachable");
    build();
    t_true("problem line is second, disabled", g_m.nitems >= 3 && strcmp(g_m.items[1].title, "control server unreachable") == 0 &&
                                                   g_m.items[1].action == TS_ACT_NONE && !g_m.items[1].enabled);

    reset("RUNNING", "yes", "up");
    g_r.have_ipv4 = 1;
    g_r.ipv4 = (100u << 24) | (64u << 16) | 5u;
    snprintf(g_r.self, sizeof g_r.self, "laptop.example.test.");
    build();
    i = find("This Mac: laptop (100.64.0.5)");
    t_true("this mac copies ip", i == 1 && g_m.items[i].action == TS_ACT_COPY && strcmp(g_m.items[i].arg, "100.64.0.5") == 0 && g_m.items[i].enabled);
    reset("RUNNING", "yes", "up");
    g_r.have_ipv4 = 1;
    g_r.ipv4 = (100u << 24) | (64u << 16) | 5u;
    snprintf(g_r.self, sizeof g_r.self, "nodot");
    build();
    t_true("self without dot", find("This Mac: nodot (100.64.0.5)") >= 0);
    reset("RUNNING", "yes", "up");
    g_r.have_ipv4 = 1;
    g_r.ipv4 = (100u << 24) | (64u << 16) | 5u;
    build();
    t_true("empty self", find("This Mac: (no name) (100.64.0.5)") >= 0);
}

static void test_down_hides(void)
{
    reset("IDLE", "yes", "down");
    build();
    t_true("yes+down: Connect only", find("Connect") >= 0 && find("Disconnect") < 0);
    reset("IDLE", "yes", "down");
    g_r.have_ipv4 = 1;
    g_r.ipv4 = 0x64400001u;
    snprintf(g_r.self, sizeof g_r.self, "laptop.example.test.");
    add_peer("a.example.test.", 1, 1, 0x64400002u);
    g_r.truncated = 1;
    build();
    t_true("down: no This Mac", find("This Mac: laptop (100.64.0.1)") < 0 && find_act(TS_ACT_COPY) < 0);
    t_true("down: no devices submenu", find("Devices (1 online)") < 0 && find("More devices not shown") < 0 && g_m.ndevices_online == 0);
    t_true("down: only status, Connect, Log Out, Quit", g_m.nitems == 4);
    g_r.wanted[0] = '\0';
    build();
    t_true("wanted unknown: Connect, no stale items", find("Connect") >= 0 && find("Disconnect") < 0 && find_act(TS_ACT_COPY) < 0);
    snprintf(g_r.wanted, sizeof g_r.wanted, "up");
    build();
    t_true("up: This Mac and devices shown", find("This Mac: laptop (100.64.0.1)") >= 0 && find("Devices (1 online)") >= 0);
}

/* Stuck states that wait for an up get an item that sends one. */
static void test_retry(void)
{
    int d, i;
    reset("NEED_LOGIN", "yes", "up");
    snprintf(g_r.problem, sizeof g_r.problem, "node key expired, run `tsppc up`");
    build();
    d = find("Disconnect");
    i = find("Log In Again...");
    t_true("expired: Log In Again... after Disconnect", d >= 0 && i == d + 1 && g_m.items[i].action == TS_ACT_UP &&
           g_m.items[i].enabled && g_m.items[i].arg[0] == '\0');
    t_true("expired: no Connect, no Log In..., one up item", find("Connect") < 0 && find("Log In...") < 0 &&
           find_act(TS_ACT_UP) == i && find("Try Again") < 0);

    reset("FAILED", "yes", "up");
    build();
    d = find("Disconnect");
    i = find("Try Again");
    t_true("failed: Try Again after Disconnect", d >= 0 && i == d + 1 && g_m.items[i].action == TS_ACT_UP && g_m.items[i].enabled);
    t_true("failed: no Log In Again...", find("Log In Again...") < 0 && find("Connect") < 0);

    reset("NEED_LOGIN", "no", "up");
    snprintf(g_r.url, sizeof g_r.url, "https://login.example.test/a/abc123");
    build();
    t_true("url: Log In... and no extra up item", find("Log In...") >= 0 && find_act(TS_ACT_UP) < 0 &&
           find("Log In Again...") < 0 && find("Try Again") < 0 && find("Disconnect") >= 0);

    reset("FAILED", "yes", "down");
    build();
    t_true("failed, wanted down: Connect only", find("Connect") >= 0 && find("Try Again") < 0 && find("Disconnect") < 0);
    reset("NEED_LOGIN", "leaving", "up");
    build();
    t_true("leaving: no up item", find_act(TS_ACT_UP) < 0);
    reset("RUNNING", "yes", "up");
    build();
    t_true("running: no up item", find_act(TS_ACT_UP) < 0);
}

/* The problem line and an error status line carry their whole text for a tooltip. */
static void test_tooltips(void)
{
    char longp[300];
    size_t i;
    for (i = 0; i < sizeof longp - 1; i++) longp[i] = (char)('a' + i % 26);
    longp[sizeof longp - 1] = '\0';
    longp[5] = '\t';
    reset("BACKOFF", "yes", "up");
    snprintf(g_r.problem, sizeof g_r.problem, "%s", longp);
    build();
    longp[5] = '?';
    t_true("problem: title cut", strlen(g_m.items[1].title) == TS_MENU_TITLE_MAX - 1 &&
           strcmp(g_m.items[1].title + TS_MENU_TITLE_MAX - 4, "...") == 0 && g_m.items[1].action == TS_ACT_NONE);
    t_true("problem: whole cleaned text in arg", strcmp(g_m.items[1].arg, longp) == 0);
    t_true("plain status line: no tooltip", g_m.items[0].arg[0] == '\0');

    reset("BACKOFF", "yes", "up");
    snprintf(g_r.problem, sizeof g_r.problem, "short");
    build();
    t_true("short problem: tooltip too", strcmp(g_m.items[1].title, "short") == 0 && strcmp(g_m.items[1].arg, "short") == 0);

    reset("RUNNING", "yes", "up");
    g_r.ok = 0;
    snprintf(g_r.error, sizeof g_r.error, "%s", longp);
    build();
    t_true("error status: title cut, whole text in arg", strlen(g_m.items[0].title) == TS_MENU_TITLE_MAX - 1 &&
           strncmp(g_m.items[0].arg, "tsppcd error: ", 14) == 0 && strcmp(g_m.items[0].arg + 14, longp) == 0);

    memset(g_r.error, 'e', sizeof g_r.error - 1);
    g_r.error[sizeof g_r.error - 1] = '\0';
    build();
    t_true("error status: over-long text cut in arg too", strlen(g_m.items[0].arg) == sizeof g_m.items[0].arg - 1 &&
           strcmp(g_m.items[0].arg + sizeof g_m.items[0].arg - 4, "...") == 0);
}

static void moving_case(const char *name, const char *state, const char *login, const char *wanted, int want)
{
    reset(state, login, wanted);
    t_true(name, ts_menu_moving(TS_REQ_OK, &g_r) == want);
}

static void test_moving(void)
{
    moving_case("moving: connecting up", "CONNECTING", "yes", "up", 1);
    moving_case("moving: backoff up", "BACKOFF", "yes", "up", 1);
    moving_case("moving: need login up", "NEED_LOGIN", "no", "up", 1);
    moving_case("moving: await approval up", "AWAIT_APPROVAL", "yes", "up", 1);
    moving_case("moving: leaving", "IDLE", "leaving", "down", 1);
    moving_case("still: running", "RUNNING", "yes", "up", 0);
    moving_case("still: connecting down", "CONNECTING", "yes", "down", 0);
    moving_case("still: backoff down", "BACKOFF", "no", "down", 0);
    moving_case("still: idle down", "IDLE", "yes", "down", 0);
    moving_case("still: failed up", "FAILED", "yes", "up", 0);
    reset("CONNECTING", "yes", "up");
    t_true("still: not ok", ts_menu_moving(TS_REQ_TIMEOUT, &g_r) == 0 && ts_menu_moving(TS_REQ_OK, NULL) == 0);
    g_r.ok = 0;
    t_true("still: error reply", ts_menu_moving(TS_REQ_OK, &g_r) == 0);
}

static void test_devices(void)
{
    size_t i;
    int p;
    reset("RUNNING", "yes", "up");
    add_peer("zed.example.test.", 1, 1, (100u << 24) | (64u << 16) | 3u);
    add_peer("alpha.example.test.", 0, 1, (100u << 24) | (64u << 16) | 1u);
    add_peer("mid.example.test.", 1, 0, 0);
    add_peer("alpha.example.test.", 1, 1, (100u << 24) | (64u << 16) | 2u);
    add_peer("", 1, 1, (100u << 24) | (64u << 16) | 9u);
    add_peer("dup.a.test.", 1, 1, (100u << 24) | (64u << 16) | 20u);
    add_peer("dup.b.test.", 1, 1, (100u << 24) | (64u << 16) | 21u);
    build();
    t_true("online count", g_m.ndevices_online == 6);
    p = find("Devices (6 online)");
    t_true("devices parent", p > 0 && g_m.items[p].action == TS_ACT_NONE && g_m.items[p].enabled && !g_m.items[p].in_devices);
    t_true("order: online by name then offline",
           strcmp(g_m.items[p + 1].title, "(no name)  100.64.0.9") == 0 &&
               strcmp(g_m.items[p + 2].title, "alpha  100.64.0.2") == 0 &&
               strcmp(g_m.items[p + 3].title, "dup  100.64.0.20") == 0 &&
               strcmp(g_m.items[p + 4].title, "dup  100.64.0.21") == 0 &&
               strcmp(g_m.items[p + 5].title, "mid  no address") == 0 &&
               strcmp(g_m.items[p + 6].title, "zed  100.64.0.3") == 0 &&
               strcmp(g_m.items[p + 7].title, "alpha  100.64.0.1 (offline)") == 0);
    t_true("device items in_devices, copy ip",
           g_m.items[p + 2].in_devices == 1 && g_m.items[p + 2].action == TS_ACT_COPY && g_m.items[p + 2].enabled &&
               strcmp(g_m.items[p + 2].arg, "100.64.0.2") == 0);
    t_true("peer without ip is disabled and has no copy",
           g_m.items[p + 5].in_devices == 1 && g_m.items[p + 5].action == TS_ACT_NONE && !g_m.items[p + 5].enabled && g_m.items[p + 5].arg[0] == '\0');
    t_true("offline peer with ip can still copy", g_m.items[p + 7].action == TS_ACT_COPY && g_m.items[p + 7].enabled);
    t_true("no more-devices line", find("More devices not shown") < 0);
    t_true("log out and quit follow devices", g_m.items[p + 8].action == TS_ACT_LOGOUT && g_m.items[p + 9].action == TS_ACT_QUIT && g_m.nitems == (size_t)p + 10);

    g_r.truncated = 1;
    build();
    i = (size_t)find("More devices not shown");
    t_true("truncated line", i == (size_t)p + 8 && !g_m.items[i].enabled && g_m.items[i].in_devices == 1 && g_m.items[i].action == TS_ACT_NONE);

    reset("RUNNING", "yes", "up");
    add_peer("a.example.test.", 0, 1, 1);
    build();
    t_true("zero online", find("Devices (0 online)") >= 0);
    reset("RUNNING", "yes", "up");
    g_r.truncated = 1;
    build();
    t_true("no peers: no devices menu", find("More devices not shown") < 0 && g_m.nitems == 4);
}

static void test_names(void)
{
    static char big[301];
    size_t n;
    int p;
    reset("RUNNING", "yes", "up");
    memset(big, 'x', 300);
    big[300] = '\0';
    snprintf(g_r.self, sizeof g_r.self, "%s", big);   /* cut to 255 by the buffer */
    g_r.have_ipv4 = 1;
    g_r.ipv4 = 0x64400001u;
    build();
    n = strlen(g_m.items[1].title);
    t_true("long self: name cut with dots, ip kept", n == TS_MENU_TITLE_MAX - 1 && strncmp(g_m.items[1].title, "This Mac: xxx", 13) == 0 &&
                                                         strcmp(g_m.items[1].title + n - 19, "... (100.64.0.1)") != 0 && strcmp(g_m.items[1].title + n - 16, "... (100.64.0.1)") == 0);
    t_true("long self still copies the ip", g_m.items[1].action == TS_ACT_COPY && strcmp(g_m.items[1].arg, "100.64.0.1") == 0);

    reset("RUNNING", "yes", "up");
    memset(big, 'y', 300);
    snprintf(g_r.problem, sizeof g_r.problem, "%s", big);
    add_peer(big, 1, 1, 0x64400002u);
    add_peer("q\x01\x7f\xc3\xa9?z.example.test.", 1, 1, 0x64400003u);
    build();
    n = strlen(g_m.items[1].title);
    t_true("long problem cut with dots", n == TS_MENU_TITLE_MAX - 1 && strcmp(g_m.items[1].title + n - 3, "...") == 0);
    p = find("Devices (2 online)");
    n = strlen(g_m.items[p + 2].title);
    t_true("long device name: cut with dots, ip kept", n == TS_MENU_TITLE_MAX - 1 && strcmp(g_m.items[p + 2].title + n - 15, "...  100.64.0.2") == 0);
    {
        size_t i, j;
        int ok = 1;
        for (i = 0; i < g_m.nitems; i++)
            for (j = 0; g_m.items[i].title[j]; j++)
                if ((unsigned char)g_m.items[i].title[j] < 0x20 || (unsigned char)g_m.items[i].title[j] > 0x7e) ok = 0;
        t_true("every title printable", ok);
    }
    /* stray bytes become '?' */
    t_true("stray bytes replaced", strcmp(g_m.items[p + 1].title, "q?????z  100.64.0.3") == 0);

    /* a realistic 45-byte name keeps its ip, and "(offline)" when offline */
    reset("RUNNING", "yes", "up");
    memset(big, 'k', 45);
    big[45] = '\0';
    add_peer(big, 1, 1, 0x64400005u);
    add_peer(big, 0, 1, 0x64400006u);
    build();
    p = find("Devices (1 online)");
    n = strlen(g_m.items[p + 1].title);
    t_true("45-byte online name: whole name and ip kept", n == 45 + 2 + 10 && strcmp(g_m.items[p + 1].title + n - 12, "  100.64.0.5") == 0);
    n = strlen(g_m.items[p + 2].title);
    t_true("45-byte offline name: ip and (offline) kept", n <= TS_MENU_TITLE_MAX - 1 && strstr(g_m.items[p + 2].title, "...  100.64.0.6 (offline)") != NULL &&
                                                              strcmp(g_m.items[p + 2].title + n - 10, " (offline)") == 0);

    reset("RUNNING", "yes", "up");
    add_peer("ab?cd.example.test.", 1, 1, 0x64400004u);
    build();
    t_true("cleaned ? name", find("ab?cd  100.64.0.4") >= 0);
}

static void test_capacity(void)
{
    size_t i;
    int p;
    reset("RUNNING", "yes", "up");
    g_r.have_ipv4 = 1;
    g_r.ipv4 = 0x64400001u;
    snprintf(g_r.problem, sizeof g_r.problem, "p");
    snprintf(g_r.url, sizeof g_r.url, "https://login.example.test/x");
    g_r.truncated = 1;
    for (i = 0; i < TS_MAX_PEERS; i++) {
        char nm[32];
        snprintf(nm, sizeof nm, "n%03u.example.test.", (unsigned)(TS_MAX_PEERS - 1 - i));
        add_peer(nm, (int)(i & 1), 1, 0x64400000u + (unsigned)i);
    }
    build();
    p = find("Devices (128 online)");
    t_true("256 peers fit", p > 0 && g_m.nitems <= TS_MENU_MAX_ITEMS && g_m.nitems == 256 + 9 && g_m.ndevices_online == 128);
    t_true("sorted online first", strncmp(g_m.items[p + 1].title, "n000", 4) == 0 && strstr(g_m.items[p + 128].title, "(offline)") == NULL &&
                                      strstr(g_m.items[p + 129].title, "(offline)") != NULL);
}

void test_menu_model(void)
{
    test_status_table();
    test_total();
    test_items_table();
    test_down_hides();
    test_retry();
    test_tooltips();
    test_moving();
    test_devices();
    test_names();
    test_capacity();
}
