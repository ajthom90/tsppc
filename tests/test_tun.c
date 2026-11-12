#include "harness.h"

#include <stdio.h>
#include <string.h>

#include "../src/platform/tun.h"

#define IP_TEST 0x64656667u   /* 100.101.102.103 */

/* argv[0..] up to the first NULL, joined by single spaces. */
static void join(char *out, size_t cap, const char **argv)
{
    size_t n = 0;
    int i;
    out[0] = 0;
    for (i = 0; argv[i] && n < cap; i++) n += (size_t)snprintf(out + n, cap - n, "%s%s", i ? " " : "", argv[i]);
}

void test_tun_cmds(void);
void test_tun_cmds(void)
{
    const char *argv[24];
    char buf[256], s[256];
    int n;

    n = ts_tun_cmd_ifconfig_up(argv, 24, buf, sizeof buf, "tun3", IP_TEST);
    join(s, sizeof s, argv);
    t_true("tun: ifconfig up", n == 10 && argv[10] == NULL &&
           strcmp(s, "/sbin/ifconfig tun3 inet 100.101.102.103 100.101.102.103 netmask 255.255.255.255 "
                     "mtu 1280 up") == 0);

    n = ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun3");
    join(s, sizeof s, argv);
    t_true("tun: route add", n == 7 && argv[7] == NULL &&
           strcmp(s, "/sbin/route -n add -net 100.64.0.0/10 -interface tun3") == 0);

    n = ts_tun_cmd_route_delete(argv, 24, buf, sizeof buf);
    join(s, sizeof s, argv);
    t_true("tun: route delete", n == 5 && argv[5] == NULL &&
           strcmp(s, "/sbin/route -n delete -net 100.64.0.0/10") == 0);

    /* Down is two commands: the first, NULL, the second, NULL. */
    n = ts_tun_cmd_ifconfig_down(argv, 24, buf, sizeof buf, "tun3", IP_TEST);
    join(s, sizeof s, argv);
    t_true("tun: ifconfig down, first", n == 9 && argv[5] == NULL &&
           strcmp(s, "/sbin/ifconfig tun3 inet 100.101.102.103 delete") == 0);
    join(s, sizeof s, argv + 6);
    t_true("tun: ifconfig down, second", n == 9 && argv[9] == NULL && strcmp(s, "/sbin/ifconfig tun3 down") == 0);

    t_true("tun: tun15 and tun0 accepted", ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun15") == 7 &&
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun0") == 7);
    t_true("tun: name over 15 bytes refused",
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun0000000000000") == -1 &&
           ts_tun_cmd_ifconfig_up(argv, 24, buf, sizeof buf, "tun0000000000000", IP_TEST) == -1);
    t_true("tun: 15 bytes accepted", ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun000000000000") == 7);
    t_true("tun: not tun + digits refused",
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun") == -1 &&
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "en0") == -1 &&
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun3x") == -1 &&
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun-1") == -1 &&
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "tun 3") == -1 &&
           ts_tun_cmd_route_add(argv, 24, buf, sizeof buf, "TUN3") == -1 &&
           ts_tun_cmd_ifconfig_down(argv, 24, buf, sizeof buf, "utun3", IP_TEST) == -1 &&
           ts_tun_cmd_ifconfig_up(argv, 24, buf, sizeof buf, "", IP_TEST) == -1);
    t_true("tun: small argv or buffer refused",
           ts_tun_cmd_ifconfig_up(argv, 10, buf, sizeof buf, "tun3", IP_TEST) == -1 &&
           ts_tun_cmd_ifconfig_up(argv, 11, buf, sizeof buf, "tun3", IP_TEST) == 10 &&
           ts_tun_cmd_ifconfig_up(argv, 24, buf, 40, "tun3", IP_TEST) == -1 &&
           ts_tun_cmd_ifconfig_down(argv, 9, buf, sizeof buf, "tun3", IP_TEST) == -1 &&
           ts_tun_cmd_route_delete(argv, 5, buf, sizeof buf) == -1);

    /* ts_run: no shell, no PATH, the exit status. */
    {
        const char *t[] = { "/usr/bin/true", NULL };
        const char *f[] = { "/usr/bin/false", NULL };
        const char *m[] = { "/nonexistent/tsppc-none", NULL };
        const char *rel[] = { "true", NULL };
        const char *sh[] = { "/bin/sh", "-c", "exit 3", NULL };
        t_true("run: true exits 0", ts_run(t) == 0);
        t_true("run: false exits non-zero", ts_run(f) > 0);
        t_true("run: a missing program fails", ts_run(m) != 0);
        t_true("run: a relative path is refused", ts_run(rel) == -1);
        t_true("run: exit status returned", ts_run(sh) == 3);
    }
}
