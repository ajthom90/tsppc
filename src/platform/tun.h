#ifndef TS_PLATFORM_TUN_H
#define TS_PLATFORM_TUN_H

#include <stddef.h>
#include <stdint.h>

/* The tun device (tuntaposx /dev/tunN: raw IPv4 packets, no header) and the
 * commands that give it our address and the tailnet route.
 *
 * The command builders fill argv with pointers into buf (no shell, absolute
 * paths) and return the number of entries before the terminating NULL, or -1
 * if ifname is not "tun" followed by 1 or more digits (at most 15 bytes in
 * all) or argv (max entries, the NULL included) or buf (cap bytes) is too
 * small. ts_tun_cmd_ifconfig_down builds two commands: argv holds the first,
 * a NULL, the second and a NULL, and the count covers all of that except the
 * last NULL; the second starts after the first NULL. Addresses are host byte
 * order. */

#define TS_TUN_MAX_UNIT 15
#define TS_TUN_MTU 1280
#define TS_TAILNET_NET "100.64.0.0/10"
#define TS_RUN_LIMIT_MS 10000

/* The first /dev/tunN (N = 0..TS_TUN_MAX_UNIT) that opens, as a non-blocking,
 * close-on-exec descriptor, with its name ("tunN") in ifname; or -1 with errno
 * from the last attempt (ENOENT for every unit: the driver is not loaded). */
int ts_tun_open(char ifname[16]);

/* /sbin/ifconfig tunN inet A A netmask 255.255.255.255 mtu 1280 up */
int ts_tun_cmd_ifconfig_up(const char **argv, size_t max, char *buf, size_t cap, const char *ifname, uint32_t ip);
/* /sbin/route -n add -net 100.64.0.0/10 -interface tunN */
int ts_tun_cmd_route_add(const char **argv, size_t max, char *buf, size_t cap, const char *ifname);
/* /sbin/route -n delete -net 100.64.0.0/10 */
int ts_tun_cmd_route_delete(const char **argv, size_t max, char *buf, size_t cap);
/* /sbin/ifconfig tunN inet A delete, then /sbin/ifconfig tunN down */
int ts_tun_cmd_ifconfig_down(const char **argv, size_t max, char *buf, size_t cap, const char *ifname, uint32_t ip);

/* Run argv[0] (an absolute path) with argv: fork and execv, no shell and no
 * PATH search. The child closes every descriptor above 2 and has stdin,
 * stdout and stderr on /dev/null. Waits for that child only (waitpid on its
 * pid; no SIGCHLD handler), at most TS_RUN_LIMIT_MS, then kills it with
 * SIGKILL and reaps it. Returns its exit status (127 if it could not be
 * executed), or -1 (a relative path, fork failed, killed or timed out). */
int ts_run(const char *const *argv);

#endif
