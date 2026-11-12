#ifndef TS_PLATFORM_NETINFO_H
#define TS_PLATFORM_NETINFO_H

#include <stddef.h>
#include <stdint.h>

/* The machine's IPv4 interface addresses and default route. */

typedef struct {
    char name[16];
    uint32_t addr, mask;        /* host byte order */
} ts_ifaddr;

/* Up AF_INET interfaces (not loopback) into out[0..*n), at most cap, via
 * getifaddrs; the default gateway (host byte order) and its interface name
 * via an RTM_GET for 0.0.0.0/0 on a PF_ROUTE socket. No default route gives
 * *gw = 0 and gw_if = "". 0, or -1 when getifaddrs fails. */
int ts_net_snapshot(ts_ifaddr *out, size_t cap, size_t *n, uint32_t *gw, char gw_if[16]);

#endif
