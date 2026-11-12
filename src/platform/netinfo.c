#include "netinfo.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* The kernel pads each sockaddr in a routing message to 4 bytes (the same as
 * sizeof(long) on 32-bit PowerPC; a 64-bit long would misparse). */
#define RT_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

#define RT_BUF 512

static void copy_name(char out[16], const char *src, size_t n)
{
    if (n > 15)
        n = 15;
    memcpy(out, src, n);
    out[n] = 0;
}

/* The default route, by RTM_GET. 0 when the kernel answered (ESRCH, no
 * default route, gives *gw = 0 and gw_if = ""); -1 when it could not be
 * asked or did not answer (socket error, timeout, only foreign messages). */
static int default_route(uint32_t *gw, char gw_if[16])
{
    struct {
        struct rt_msghdr h;
        struct sockaddr_in dst;
        struct sockaddr_in mask;
        struct sockaddr_dl ifp;
    } req;
    union {
        struct rt_msghdr h;
        char c[RT_BUF];
    } bu;
    char *buf = bu.c;
    int ok = -1;
    struct timeval tv;
    pid_t pid = getpid();
    int s, tries;

    *gw = 0;
    gw_if[0] = 0;
    s = socket(PF_ROUTE, SOCK_RAW, 0);
    if (s < 0)
        return -1;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&req, 0, sizeof(req));
    req.h.rtm_msglen = sizeof(req);
    req.h.rtm_version = RTM_VERSION;
    req.h.rtm_type = RTM_GET;
    req.h.rtm_flags = RTF_UP | RTF_GATEWAY;
    req.h.rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;
    req.h.rtm_pid = pid;
    req.h.rtm_seq = 1;
    req.dst.sin_len = sizeof(req.dst);
    req.dst.sin_family = AF_INET;
    req.mask.sin_len = sizeof(req.mask);
    req.mask.sin_family = AF_INET;
    req.ifp.sdl_len = sizeof(req.ifp);
    req.ifp.sdl_family = AF_LINK;
    if (write(s, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        int no_route = errno == ESRCH;
        close(s);
        return no_route ? 0 : -1;
    }
    for (tries = 0; tries < 32; tries++) {
        ssize_t r = read(s, buf, RT_BUF);
        struct rt_msghdr *rh;
        char *p, *end;
        int bit;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;                      /* timeout or error */
        }
        if ((size_t)r < sizeof(struct rt_msghdr))
            continue;
        rh = (struct rt_msghdr *)buf;
        if (rh->rtm_type != RTM_GET || rh->rtm_seq != 1 || rh->rtm_pid != pid)
            continue;
        if (rh->rtm_errno != 0) {
            if (rh->rtm_errno == ESRCH)
                ok = 0;
            break;
        }
        ok = 0;
        end = buf + ((size_t)rh->rtm_msglen < (size_t)r ? (size_t)rh->rtm_msglen : (size_t)r);
        p = buf + sizeof(struct rt_msghdr);
        for (bit = 0; bit < RTAX_MAX && p < end; bit++) {
            struct sockaddr *sa;
            size_t len;
            if (!(rh->rtm_addrs & (1 << bit)))
                continue;
            if (p + 1 > end)
                break;
            sa = (struct sockaddr *)p;
            len = RT_ROUNDUP((size_t)sa->sa_len);
            if (p + len > end)
                break;
            if (bit == RTAX_GATEWAY && sa->sa_family == AF_INET && sa->sa_len >= sizeof(struct sockaddr_in)) {
                struct sockaddr_in sin;
                memcpy(&sin, sa, sizeof(sin));
                *gw = ntohl(sin.sin_addr.s_addr);
            } else if (bit == RTAX_IFP && sa->sa_family == AF_LINK && sa->sa_len >= offsetof(struct sockaddr_dl, sdl_data)) {
                struct sockaddr_dl *dl = (struct sockaddr_dl *)sa;
                size_t room = (size_t)sa->sa_len - offsetof(struct sockaddr_dl, sdl_data);
                size_t nl = dl->sdl_nlen < room ? dl->sdl_nlen : room;
                copy_name(gw_if, dl->sdl_data, nl);
            }
            p += len;
        }
        if (gw_if[0] == 0 && rh->rtm_index != 0) {
            char nm[IF_NAMESIZE];
            if (if_indextoname(rh->rtm_index, nm) != NULL)
                copy_name(gw_if, nm, strlen(nm));
        }
        break;
    }
    close(s);
    return ok;
}

int ts_net_snapshot(ts_ifaddr *out, size_t cap, size_t *n, uint32_t *gw, char gw_if[16])
{
    struct ifaddrs *list, *p;
    size_t m = 0;

    *n = 0;
    if (getifaddrs(&list) != 0)
        return -1;
    for (p = list; p != NULL; p = p->ifa_next) {
        struct sockaddr_in a, k;
        if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK))
            continue;
        if (p->ifa_addr == NULL || p->ifa_addr->sa_family != AF_INET || p->ifa_name == NULL)
            continue;
        if (m >= cap)
            break;
        memset(&k, 0, sizeof(k));
        memcpy(&a, p->ifa_addr, sizeof(a));
        if (p->ifa_netmask != NULL)
            memcpy(&k, p->ifa_netmask, sizeof(k));
        copy_name(out[m].name, p->ifa_name, strlen(p->ifa_name));
        out[m].addr = ntohl(a.sin_addr.s_addr);
        out[m].mask = ntohl(k.sin_addr.s_addr);
        m++;
    }
    freeifaddrs(list);
    *n = m;
    return default_route(gw, gw_if);
}
