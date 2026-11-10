#ifndef TS_NET_SOCK_H
#define TS_NET_SOCK_H

#include <stdint.h>

/* Non-blocking IPv4 TCP connect. */

/* Start connecting to the dotted-quad ip (no host names) on port. Returns a
 * non-blocking, close-on-exec socket with SIGPIPE suppressed (SO_NOSIGPIPE) and
 * Nagle off, or -1 if ip is not an IPv4 address or the connect failed at once.
 * Wait for the socket to become writable, then call ts_tcp_finish. */
int ts_tcp_start(const char *ip, uint16_t port);

/* After the socket from ts_tcp_start became writable: 0 if connected, -1 if
 * the connect failed (SO_ERROR set, or no peer). The caller closes fd. */
int ts_tcp_finish(int fd);

/* Make fd non-blocking and close-on-exec. Returns 0 or -1. */
int ts_fd_nonblock(int fd);

#endif
