#include "sock.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

int ts_fd_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) return -1;
    fl = fcntl(fd, F_GETFD);
    if (fl < 0 || fcntl(fd, F_SETFD, fl | FD_CLOEXEC) != 0) return -1;
    return 0;
}

int ts_tcp_start(const char *ip, uint16_t port)
{
    struct sockaddr_in a;
    int fd, one = 1;

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (ip == NULL || inet_pton(AF_INET, ip, &a.sin_addr) != 1) return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (ts_fd_nonblock(fd) != 0) goto fail;
#ifdef SO_NOSIGPIPE
    /* Darwin has no MSG_NOSIGNAL; a write to a reset peer must not kill us. */
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) != 0) goto fail;
#endif
    /* Small request and handshake writes should not wait for an ACK. */
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) return fd;
    /* EINTR on a non-blocking connect: it carries on asynchronously. */
    if (errno == EINPROGRESS || errno == EINTR) return fd;
fail:
    close(fd);
    return -1;
}

int ts_tcp_finish(int fd)
{
    struct sockaddr_in peer;
    socklen_t len = sizeof peer;
    int err = 0;
    socklen_t elen = sizeof err;

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) return -1;
    /* SO_ERROR is also 0 before the connect has finished; require a peer. */
    if (getpeername(fd, (struct sockaddr *)&peer, &len) != 0) return -1;
    return 0;
}
