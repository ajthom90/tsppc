#include "random.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int ts_random_bytes(void *out, size_t n)
{
    unsigned char *p = out;
    int fd;

    do { fd = open("/dev/urandom", O_RDONLY); } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) { close(fd); return -1; }
        p += r;
        n -= (size_t)r;
    }
    close(fd);
    return 0;
}
