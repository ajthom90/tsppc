/*
 * Check of the tunnel driver, in both directions. Run as root with the driver
 * loaded: it opens /dev/tun0, gives tun0 a point-to-point address, pings the
 * far end, answers that ping itself through the device, and checks that ping
 * received the answer. Prints PASS/FAIL lines; exits nonzero on any failure.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/core/bytes.h"

#define TUN_DEVICE     "/dev/tun0"
#define TUN_NAME       "tun0"
#define LOCAL_ADDR     "10.99.99.1"
#define PEER_ADDR      "10.99.99.2"
#define PEER_ADDR_BE32 0x0a636302u

#define READ_LIMIT_SEC  6
#define CHILD_LIMIT_SEC 10
#define PACKET_MAX      2048

/* IPv4 header field offsets. */
#define IP_VER_IHL   0
#define IP_TOTAL_LEN 2
#define IP_PROTOCOL  9
#define IP_CHECKSUM  10
#define IP_SRC       12
#define IP_DST       16
#define IP_MIN_LEN   20
#define IP_PROTO_ICMP 1

/* ICMP field offsets, from the start of the ICMP message. */
#define ICMP_TYPE     0
#define ICMP_CODE     1
#define ICMP_CHECKSUM 2
#define ICMP_MIN_LEN  8
#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8

/* Internet checksum of n bytes (RFC 1071). */
static uint16_t inet_checksum(const uint8_t *p, size_t n)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < n; i += 2) sum += ts_get_be16(p + i);
    if (i < n) sum += (uint32_t)p[i] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

/*
 * If the n bytes at pkt are an IPv4 ICMP echo request to the peer, store the
 * IP header length and total length and return 1. Otherwise return 0. Both
 * lengths are validated against n, so callers may use them as bounds.
 */
static int is_echo_to_peer(const uint8_t *pkt, size_t n, size_t *ihl, size_t *total)
{
    size_t hl, tl;

    if (n < IP_MIN_LEN || (pkt[IP_VER_IHL] >> 4) != 4) return 0;
    hl = (size_t)(pkt[IP_VER_IHL] & 0x0f) * 4;
    tl = ts_get_be16(pkt + IP_TOTAL_LEN);
    if (hl < IP_MIN_LEN || tl > n || tl < hl + ICMP_MIN_LEN) return 0;
    if (pkt[IP_PROTOCOL] != IP_PROTO_ICMP) return 0;
    if (ts_get_be32(pkt + IP_DST) != PEER_ADDR_BE32) return 0;
    if (pkt[hl + ICMP_TYPE] != ICMP_ECHO_REQUEST || pkt[hl + ICMP_CODE] != 0) return 0;
    *ihl = hl;
    *total = tl;
    return 1;
}

/* Turn a request accepted by is_echo_to_peer into its reply, in place. */
static void make_echo_reply(uint8_t *pkt, size_t ihl, size_t total)
{
    uint8_t tmp[4];

    memcpy(tmp, pkt + IP_SRC, sizeof tmp);
    memcpy(pkt + IP_SRC, pkt + IP_DST, sizeof tmp);
    memcpy(pkt + IP_DST, tmp, sizeof tmp);

    pkt[ihl + ICMP_TYPE] = ICMP_ECHO_REPLY;
    ts_put_be16(pkt + ihl + ICMP_CHECKSUM, 0);
    ts_put_be16(pkt + ihl + ICMP_CHECKSUM, inet_checksum(pkt + ihl, total - ihl));

    ts_put_be16(pkt + IP_CHECKSUM, 0);
    ts_put_be16(pkt + IP_CHECKSUM, inet_checksum(pkt, ihl));
}

static double now_sec(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/*
 * Read from fd until an echo request to the peer arrives or the limit passes.
 * The interface can also carry unrelated traffic when it comes up (multicast
 * from system daemons), so other packets are counted and skipped. Returns 1 on
 * a match and 0 on timeout or error.
 */
static int read_echo(int fd, uint8_t *pkt, size_t cap, size_t *ihl, size_t *total)
{
    double deadline = now_sec() + READ_LIMIT_SEC;
    unsigned skipped = 0;

    for (;;) {
        double left = deadline - now_sec();
        struct timeval tv;
        fd_set rd;
        ssize_t n;
        int r;

        if (left <= 0) {
            printf("note: no echo request within %d seconds, %u other packet(s) skipped\n",
                   READ_LIMIT_SEC, skipped);
            return 0;
        }
        tv.tv_sec = (time_t)left;
        tv.tv_usec = (suseconds_t)((left - (double)tv.tv_sec) * 1e6);
        FD_ZERO(&rd);
        FD_SET(fd, &rd);
        r = select(fd + 1, &rd, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) continue;
            printf("note: select: %s\n", strerror(errno));
            return 0;
        }
        if (r == 0) continue;

        n = read(fd, pkt, cap);
        if (n < 0) {
            if (errno == EINTR) continue;
            printf("note: read: %s\n", strerror(errno));
            return 0;
        }
        if (is_echo_to_peer(pkt, (size_t)n, ihl, total)) {
            if (skipped > 0) printf("note: skipped %u other packet(s) first\n", skipped);
            return 1;
        }
        skipped++;
    }
}

static pid_t spawn(const char *path, char *const argv[])
{
    pid_t pid = fork();

    if (pid == 0) {
        execv(path, argv);
        _exit(127);
    }
    return pid;
}

/* Wait up to the child limit. Returns the exit status, or -1 if it did not
 * exit normally in time; a child that overruns is killed and reaped. */
static int wait_child(pid_t pid)
{
    double deadline = now_sec() + CHILD_LIMIT_SEC;
    int status;

    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);

        if (r == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (r < 0 && errno != EINTR) return -1;
        if (now_sec() >= deadline) break;
        usleep(100000);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
    return -1;
}

static int configure_interface(void)
{
    char *const argv[] = {
        "ifconfig", TUN_NAME, "inet", LOCAL_ADDR, PEER_ADDR, "up", NULL
    };
    pid_t pid = spawn("/sbin/ifconfig", argv);

    if (pid < 0) return -1;
    return wait_child(pid);
}

int main(void)
{
    char *const ping_argv[] = { "ping", "-c", "1", "-t", "5", PEER_ADDR, NULL };
    uint8_t pkt[PACKET_MAX];
    size_t ihl = 0, total = 0;
    ssize_t written;
    pid_t ping;
    int fd, rc;

    setvbuf(stdout, NULL, _IOLBF, 0);

    fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("FAIL open %s: %s\n", TUN_DEVICE, strerror(errno));
        return 1;
    }
    /* The device must not stay open in children, or unloading would fail. */
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        printf("FAIL set close-on-exec: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    rc = configure_interface();
    if (rc != 0) {
        printf("FAIL ifconfig %s (status %d)\n", TUN_NAME, rc);
        close(fd);
        return 1;
    }

    ping = spawn("/sbin/ping", ping_argv);
    if (ping < 0) {
        printf("FAIL fork ping: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    if (!read_echo(fd, pkt, sizeof pkt, &ihl, &total)) {
        printf("FAIL outbound packet read\n");
        printf("FAIL inbound reply delivered (no request to answer)\n");
        kill(ping, SIGKILL);
        wait_child(ping);
        close(fd);
        return 1;
    }
    printf("PASS outbound packet read\n");

    make_echo_reply(pkt, ihl, total);
    written = write(fd, pkt, total);
    if (written != (ssize_t)total) {
        printf("FAIL inbound reply delivered (write: %s)\n",
               written < 0 ? strerror(errno) : "short write");
        kill(ping, SIGKILL);
        wait_child(ping);
        close(fd);
        return 1;
    }

    rc = wait_child(ping);
    close(fd);
    if (rc != 0) {
        printf("FAIL inbound reply delivered (ping status %d)\n", rc);
        return 1;
    }
    printf("PASS inbound reply delivered\n");
    return 0;
}
