#ifndef TS_NET_RESOLVE_H
#define TS_NET_RESOLVE_H

#include <stddef.h>
#include <sys/types.h>

/* Non-blocking IPv4 name lookup.
 *
 * getaddrinfo blocks, so ts_resolve_start forks a helper process that closes
 * every descriptor except its pipe, calls getaddrinfo (AF_INET, SOCK_STREAM),
 * writes the first address as a dotted quad and leaves with _exit. alarm()
 * kills it after TS_RESOLVE_TIMEOUT seconds, which ends the lookup as failed.
 * The parent waits for the pipe (ts_resolve_fd) to become readable and calls
 * ts_resolve_finish. Finish (once it returns 0 or -1) and cancel both kill and
 * reap the helper, so no zombie is left. No one else may reap it: a SIGCHLD
 * handler that calls wait() would break this. */

#define TS_RESOLVE_TIMEOUT 15
#define TS_RESOLVE_NAME_MAX 253

typedef struct {
    pid_t pid;      /* helper, or -1 */
    int fd;         /* read end of the pipe, or -1 */
    size_t len;
    char buf[24];   /* answer so far */
} ts_resolve;

/* Start a lookup of host (1 to TS_RESOLVE_NAME_MAX characters from
 * [A-Za-z0-9.-]). Returns 0, or -1 (bad name, pipe or fork failed; r is then
 * idle and cancel is a no-op). */
int ts_resolve_start(ts_resolve *r, const char *host);

/* Descriptor to wait on for reading while a lookup is pending, else -1. */
int ts_resolve_fd(const ts_resolve *r);

/* 1: pending. 0: done, ip_out holds the dotted quad. -1: failed (no address,
 * timed out, or ip_out smaller than the answer plus its NUL). After 0 or -1
 * the helper is reaped and r is idle. */
int ts_resolve_finish(ts_resolve *r, char *ip_out, size_t cap);

/* Kill and reap a pending helper and close the pipe. A no-op on an idle r
 * (after a failed start, a finish or a cancel). */
void ts_resolve_cancel(ts_resolve *r);

#ifdef TS_TEST_HOOKS
/* Seconds the helper sleeps after closing its descriptors. Tests only. */
extern unsigned ts_resolve_test_delay;
#endif

#endif
