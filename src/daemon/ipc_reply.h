#ifndef TS_DAEMON_IPC_REPLY_H
#define TS_DAEMON_IPC_REPLY_H

#include <stddef.h>
#include <stdint.h>

#include "src/control/netmap.h"
#include "src/daemon/ipc.h"

/* Reply parsing and a bounded request, shared by the CLI and the menu bar app.
 * The reply format is described at the top of ipc.h. Everything from the
 * daemon is untrusted: values are cleaned with ts_ipc_clean as they are
 * parsed, so every string here holds only printable ASCII. */

typedef struct {
    uint32_t ipv4;              /* host byte order, valid when have_ipv4 */
    int have_ipv4;
    int online;
    char name[TS_NODE_NAME_MAX + 1];
} ts_reply_peer;

/* A parsed reply. It is large (peers, and the value buffers): never put a
 * ts_reply or a peer array on the stack; use static or malloc'd storage. */
typedef struct {
    int ok;                          /* "ok" seen */
    char error[TS_IPC_VALUE_MAX];    /* "error" value, "" if none */
    char state[32], status[TS_IPC_VALUE_MAX], url[TS_IPC_VALUE_MAX], problem[TS_IPC_VALUE_MAX];
    char login[16], wanted[16], self[TS_NODE_NAME_MAX + 1];
    uint32_t ipv4; int have_ipv4;
    ts_reply_peer *peers; size_t npeers;   /* peers: caller array of TS_MAX_PEERS */
    int truncated;                   /* "truncated" seen, or more than TS_MAX_PEERS peers */
} ts_reply;

/* Parse a whole reply (bytes up to the daemon's close). Unknown keys and
 * malformed lines are skipped; values are cleaned with ts_ipc_clean. For a key
 * that occurs more than once, the first occurrence wins (peer lines add). A
 * peer line needs a valid a.b.c.d or "-", "online" or "offline", and a space
 * after the status (the name after it may be empty), or it is skipped. Returns 0, or -1 if the reply holds no
 * "ok" and no "error" line. */
int ts_reply_parse(ts_reply *r, ts_reply_peer *peers, const char *buf, size_t len);

typedef enum { TS_REQ_OK = 0, TS_REQ_NO_DAEMON, TS_REQ_DENIED, TS_REQ_TIMEOUT, TS_REQ_FAILED } ts_req_result;

/* Connect to path, send cmd, read until close or timeout_ms (whole request).
 * ENOENT and ECONNREFUSED give NO_DAEMON; EACCES and EPERM give DENIED.
 * Non-blocking with select(); never blocks longer than timeout_ms (plus
 * scheduling delay). *len = bytes read (at most cap; also set on TIMEOUT and
 * FAILED). If the reply is longer than cap, the first cap bytes are kept and
 * the result is still TS_REQ_OK (a daemon reply never exceeds
 * TS_IPC_RESP_MAX, so a cap of that size never cuts one). The buffer is not
 * NUL-terminated. On NO_DAEMON, DENIED and a failed connect, errno holds the
 * connect error. A listener whose backlog is full reads as NO_DAEMON (Darwin
 * refuses the connection). Not thread-safe (the clock's timebase is set up on
 * first use): call it from one thread, such as the app's main thread. */
ts_req_result ts_ipc_request(const char *path, ts_ipc_cmd cmd, int timeout_ms, char *buf, size_t cap, size_t *len);

#endif
