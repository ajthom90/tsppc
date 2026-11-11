#ifndef TS_DAEMON_IPC_H
#define TS_DAEMON_IPC_H

#include <stddef.h>
#include <sys/types.h>

/* The local control socket between tsppc (the CLI) and tsppcd (the daemon).
 *
 * Protocol: the client connects, sends one request line (a command name and
 * '\n', at most TS_IPC_LINE_MAX bytes with the newline), and reads the reply
 * until the daemon closes the connection. One request per connection; bytes
 * after the newline make it an error.
 *
 * Every reply line is "<key> <value>\n" or "<key>\n". Keys:
 *   ok                      the command was accepted
 *   error <text>            it was not (unknown command, too long, busy)
 *   state <NAME>            IDLE, CONNECTING, NEED_LOGIN, AWAIT_APPROVAL,
 *                           RUNNING, BACKOFF or FAILED
 *   status <text>           one line about the state
 *   url <url>               the login URL, only in NEED_LOGIN
 *   problem <text>          a current problem, such as "system clock is wrong"
 *   login <yes|no|leaving>  whether the saved state holds a login, and
 *                           whether a logout is still being sent
 *   wanted <up|down>        whether the node is meant to be connected: down
 *                           when logged out, or after "down" (kept across
 *                           restarts)
 *   self <name>             the node's own name as control sent it (an FQDN
 *                           with a trailing dot), when known
 *   ip <a.b.c.d>            the node's tailnet IPv4 address, when known
 *   peer <a.b.c.d|-> <online|offline> <name>
 *   truncated               the reply hit TS_IPC_RESP_MAX
 * The daemon replaces control bytes in every value. Clients still treat the
 * reply as untrusted and clean it (ts_ipc_clean) before printing it.
 *
 * Access: the socket is mode 0660, owner root, group admin, so only root and
 * the admin group can connect (Darwin checks write permission on connect).
 * getpeereid only gives the peer's primary group, which for an admin user is
 * normally staff, so it is not used to decide access. */

#define TS_IPC_PATH "/var/run/tsppc.sock"
#define TS_IPC_LINE_MAX 64             /* longest request, newline included */
#define TS_IPC_MAX_CLIENTS 8           /* more are accepted and closed at once */
#define TS_IPC_CLIENT_TIMEOUT_MS 10000 /* a client must be done within this */
#define TS_IPC_RESP_MAX 131072         /* largest reply, bytes */
#define TS_IPC_VALUE_MAX 2048          /* longest reply value a client must handle */
#define TS_IPC_GROUP "admin"
#define TS_IPC_GROUP_GID 80            /* admin's gid if the lookup fails */

typedef enum {
    TS_IPC_STATUS,
    TS_IPC_UP,
    TS_IPC_IP,
    TS_IPC_LOGOUT,
    TS_IPC_DOWN
} ts_ipc_cmd;

/* The socket path: TS_IPC_PATH. In builds with -DTS_TEST_HOOKS only, the
 * TSPPC_SOCKET environment variable overrides it. */
const char *ts_ipc_socket_path(void);

/* Parse one request line of len bytes: "status\n", "up\n", "ip\n",
 * "logout\n" or "down\n" exactly. Returns 0 with *out set, or -1 for anything else
 * (unknown command, missing newline, a NUL or other byte, len over
 * TS_IPC_LINE_MAX). */
int ts_ipc_parse_request(const char *line, size_t len, ts_ipc_cmd *out);

/* The request line for cmd, newline included. */
const char *ts_ipc_cmd_line(ts_ipc_cmd cmd);

/* Copy in[0..n) to out for a terminal: bytes below 0x20 and from 0x7f up
 * become '?', except '\n' when keep_newline. Stops at cap - 1 bytes; out is
 * always NUL-terminated (cap >= 1). Returns the length written. */
size_t ts_ipc_clean(char *out, size_t cap, const char *in, size_t n, int keep_newline);

/* Split a reply line (no newline) at its first space: key is line[0..*klen),
 * the value is line[*voff..len) ("" when there is no space). Returns 0, or -1
 * if the key is empty or holds a byte outside 'a'..'z'. */
int ts_ipc_split(const char *line, size_t len, size_t *klen, size_t *voff);

/* Create the listening socket at path (non-blocking, close-on-exec):
 * - a socket already at path that accepts a connection is a running daemon:
 *   refused;
 * - a socket that refuses five times over about a second is left from a
 *   crash: removed (a live daemon with a full backlog also refuses, briefly);
 * - anything else at path (file, directory, symbolic link) is refused.
 * It is bound under umask 077 and listens at once, then gets owner root (if
 * running as root) and group gid, then mode 0660. As root, a failed chown is an error;
 * otherwise (tests) the group is best effort. On success the device and inode
 * of the new socket go to *dev and *ino (for ts_ipc_unlink). Returns the
 * descriptor, or -1 with a message in err. */
int ts_ipc_listen(const char *path, gid_t gid, dev_t *dev, ino_t *ino, char *err, size_t errcap);

/* Remove path if it is still the socket that ts_ipc_listen made. */
void ts_ipc_unlink(const char *path, dev_t dev, ino_t ino);

/* Connect to the daemon's socket (blocking). Returns the descriptor, or -1
 * with errno set (ENAMETOOLONG for a path that does not fit). */
int ts_ipc_connect(const char *path);

#endif
