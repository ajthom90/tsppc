#ifndef TS_CONTROL_UPGRADE_H
#define TS_CONTROL_UPGRADE_H

#include <stddef.h>
#include <stdint.h>

#include "noise.h"

/* HTTP/1.1 upgrade to the control protocol, and the optional early payload
 * that may precede HTTP/2 inside the Noise channel. Sans-I/O. */

#define TS_UPGRADE_HEADER_MAX 8192       /* response status line and headers */
#define TS_EARLY_PAYLOAD_MAX 65536       /* largest early payload accepted */

/* Write the upgrade request: POST /ts2021 with Host, Upgrade:
 * tailscale-control-protocol, Connection: upgrade, Content-Length: 0 (as Go's
 * transport sends for a body-less POST) and X-Tailscale-Handshake carrying the
 * base64 init. Returns its length (a NUL follows), or 0 if cap is
 * too small or host is empty or holds a byte outside '!'..'~'. */
size_t ts_upgrade_request(char *out, size_t cap, const char *host,
                          const uint8_t init[TS_NOISE_INIT_LEN]);

/* Parse the server's reply from the start of buf. Returns 0 when a complete
 * 101 response with "Upgrade: tailscale-control-protocol" has arrived, with
 * *consumed set to the bytes through the blank line (anything after is Noise);
 * 1 if more bytes are needed; -1 for any other status, a malformed status line,
 * a missing or different Upgrade header, or headers over TS_UPGRADE_HEADER_MAX.
 * Header names and the Upgrade value match case-insensitively; only the first
 * Upgrade header counts, as with Go's Header.Get. */
int ts_upgrade_response(const char *buf, size_t len, size_t *consumed);

/* Look for the early payload at the start of the decrypted server stream:
 * "\xff\xff\xffTS", BE32 length, then that many bytes of JSON. The JSON is
 * syntax-checked (one value, whitespace around it allowed) and otherwise
 * ignored: it carries nothing this client uses. Returns 0 with
 * *consumed = 9 + length when one is complete, 0 with *consumed = 0 when the
 * stream does not start with the magic, 1 if more bytes are needed to decide
 * or to finish, and -1 if the length exceeds TS_EARLY_PAYLOAD_MAX or a
 * complete payload is not valid JSON (upstream fails the same way). */
int ts_early_payload(const uint8_t *buf, size_t len, size_t *consumed);

#endif
