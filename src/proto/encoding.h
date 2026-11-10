#ifndef TS_PROTO_ENCODING_H
#define TS_PROTO_ENCODING_H

#include <stddef.h>
#include <stdint.h>

/* Lowercase hex of in[0..n). Writes 2n characters plus a NUL and returns 2n.
 * If cap < 2n + 1 nothing is written (except out[0] = 0 when cap > 0) and 0
 * is returned. An empty input also returns 0, with out = "". */
size_t ts_hex_encode(char *out, size_t cap, const uint8_t *in, size_t n);

/* Decode exactly `want` bytes from hexlen hex digits (either case). Returns 0
 * on success; -1 if hexlen != 2*want or a character is not a hex digit (out
 * contents are then unspecified). */
int ts_hex_decode(uint8_t *out, size_t want, const char *hex, size_t hexlen);

/* Standard base64 (RFC 4648, with '=' padding) of in[0..n), then a NUL.
 * Returns the length written (not counting the NUL), which is 4*ceil(n/3).
 * If cap is too small, nothing is written (except out[0] = 0 when cap > 0)
 * and 0 is returned. An empty input also returns 0, with out = "". */
size_t ts_b64_encode(char *out, size_t cap, const uint8_t *in, size_t n);

#endif
