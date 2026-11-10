#ifndef TS_STATE_STORE_H
#define TS_STATE_STORE_H

#include <stddef.h>
#include <stdint.h>

/* Persistent node state: the machine, node and disco private keys.
 *
 * The state directory must be owned by the effective user with no group or
 * other permission bits, and must not be a symbolic link. The state file in it
 * must be a regular file, owned by the effective user, mode 0600. Anything else
 * is refused with a message in err. A file that is truncated, corrupt, has a
 * bad checksum or an unknown version is an error and is never overwritten.
 *
 * File format (all integers big-endian), TS_STATE_FILE_LEN bytes:
 *   0   4  magic "TSPS"
 *   4   2  version (1)
 *   6   2  flags: bit 0 have_old_node, bit 1 have_login; other bits must be 0
 *  8  32  machine private key
 *  40 32  node private key
 *  72 32  old node private key (all zero unless have_old_node)
 * 104 32  disco private key
 * 136 32  BLAKE2s-256 of bytes 0..135
 *
 * The parent of the state directory must be trusted (for example /var/db, owned
 * by root and not writable by others): only the final path component is checked
 * for being a symbolic link.
 *
 * Creating the first state installs it with link(), so an existing file is never
 * replaced; ts_state_save replaces with rename. In both, if the final directory
 * fsync fails the file is already installed but may not be durable; an error is
 * returned and the caller should treat the save as not confirmed. Load removes
 * leftover ".state.*" temporary files (regular files we own) from a crashed save.
 *
 * Private keys never appear in error messages. */

#define TS_STATE_DIR "/var/db/tsppc"
#define TS_STATE_FILE "state.bin"
#define TS_STATE_FILE_LEN 168
#define TS_STATE_VERSION 1

#define TS_STATE_TMP_PREFIX ".state."
#define TS_STATE_TMP_TEMPLATE ".state.XXXXXX"

/* The directory the daemon should use: TS_STATE_DIR. In builds with
 * -DTS_TEST_HOOKS only, the TSPPC_STATE_DIR environment variable overrides it. */
const char *ts_state_default_dir(void);

typedef struct {
    uint8_t machine_priv[32];
    uint8_t node_priv[32];
    uint8_t old_node_priv[32];
    uint8_t disco_priv[32];
    int have_old_node;
    int have_login;
} ts_state;

/* Clamp 32 random bytes into an X25519 private key, as every key in the state
 * is made (the crypto module clamps again when it uses the key). */
void ts_state_clamp_key(uint8_t k[32]);

/* Serialise s into out (TS_STATE_FILE_LEN bytes). */
void ts_state_encode(uint8_t out[TS_STATE_FILE_LEN], const ts_state *s);

/* Parse a state file image. Returns 0, or -1 for any defect, in which case *s
 * is zeroed. */
int ts_state_parse(ts_state *s, const uint8_t *buf, size_t len);

/* Load the state in dir, creating the directory (mode 0700) and a fresh state
 * (three new random keys) if there is none. Returns 0, or -1 with a message
 * in err (which may be NULL if errcap is 0). On failure *s is zeroed. */
int ts_state_load_or_create(ts_state *s, const char *dir, char *err, size_t errcap);

/* Atomically replace the state file: temp file in dir, fsync, rename, fsync dir. */
int ts_state_save(const ts_state *s, const char *dir, char *err, size_t errcap);

#endif
