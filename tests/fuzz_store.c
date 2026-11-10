#include "fuzz.h"
#include "../src/crypto/blake2s.h"
#include "../src/state/store.h"

#include <stdlib.h>
#include <string.h>

static int all_zero(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

static void check(const uint8_t *data, size_t len);

/* Run the input as is, and with its checksum recomputed so that mutations
 * reach the structural checks behind the checksum. */
static void target(const uint8_t *data, size_t len)
{
    check(data, len);
    if (len == TS_STATE_FILE_LEN) {
        uint8_t fixed[TS_STATE_FILE_LEN];
        memcpy(fixed, data, len);
        ts_blake2s(fixed + 136, fixed, 136);
        check(fixed, len);
    }
}

static void check(const uint8_t *data, size_t len)
{
    ts_state s, t;
    uint8_t enc[TS_STATE_FILE_LEN];

    memset(&s, 0xa5, sizeof s);   /* a failed parse must not leave this behind */
    if (ts_state_parse(&s, data, len) != 0) {
        TS_FUZZ_ASSERT(all_zero(&s, sizeof s));
        return;
    }
    /* Accepted: it must be canonical, so re-encoding reproduces the input. */
    TS_FUZZ_ASSERT(len == TS_STATE_FILE_LEN);
    TS_FUZZ_ASSERT(s.have_old_node == 0 || s.have_old_node == 1);
    TS_FUZZ_ASSERT(s.have_login == 0 || s.have_login == 1);
    TS_FUZZ_ASSERT(s.logout_pending == 0 || s.logout_pending == 1);
    TS_FUZZ_ASSERT(!(s.logout_pending && s.have_login));
    TS_FUZZ_ASSERT(s.have_old_node || all_zero(s.old_node_priv, 32));
    ts_state_encode(enc, &s);
    TS_FUZZ_ASSERT(memcmp(enc, data, len) == 0);
    TS_FUZZ_ASSERT(ts_state_parse(&t, enc, sizeof enc) == 0 && memcmp(&s, &t, sizeof s) == 0);
}

void ts_fuzz_store(void)
{
    static uint8_t seed_a[TS_STATE_FILE_LEN], seed_b[TS_STATE_FILE_LEN], seed_c[TS_STATE_FILE_LEN],
        seed_d[TS_STATE_FILE_LEN];
    const uint8_t *seeds[4];
    size_t lens[4], i;
    ts_state s;

    memset(&s, 0, sizeof s);
    for (i = 0; i < 32; i++) {
        s.machine_priv[i] = (uint8_t)(i + 1);
        s.node_priv[i] = (uint8_t)(0x40 + i);
        s.disco_priv[i] = (uint8_t)(0x80 + i);
    }
    ts_state_encode(seed_a, &s);
    memcpy(s.old_node_priv, s.machine_priv, 32);
    s.have_old_node = 1;
    s.have_login = 1;
    ts_state_encode(seed_b, &s);
    /* A logout not yet confirmed by control. */
    s.have_login = 0;
    s.logout_pending = 1;
    ts_state_encode(seed_d, &s);
    /* A structurally invalid image with a correct checksum: reserved flag. */
    memcpy(seed_c, seed_a, sizeof seed_c);
    seed_c[7] = 0x80;
    ts_blake2s(seed_c + 136, seed_c, 136);
    seeds[0] = seed_a; seeds[1] = seed_b; seeds[2] = seed_c; seeds[3] = seed_d;
    for (i = 0; i < 4; i++) lens[i] = TS_STATE_FILE_LEN;
    ts_fuzz_run("store", target, seeds, lens, 4, TS_FUZZ_DEFAULT_ITERS);
}
