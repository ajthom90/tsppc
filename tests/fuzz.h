#ifndef TS_TEST_FUZZ_H
#define TS_TEST_FUZZ_H

#include <stddef.h>
#include <stdint.h>

/* Deterministic mutation fuzzing (Apple's clang ships no libFuzzer runtime).
 *
 * Each iteration derives its own PRNG state from (base seed, iteration), takes a
 * seed input, applies 1 to 4 mutations (bit flip, byte substitution, truncation,
 * insertion, splice) and calls target with a heap buffer of exactly the input
 * length, so AddressSanitizer catches any read past the end.
 *
 * If the target faults (ASan, UBSan, signal), the process prints
 *   FUZZ FAULT: <name> seed=<s> iteration=<i>
 * and exits non-zero. Reproduce with
 *   TS_FUZZ_SEED=<s> TS_FUZZ_START=<i> TS_FUZZ_ITERS=1 build/fuzz/fuzz_all [name]
 * Environment: TS_FUZZ_ITERS overrides the iteration count, TS_FUZZ_SEED the
 * base seed (default fixed), TS_FUZZ_START the first iteration (default 0). */
void ts_fuzz_run(const char *name, void (*target)(const uint8_t *, size_t),
                 const uint8_t *const *seeds, const size_t *seedlens,
                 size_t nseeds, unsigned iterations);

/* Default iteration count per target. */
#define TS_FUZZ_DEFAULT_ITERS 200000u

#endif
