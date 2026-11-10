#ifndef TS_TEST_HARNESS_H
#define TS_TEST_HARNESS_H

#include <stddef.h>
#include <stdint.h>

/* Compare got[0..n) with the hex string want_hex. */
void t_hex(const char *name, const uint8_t *got, size_t n, const char *want_hex);
void t_true(const char *name, int cond);
/* Decode hex into out; out must hold strlen(hex)/2 bytes. */
void t_unhex(uint8_t *out, const char *hex);
/* Prints "RESULT: all passed" or "RESULT: N FAILED"; nonzero on failure. */
int t_summary(void);

#endif
