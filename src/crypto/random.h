#ifndef TS_CRYPTO_RANDOM_H
#define TS_CRYPTO_RANDOM_H

#include <stddef.h>

/* Fill out with n bytes from /dev/urandom. Returns 0, or -1 on failure. */
int ts_random_bytes(void *out, size_t n);

#endif
