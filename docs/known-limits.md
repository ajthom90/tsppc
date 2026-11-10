# Known limits

Accepted limits, with the decision behind each.

## BearSSL's X25519 leaves a clamped scalar on its stack

`ts_x25519` wipes its own copy of the scalar and every buffer it controls, but
`api_mul` in `vendor/bearssl-0.6/src/ec/ec_c25519_m31.c` copies the scalar into
a local array, clamps it, and returns without wiping it. The clamped scalar is
the private key apart from a few fixed bits, and it stays in that stack frame
until the stack is reused.

Decision: accepted until long-term key handling is reviewed. Changing it would
mean modifying vendored code, and a process that can read this memory can also
read the key material we hold on purpose.
