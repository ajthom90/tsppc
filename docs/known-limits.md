# Known limits

Accepted limits, with the decision behind each.

## BearSSL's X25519 leaves a clamped scalar on its stack

`ts_x25519` wipes its own copy of the scalar and every buffer it controls, but
`api_mul` in `vendor/bearssl-0.6/src/ec/ec_c25519_m31.c` copies the scalar into
a local array, clamps it, and returns without wiping it. The clamped scalar is
the private key apart from a few fixed bits, and it stays in that stack frame
until the stack is reused.

Decision: accepted until long-term key handling is reviewed. Changing it would
mean a further patch to vendored code, and a process that can read this memory
can also read the key material we hold on purpose.

## Constant-time evidence comes from disassembly

The claim that multiplies are constant-time on G3 and G4 rests on reading the
PowerPC code that gcc-4.0 builds. No timing has been measured on real hardware.

Every `mullw`, `mulhw` and `mulhwu` in `poly1305_ctmul32.o`, `ec_c25519_m31.o`
and `nacl.o` takes both inputs from values with bit 31 forced to 1. Which
operand a 750 or 7400 inspects for early-out therefore no longer matters,
because both are forced. `tools/check-ct.sh` checks this on the VM and fails
the run if it stops holding. Its header lists what it cannot detect.

The compiler can remove such forcing without changing any result, so tests
cannot catch it. Other BearSSL objects are not part of that check.
