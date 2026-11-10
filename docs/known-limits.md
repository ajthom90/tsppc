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
and `nacl.o` takes both inputs from values with bit 31 set and bit 30 clear.
Bit 31 is forced on every operand. Bit 30 stays clear because the operands are
30-bit limbs or smaller: the X25519 limbs are 30 bits, and the `MUL15` operands
are at most 17 bits. Both conditions are needed. `mullw` may treat its operands
as signed and finish early when the top bits are all ones, so a 31-bit operand
with bits 30 to 16 set becomes 0xFFFFxxxx after the OR and is not protected.

With both conditions met, which operand a 750 or 7400 inspects for early-out no
longer matters. `tools/check-ct.sh` checks bit 31 on the VM and fails the run
if it stops holding. Bit 30 follows from the operand widths in the source, and
the script cannot see it. Its header lists what else it cannot detect.

The compiler can remove such forcing without changing any result, so tests
cannot catch it. Other BearSSL objects are not part of that check. The `i31`
code uses 31-bit words, so this reasoning does not cover it.

## Requirements on the TLS client (control-session Task 6)

`ts_tls` wraps `br_ssl_client_context`, and BearSSL's client defaults are not
all covered by the evidence above. `BR_LOMUL` is only set on ARM Cortex-M, and
PowerPC here is not `BR_64`, so the defaults on PowerPC include the items below.
Task 6 must handle each one:

- **Poly1305:** the default is `br_poly1305_ctmul_run`. Set
  `br_poly1305_ctmul32_run` explicitly on PowerPC.
- **GCM:** the default GHASH is `br_ghash_ctmul`, which uses the unforced `MUL`.
  Decide whether to allow GCM suites on PowerPC, and with which GHASH.
- **Curves:** the default is `br_ec_all_m31`. P-256 ephemeral scalars go through
  `ec_p256_m31`, and P-384 and P-521 go through `ec_prime_i31`, which uses
  31-bit words. Decide which curves to allow.
- **Check:** add `ec_p256_m31.o` to `tools/check-ct.sh`, with a reviewed
  allowance for the one `mulli` in `p256_mulgen`. That `mulli` appears to scale
  a public loop counter to a `Gwin` row (72 bytes per row). This is inferred
  from the source and has not been traced in the object code.
