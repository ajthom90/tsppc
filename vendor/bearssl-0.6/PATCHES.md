# Local patches to BearSSL 0.6

## `src/inner.h`: multiply operands the compiler cannot simplify

Applies when `BR_CT_MUL15` or `BR_CT_MUL31` is set. Builds without those flags
are unchanged.

`MUL15`, `MUL31` and `MUL31_lo` set bit 31 of each operand so that the G3 and
G4 multipliers cannot finish early on a small value. Upstream's C expresses
that with a plain OR. The top bit of an operand cannot affect the low 31 bits
of a product, so where only those bits are kept gcc-4.0 is free to delete the
OR, and it does. In `poly1305_ctmul32.o` at -O2 only one of the two operands
stayed forced, and at -O1 neither did. The `mulli` that gcc-4.0 produced for
`MUL15(x, 19)` in `ec_c25519_m31.o` was not forced at all.

The patch adds `br_ct_mul_operand`, which applies the OR and then passes the
value through an empty `asm` statement. The optimizer cannot see through it,
so the OR stays. The arithmetic is unchanged, so results are identical for
all inputs. A constant operand now also goes through a real `mullw` with bit
31 forced.

`tools/check-ct.sh` verifies the built objects on the VM.
