#!/bin/sh
# Check built PowerPC objects for multiplies that could take data-dependent
# time on G3/G4. Run on the VM from the tree root, after a ppc-test build.
# Usage: tools/check-ct.sh [object ...]
#
# Compilers can legally remove the OR that makes a multiply constant-time, and
# every test still passes when they do, so this reads the code that was built.
# Each mullw/mulhw/mulhwu must take both inputs from values with bit 31 forced
# to 1. That is necessary but not sufficient (see below). mulli and divides are
# rejected outright.
#
# It walks otool -tv output top to bottom in each function, tracking which
# registers, r1-based stack words, lr and ctr have bit 31 forced by oris, lis,
# ori or or.
# It is a conservative screen, not a proof:
# - It shows that bit 31 is set, not that bit 30 is clear. mullw may treat its
#   operands as signed and finish early when the top bits are all ones, so an
#   operand with bits 30..16 set (0xFFFFxxxx after the OR) is unsafe and still
#   passes. The default objects are safe because their operands are 30-bit limbs
#   or smaller, which comes from the source and not from this check. A pass on
#   code with 31-bit words, such as BearSSL's i31 objects, shows nothing.
# - It cannot see which values are secret, so it rejects every other multiply.
# - It follows the listing in address order and carries state over branches, so
#   a value forced on only one path into a multiply is reported as forced.
# - It assumes writes through pointers do not change r1-based stack words.
# - A correct multiply whose forced operand it cannot follow is a false failure.
# - It checks the instructions only; it does not measure timing.

DEFAULT_OBJS="build/vendor-ppc/vendor/bearssl-0.6/src/symcipher/poly1305_ctmul32.o
build/vendor-ppc/vendor/bearssl-0.6/src/ec/ec_c25519_m31.o
build/ppc-test/src/crypto/nacl.o"

if [ $# -gt 0 ]; then OBJS=$*; else OBJS=$DEFAULT_OBJS; fi

status=0
for obj in $OBJS; do
    if [ ! -f "$obj" ]; then
        echo "check-ct: FAIL $obj: missing"
        status=1
        continue
    fi
    list=$(otool -tv "$obj") || { echo "check-ct: FAIL $obj: otool failed"; status=1; continue; }
    printf '%s\n' "$list" | awk -F'\t' -v obj="$obj" '
    function reset() { split("", reg); split("", slot); split("", spr) }
    # A call changes the volatile registers, the link register and ctr.
    function clobber(i) {
        for (i = 0; i <= 12; i++) if (i != 1 && i != 2) delete reg["r" i]
        split("", spr)
    }
    # True if a hexadecimal immediate has bit 15 set (bit 31 once shifted).
    function high(s, d, c) {
        sub(/^0x/, "", s)
        if (length(s) > 4) s = substr(s, length(s) - 3)
        if (length(s) < 4) return 0
        c = index("0123456789abcdef", tolower(substr(s, 1, 1))) - 1
        return c >= 8
    }
    function bad(why) { printf "check-ct: FAIL %s: %s: %s  %s %s\n", obj, fn, why, $2, $3; fails++ }
    BEGIN { reset(); fn = "?"; muls = 0; fails = 0 }
    /^[^\t]*:$/ { fn = $0; sub(/:$/, "", fn); reset(); next }
    NF < 3 {
        if ($2 ~ /^(blrl|bctrl)/) clobber()
        next
    }
    {
        op = $2; args = $3; gsub(/ /, "", args); n = split(args, a, ",")
        sub(/[.]$/, "", op)
    }
    op ~ /^(mullw|mullwo|mulhw|mulhwu)$/ {
        muls++
        if (!(a[2] in reg) || !(a[3] in reg)) bad("operand bit 31 not forced")
        delete reg[a[1]]
        next
    }
    op ~ /^(mulli|divw|divwu|divwo|divwuo)/ { bad("variable-time instruction"); delete reg[a[1]]; next }
    op == "bl" || op == "bla" {
        clobber()
        next
    }
    op == "mtspr" && (a[1] == "lr" || a[1] == "ctr") {
        if (a[2] in reg) spr[a[1]] = 1; else delete spr[a[1]]
        next
    }
    op == "mfspr" && (a[2] == "lr" || a[2] == "ctr") {
        if (a[2] in spr) reg[a[1]] = 1; else delete reg[a[1]]
        next
    }
    op == "stw" && a[2] ~ /\(r1\)$/ {
        if (a[1] in reg) slot[a[2]] = 1; else delete slot[a[2]]
        next
    }
    (op == "stb" || op == "sth" || op == "stmw" || op == "stwx") && args ~ /r1/ { split("", slot); next }
    op ~ /^(st|cmp|b|mt|dcb|icb|sync|isync|nop|tw)/ { next }
    op == "lwz" && a[2] ~ /\(r1\)$/ {
        if (a[2] in slot) reg[a[1]] = 1; else delete reg[a[1]]
        next
    }
    op == "lmw" { reset(); next }
    op == "lis" { if (high(a[2])) reg[a[1]] = 1; else delete reg[a[1]]; next }
    op == "oris" {
        if (high(a[3]) || (a[2] in reg)) reg[a[1]] = 1; else delete reg[a[1]]
        next
    }
    op == "ori" { if (a[2] in reg) reg[a[1]] = 1; else delete reg[a[1]]; next }
    op == "or" {
        if ((a[2] in reg) || (a[3] in reg)) reg[a[1]] = 1; else delete reg[a[1]]
        next
    }
    a[1] ~ /^r[0-9]+$/ { delete reg[a[1]] }
    END {
        if (muls == 0) { printf "check-ct: FAIL %s: no multiplies found\n", obj; fails++ }
        if (fails == 0) printf "check-ct: ok %s: %d multiplies, bit 31 forced on all operands\n", obj, muls
        exit(fails != 0)
    }' || status=1
done

if [ "$status" -ne 0 ]; then
    echo "check-ct: FAILED"
else
    echo "check-ct: passed"
fi
exit $status
