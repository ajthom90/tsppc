#!/bin/sh
# Check that a release program has no test hooks: no test-only symbols, none
# of the environment overrides (no TSPPC_ string at all), and no getenv (it
# reads no environment). With a second argument (the hooked build of the same
# program from the same tree), also check that the hooked one has them, so the
# check cannot pass because it looks in the wrong place.
# --cli checks the tsppc command line program (its only hook is TSPPC_SOCKET,
# in the socket code it shares with the daemon) instead of tsppcd.
# Usage: tools/check-release.sh [--cli] <release program> [<hooked program>]
set -u

if [ "${1:-}" = --cli ]; then
    shift
    SYMS="getenv"
    STRS="TSPPC_SOCKET"
else
    SYMS="ts_noise_init_eph ts_resolve_test_delay ts_wg_test_dh_count ts_wg_test_has_keys ts_wg_test_keypairs ts_dpio_test_tun_open ts_dpio_test_run ts_dp_test_counters ts_dp_test_on_deliver ts_dp_test_has_keys ts_names_test_writes ts_names_test_flushes getenv"
    STRS="TSPPC_STATE_DIR TSPPC_SOCKET TSPPC_CONTROL TSPPC_CONTROL_KEY TSPPC_NO_TUN TSPPC_DERP_PLAIN TSPPC_HOSTS_FILE"
fi
REL=${1:?usage: $0 [--cli] <release program> [<hooked program>]}
HOOKED=${2:-}
fail=0

tmp=$(mktemp -t tsppcnm) || exit 1
trap 'rm -f "$tmp"' EXIT

syms_of() {
    if ! nm "$1" >"$tmp" 2>/dev/null; then
        echo "check-release: nm failed on $1" >&2
        exit 1
    fi
    if ! grep -q ' _main$' "$tmp"; then
        echo "check-release: no _main in the symbols of $1" >&2
        exit 1
    fi
}

check() {   # check <binary> <want: 0 absent, 1 present>
    bin=$1
    want=$2
    [ -f "$bin" ] || { echo "check-release: $bin missing" >&2; exit 1; }
    syms_of "$bin"
    for s in $SYMS; do
        # Defined (" T _x") or imported (" U _x") both count.
        if grep -q " _$s\$" "$tmp"; then got=1; else got=0; fi
        if [ "$got" != "$want" ]; then
            echo "check-release: $bin: symbol $s $( [ "$want" = 1 ] && echo missing || echo present)" >&2
            fail=1
        fi
    done
    for s in $STRS; do
        if LC_ALL=C grep -a -q "$s" "$bin"; then got=1; else got=0; fi
        if [ "$got" != "$want" ]; then
            echo "check-release: $bin: string $s $( [ "$want" = 1 ] && echo missing || echo present)" >&2
            fail=1
        fi
    done
}

check "$REL" 0
# Any other TSPPC_ name is an override this script does not know yet.
if LC_ALL=C grep -a -q TSPPC_ "$REL"; then
    echo "check-release: $REL: a TSPPC_ string is present" >&2
    fail=1
fi
if [ -n "$HOOKED" ]; then check "$HOOKED" 1; fi
if [ "$fail" != 0 ]; then exit 1; fi
echo "check-release: $REL has no test hooks"
