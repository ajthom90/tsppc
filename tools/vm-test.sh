#!/bin/sh
# Build and run the PowerPC test binary on a VM.
# Usage: TSPPC_SSH_CONFIG=<ssh config> [TSPPC_VM_USER=<login>] tools/vm-test.sh <leopard|tiger>
# leopard: copy the tree, build with make ppc-test CC=gcc-4.0, run the binary.
# tiger:   fetch the Leopard-built binary via the host, copy to Tiger, run it.
set -u

: "${TSPPC_SSH_CONFIG:?set TSPPC_SSH_CONFIG to the ssh config path}"
HOSTNAME_ARG=${1:-}
case "$HOSTNAME_ARG" in
leopard|tiger) ;;
*) echo "usage: $0 <leopard|tiger>" >&2; exit 2 ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SSHOPTS="-F $TSPPC_SSH_CONFIG -o BatchMode=yes"
if [ -n "${TSPPC_VM_USER:-}" ]; then SSHOPTS="$SSHOPTS -l $TSPPC_VM_USER"; fi
BIN=build/ppc-test/test_all

# Run ssh with the macOS _CFGetHostUUID noise removed from stderr, keeping
# the remote exit status.
vmssh() {
    host=$1; shift
    errf=$(mktemp -t tsppc) || exit 1
    # shellcheck disable=SC2086
    ssh $SSHOPTS "$host" "$@" 2>"$errf"
    rc=$?
    grep -v '_CFGetHostUUID' "$errf" >&2
    rm -f "$errf"
    return $rc
}

case "$HOSTNAME_ARG" in
leopard)
    ( cd "$ROOT" && COPYFILE_DISABLE=1 tar -cf - --exclude ./build --exclude ./spike --exclude ./.superpowers --exclude ./.git . ) |
        vmssh leopard 'mkdir -p "$HOME/tsppc" && cd "$HOME/tsppc" && tar -xf -' || exit 1
    vmssh leopard 'cd "$HOME/tsppc" && make ppc-test CC=gcc-4.0'
    exit $?
    ;;
tiger)
    tmp=$(mktemp -t tsppcbin) || exit 1
    trap 'rm -f "$tmp"' EXIT
    vmssh leopard 'cat "$HOME/tsppc/'$BIN'"' >"$tmp" || exit 1
    vmssh tiger 'cat > "$HOME/test_all" && chmod +x "$HOME/test_all"' <"$tmp" || exit 1
    vmssh tiger '"$HOME/test_all"'
    exit $?
    ;;
esac
