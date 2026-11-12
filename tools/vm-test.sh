#!/bin/sh
# Build and run the PowerPC test binary on a VM.
# Usage: TSPPC_SSH_CONFIG=<ssh config> [TSPPC_VM_USER=<login>] [TSPPC_VM_DIR=<dir>] tools/vm-test.sh <leopard|tiger|leopard-root>
# leopard: copy the tree, build with make ppc-test CC=gcc-4.0 (which also builds
#          tsppcd and tsppc, hooked and release, checks with
#          tools/check-release.sh that the release tsppcd has no test hooks,
#          and runs the binary, daemon tests included), check the built
#          objects with tools/check-ct.sh, build the menu bar app with
#          make menubar and check it with tools/check-app.sh (after checking
#          that check-app.sh rejects /bin/ls).
# leopard-root: run the Leopard-built binary under sudo (after a leopard run).
# tiger:   fetch the Leopard-built binary via the host, copy to Tiger, run it
#          (without tsppcd and tsppc beside it, the daemon tests print SKIP).
set -u

: "${TSPPC_SSH_CONFIG:?set TSPPC_SSH_CONFIG to the ssh config path}"
HOSTNAME_ARG=${1:-}
case "$HOSTNAME_ARG" in
leopard|tiger|leopard-root) ;;
*) echo "usage: $0 <leopard|tiger|leopard-root>" >&2; exit 2 ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# TSPPC_VM_DIR: the build directory under the VM login's home (default
# tsppc). CI uses its own, so it never touches a build made by hand.
VMDIR=${TSPPC_VM_DIR:-tsppc}
case "$VMDIR" in
''|*[!A-Za-z0-9._-]*|.*) echo "vm-test.sh: bad TSPPC_VM_DIR" >&2; exit 2 ;;
esac
if [ "$VMDIR" = tsppc ]; then TBIN=test_all; else TBIN=${VMDIR}_test_all; fi
SSHOPTS="-F $TSPPC_SSH_CONFIG -o BatchMode=yes"
if [ -n "${TSPPC_VM_USER:-}" ]; then SSHOPTS="$SSHOPTS -l $TSPPC_VM_USER"; fi
BIN=build/ppc-test/test_all

# Run ssh with the macOS _CFGetHostUUID noise removed from stderr, keeping
# the remote exit status.
vmssh() {
    host=$1; shift
    errf=$(mktemp "${TMPDIR:-/tmp}/tsppc.XXXXXX") || exit 1
    # shellcheck disable=SC2086
    ssh $SSHOPTS "$host" "$@" 2>"$errf"
    rc=$?
    grep -v '_CFGetHostUUID' "$errf" >&2
    rm -f "$errf"
    return $rc
}

case "$HOSTNAME_ARG" in
leopard-root)
    # Run the binary built by a previous "leopard" run as root (passwordless sudo),
    # for the tests that need to chown.
    vmssh leopard 'cd "$HOME/'"$VMDIR"'" && sudo ./'$BIN
    exit $?
    ;;
leopard)
    # Build the archive in a file first, so a tar failure is not hidden by a pipe.
    arc=$(mktemp "${TMPDIR:-/tmp}/tsppcsrc.XXXXXX") || exit 1
    trap 'rm -f "$arc"' EXIT
    ( cd "$ROOT" && COPYFILE_DISABLE=1 tar -cf "$arc" --exclude ./build --exclude ./spike --exclude ./.superpowers --exclude ./.git . ) ||
        { echo "vm-test.sh: tar failed" >&2; exit 1; }
    # Remove the old sources first so files deleted on the host are not built.
    # build/ is kept. The id file records what this tree was.
    ID="$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo nogit)"
    if [ -n "$(cd "$ROOT" && git status --porcelain --untracked-files=no -- src tests tools vendor macos Makefile 2>/dev/null)" ]; then
        ID="$ID+modified"
    fi
    ID="$ID archive-cksum $(cksum <"$arc" | cut -d' ' -f1,2 | tr ' ' :)"
    vmssh leopard 'mkdir -p "$HOME/'"$VMDIR"'" && cd "$HOME/'"$VMDIR"'" && rm -rf src tests tools vendor macos Makefile && tar -xf -' <"$arc" || exit 1
    vmssh leopard 'mkdir -p "$HOME/'"$VMDIR"'/build/ppc-test" && echo '"'$ID'"' >"$HOME/'"$VMDIR"'/build/ppc-test/SOURCE_ID"' || exit 1
    vmssh leopard 'cd "$HOME/'"$VMDIR"'" && make ppc-test CC=gcc-4.0 && sh tools/check-ct.sh' || exit 1
    vmssh leopard 'cd "$HOME/'"$VMDIR"'" &&
        if sh tools/check-app.sh /bin/ls >/dev/null 2>&1; then echo "vm-test.sh: check-app.sh passed /bin/ls" >&2; exit 1; fi &&
        make menubar CC=gcc-4.0 && sh tools/check-app.sh build/ppc/tsppc.app'
    exit $?
    ;;
tiger)
    tmp=$(mktemp "${TMPDIR:-/tmp}/tsppcbin.XXXXXX") || exit 1
    trap 'rm -f "$tmp"' EXIT
    vmssh leopard 'cat "$HOME/'"$VMDIR"'/'$BIN'"' >"$tmp" || exit 1
    echo "binary cksum: $(cksum <"$tmp" | cut -d' ' -f1,2)"
    if command -v shasum >/dev/null 2>&1; then echo "binary sha256: $(shasum -a 256 <"$tmp" | cut -d' ' -f1)"; fi
    echo "built from: $(vmssh leopard 'cat "$HOME/'"$VMDIR"'/build/ppc-test/SOURCE_ID"' 2>/dev/null || echo unknown)"
    vmssh tiger 'cat > "$HOME/'"$TBIN"'" && chmod +x "$HOME/'"$TBIN"'"' <"$tmp" || exit 1
    vmssh tiger '"$HOME/'"$TBIN"'"'
    exit $?
    ;;
esac
