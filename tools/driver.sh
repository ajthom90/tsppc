#!/bin/sh
# Build, load and exercise the patched tun driver on a PowerPC Mac.
# Usage: tools/driver.sh build
#        sudo tools/driver.sh load|unload|cycle
#
# load and cycle take tun.kext, and cycle takes tun_check, from:
#   1. $TSPPC_KEXT and $TSPPC_TUN_CHECK (sudo clears the environment, so pass
#      them as: sudo env TSPPC_KEXT=... tools/driver.sh cycle);
#   2. otherwise build/driver/tun.kext and build/ppc-test/tun_check in this tree.
# This script runs as root, so it never takes them from the current directory,
# and it refuses a symlink.
# Only build needs a compiler.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=20090913
VENDOR_SRC=$ROOT/vendor/tuntaposx-$VERSION/tuntap/src
OUT=$ROOT/build/driver
BUNDLE_ID=foo.tun
STAGING_TEMPLATE=/tmp/tsppc.XXXXXX
# Records the private staging directory. /var/db is writable only by root;
# /var/run is not, as group daemon can write there.
RECORD=/var/db/tsppc-tun-staging
DEV=/dev/tun0
POLL_SEC=10
UNLOAD_TRIES=5
CYCLES=2

die() {
    echo "driver.sh: $1" >&2
    exit 1
}

need_root() {
    [ "$(id -u)" = 0 ] || die "$1 must run as root"
}

# locate <test flag> <env name> <env value> <build path>
# Print the file to use, or fail. Call as: x=$(locate ...) || exit 1
locate() {
    path=$4
    [ -n "$3" ] && path=$3
    # A trailing slash would make the symlink test look through the link.
    case "$path" in */) die "path must not end in /: $path" ;; esac
    [ -L "$path" ] && die "refusing symlink: $path"
    [ "$1" "$path" ] || die "not found or not usable: $path (set \$$2 to override)"
    echo "$path"
}

# wait_dev present|absent: wait up to POLL_SEC for the device node.
wait_dev() {
    waited=0
    while :; do
        if [ -e "$DEV" ]; then
            [ "$1" = present ] && return 0
        else
            [ "$1" = absent ] && return 0
        fi
        [ "$waited" -ge "$POLL_SEC" ] && return 1
        sleep 1
        waited=$((waited + 1))
    done
}

# Print the staging directory named in the record, if it has the form mktemp
# gives it. The result is only used for rm -rf after is_private_dir agrees.
staged_dir() {
    [ -f "$RECORD" ] || return 0
    d=$(cat "$RECORD")
    case "$d" in
    /tmp/tsppc.*/*) return 0 ;;
    /tmp/tsppc.??????) echo "$d" ;;
    esac
}

# True if $1 is a real directory, owned by root, with mode 700. Uses BSD stat,
# or the first and third fields of ls -ld where stat gives nothing.
is_private_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] || return 1
    info=$(stat -f '%u %Lp' "$1" 2>/dev/null)
    if [ -n "$info" ]; then
        [ "$info" = "0 700" ]
    else
        # shellcheck disable=SC2046
        set -- $(ls -ld "$1")
        [ "${1:-}" = drwx------ ] && [ "${3:-}" = root ]
    fi
}

# Remove the staging directory named in the record, and the record. Anything
# that is not a private root directory is left alone and reported.
clear_staging() {
    d=$(staged_dir)
    if [ -n "$d" ]; then
        if is_private_dir "$d"; then
            rm -rf "$d"
        elif [ -e "$d" ] || [ -L "$d" ]; then
            echo "driver.sh: not removing $d: not a private root directory" >&2
        fi
    fi
    rm -f "$RECORD"
}

# The kext is built from a copy: upstream's Makefile writes objects beside the
# sources, and a fresh copy ensures no object survives a flag change.
cmd_build() {
    [ -d "$VENDOR_SRC" ] || die "missing $VENDOR_SRC"
    rm -rf "$OUT" || die "cannot clear $OUT"
    mkdir -p "$OUT" || die "cannot create $OUT"
    cp -R "$VENDOR_SRC" "$OUT/src" || die "cannot copy driver source"
    ( cd "$OUT/src/tun" && make TUNTAP_VERSION="$VERSION" -f Makefile all ) || die "build failed"
    [ -f "$OUT/tun.kext/Contents/MacOS/tun" ] || die "build produced no $OUT/tun.kext"
    echo "built $OUT/tun.kext"
}

cmd_load() {
    need_root load
    [ -e "$DEV" ] && die "$DEV is already present; run unload first"
    kext=$(locate -d TSPPC_KEXT "${TSPPC_KEXT:-}" "$OUT/tun.kext") || exit 1
    clear_staging
    # Root loads this copy, so it lives in a new private directory rather than
    # at a fixed /tmp path that another user could plant or swap.
    staging=$(mktemp -d "$STAGING_TEMPLATE") || die "mktemp failed"
    if ! echo "$staging" >"$RECORD"; then
        rm -rf "$staging"
        die "cannot write $RECORD"
    fi
    staged=$staging/tun.kext
    if ! { chmod 700 "$staging" &&
           cp -R "$kext" "$staged" &&
           chown -R root:wheel "$staged" &&
           chmod -R go-w "$staged" &&
           kextload "$staged"; }; then
        clear_staging
        die "could not stage and load $kext"
    fi
    wait_dev present || die "$DEV did not appear after kextload"
    echo "loaded $kext, $DEV present"
}

# The interface detaches after the device closes, so the first kextunload can
# find the driver still busy.
cmd_unload() {
    need_root unload
    tries=1
    while :; do
        kextunload -b "$BUNDLE_ID" && break
        [ "$tries" -ge "$UNLOAD_TRIES" ] && die "kextunload failed after $tries tries"
        tries=$((tries + 1))
        sleep 2
    done
    wait_dev absent || die "$DEV still present after kextunload"
    clear_staging
    echo "unloaded, $DEV gone"
}

cmd_cycle() {
    need_root cycle
    check=$(locate -x TSPPC_TUN_CHECK "${TSPPC_TUN_CHECK:-}" "$ROOT/build/ppc-test/tun_check") || exit 1
    n=1
    while [ "$n" -le "$CYCLES" ]; do
        echo "=== cycle $n of $CYCLES ==="
        cmd_load
        "$check"
        rc=$?
        # Unload even after a failed check, so a failure leaves no driver behind.
        cmd_unload
        [ "$rc" -eq 0 ] || die "tun_check failed in cycle $n (exit $rc)"
        n=$((n + 1))
    done
    [ -e "$DEV" ] && die "$DEV present after the last cycle"
    echo "cycle complete: $CYCLES passes, $DEV gone"
}

case "${1:-}" in
build)  cmd_build ;;
load)   cmd_load ;;
unload) cmd_unload ;;
cycle)  cmd_cycle ;;
*)      echo "usage: $0 build|load|unload|cycle" >&2; exit 2 ;;
esac
