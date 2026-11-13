#!/bin/sh
# Build a tsppc release. Runs on the host Mac, from a clean git checkout at
# the release tag; the build itself runs on the Leopard VM (Xcode 3.1,
# gcc-4.0, the 10.4u SDK), reached as tools/vm-test.sh reaches it.
# Usage: TSPPC_SSH_CONFIG=<ssh config> [TSPPC_VM_USER=<login>] tools/release.sh <tag>
#   <tag> is v<version> or <version>, <version> being TS_IPN_VERSION without -ppc.
#
# 1. Refuses unless the working tree is clean (and git status works), the tag
#    exists and HEAD is at it.
# 2. Ships git archive <tag> to a fresh ~/tsppc-release/<tag> on the VM
#    (removed and recreated each run) and runs there, in order: the PowerPC
#    suite (make ppc-test, as tools/vm-test.sh does), make release ppc (each
#    checked by tools/check-release.sh), tools/check-ct.sh, make menubar with
#    tools/check-app.sh, tools/driver.sh build and tools/package.sh <version>.
# 3. Copies the .dmg and the standalone uninstaller to build/release/ here,
#    checks they arrived intact, and writes build/release/SHA256SUMS with
#    shasum -a 256.
# 4. Prints the file list. It never signs and never uploads.
set -u

TAG=${1:-}
[ -n "$TAG" ] || { echo "usage: TSPPC_SSH_CONFIG=<ssh config> $0 <tag>" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "release.sh: $*" >&2; exit 1; }

cd "$ROOT" || die "cannot cd to $ROOT"
case "$TAG" in
''|-*|.*|*[!A-Za-z0-9._-]*) die "bad tag name: $TAG" ;;
esac

# A clean checkout at the tag, before anything else. git status failing
# counts as not clean.
command -v git >/dev/null 2>&1 || die "git not found"
[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = true ] || die "$ROOT is not a git checkout"
st=$(git status --porcelain 2>/dev/null) || die "git status failed; cannot tell whether the checkout is clean"
[ -z "$st" ] || die "the checkout has changes or untracked files; release from a clean checkout"
tagc=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null) || die "no tag $TAG"
headc=$(git rev-parse HEAD) || die "cannot read HEAD"
[ "$tagc" = "$headc" ] || die "HEAD is not at $TAG"

VERSION=${TAG#v}
want=$(git show "$TAG:src/state/hostinfo.h" | sed -n 's/^#define TS_IPN_VERSION "\(.*\)-ppc"$/\1/p')
[ -n "$want" ] || die "cannot read TS_IPN_VERSION at $TAG"
[ "$VERSION" = "$want" ] || die "tag $TAG does not match TS_IPN_VERSION ($want-ppc)"

: "${TSPPC_SSH_CONFIG:?set TSPPC_SSH_CONFIG to the ssh config path}"
command -v shasum >/dev/null 2>&1 || die "shasum not found"
SSHOPTS="-F $TSPPC_SSH_CONFIG -o BatchMode=yes"
if [ -n "${TSPPC_VM_USER:-}" ]; then SSHOPTS="$SSHOPTS -l $TSPPC_VM_USER"; fi

# Run ssh on the Leopard VM with the macOS _CFGetHostUUID noise removed from
# stderr, keeping the remote exit status.
vmssh() {
    errf=$(mktemp "${TMPDIR:-/tmp}/tsppc.XXXXXX") || exit 1
    # shellcheck disable=SC2086
    ssh $SSHOPTS leopard "$@" 2>"$errf"
    rc=$?
    grep -v '_CFGetHostUUID' "$errf" >&2
    rm -f "$errf"
    return $rc
}

RDIR='$HOME/tsppc-release/'$TAG
OUT=$ROOT/build/release
DMG=tsppc-$VERSION.dmg
UNINST=tsppc-uninstall

arc=$(mktemp "${TMPDIR:-/tmp}/tsppcrel.XXXXXX") || die "mktemp failed"
trap 'rm -f "$arc"' EXIT
git archive --format=tar "$TAG" >"$arc" || die "git archive failed"

echo "=== shipping $TAG ($headc) to the VM"
vmssh "rm -rf $RDIR && mkdir -p $RDIR && cd $RDIR && tar -xf -" <"$arc" || die "cannot ship the tree to the VM"

echo "=== building on the VM"
vmssh "cd $RDIR &&
    echo '=== make ppc-test' && make ppc-test CC=gcc-4.0 &&
    echo '=== make release ppc' && make release ppc CC=gcc-4.0 &&
    echo '=== check-ct' && sh tools/check-ct.sh &&
    if sh tools/check-app.sh /bin/ls >/dev/null 2>&1; then echo 'check-app.sh passed /bin/ls' >&2; exit 1; fi &&
    echo '=== make menubar' && make menubar CC=gcc-4.0 && sh tools/check-app.sh build/ppc/tsppc.app &&
    echo '=== driver build' && sh tools/driver.sh build &&
    echo '=== package' && sh tools/package.sh $VERSION" || die "the build on the VM failed"

echo "=== fetching the release files"
mkdir -p "$OUT" || die "cannot create $OUT"
rm -f "$OUT/$DMG" "$OUT/$UNINST" "$OUT/SHA256SUMS" || die "cannot clear $OUT"
for f in "$DMG" "$UNINST"; do
    vmssh "cat $RDIR/build/release/$f" >"$OUT/$f" || die "cannot fetch $f"
done
chmod 755 "$OUT/$UNINST" || die "cannot chmod $OUT/$UNINST"
# The copies match the VM's files (Python 2.5's hashlib there: Leopard's
# OpenSSL 0.9.7 has no SHA-256).
remote=$(vmssh "cd $RDIR/build/release && python -c 'import sys, hashlib
for n in sys.argv[1:]:
    f = open(n, \"rb\"); sys.stdout.write(\"%s  %s\\n\" % (hashlib.sha256(f.read()).hexdigest(), n)); f.close()' $DMG $UNINST") ||
    die "cannot hash the files on the VM"
(cd "$OUT" && shasum -a 256 "$DMG" "$UNINST" >SHA256SUMS) || die "cannot write SHA256SUMS"
[ "$remote" = "$(cat "$OUT/SHA256SUMS")" ] || die "the fetched files differ from the VM's"

echo "=== release $TAG (not signed, not uploaded)"
ls -l "$OUT/$DMG" "$OUT/$UNINST" "$OUT/SHA256SUMS"
cat "$OUT/SHA256SUMS"
