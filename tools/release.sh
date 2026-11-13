#!/bin/sh
# Build a tsppc release on a PowerPC Mac (or the Leopard VM) with Xcode 3.1
# (gcc-4.0, the 10.4u SDK) and git, from a clean checkout at the release tag.
# Usage: tools/release.sh <tag>        (tag v<version> or <version>, where
#                                       <version> is TS_IPN_VERSION without -ppc)
# Runs make clean, the PowerPC suite (as tools/vm-test.sh runs it on the VM),
# make ppc, tools/check-ct.sh, make menubar with tools/check-app.sh,
# tools/driver.sh build and tools/package.sh, then writes
# build/release/SHA256SUMS for the disk image and the uninstaller (with
# Python's hashlib: Leopard's OpenSSL 0.9.7 has no SHA-256) and lists the
# files. It never signs and never uploads.
set -u

TAG=${1:-}
[ -n "$TAG" ] || { echo "usage: $0 <tag>" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "release.sh: $*" >&2; exit 1; }

cd "$ROOT" || die "cannot cd to $ROOT"

# A clean checkout at the tag, before anything is built.
command -v git >/dev/null 2>&1 || die "git not found; a release is built from a git checkout"
[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = true ] || die "$ROOT is not a git checkout"
[ -z "$(git status --porcelain 2>/dev/null)" ] || die "the checkout has changes or untracked files; release from a clean checkout"
tagc=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null) || die "no tag $TAG"
headc=$(git rev-parse HEAD) || die "cannot read HEAD"
[ "$tagc" = "$headc" ] || die "HEAD is not at $TAG"

VERSION=${TAG#v}
want=$(sed -n 's/^#define TS_IPN_VERSION "\(.*\)-ppc"$/\1/p' src/state/hostinfo.h)
[ "$VERSION" = "$want" ] || die "tag $TAG does not match TS_IPN_VERSION ($want-ppc)"

if ! command -v gcc-4.0 >/dev/null 2>&1 || [ ! -d /Developer/SDKs/MacOSX10.4u.sdk ]; then
    die "needs gcc-4.0 and /Developer/SDKs/MacOSX10.4u.sdk; run on a PowerPC Mac or the Leopard VM"
fi
command -v python >/dev/null 2>&1 || die "python not found (for SHA256SUMS)"

step() { echo "=== $*"; "$@" || die "failed: $*"; }

step make clean
# The PowerPC suite: test binary, hooked and release programs, the release
# check, and the tests themselves (as tools/vm-test.sh runs it).
step make ppc-test CC=gcc-4.0
step make ppc
step sh tools/check-ct.sh
# check-app.sh must reject something that is not the app.
if sh tools/check-app.sh /bin/ls >/dev/null 2>&1; then die "check-app.sh passed /bin/ls"; fi
step make menubar CC=gcc-4.0
step sh tools/check-app.sh build/ppc/tsppc.app
step sh tools/driver.sh build
step sh tools/package.sh "$VERSION"

OUT=build/release
DMG=tsppc-$VERSION.dmg
UNINST=tsppc-uninstall
[ -f "$OUT/$DMG" ] && [ -f "$OUT/$UNINST" ] || die "package.sh left no $OUT/$DMG or $OUT/$UNINST"
# Python 2.5 syntax: no with, no format.
(cd "$OUT" && python -c '
import sys, hashlib
for name in sys.argv[1:]:
    f = open(name, "rb")
    h = hashlib.sha256()
    while True:
        b = f.read(65536)
        if not b:
            break
        h.update(b)
    f.close()
    sys.stdout.write("%s  %s\n" % (h.hexdigest(), name))
' "$DMG" "$UNINST" >SHA256SUMS) || die "cannot write SHA256SUMS"

echo "=== release $TAG (not signed, not uploaded)"
ls -l "$OUT"
cat "$OUT/SHA256SUMS"
