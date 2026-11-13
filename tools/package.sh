#!/bin/sh
# Build the tsppc Installer package and disk image on the Leopard VM (or a
# PowerPC Mac with Xcode), from a tree where make ppc, make menubar and
# tools/driver.sh build have run. make package does all of that, then this.
#
# Usage: tools/package.sh <version>      (the version is TS_IPN_VERSION
#                                          without its -ppc suffix)
# Makes, in build/release:
#   tsppc-<version>.pkg   a bundle-style package, which Tiger's Installer reads
#   tsppc-uninstall       the uninstaller, as installed
#   tsppc-<version>.dmg   UDZO image with the package, the uninstaller, ReadMe.txt
# and ends with tools/check-pkg.sh on the package.
#
# sudo is used only to give the staging tree root ownership (the payload's
# owners come from it) and to remove that tree.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${1:-}
LABEL=com.github.ajthom90.tsppcd

die() { echo "package.sh: $*" >&2; exit 1; }

[ -n "$VERSION" ] || { echo "usage: $0 <version>" >&2; exit 2; }
case "$VERSION" in
*[!0-9.]*|.*|*.) die "bad version: $VERSION" ;;
esac
[ -n "$ROOT" ] && [ "$ROOT" != / ] || die "cannot find the source tree"
cd "$ROOT" || die "cannot cd to $ROOT"

want=$(sed -n 's/^#define TS_IPN_VERSION "\(.*\)-ppc"$/\1/p' src/state/hostinfo.h)
[ -n "$want" ] || die "cannot read TS_IPN_VERSION from src/state/hostinfo.h"
[ "$VERSION" = "$want" ] || die "version $VERSION differs from TS_IPN_VERSION ($want-ppc)"

DAEMON=build/ppc/tsppcd
CLI=build/ppc/tsppc
APP=build/ppc/tsppc.app
KEXT=build/driver/tsppc-tun.kext
UNINST=tools/uninstall.sh
LDPLIST=macos/launchd/$LABEL.plist
for f in "$DAEMON" "$CLI" "$APP/Contents/MacOS/tsppc" "$APP/Contents/Info.plist" \
         "$APP/Contents/PkgInfo" "$KEXT/Contents/MacOS/tun" "$KEXT/Contents/Info.plist" \
         "$UNINST" "$LDPLIST" macos/pkg/Info.plist.in macos/pkg/Description.plist \
         macos/pkg/preflight macos/pkg/postflight macos/pkg/ReadMe.txt \
         LICENSE vendor/bearssl-0.6/LICENSE.txt vendor/tuntaposx-20090913/tuntap/src/tuntap.cc; do
    [ -f "$f" ] || die "missing $f (run make ppc, make menubar and tools/driver.sh build first)"
done
# The release programs carry no test hooks, and the app passes its checks.
sh tools/check-release.sh "$DAEMON" || die "check-release.sh failed on $DAEMON"
sh tools/check-release.sh --cli "$CLI" || die "check-release.sh failed on $CLI"
sh tools/check-app.sh "$APP" || die "check-app.sh failed on $APP"

# No AppleDouble files from cp, pax or hdiutil.
COPYFILE_DISABLE=1
COPY_EXTENDED_ATTRIBUTES_DISABLE=1
export COPYFILE_DISABLE COPY_EXTENDED_ATTRIBUTES_DISABLE

OUT=$ROOT/build/release
STAGE=$ROOT/build/pkgstage
PKG=$OUT/tsppc-$VERSION.pkg
DMG=$OUT/tsppc-$VERSION.dmg
DMGSRC=$OUT/dmg-src

# The staging tree becomes root-owned, so it is removed with sudo. The path is
# fixed under build/; never an empty or other one.
clear_stage() {
    case "$STAGE" in
    "$ROOT"/build/pkgstage) sudo rm -rf "$STAGE" ;;
    *) echo "package.sh: not removing unexpected staging path $STAGE" >&2 ;;
    esac
}
trap 'clear_stage; rm -rf "$DMGSRC"' EXIT
trap 'exit 1' HUP INT TERM

clear_stage
[ -e "$STAGE" ] && die "cannot remove the old $STAGE"
rm -rf "$PKG" "$DMG" "$DMGSRC" "$OUT/tsppc-uninstall" || die "cannot clear old outputs"
mkdir -p "$OUT" || die "cannot create $OUT"

# The root tree. Modes are set while the files are still ours; one sudo chown
# pass then gives the owners. Directories that already exist on 10.4 and 10.5
# (/, /Applications, /Library, /Library/LaunchDaemons, /usr) get the owner and
# mode they already have; tools/check-pkg.sh pins every path.
mkdir -p "$STAGE/Applications" "$STAGE/Library/Extensions" "$STAGE/Library/LaunchDaemons" \
         "$STAGE/usr/local/bin" "$STAGE/usr/local/sbin" || die "cannot create $STAGE"
cp "$DAEMON" "$STAGE/usr/local/sbin/tsppcd" &&
cp "$UNINST" "$STAGE/usr/local/sbin/tsppc-uninstall" &&
cp "$CLI" "$STAGE/usr/local/bin/tsppc" &&
cp "$LDPLIST" "$STAGE/Library/LaunchDaemons/$LABEL.plist" &&
cp -R "$KEXT" "$STAGE/Library/Extensions/tsppc-tun.kext" &&
cp -R "$APP" "$STAGE/Applications/tsppc.app" || die "cannot copy into $STAGE"

S=$STAGE
chmod 1775 "$S" "$S/Library" &&
chmod 775 "$S/Applications" &&
chmod 755 "$S/Library/Extensions" "$S/Library/LaunchDaemons" "$S/usr" "$S/usr/local" \
          "$S/usr/local/bin" "$S/usr/local/sbin" &&
chmod 755 "$S/usr/local/sbin/tsppcd" "$S/usr/local/sbin/tsppc-uninstall" "$S/usr/local/bin/tsppc" &&
chmod 644 "$S/Library/LaunchDaemons/$LABEL.plist" &&
find "$S/Library/Extensions/tsppc-tun.kext" -type d -exec chmod 755 {} \; &&
find "$S/Library/Extensions/tsppc-tun.kext" -type f -exec chmod 644 {} \; &&
find "$S/Applications/tsppc.app" -type d -exec chmod 775 {} \; &&
find "$S/Applications/tsppc.app" -type f -exec chmod 644 {} \; &&
chmod 755 "$S/Applications/tsppc.app/Contents/MacOS/tsppc" || die "cannot set modes in $STAGE"
sudo chown -R 0:0 "$S" &&
sudo chown 0:80 "$S" "$S/Library" &&
sudo chown -R 0:80 "$S/Applications" || die "cannot set owners in $STAGE (sudo)"

# The bundle.
C=$PKG/Contents
mkdir -p "$C/Resources/English.lproj" || die "cannot create $C"
(cd "$STAGE" && pax -w -x cpio -z .) >"$C/Archive.pax.gz" || die "pax failed"
mkbom "$STAGE" "$C/Archive.bom" || die "mkbom failed"
size=$(du -sk "$STAGE" | awk '{ print $1 }')
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE_KB@/$size/" macos/pkg/Info.plist.in >"$C/Info.plist" ||
    die "cannot write Info.plist"
printf 'pmkrpkg1' >"$C/PkgInfo" || die "cannot write PkgInfo"
cp macos/pkg/preflight macos/pkg/postflight macos/pkg/ReadMe.txt "$C/Resources/" &&
chmod 755 "$C/Resources/preflight" "$C/Resources/postflight" &&
cp macos/pkg/Description.plist "$C/Resources/English.lproj/Description.plist" ||
    die "cannot copy the package resources"

# License.txt: tsppc's licence, then the tuntaposx notice (the header comment
# of its sources; it has no licence file), then BearSSL's licence.
{
    cat LICENSE
    printf '\n\n----------------------------------------------------------------------\n'
    printf 'tuntaposx (the tun driver in /Library/Extensions/tsppc-tun.kext)\n\n'
    awk '/^ \* Copyright/ { on = 1 }
         on && /^ \*\// { exit }
         on { s = $0; sub(/^ \* ?/, "", s); sub(/^ \*$/, "", s); print s }' \
        vendor/tuntaposx-20090913/tuntap/src/tuntap.cc
    printf '\n\n----------------------------------------------------------------------\n'
    printf 'BearSSL (built into tsppcd)\n\n'
    cat vendor/bearssl-0.6/LICENSE.txt
} >"$C/Resources/License.txt" || die "cannot write License.txt"
grep -q 'Mattias Nissler' "$C/Resources/License.txt" || die "the tuntaposx notice was not found"

# The uninstaller beside the package, for the checksums and the disk image.
cp "$UNINST" "$OUT/tsppc-uninstall" && chmod 755 "$OUT/tsppc-uninstall" || die "cannot copy the uninstaller"

# The disk image (HFS+, UDZO: both read on Tiger).
mkdir -p "$DMGSRC" &&
cp -R "$PKG" "$DMGSRC/" &&
cp "$OUT/tsppc-uninstall" "$DMGSRC/tsppc-uninstall" &&
cp macos/pkg/ReadMe.txt "$DMGSRC/ReadMe.txt" || die "cannot stage the disk image"
hdiutil create -quiet -ov -fs HFS+ -format UDZO -volname "tsppc $VERSION" \
    -srcfolder "$DMGSRC" "$DMG" || die "hdiutil create failed"

sh tools/check-pkg.sh "$PKG" || die "check-pkg.sh failed"
echo "built $PKG"
echo "built $DMG"
