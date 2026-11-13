#!/bin/sh
# Check the built menu bar app: no "Tailscale" anywhere in the binary or its
# Info.plist, no test hooks (no TSPPC_ string, no getenv: it is built from the
# release socket code, as tools/check-release.sh checks for tsppc), a PowerPC
# binary, only the system libraries it needs, and no
# name-lookup or network API among its undefined symbols (resolver calls
# included). Its one connection
# is the daemon's Unix socket, so socket, connect, read, write, select, close
# and fcntl are allowed. Run on the VM (needs otool, nm and lipo for ppc).
# Usage: tools/check-app.sh <path to tsppc.app>
set -u

APP=${1:?usage: $0 <path to tsppc.app>}
BIN=$APP/Contents/MacOS/tsppc
PLIST=$APP/Contents/Info.plist
fail=0

die() { echo "check-app: $*" >&2; exit 1; }
bad() { echo "check-app: $*" >&2; fail=1; }

[ -d "$APP/Contents" ] || die "$APP is not an app bundle"
[ -f "$PLIST" ] || die "$PLIST missing"
[ -f "$BIN" ] || die "$BIN missing"

tmp=$(mktemp -t tsppcapp) || exit 1
trap 'rm -f "$tmp"' EXIT

# The name.
for f in "$BIN" "$PLIST"; do
    if LC_ALL=C grep -a -i -q tailscale "$f"; then bad "$f contains \"Tailscale\""; fi
done

# No test hooks: an environment override would let any user redirect the app.
if LC_ALL=C grep -a -q TSPPC_ "$BIN"; then bad "$BIN contains a TSPPC_ string (a test hook)"; fi

# The architecture: a thin ppc binary.
lipo -info "$BIN" >"$tmp" 2>&1 || die "lipo failed on $BIN"
if ! grep -q 'is architecture: ppc$' "$tmp"; then bad "$BIN is not a ppc binary: $(cat "$tmp")"; fi

# The libraries. libgcc_s and libobjc are linked by gcc-4.0 itself into every
# Objective-C program built against the 10.4u SDK; both are part of the system.
otool -L "$BIN" >"$tmp" 2>/dev/null || die "otool -L failed on $BIN"
libs=$(sed -n '2,$p' "$tmp" | sed 's/^[[:space:]]*//; s/ (compatibility.*//')
[ -n "$libs" ] || die "otool -L listed no libraries for $BIN"
seen_cocoa=0
for l in $libs; do
    case "$l" in
    /System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa) seen_cocoa=1 ;;
    /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation) ;;
    /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit) ;;
    # The Login Items code calls CFPreferences, so the linker records
    # CoreFoundation (and the CoreServices umbrella it comes through) itself.
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation) ;;
    /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices) ;;
    /usr/lib/libSystem.B.dylib) ;;
    /usr/lib/libgcc_s.1.dylib) ;;
    /usr/lib/libobjc.A.dylib) ;;
    *) bad "$BIN links $l" ;;
    esac
done
[ "$seen_cocoa" = 1 ] || bad "$BIN does not link Cocoa (wrong file?)"

# The undefined symbols.
nm -u "$BIN" >"$tmp" 2>/dev/null || die "nm -u failed on $BIN"
# The Unix socket calls must be there, or this looked in the wrong place.
for s in socket connect; do
    grep -q "^_$s\$" "$tmp" || die "no _$s among the undefined symbols of $BIN (wrong file?)"
done
hits=$(grep -E '^_(getenv|getaddrinfo|gethostbyname[0-9_a-z]*|gethostbyaddr|getnameinfo|getipnodebyname|getipnodebyaddr|res_[0-9_a-z]*|sendto|recvfrom|bind|listen|accept)(\$.*)?$|NSURL|CFNetwork|CFSocket|CFStream' "$tmp")
for s in $hits; do bad "$BIN uses $s"; done

if [ "$fail" != 0 ]; then exit 1; fi
echo "check-app: $APP passes"
