#!/bin/sh
# Check a built tsppc Installer package (bundle style, for Tiger and Leopard):
# the bundle layout, every Info.plist key, the payload's exact path set with
# owners and modes (from the bom and from the pax archive, which must agree),
# the LaunchDaemon plist inside the payload, the scripts and the ReadMe.
# Runs on the VM or the host (needs lsbom, pax and gzip).
# Usage: tools/check-pkg.sh <path to tsppc-<version>.pkg>
set -u

PKG=${1:-}
[ -n "$PKG" ] || { echo "usage: $0 <path to tsppc-<version>.pkg>" >&2; exit 2; }
PKG=${PKG%/}
C=$PKG/Contents
R=$C/Resources
LABEL=com.github.ajthom90.tsppcd
PLIST_PATH=./Library/LaunchDaemons/$LABEL.plist
NOTICE='tsppc is an unofficial Tailscale client for PowerPC Macs. It is not affiliated with or endorsed by Tailscale Inc.'
fail=0

die() { echo "check-pkg: $*" >&2; exit 1; }
bad() { echo "check-pkg: $*" >&2; fail=1; }

[ -e "$PKG" ] || die "$PKG: no such package"
[ -d "$C" ] || die "$PKG is not a bundle package (no Contents directory)"

case "$(basename "$PKG")" in
tsppc-*.pkg) VERSION=$(basename "$PKG" .pkg); VERSION=${VERSION#tsppc-} ;;
*) die "$PKG: the name must be tsppc-<version>.pkg" ;;
esac

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tsppcpkg.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$tmp"' EXIT

# The bundle layout.
for f in Info.plist PkgInfo Archive.pax.gz Archive.bom \
         Resources/preflight Resources/postflight Resources/ReadMe.txt \
         Resources/License.txt Resources/English.lproj/Description.plist; do
    [ -f "$C/$f" ] || bad "missing Contents/$f"
done
[ "$fail" = 0 ] || exit 1
[ "$(cat "$C/PkgInfo")" = pmkrpkg1 ] || bad "Contents/PkgInfo is not pmkrpkg1"

# plist_value <file> <key>: the line after <key>key</key>, trimmed.
plist_value() {
    awk -v k="<key>$2</key>" '
        found { sub(/^[ \t]+/, ""); sub(/[ \t]+$/, ""); print; exit }
        { line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line); if (line == k) found = 1 }
    ' "$1"
}

# Info.plist: every key the package needs, with its exact value.
INFO=$C/Info.plist
while read -r key want; do
    got=$(plist_value "$INFO" "$key")
    [ "$got" = "$want" ] || bad "Info.plist $key is \"$got\", want \"$want\""
done <<EOF
CFBundleIdentifier <string>com.github.ajthom90.tsppc.pkg</string>
CFBundleShortVersionString <string>$VERSION</string>
IFPkgFlagAuthorizationAction <string>RootAuthorization</string>
IFPkgFlagDefaultLocation <string>/</string>
IFPkgFlagRelocatable <false/>
IFPkgFlagRestartAction <string>None</string>
IFPkgFlagRootVolumeOnly <true/>
IFPkgFlagOverwritePermissions <true/>
IFPkgFlagFollowLinks <false/>
IFPkgFormatVersion <real>0.1</real>
EOF
if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$INFO" >/dev/null 2>&1 || bad "Info.plist does not parse"
    plutil -lint "$R/English.lproj/Description.plist" >/dev/null 2>&1 || bad "Description.plist does not parse"
fi

# The payload. Every path, with its type, permission bits, uid and gid
# (0 = root or wheel, 80 = admin). Existing system directories (/, /Library,
# /Applications, /usr, /Library/LaunchDaemons) carry the owner and mode they
# already have on 10.4 and 10.5: with IFPkgFlagOverwritePermissions true,
# Installer applies these to existing directories, so they must be the
# system's own values.
cat >"$tmp/want" <<'EOF'
. d 1775 0 80
./Applications d 775 0 80
./Applications/tsppc.app d 775 0 80
./Applications/tsppc.app/Contents d 775 0 80
./Applications/tsppc.app/Contents/Info.plist f 644 0 80
./Applications/tsppc.app/Contents/MacOS d 775 0 80
./Applications/tsppc.app/Contents/MacOS/tsppc f 755 0 80
./Applications/tsppc.app/Contents/PkgInfo f 644 0 80
./Library d 1775 0 80
./Library/Extensions d 755 0 0
./Library/Extensions/tsppc-tun.kext d 755 0 0
./Library/Extensions/tsppc-tun.kext/Contents d 755 0 0
./Library/Extensions/tsppc-tun.kext/Contents/Info.plist f 644 0 0
./Library/Extensions/tsppc-tun.kext/Contents/MacOS d 755 0 0
./Library/Extensions/tsppc-tun.kext/Contents/MacOS/tun f 644 0 0
./Library/LaunchDaemons d 755 0 0
./Library/LaunchDaemons/com.github.ajthom90.tsppcd.plist f 644 0 0
./usr d 755 0 0
./usr/local d 755 0 0
./usr/local/bin d 755 0 0
./usr/local/bin/tsppc f 755 0 0
./usr/local/sbin d 755 0 0
./usr/local/sbin/tsppc-uninstall f 755 0 0
./usr/local/sbin/tsppcd f 755 0 0
EOF
sort "$tmp/want" >"$tmp/want.s"

# From the bom: lsbom prints the mode as octal with the file type bits
# (40755, 100644) and the owner as uid/gid.
lsbom -p fmug "$C/Archive.bom" >"$tmp/bom.raw" 2>"$tmp/err" || { cat "$tmp/err" >&2; die "lsbom failed"; }
awk -F '\t' '
    {
        m = $2; t = "?"
        if (length(m) == 5 && m ~ /^4/) { t = "d"; m = substr(m, 2) }
        else if (length(m) == 6 && m ~ /^10/) { t = "f"; m = substr(m, 3) }
        sub(/^0+/, "", m); if (m == "") m = "0"
        print $1, t, m, $3, $4
    }' "$tmp/bom.raw" | sort >"$tmp/bom.s"
if ! cmp -s "$tmp/want.s" "$tmp/bom.s"; then
    bad "the bom differs from the expected payload (< expected, > bom):"
    diff "$tmp/want.s" "$tmp/bom.s" | grep '^[<>]' >&2
fi

# From the archive: pax -v prints ls -l style lines. The permission string is
# turned back into octal; the owner and group names into ids.
gzip -dc "$C/Archive.pax.gz" >"$tmp/archive.cpio" 2>"$tmp/err" || { cat "$tmp/err" >&2; die "Archive.pax.gz does not decompress"; }
(cd "$tmp" && pax -v -f archive.cpio) >"$tmp/pax.raw" 2>"$tmp/err" || { cat "$tmp/err" >&2; die "pax cannot list the archive"; }
awk '
    function bits(s, i,   c, v) {
        v = 0
        c = substr(s, i, 1); if (c == "r") v += 4
        c = substr(s, i + 1, 1); if (c == "w") v += 2
        c = substr(s, i + 2, 1); if (c == "x" || c == "s" || c == "t") v += 1
        return v
    }
    function id(n) {
        if (n == "root" || n == "wheel" || n == "0") return 0
        if (n == "admin" || n == "80") return 80
        return n
    }
    # Only entry lines: Tiger pax ends the listing with a summary line.
    length($1) == 10 && $1 ~ /^[-a-z][-rwxsStT]+$/ {
        p = $1; t = substr(p, 1, 1)
        if (t == "-") t = "f"
        sp = 0
        if (substr(p, 10, 1) == "t" || substr(p, 10, 1) == "T") sp = 1
        m = (sp ? sp : "") bits(p, 2) bits(p, 5) bits(p, 8)
        name = $NF
        print name, t, m, id($3), id($4)
    }' "$tmp/pax.raw" | sort >"$tmp/pax.s"
if ! cmp -s "$tmp/want.s" "$tmp/pax.s"; then
    bad "the archive differs from the expected payload (< expected, > archive):"
    diff "$tmp/want.s" "$tmp/pax.s" | grep '^[<>]' >&2
fi

# The LaunchDaemon plist, as the payload carries it: exactly the four keys
# Tiger's launchd understands, with their values.
mkdir "$tmp/x" || die "mkdir failed"
(cd "$tmp/x" && pax -r -f ../archive.cpio "$PLIST_PATH") 2>"$tmp/err" || { cat "$tmp/err" >&2; die "cannot extract $PLIST_PATH"; }
LD=$tmp/x/$PLIST_PATH
if [ ! -f "$LD" ]; then
    bad "$PLIST_PATH missing from the archive"
else
    keys=$(awk '{ s = $0; if (sub(/^[ \t]*<key>/, "", s) && sub(/<\/key>[ \t]*$/, "", s)) print s }' "$LD" | sort | tr '\n' ' ')
    [ "$keys" = "Label OnDemand ProgramArguments RunAtLoad " ] || bad "the launchd plist keys are \"$keys\", want exactly Label OnDemand ProgramArguments RunAtLoad"
    [ "$(grep -c '<key>' "$LD")" = 4 ] || bad "the launchd plist has other than 4 <key> lines"
    [ "$(plist_value "$LD" Label)" = "<string>$LABEL</string>" ] || bad "launchd Label is not $LABEL"
    [ "$(plist_value "$LD" RunAtLoad)" = "<true/>" ] || bad "launchd RunAtLoad is not true"
    [ "$(plist_value "$LD" OnDemand)" = "<false/>" ] || bad "launchd OnDemand is not false"
    args=$(awk '/<key>ProgramArguments<\/key>/ { on = 1; next }
                on && /<\/array>/ { exit }
                on && /<string>/ { s = $0; sub(/^[ \t]*<string>/, "", s); sub(/<\/string>[ \t]*$/, "", s); printf "%s|", s }' "$LD")
    [ "$args" = "/usr/local/sbin/tsppcd|-l|/var/log/tsppcd.log|" ] || bad "launchd ProgramArguments are \"$args\""
    if command -v plutil >/dev/null 2>&1; then
        plutil -lint "$LD" >/dev/null 2>&1 || bad "the launchd plist does not parse"
    fi
fi

# The scripts: executable, and valid sh.
for s in preflight postflight; do
    [ -x "$R/$s" ] || bad "Resources/$s is not executable"
    head -1 "$R/$s" | grep -q '^#!/bin/sh' || bad "Resources/$s does not start with #!/bin/sh"
    sh -n "$R/$s" || bad "Resources/$s has a syntax error"
done

# The ReadMe says plainly that tsppc is unofficial; the licence carries all
# three notices.
grep -F -q "$NOTICE" "$R/ReadMe.txt" || bad "ReadMe.txt lacks the not-affiliated sentence"
grep -F -q 'BSD 3-Clause License' "$R/License.txt" || bad "License.txt lacks the tsppc licence"
grep -F -q 'Mattias Nissler' "$R/License.txt" || bad "License.txt lacks the tuntaposx notice"
grep -F -q 'Thomas Pornin' "$R/License.txt" || bad "License.txt lacks the BearSSL notice"
grep -F -q 'not affiliated with or endorsed by Tailscale Inc.' "$R/English.lproj/Description.plist" ||
    bad "Description.plist lacks the not-affiliated sentence"

if [ "$fail" != 0 ]; then
    echo "check-pkg: $PKG FAILED" >&2
    exit 1
fi
echo "check-pkg: $PKG ok ($(wc -l <"$tmp/want.s" | tr -d ' ') payload paths, version $VERSION)"
