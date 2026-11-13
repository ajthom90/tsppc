#!/bin/sh
# tsppc uninstaller, installed as /usr/local/sbin/tsppc-uninstall.
# Usage: sudo tsppc-uninstall [-y] [--remove-state]
#   -y              do not ask; answer yes to every question
#   --remove-state  also delete /var/db/tsppc (this Mac's node identity)
#
# Stops tsppcd, removes its route and /etc/hosts block (tsppcd --cleanup),
# quits the menu bar app, unloads tsppc's own driver (never another tun
# driver), and removes every installed file, the log and the receipt; itself
# last. Exit 0 when the daemon is gone, no 100.64/10 route points at a tun
# interface and /etc/hosts has no tsppc block; otherwise 1, naming the check.
# Uses only tools on both 10.4 and 10.5.
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

LABEL=com.github.ajthom90.tsppcd
PLIST=/Library/LaunchDaemons/$LABEL.plist
DAEMON=/usr/local/sbin/tsppcd
CLI=/usr/local/bin/tsppc
SELF=/usr/local/sbin/tsppc-uninstall
KEXT=/Library/Extensions/tsppc-tun.kext
KEXT_ID=com.github.ajthom90.tsppc.tun
APP=/Applications/tsppc.app
APP_BIN=$APP/Contents/MacOS/tsppc
LOG=/var/log/tsppcd.log
STATE=/var/db/tsppc
PKG_ID=com.github.ajthom90.tsppc.pkg
HOSTS_BEGIN='# tsppc begin'
WAIT_SEC=30
UNLOAD_TRIES=5

usage() {
    echo "usage: sudo $0 [-y] [--remove-state]" >&2
    exit 2
}

yes=0
remove_state=0
for a in "$@"; do
    case "$a" in
    -y) yes=1 ;;
    --remove-state) remove_state=1 ;;
    *) usage ;;
    esac
done

if [ "$(id -u)" != 0 ]; then
    echo "tsppc-uninstall must run as root: sudo $0" >&2
    exit 1
fi

# ask <question>: 0 for yes. -y answers yes; no answer is no.
ask() {
    [ "$yes" = 1 ] && return 0
    printf '%s [y/N] ' "$1"
    read -r answer || return 1
    case "$answer" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
    esac
}

if ! ask "Remove tsppc?"; then
    echo "Nothing removed."
    exit 1
fi
if [ "$remove_state" = 1 ]; then
    echo "--remove-state deletes $STATE, this Mac's node identity. The node stays"
    echo "in your tailnet's admin console until you remove it there."
    if ! ask "Delete $STATE too?"; then
        echo "Keeping $STATE."
        remove_state=0
    fi
fi

# The pids of processes named exactly tsppcd. Not ps -p: on Tiger it
# succeeds for a pid that is gone.
tsppcd_pids() {
    ps axc -o pid,command | awk 'NR > 1 && $2 == "tsppcd" { printf "%s%s", s, $1; s = " " }'
}

# The pids of the menu bar app at its installed path (not a copy elsewhere).
app_pids() {
    ps axww -o pid,command | awk -v p="$APP_BIN" 'NR > 1 && $2 == p { printf "%s%s", s, $1; s = " " }'
}

# wait_gone <function> <seconds>: wait for it to print nothing.
wait_gone() {
    waited=0
    while :; do
        pids=$($1)
        [ -z "$pids" ] && return 0
        [ "$waited" -ge "$2" ] && return 1
        sleep 1
        waited=$((waited + 1))
    done
}

# 1. Stop the daemon. Nothing is removed while one still runs.
if [ -f "$PLIST" ]; then
    launchctl unload "$PLIST" && echo "Stopped $LABEL." ||
        echo "launchctl unload $PLIST failed; checking for tsppcd anyway" >&2
fi
if ! wait_gone tsppcd_pids "$WAIT_SEC"; then
    echo "tsppcd is still running (pid $(tsppcd_pids)) after ${WAIT_SEC}s." >&2
    echo "Stop it and run tsppc-uninstall again. Nothing was removed." >&2
    exit 1
fi

# 2. The route and /etc/hosts block a crashed daemon may have left.
if [ -x "$DAEMON" ]; then
    "$DAEMON" --cleanup && echo "Removed any leftover tsppc route and /etc/hosts block." ||
        echo "tsppcd --cleanup failed; checked again below" >&2
else
    echo "$DAEMON is missing; cannot run its cleanup; checked again below" >&2
fi

# 3. Quit the menu bar app.
pids=$(app_pids)
if [ -n "$pids" ]; then
    # shellcheck disable=SC2086
    kill -TERM $pids 2>/dev/null
    wait_gone app_pids 5 || echo "$APP is still running (pid $(app_pids))" >&2
    echo "Quit $APP."
fi

# 4. Unload tsppc's own driver, by its bundle ID only.
kext_loaded() {
    kextstat | awk -v id="$KEXT_ID" '$6 == id { f = 1 } END { exit !f }'
}
if kext_loaded; then
    tries=1
    while :; do
        if kextunload -b "$KEXT_ID" >/dev/null 2>&1 || ! kext_loaded; then
            echo "Unloaded $KEXT_ID."
            break
        fi
        if [ "$tries" -ge "$UNLOAD_TRIES" ]; then
            echo "$KEXT_ID is still loaded after $tries tries; it goes away at the next restart." >&2
            break
        fi
        tries=$((tries + 1))
        sleep 1
    done
fi

# 5. The files.
removed() { echo "Removed $1"; }
for f in "$DAEMON" "$CLI" "$PLIST"; do
    if [ -f "$f" ] || [ -L "$f" ]; then rm -f "$f" && removed "$f"; fi
done
if [ -d "$KEXT" ]; then rm -rf "$KEXT" && removed "$KEXT"; fi
if [ -d "$APP" ]; then rm -rf "$APP" && removed "$APP"; fi
for f in "$LOG" "$LOG".*; do
    if [ -f "$f" ]; then rm -f "$f" && removed "$f"; fi
done
for r in /Library/Receipts/tsppc*.pkg; do
    case "$r" in
    /Library/Receipts/tsppc-*.pkg|/Library/Receipts/tsppc.pkg) ;;
    *) continue ;;
    esac
    if [ -e "$r" ]; then rm -rf "$r" && removed "$r (receipt)"; fi
done
if [ -x /usr/sbin/pkgutil ] && /usr/sbin/pkgutil --pkg-info "$PKG_ID" >/dev/null 2>&1; then
    /usr/sbin/pkgutil --forget "$PKG_ID" >/dev/null && removed "the $PKG_ID receipt"
fi
if [ "$remove_state" = 1 ] && [ -d "$STATE" ]; then
    rm -rf "$STATE" && removed "$STATE"
fi

# 6. Itself, last. sh has the script open, so this is safe.
if [ -f "$SELF" ]; then rm -f "$SELF" && removed "$SELF"; fi

# The checks.
failed=0
if [ -n "$(tsppcd_pids)" ]; then
    echo "check failed: tsppcd is running (pid $(tsppcd_pids))" >&2
    failed=1
fi
if netstat -rn -f inet | awk '$1 == "100.64/10" { for (i = 2; i <= NF; i++) if ($i ~ /^tun[0-9]+$/) f = 1 } END { exit !f }'; then
    echo "check failed: the 100.64/10 route still points at a tun interface" >&2
    failed=1
fi
if grep -q "^$HOSTS_BEGIN" /etc/hosts 2>/dev/null; then
    echo "check failed: /etc/hosts still has a tsppc block" >&2
    failed=1
fi
if [ "$failed" != 0 ]; then
    echo "tsppc removed, but the checks above failed."
    exit 1
fi
echo "tsppc removed."
exit 0
