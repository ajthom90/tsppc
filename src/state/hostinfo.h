#ifndef TS_STATE_HOSTINFO_H
#define TS_STATE_HOSTINFO_H

#include <stddef.h>

#define TS_IPN_VERSION "0.1.0-ppc"

/* GoArch for the compile target: ppc, 386, amd64 or arm64. */
const char *ts_hostinfo_goarch(void);

/* True if s is a non-empty run of digits and dots, starting with a digit, at
 * most 31 characters. */
int ts_hostinfo_version_ok(const char *s);

/* The OS version, tried in order: the output of /usr/bin/sw_vers -productVersion
 * (run without a shell, stdout only, bounded, 5 s deadline, validated);
 * ProductVersion from /System/Library/CoreServices/SystemVersion.plist; the
 * kern.osrelease Darwin release mapped with ts_hostinfo_map_darwin; else "".
 * Always NUL-terminated within cap (cap >= 1). */
void ts_hostinfo_os_version(char *out, size_t cap);

/* Find <key>ProductVersion</key><string>V</string> in a plist image and copy V
 * to out if it is a valid version. Returns 0, or -1 (out is then ""). */
int ts_hostinfo_parse_plist_version(const char *buf, size_t len, char *out, size_t cap);

/* Map a Darwin release M.N[.x] to the Mac OS X version 10.(M-4).N for M from 8
 * to 10 (8.11.0 -> 10.4.11, 9.8.0 -> 10.5.8, 10.8.0 -> 10.6.8). Returns 0, or
 * -1 for anything else (out is then ""). */
int ts_hostinfo_map_darwin(const char *darwin, char *out, size_t cap);

/* Write the Hostinfo JSON object (UTF-8, NUL-terminated) to out. Returns its
 * length, or -1 if it does not fit in cap. */
int ts_hostinfo_json(char *out, size_t cap);

#endif
