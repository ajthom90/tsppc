#ifndef TS_STATE_HOSTINFO_H
#define TS_STATE_HOSTINFO_H

#include <stddef.h>

#define TS_IPN_VERSION "0.1.0-ppc"

/* GoArch for the compile target: ppc, 386, amd64 or arm64. */
const char *ts_hostinfo_goarch(void);

/* True if s is a non-empty run of digits and dots, starting with a digit, at
 * most 31 characters. */
int ts_hostinfo_version_ok(const char *s);

/* The OS version: the output of /usr/bin/sw_vers -productVersion (run without
 * a shell, stdout only, bounded and validated), else the kernel release from
 * sysctl kern.osrelease, else "". Always NUL-terminated within cap (cap >= 1). */
void ts_hostinfo_os_version(char *out, size_t cap);

/* Write the Hostinfo JSON object (UTF-8, NUL-terminated) to out. Returns its
 * length, or -1 if it does not fit in cap. */
int ts_hostinfo_json(char *out, size_t cap);

#endif
