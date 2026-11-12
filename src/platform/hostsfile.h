#ifndef TS_PLATFORM_HOSTSFILE_H
#define TS_PLATFORM_HOSTSFILE_H

#include <stddef.h>

/* Reading and atomically replacing the hosts file, and flushing the
 * resolver cache. Only the final path component is checked with lstat: on
 * Mac OS X /etc is itself a symlink to /private/etc. err gets a short reason
 * ("not a regular file", "too large", or the system's error text). */

/* Reads path into buf (not NUL-terminated). lstat first: not a regular file
 * is -1 "not a regular file"; a missing file is 0 with *len = 0; larger than
 * TS_HOSTS_FILE_MAX (or than cap) is -1 "too large". The opened file must be
 * the one lstat saw. 0 or -1. */
int ts_hostsfile_read(const char *path, char *buf, size_t cap, size_t *len, char *err, size_t errcap);

/* Replaces path with buf[0..len): a temp file <dir>/.hosts.tsppc.XXXXXX
 * (mkstemp, same directory), written in full, given the existing file's mode
 * and owner (0644 root:wheel when there was none; the owner only when running
 * as root), fsync'd and renamed over path. path must be missing or a regular
 * file. On any failure the temp file is unlinked and path is untouched.
 * 0 or -1. */
int ts_hostsfile_write(const char *path, const char *buf, size_t len, char *err, size_t errcap);

/* /usr/bin/dscacheutil -flushcache if it is executable (10.5), else
 * /usr/sbin/lookupd -flushcache if executable (10.4), through ts_run (blocks
 * up to TS_RUN_LIMIT_MS). The result is ignored. */
void ts_hostsfile_flush_cache(void);

#endif
