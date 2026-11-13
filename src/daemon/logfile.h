/* The daemon's log file (tsppcd -l <path>): stderr is pointed at an
 * append-only file that is rotated once, by size. launchd starts the daemon
 * with -l, so the daemon caps its own log. */
#ifndef TS_LOGFILE_H
#define TS_LOGFILE_H

#include <stddef.h>

#define TS_LOG_MAX (1024 * 1024)

/* Open path (O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW, mode 0644) and dup2 it
 * onto STDERR_FILENO. Anything that is not a regular file is refused. 0, or
 * -1 with a message in err (cap bytes). */
int ts_logfile_open(const char *path, char *err, size_t cap);

/* When a file is open and has reached TS_LOG_MAX bytes: rename it to
 * <path>.1 (replacing an old one) and open a new file the same way. Does
 * nothing when no file is open. Call it after each log line. */
void ts_logfile_check(void);

#endif
