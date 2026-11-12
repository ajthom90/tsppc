#ifndef TS_NAMES_HOSTS_H
#define TS_NAMES_HOSTS_H

#include <stddef.h>

#include "../control/netmap.h"

/* The tsppc block of /etc/hosts, without any I/O: build the block from a
 * network map, and merge it into the text of an existing file. */

#define TS_HOSTS_BEGIN "# tsppc begin: peer names from your tailnet, rewritten by tsppcd"
#define TS_HOSTS_END "# tsppc end"
#define TS_HOSTS_FILE_MAX 1048576       /* a larger existing file is refused */
/* TS_MAX_PEERS + 1 entries at the longest line ("a.b.c.d\t" 16 + fqdn 253 + " " +
 * short 63 + "\n" = 334, rounded up to 336), plus both marker lines. */
#define TS_HOSTS_BLOCK_MAX ((TS_MAX_PEERS + 1) * 336 + 160)

/* Validates a node Name from control: one optional trailing dot is removed;
 * 1..253 bytes; dot-separated labels of 1..63 bytes from [A-Za-z0-9-], not
 * starting or ending with '-'. Writes the name lowercased (ASCII only, no
 * trailing dot) to fqdn and its first label to shortname. 0 if valid, -1
 * otherwise (or if a buffer is too small: 254 and 64 bytes always suffice);
 * the buffers are then unspecified. A NUL ends the name (it is a C string). */
int ts_hosts_name_ok(const char *name, char *fqdn, size_t fqdn_cap, char *shortname, size_t short_cap);

/* Writes the whole block: begin line, one line per node (self included) that
 * has an IPv4 address and a valid name of at least two labels,
 * "<a.b.c.d>\t<fqdn> <short>\n" (just the fqdn when the short name is
 * withheld), end line. Sorted by IPv4 then fqdn, so a map gives the same bytes
 * every time. A node with an address and an invalid or single-label name is
 * counted in *nskipped and never written. Short names are written only for
 * nodes whose fqdn minus its first label equals self's (so none without a
 * valid self, and none for nodes shared in from another tailnet), and are
 * withheld when: it is localhost, broadcasthost, wpad, isatap or starts with
 * "ip6-"; more than one such node has it; or it is a host-name token
 * (case-insensitive; the first token of a line is the address and is skipped;
 * '#' starts a comment) of a line of old outside any tsppc section, so the
 * owner's own names are never shadowed. old may be NULL with oldlen 0.
 * Returns the length (not NUL-terminated), or -1 if cap is too small.
 * *nentries counts the lines (either count pointer may be NULL).
 * Uses about 85 KB of stack. */
int ts_hosts_build(char *out, size_t cap, const ts_netmap *nm, const char *old, size_t oldlen, size_t *nentries,
                   size_t *nskipped);

/* Copies old without any tsppc section (a line equal to TS_HOSTS_BEGIN through
 * the next line equal to TS_HOSTS_END, both included; trailing spaces, tabs
 * and '\r' are ignored when comparing; a lone end line goes too) and appends
 * block (when blocklen > 0), first adding '\n' if the kept text is non-empty
 * and lacks a final one. Every other byte is kept. Returns the length; -1 if
 * cap is too small or oldlen > TS_HOSTS_FILE_MAX; -2 if a begin line has no
 * end line after it (the caller must not write: the owner's lines are not
 * ours to guess at). */
int ts_hosts_merge(char *out, size_t cap, const char *old, size_t oldlen, const char *block, size_t blocklen);

#endif
