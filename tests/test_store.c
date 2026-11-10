#include "harness.h"

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/crypto/blake2s.h"
#include "../src/proto/json.h"
#include "../src/state/hostinfo.h"
#include "../src/state/store.h"

static char ROOT[256];

static int nonzero(const uint8_t *k)
{
    size_t i;
    for (i = 0; i < 32; i++) if (k[i]) return 1;
    return 0;
}

static int count_entries(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int n = 0;
    if (!d) return -1;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    closedir(d);
    return n;
}

static void path_in(char *out, size_t cap, const char *a, const char *b)
{
    snprintf(out, cap, "%s/%s", a, b);
}

static void rm_tree(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char p[512];
    if (!d) return;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        path_in(p, sizeof p, dir, e->d_name);
        unlink(p);
    }
    closedir(d);
    rmdir(dir);
}

static void write_file(const char *path, const uint8_t *b, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        if (n) (void)!write(fd, b, n);
        close(fd);
    }
}

static size_t read_file(const char *path, uint8_t *b, size_t cap)
{
    int fd = open(path, O_RDONLY);
    ssize_t r;
    if (fd < 0) return 0;
    r = read(fd, b, cap);
    close(fd);
    return r < 0 ? 0 : (size_t)r;
}

static void test_create_load(void)
{
    char dir[320], file[400], err[160];
    ts_state a, b;
    struct stat st;
    uint8_t raw[512];
    size_t n;

    snprintf(dir, sizeof dir, "%s/s1", ROOT);
    memset(&a, 0, sizeof a);
    t_true("store: create ok", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    t_true("store: machine/node/disco nonzero",
           nonzero(a.machine_priv) && nonzero(a.node_priv) && nonzero(a.disco_priv));
    t_true("store: three distinct keys",
           memcmp(a.machine_priv, a.node_priv, 32) && memcmp(a.machine_priv, a.disco_priv, 32) &&
           memcmp(a.node_priv, a.disco_priv, 32));
    t_true("store: no old node key", !a.have_old_node && !nonzero(a.old_node_priv));
    t_true("store: not logged in", !a.have_login);
    t_true("store: keys clamped",
           (a.machine_priv[0] & 7) == 0 && (a.machine_priv[31] & 0x80) == 0 && (a.machine_priv[31] & 0x40) &&
           (a.node_priv[0] & 7) == 0 && (a.disco_priv[0] & 7) == 0);

    t_true("store: dir exists", stat(dir, &st) == 0 && S_ISDIR(st.st_mode));
    t_true("store: dir mode 0700", (st.st_mode & 0777) == 0700);
    t_true("store: dir owner", st.st_uid == geteuid());
    path_in(file, sizeof file, dir, TS_STATE_FILE);
    t_true("store: file exists", stat(file, &st) == 0 && S_ISREG(st.st_mode));
    t_true("store: file mode 0600", (st.st_mode & 0777) == 0600);
    t_true("store: file owner", st.st_uid == geteuid());
    t_true("store: no temp file left", count_entries(dir) == 1);

    memset(&b, 0, sizeof b);
    t_true("store: load ok", ts_state_load_or_create(&b, dir, err, sizeof err) == 0);
    t_true("store: same keys", !memcmp(a.machine_priv, b.machine_priv, 32) &&
           !memcmp(a.node_priv, b.node_priv, 32) && !memcmp(a.disco_priv, b.disco_priv, 32));

    /* Round trip of the flags and old key. */
    memcpy(b.old_node_priv, a.machine_priv, 32);
    b.have_old_node = 1;
    b.have_login = 1;
    t_true("store: save ok", ts_state_save(&b, dir, err, sizeof err) == 0);
    t_true("store: save leaves no temp", count_entries(dir) == 1);
    memset(&a, 0, sizeof a);
    t_true("store: reload ok", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    t_true("store: flags and old key round-trip",
           a.have_old_node == 1 && a.have_login == 1 && !memcmp(a.old_node_priv, b.old_node_priv, 32) &&
           !memcmp(a.node_priv, b.node_priv, 32));

    /* Format: magic, big-endian version. */
    n = read_file(file, raw, sizeof raw);
    t_true("store: file size", n == TS_STATE_FILE_LEN);
    t_true("store: magic", n >= 4 && !memcmp(raw, "TSPS", 4));
    t_true("store: version bytes", n >= 6 && raw[4] == 0 && raw[5] == 1);
    rm_tree(dir);
}

static void test_corrupt(void)
{
    char dir[320], file[400], err[160];
    ts_state a, b;
    uint8_t raw[512], orig[512];
    size_t n, i;

    snprintf(dir, sizeof dir, "%s/s2", ROOT);
    t_true("corrupt: create", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    path_in(file, sizeof file, dir, TS_STATE_FILE);
    n = read_file(file, orig, sizeof orig);
    t_true("corrupt: have file", n == TS_STATE_FILE_LEN);

    /* Truncated at several lengths. */
    for (i = 0; i < 4; i++) {
        static const size_t cuts[4] = { 0, 1, 100, TS_STATE_FILE_LEN - 1 };
        size_t m;
        write_file(file, orig, cuts[i]);
        memset(&b, 0x55, sizeof b);
        t_true("corrupt: truncated rejected", ts_state_load_or_create(&b, dir, err, sizeof err) != 0);
        t_true("corrupt: error text", err[0] != 0);
        t_true("corrupt: out zeroed", !nonzero(b.machine_priv) && !nonzero(b.node_priv));
        m = read_file(file, raw, sizeof raw);
        t_true("corrupt: truncated file not overwritten", m == cuts[i] && !memcmp(raw, orig, m));
    }

    /* One bit flipped in each region: magic, version, flags, key, checksum. */
    {
        static const size_t at[5] = { 0, 5, 7, 40, TS_STATE_FILE_LEN - 1 };
        for (i = 0; i < 5; i++) {
            memcpy(raw, orig, n);
            raw[at[i]] ^= 0x01;
            write_file(file, raw, n);
            t_true("corrupt: bit flip rejected", ts_state_load_or_create(&b, dir, err, sizeof err) != 0);
            {
                uint8_t chk[512];
                size_t m = read_file(file, chk, sizeof chk);
                t_true("corrupt: flipped file not overwritten", m == n && !memcmp(chk, raw, n));
            }
        }
    }

    /* Unknown version with a valid checksum is still an error, and save refuses nothing here. */
    t_true("corrupt: trailing garbage rejected",
           (memcpy(raw, orig, n), raw[n] = 0, write_file(file, raw, n + 1),
            ts_state_load_or_create(&b, dir, err, sizeof err) != 0));
    rm_tree(dir);
}

static void test_perms(void)
{
    char dir[320], file[400], link[400], err[160];
    ts_state a;
    uint8_t orig[512];
    size_t n;

    /* Loose directory mode. */
    snprintf(dir, sizeof dir, "%s/s3", ROOT);
    t_true("perms: create", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    chmod(dir, 0750);
    t_true("perms: group-readable dir refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("perms: message names the problem", strstr(err, "mode") != NULL);
    t_true("perms: save refused too", ts_state_save(&a, dir, err, sizeof err) != 0);
    chmod(dir, 0705);
    t_true("perms: world-accessible dir refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    chmod(dir, 0700);

    /* Loose file mode. */
    path_in(file, sizeof file, dir, TS_STATE_FILE);
    chmod(file, 0644);
    t_true("perms: world-readable file refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("perms: file message", strstr(err, "mode") != NULL);
    chmod(file, 0600);
    t_true("perms: fixed file loads", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);

    /* Symlinked state file. */
    n = read_file(file, orig, sizeof orig);
    path_in(link, sizeof link, dir, "real");
    rename(file, link);
    t_true("perms: symlink made", symlink("real", file) == 0);
    t_true("perms: symlinked file refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("perms: symlink message", strstr(err, "symbolic") != NULL);
    unlink(file);
    rename(link, file);
    (void)n;
    rm_tree(dir);

    /* Symlinked directory. */
    snprintf(dir, sizeof dir, "%s/s4", ROOT);
    snprintf(link, sizeof link, "%s/s4real", ROOT);
    mkdir(link, 0700);
    t_true("perms: dir symlink made", symlink("s4real", dir) == 0);
    t_true("perms: symlinked dir refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("perms: dir symlink message", strstr(err, "symbolic") != NULL);
    t_true("perms: nothing created in target", count_entries(link) == 0);
    unlink(dir);
    rmdir(link);

    /* Not a directory. */
    snprintf(dir, sizeof dir, "%s/s5", ROOT);
    write_file(dir, (const uint8_t *)"x", 1);
    t_true("perms: plain file as dir refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    unlink(dir);

    /* Missing parent. */
    snprintf(dir, sizeof dir, "%s/nope/s6", ROOT);
    t_true("perms: missing parent refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("perms: err cap zero is safe", ts_state_load_or_create(&a, dir, NULL, 0) != 0);
}

static void test_umask(void)
{
    char dir[320], err[160];
    ts_state a;
    struct stat st;
    mode_t old = umask(077);
    snprintf(dir, sizeof dir, "%s/s7", ROOT);
    t_true("umask: create", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    t_true("umask: dir still 0700", stat(dir, &st) == 0 && (st.st_mode & 0777) == 0700);
    umask(old);
    rm_tree(dir);
}

static void test_parse(void)
{
    ts_state a, b;
    uint8_t buf[TS_STATE_FILE_LEN];
    uint8_t bad[TS_STATE_FILE_LEN];
    size_t i;

    memset(&a, 0, sizeof a);
    for (i = 0; i < 32; i++) {
        a.machine_priv[i] = (uint8_t)(1 + i);
        a.node_priv[i] = (uint8_t)(50 + i);
        a.disco_priv[i] = (uint8_t)(90 + i);
    }
    ts_state_encode(buf, &a);
    memset(&b, 0, sizeof b);
    t_true("parse: round trip", ts_state_parse(&b, buf, sizeof buf) == 0 &&
           !memcmp(b.node_priv, a.node_priv, 32) && !b.have_old_node);

    /* Structurally invalid but correctly checksummed images are rejected. */
    memcpy(bad, buf, sizeof buf);
    bad[7] |= 0x80;
    ts_blake2s(bad + 136, bad, 136);
    t_true("parse: reserved flag rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
    memcpy(bad, buf, sizeof buf);
    bad[80] = 1;
    ts_blake2s(bad + 136, bad, 136);
    t_true("parse: old key without flag rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
    memcpy(bad, buf, sizeof buf);
    bad[5] = 2;
    ts_blake2s(bad + 136, bad, 136);
    t_true("parse: unknown version rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
    t_true("parse: failure zeroes output", !nonzero(b.machine_priv) && !nonzero(b.node_priv) && !b.have_login);
    t_true("parse: short", ts_state_parse(&b, buf, sizeof buf - 1) != 0);
    t_true("parse: empty", ts_state_parse(&b, buf, 0) != 0);
}

static int find_str(const char *json, const char *key, char *out, size_t cap)
{
    ts_json j;
    ts_json_tok t, v;
    int depth_ok = 0;
    ts_json_init(&j, json, strlen(json));
    if (ts_json_next(&j, &t) != TS_JSON_OBJ_START) return -1;
    for (;;) {
        ts_json_type ty = ts_json_next(&j, &t);
        if (ty == TS_JSON_OBJ_END) break;
        if (ty != TS_JSON_KEY) return -1;
        if (ts_json_next(&j, &v) != TS_JSON_STRING) return -1;
        depth_ok = 1;
        if (strlen(key) == t.rawlen && !memcmp(key, t.raw, t.rawlen)) {
            return ts_json_string(out, cap, &v) >= 0 ? 0 : -1;
        }
    }
    (void)depth_ok;
    return -1;
}

static void test_hostinfo(void)
{
    char out[512], v[128];
    ts_json j;
    ts_json_tok t;
    int n;
    ts_json_type ty;
    char host[256];

    n = ts_hostinfo_json(out, sizeof out);
    t_true("hostinfo: produced", n > 0 && (size_t)n == strlen(out));
    ts_json_init(&j, out, strlen(out));
    while ((ty = ts_json_next(&j, &t)) != TS_JSON_END && ty != TS_JSON_ERROR) {}
    t_true("hostinfo: valid JSON", ty == TS_JSON_END);
    t_true("hostinfo: OS", find_str(out, "OS", v, sizeof v) == 0 && !strcmp(v, "macOS"));
#if defined(__ppc__)
    t_true("hostinfo: GoArch", find_str(out, "GoArch", v, sizeof v) == 0 && !strcmp(v, "ppc"));
#elif defined(__i386__)
    t_true("hostinfo: GoArch", find_str(out, "GoArch", v, sizeof v) == 0 && !strcmp(v, "386"));
#elif defined(__x86_64__)
    t_true("hostinfo: GoArch", find_str(out, "GoArch", v, sizeof v) == 0 && !strcmp(v, "amd64"));
#elif defined(__aarch64__) || defined(__arm64__)
    t_true("hostinfo: GoArch", find_str(out, "GoArch", v, sizeof v) == 0 && !strcmp(v, "arm64"));
#endif
    t_true("hostinfo: IPNVersion",
           find_str(out, "IPNVersion", v, sizeof v) == 0 && !strcmp(v, "0.1.0-ppc"));
    t_true("hostinfo: OSVersion digits and dots",
           find_str(out, "OSVersion", v, sizeof v) == 0 && ts_hostinfo_version_ok(v));
    t_true("hostinfo: Hostname short",
           find_str(out, "Hostname", v, sizeof v) == 0 && v[0] != 0 && !strchr(v, '.'));
    if (gethostname(host, sizeof host) == 0 && host[0] && host[0] != '.') {
        char *dot = strchr(host, '.');
        if (dot) *dot = 0;
        if (strchr(host, '"') == NULL && strchr(host, '\\') == NULL)
            t_true("hostinfo: Hostname matches", !strcmp(v, host));
    }
    t_true("hostinfo: too small fails", ts_hostinfo_json(out, 20) == -1);
    t_true("hostinfo: cap 0 fails", ts_hostinfo_json(out, 0) == -1);

    t_true("version_ok: 10.5.8", ts_hostinfo_version_ok("10.5.8"));
    t_true("version_ok: 15.1", ts_hostinfo_version_ok("15.1"));
    t_true("version_ok: empty", !ts_hostinfo_version_ok(""));
    t_true("version_ok: letters", !ts_hostinfo_version_ok("10.5a"));
    t_true("version_ok: leading dot", !ts_hostinfo_version_ok(".5"));
    t_true("version_ok: space", !ts_hostinfo_version_ok("10 5"));
    t_true("version_ok: quote", !ts_hostinfo_version_ok("10\".5"));
    t_true("version_ok: too long", !ts_hostinfo_version_ok("1234567890123456789012345678901234567890"));
}

void test_store(void)
{
    const char *base = getenv("TMPDIR");
    char tmpl[256];
    char *r;
    snprintf(tmpl, sizeof tmpl, "%s/tsppc-store-XXXXXX", base && base[0] ? base : "/tmp");
    r = mkdtemp(tmpl);
    if (!r) { t_true("store: temp dir", 0); return; }
    snprintf(ROOT, sizeof ROOT, "%s", r);
    test_create_load();
    test_corrupt();
    test_perms();
    test_umask();
    test_parse();
    test_hostinfo();
    rm_tree(ROOT);
}
