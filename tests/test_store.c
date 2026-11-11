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

static int clamped(const uint8_t *k)
{
    return (k[0] & 7) == 0 && (k[31] & 0x80) == 0 && (k[31] & 0x40) != 0;
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
           clamped(a.machine_priv) && clamped(a.node_priv) && clamped(a.disco_priv));

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

    /* A valid image followed by an extra byte is rejected, and left alone. */
    memcpy(raw, orig, n);
    raw[n] = 0;
    write_file(file, raw, n + 1);
    t_true("corrupt: trailing byte rejected", ts_state_load_or_create(&b, dir, err, sizeof err) != 0);
    {
        uint8_t chk[512];
        size_t m = read_file(file, chk, sizeof chk);
        t_true("corrupt: trailing-byte file unchanged", m == n + 1 && !memcmp(chk, raw, n + 1));
    }
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

static void test_stale_and_fifo(void)
{
    char dir[320], p[400], err[160];
    ts_state a;
    snprintf(dir, sizeof dir, "%s/s8", ROOT);
    t_true("stale: create", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    path_in(p, sizeof p, dir, ".state.AbCdEf");
    write_file(p, (const uint8_t *)"junk", 4);
    path_in(p, sizeof p, dir, "other");
    write_file(p, (const uint8_t *)"keep", 4);
    t_true("stale: load ok", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    t_true("stale: temp removed, others kept", count_entries(dir) == 2);
    unlink(p);
    path_in(p, sizeof p, dir, TS_STATE_FILE);
    unlink(p);
    t_true("fifo: made", mkfifo(p, 0600) == 0);
    t_true("fifo: refused without blocking", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("fifo: message", strstr(err, "regular") != NULL);
    unlink(p);
    rm_tree(dir);
}

/* Needs root: chown to another user. */
static void test_wrong_owner(void)
{
    char dir[320], file[400], err[160];
    ts_state a;
    if (geteuid() != 0) {
        printf("SKIP: wrong-owner tests need root\n");
        return;
    }
    snprintf(dir, sizeof dir, "%s/s9", ROOT);
    path_in(file, sizeof file, dir, TS_STATE_FILE);
    t_true("owner: create", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    t_true("owner: chown dir", chown(dir, (uid_t)-2, (gid_t)-1) == 0);
    t_true("owner: wrong-owner dir refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("owner: dir message", strstr(err, "wrong user") != NULL);
    t_true("owner: save refused", ts_state_save(&a, dir, err, sizeof err) != 0);
    t_true("owner: chown dir back", chown(dir, geteuid(), (gid_t)-1) == 0);
    t_true("owner: chown file", chown(file, (uid_t)-2, (gid_t)-1) == 0);
    t_true("owner: wrong-owner file refused", ts_state_load_or_create(&a, dir, err, sizeof err) != 0);
    t_true("owner: file message", strstr(err, "wrong user") != NULL);
    rm_tree(dir);
}

static void test_umask(void)
{
    char dir[320], err[160];
    ts_state a;
    struct stat st;
    mode_t old = umask(0277);   /* strips the owner bits: mkdir alone would give 0400 */
    snprintf(dir, sizeof dir, "%s/s7", ROOT);
    t_true("umask: create", ts_state_load_or_create(&a, dir, err, sizeof err) == 0);
    t_true("umask: dir fixed to 0700", stat(dir, &st) == 0 && (st.st_mode & 0777) == 0700);
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
    /* logout_pending (bit 2) round-trips, and never with have_login. */
    a.logout_pending = 1;
    ts_state_encode(buf, &a);
    t_true("parse: logout_pending flag is bit 2", buf[7] == 4);
    t_true("parse: logout_pending round trip", ts_state_parse(&b, buf, sizeof buf) == 0 && b.logout_pending == 1 &&
           !b.have_login);
    memcpy(bad, buf, sizeof buf);
    bad[7] |= 2;
    ts_blake2s(bad + 136, bad, 136);
    t_true("parse: logout_pending with have_login rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
    memcpy(bad, buf, sizeof buf);
    bad[7] |= 8;
    ts_blake2s(bad + 136, bad, 136);
    t_true("parse: down with logout_pending rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
    a.logout_pending = 0;
    ts_state_encode(buf, &a);
    t_true("parse: failure zeroes output", !nonzero(b.machine_priv) && !nonzero(b.node_priv) && !b.have_login);
    t_true("parse: short", ts_state_parse(&b, buf, sizeof buf - 1) != 0);
    t_true("parse: empty", ts_state_parse(&b, buf, 0) != 0);
}

/* A state file written by the control-session build (version 1, have_login),
 * before down existed. Invented keys: machine 0x20.., node 0x60.., disco
 * 0xa0.., each clamped. Files like it are on real nodes and must keep loading. */
static const uint8_t V1_LOGGED_IN[TS_STATE_FILE_LEN] = {
    0x54, 0x53, 0x50, 0x53, 0x00, 0x01, 0x00, 0x02, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x7f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
    0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xa1, 0xa2, 0xa3,
    0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    0xbc, 0xbd, 0xbe, 0x7f, 0xf2, 0x33, 0xa1, 0x1e, 0xb2, 0x99, 0x88, 0x99,
    0xb3, 0xbf, 0x4c, 0x8f, 0x15, 0xc2, 0xfe, 0xc3, 0x0a, 0x77, 0xec, 0x1f,
    0xf4, 0x69, 0xea, 0x44, 0x62, 0x7b, 0xae, 0xf1, 0xc5, 0x3f, 0x39, 0xfb,
};

static void test_store_v1_fixture_loads(void)
{
    ts_state s;
    uint8_t want[32], enc[TS_STATE_FILE_LEN];
    size_t i;
    int keys_ok = 1;

    t_true("v1 fixture: parses", ts_state_parse(&s, V1_LOGGED_IN, sizeof V1_LOGGED_IN) == 0);
    t_true("v1 fixture: logged in, not down", s.have_login == 1 && s.down == 0 && !s.logout_pending &&
           !s.have_old_node);
    for (i = 0; i < 32; i++) want[i] = (uint8_t)(0x20 + i);
    ts_state_clamp_key(want);
    keys_ok &= !memcmp(s.machine_priv, want, 32);
    for (i = 0; i < 32; i++) want[i] = (uint8_t)(0x60 + i);
    ts_state_clamp_key(want);
    keys_ok &= !memcmp(s.node_priv, want, 32);
    for (i = 0; i < 32; i++) want[i] = (uint8_t)(0xa0 + i);
    ts_state_clamp_key(want);
    keys_ok &= !memcmp(s.disco_priv, want, 32);
    t_true("v1 fixture: same keys", keys_ok && !nonzero(s.old_node_priv));
    ts_state_encode(enc, &s);
    t_true("v1 fixture: re-encodes byte for byte", !memcmp(enc, V1_LOGGED_IN, sizeof enc));
}

static void test_store_down_roundtrip(void)
{
    ts_state a, b;
    uint8_t buf[TS_STATE_FILE_LEN], bad[TS_STATE_FILE_LEN];
    size_t i;

    memset(&a, 0, sizeof a);
    for (i = 0; i < 32; i++) {
        a.machine_priv[i] = (uint8_t)(3 + i);
        a.node_priv[i] = (uint8_t)(40 + i);
        a.disco_priv[i] = (uint8_t)(120 + i);
    }
    a.have_login = 1;
    a.down = 1;
    ts_state_encode(buf, &a);
    t_true("down: flag is bit 3", buf[6] == 0 && buf[7] == (2 | 8));
    t_true("down: version stays 1", buf[4] == 0 && buf[5] == 1);
    memset(&b, 0, sizeof b);
    t_true("down: round trip", ts_state_parse(&b, buf, sizeof buf) == 0 && b.down == 1 && b.have_login == 1 &&
           !memcmp(b.node_priv, a.node_priv, 32));

    /* down without have_login is rejected. */
    memcpy(bad, buf, sizeof buf);
    bad[7] = 8;
    ts_blake2s(bad + 136, bad, 136);
    t_true("down: without have_login rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
    /* Bit 4 (and the rest) stay reserved. */
    memcpy(bad, buf, sizeof buf);
    bad[7] |= 16;
    ts_blake2s(bad + 136, bad, 136);
    t_true("down: bit 4 rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
    memcpy(bad, buf, sizeof buf);
    bad[6] |= 0x01;
    ts_blake2s(bad + 136, bad, 136);
    t_true("down: bit 8 rejected", ts_state_parse(&b, bad, sizeof bad) != 0);
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

static void test_osversion_helpers(void)
{
    char v[32];
    t_true("map: 8.11.0", ts_hostinfo_map_darwin("8.11.0", v, sizeof v) == 0 && !strcmp(v, "10.4.11"));
    t_true("map: 9.8.0", ts_hostinfo_map_darwin("9.8.0", v, sizeof v) == 0 && !strcmp(v, "10.5.8"));
    t_true("map: 10.8.0", ts_hostinfo_map_darwin("10.8.0", v, sizeof v) == 0 && !strcmp(v, "10.6.8"));
    t_true("map: 8.0", ts_hostinfo_map_darwin("8.0", v, sizeof v) == 0 && !strcmp(v, "10.4.0"));
    t_true("map: 7.9.0 out of range", ts_hostinfo_map_darwin("7.9.0", v, sizeof v) != 0 && v[0] == 0);
    t_true("map: 11.0.0 out of range", ts_hostinfo_map_darwin("11.0.0", v, sizeof v) != 0);
    t_true("map: junk", ts_hostinfo_map_darwin("9.x", v, sizeof v) != 0);
    t_true("map: empty", ts_hostinfo_map_darwin("", v, sizeof v) != 0);
    t_true("map: trailing junk", ts_hostinfo_map_darwin("9.8.0a", v, sizeof v) != 0);
    t_true("map: huge", ts_hostinfo_map_darwin("99999999999999999999.1", v, sizeof v) != 0);
    t_true("map: small cap", ts_hostinfo_map_darwin("9.8.0", v, 4) != 0);

    {
        const char *plist =
            "<?xml version=\"1.0\"?>\n<dict>\n\t<key>ProductName</key>\n\t<string>Mac OS X</string>\n"
            "\t<key>ProductUserVisibleVersion</key>\n\t<string>10.5.8</string>\n"
            "\t<key>ProductVersion</key>\n\t<string>10.5.8</string>\n</dict>\n";
        t_true("plist: parsed", ts_hostinfo_parse_plist_version(plist, strlen(plist), v, sizeof v) == 0 &&
               !strcmp(v, "10.5.8"));
    }
    {
        const char *p2 = "<key>ProductVersion</key><string>10.4.11</string>";
        t_true("plist: compact", ts_hostinfo_parse_plist_version(p2, strlen(p2), v, sizeof v) == 0 &&
               !strcmp(v, "10.4.11"));
    }
    {
        const char *bad[] = {
            "<key>ProductVersion</key><string>10.x</string>",
            "<key>ProductVersion</key><string>10.5.8",
            "<key>ProductVersion</key><integer>5</integer>",
            "<key>ProductVersion</key><string></string>",
            "<key>ProductVersion</key><string>1234567890123456789012345678901234567890</string>",
            "<key>ProductName</key><string>10.5.8</string>",
            "",
        };
        size_t i;
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
            t_true("plist: bad rejected", ts_hostinfo_parse_plist_version(bad[i], strlen(bad[i]), v, sizeof v) != 0 && v[0] == 0);
    }
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
    test_stale_and_fifo();
    test_wrong_owner();
    test_parse();
    test_store_v1_fixture_loads();
    test_store_down_roundtrip();
    test_osversion_helpers();
    test_hostinfo();
    rm_tree(ROOT);
}
