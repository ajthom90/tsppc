/* A fake DERP relay for tests that run the real relay client over plain TCP
 * (TSPPC_DERP_PLAIN=1), meant for a child process on a listening socket. It
 * answers the upgrade request with 101 and a ServerKey, opens a ClientInfo
 * box and answers with a sealed ServerInfo, then reads frames until the
 * client closes; one connection at a time. A connection that closes before
 * sending anything is a home probe. The key is made up.
 *
 * Events go to sink->event: 'u' upgraded, 'r' ServerInfo sent, 'P'/'p'
 * NotePreferred 1/0, 'b' a broken ClientInfo, 'e' closed after the upgrade.
 * Every SendPacket body (destination key, then packet) goes to sink->on_send
 * if set, which may answer with fr_frame on fd. The client's public key from
 * each good ClientInfo goes to sink->on_client if set.
 *
 * Needs, before inclusion: <errno.h>, <fcntl.h>, <unistd.h>, <sys/socket.h>,
 * src/core/bytes.h, src/crypto/nacl.h, src/crypto/x25519.h, src/derp/derp.h
 * and src/state/store.h. */

typedef struct {
    void (*event)(void *ctx, char e);
    void (*on_send)(void *ctx, int fd, const uint8_t *body, size_t len);
    void (*on_client)(void *ctx, const uint8_t key[32]);
    void *ctx;
} fr_sink;

static int fr_read_all(int fd, uint8_t *p, size_t n)
{
    while (n) {
        ssize_t k = read(fd, p, n);
        if (k <= 0) return -1;
        p += k;
        n -= (size_t)k;
    }
    return 0;
}

static void fr_write_all(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t k = write(fd, p, n);
        if (k <= 0) return;
        p += k;
        n -= (size_t)k;
    }
}

static void fr_frame(int fd, int type, const uint8_t *body, size_t n)
{
    uint8_t h[5];
    h[0] = (uint8_t)type;
    ts_put_be32(h + 1, (uint32_t)n);
    fr_write_all(fd, h, 5);
    fr_write_all(fd, body, n);
}

static void fr_event(const fr_sink *sink, char e)
{
    if (sink->event) sink->event(sink->ctx, e);
}

static void fr_serve(int fd, const fr_sink *sink, const uint8_t s_priv[32], const uint8_t s_pub[32])
{
    static const char resp[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n"
                               "Connection: Upgrade\r\nDerp-Version: 2\r\n\r\n";
    static uint8_t body[70000];
    char hdr[2048];
    size_t hl = 0;
    uint8_t sk[40], h[5];

    while (hl < sizeof hdr - 1) {
        ssize_t k = read(fd, hdr + hl, 1);
        if (k <= 0) return;   /* a probe: connected, closed */
        hl += (size_t)k;
        if (hl >= 4 && memcmp(hdr + hl - 4, "\r\n\r\n", 4) == 0) break;
    }
    hdr[hl] = 0;
    if (strncmp(hdr, "GET /derp HTTP/1.1\r\n", 20) != 0) return;
    fr_write_all(fd, (const uint8_t *)resp, sizeof resp - 1);
    memcpy(sk, "DERP\xf0\x9f\x94\x91", 8);
    memcpy(sk + 8, s_pub, 32);
    fr_frame(fd, TS_DERP_SERVER_KEY, sk, 40);
    fr_event(sink, 'u');
    for (;;) {
        uint32_t len;
        if (fr_read_all(fd, h, 5) != 0) break;
        len = ts_get_be32(h + 1);
        if (len > sizeof body || fr_read_all(fd, body, len) != 0) break;
        if (h[0] == TS_DERP_CLIENT_INFO) {
            uint8_t json[256], info[24 + 16 + 64], cpub[32];
            static const char sj[] = "{\"version\":2}";
            size_t i;
            if (len < 72 || len - 72 >= sizeof json ||
                ts_box_open(json, body + 32, body, s_priv, body + 56, len - 56) != 0) {
                fr_event(sink, 'b');
                break;
            }
            memcpy(cpub, body, 32);
            if (sink->on_client) sink->on_client(sink->ctx, cpub);
            for (i = 0; i < 24; i++) info[i] = (uint8_t)(0x40 + i);
            ts_box_seal(info + 24, info, cpub, s_priv, (const uint8_t *)sj, sizeof sj - 1);
            fr_frame(fd, TS_DERP_SERVER_INFO, info, 24 + 16 + sizeof sj - 1);
            fr_event(sink, 'r');
        } else if (h[0] == TS_DERP_NOTE_PREFERRED && len == 1) {
            fr_event(sink, body[0] ? 'P' : 'p');
        } else if (h[0] == TS_DERP_SEND_PACKET && sink->on_send) {
            sink->on_send(sink->ctx, fd, body, len);
        }
    }
    fr_event(sink, 'e');
}

/* The child's whole life: serve connections on lfd until the parent goes
 * (or 10 minutes pass). stdout and stderr go to /dev/null. */
static void fr_server(int lfd, const fr_sink *sink)
{
    uint8_t s_priv[32], s_pub[32];
    int i, nul = open("/dev/null", O_RDWR);
    if (nul >= 0) {
        dup2(nul, 1);
        dup2(nul, 2);
        if (nul > 2) close(nul);
    }
    alarm(600);
    for (i = 0; i < 32; i++) s_priv[i] = (uint8_t)(0x31 + 7 * i);   /* made up */
    ts_state_clamp_key(s_priv);
    ts_x25519_public(s_pub, s_priv);
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (getppid() == 1) return;
        fr_serve(fd, sink, s_priv, s_pub);
        close(fd);
    }
}
