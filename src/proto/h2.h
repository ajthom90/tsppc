#ifndef TS_PROTO_H2_H
#define TS_PROTO_H2_H

#include <stddef.h>
#include <stdint.h>

#include "hpack.h"

/* Sans-I/O HTTP/2 client (RFC 9113) for the control protocol.
 *
 * The caller moves bytes: server bytes go in with ts_h2_feed, and client bytes
 * come out with ts_h2_output and ts_h2_consumed. Bytes may arrive split at any
 * boundary; callbacks and output are the same however the input is split,
 * because DATA is delivered one complete frame at a time.
 *
 * Init queues the preface, a SETTINGS frame (ENABLE_PUSH 0, INITIAL_WINDOW_SIZE
 * TS_H2_WINDOW) and a connection WINDOW_UPDATE that raises the connection
 * receive window to TS_H2_WINDOW. Requests use :scheme https.
 *
 * Errors: every protocol error, including those RFC 9113 calls stream errors,
 * is treated as a connection error (allowed by section 5.4). ts_h2_feed then
 * returns -1, a GOAWAY with the error code is queued if there is room, and the
 * connection is dead: later feeds and requests return -1 and no callback fires
 * again. ts_h2_error gives the code. Unknown frame types and settings are
 * ignored. PUSH_PROMISE is a PROTOCOL_ERROR, since push is disabled.
 *
 * Memory: fixed buffers inside ts_h2, plus one allocation per connection (made
 * by ts_h2_init, released by ts_h2_free) of TS_H2_OUT_MAX + TS_H2_BODY_MAX bytes
 * for the output queue and the unsent request bodies. If it fails the
 * connection starts dead. */

#define TS_H2_MAX_STREAMS 8               /* concurrent streams we open */
#define TS_H2_WINDOW 1048576u             /* our receive window, per stream and per connection */
#define TS_H2_FRAME_MAX 16384             /* largest frame payload we accept (default, not raised) */
#define TS_H2_HBLOCK_MAX 32768            /* encoded HEADERS + CONTINUATION block we accept */
#define TS_H2_HDR_BYTES_MAX 65536         /* decoded name + value bytes in one header block */
#define TS_H2_HDR_FIELDS_MAX 128          /* decoded fields in one header block */
#define TS_H2_REQ_HDR_MAX 16384           /* encoded request header block: one HEADERS frame */
#define TS_H2_BODY_MAX 65536              /* unsent request body bytes, all streams together */
#define TS_H2_OUT_MAX 65536               /* queued output bytes */

/* HTTP/2 error codes (RFC 9113 section 7) used by ts_h2_error and GOAWAY. */
#define TS_H2_NO_ERROR 0x0
#define TS_H2_PROTOCOL_ERROR 0x1
#define TS_H2_INTERNAL_ERROR 0x2
#define TS_H2_FLOW_CONTROL_ERROR 0x3
#define TS_H2_FRAME_SIZE_ERROR 0x6
#define TS_H2_REFUSED_STREAM 0x7
#define TS_H2_CANCEL 0x8
#define TS_H2_COMPRESSION_ERROR 0x9
#define TS_H2_ENHANCE_YOUR_CALM 0xb

/* The end callback's error argument. */
#define TS_H2_END_OK 0          /* complete response (END_STREAM received) */
#define TS_H2_END_RESET 1       /* the server reset the stream (RST_STREAM, any code but REFUSED_STREAM) */
#define TS_H2_END_REFUSED 2     /* not processed by the server, safe to retry: RST_STREAM
                                 * REFUSED_STREAM, or the stream id is above a GOAWAY's last id */

/* Callbacks. Strings are not NUL-terminated; all pointers are valid only during
 * the call. For each response:
 *   - header fires once per regular field of the response header block, in
 *     order. Pseudo-header fields are not passed to it. A block whose :status
 *     is 1xx (informational) is decoded and dropped: no callbacks.
 *   - headers fires once, after the header calls for the final (non-1xx)
 *     response header block, with its :status (200..599).
 *   - data fires once per DATA frame with a non-empty payload, padding removed.
 *     The bytes count against the receive windows until the caller passes them
 *     to ts_h2_consume_data.
 *   - Trailers (a later header block, which must carry END_STREAM) fire header
 *     for each field and do not fire headers again.
 *   - end fires exactly once per stream that was not cancelled with
 *     ts_h2_cancel, last, with a TS_H2_END_* value. The stream is already
 *     released when it fires, so its id is no longer known to the connection.
 *     If the server ends the response before the request body was all sent, the
 *     client sends RST_STREAM NO_ERROR and drops the rest of the body.
 * goaway fires for each GOAWAY received, before end (TS_H2_END_REFUSED) fires
 * for every open stream above last_sid. After a GOAWAY, ts_h2_request fails.
 * No callback fires for a stream id the caller did not open, or after its end.
 *
 * Callbacks may call ts_h2_request, ts_h2_cancel, ts_h2_consume_data, ts_h2_ping,
 * ts_h2_output and ts_h2_consumed, but not ts_h2_feed, ts_h2_init or ts_h2_free.
 * Any member may be NULL. */
typedef struct {
    void (*headers)(void *user, uint32_t sid, int status);
    void (*header)(void *user, uint32_t sid, const char *n, size_t nl, const char *v, size_t vl);
    void (*data)(void *user, uint32_t sid, const uint8_t *d, size_t n);
    void (*end)(void *user, uint32_t sid, int error);
    void (*goaway)(void *user, uint32_t last_sid, uint32_t code);
} ts_h2_cbs;

/* One open stream. Treat as opaque outside tests. */
typedef struct {
    uint32_t id;              /* 0: slot free */
    int64_t send_win;         /* may be negative after INITIAL_WINDOW_SIZE shrinks */
    int64_t recv_win;         /* what the server may still send us */
    uint32_t held;            /* delivered, not yet consumed by the caller */
    uint32_t credit;          /* consumed or padding, not yet returned with WINDOW_UPDATE */
    uint32_t body_off, body_len, body_sent;   /* unsent body, in the body area */
    uint8_t local_done;       /* END_STREAM sent */
    uint8_t got_final;        /* final response headers delivered */
} ts_h2_stream;

/* A connection. Treat as opaque outside tests; it is about 70 KB, so keep it
 * off small stacks. */
typedef struct {
    const ts_h2_cbs *cbs;
    void *user;
    uint8_t *mem;             /* the one allocation: output queue then body area */
    size_t out_off, out_len;  /* queued output is mem[out_off, out_off + out_len) */
    size_t body_used;         /* body area bytes in use */
    int dead;
    uint32_t err;             /* error code that killed the connection */
    int goaway;               /* a GOAWAY was received */
    int got_settings;         /* the server's first SETTINGS was seen */

    ts_h2_stream st[TS_H2_MAX_STREAMS];
    uint32_t next_id;         /* next client stream id */

    int64_t conn_send;        /* connection send window */
    int64_t conn_recv;        /* connection receive window */
    uint32_t conn_credit;     /* connection credit not yet returned */

    /* Server settings. */
    uint32_t peer_init_win;
    uint32_t peer_max_frame;
    uint32_t peer_max_streams;

    uint32_t ping_seq;

    /* Frame reader. */
    uint8_t fh[9];
    size_t fh_len;
    uint32_t f_len;
    size_t f_have;
    uint8_t frame[TS_H2_FRAME_MAX];

    /* Header block being assembled (HEADERS then CONTINUATION). */
    uint32_t hb_sid;          /* 0: none in progress */
    uint8_t hb_end_stream;
    size_t hb_len;
    uint8_t hblock[TS_H2_HBLOCK_MAX];

    /* Decoding state for the current block. */
    uint32_t dec_sid;         /* stream the fields go to, 0 if dropped */
    int dec_trailers;
    int dec_status;           /* -1 none yet */
    int dec_regular;          /* a regular field was seen */
    int dec_bad;              /* malformed or over a limit */
    uint32_t dec_fields;
    uint32_t dec_bytes;

    ts_hpack hpack;
    uint8_t ebuf[TS_H2_REQ_HDR_MAX];   /* request header block encoding */
} ts_h2;

void ts_h2_init(ts_h2 *c, const ts_h2_cbs *cbs, void *user);

/* Release the allocation. Call before ts_h2_init on the same struct again. */
void ts_h2_free(ts_h2 *c);

/* Process server bytes. Returns 0, or -1 on a connection error (see above). */
int ts_h2_feed(ts_h2 *c, const uint8_t *in, size_t n);

/* Queued client bytes: *out points at them and the count is returned (0 when
 * none). The pointer is valid until the next call on this connection. Pass the
 * number actually sent to ts_h2_consumed, which frees queue space and lets
 * queued request bodies continue. After a connection error the queue still
 * holds the GOAWAY. */
size_t ts_h2_output(ts_h2 *c, const uint8_t **out);
void ts_h2_consumed(ts_h2 *c, size_t n);

/* The caller has finished with n bytes of sid's data: return that much window
 * credit. WINDOW_UPDATE frames go out once a quarter of TS_H2_WINDOW has built
 * up. Returns 0, or -1 if n exceeds what was delivered and not yet consumed on
 * that stream. For a stream that has ended (or an unknown id) it does nothing
 * and returns 0: when a stream ends, its unconsumed bytes are credited back to
 * the connection automatically. */
int ts_h2_consume_data(ts_h2 *c, uint32_t sid, size_t n);

/* Open a stream: HEADERS with :method, :scheme https, :path, :authority, then
 * nheaders (name, value) pairs from headers[0..2*nheaders). Names are sent in
 * lowercase. The body (if any) is copied and sent as flow control allows; the
 * last frame carries END_STREAM. On success *sid is set and 0 returned. Returns
 * -1, with no output and no stream id used, if the connection is dead or going
 * away, TS_H2_MAX_STREAMS (or the server's limit) are open, the encoded block
 * exceeds TS_H2_REQ_HDR_MAX, the body does not fit in what remains of
 * TS_H2_BODY_MAX, or the output queue is full. */
int ts_h2_request(ts_h2 *c, uint32_t *sid, const char *method, const char *path,
                  const char *authority, const char *const *headers, size_t nheaders,
                  const uint8_t *body, size_t bodylen);

/* Abandon a stream: RST_STREAM CANCEL, unsent body dropped, no end callback.
 * Returns 0, or -1 if sid is not open. */
int ts_h2_cancel(ts_h2 *c, uint32_t sid);

/* Queue a PING (dropped if the output queue is full or the connection dead).
 * Any bytes from the server, including the PING ACK, show it is alive. */
void ts_h2_ping(ts_h2 *c);

/* The HTTP/2 error code that killed the connection (TS_H2_NO_ERROR if alive). */
uint32_t ts_h2_error(const ts_h2 *c);

#endif
