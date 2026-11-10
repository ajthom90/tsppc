#ifndef TS_PROTO_JSON_H
#define TS_PROTO_JSON_H

#include <stddef.h>
#include <stdint.h>

/* Bounded pull JSON reader. No allocation; never reads outside buf[0..len);
 * the buffer need not be NUL-terminated and must outlive the reader and any
 * token (tokens point into it). The grammar is checked strictly as tokens are
 * pulled: commas, colons, string escapes (including surrogate pairs), numbers
 * and nesting depth. Strings must be valid UTF-8, and a \u0000 escape is
 * refused: either makes ts_json_next return TS_JSON_ERROR, so the whole
 * document is rejected. Anything else is TS_JSON_ERROR, and the error is sticky. */

#define TS_JSON_MAX_DEPTH 32   /* 32 nested containers pass, 33 are an error */

typedef enum {
    TS_JSON_OBJ_START,
    TS_JSON_OBJ_END,
    TS_JSON_ARR_START,
    TS_JSON_ARR_END,
    TS_JSON_KEY,      /* raw is the undecoded text between the quotes */
    TS_JSON_STRING,   /* same */
    TS_JSON_NUMBER,   /* raw is the number text */
    TS_JSON_TRUE,
    TS_JSON_FALSE,
    TS_JSON_NUL,
    TS_JSON_END,      /* one complete top-level value has been read */
    TS_JSON_ERROR
} ts_json_type;

typedef struct {
    ts_json_type type;
    const char *raw;
    size_t rawlen;
} ts_json_tok;

typedef struct {
    const char *buf;
    size_t len;
    size_t pos;
    uint32_t is_obj;   /* bit d set: container at depth d (0-based) is an object */
    int depth;
    int state;
} ts_json;

void ts_json_init(ts_json *j, const char *buf, size_t len);

/* Next token. Returns t->type. For END and ERROR, raw is NULL and rawlen 0. */
ts_json_type ts_json_next(ts_json *j, ts_json_tok *t);

/* Consume the remainder of the value that began with token `first` (an object
 * or array start: through its matching end; a KEY: its value; a scalar: nothing).
 * Returns 0, or -1 on a parse error or if `first` cannot begin a value. */
int ts_json_skip(ts_json *j, const ts_json_tok *first);

/* Decode a STRING or KEY token (escapes, surrogate pairs) to UTF-8 in out,
 * NUL-terminated. Returns the length excluding the NUL, or -1 if the token is
 * not a string, is invalid, or does not fit in cap (including the NUL).
 * Never writes past cap; on failure with cap > 0, out is set to "". */
int ts_json_string(char *out, size_t cap, const ts_json_tok *t);

/* Parse a NUMBER token that is a plain integer (no fraction or exponent) in
 * int64 range. Returns 0 or -1. */
int ts_json_int64(int64_t *out, const ts_json_tok *t);

#endif
