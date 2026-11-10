#include "json.h"

enum {
    ST_VALUE,          /* a value is required */
    ST_VALUE_OR_ARR_END,
    ST_KEY_OR_OBJ_END,
    ST_KEY,
    ST_COLON,
    ST_COMMA_OR_END,   /* inside a container, after a value */
    ST_DONE,           /* top-level value complete */
    ST_ERROR
};

void ts_json_init(ts_json *j, const char *buf, size_t len)
{
    j->buf = buf;
    j->len = len;
    j->pos = 0;
    j->is_obj = 0;
    j->depth = 0;
    j->state = ST_VALUE;
}

static int hex4(const char *p, uint32_t *v)
{
    uint32_t r = 0;
    int i;
    for (i = 0; i < 4; i++) {
        char c = p[i];
        r <<= 4;
        if (c >= '0' && c <= '9') r |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') r |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') r |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    *v = r;
    return 0;
}

/* Parse one string body in s[0..n) (the text between the quotes), optionally
 * decoding to out. Returns the decoded length, or -1 if invalid (or, when out
 * is non-NULL, if the result plus a NUL does not fit in cap). */
static long scan_string(const char *s, size_t n, char *out, size_t cap)
{
    size_t i = 0, o = 0;
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        uint32_t cp;
        size_t need;
        if (c < 0x20) return -1;
        if (c >= 0x80) {
            /* Validate UTF-8: no overlongs, surrogates, > U+10FFFF, or truncation. */
            size_t k, extra;
            unsigned char lo = 0x80, hi = 0xbf;
            if (c >= 0xc2 && c <= 0xdf) extra = 1;
            else if (c >= 0xe0 && c <= 0xef) {
                extra = 2;
                if (c == 0xe0) lo = 0xa0;
                if (c == 0xed) hi = 0x9f;
            } else if (c >= 0xf0 && c <= 0xf4) {
                extra = 3;
                if (c == 0xf0) lo = 0x90;
                if (c == 0xf4) hi = 0x8f;
            } else return -1;
            if (n - i < extra + 1) return -1;
            for (k = 1; k <= extra; k++) {
                unsigned char b = (unsigned char)s[i + k];
                if (k == 1 ? (b < lo || b > hi) : (b < 0x80 || b > 0xbf)) return -1;
            }
            if (out) {
                if (o + extra + 1 >= cap) return -1;
                for (k = 0; k <= extra; k++) out[o + k] = s[i + k];
            }
            o += extra + 1; i += extra + 1;
            continue;
        }
        if (c != '\\') {
            if (out) { if (o + 1 >= cap) return -1; out[o] = (char)c; }
            o++; i++;
            continue;
        }
        i++;
        if (i >= n) return -1;
        c = (unsigned char)s[i++];
        switch (c) {
        case '"': cp = '"'; break;
        case '\\': cp = '\\'; break;
        case '/': cp = '/'; break;
        case 'b': cp = 8; break;
        case 'f': cp = 12; break;
        case 'n': cp = 10; break;
        case 'r': cp = 13; break;
        case 't': cp = 9; break;
        case 'u':
            if (n - i < 4 || hex4(s + i, &cp) != 0) return -1;
            i += 4;
            if (cp >= 0xdc00 && cp <= 0xdfff) return -1;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                uint32_t lo;
                if (n - i < 6 || s[i] != '\\' || s[i + 1] != 'u' ||
                    hex4(s + i + 2, &lo) != 0 || lo < 0xdc00 || lo > 0xdfff)
                    return -1;
                i += 6;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            }
            if (cp == 0) return -1;
            break;
        default:
            return -1;
        }
        need = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
        if (out) {
            if (o + need >= cap) return -1;
            if (need == 1) out[o] = (char)cp;
            else if (need == 2) {
                out[o] = (char)(0xc0 | (cp >> 6));
                out[o + 1] = (char)(0x80 | (cp & 0x3f));
            } else if (need == 3) {
                out[o] = (char)(0xe0 | (cp >> 12));
                out[o + 1] = (char)(0x80 | ((cp >> 6) & 0x3f));
                out[o + 2] = (char)(0x80 | (cp & 0x3f));
            } else {
                out[o] = (char)(0xf0 | (cp >> 18));
                out[o + 1] = (char)(0x80 | ((cp >> 12) & 0x3f));
                out[o + 2] = (char)(0x80 | ((cp >> 6) & 0x3f));
                out[o + 3] = (char)(0x80 | (cp & 0x3f));
            }
        }
        o += need;
    }
    if (out) {
        if (o + 1 > cap) return -1;
        out[o] = 0;
    }
    return (long)o;
}

static int isdig(char c) { return c >= '0' && c <= '9'; }

/* Length of the JSON number at s[0..n), or 0 if malformed. */
static size_t scan_number(const char *s, size_t n)
{
    size_t i = 0;
    if (i < n && s[i] == '-') i++;
    if (i >= n || !isdig(s[i])) return 0;
    if (s[i] == '0') i++;
    else while (i < n && isdig(s[i])) i++;
    if (i < n && s[i] == '.') {
        i++;
        if (i >= n || !isdig(s[i])) return 0;
        while (i < n && isdig(s[i])) i++;
    }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        i++;
        if (i < n && (s[i] == '+' || s[i] == '-')) i++;
        if (i >= n || !isdig(s[i])) return 0;
        while (i < n && isdig(s[i])) i++;
    }
    return i;
}

static ts_json_type fail(ts_json *j, ts_json_tok *t)
{
    j->state = ST_ERROR;
    t->type = TS_JSON_ERROR;
    t->raw = NULL;
    t->rawlen = 0;
    return TS_JSON_ERROR;
}

static ts_json_type emit(ts_json_tok *t, ts_json_type ty, const char *raw, size_t n)
{
    t->type = ty;
    t->raw = raw;
    t->rawlen = n;
    return ty;
}

static int lit(const ts_json *j, const char *word, size_t n)
{
    size_t i;
    if (j->len - j->pos < n) return 0;
    for (i = 0; i < n; i++)
        if (j->buf[j->pos + i] != word[i]) return 0;
    return 1;
}

/* State after a complete value. */
static void value_done(ts_json *j)
{
    j->state = j->depth == 0 ? ST_DONE : ST_COMMA_OR_END;
}

static int in_object(const ts_json *j)
{
    return j->depth > 0 && ((j->is_obj >> (j->depth - 1)) & 1u) != 0;
}

ts_json_type ts_json_next(ts_json *j, ts_json_tok *t)
{
    char c;
    emit(t, TS_JSON_ERROR, NULL, 0);
    if (j->state == ST_ERROR) return TS_JSON_ERROR;

    while (j->pos < j->len) {
        c = j->buf[j->pos];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
        j->pos++;
    }
    if (j->pos >= j->len) {
        if (j->state == ST_DONE) return emit(t, TS_JSON_END, NULL, 0);
        return fail(j, t);
    }
    c = j->buf[j->pos];

    switch (j->state) {
    case ST_DONE:
        return fail(j, t);

    case ST_COLON:
        if (c != ':') return fail(j, t);
        j->pos++;
        j->state = ST_VALUE;
        return ts_json_next(j, t);

    case ST_COMMA_OR_END:
        if (c == ',') {
            j->pos++;
            j->state = in_object(j) ? ST_KEY : ST_VALUE;
            return ts_json_next(j, t);
        }
        if (c == '}' && in_object(j)) goto obj_end;
        if (c == ']' && !in_object(j)) goto arr_end;
        return fail(j, t);

    case ST_KEY_OR_OBJ_END:
        if (c == '}') goto obj_end;
        /* fall through */
    case ST_KEY:
        if (c == '"') {
            size_t start = j->pos + 1, i = start;
            while (i < j->len && j->buf[i] != '"') {
                if (j->buf[i] == '\\') i++;
                i++;
            }
            if (i >= j->len || scan_string(j->buf + start, i - start, NULL, 0) < 0)
                return fail(j, t);
            j->pos = i + 1;
            j->state = ST_COLON;
            return emit(t, TS_JSON_KEY, j->buf + start, i - start);
        }
        return fail(j, t);

    case ST_VALUE_OR_ARR_END:
        if (c == ']') goto arr_end;
        /* fall through */
    case ST_VALUE:
        break;
    default:
        return fail(j, t);
    }

    /* A value is expected. */
    switch (c) {
    case '{':
    case '[':
        if (j->depth >= TS_JSON_MAX_DEPTH) return fail(j, t);
        if (c == '{') j->is_obj |= 1u << j->depth;
        else j->is_obj &= ~(1u << j->depth);
        j->depth++;
        j->pos++;
        j->state = c == '{' ? ST_KEY_OR_OBJ_END : ST_VALUE_OR_ARR_END;
        return emit(t, c == '{' ? TS_JSON_OBJ_START : TS_JSON_ARR_START,
                    j->buf + j->pos - 1, 1);
    case '"': {
        size_t start = j->pos + 1, i = start;
        while (i < j->len && j->buf[i] != '"') {
            if (j->buf[i] == '\\') i++;
            i++;
        }
        if (i >= j->len || scan_string(j->buf + start, i - start, NULL, 0) < 0)
            return fail(j, t);
        j->pos = i + 1;
        value_done(j);
        return emit(t, TS_JSON_STRING, j->buf + start, i - start);
    }
    case 't':
        if (!lit(j, "true", 4)) return fail(j, t);
        j->pos += 4; value_done(j);
        return emit(t, TS_JSON_TRUE, j->buf + j->pos - 4, 4);
    case 'f':
        if (!lit(j, "false", 5)) return fail(j, t);
        j->pos += 5; value_done(j);
        return emit(t, TS_JSON_FALSE, j->buf + j->pos - 5, 5);
    case 'n':
        if (!lit(j, "null", 4)) return fail(j, t);
        j->pos += 4; value_done(j);
        return emit(t, TS_JSON_NUL, j->buf + j->pos - 4, 4);
    default:
        if (c == '-' || isdig(c)) {
            size_t n = scan_number(j->buf + j->pos, j->len - j->pos);
            if (n == 0) return fail(j, t);
            j->pos += n; value_done(j);
            return emit(t, TS_JSON_NUMBER, j->buf + j->pos - n, n);
        }
        return fail(j, t);
    }

obj_end:
    j->pos++;
    j->depth--;
    value_done(j);
    return emit(t, TS_JSON_OBJ_END, j->buf + j->pos - 1, 1);
arr_end:
    j->pos++;
    j->depth--;
    value_done(j);
    return emit(t, TS_JSON_ARR_END, j->buf + j->pos - 1, 1);
}

int ts_json_skip(ts_json *j, const ts_json_tok *first)
{
    ts_json_tok t;
    int nest = 0;
    switch (first->type) {
    case TS_JSON_STRING: case TS_JSON_NUMBER: case TS_JSON_TRUE:
    case TS_JSON_FALSE: case TS_JSON_NUL:
        return 0;
    case TS_JSON_KEY:
        if (ts_json_next(j, &t) == TS_JSON_ERROR) return -1;
        return ts_json_skip(j, &t);
    case TS_JSON_OBJ_START: case TS_JSON_ARR_START:
        nest = 1;
        break;
    default:
        return -1;
    }
    while (nest > 0) {
        switch (ts_json_next(j, &t)) {
        case TS_JSON_OBJ_START: case TS_JSON_ARR_START: nest++; break;
        case TS_JSON_OBJ_END: case TS_JSON_ARR_END: nest--; break;
        case TS_JSON_END: case TS_JSON_ERROR: return -1;
        default: break;
        }
    }
    return 0;
}

int ts_json_string(char *out, size_t cap, const ts_json_tok *t)
{
    long n;
    if (cap == 0) return -1;
    if ((t->type != TS_JSON_STRING && t->type != TS_JSON_KEY) ||
        (t->raw == NULL && t->rawlen > 0)) {
        out[0] = 0;
        return -1;
    }
    n = scan_string(t->raw, t->rawlen, out, cap);
    if (n < 0 || n > 0x7fffffffL) { out[0] = 0; return -1; }
    return (int)n;
}

int ts_json_int64(int64_t *out, const ts_json_tok *t)
{
    size_t i = 0, n = t->rawlen;
    int neg = 0;
    uint64_t v = 0, limit;
    if (t->type != TS_JSON_NUMBER || n == 0 || t->raw == NULL) return -1;
    if (t->raw[0] == '-') { neg = 1; i = 1; }
    if (i >= n) return -1;
    if (t->raw[i] == '0' && n - i > 1) return -1;
    limit = neg ? (uint64_t)1 << 63 : ((uint64_t)1 << 63) - 1;
    for (; i < n; i++) {
        unsigned d;
        if (!isdig(t->raw[i])) return -1;
        d = (unsigned)(t->raw[i] - '0');
        if (v > (limit - d) / 10) return -1;
        v = v * 10 + d;
    }
    if (neg) *out = v == (uint64_t)1 << 63 ? INT64_MIN : -(int64_t)v;
    else *out = (int64_t)v;
    return 0;
}
