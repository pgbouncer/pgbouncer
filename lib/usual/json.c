/*
 * Read and write JSON.
 *
 * Copyright (c) 2014  Marko Kreen
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <usual/json.h>
#include <usual/cxextra.h>
#include <usual/cbtree.h>
#include <usual/misc.h>
#include <usual/utf8.h>
#include <usual/ctype.h>
#include <usual/bytemap.h>
#include <usual/string.h>
#include <math.h>

#define TYPE_BITS	3
#define TYPE_MASK	((1 << TYPE_BITS) - 1)
#define UNATTACHED	((struct JsonValue *)(1 << TYPE_BITS))

#define JSON_MAX_KEY	(1024*1024)

#define NUMBER_BUF	100

#define JSON_MAXINT	((1LL << 53) - 1)
#define JSON_MININT	(-(1LL << 53) + 1)

/*
 * Common struct for all JSON values
 */
struct JsonValue {
	/* actual value for simple types */
	union {
		double v_float;			/* float */
		int64_t v_int;			/* int */
		bool v_bool;			/* bool */
		size_t v_size;			/* str/list/dict */
	} u;

	/* pointer to next elem and type in low bits */
	uintptr_t v_next_and_type;
};

/*
 * List container.
 */
struct ValueList {
	struct JsonValue *first;
	struct JsonValue *last;
	struct JsonValue **array;
};

/*
 * Extra data for list/dict.
 */
struct JsonContainer {
	/* parent container */
	struct JsonValue *c_parent;

	/* main context for child alloc */
	struct JsonContext *c_ctx;

	/* child elements */
	union {
		struct CBTree *c_dict;
		struct ValueList c_list;
	} u;
};

#define DICT_EXTRA (offsetof(struct JsonContainer, u.c_dict) + sizeof(struct CBTree *))
#define LIST_EXTRA (sizeof(struct JsonContainer))

/*
 * Allocation context.
 */
struct JsonContext {
	CxMem *pool;
	unsigned int options;

	/* parse state */
	struct JsonValue *parent;
	struct JsonValue *cur_key;
	struct JsonValue *top;
	const char *lasterr;
	char errbuf[128];
	int64_t linenr;
};

struct RenderState {
	struct MBuf *dst;
	unsigned int options;
};

/*
 * Parser states
 */
enum ParseState {
	S_INITIAL_VALUE = 1,
	S_LIST_VALUE,
	S_LIST_VALUE_OR_CLOSE,
	S_LIST_COMMA_OR_CLOSE,
	S_DICT_KEY,
	S_DICT_KEY_OR_CLOSE,
	S_DICT_COLON,
	S_DICT_VALUE,
	S_DICT_COMMA_OR_CLOSE,
	S_PARENT,
	S_DONE,
	MAX_STATES,
};

/*
 * Tokens that change state.
 */
enum TokenTypes {
	T_STRING,
	T_OTHER,
	T_COMMA,
	T_COLON,
	T_OPEN_DICT,
	T_OPEN_LIST,
	T_CLOSE_DICT,
	T_CLOSE_LIST,
	MAX_TOKENS
};

/*
 * 4-byte ints for small string tokens.
 */

#define C_NULL FOURCC('n','u','l','l')
#define C_TRUE FOURCC('t','r','u','e')
#define C_ALSE FOURCC('a','l','s','e')

/*
 * Signature for render functions.
 */
typedef bool (*render_func_t)(struct RenderState *rs, struct JsonValue *jv);

static bool render_any(struct RenderState *rs, struct JsonValue *jv);

/*
 * Header manipulation
 */

static inline enum JsonValueType get_type(struct JsonValue *jv)
{
	return jv->v_next_and_type & TYPE_MASK;
}

static inline bool has_type(struct JsonValue *jv, enum JsonValueType type)
{
	if (!jv)
		return false;
	return get_type(jv) == type;
}

static inline struct JsonValue *get_next(struct JsonValue *jv)
{
	return (struct JsonValue *)(jv->v_next_and_type & ~(uintptr_t)TYPE_MASK);
}

static inline void set_next(struct JsonValue *jv, struct JsonValue *next)
{
	jv->v_next_and_type = (uintptr_t)next | get_type(jv);
}

static inline bool is_unattached(struct JsonValue *jv)
{
	return get_next(jv) == UNATTACHED;
}

static inline void *get_extra(struct JsonValue *jv)
{
	return (void *)(jv + 1);
}

static inline char *get_cstring(struct JsonValue *jv)
{
	enum JsonValueType type = get_type(jv);
	if (type != JSON_STRING)
		return NULL;
	return get_extra(jv);
}

/*
 * Collection header manipulation.
 */

static inline struct JsonContainer *get_container(struct JsonValue *jv)
{
	enum JsonValueType type = get_type(jv);
	if (type != JSON_DICT && type != JSON_LIST)
		return NULL;
	return get_extra(jv);
}

static inline void set_parent(struct JsonValue *jv, struct JsonValue *parent)
{
	struct JsonContainer *c = get_container(jv);
	if (c)
		c->c_parent = parent;
}

static inline struct JsonContext *get_context(struct JsonValue *jv)
{
	struct JsonContainer *c = get_container(jv);
	return c ? c->c_ctx : NULL;
}

static inline struct CBTree *get_dict_tree(struct JsonValue *jv)
{
	struct JsonContainer *c;
	if (has_type(jv, JSON_DICT)) {
		c = get_container(jv);
		return c->u.c_dict;
	}
	return NULL;
}

static inline struct ValueList *get_list_vlist(struct JsonValue *jv)
{
	struct JsonContainer *c;
	if (has_type(jv, JSON_LIST)) {
		c = get_container(jv);
		return &c->u.c_list;
	}
	return NULL;
}

/*
 * Random helpers
 */

/* copy and return final pointer */
static inline char *plain_copy(char *dst, const char *src, const char *endptr)
{
	if (src < endptr) {
		memcpy(dst, src, endptr - src);
		return dst + (endptr - src);
	}
	return dst;
}

/* error message on context */
_PRINTF(2,0)
static void format_err(struct JsonContext *ctx, const char *errmsg, va_list ap)
{
	char buf[119];
	if (ctx->lasterr)
		return;
	vsnprintf(buf, sizeof(buf), errmsg, ap);
	snprintf(ctx->errbuf, sizeof(ctx->errbuf), "Line #%" PRIi64 ": %s", ctx->linenr, buf);
	ctx->lasterr = ctx->errbuf;
}

/* set message and return false */
_PRINTF(2,3)
static bool err_false(struct JsonContext *ctx, const char *errmsg, ...)
{
	va_list ap;
	va_start(ap, errmsg);
	format_err(ctx, errmsg, ap);
	va_end(ap);
	return false;
}

/* set message and return NULL */
_PRINTF(2,3)
static void *err_null(struct JsonContext *ctx, const char *errmsg, ...)
{
	va_list ap;
	va_start(ap, errmsg);
	format_err(ctx, errmsg, ap);
	va_end(ap);
	return NULL;
}

/* callback for cbtree, returns key bytes */
static size_t get_key_data_cb(void *dictptr, void *keyptr, const void **dst_p)
{
	struct JsonValue *key = keyptr;
	*dst_p = get_cstring(key);
	return key->u.v_size;
}

/* add elemnt to list */
static void real_list_append(struct JsonValue *list, struct JsonValue *elem)
{
	struct ValueList *vlist;

	vlist = get_list_vlist(list);
	if (vlist->last) {
		set_next(vlist->last, elem);
	} else {
		vlist->first = elem;
	}
	vlist->last = elem;
	vlist->array = NULL;

	list->u.v_size++;
}

/* add key to tree */
static bool real_dict_add_key(struct JsonContext *ctx, struct JsonValue *dict, struct JsonValue *key)
{
	struct CBTree *tree;

	tree = get_dict_tree(dict);
	if (!tree)
		return err_false(ctx, "Expect dict");

	if (json_value_size(key) > JSON_MAX_KEY)
		return err_false(ctx, "Too large key");

	dict->u.v_size++;
	if (!cbtree_insert(tree, key))
		return err_false(ctx, "Key insertion failed");

	return true;
}

/* create basic value struct, link to stuctures */
static struct JsonValue *mk_value(struct JsonContext *ctx, enum JsonValueType type, size_t extra, bool attach)
{
	struct JsonValue *val;
	struct JsonContainer *col = NULL;

	if (!ctx)
		return NULL;

	val = cx_alloc(ctx->pool, sizeof(struct JsonValue) + extra);
	if (!val)
		return err_null(ctx, "No memory");
	if ((uintptr_t)val & TYPE_MASK)
		return err_null(ctx, "Unaligned pointer");

	/* initial value */
	val->v_next_and_type = type;
	val->u.v_int = 0;

	if (type == JSON_DICT || type == JSON_LIST) {
		col = get_container(val);
		col->c_ctx = ctx;
		col->c_parent = NULL;
		if (type == JSON_DICT) {
			col->u.c_dict = cbtree_create(get_key_data_cb, NULL, val, ctx->pool);
			if (!col->u.c_dict)
				return err_null(ctx, "No memory");
		} else {
			memset(&col->u.c_list, 0, sizeof(col->u.c_list));
		}
	}

	/* independent JsonValue? */
	if (!attach) {
		set_next(val, UNATTACHED);
		return val;
	}

	/* attach to parent */
	if (col)
		col->c_parent = ctx->parent;

	/* attach to previous value */
	if (has_type(ctx->parent, JSON_DICT)) {
		if (ctx->cur_key) {
			set_next(ctx->cur_key, val);
			ctx->cur_key = NULL;
		} else {
			ctx->cur_key = val;
		}
	} else if (has_type(ctx->parent, JSON_LIST)) {
		real_list_append(ctx->parent, val);
	} else if (!ctx->top) {
		ctx->top = val;
	} else {
		return err_null(ctx, "Only one top element is allowed");
	}
	return val;
}

static void prepare_array(struct JsonValue *list)
{
	struct JsonContainer *c;
	struct JsonValue *val;
	struct ValueList *vlist;
	size_t i;

	vlist = get_list_vlist(list);
	if (vlist->array)
		return;
	c = get_container(list);
	vlist->array = cx_alloc(c->c_ctx->pool, list->u.v_size * sizeof(struct JsonValue *));
	if (!vlist->array)
		return;
	val = vlist->first;
	for (i = 0; i < list->u.v_size && val; i++) {
		vlist->array[i] = val;
		val = get_next(val);
	}
}

/*
 * Parsing code starts
 */

/* create and change context */
static bool open_container(struct JsonContext *ctx, enum JsonValueType type, unsigned int extra)
{
	struct JsonValue *jv;

	jv = mk_value(ctx, type, extra, true);
	if (!jv)
		return false;

	ctx->parent = jv;
	ctx->cur_key = NULL;
	return true;
}

/* close and change context */
static enum ParseState close_container(struct JsonContext *ctx, enum ParseState state)
{
	struct JsonContainer *c;

	if (state != S_PARENT)
		return (int)err_false(ctx, "close_container bug");

	c = get_container(ctx->parent);
	if (!c)
		return (int)err_false(ctx, "invalid parent");

	ctx->parent = c->c_parent;
	ctx->cur_key = NULL;

	if (has_type(ctx->parent, JSON_DICT)) {
		return S_DICT_COMMA_OR_CLOSE;
	} else if (has_type(ctx->parent, JSON_LIST)) {
		return S_LIST_COMMA_OR_CLOSE;
	}
	return S_DONE;
}

/* parse 4-char token */
static bool parse_char4(struct JsonContext *ctx, const char **src_p, const char *end,
			uint32_t t_exp, enum JsonValueType type, bool val)
{
	const char *src;
	uint32_t t_got;
	struct JsonValue *jv;

	src = *src_p;
	if (src + 4 > end)
		return err_false(ctx, "Unexpected end of token");

	memcpy(&t_got, src, 4);
	if (t_exp != t_got)
		return err_false(ctx, "Invalid token");

	jv = mk_value(ctx, type, 0, true);
	if (!jv)
		return false;
	jv->u.v_bool = val;

	*src_p += 4;
	return true;
}

/* parse int or float */
static bool parse_number(struct JsonContext *ctx, const char **src_p, const char *end)
{
	const char *start, *src;
	enum JsonValueType type = JSON_INT;
	char *tokend = NULL;
	char buf[NUMBER_BUF];
	size_t len;
	struct JsonValue *jv;
	double v_float = 0;
	int64_t v_int = 0;

	/* scan & copy */
	start = src = *src_p;
	for (; src < end; src++) {
		if (*src >= '0' && *src <= '9') {
		} else if (*src == '+' || *src == '-') {
		} else if (*src == '.' || *src == 'e' || *src == 'E') {
			type = JSON_FLOAT;
		} else {
			break;
		}
	}
	len = src - start;
	if (len >= NUMBER_BUF)
		goto failed;
	memcpy(buf, start, len);
	buf[len] = 0;

	/* now parse */
	errno = 0;
	tokend = buf;
	if (type == JSON_FLOAT) {
		v_float = strtod_dot(buf, &tokend);
		if (*tokend != 0 || errno || !isfinite(v_float))
			goto failed;
	} else if (len < 8) {
		v_int = strtol(buf, &tokend, 10);
		if (*tokend != 0 || errno)
			goto failed;
	} else {
		v_int = strtoll(buf, &tokend, 10);
		if (*tokend != 0 || errno || v_int < JSON_MININT || v_int > JSON_MAXINT)
			goto failed;
	}

	/* create value struct */
	jv = mk_value(ctx, type, 0, true);
	if (!jv)
		return false;
	if (type == JSON_FLOAT) {
		jv->u.v_float = v_float;
	} else {
		jv->u.v_int = v_int;
	}

	*src_p = src;
	return true;
failed:
	if (!errno)
		errno = EINVAL;
	return err_false(ctx, "Number parse failed");
}

/*
 * String parsing
 */

static int parse_hex(const char *s, const char *end)
{
	int v = 0, c, i, x;
	if (s + 4 > end)
		return -1;
	for (i = 0; i < 4; i++) {
		c = s[i];
		if (c >= '0' && c <= '9') {
			x = c - '0';
		} else if (c >= 'a' && c <= 'f') {
			x = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			x = c - 'A' + 10;
		} else {
			return -1;
		}
		v = (v << 4) | x;
	}
	return v;
}

/* process \uXXXX escapes, merge surrogates */
static bool parse_uescape(struct JsonContext *ctx, char **dst_p, char *dstend,
			  const char **src_p, const char *end)
{
	int c, c2;
	const char *src = *src_p;

	c = parse_hex(src, end);
	if (c <= 0)
		return err_false(ctx, "Invalid hex escape");
	src += 4;

	if (c >= 0xD800 && c <= 0xDFFF) {
		/* first surrogate */
		if (c >= 0xDC00)
			return err_false(ctx, "Invalid UTF16 escape");
		if (src + 6 > end)
			return err_false(ctx, "Invalid UTF16 escape");

		/* second surrogate */
		if (src[0] != '\\' || src[1] != 'u')
			return err_false(ctx, "Invalid UTF16 escape");
		c2 = parse_hex(src + 2, end);
		if (c2 < 0xDC00 || c2 > 0xDFFF)
			return err_false(ctx, "Invalid UTF16 escape");
		c = 0x10000 + ((c & 0x3FF) << 10) + (c2 & 0x3FF);
		src += 6;
	}

	/* now write char */
	if (!utf8_put_char(c, dst_p, dstend))
		return err_false(ctx, "Invalid UTF16 escape");

	*src_p = src;
	return true;
}

#define meta_string(c) (((c) == '"' || (c) == '\\' || (c) == '\0' || \
			 (c) == '\n' || ((c) & 0x80) != 0) ? 1 : 0)
static const uint8_t string_examine_chars[] = INTMAP256_CONST(meta_string);

/* look for string end, validate contents */
static bool scan_string(struct JsonContext *ctx, const char *src, const char *end,
			const char **str_end_p, bool *hasesc_p, int64_t *nlines_p)
{
	bool hasesc = false;
	int64_t lines = 0;
	unsigned int n;
	bool check_utf8 = true;

	if (ctx->options & JSON_PARSE_IGNORE_ENCODING)
		check_utf8 = false;

	while (src < end) {
		if (!string_examine_chars[(uint8_t)*src]) {
			src++;
		} else if (*src == '"') {
			/* string end */
			*hasesc_p = hasesc;
			*str_end_p = src;
			*nlines_p = lines;
			return true;
		} else if (*src == '\\') {
			hasesc = true;
			src++;
			if (src < end && (*src == '\\' || *src == '"'))
				src++;
		} else if (*src & 0x80) {
			n = utf8_validate_seq(src, end);
			if (n) {
				src += n;
			} else if (check_utf8) {
				goto badutf;
			} else {
				src++;
			}
		} else if (*src == '\n') {
			lines++;
			src++;
		} else {
			goto badutf;
		}
	}
	return err_false(ctx, "Unexpected end of string");

badutf:
	return err_false(ctx, "Invalid UTF8 sequence");
}

/* string boundaries are known, copy and unescape */
static char *process_escapes(struct JsonContext *ctx,
			     const char *src, const char *end,
			     char *dst, char *dstend)
{
	const char *esc;

	/* process escapes */
	while (src < end) {
		esc = memchr(src, '\\', end - src);
		if (!esc) {
			dst = plain_copy(dst, src, end);
			break;
		}
		dst = plain_copy(dst, src, esc);
		src = esc + 1;
		switch (*src++) {
		case '"': *dst++ = '"'; break;
		case '\\': *dst++ = '\\'; break;
		case '/': *dst++ = '/'; break;
		case 'b': *dst++ = '\b'; break;
		case 'f': *dst++ = '\f'; break;
		case 'n': *dst++ = '\n'; break;
		case 'r': *dst++ = '\r'; break;
		case 't': *dst++ = '\t'; break;
		case 'u':
			if (!parse_uescape(ctx, &dst, dstend, &src, end))
				return NULL;
			break;
		default:
			return err_null(ctx, "Invalid escape code");
		}
	}
	return dst;
}

/* 2-phase string processing */
static bool parse_string(struct JsonContext *ctx, const char **src_p, const char *end)
{
	const char *start, *strend = NULL;
	bool hasesc = false;
	char *dst, *dstend;
	size_t len;
	struct JsonValue *jv;
	int64_t lines = 0;

	/* find string boundaries, validate */
	start = *src_p;
	if (!scan_string(ctx, start, end, &strend, &hasesc, &lines))
		return false;

	/* create value struct */
	len = strend - start;
	jv = mk_value(ctx, JSON_STRING, len + 1, true);
	if (!jv)
		return false;
	dst = get_cstring(jv);
	dstend = dst + len;

	/* copy & process escapes */
	if (hasesc) {
		dst = process_escapes(ctx, start, strend, dst, dstend);
		if (!dst)
			return false;
	} else {
		dst = plain_copy(dst, start, strend);
	}

	*dst = '\0';
	jv->u.v_size = dst - get_cstring(jv);
	ctx->linenr += lines;
	*src_p = strend + 1;
	return true;
}

/*
 * Helpers for relaxed parsing
 */

static bool skip_comment(struct JsonContext *ctx, const char **src_p, const char *end)
{
	const char *s;
	char c;
	size_t lnr;

	s = *src_p;
	if (s >= end)
		return false;
	c = *s++;
	if (c == '/') {
		s = memchr(s, '\n', end - s);
		if (s) {
			ctx->linenr++;
			*src_p = s + 1;
		} else {
			*src_p = end;
		}
		return true;
	} else if (c == '*') {
		for (lnr = 0; s + 2 <= end; s++) {
			if (s[0] == '*' && s[1] == '/') {
				ctx->linenr += lnr;
				*src_p = s + 2;
				return true;
			} else if (s[0] == '\n') {
				lnr++;
			}
		}
	}
	return false;
}

static bool skip_extra_comma(struct JsonContext *ctx, const char **src_p, const char *end, enum ParseState state)
{
	bool skip = false;
	const char *src = *src_p;

	while (src < end && isspace(*src)) {
		if (*src == '\n')
			ctx->linenr++;
		src++;
	}

	if (src < end) {
		if (*src == '}') {
			if (state == S_DICT_COMMA_OR_CLOSE || state == S_DICT_KEY_OR_CLOSE)
				skip = true;
		} else if (*src == ']') {
			if (state == S_LIST_COMMA_OR_CLOSE || state == S_LIST_VALUE_OR_CLOSE)
				skip = true;
		}
	}
	*src_p = src;
	return skip;
}

/*
 * Main parser
 */

/* oldstate + token -> newstate */
static const unsigned char STATE_STEPS[MAX_STATES][MAX_TOKENS] = {
[S_INITIAL_VALUE] = {
	[T_OPEN_LIST] = S_LIST_VALUE_OR_CLOSE,
	[T_OPEN_DICT] = S_DICT_KEY_OR_CLOSE,
	[T_STRING] = S_DONE,
	[T_OTHER] = S_DONE },
[S_LIST_VALUE] = {
	[T_OPEN_LIST] = S_LIST_VALUE_OR_CLOSE,
	[T_OPEN_DICT] = S_DICT_KEY_OR_CLOSE,
	[T_STRING] = S_LIST_COMMA_OR_CLOSE,
	[T_OTHER] = S_LIST_COMMA_OR_CLOSE },
[S_LIST_VALUE_OR_CLOSE] = {
	[T_OPEN_LIST] = S_LIST_VALUE_OR_CLOSE,
	[T_OPEN_DICT] = S_DICT_KEY_OR_CLOSE,
	[T_STRING] = S_LIST_COMMA_OR_CLOSE,
	[T_OTHER] = S_LIST_COMMA_OR_CLOSE,
	[T_CLOSE_LIST] = S_PARENT },
[S_LIST_COMMA_OR_CLOSE] = {
	[T_COMMA] = S_LIST_VALUE,
	[T_CLOSE_LIST] = S_PARENT },
[S_DICT_KEY] = {
	[T_STRING] = S_DICT_COLON },
[S_DICT_KEY_OR_CLOSE] = {
	[T_STRING] = S_DICT_COLON,
	[T_CLOSE_DICT] = S_PARENT },
[S_DICT_COLON] = {
	[T_COLON] = S_DICT_VALUE },
[S_DICT_VALUE] = {
	[T_OPEN_LIST] = S_LIST_VALUE_OR_CLOSE,
	[T_OPEN_DICT] = S_DICT_KEY_OR_CLOSE,
	[T_STRING] = S_DICT_COMMA_OR_CLOSE,
	[T_OTHER] = S_DICT_COMMA_OR_CLOSE },
[S_DICT_COMMA_OR_CLOSE] = {
	[T_COMMA] = S_DICT_KEY,
	[T_CLOSE_DICT] = S_PARENT },
};

#define MAPSTATE(state, tok) do { \
	int newstate = STATE_STEPS[state][tok]; \
	if (!newstate) \
		return err_false(ctx, "Unexpected symbol: '%c'", c); \
	state = newstate; \
} while (0)

/* actual parser */
static bool parse_tokens(struct JsonContext *ctx, const char *src, const char *end)
{
	char c;
	enum ParseState state = S_INITIAL_VALUE;
	bool relaxed = ctx->options & JSON_PARSE_RELAXED;

	while (src < end) {
		c = *src++;
		switch (c) {
		case '\n':
			ctx->linenr++;
		case ' ': case '\t': case '\r': case '\f': case '\v':
			/* common case - many spaces */
			while (src < end && *src == ' ') src++;
			break;
		case '"':
			MAPSTATE(state, T_STRING);
			if (!parse_string(ctx, &src, end))
				goto failed;
			break;
		case 'n':
			MAPSTATE(state, T_OTHER);
			src--;
			if (!parse_char4(ctx, &src, end, C_NULL, JSON_NULL, 0))
				goto failed;
			continue;
		case 't':
			MAPSTATE(state, T_OTHER);
			src--;
			if (!parse_char4(ctx, &src, end, C_TRUE, JSON_BOOL, 1))
				goto failed;
			break;
		case 'f':
			MAPSTATE(state, T_OTHER);
			if (!parse_char4(ctx, &src, end, C_ALSE, JSON_BOOL, 0))
				goto failed;
			break;
		case '-':
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			MAPSTATE(state, T_OTHER);
			src--;
			if (!parse_number(ctx, &src, end))
				goto failed;
			break;
		case '[':
			MAPSTATE(state, T_OPEN_LIST);
			if (!open_container(ctx, JSON_LIST, LIST_EXTRA))
				goto failed;
			break;
		case '{':
			MAPSTATE(state, T_OPEN_DICT);
			if (!open_container(ctx, JSON_DICT, DICT_EXTRA))
				goto failed;
			break;
		case ']':
			MAPSTATE(state, T_CLOSE_LIST);
			state = close_container(ctx, state);
			if (!state)
				goto failed;
			break;
		case '}':
			MAPSTATE(state, T_CLOSE_DICT);
			state = close_container(ctx, state);
			if (!state)
				goto failed;
			break;
		case ':':
			MAPSTATE(state, T_COLON);
			if (!real_dict_add_key(ctx, ctx->parent, ctx->cur_key))
				goto failed;
			break;
		case ',':
			if (relaxed && skip_extra_comma(ctx, &src, end, state))
				continue;
			MAPSTATE(state, T_COMMA);
			break;
		case '/':
			if (relaxed && skip_comment(ctx, &src, end))
				continue;
			/* fallthrough */
		default:
			return err_false(ctx, "Invalid symbol: '%c'", c);
		}
	}
	if (state != S_DONE)
		return err_false(ctx, "Container still open");
	return true;
failed:
	return false;
}

/* parser public api */
struct JsonValue *json_parse(struct JsonContext *ctx, const char *json, size_t len)
{
	const char *end = json + len;

	/* reset parser */
	ctx->linenr = 1;
	ctx->parent = NULL;
	ctx->cur_key = NULL;
	ctx->lasterr = NULL;
	ctx->top = NULL;

	if (!parse_tokens(ctx, json, end))
		return NULL;

	return ctx->top;
}

/*
 * Render value as JSON string.
 */

static bool render_null(struct RenderState *rs, struct JsonValue *jv)
{
	return mbuf_write(rs->dst, "null", 4);
}

static bool render_bool(struct RenderState *rs, struct JsonValue *jv)
{
	if (jv->u.v_bool)
		return mbuf_write(rs->dst, "true", 4);
	return mbuf_write(rs->dst, "false", 5);
}

static bool render_int(struct RenderState *rs, struct JsonValue *jv)
{
	char buf[NUMBER_BUF];
	int len;

	len = snprintf(buf, sizeof(buf), "%" PRIi64, jv->u.v_int);
	if (len < 0 || len >= NUMBER_BUF)
		return false;
	return mbuf_write(rs->dst, buf, len);
}

static bool render_float(struct RenderState *rs, struct JsonValue *jv)
{
	char buf[NUMBER_BUF + 2];
	int len;

	len = dtostr_dot(buf, NUMBER_BUF, jv->u.v_float);
	if (len < 0 || len >= NUMBER_BUF)
		return false;
	if (!memchr(buf, '.', len) && !memchr(buf, 'e', len)) {
	    buf[len++] = '.';
	    buf[len++] = '0';
	}
	return mbuf_write(rs->dst, buf, len);
}

static bool escape_char(struct MBuf *dst, unsigned int c)
{
	char ec;
	char buf[10];

	/* start escape */
	if (!mbuf_write_byte(dst, '\\'))
		return false;

	/* escape same char */
	if (c == '"' || c == '\\')
		return mbuf_write_byte(dst, c);

	/* low-ascii mess */
	switch (c) {
	case '\b': ec = 'b'; break;
	case '\f': ec = 'f'; break;
	case '\n': ec = 'n'; break;
	case '\r': ec = 'r'; break;
	case '\t': ec = 't'; break;
	default:
		snprintf(buf, sizeof(buf), "u%04x", c);
		return mbuf_write(dst, buf, 5);
	}
	return mbuf_write_byte(dst, ec);
}

static bool render_string(struct RenderState *rs, struct JsonValue *jv)
{
	const char *s, *last;
	const char *val = get_cstring(jv);
	size_t len = jv->u.v_size;
	const char *end = val + len;
	unsigned int c;

	/* start quote */
	if (!mbuf_write_byte(rs->dst, '"'))
		return false;

	for (s = last = val; s < end; s++) {
		if (*s == '"' || *s == '\\' || (unsigned char)*s < 0x20 ||
			/* Valid in JSON, but not in JS:
			   \u2028 - Line separator
			   \u2029 - Paragraph separator */
			((unsigned char)s[0] == 0xE2 && (unsigned char)s[1] == 0x80 &&
			 ((unsigned char)s[2] == 0xA8 || (unsigned char)s[2] == 0xA9)))
		{
			/* flush */
			if (last < s) {
				if (!mbuf_write(rs->dst, last, s - last))
					return false;
			}

			if ((unsigned char)s[0] == 0xE2) {
				c = 0x2028 + ((unsigned char)s[2] - 0xA8);
				last = s + 3;
			} else {
				c = (unsigned char)*s;
				last = s + 1;
			}

			/* output escaped char */
			if (!escape_char(rs->dst, c))
				return false;
		}
	}

	/* flush */
	if (last < s) {
		if (!mbuf_write(rs->dst, last, s - last))
			return false;
	}

	/* final quote */
	if (!mbuf_write_byte(rs->dst, '"'))
		return false;

	return true;
}

/*
 * Render complex values
 */

struct ElemWriterState {
	struct RenderState *rs;
	char sep;
};

static bool list_elem_writer(void *arg, struct JsonValue *elem)
{
	struct ElemWriterState *state = arg;

	if (state->sep && !mbuf_write_byte(state->rs->dst, state->sep))
		return false;
	state->sep = ',';

	return render_any(state->rs, elem);
}

static bool render_list(struct RenderState *rs, struct JsonValue *list)
{
	struct ElemWriterState state;

	state.rs = rs;
	state.sep = 0;

	if (!mbuf_write_byte(rs->dst, '['))
		return false;
	if (!json_list_iter(list, list_elem_writer, &state))
		return false;
	if (!mbuf_write_byte(rs->dst, ']'))
		return false;
	return true;
}

static bool dict_elem_writer(void *ctx, struct JsonValue *key, struct JsonValue *val)
{
	struct ElemWriterState *state = ctx;

	if (state->sep && !mbuf_write_byte(state->rs->dst, state->sep))
		return false;
	state->sep = ',';

	if (!render_any(state->rs, key))
		return false;
	if (!mbuf_write_byte(state->rs->dst, ':'))
		return false;
	return render_any(state->rs, val);
}

static bool render_dict(struct RenderState *rs, struct JsonValue *dict)
{
	struct ElemWriterState state;

	state.rs = rs;
	state.sep = 0;

	if (!mbuf_write_byte(rs->dst, '{'))
		return false;
	if (!json_dict_iter(dict, dict_elem_writer, &state))
		return false;
	if (!mbuf_write_byte(rs->dst, '}'))
		return false;

	return true;
}

static bool render_invalid(struct RenderState *rs, struct JsonValue *jv)
{
	return false;
}

/*
 * Public api
 */

static bool render_any(struct RenderState *rs, struct JsonValue *jv)
{
	static const render_func_t rfunc_map[] = {
		render_invalid, render_null, render_bool, render_int,
		render_float, render_string, render_list, render_dict,
	};
	return rfunc_map[get_type(jv)](rs, jv);
}

bool json_render(struct MBuf *dst, struct JsonValue *jv)
{
	struct RenderState rs;

	rs.dst = dst;
	rs.options = 0;
	return render_any(&rs, jv);
}

/*
 * Examine single value
 */

enum JsonValueType json_value_type(struct JsonValue *jv)
{
	return get_type(jv);
}

size_t json_value_size(struct JsonValue *jv)
{
	if (has_type(jv, JSON_STRING) ||
	    has_type(jv, JSON_LIST) ||
	    has_type(jv, JSON_DICT))
		return jv->u.v_size;
	return 0;
}

bool json_value_as_bool(struct JsonValue *jv, bool *dst_p)
{
	if (!has_type(jv, JSON_BOOL))
		return false;
	*dst_p = jv->u.v_bool;
	return true;
}

bool json_value_as_int(struct JsonValue *jv, int64_t *dst_p)
{
	if (!has_type(jv, JSON_INT))
		return false;
	*dst_p = jv->u.v_int;
	return true;
}

bool json_value_as_float(struct JsonValue *jv, double *dst_p)
{
	if (!has_type(jv, JSON_FLOAT)) {
		if (has_type(jv, JSON_INT)) {
			*dst_p = jv->u.v_int;
			return true;
		}
		return false;
	}
	*dst_p = jv->u.v_float;
	return true;
}

bool json_value_as_string(struct JsonValue *jv, const char **dst_p, size_t *size_p)
{
	if (!has_type(jv, JSON_STRING))
		return false;
	*dst_p = get_cstring(jv);
	if (size_p)
		*size_p = jv->u.v_size;
	return true;
}

/*
 * Load value from dict.
 */

static int dict_getter(struct JsonValue *dict,
		       const char *key, unsigned int klen,
		       struct JsonValue **val_p,
		       enum JsonValueType req_type, bool req_value)
{
	struct JsonValue *val, *kjv;
	struct CBTree *tree;

	tree = get_dict_tree(dict);
	if (!tree)
		return false;

	kjv = cbtree_lookup(tree, key, klen);
	if (!kjv) {
		if (req_value)
			return false;
		*val_p = NULL;
		return true;
	}
	val = get_next(kjv);
	if (!req_value && json_value_is_null(val)) {
		*val_p = NULL;
		return true;
	}
	if (!has_type(val, req_type))
		return false;
	*val_p = val;
	return true;
}

bool json_dict_get_value(struct JsonValue *dict, const char *key, struct JsonValue **val_p)
{
	struct CBTree *tree;
	struct JsonValue *kjv;
	size_t klen;

	tree = get_dict_tree(dict);
	if (!tree)
		return false;

	klen = strlen(key);
	kjv = cbtree_lookup(tree, key, klen);
	if (!kjv)
		return false;
	*val_p = get_next(kjv);
	return true;
}

bool json_dict_is_null(struct JsonValue *dict, const char *key)
{
	struct JsonValue *val;
	if (!json_dict_get_value(dict, key, &val))
		return true;
	return has_type(val, JSON_NULL);
}

bool json_dict_get_bool(struct JsonValue *dict, const char *key, bool *dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_BOOL, true))
		return false;
	return json_value_as_bool(val, dst_p);
}

bool json_dict_get_int(struct JsonValue *dict, const char *key, int64_t *dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_INT, true))
		return false;
	return json_value_as_int(val, dst_p);
}

bool json_dict_get_float(struct JsonValue *dict, const char *key, double *dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_FLOAT, true))
		return false;
	return json_value_as_float(val, dst_p);
}

bool json_dict_get_string(struct JsonValue *dict, const char *key, const char **dst_p, size_t *len_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_STRING, true))
		return false;
	return json_value_as_string(val, dst_p, len_p);
}

bool json_dict_get_list(struct JsonValue *dict, const char *key, struct JsonValue **dst_p)
{
	return dict_getter(dict, key, strlen(key), dst_p, JSON_LIST, true);
}

bool json_dict_get_dict(struct JsonValue *dict, const char *key, struct JsonValue **dst_p)
{
	return dict_getter(dict, key, strlen(key), dst_p, JSON_DICT, true);
}

/*
 * Load optional dict element.
 */

bool json_dict_get_opt_bool(struct JsonValue *dict, const char *key, bool *dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_BOOL, false))
		return false;
	return !val || json_value_as_bool(val, dst_p);
}

bool json_dict_get_opt_int(struct JsonValue *dict, const char *key, int64_t *dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_INT, false))
		return false;
	return !val || json_value_as_int(val, dst_p);
}

bool json_dict_get_opt_float(struct JsonValue *dict, const char *key, double *dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_FLOAT, false))
		return false;
	return !val || json_value_as_float(val, dst_p);
}

bool json_dict_get_opt_string(struct JsonValue *dict, const char *key, const char **dst_p, size_t *len_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_STRING, false))
		return false;
	return !val || json_value_as_string(val, dst_p, len_p);
}

bool json_dict_get_opt_list(struct JsonValue *dict, const char *key, struct JsonValue **dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_LIST, false))
		return false;
	if (val)
		*dst_p = val;
	return true;
}

bool json_dict_get_opt_dict(struct JsonValue *dict, const char *key, struct JsonValue **dst_p)
{
	struct JsonValue *val;

	if (!dict_getter(dict, key, strlen(key), &val, JSON_DICT, false))
		return false;
	if (val)
		*dst_p = val;
	return true;
}

/*
 * Load value from list.
 */

bool json_list_get_value(struct JsonValue *list, size_t index, struct JsonValue **val_p)
{
	struct JsonValue *val;
	struct ValueList *vlist;
	size_t i;

	vlist = get_list_vlist(list);
	if (!vlist)
		return false;

	if (index >= list->u.v_size)
		return false;

	if (!vlist->array && list->u.v_size > 10)
		prepare_array(list);

	/* direct fetch */
	if (vlist->array) {
		*val_p = vlist->array[index];
		return true;
	}

	/* walk */
	val = vlist->first;
	for (i = 0; val; i++) {
		if (i == index) {
			*val_p = val;
			return true;
		}
		val = get_next(val);
	}
	return false;
}

bool json_list_is_null(struct JsonValue *list, size_t n)
{
	struct JsonValue *jv;
	if (!json_list_get_value(list, n, &jv))
		return true;
	return has_type(jv, JSON_NULL);
}

bool json_list_get_bool(struct JsonValue *list, size_t index, bool *val_p)
{
	struct JsonValue *jv;
	if (!json_list_get_value(list, index, &jv))
		return false;
	return json_value_as_bool(jv, val_p);
}

bool json_list_get_int(struct JsonValue *list, size_t index, int64_t *val_p)
{
	struct JsonValue *jv;
	if (!json_list_get_value(list, index, &jv))
		return false;
	return json_value_as_int(jv, val_p);
}

bool json_list_get_float(struct JsonValue *list, size_t index, double *val_p)
{
	struct JsonValue *jv;
	if (!json_list_get_value(list, index, &jv))
		return false;
	return json_value_as_float(jv, val_p);
}

bool json_list_get_string(struct JsonValue *list, size_t index, const char **val_p, size_t *len_p)
{
	struct JsonValue *jv;
	if (!json_list_get_value(list, index, &jv))
		return false;
	return json_value_as_string(jv, val_p, len_p);
}

bool json_list_get_list(struct JsonValue *list, size_t index, struct JsonValue **val_p)
{
	struct JsonValue *jv;
	if (!json_list_get_value(list, index, &jv))
		return false;
	if (!has_type(jv, JSON_LIST))
		return false;
	*val_p = jv;
	return true;
}

bool json_list_get_dict(struct JsonValue *list, size_t index, struct JsonValue **val_p)
{
	struct JsonValue *jv;
	if (!json_list_get_value(list, index, &jv))
		return false;
	if (!has_type(jv, JSON_DICT))
		return false;
	*val_p = jv;
	return true;
}

/*
 * Iterate over list and dict values.
 */

struct DictIterState {
	json_dict_iter_callback_f cb_func;
	void *cb_arg;
};

static bool dict_iter_helper(void *arg, void *jv)
{
	struct DictIterState *state = arg;
	struct JsonValue *key = jv;
	struct JsonValue *val = get_next(key);

	return state->cb_func(state->cb_arg, key, val);
}

bool json_dict_iter(struct JsonValue *dict, json_dict_iter_callback_f cb_func, void *cb_arg)
{
	struct DictIterState state;
	struct CBTree *tree;

	tree = get_dict_tree(dict);
	if (!tree)
		return false;

	state.cb_func = cb_func;
	state.cb_arg = cb_arg;
	return cbtree_walk(tree, dict_iter_helper, &state);
}

bool json_list_iter(struct JsonValue *list, json_list_iter_callback_f cb_func, void *cb_arg)
{
	struct JsonValue *elem;
	struct ValueList *vlist;

	vlist = get_list_vlist(list);
	if (!vlist)
		return false;

	for (elem = vlist->first; elem; elem = get_next(elem)) {
		if (!cb_func(cb_arg, elem))
			return false;
	}
	return true;
}

/*
 * Create new values.
 */

struct JsonValue *json_new_null(struct JsonContext *ctx)
{
	return mk_value(ctx, JSON_NULL, 0, false);
}

struct JsonValue *json_new_bool(struct JsonContext *ctx, bool val)
{
	struct JsonValue *jv;

	jv = mk_value(ctx, JSON_BOOL, 0, false);
	if (jv)
		jv->u.v_bool = val;
	return jv;
}

struct JsonValue *json_new_int(struct JsonContext *ctx, int64_t val)
{
	struct JsonValue *jv;

	if (val < JSON_MININT || val > JSON_MAXINT) {
		errno = ERANGE;
		return NULL;
	}

	jv = mk_value(ctx, JSON_INT, 0, false);
	if (jv)
		jv->u.v_int = val;
	return jv;
}

struct JsonValue *json_new_float(struct JsonContext *ctx, double val)
{
	struct JsonValue *jv;

	/* check if value survives JSON roundtrip */
	if (!isfinite(val))
		return false;

	jv = mk_value(ctx, JSON_FLOAT, 0, false);
	if (jv)
		jv->u.v_float = val;
	return jv;
}

struct JsonValue *json_new_string(struct JsonContext *ctx, const char *val)
{
	struct JsonValue *jv;
	size_t len;

	len = strlen(val);
	if (!utf8_validate_string(val, val + len))
		return NULL;

	jv = mk_value(ctx, JSON_STRING, len + 1, false);
	if (jv) {
		memcpy(get_cstring(jv), val, len + 1);
		jv->u.v_size = len;
	}
	return jv;
}

struct JsonValue *json_new_list(struct JsonContext *ctx)
{
	return mk_value(ctx, JSON_LIST, LIST_EXTRA, false);
}

struct JsonValue *json_new_dict(struct JsonContext *ctx)
{
	return mk_value(ctx, JSON_DICT, DICT_EXTRA, false);
}

/*
 * Add to containers
 */

bool json_list_append(struct JsonValue *list, struct JsonValue *val)
{
	if (!val)
		return false;
	if (!has_type(list, JSON_LIST))
		return false;
	if (!is_unattached(val))
		return false;
	set_parent(val, list);
	set_next(val, NULL);
	real_list_append(list, val);
	return true;
}

bool json_list_append_null(struct JsonValue *list)
{
	struct JsonValue *v;

	v = json_new_null(get_context(list));
	return json_list_append(list, v);
}

bool json_list_append_bool(struct JsonValue *list, bool val)
{
	struct JsonValue *v;

	v = json_new_bool(get_context(list), val);
	return json_list_append(list, v);
}

bool json_list_append_int(struct JsonValue *list, int64_t val)
{
	struct JsonValue *v;

	v = json_new_int(get_context(list), val);
	return json_list_append(list, v);
}

bool json_list_append_float(struct JsonValue *list, double val)
{
	struct JsonValue *v;

	v = json_new_float(get_context(list), val);
	return json_list_append(list, v);
}

bool json_list_append_string(struct JsonValue *list, const char *val)
{
	struct JsonValue *v;

	v = json_new_string(get_context(list), val);
	return json_list_append(list, v);
}

bool json_dict_put(struct JsonValue *dict, const char *key, struct JsonValue *val)
{
	struct JsonValue *kjv;
	struct JsonContainer *c;

	if (!key || !val)
		return false;
	if (!has_type(dict, JSON_DICT))
		return false;
	if (!is_unattached(val))
		return false;

	c = get_container(dict);
	kjv = json_new_string(c->c_ctx, key);
	if (!kjv)
		return false;

	if (!real_dict_add_key(c->c_ctx, dict, kjv))
		return false;

	set_next(kjv, val);
	set_next(val, NULL);

	set_parent(val, dict);

	return true;
}

bool json_dict_put_null(struct JsonValue *dict, const char *key)
{
	struct JsonValue *v;

	v = json_new_null(get_context(dict));
	return json_dict_put(dict, key, v);
}

bool json_dict_put_bool(struct JsonValue *dict, const char *key, bool val)
{
	struct JsonValue *v;

	v = json_new_bool(get_context(dict), val);
	return json_dict_put(dict, key, v);
}

bool json_dict_put_int(struct JsonValue *dict, const char *key, int64_t val)
{
	struct JsonValue *v;

	v = json_new_int(get_context(dict), val);
	return json_dict_put(dict, key, v);
}

bool json_dict_put_float(struct JsonValue *dict, const char *key, double val)
{
	struct JsonValue *v;

	v = json_new_float(get_context(dict), val);
	return json_dict_put(dict, key, v);
}

bool json_dict_put_string(struct JsonValue *dict, const char *key, const char *val)
{
	struct JsonValue *v;

	v = json_new_string(get_context(dict), val);
	return json_dict_put(dict, key, v);
}

/*
 * Main context management
 */

struct JsonContext *json_new_context(const void *cx, size_t initial_mem)
{
	struct JsonContext *ctx;
	CxMem *pool;

	pool = cx_new_pool(cx, initial_mem, 8);
	if (!pool)
		return NULL;
	ctx = cx_alloc0(pool, sizeof(*ctx));
	if (!ctx) {
		cx_destroy(pool);
		return NULL;
	}
	ctx->pool = pool;
	return ctx;
}

void json_free_context(struct JsonContext *ctx)
{
	if (ctx) {
		CxMem *pool = ctx->pool;
		memset(ctx, 0, sizeof(*ctx));
		cx_destroy(pool);
	}
}

const char *json_strerror(struct JsonContext *ctx)
{
	return ctx->lasterr;
}

void json_set_options(struct JsonContext *ctx, unsigned int options)
{
	ctx->options = options;
}
