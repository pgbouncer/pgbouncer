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

/** @file
 * Read and write JSON.
 *
 * Features:
 * - Robust - does not crash or assert() on invalid data.
 * - Fast memory allocation - it uses single pooled area
 *   for all objects thus alloc/free are fast.
 * - Strict UTF8 validation.
 * - Full int64_t and double passthrough, except NaN and +-Infinity.
 * - Proper number I/O even in weird locales.
 *
 * Optional features for JSON config files, off by default:
 * - Allow C comments.
 * - Allow extra comma in dict/list.
 */

#ifndef _USUAL_JSON_
#define _USUAL_JSON_

#include <usual/base.h>
#include <usual/mbuf.h>

/**
 * JSON value types
 *
 * Returned by json_value_type().
 */
enum JsonValueType {
	JSON_NULL = 1,		/**< Null value */
	JSON_BOOL,		/**< Boolean value */
	JSON_INT,		/**< Integer value */
	JSON_FLOAT,		/**< Float value */
	JSON_STRING,		/**< String value */
	JSON_LIST,		/**< JSON list */
	JSON_DICT,		/**< JSON "object", which is key->value map */
};

/** Options for JSON parser. */
enum JsonParseOptions {
	/** Default - do strict parsing.  No comments, no extra comma. */
	JSON_STRICT = 0,
	/** Allow comments, allow extra comma.  Useful for JSON in config files. */
	JSON_PARSE_RELAXED = 1,
	/** Do not validate UTF-8.  The default behavior is to validate UTF-8. */
	JSON_PARSE_IGNORE_ENCODING = 2,
};

/**
 * @struct JsonValue
 *
 * Json value
 */
struct JsonValue;

/**
 * @struct JsonContext
 *
 * Allocation context.
 */
struct JsonContext;

/** Callback for dict iterator */
typedef bool (*json_dict_iter_callback_f)(void *arg, struct JsonValue *key, struct JsonValue *val);
/** Callback for list iterator */
typedef bool (*json_list_iter_callback_f)(void *arg, struct JsonValue *elem);

/**
 * @name Allocation context.
 *
 * @{
 */

/** Create allocation context */
struct JsonContext *json_new_context(const void *cx_mem, size_t initial_mem);
/** Create allocation context */
void json_free_context(struct JsonContext *ctx);
/** Create allocation context */
const char *json_strerror(struct JsonContext *ctx);

/**
 * @}
 *
 * @name Parse JSON
 *
 * @{
 */

/** Parse JSON string */
struct JsonValue *json_parse(struct JsonContext *ctx, const char *src, size_t length);

/** Set parsing options */
void json_set_options(struct JsonContext *ctx, unsigned int options);

/**
 * @}
 *
 * @name Examine single value
 *
 * @{
 */

/** Return type for value */
enum JsonValueType json_value_type(struct JsonValue *jv);

/**
 * Return element size.
 *
 * For JSON strings, it's bytes in string, for list and
 * dict it returns number of elements.
 */
size_t json_value_size(struct JsonValue *jv);

/** Return true if value is null */
static inline bool json_value_is_null(struct JsonValue *jv)
{
	return json_value_type(jv) == JSON_NULL;
}
/** Return true if value is boolean */
static inline bool json_value_is_bool(struct JsonValue *jv)
{
	return json_value_type(jv) == JSON_BOOL;
}
/** Return true if value is int */
static inline bool json_value_is_int(struct JsonValue *jv)
{
	return json_value_type(jv) == JSON_INT;
}
/** Return true if value is float */
static inline bool json_value_is_float(struct JsonValue *jv)
{
	return json_value_type(jv) == JSON_FLOAT;
}
/** Return true if value is string */
static inline bool json_value_is_string(struct JsonValue *jv)
{
	return json_value_type(jv) == JSON_STRING;
}
/** Return true if value is list */
static inline bool json_value_is_list(struct JsonValue *jv)
{
	return json_value_type(jv) == JSON_LIST;
}
/** Return true if value is dict */
static inline bool json_value_is_dict(struct JsonValue *jv)
{
	return json_value_type(jv) == JSON_DICT;
}

/** Get bool value */
bool json_value_as_bool(struct JsonValue *jv, bool *dst_p);
/** Get int value */
bool json_value_as_int(struct JsonValue *jv, int64_t *dst_p);
/** Get double value */
bool json_value_as_float(struct JsonValue *jv, double *dst_p);
/** Get string value */
bool json_value_as_string(struct JsonValue *jv, const char **dst_p, size_t *size_p);

/**
 * @}
 *
 * @name Get values from dict
 *
 * @{
 */

/** Get key value from dict */
bool json_dict_get_value(struct JsonValue *dict, const char *key, struct JsonValue **val_p);
/** Return true if value is null or missing */
bool json_dict_is_null(struct JsonValue *jv, const char *key);
/** Get boolean value from dict */
bool json_dict_get_bool(struct JsonValue *jv, const char *key, bool *dst_p);
/** Get int value from dict */
bool json_dict_get_int(struct JsonValue *jv, const char *key, int64_t *dst_p);
/** Get float  value from dict */
bool json_dict_get_float(struct JsonValue *jv, const char *key, double *dst_p);
/** Get string value from dict */
bool json_dict_get_string(struct JsonValue *jv, const char *key, const char **dst_p, size_t *len_p);
/** Get sub-dict from dict */
bool json_dict_get_dict(struct JsonValue *jv, const char *key, struct JsonValue **dst_p);
/** Get list from dict */
bool json_dict_get_list(struct JsonValue *jv, const char *key, struct JsonValue **dst_p);

/*
 * Optional elements
 */

/** Get optional bool from dict */
bool json_dict_get_opt_bool(struct JsonValue *jv, const char *key, bool *dst_p);
/** Get optional int from dict */
bool json_dict_get_opt_int(struct JsonValue *jv, const char *key, int64_t *dst_p);
/** Get optional float from dict */
bool json_dict_get_opt_float(struct JsonValue *jv, const char *key, double *dst_p);
/** Get optional string from dict */
bool json_dict_get_opt_string(struct JsonValue *jv, const char *key, const char **dst_p, size_t *len_p);
/** Get optional list from dict */
bool json_dict_get_opt_list(struct JsonValue *jv, const char *key, struct JsonValue **dst_p);
/** Get optional dict from dict */
bool json_dict_get_opt_dict(struct JsonValue *jv, const char *key, struct JsonValue **dst_p);

/**
 * @}
 *
 * @name Get values from list.
 *
 * @{
 */

/** Get value from list */
bool json_list_get_value(struct JsonValue *list, size_t index, struct JsonValue **val_p);
/** Return true if value is null or missing */
bool json_list_is_null(struct JsonValue *list, size_t index);
/** Get bool from list */
bool json_list_get_bool(struct JsonValue *list, size_t index, bool *val_p);
/** Get int from list */
bool json_list_get_int(struct JsonValue *list, size_t index, int64_t *val_p);
/** Get float from list */
bool json_list_get_float(struct JsonValue *list, size_t index, double *val_p);
/** Get string from list */
bool json_list_get_string(struct JsonValue *list, size_t index, const char **val_p, size_t *len_p);
/** Get list value from list */
bool json_list_get_list(struct JsonValue *list, size_t index, struct JsonValue **val_p);
/** Get dict value from list */
bool json_list_get_dict(struct JsonValue *list, size_t index, struct JsonValue **val_p);

/**
 * @}
 *
 * @name Iterate over elements in list/dict.
 *
 * @{
 */

/** Walk over dict elements */
bool json_dict_iter(struct JsonValue *dict, json_dict_iter_callback_f cb_func, void *cb_arg);

/** Walk over list elements */
bool json_list_iter(struct JsonValue *list, json_list_iter_callback_f cb_func, void *cb_arg);

/**
 * @}
 *
 * @name Output JSON.
 *
 * @{
 */

/** Render JSON object as string */
bool json_render(struct MBuf *dst, struct JsonValue *jv);

/**
 * @}
 *
 * @name Create new values.
 *
 * @{
 */

/** Create NULL value */
struct JsonValue *json_new_null(struct JsonContext *ctx);
/** Create bool value */
struct JsonValue *json_new_bool(struct JsonContext *ctx, bool val);
/** Create int value */
struct JsonValue *json_new_int(struct JsonContext *ctx, int64_t val);
/** Create float value */
struct JsonValue *json_new_float(struct JsonContext *ctx, double val);
/** Create string value */
struct JsonValue *json_new_string(struct JsonContext *ctx, const char *val);
/** Create dict value */
struct JsonValue *json_new_dict(struct JsonContext *ctx);
/** Create list value */
struct JsonValue *json_new_list(struct JsonContext *ctx);

/**
 * @}
 *
 * @name Add values to containers.
 *
 * @{
 */

/** Add value to list */
bool json_list_append(struct JsonValue *list, struct JsonValue *elem);
/** Add null to list */
bool json_list_append_null(struct JsonValue *list);
/** Add bool to list */
bool json_list_append_bool(struct JsonValue *list, bool val);
/** Add int to list */
bool json_list_append_int(struct JsonValue *list, int64_t val);
/** Add float to list */
bool json_list_append_float(struct JsonValue *list, double val);
/** Add string to list */
bool json_list_append_string(struct JsonValue *list, const char *val);

/** Add element to dict */
bool json_dict_put(struct JsonValue *dict, const char *key, struct JsonValue *val);
/** Add null to dict */
bool json_dict_put_null(struct JsonValue *dict, const char *key);
/** Add bool to dict */
bool json_dict_put_bool(struct JsonValue *dict, const char *key, bool val);
/** Add int to dict */
bool json_dict_put_int(struct JsonValue *dict, const char *key, int64_t val);
/** Add float to dict */
bool json_dict_put_float(struct JsonValue *dict, const char *key, double val);
/** Add string to dict */
bool json_dict_put_string(struct JsonValue *dict, const char *key, const char *str);

/**
 * @}
 */

#endif
