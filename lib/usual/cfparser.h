/*
 * Copyright (c) 2007-2009 Marko Kreen, Skype Technologies OÜ
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
 * Config file parser.
 */
#ifndef _USUAL_CFPARSER_H_
#define _USUAL_CFPARSER_H_

#include <usual/base.h>

/**
 * @name Simple line-by-line parser
 * @{
 */

/** Callback signarure for @ref parse_ini_file() */
typedef bool (*cf_handler_f)(void *arg, bool is_sect, const char *key, const char *val);

/**
 * Simple parser, launches callback for each line
 */
bool parse_ini_file(const char *fn, cf_handler_f user_handler, void *arg) _MUSTCHECK;

/* @} */

/**
 * @name Complex parser with variable setting.
 * @{
 */

/** @name Per-key flags
 * @{
 */

/** The pointer is absolute */
#define CF_VAL_ABS 0

/** The pointer is relative to base */
#define CF_VAL_REL (1<<1)

/** Value must not be changed on reload */
#define CF_NO_RELOAD (1<<2)

/** Value can only be read */
#define CF_READONLY (1<<3)

/** @} */

/**
 * Helper structure for passing key info to CfOps
 */
struct CfValue {
	void *value_p;
	const void *extra;
	const char *key_name;
	char *buf;
	int buflen;
};

/**
 * Callbacks for setting and getting a variable value.
 *
 * Getter requires temp buf, returns string pointer, which
 * may or may not point to temp buf.  Getter is optional.
 */
struct CfOps {
	bool (*setter)(struct CfValue *cv, const char *value);
	const char *(*getter)(struct CfValue *cv);
	const void *op_extra;
};

/**
 * Parameter description
 */
struct CfKey {
	/** Parameter name */
	const char *key_name;
	/** Type-specific functions, called with absolute pointer */
	struct CfOps op;
	/** Flags: CF_VAL_ABS, CF_VAL_REL */
	int flags;
	/** Absolute or relative offset */
	uintptr_t key_ofs;
	/** Default value as string */
	const char *def_value;
};

/**
 * Section description
 */
struct CfSect {
	/** Section name */
	const char *sect_name;

	/** Key list */
	const struct CfKey *key_list;

	/** Get base pointer to dynamic sections (optional) */
	void *(*base_lookup)(void *top_base, const char *sect_name);

	/** Set dynamic keys (optional) */
	bool (*set_key)(void *base, const char *key, const char *val);

	/** Get dynamic keys (optional) */
	const char *(*get_key)(void *base, const char *key, char *buf, int buflen);

	/** New section callback (optional) */
	bool (*section_start)(void *top_base, const char *sect_name);
};

/**
 * Top-level config information
 */
struct CfContext {
	/** Section list */
	const struct CfSect *sect_list;
	/** Top-level base pointer, needed for relative addressing */
	void *base;
	/** If set, then CF_NO_RELOAD keys cannot be changed anymore */
	bool loaded;
};

/**
 * @name Type-specific helpers
 * @{
 */

/** Setter for string */
bool cf_set_str(struct CfValue *cv, const char *value);
/** Setter for filename */
bool cf_set_filename(struct CfValue *cv, const char *value);
/** Setter for int */
bool cf_set_int(struct CfValue *cv, const char *value);
/** Setter for unsigned int */
bool cf_set_uint(struct CfValue *cv, const char *value);
/** Setter for time-usec */
bool cf_set_time_usec(struct CfValue *cv, const char *value);
/** Setter for time-double */
bool cf_set_time_double(struct CfValue *cv, const char *value);
/** Setter for lookup */
bool cf_set_lookup(struct CfValue *cv, const char *value);

/** Getter for string */
const char *cf_get_str(struct CfValue *cv);
/** Getter for int */
const char *cf_get_int(struct CfValue *cv);
/** Getter for unsigned int */
const char *cf_get_uint(struct CfValue *cv);
/** Getter for time-usec */
const char *cf_get_time_usec(struct CfValue *cv);
/** Getter for time-double */
const char *cf_get_time_double(struct CfValue *cv);
/** Getter for int lookup */
const char *cf_get_lookup(struct CfValue *cv);

/** @} */

/**
 * @name Shortcut CfOps for well-known types
 * @{
 */

/** Ops for string */
#define CF_STR  { cf_set_str, cf_get_str }
/** Ops for filename */
#define CF_FILE { cf_set_filename, cf_get_str }
/** Ops for integer */
#define CF_INT  { cf_set_int, cf_get_int }
/** Ops for unsigned integer */
#define CF_UINT { cf_set_uint, cf_get_uint }
/** Ops for boolean */
#define CF_BOOL { cf_set_int, cf_get_int }
/** Ops for time as usec */
#define CF_TIME_USEC    { cf_set_time_usec, cf_get_time_usec }
/** Ops for time as double */
#define CF_TIME_DOUBLE  { cf_set_time_double, cf_get_time_double }
/** Ops for lookup, takes table as argument */
#define CF_LOOKUP(t)    { cf_set_lookup, cf_get_lookup, t }

/** @} */

/**
 * Lookup entry for CF_LOOKUP table.
 */
struct CfLookup {
	const char *name;
	int value;
};

/**
 * Helper to describe CfKey with absolute addressing
 */
#define CF_ABS(name, ops, var, flags, def) \
	{ name, ops, flags | CF_VAL_ABS, (uintptr_t)&(var), def }

/**
 * Helper to describe CfKey with relative addressing.
 *
 * Before using it defined CF_REL_BASE to base struct.
 *
 * The var should be field in that struct.
 *
 * @code
 * struct Foo {
 * 	char *foo_name;
 * };
 * #define CF_REL_BASE struct Foo
 * ...
 * CF_REL("name", CF_STR, foo_name, 0, NULL)
 * ...
 * #undef CF_REL_BASE
 * @endcode
 */
#define CF_REL(name, ops, var, flags, def) \
	{ name, ops, flags | CF_VAL_REL, offsetof(CF_REL_BASE, var), def }

/**
 * Load config from file.
 */
bool cf_load_file(const struct CfContext *cf, const char *fn) _MUSTCHECK;

/**
 * Get single value.
 */
const char *cf_get(const struct CfContext *cf, const char *sect, const char *var, char *buf, int buflen);

/**
 * Set single value.
 */
bool cf_set(const struct CfContext *cf, const char *sect, const char *var, const char *val);

/* @} */

#endif
