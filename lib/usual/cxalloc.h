/*
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
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

/**
 * @file
 *
 * Context-based Memory Allocator.
 *
 * The idea is that each data structure is given a context to allocate from,
 * and it can create subcontext for that which can be specific allocation
 * pattern that matches the data structure.
 *
 * It is slightly more work to use than palloc (PostgreSQL) or talloc (Samba),
 * but it avoids the need to have big fully-featured framework that does
 * everything at once.
 *
 * Instead you have small task-specific allocators, and you can always fall
 * back to raw malloc if you want to valgrind the code.
 *
 * Potential variants:
 * - fully-featured pooled
 * - randomly failing
 * - logging
 * - locking
 * - guard signatures
 * - palloc / talloc like API
 */

#ifndef _USUAL_CXALLOC_H_
#define _USUAL_CXALLOC_H_

#include <usual/base.h>

/**
 * Ops for allocator that takes context.
 *
 * NB! - they are not equivalent to cx_* API.  The cx_*
 * functions do additional sanitizing.
 */
struct CxOps {
	/**
	 * Allocate memory.
	 * len will not be 0.
	 */
	void *(*c_alloc)(void *ctx, size_t len);
	/**
	 * Resize existing allocation.
	 * Both p and len will not be 0
	 */
	void *(*c_realloc)(void *ctx, void *p, size_t len);
	/**
	 * Free existing allocation.
	 * p will not be 0
	 */
	void (*c_free)(void *ctx, void *p);
	/**
	 * Release all memory in context.
	 * This is not supported by all allocators.
	 */
	void (*c_destroy)(void *ctx);
};

/**
 * Memory allocation context.
 */
struct CxMem {
	const struct CxOps *ops;
	void *ctx;
};

/** Shortcut to const CxMem */
typedef const struct CxMem CxMem;

/*
 * Basic operations on allocation context.
 */

/**
 * Allocate memory from context.
 *
 * Returns NULL if no memory or len == 0.
 */
void *cx_alloc(CxMem *cx, size_t len) _MALLOC;

/**
 * Change existing allocation.
 *
 * If ptr is NULL it creates new allocation.
 * If len is 0 it frees the memory.
 */
void *cx_realloc(CxMem *cx, void *ptr, size_t len);

/**
 * Free existing allocation.
 *
 * Does nothing if ptr is NULL.
 */
void cx_free(CxMem *cx, void *ptr);

/**
 * Release all memory allocated in context.
 *
 * Should be called only on contexts that support it.
 */
void cx_destroy(CxMem *cx);

/** Allocate and zero-fill memory */
void *cx_alloc0(CxMem *cx, size_t len) _MALLOC;

/** Allocate and copy */
void *cx_memdup(CxMem *cx, const void *src, size_t len) _MALLOC;

/** Allocate and copy string */
void *cx_strdup(CxMem *cx, const char *str) _MALLOC;

/** Print to allocated string, return length or -1 on error. */
int cx_asprintf(CxMem *cx, char **dst_p, const char *fmt, ...) _PRINTF(3, 4);

/** Print to allocated string, return length or -1 on error */
int cx_vasprintf(CxMem *cx, char **dst_p, const char *fmt, va_list ap) _PRINTF(3, 0);

/** Print to allocated string, return new string or NULL on error */
char *cx_sprintf(CxMem *cx, const char *fmt, ...) _PRINTF(2, 3);

/** Print to allocated string, return new string or NULL on error */
char *cx_vsprintf(CxMem *cx, const char *fmt, va_list ap) _PRINTF(2, 0);


/** Allocator that uses libc malloc/realloc/free */
extern CxMem cx_libc_allocator;

/** Default allocator */
#ifndef USUAL_ALLOC
#define USUAL_ALLOC (&cx_libc_allocator)
#endif

#endif
