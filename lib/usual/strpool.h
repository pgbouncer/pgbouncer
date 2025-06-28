/*
 * Pool for shared strings.
 *
 * Copyright (c) 2010  Marko Kreen, Skype Technologies OÜ
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
 * Storage for shared strings.
 *
 * This provides refcounted searchable string pool for cases
 * where lot of objects reference same strings.
 */

#ifndef _USUAL_STRPOOL_H_
#define _USUAL_STRPOOL_H_

#include <usual/cxalloc.h>

/** Handle for the pool */
struct StrPool;

/** Pooled String */
struct PStr {
	/** Parent pool */
	struct StrPool *pool;
	/** String length */
	size_t len;
	/** Reference count */
	int refcnt;
	/** Zero-terminated value */
	char str[FLEX_ARRAY];
};

/** Create new pool */
struct StrPool *strpool_create(CxMem *ca);

/** Release pool */
void strpool_free(struct StrPool *sp);

/** Return either existing or new PStr for given value */
struct PStr *strpool_get(struct StrPool *sp, const char *str, ssize_t len);

/** Increase reference count for existing PStr */
void strpool_incref(struct PStr *str);

/** Decrease reference count for existing PStr */
void strpool_decref(struct PStr *str);

/** Return count of strings in the pool */
int strpool_total(struct StrPool *sp);

#endif
