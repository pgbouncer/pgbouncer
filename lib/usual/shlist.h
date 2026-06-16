/*
 * Circular list for shared mem.
 *
 * Copyright (c) 2009  Marko Kreen
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
 * Circular list for shared mem.
 *
 * Instead of pointers, it uses offsets from list head.
 */
#ifndef _USUAL_SHLIST_H_
#define _USUAL_SHLIST_H_

#include <usual/base.h>

/* clang: pointers are hard */
#if defined(__clang__)
#define __shlist_clang_workaround__ volatile
#else
#define __shlist_clang_workaround__
#endif

/** List node/head.  Uses offsets from current node instead of direct pointers. */
struct SHList {
	ptrdiff_t next;
	ptrdiff_t prev;
};

/*
 * Calculate offset relative to base.
 *
 * Instead of using some third pointer (eg. shmem start) as base,
 * we use node itself as base.  This results in simpler APi
 * and also means that empty node appears as zero-filled.
 */

/** Get next element in list */
static inline struct SHList *shlist_get_next(const struct SHList *node)
{
	char *p = (char *)node + node->next;
	return (struct SHList *)p;
}

/** Get prev element in list */
static inline struct SHList *shlist_get_prev(const struct SHList *node)
{
	char *p = (char *)node + node->prev;
	return (struct SHList *)p;
}

static inline void _shlist_set_next(__shlist_clang_workaround__
				    struct SHList *node, const struct SHList *next)
{
	node->next = (char *)next - (char *)node;
}

static inline void _shlist_set_prev(__shlist_clang_workaround__
				    struct SHList *node, const struct SHList *prev)
{
	node->prev = (char *)prev - (char *)node;
}

/*
 * List operations.
 */

/** Initialize list head */
static inline void shlist_init(struct SHList *list)
{
	list->next = 0;
	list->prev = 0;
}

/** Insert as last element */
static inline void shlist_append(struct SHList *list, struct SHList *node)
{
	struct SHList *last;
	last = shlist_get_prev(list);
	_shlist_set_next(node, list);
	_shlist_set_prev(node, last);
	_shlist_set_next(last, node);
	_shlist_set_prev(list, node);
}

/** Insert as first element */
static inline void shlist_prepend(struct SHList *list, struct SHList *node)
{
	struct SHList *first;
	first = shlist_get_next(list);
	_shlist_set_next(node, first);
	_shlist_set_prev(node, list);
	_shlist_set_next(list, node);
	_shlist_set_prev(first, node);
}

/** Remove an node */
static inline void shlist_remove(struct SHList *node)
{
	struct SHList *next = shlist_get_next(node);
	struct SHList *prev = shlist_get_prev(node);
	_shlist_set_prev(next, prev);
	_shlist_set_next(prev, next);
	shlist_init(node);
}

/** No elements? */
static inline bool shlist_empty(const struct SHList *list)
{
	return list->next == 0;
}

/** Return first elem */
static inline struct SHList *shlist_first(const struct SHList *list)
{
	if (shlist_empty(list))
		return NULL;
	return shlist_get_next(list);
}

/** Return last elem */
static inline struct SHList *shlist_last(const struct SHList *list)
{
	if (shlist_empty(list))
		return NULL;
	return shlist_get_prev(list);
}

/** Remove first elem */
static inline struct SHList *shlist_pop(struct SHList *list)
{
	struct SHList *node = shlist_first(list);
	if (node)
		shlist_remove(node);
	return node;
}

/** Remove and return specific type of elem */
#define shlist_pop_type(list, type, field) ( \
		shlist_empty(list) ? NULL : container_of(shlist_pop(list), type, field))

/** Loop over list */
#define shlist_for_each(node, list) \
	for ((node) = shlist_get_next(list); \
	     (node) != (list); \
	     (node) = shlist_get_next(node))

/** Loop over list and allow removing node */
#define shlist_for_each_safe(node, list, tmp) \
	for ((node) = shlist_get_next(list), (tmp) = shlist_get_next(node); \
	     (node) != (list); \
	     (node) = (tmp), (tmp) = shlist_get_next(node))


#endif
