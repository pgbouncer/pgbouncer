/*
 * Circular doubly linked list implementation.
 *
 * Copyright (c) 2007 Marko Kreen, Skype Technologies OÜ
 *
 * Permission to use, copy, modify, and distribute this software for any
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
 * Circular doubly linked list.
 */

#ifndef _USUAL_LIST_H_
#define _USUAL_LIST_H_

#include <usual/base.h>

/**
 * Structure for both list nodes and heads.
 *
 * It is meant to be embedded in parent structure,
 * which can be acquired with container_of().
 */
struct List {
	/** Pointer to next node or head. */
	struct List *next;
	/** Pointer to previous node or head. */
	struct List *prev;
};

/** Define and initialize emtpy list head */
#define LIST(var) struct List var = { &var, &var }

/** Initialize empty list head. */
static inline void list_init(struct List *list)
{
	list->next = list->prev = list;
}

/** Is list empty? */
static inline int list_empty(const struct List *list)
{
	return list->next == list;
}

/** Add item to the start of the list */
static inline struct List *list_prepend(struct List *list, struct List *item)
{
	item->next = list->next;
	item->prev = list;
	list->next->prev = item;
	list->next = item;
	return item;
}

/** Add item to the end of the list */
static inline struct List *list_append(struct List *list, struct List *item)
{
	item->next = list;
	item->prev = list->prev;
	list->prev->next = item;
	list->prev = item;
	return item;
}

/** Remove item from list */
static inline struct List *list_del(struct List *item)
{
	item->prev->next = item->next;
	item->next->prev = item->prev;
	item->next = item->prev = item;
	return item;
}

/** Remove first from list and return */
static inline struct List *list_pop(struct List *list)
{
	if (list_empty(list))
		return NULL;
	return list_del(list->next);
}

/** Get first elem from list */
static inline struct List *list_first(const struct List *list)
{
	if (list_empty(list))
		return NULL;
	return list->next;
}

/** Get last elem from list */
static inline struct List *list_last(const struct List *list)
{
	if (list_empty(list))
		return NULL;
	return list->prev;
}

/** Remove first elem from list and return with casting */
#define list_pop_type(list, typ, field) \
	(list_empty(list) ? NULL \
	 : container_of(list_del((list)->next), typ, field))

/** Loop over list */
#define list_for_each(item, list) \
	for ((item) = (list)->next; \
	     (item) != (list); \
	     (item) = (item)->next)

/** Loop over list backwards */
#define list_for_each_reverse(item, list) \
	for ((item) = (list)->prev; \
	     (item) != (list); \
	     (item) = (item)->prev)

/** Loop over list and allow removing item */
#define list_for_each_safe(item, list, tmp) \
	for ((item) = (list)->next, (tmp) = (list)->next->next; \
	     (item) != (list); \
	     (item) = (tmp), (tmp) = (tmp)->next)

/** Loop over list backwards and allow removing item */
#define list_for_each_reverse_safe(item, list, tmp) \
	for ((item) = (list)->prev, (tmp) = (list)->prev->prev; \
	     (item) != (list); \
	     (item) = (tmp), (tmp) = (tmp)->prev)

/** Comparator function signature for list_sort() */
typedef int (*list_cmp_f)(const struct List *a, const struct List *b);

/**
 * Sort list.
 *
 * This implementation uses stable merge sort which operates in-place.
 */
void list_sort(struct List *list, list_cmp_f cmp_func);

#endif
