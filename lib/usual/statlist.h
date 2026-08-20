/*
 * Wrapper for list.h that keeps track of number of items.
 *
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
 * Circular list that keep track of stats about the list.
 *
 * Currenly only count of abjects currently in list
 * is kept track of.  The plan was to track more,
 * like max, but it was not useful enough.
 */
#ifndef _USUAL_STATLIST_H_
#define _USUAL_STATLIST_H_

#include <usual/list.h>

/**
 * Header structure for StatList.
 */
struct StatList {
	/** Actual list head */
	struct List head;
	/** Count of objects currently in list */
	int cur_count;
#ifdef LIST_DEBUG
	/** List name */
	const char *name;
#endif
};

/** Define and initialize StatList head */
#ifdef LIST_DEBUG
#define STATLIST(var) struct StatList var = {{&var.head, &var.head}, 0, #var }
#else
#define STATLIST(var) struct StatList var = {{&var.head, &var.head}, 0 }
#endif

/** Add to the start of the list */
static inline void statlist_prepend(struct StatList *list, struct List *item)
{
	list_prepend(&list->head, item);
	list->cur_count++;
}

/** Add to the end of the list */
static inline void statlist_append(struct StatList *list, struct List *item)
{
	list_append(&list->head, item);
	list->cur_count++;
}

/** Remove element from the list */
static inline void statlist_remove(struct StatList *list, struct List *item)
{
	list_del(item);
	list->cur_count--;

	/* Assert(list->cur_count >= 0); */
}

/** Initialize StatList head */
static inline void statlist_init(struct StatList *list, const char *name)
{
	list_init(&list->head);
	list->cur_count = 0;
#ifdef LIST_DEBUG
	list->name = name;
#endif
}

/** return number of elements currently in list */
static inline int statlist_count(const struct StatList *list)
{
	/* Assert(list->cur_count > 0 || list_empty(&list->head)); */
	return list->cur_count;
}

/** remove and return first element */
static inline struct List *statlist_pop(struct StatList *list)
{
	struct List *item = list_pop(&list->head);

	if (item)
		list->cur_count--;

	/* Assert(list->cur_count >= 0); */

	return item;
}

/** Return first element */
static inline struct List *statlist_first(const struct StatList *list)
{
	return list_first(&list->head);
}

/** Return last element */
static inline struct List *statlist_last(const struct StatList *list)
{
	return list_last(&list->head);
}

/** Is list empty */
static inline bool statlist_empty(const struct StatList *list)
{
	return list_empty(&list->head);
}

/** Loop over list */
#define statlist_for_each(item, list) list_for_each(item, &((list)->head))

/** Loop over list backwards */
#define statlist_for_each_reverse(item, list) list_for_each_reverse(item, &((list)->head))

/** Loop over list safely, so that elements can be removed during */
#define statlist_for_each_safe(item, list, tmp) list_for_each_safe(item, &((list)->head), tmp)

/** Loop over list backwards safely, so that elements can be removed during */
#define statlist_for_each_reverse_safe(item, list, tmp) list_for_each_reverse_safe(item, &((list)->head), tmp)

/** Put intem before another */
static inline void statlist_put_before(struct StatList *list, struct List *item, struct List *pos)
{
	list_append(pos, item);
	list->cur_count++;
}

/** Put item after another */
static inline void statlist_put_after(struct StatList *list, struct List *item, struct List *pos)
{
	list_prepend(pos, item);
	list->cur_count++;
}

#endif /* __LIST_H_ */
