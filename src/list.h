/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
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

/*
 * Circular doubly linked list implementation.
 *
 * Basic idea from <linux/list.h>.
 *
 * <sys/queue.h> seemed usable, but overcomplicated.
 */

#ifndef __LIST_H_
#define __LIST_H_

/* turn on slow checking */
#if defined(CASSERT) && !defined(LIST_DEBUG)
#define LIST_DEBUG
#endif

/* give offset of a field inside struct */
#ifndef offsetof
#define offsetof(type, field) ((unsigned)&(((type *)0)->field))
#endif

/* given pointer to field inside struct, return pointer to struct */
#ifndef container_of
#define container_of(ptr, type, field) ((type *)((char *)(ptr) - offsetof(type, field)))
#endif

/* list type */
typedef struct List List;
struct List {
	List *next;
	List *prev;
};

#define LIST(var) List var = { &var, &var }

/* initialize struct */
static inline void list_init(List *list)
{
	list->next = list->prev = list;
}

/* is list empty? */
static inline bool list_empty(List *list)
{
	return list->next == list;
}

/* add item to the start of the list */
static inline List *list_prepend(List *item, List *list)
{
	Assert(list_empty(item));

	item->next = list->next;
	item->prev = list;
	list->next->prev = item;
	list->next = item;
	return item;
}

/* add item to the end of the list */
static inline List *list_append(List *item, List *list)
{
	Assert(list_empty(item));

	item->next = list;
	item->prev = list->prev;
	list->prev->next = item;
	list->prev = item;
	return item;
}

/* remove item from list */
static inline List *list_del(List *item)
{
	item->prev->next = item->next;
	item->next->prev = item->prev;
	item->next = item->prev = item;
	return item;
}

/* remove first from list and return */
static inline List *list_pop(List *list)
{
	if (list_empty(list))
		return NULL;
	return list_del(list->next);
}

/* remove first from list and return */
static inline List *list_first(List *list)
{
	if (list_empty(list))
		return NULL;
	return list->next;
}

/* put all elems in one list in the start of another list */
static inline void list_prepend_list(List *src, List *dst)
{
	if (list_empty(src))
		return;
	src->next->prev = dst;
	src->prev->next = dst->next;
	dst->next->prev = src->prev;
	dst->next = src->next;

	src->next = src->prev = src;
}

/* put all elems in one list in the end of another list */
static inline void list_append_list(List *src, List *dst)
{
	if (list_empty(src))
		return;
	src->next->prev = dst->prev;
	src->prev->next = dst;
	dst->prev->next = src->next;
	dst->prev = src->prev;

	src->next = src->prev = src;
}

/* remove first elem from list and return with casting */
#define list_pop_type(list, typ, field) \
	(list_empty(list) ? NULL \
	 : container_of(list_del((list)->next), typ, field))

/* loop over list */
#define list_for_each(item, list) \
	for ((item) = (list)->next; \
	     (item) != (list); \
	     (item) = (item)->next)

/* loop over list and allow removing item */
#define list_for_each_safe(item, list, tmp) \
	for ((item) = (list)->next, (tmp) = (list)->next->next; \
	     (item) != (list); \
	     (item) = (tmp), (tmp) = (tmp)->next)

static inline bool item_in_list(List *item, List *list)
{
	List *tmp;
	list_for_each(tmp, list)
		if (tmp == item)
			return 1;
	return 0;
}


/*
 * wrapper for List that keeps track of number of items
 */

typedef struct StatList StatList;
struct StatList {
	List head;
	int cur_count;
	int max_count;
	const char *name;
};

static inline void statlist_inc_count(StatList *list, int val)
{
	list->cur_count += val;
	if (list->cur_count > list->max_count)
		list->max_count = list->cur_count;
}

#define STATLIST(var) StatList var = { {&var.head, &var.head}, 0, 0, #var }

static inline void statlist_reset(StatList *list)
{
	list->max_count = list->cur_count;
}

static inline void statlist_prepend(List *item, StatList *list)
{
	list_prepend(item, &list->head);
	statlist_inc_count(list, 1);
}

static inline void statlist_append(List *item, StatList *list)
{
	list_append(item, &list->head);
	statlist_inc_count(list, 1);
}

static inline void statlist_put_before(List *item, StatList *list, List *pos)
{
	list_append(item, pos);
	statlist_inc_count(list, 1);
}

static inline void statlist_remove(List *item, StatList *list)
{
#ifdef LIST_DEBUG
	/* sanity check */
	if (!item_in_list(item, &list->head))
		fatal("item in wrong list, expected: %s", list->name);
#endif

	list_del(item);
	list->cur_count--;

	Assert(list->cur_count >= 0);
}

static inline void statlist_init(StatList *list, const char *name)
{
	list_init(&list->head);
	list->name = name;
	list->cur_count = list->max_count = 0;
}

static inline int statlist_count(StatList *list)
{
	Assert(list->cur_count > 0 || list_empty(&list->head));
	return list->cur_count;
}

static inline int statlist_max(StatList *list)
{
	return list->max_count > list->cur_count
		? list->max_count : list->cur_count;
}

static inline List *statlist_pop(StatList *list)
{
	List *item = list_pop(&list->head);

	if (item)
		list->cur_count--;

	Assert(list->cur_count >= 0);

	return item;
}

static inline void statlist_prepend_list(StatList *src, StatList *dst)
{
	list_prepend_list(&src->head, &dst->head);
	statlist_inc_count(dst, src->cur_count);
	src->cur_count = 0;
}

static inline void statlist_append_list(StatList *src, StatList *dst)
{
	list_append_list(&src->head, &dst->head);
	statlist_inc_count(dst, src->cur_count);
	src->cur_count = 0;
}

static inline List *statlist_first(StatList *list)
{
	return list_first(&list->head);
}

static inline bool statlist_empty(StatList *list)
{
	return list_empty(&list->head);
}

#define statlist_for_each(item, list) list_for_each(item, &((list)->head))
#define statlist_for_each_safe(item, list, tmp) list_for_each_safe(item, &((list)->head), tmp)

#endif /* __LIST_H_ */

