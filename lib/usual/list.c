/*
 * Circular doubly linked list implementation.
 *
 * Copyright (c) 2010 Marko Kreen, Skype Technologies OÜ
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

#include <usual/list.h>

/* merge 2 ordered arrays into one */
static struct List *merge(list_cmp_f cmp_func, struct List *p, struct List *q)
{
	struct List res[1], *tail = res, *e;

	while (p && q) {
		if (cmp_func(p, q) <= 0) {
			e = p;
			p = p->next;
		} else {
			e = q;
			q = q->next;
		}
		tail->next = e;
		tail = e;
	}
	tail->next = p ? p : q;
	return res->next;
}

/*
 * non-recursive merge sort
 *
 * uses singly-linked NULL-terminated arrays internally.
 */
void list_sort(struct List *list, list_cmp_f cmp_func)
{
	int i, top = 0;
	struct List *p;
	struct List *stack[64];

	if (list_empty(list))
		return;

	/* merge small sorted fragments into larger ones */
	while (list->next != list) {
		p = list->next;
		list->next = p->next;
		p->next = NULL;

		for (i = 0; (i < top) && stack[i]; i++) {
			p = merge(cmp_func, stack[i], p);
			stack[i] = NULL;
		}

		stack[i] = p;
		if (i == top)
			top++;
	}

	/* merge remaining fragments */
	for (p = NULL, i = 0; i < top; i++)
		p = merge(cmp_func, stack[i], p);

	/* restore proper List */
	list->next = p;
	for (p = list; p->next; p = p->next)
		p->next->prev = p;
	list->prev = p;
	p->next = list;
}
