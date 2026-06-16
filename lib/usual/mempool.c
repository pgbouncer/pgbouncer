/*
 * Simple memory pool for variable-length allocations.
 *
 * Copyright (c) 2009 Marko Kreen
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

#include <usual/mempool.h>

/*
 * Allows allocation of several variable-sized objects,
 * freeing them all together.
 *
 * ToDo: make it more 'obstack'-like (???)
 * - free_last
 * - resize_last
 * - append
 */

struct MemPool {
	struct MemPool *prev;
	unsigned size;
	unsigned used;
};

void *mempool_alloc(struct MemPool **pool, unsigned size)
{
	struct MemPool *cur = *pool;
	void *ptr;
	unsigned nsize;

	size = ALIGN(size);
	if (cur && cur->used + size <= cur->size) {
		ptr = (char *)(cur + 1) + cur->used;
		cur->used += size;
		return ptr;
	} else {
		nsize = cur ? (2 * cur->size) : 512;
		while (nsize < size)
			nsize *= 2;
		cur = calloc(1, sizeof(*cur) + nsize);
		if (cur == NULL)
			return NULL;
		cur->used = size;
		cur->size = nsize;
		cur->prev = *pool;
		*pool = cur;
		return (char *)(cur + 1);
	}
}

void mempool_destroy(struct MemPool **pool)
{
	struct MemPool *cur, *tmp;
	if (!pool)
		return;
	for (cur = *pool, *pool = NULL; cur; ) {
		tmp = cur->prev;
		free(cur);
		cur = tmp;
	}
}
