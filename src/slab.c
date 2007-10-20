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
 * SLAB-like allocator, but without the complexities of deallocation...
 *
 * - On first alloc initializer is called for all objects.
 * - On each release, cleaner is called.
 * - When giving object out, nothing is done.
 * - Writes obj header with List struct, expects it to be overwritten on use.
 */

#include "system.h"
#include "list.h"
#include "slab.h"

/*
 * Stores pre-initialized objects of one type.
 */
struct ObjectCache {
	List head;
	StatList freelist;
	const char *name;
	int obj_size;
	int align;
	int total_count;
	obj_init_fn  init_func;
	obj_clean_fn clean_func;
};

/* keep track of all caches */
static STATLIST(objcache_list);

/* make new cache */
ObjectCache * objcache_create(const char *name, int obj_size, int align,
			      obj_init_fn init_func,
			      obj_clean_fn clean_func)
{
	ObjectCache *cache = malloc(sizeof(*cache));
	if (!cache)
		return NULL;
	list_init(&cache->head);
	statlist_init(&cache->freelist, name);
	cache->name = name;
	cache->obj_size = obj_size;
	cache->align = align;
	cache->total_count = 0;
	cache->init_func = init_func;
	cache->clean_func = clean_func;
	statlist_append(&cache->head, &objcache_list);

	return cache;
}

/* add new block of objects to cache */
static void grow(ObjectCache *cache)
{
	int count, i, real_size;
	char *area;
	
	real_size = (cache->obj_size + cache->align - 1) & ~(cache->align - 1);

	count = 8192 / real_size;
	if (count < 20)
		count = 20;

	area = malloc(count * real_size);
	if (!area)
		return;

	memset(area, 0, count * real_size);
	for (i = 0; i < count; i++) {
		void *obj = area + i * real_size;
		cache->init_func(obj);
		statlist_append((List *)obj, &cache->freelist);
	}

	cache->total_count += count;
}

/* get free object from cache */
void *obj_alloc(ObjectCache *cache)
{
	List *item;

	item = statlist_pop(&cache->freelist);
	if (item)
		return item;

	grow(cache);

	return statlist_pop(&cache->freelist);
}

/* put object back to cache */
void obj_free(ObjectCache *cache, void *obj)
{
	List *item = obj;
	cache->clean_func(obj);
	statlist_prepend(item, &cache->freelist);
}

/* total number of objects allocated from cache */
int objcache_total_count(ObjectCache *cache)
{
	return cache->total_count;
}

/* free objects in cache */
int objcache_free_count(ObjectCache *cache)
{
	return statlist_count(&cache->freelist);
}

/* number of objects in use */
int objcache_active_count(ObjectCache *cache)
{
	return objcache_total_count(cache) - objcache_free_count(cache);
}

