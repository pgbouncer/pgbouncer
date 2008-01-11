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
 * Primitive slab allocator.
 *
 * - On first alloc initializer is called for all objects.
 * - On each release, cleaner is called.
 * - When giving object out, nothing is done.
 * - Writes List struct on obj header, expects it to be overwritten on use.
 */

#include <sys/param.h>

#include "bouncer.h"

#define CUSTOM_ALIGN(x, a) (((unsigned long)(x) + (a)) & ~(a))

#ifndef ALIGN
#define ALIGN(x)  CUSTOM_ALIGN(x, sizeof(long))
#endif

/*
 * Store for pre-initialized objects of one type.
 */
struct ObjectCache {
	List head;
	StatList freelist;
	StatList slablist;
	char name[32];
	unsigned final_size;
	unsigned total_count;
	obj_init_fn  init_func;
	obj_clean_fn clean_func;
};

/*
 * Header for each slab.
 */
struct Slab {
	List head;
};

/* keep track of all caches */
static STATLIST(objcache_list);

/* cache for cache headers */
static ObjectCache *objcache_cache = NULL;

/* fill struct contents */
static void init_objcache(ObjectCache *cache,
			  const char *name,
			  unsigned obj_size,
			  unsigned align,
			  obj_init_fn init_func,
			  obj_clean_fn clean_func)
{
	list_init(&cache->head);
	statlist_init(&cache->freelist, name);
	statlist_init(&cache->slablist, name);
	strlcpy(cache->name, name, sizeof(cache->name));
	cache->total_count = 0;
	cache->init_func = init_func;
	cache->clean_func = clean_func;
	statlist_append(&cache->head, &objcache_list);

	if (align == 0)
		cache->final_size = ALIGN(obj_size);
	else
		cache->final_size = CUSTOM_ALIGN(obj_size, align);
}

/* make new cache */
ObjectCache * objcache_create(const char *name,
			      unsigned obj_size,
			      unsigned align,
			      obj_init_fn init_func,
			      obj_clean_fn clean_func)
{
	ObjectCache *cache;

	/* main cache */
	if (!objcache_cache) {
		objcache_cache = malloc(sizeof(ObjectCache));
		if (!objcache_cache)
			return NULL;
		init_objcache(objcache_cache, "objcache_cache",
			      sizeof(ObjectCache), 0, NULL, NULL);
	}

	/* new cache object */
	cache = obj_alloc(objcache_cache);
	if (cache)
		init_objcache(cache, name, obj_size, align,
			      init_func, clean_func);
	return cache;
}

/* free all storage associated by cache */
void objcache_destroy(ObjectCache *cache)
{
	List *item, *tmp;
	struct Slab *slab;

	statlist_for_each_safe(item, &cache->slablist, tmp) {
		slab = container_of(item, struct Slab, head);
		free(slab);
	}
	statlist_remove(&cache->head, &objcache_list);
	memset(cache, 0, sizeof(*cache));
	obj_free(objcache_cache, cache);
}

/* add new block of objects to cache */
static void grow(ObjectCache *cache)
{
	unsigned count, i, size;
	char *area;
	struct Slab *slab;

	/* calc new slab size */
	count = cache->total_count;
	if (count < 50)
		count = 16 * 1024 / cache->final_size;
	if (count < 50)
		count = 50;
	size = count * cache->final_size;

	/* allocate & init */
	slab = malloc(size + sizeof(struct Slab));
	if (!slab)
		return;
	list_init(&slab->head);
	area = (char *)slab + sizeof(struct Slab);
	memset(area, 0, size);

	/* init objects */
	for (i = 0; i < count; i++) {
		void *obj = area + i * cache->final_size;
		List *head = (List *)obj;

		if (cache->init_func)
			cache->init_func(obj);
		list_init(head);
		statlist_append(head, &cache->freelist);
	}

	/* register to cache */
	cache->total_count += count;
	statlist_append(&slab->head, &cache->slablist);
}

/* get free object from cache */
void *obj_alloc(ObjectCache *cache)
{
	List *item = statlist_pop(&cache->freelist);
	if (!item) {
		grow(cache);
		item = statlist_pop(&cache->freelist);
	}
	if (item && !cache->init_func)
		memset(item, 0, cache->final_size);
	return item;
}

/* put object back to cache */
void obj_free(ObjectCache *cache, void *obj)
{
	List *item = obj;
	if (cache->clean_func)
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

static void run_slab_stats(ObjectCache *cache, slab_stat_fn fn, void *arg)
{
	unsigned free = statlist_count(&cache->freelist);
	fn(arg, cache->name, cache->final_size, free, cache->total_count);
}

void objcache_stats(slab_stat_fn fn, void *arg)
{
	ObjectCache *cache;
	List *item;

	statlist_for_each(item, &objcache_list) {
		cache = container_of(item, ObjectCache, head);
		run_slab_stats(cache, fn, arg);
	}
}

