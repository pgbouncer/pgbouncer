/*
 * Primitive slab allocator.
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
 * Slab allocator for same-size objects.
 *
 * Basic behaviour:
 * - On each alloc initializer is called.
 * - if init func is not given, memset() is done
 * - init func gets either zeroed obj or old obj from _free().
 *   'struct List' on obj start is non-zero.
 *
 * ATM custom 'align' larger than malloc() alignment does not work.
 */
#ifndef _USUAL_SLAB_H_
#define _USUAL_SLAB_H_

#include <usual/cxalloc.h>

/** Reference to main */
struct Slab;

/** Signature for object init function */
typedef void (*slab_init_fn)(void *obj);

/** Create new slab context for specific size */
struct Slab *slab_create(const char *name, unsigned obj_size, unsigned align,
			 slab_init_fn init_func,
			 CxMem *cx);

/** Free whole context */
void slab_destroy(struct Slab *slab);

/** Allocate single object from slab cache */
void *slab_alloc(struct Slab *slab) _MALLOC _MUSTCHECK;

/** Release single object back */
void slab_free(struct Slab *slab, void *obj);

/** Return sum of free and used objects */
int slab_total_count(const struct Slab *slab);

/** Return number of free objects in cache */
int slab_free_count(const struct Slab *slab);

/** Return number of used objects */
int slab_active_count(const struct Slab *slab);

/** Signature for stat info callback */
typedef void (*slab_stat_fn)(void *arg, const char *slab_name,
			     unsigned size, unsigned free,
			     unsigned total);

/** Run stat info callback on all slabs */
void slab_stats(slab_stat_fn cb_func, void *cb_arg);

#endif
