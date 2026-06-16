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

#include <usual/slab.h>

#include <string.h>

#include <usual/statlist.h>

#ifndef USUAL_FAKE_SLAB

/*
 * Store for pre-initialized objects of one type.
 */
struct Slab {
	struct List head;
	struct StatList freelist;
	struct StatList fraglist;
	char name[32];
	unsigned final_size;
	unsigned total_count;
	slab_init_fn init_func;
	CxMem *cx;
};


/*
 * Header for each slab.
 */
struct SlabFrag {
	struct List head;
};

/* keep track of all active slabs */
static STATLIST(slab_list);

static void slab_list_append(struct Slab *slab)
{
#ifndef _REENTRANT
	statlist_append(&slab_list, &slab->head);
#endif
}

static void slab_list_remove(struct Slab *slab)
{
#ifndef _REENTRANT
	statlist_remove(&slab_list, &slab->head);
#endif
}

/* fill struct contents */
static void init_slab(struct Slab *slab, const char *name, unsigned obj_size,
		      unsigned align, slab_init_fn init_func,
		      CxMem *cx)
{
	unsigned slen = strlen(name);

	list_init(&slab->head);
	statlist_init(&slab->freelist, name);
	statlist_init(&slab->fraglist, name);
	slab->total_count = 0;
	slab->init_func = init_func;
	slab->cx = cx;

	if (slen >= sizeof(slab->name))
		slen = sizeof(slab->name) - 1;
	memcpy(slab->name, name, slen);
	slab->name[slen] = 0;

	/* don't allow too small align, as we want to put pointers into area */
	if (align < sizeof(long))
		align = 0;

	/* actual area for one object */
	if (align == 0)
		slab->final_size = ALIGN(obj_size);
	else
		slab->final_size = CUSTOM_ALIGN(obj_size, align);

	/* allow small structs */
	if (slab->final_size < sizeof(struct List))
		slab->final_size = sizeof(struct List);

	slab_list_append(slab);
}

/* make new slab */
struct Slab *slab_create(const char *name, unsigned obj_size, unsigned align,
			 slab_init_fn init_func,
			 CxMem *cx)
{
	struct Slab *slab;

	/* new slab object */
	slab = cx_alloc0(cx, sizeof(*slab));
	if (slab)
		init_slab(slab, name, obj_size, align, init_func, cx);
	return slab;
}

/* free all storage associated by slab */
void slab_destroy(struct Slab *slab)
{
	struct List *item, *tmp;
	struct SlabFrag *frag;

	if (!slab)
		return;

	slab_list_remove(slab);
	statlist_for_each_safe(item, &slab->fraglist, tmp) {
		frag = container_of(item, struct SlabFrag, head);
		cx_free(slab->cx, frag);
	}
	cx_free(slab->cx, slab);
}

/* add new block of objects to slab */
static void grow(struct Slab *slab)
{
	unsigned count, i, size;
	char *area;
	struct SlabFrag *frag;

	/* calc new slab size */
	count = slab->total_count;
	if (count < 50)
		count = 16 * 1024 / slab->final_size;
	if (count < 50)
		count = 50;
	size = count * slab->final_size;

	/* allocate & init */
	frag = cx_alloc0(slab->cx, size + sizeof(struct SlabFrag));
	if (!frag)
		return;
	list_init(&frag->head);
	area = (char *)frag + sizeof(struct SlabFrag);

	/* init objects */
	for (i = 0; i < count; i++) {
		void *obj = area + i * slab->final_size;
		struct List *head = (struct List *)obj;
		list_init(head);
		statlist_append(&slab->freelist, head);
	}

	/* register to slab */
	slab->total_count += count;
	statlist_append(&slab->fraglist, &frag->head);
}

/* get free object from slab */
void *slab_alloc(struct Slab *slab)
{
	struct List *item = statlist_pop(&slab->freelist);
	if (!item) {
		grow(slab);
		item = statlist_pop(&slab->freelist);
	}
	if (item) {
		if (slab->init_func)
			slab->init_func(item);
		else
			memset(item, 0, slab->final_size);
	}
	return item;
}

/* put object back to slab */
void slab_free(struct Slab *slab, void *obj)
{
	struct List *item = obj;
	list_init(item);
	statlist_prepend(&slab->freelist, item);
}

/* total number of objects allocated from slab */
int slab_total_count(const struct Slab *slab)
{
	return slab->total_count;
}

/* free objects in slab */
int slab_free_count(const struct Slab *slab)
{
	return statlist_count(&slab->freelist);
}

/* number of objects in use */
int slab_active_count(const struct Slab *slab)
{
	return slab_total_count(slab) - slab_free_count(slab);
}

static void run_slab_stats(struct Slab *slab, slab_stat_fn cb_func, void *cb_arg)
{
	unsigned free = statlist_count(&slab->freelist);
	cb_func(cb_arg, slab->name, slab->final_size, free, slab->total_count);
}

/* call a function for all active slabs */
void slab_stats(slab_stat_fn cb_func, void *cb_arg)
{
	struct Slab *slab;
	struct List *item;

	statlist_for_each(item, &slab_list) {
		slab = container_of(item, struct Slab, head);
		run_slab_stats(slab, cb_func, cb_arg);
	}
}

#else

struct Slab {
	int size;
	struct StatList obj_list;
	slab_init_fn init_func;
	CxMem *cx;
};


struct Slab *slab_create(const char *name, unsigned obj_size, unsigned align,
			 slab_init_fn init_func,
			 CxMem *cx)
{
	struct Slab *s = cx_alloc(cx, sizeof(*s));
	if (s) {
		s->size = obj_size;
		s->init_func = init_func;
		s->cx = cx;
		statlist_init(&s->obj_list, "obj_list");
	}
	return s;
}

void slab_destroy(struct Slab *slab)
{
	struct List *el, *tmp;
	statlist_for_each_safe(el, &slab->obj_list, tmp) {
		statlist_remove(&slab->obj_list, el);
		cx_free(slab->cx, el);
	}
	cx_free(slab->cx, slab);
}

void *slab_alloc(struct Slab *slab)
{
	struct List *o;
	void *res;
	o = cx_alloc(slab->cx, sizeof(struct List) + slab->size);
	if (!o)
		return NULL;
	list_init(o);
	statlist_append(&slab->obj_list, o);
	res = (void *)(o + 1);
	if (slab->init_func)
		slab->init_func(res);
	return res;
}

void slab_free(struct Slab *slab, void *obj)
{
	if (obj) {
		struct List *el = obj;
		statlist_remove(&slab->obj_list, el - 1);
		cx_free(slab->cx, el - 1);
	}
}

int slab_total_count(const struct Slab *slab)
{
	return 0;
}
int slab_free_count(const struct Slab *slab)
{
	return 0;
}
int slab_active_count(const struct Slab *slab)
{
	return 0;
}
void slab_stats(slab_stat_fn cb_func, void *cb_arg)
{
}


#endif
