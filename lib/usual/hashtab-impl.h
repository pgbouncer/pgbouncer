/*
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

/** @file
 * Simple customizable hashtable implementation.
 *
 * - Fixed-size hash table, open-addressed
 * - Extended by linking several together
 * - Resizable by copying.
 * - Can be lockless in multi-reader, one-writer situation if
 *   mempory barrier macros are defined.  This also requires that
 *   HashItem must not be split across cachelines.
 */

#include <usual/cxalloc.h>

#include <string.h>

#ifndef HTAB_KEY_T
/** Overridable type for key */
#define HTAB_KEY_T unsigned long
#endif
#ifndef HTAB_VAL_T
/** Overridable type for value */
#define HTAB_VAL_T void *
#endif

#ifndef HTAB_RMB
#define HTAB_RMB
#endif
#ifndef HTAB_WMB
#define HTAB_WMB
#endif

/** Typedef for key */
typedef HTAB_KEY_T htab_key_t;
/** Typedef for value */
typedef HTAB_VAL_T htab_val_t;

#ifndef HTAB_ITEM
#define HTAB_ITEM
/** HashTab slot */
struct HashItem {
	htab_key_t key;
	htab_val_t value;
};
#endif

/** Signature for comparision function */
typedef bool (*hash_cmp_fn)(const htab_val_t curval, const void *arg);

#ifndef HTAB_MAX_FILL
/** Max fill percentage */
#define HTAB_MAX_FILL 75
#endif

#define MASK(h) ((h)->size - 1)
#define CALC_POS(h, key) ((key)&MASK(h))
#define NEXT_POS(h, pos) (((pos) * 5 + 1)&MASK(h))
#define MAX_USED(h) ((h)->size * HTAB_MAX_FILL / 100)

/** Single HashTab segment */
struct HashTab {
	struct HashTab *next;
	hash_cmp_fn cmp_fn;
	CxMem *ca;
	unsigned size;
	unsigned used;
	struct HashItem tab[FLEX_ARRAY];
};

/** Initialize HashTab */
static struct HashTab *hashtab_create(unsigned size, hash_cmp_fn cmp_fn, CxMem *ca)
{
	struct HashTab *h;
	unsigned len = size * sizeof(struct HashItem) + offsetof(struct HashTab, tab);
	h = cx_alloc0(ca, len);
	if (h) {
		h->size = size;
		h->cmp_fn = cmp_fn;
		h->ca = ca;
	}
	return h;
}

/** Free HashTab */
static void hashtab_destroy(struct HashTab *h)
{
	struct HashTab *tmp;
	while (h) {
		tmp = h->next;
		cx_free(h->ca, h);
		h = tmp;
	}
}

/** Element lookup, optionally inserting new slot */
static htab_val_t *hashtab_lookup(struct HashTab *h, htab_key_t key, bool do_insert, const void *arg)
{
	unsigned pos;
	struct HashItem *i;
loop:
	/* find key, starting from pos */
	pos = CALC_POS(h, key);
	while (h->tab[pos].value) {
		i = &h->tab[pos];
		HTAB_RMB;
		if (i->key == key) {
			if (arg && h->cmp_fn(i->value, arg))
				return &i->value;
		}
		pos = NEXT_POS(h, pos);
	}

	/* not found in this one, check chained tables */
	if (h->next) {
		h = h->next;
		goto loop;
	}

	/* just lookup? */
	if (!do_insert)
		return NULL;

	/* insert */
	if (h->used >= MAX_USED(h)) {
		struct HashTab *tmp;
		tmp = hashtab_create(h->size, h->cmp_fn, h->ca);
		if (!tmp)
			return NULL;
		h->next = tmp;
		h = tmp;
		pos = CALC_POS(h, key);
	}
	h->used++;
	h->tab[pos].key = key;
	HTAB_WMB;
	return &h->tab[pos].value;
}

/* if proper pos is between src and dst, cannot move */
static bool _hashtab_slot_can_move(struct HashTab *h, unsigned dstpos, unsigned srcpos)
{
	htab_key_t key = h->tab[srcpos].key;
	unsigned pos, kpos = CALC_POS(h, key);
	if (kpos == srcpos)
		return false;
	if (kpos == dstpos)
		return true;
	for (pos = NEXT_POS(h, dstpos); pos != srcpos; pos = NEXT_POS(h, pos)) {
		if (pos == kpos)
			return false;
	}
	return true;
}

/** Delete an element */
static void hashtab_delete(struct HashTab *h, htab_key_t key, void *arg)
{
	htab_val_t *vptr;
	struct HashItem *hd;
	unsigned pos, dstpos;

	/* find it */
	vptr = hashtab_lookup(h, key, false, arg);
	if (!vptr)
		return;

	/* find right tab */
	hd = container_of(vptr, struct HashItem, value);
	while (h && ((hd < h->tab) || (hd >= h->tab + h->size)))
		h = h->next;

	/* calculate index */
	dstpos = hd - h->tab;

loop:
	/* move slot */
	for (pos = NEXT_POS(h, dstpos); h->tab[pos].value; pos = NEXT_POS(h, pos)) {
		if (_hashtab_slot_can_move(h, dstpos, pos)) {
			h->tab[dstpos].key = h->tab[pos].key;
			h->tab[dstpos].value = h->tab[pos].value;
			dstpos = pos;
			goto loop;
		}
	}
	h->tab[dstpos].value = 0;
	HTAB_WMB;
	h->tab[dstpos].key = 0;
	h->used--;
}

/** Count elements and fragments */
static void hashtab_stats(struct HashTab *h, unsigned *nitem_p, unsigned *ntab_p)
{
	unsigned n = 0, l = 0;
	while (h) {
		l++;
		n += h->used;
		h = h->next;
	}
	*nitem_p = n;
	*ntab_p = l;
}

/** Copy elements to new hashtab, perhaps with different size */
static struct HashTab *hashtab_copy(struct HashTab *h_old, unsigned newsize)
{
	struct HashTab *h_new;
	unsigned i;

	h_new = hashtab_create(newsize, h_old->cmp_fn, h_old->ca);
	for (; h_old; h_old = h_old->next) {
		for (i = 0; i < h_old->size; i++) {
			struct HashItem *s = &h_old->tab[i];
			htab_val_t *new_pos;
			if (s->value) {
				new_pos = hashtab_lookup(h_new, s->key, true, NULL);
				if (!new_pos)
					goto err;
				*new_pos = s->value;
			}
		}
	}
	return h_new;
err:
	hashtab_destroy(h_new);
	return NULL;
}

/* example, and avoid "unused" warnings */
static inline void _hashtab_example(void)
{
	unsigned nitem, nlink;
	struct HashTab *h, *h2;

	h = hashtab_create(1024, NULL, NULL);
	hashtab_lookup(h, 123, true, NULL);
	hashtab_stats(h, &nitem, &nlink);
	h2 = hashtab_copy(h, 2048);
	hashtab_delete(h, 123, NULL);
	hashtab_destroy(h);
	hashtab_destroy(h2);
}
