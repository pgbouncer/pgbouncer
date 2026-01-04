/*
 * Pool for shared strings.
 *
 * Copyright (c) 2010  Marko Kreen, Skype Technologies OÜ
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

#include <usual/strpool.h>

#include <usual/cbtree.h>
#include <string.h>

/*
 * Put all strings into cbtree.
 */
struct StrPool {
	CxMem *ca;
	struct CBTree *tree;
	int count;
};

/* pass key info to cbtree */
static size_t get_key(void *ctx, void *obj, const void **dst_p)
{
	struct PStr *s = obj;
	*dst_p = s->str;
	return s->len;
}

/* free PStr obj */
static bool free_str(void *arg, void *obj)
{
	struct PStr *p = obj;
	struct StrPool *sp = p->pool;

	memset(p, 0, offsetof(struct PStr, str) + 1);
	cx_free(sp->ca, obj);
	return true;
}

/* create main structure */
struct StrPool *strpool_create(CxMem *ca)
{
	struct StrPool *sp;

	sp = cx_alloc(ca, sizeof(*sp));
	if (!sp)
		return NULL;
	sp->count = 0;
	sp->ca = ca;
	sp->tree = cbtree_create(get_key, NULL, NULL, ca);
	if (!sp->tree) {
		cx_free(ca, sp);
		return NULL;
	}
	return sp;
}

/* free main structure */
void strpool_free(struct StrPool *sp)
{
	if (sp) {
		cbtree_walk(sp->tree, free_str, sp);
		cbtree_destroy(sp->tree);
		cx_free(sp->ca, sp);
	}
}

/* return total count of strings in pool */
int strpool_total(struct StrPool *sp)
{
	return sp->count;
}

/* get new reference to str */
struct PStr *strpool_get(struct StrPool *sp, const char *str, ssize_t len)
{
	struct PStr *cstr;
	bool ok;

	if (len < 0)
		len = strlen(str);

	/* search */
	cstr = cbtree_lookup(sp->tree, str, len);
	if (cstr) {
		cstr->refcnt++;
		return cstr;
	}

	/* create */
	cstr = cx_alloc(sp->ca, sizeof(*cstr) + len + 1);
	if (!cstr)
		return NULL;
	cstr->pool = sp;
	cstr->refcnt = 1;
	cstr->len = len;
	memcpy(cstr->str, str, len + 1);

	/* insert */
	ok = cbtree_insert(sp->tree, cstr);
	if (!ok) {
		cx_free(sp->ca, cstr);
		return NULL;
	}
	sp->count++;
	return cstr;
}

/* add reference */
void strpool_incref(struct PStr *s)
{
	if (s)
		s->refcnt++;
}

/* drop reference, free if none left */
void strpool_decref(struct PStr *s)
{
	struct StrPool *sp;

	if (!s)
		return;
	Assert(s->refcnt > 0);

	s->refcnt--;
	if (s->refcnt > 0)
		return;

	/* remove */
	sp = s->pool;
	sp->count--;
	cbtree_delete(sp->tree, s->str, s->len);
	free_str(NULL, s);
}
