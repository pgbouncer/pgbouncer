/*
 * talloc.c - implementation of "talloc" API from Samba.
 *
 * Copyright (c) 2013 Marko Kreen
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

#include <usual/talloc.h>
#include <usual/cxalloc.h>
#include <usual/cxextra.h>
#include <usual/list.h>
#include <usual/bits.h>
#ifndef HAVE_STRNLEN
#include <usual/string.h>	/* needed for compat strnlen prototype  */
#endif

#include <string.h>

#define MAGIC_USED		0xF100F7	/* allocated block */
#define MAGIC_FREE		0x8600CB	/* freed block */
#define MAGIC_MASK		0xFFFFFF	/* keep only magic */

#define FLAG_PENDING		(1 << 24)	/* partially freed */
#define FLAG_USE_MEMLIMIT	(1 << 25)	/* some parent has memlimit */
#define FLAG_HAS_MEMLIMIT	(1 << 26)	/* current node has TLimit child */

/* flags parent passes to children */
#define INHERIT_FLAGS		(FLAG_USE_MEMLIMIT)

/* recursion limit */
#define TALLOC_MAX_DEPTH	10000

/* Don't deal with extreme areas */
#define TALLOC_MAXLEN	0x10000000		/* 256MB */

/* header size that is prepended to each pointer */
#define THSIZE	(sizeof(struct THeader))

/*
 * Prefix on each allocated chunk.
 *
 * child_list - internal chunks are put into start of list,
 * 		use allocations at the end.  freeing happens
 * 		from start.  this makes sure refs are freed
 * 		before other objects.
 */
struct THeader {
	uint32_t th_flags;		/* flags & magic */
	uint32_t size;			/* requested size */
	CxMem *cx;			/* low-level allocation context */
	struct THeader *parent;		/* parent node, may be NULL */
	struct List node;		/* node in parent->child_list */
	struct List child_list;		/* contains child->node */
	struct List ref_list;		/* contains TRef->ref_node */
	const char *name;		/* pointer to name string */
	talloc_destructor_f destructor;	/* function to be called on free */
};

/*
 * Per-reference struct, attached as child to non-primary parent.
 */
struct TRef {
	struct List ref_node;		/* node in ->ref_list */
	struct TRef *paired_ref;	/* track paired helper ref */
};

/*
 * Track memory limits.  Attached as child to
 * the node limits were set on.  FLAG_USE_MEMLIMIT says
 * if it needs to be checked.
 */
struct TLimit {
	ssize_t max_size;
	ssize_t cur_size;
};

/*
 * Internal helper functions.
 */

static void log_to_stderr(const char *message);
static void do_abort(const char *fmt, ...) _NORETURN;
static void do_log(const char *fmt, ...);
static void do_dbg(const char *fmt, ...);
static int ref_destructor(void *ptr);
static bool apply_memlimit(struct THeader *parent, ssize_t delta, bool force);
static void move_memlimit(struct THeader *t, struct THeader *newparent, struct THeader *oldparent);
static void *find_ptr_from_ref(const struct TRef *ref);

/*
 * Global variables.
 */

/* log callbacks */
static void (*_log_cb)(const char *message) = log_to_stderr;
static void (*_abort_cb)(const char *reason);

/* context for parent==NULL */
static void *null_context;

/* autofree context */
static void *autofree_ctx;

/* names for internal allocations */
static const char MEMLIMIT_NAME[] = ".memlimit";
static const char REF_NAME[] = ".ref";
static const char NULL_NAME[] = ".null-context";
static const char AUTOFREE_NAME[] = ".autofree";
static const char UNNAMED_NAME[] = "UNNAMED";

/* flags to atexit callback */
static int leak_report;

static int debug_level;
void talloc_set_debug(int level) { debug_level = level; }

/*
 * Internal utils.
 */

static inline bool has_flags(const struct THeader *t, uint32_t flags)
{
	return (t->th_flags & flags) > 0;
}

static inline void set_flags(struct THeader *t, uint32_t flags)
{
	t->th_flags |= flags;
}

static inline void clear_flags(struct THeader *t, uint32_t flags)
{
	t->th_flags &= ~flags;
}

static inline bool hdr_is_ref(const struct THeader *t)
{
	if (t->destructor == ref_destructor)
		return true;
	return false;
}

static inline void check_magic(const struct THeader *t, const char *pos)
{
	uint32_t magic = t->th_flags & MAGIC_MASK;
	if (magic != MAGIC_USED) {
		if (magic == MAGIC_FREE)
			do_abort("Use after free - %s", pos);
		else
			do_abort("Invalid magic - %s", pos);
	}
}

static inline void *hdr2ptr(const struct THeader *t)
{
	if (!t)
		return NULL;
	check_magic(t, "hdr2ptr");
	return (void *)(t + 1);
}

static inline struct THeader *ptr2hdr(const void *ptr)
{
	struct THeader *t;

	if (!ptr)
		return NULL;
	t = ((struct THeader *)ptr) - 1;
	check_magic(t, "ptr2hdr");
	return t;
}

static inline size_t total_size(size_t alloc)
{
	return ALIGN(alloc) + THSIZE;
}

/* if FLAG_CXOWNER is set, this->cx is for children */
static CxMem *get_owner_cx(struct THeader *t)
{
	return t->cx;
}

/* add refs to start, others to end */
static void add_child(struct THeader *parent, struct THeader *child)
{
	if (parent) {
		if (hdr_is_ref(child))
			list_prepend(&parent->child_list, &child->node);
		else
			list_append(&parent->child_list, &child->node);
	}
}

/*
 * actual alloc
 */

static struct THeader *hdr_alloc_cx(CxMem *cx, struct THeader *parent, size_t len, bool prepend)
{
	struct THeader *t;

	if (len > TALLOC_MAXLEN)
		return NULL;
	if (!parent)
		parent = ptr2hdr(null_context);

	if (!apply_memlimit(parent, total_size(len), false))
		return NULL;

	t = cx_alloc(cx, total_size(len));
	if (!t) {
		apply_memlimit(parent, -total_size(len), false);
		return NULL;
	}

	t->th_flags = MAGIC_USED;
	t->size = len;
	t->cx = cx;
	t->parent = parent;
	list_init(&t->node);
	list_init(&t->child_list);
	list_init(&t->ref_list);
	t->name = NULL;
	t->destructor = NULL;

	if (parent) {
		set_flags(t, parent->th_flags & INHERIT_FLAGS);
		if (prepend)
			list_prepend(&parent->child_list, &t->node);
		else
			list_append(&parent->child_list, &t->node);
	}
	return t;
}

/*
 * Allocate
 */

void *talloc_from_cx(CxMem *cx, size_t len, const char *name)
{
	struct THeader *t;

	t = hdr_alloc_cx(cx, NULL, len, false);
	if (!t)
		return NULL;
	t->name = name;
	return hdr2ptr(t);
}

void *_talloc_const_name(const void *parent, size_t elem_size, size_t count, bool zerofill, const char *name)
{
	struct THeader *t;
	void *res;
	size_t size;
	struct THeader *tparent;
	CxMem *cx;

	if (!safe_mul_size(&size, elem_size, count))
		return NULL;

	tparent = ptr2hdr(parent);
	cx = tparent ? tparent->cx : NULL;
	t = hdr_alloc_cx(cx, tparent, size, false);
	if (!t)
		return NULL;

	res = hdr2ptr(t);
	if (zerofill)
		memset(res, 0, size);

	t->name = name;
	return res;
}

void *_talloc_format_name(const void *parent, size_t elem_size, size_t count, bool zerofill, const char *fmt, ...)
{
	void *res;
	va_list ap;
	void *name;

	res = _talloc_const_name(parent, elem_size, count, zerofill, NULL);
	if (res) {
		va_start(ap, fmt);
		name = talloc_vasprintf(res, fmt, ap);
		va_end(ap);
		if (!name) {
			talloc_free(res);
			return NULL;
		}
		talloc_set_name_const(res, name);
	}
	return res;
}

/* alloc node and put into start of child_list */
static void *internal_alloc_prepend(const void *parent, size_t size, const char *name)
{
	struct THeader *t;
	void *res;
	struct THeader *tparent;
	CxMem *cx;

	tparent = ptr2hdr(parent);
	cx = tparent ? tparent->cx : NULL;
	t = hdr_alloc_cx(cx, tparent, size, true);
	if (!t)
		return NULL;
	res = hdr2ptr(t);
	t->name = name;
	return res;
}

/*
 * Freeing
 */

#undef talloc_set_destructor
void talloc_set_destructor(const void *ptr, talloc_destructor_f destructor)
{
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (t)
		t->destructor = destructor;
}

/* attach undying child to live parent */
static void throw_child(struct THeader *t)
{
	struct THeader *parent = t->parent;

	while (parent && has_flags(parent, FLAG_PENDING))
		parent = parent->parent;
	talloc_reparent(hdr2ptr(t->parent), hdr2ptr(parent), hdr2ptr(t));
}

static void free_children(const void *ptr, bool free_name, const char *source_pos)
{
	struct List *el, *tmp;
	struct THeader *tchild;
	struct THeader *t;
	void *child;

	t = ptr2hdr(ptr);
	if (!t)
		return;

	list_for_each_safe(el, &t->child_list, tmp) {
		tchild = container_of(el, struct THeader, node);
		child = hdr2ptr(tchild);
		if (free_name) {
			if (child == t->name)
				t->name = NULL;
		} else if (child == t->name) {
			continue;
		} else if (tchild->name == MEMLIMIT_NAME) {
			continue;
		}
		if (talloc_unlink(ptr, child) != 0) {
			//do_dbg("DBG: free_children: unlink failed: %s", talloc_get_name(child));
			throw_child(tchild);
		}
	}
}

void _talloc_free_children(const void *ptr, const char *source_pos)
{
	free_children(ptr, false, source_pos);
}

/* what happens when refs are present */
static int free_with_refs(struct THeader *t, const char *source_pos)
{
	struct List *el;
	struct TRef *ref = NULL;
	struct THeader *tref;

	if (t->parent == NULL || hdr2ptr(t->parent) == null_context) {
		return _talloc_unlink(NULL, hdr2ptr(t->parent), source_pos);
	}

	/* check if refs have same parent */
	list_for_each(el, &t->ref_list) {
		ref = container_of(el, struct TRef, ref_node);
		tref = ptr2hdr(ref);
		if (tref->parent != t->parent) {
			do_dbg("free_with_refs: parent fail");
			return -1;
		}
	}

	/* always same parent, drop one ref */
	return _talloc_free(ref, source_pos);
}

int _talloc_free(const void *ptr, const char *source_pos)
{
	CxMem *cx;
	struct THeader *t;
	struct THeader *tparent;
	size_t orig_size;

	do_dbg("DBG: talloc_free(%p) (%s)", ptr, talloc_get_name(ptr));
	if (!ptr)
		return -1;

	t = ptr2hdr(ptr);

	/* handle multi-parent free */
	if (!list_empty(&t->ref_list))
		return free_with_refs(t, source_pos);

	/* set pending flag */
	if (has_flags(t, FLAG_PENDING))
		return 0;
	set_flags(t, FLAG_PENDING);

	/* run destructor */
	if (t->destructor && t->destructor((void *)ptr) < 0) {
		do_dbg("DBG: talloc_free(%s) - destructor failed", talloc_get_name(ptr));
		clear_flags(t, FLAG_PENDING);
		return -1;
	}

	list_del(&t->node);
	free_children(ptr, true, source_pos);

	tparent = t->parent;
	orig_size = t->size;
	cx = t->cx;

	/* clear & free */
	memset(t, 0, THSIZE);
	t->size = orig_size;
	t->th_flags = MAGIC_FREE;
	t->name = source_pos;
	cx_free(cx, t);

	apply_memlimit(tparent, -total_size(orig_size), false);

	return 0;
}

/*
 * Refs
 */

static struct THeader *find_ref_by_parent(struct THeader *t, struct THeader *tparent)
{
	struct List *el;
	struct THeader *tref;
	struct TRef *ref;

	list_for_each(el, &t->ref_list) {
		ref = container_of(el, struct TRef, ref_node);
		tref = ptr2hdr(ref);
		if (tref->parent == tparent)
			return tref;
	}
	return NULL;
}

/* remove TRef from ->ref_list */
static int ref_destructor(void *ptr)
{
	struct TRef *ref = ptr;
	list_del(&ref->ref_node);
	if (ref->paired_ref) {
		ref->paired_ref->paired_ref = NULL;
		ref->paired_ref = NULL;
	}
	return 0;
}

static struct TRef *new_ref(const void *parent, const char *name)
{
	struct TRef *ref;

	ref = internal_alloc_prepend(parent, sizeof(struct TRef), name ? name : REF_NAME);
	if (!ref)
		return NULL;
	ref->paired_ref = NULL;
	list_init(&ref->ref_node);
	talloc_set_destructor(ref, ref_destructor);
	return ref;
}

void *_talloc_reference_named(const void *new_parent, const void *ptr, const char *name)
{
	struct TRef *ref;
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (!t)
		return NULL;

	ref = new_ref(new_parent, name);
	if (!ref)
		return NULL;

	list_append(&t->ref_list, &ref->ref_node);
	return (void *)ptr;
}

int _talloc_unlink(const void *parent, const void *ptr, const char *source_pos)
{
	struct TRef *ref;
	struct THeader *tref = NULL;
	struct THeader *tparent;
	struct THeader *t;
	int err;

	t = ptr2hdr(ptr);
	if (!t) {
		do_dbg("_talloc_unlink err: no ptr");
		return -1;
	}

	tparent = ptr2hdr(parent ? parent : null_context);
	if (t->parent != tparent) {
		/* ref is not primary */
		tref = find_ref_by_parent(t, tparent);
		if (tref) {
			err = _talloc_free(hdr2ptr(tref), source_pos);
		} else {
			do_dbg("_talloc_unlink err: find_ref_by_parent failed");
			err = -1;
		}
	} else if (list_empty(&t->ref_list)) {
		/* ref is primary and there are no other refs */
		err = _talloc_free(ptr, source_pos);
	} else {
		/* main parent but refs, move to new parent */
		/* use first ref to get new parent */
		ref = list_pop_type(&t->ref_list, struct TRef, ref_node);
		tref = ptr2hdr(ref);
		list_del(&t->node);

		/* move */
		t->parent = tref->parent;
		add_child(t->parent, t);

		/* free ref */
		err = _talloc_free(ref, source_pos);
	}

	return err;
}

/*
 * Parent change
 */

void *talloc_reparent(const void *old_parent, const void *new_parent, const void *ptr)
{
	struct THeader *tnew;
	struct THeader *told;
	struct THeader *t;
	CxMem *cxnew;

	t = ptr2hdr(ptr);
	if (!t)
		return NULL;

	tnew = ptr2hdr(new_parent ? new_parent : null_context);
	told = ptr2hdr(old_parent ? old_parent : null_context);
	if (tnew == t || tnew == told)
		return (void *)ptr;
	cxnew = tnew ? tnew->cx : NULL;

	/* find ref to change parent of */
	if (told != t->parent) {
		t = find_ref_by_parent(t, told);
		if (!t) {
			do_log("talloc_reparent failed: did not find old parent\n");
			return NULL;
		}
	}

	/* check cx change */
	if (t->cx != cxnew) {
		return NULL;
	}

	/* change parent */
	list_del(&t->node);
	add_child(tnew, t);
	t->parent = tnew;

	move_memlimit(t, tnew, told);

	return (void *)ptr;
}

void *talloc_steal(const void *new_parent, const void *ptr)
{
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (!t)
		return NULL;

	/* disallow steal when refs are present */
	if (!list_empty(&t->ref_list))
		return NULL;

	return talloc_reparent(hdr2ptr(t->parent), new_parent, ptr);
}

void *_talloc_move(const void *new_parent, void **ptr_p)
{
	void *ptr;

	ptr = talloc_steal(new_parent, *ptr_p);
	if (ptr)
		*ptr_p = NULL;
	return ptr;
}

/*
 * Realloc
 */

/* node address has moved */
static void fix_list(struct List *node, struct List *oldnode)
{
	if (node->next == oldnode) {
		list_init(node);
	} else {
		node->next->prev = node;
		node->prev->next = node;
	}
}

void *_talloc_realloc(const void *parent, void *ptr, size_t elem_size, size_t count, const char *name)
{
	struct THeader *t1, *t2;
	struct List *el;
	CxMem *this_cx;
	uint32_t old_flags;
	ssize_t delta;
	size_t size;

	/* calc total size */
	if (!safe_mul_size(&size, elem_size, count))
		return NULL;
	if (size > TALLOC_MAXLEN)
		return NULL;

	/* posix realloc behaviour */
	if (!ptr) {
		if (size == 0)
			return NULL;
		return talloc_named_const(parent, size, name);
	} else if (size == 0) {
		if (talloc_unlink(parent, ptr) != 0)
			if (0) do_log("realloc(size=0): unlink failed\n");
		return NULL;
	}

	t1 = ptr2hdr(ptr);

	/* disallow realloc when refs are present */
	if (!list_empty(&t1->ref_list))
		return NULL;

	/* size difference */
	delta = size - t1->size;
	if (delta == 0)
		return ptr;

	/* check limits */
	if (!apply_memlimit(t1->parent, delta, false))
		return NULL;

	/* actual realloc of memory */
	this_cx = get_owner_cx(t1);
	old_flags = t1->th_flags;
	t1->th_flags = MAGIC_FREE;
	t2 = cx_realloc(this_cx, t1, total_size(size));
	if (!t2) {
		apply_memlimit(t1->parent, -delta, false);
		t1->th_flags = old_flags;
		return NULL;
	}

	/* fix header after realloc */
	t2->th_flags = old_flags;
	t2->size = size;
	t2->name = name;

	/* was memory moved? */
	if (t1 == t2)
		return ptr;

	/* fix lists after move */
	fix_list(&t2->node, &t1->node);
	fix_list(&t2->child_list, &t1->child_list);
	fix_list(&t2->ref_list, &t1->ref_list);
	list_for_each(el, &t2->child_list) {
		struct THeader *tchild;
		tchild = container_of(el, struct THeader, node);
		tchild->parent = t2;
	}

	return hdr2ptr(t2);
}

void *talloc_realloc_fn(const void *parent, void *ptr, size_t size)
{
	return _talloc_realloc(parent, ptr, 1, size, "talloc_realloc_fn");
}

/*
 * memlimit
 */

/* apply delta to single context */
static bool apply_memlimit_marked(struct THeader *t, ssize_t delta, bool force)
{
	struct List *el;
	struct THeader *tlim;
	struct TLimit *lim = NULL;

	/* find memlimit struct */
	list_for_each(el, &t->child_list) {
		tlim = container_of(el, struct THeader, node);
		if (tlim->name == MEMLIMIT_NAME) {
			lim = hdr2ptr(tlim);
			goto apply;
		}
	}
	return true;

apply:
	/* check limit */
	if (delta > 0 && !force) {
		if (lim->cur_size + delta > lim->max_size)
			return false;
	}

	/* update parent first */
	if (!apply_memlimit(t->parent, delta, force))
		return false;

	/* parent is ok, safe to update current struct */
	lim->cur_size += delta;
	if (lim->cur_size < 0)
		lim->cur_size = 0;

	return true;
}

/* apply delta recursively */
static bool apply_memlimit(struct THeader *parent, ssize_t delta, bool force)
{
	struct THeader *t = parent;

	while (t && has_flags(t, FLAG_USE_MEMLIMIT)) {
		if (has_flags(t, FLAG_HAS_MEMLIMIT))
			return apply_memlimit_marked(t, delta, force);
		t = t->parent;
	}
	return true;
}

enum {
	OP_NONE = 0,
	OP_SET_MEMLIMIT = 1,
	OP_CLEAR_MEMLIMIT = 2,
};

/* count allocated memory and sync flags */
static size_t memlimit_walk(struct THeader *t, int depth, int op)
{
	struct List *el;
	struct THeader *tchild;
	size_t size = 0;

	if (has_flags(t, FLAG_PENDING))
		return 0;

	/* sync memlimit flags */
	if (op == OP_SET_MEMLIMIT) {
		set_flags(t, FLAG_USE_MEMLIMIT);
	} else if (op == OP_CLEAR_MEMLIMIT) {
		if (has_flags(t, FLAG_HAS_MEMLIMIT))
			op = OP_NONE;
		else
			clear_flags(t, FLAG_USE_MEMLIMIT);
	}

	/* avoid too deep recursion */
	if (depth > TALLOC_MAX_DEPTH)
		return t->size;

	/* recurse info child_list */
	set_flags(t, FLAG_PENDING);
	list_for_each(el, &t->child_list) {
		tchild = container_of(el, struct THeader, node);
		size += memlimit_walk(tchild, depth + 1, op);
	}
	clear_flags(t, FLAG_PENDING);

	return size + t->size;
}

static void move_memlimit(struct THeader *t, struct THeader *new_parent, struct THeader *old_parent)
{
	bool oldlim, newlim;
	ssize_t delta;
	int op = OP_NONE;

	/* is memlimit in use? */
	newlim = new_parent && has_flags(new_parent, FLAG_USE_MEMLIMIT);
	oldlim = old_parent && has_flags(old_parent, FLAG_USE_MEMLIMIT);
	if (!oldlim && !newlim)
		return;

	if (oldlim && !newlim)
		op = OP_CLEAR_MEMLIMIT;
	else if (newlim && !oldlim)
		op = OP_SET_MEMLIMIT;

	/* yes, calc memory size */
	delta = memlimit_walk(t, 0, op);

	/* subtract from old parent */
	if (oldlim)
		apply_memlimit(old_parent, -delta, true);

	if (newlim) {
		/* add to new parent */
		apply_memlimit(new_parent, delta, true);
		set_flags(t, FLAG_USE_MEMLIMIT);
	} else if (!has_flags(t, FLAG_HAS_MEMLIMIT)) {
		/* drop flag to avoid unnecessary walks */
		clear_flags(t, FLAG_USE_MEMLIMIT);
	}
}

/* configure memory limits */
int talloc_set_memlimit(const void *ptr, size_t max_size)
{
	struct TLimit *lim = NULL;
	struct THeader *t, *tmp;
	struct List *el;

	if (!ptr)
		return -1;
	t = ptr2hdr(ptr);

	/* find TLimit struct */
	if (has_flags(t, FLAG_HAS_MEMLIMIT)) {
		list_for_each(el, &t->child_list) {
			tmp = container_of(el, struct THeader, node);
			if (tmp->name == MEMLIMIT_NAME) {
				lim = hdr2ptr(tmp);
				break;
			}
		}
	}

	/* disable memlimit */
	if (max_size == 0) {
		clear_flags(t, FLAG_HAS_MEMLIMIT);
		if (lim)
			talloc_free(lim);
		return 0;
	}

	/* allocate new object */
	if (!lim) {
		lim = internal_alloc_prepend(ptr, sizeof(struct TLimit), MEMLIMIT_NAME);
		if (!lim)
			return -1;
	}

	/* configure */
	lim->max_size = max_size;
	lim->cur_size = 0;
	set_flags(t, FLAG_USE_MEMLIMIT | FLAG_HAS_MEMLIMIT);

	return 0;
}

/*
 * Name handling
 */

const char *talloc_get_name(const void *ptr)
{
	struct THeader *t = ptr2hdr(ptr);
	return (t && t->name) ? t->name : UNNAMED_NAME;
}

const char *talloc_set_name(const void *ptr, const char *fmt, ...)
{
	va_list ap;
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (t) {
		va_start(ap, fmt);
		t->name = talloc_vasprintf(ptr, fmt, ap);
		va_end(ap);
		return t->name;
	}
	return NULL;
}

void talloc_set_name_const(const void *ptr, const char *name)
{
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (t)
		t->name = name;
}

void *talloc_check_name(const void *ptr, const char *name)
{
	const char *curname;

	curname = talloc_get_name(ptr);
	if (curname && name && strcmp(name, curname) == 0)
		return (void *)ptr;
	return NULL;
}

void *_talloc_get_type_abort(const void *ptr, const char *name)
{
	void *res;

	res = talloc_check_name(ptr, name);
	if (res)
		return (void *)ptr;
	do_abort("wrong type");
}

/*
 * Info
 */

size_t talloc_get_size(const void *ptr)
{
	struct THeader *t;

	if (!ptr)
		return 0;

	t = ptr2hdr(ptr);
	return t->size;
}

bool talloc_is_parent(const void *parent, const void *ptr)
{
	struct THeader *tc;
	struct THeader *tp;
	int count = 0;

	if (!ptr || !parent)
		return false;

	tp = ptr2hdr(parent);
	tc = ptr2hdr(ptr);
	while (tc) {
		if (tc->parent == tp)
			return true;
		tc = tc->parent;

		/* dont bother too much */
		if (++count >= TALLOC_MAX_DEPTH)
			break;
	}
	return false;
}

size_t talloc_reference_count(const void *ptr)
{
	struct List *el;
	size_t cnt = 0;
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (t) {
		list_for_each(el, &t->ref_list)
			cnt++;
	}
	return cnt;
}

struct BytesAndCount {
	size_t bytes;
	size_t count;
};

static void calc_bytes_and_count(const void *ptr, int depth, int max_depth, int is_ref, void *cb_arg)
{
	struct BytesAndCount *state = cb_arg;

	state->count++;
	if (!is_ref) {
		state->bytes += talloc_get_size(ptr);
	}
}

size_t talloc_total_size(const void *ptr)
{
	struct BytesAndCount state;

	memset(&state, 0, sizeof(state));
	talloc_report_depth_cb(ptr, 0, TALLOC_MAX_DEPTH, calc_bytes_and_count, &state);
	return state.bytes;
}

size_t talloc_total_blocks(const void *ptr)
{
	struct BytesAndCount state;

	memset(&state, 0, sizeof(state));
	talloc_report_depth_cb(ptr, 0, TALLOC_MAX_DEPTH, calc_bytes_and_count, &state);
	return state.count;
}

void *talloc_parent(const void *ptr)
{
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (t && t->parent)
		return hdr2ptr(t->parent);
	return NULL;
}

const char *talloc_parent_name(const void *ptr)
{
	return talloc_get_name(talloc_parent(ptr));
}

void *talloc_find_parent_byname(const void *ptr, const char *name)
{
	struct List *el;
	struct THeader *tref;
	struct TRef *ref;
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (!t || !name)
		return NULL;

	if (t->parent && !strcmp(name, t->parent->name))
		return hdr2ptr(t->parent);

	list_for_each(el, &t->ref_list) {
		ref = container_of(el, struct TRef, ref_node);
		tref = ptr2hdr(ref);
		if (tref->parent && !strcmp(name, tref->parent->name))
			return hdr2ptr(tref->parent);
	}
	return NULL;
}

/*
 * String copy
 */

void *talloc_memdup(const void *parent, const void *src, size_t len)
{
	void *res = NULL;

	if (src) {
		res = talloc_named_const(parent, len, "talloc_memdup");
		if (res)
			memcpy(res, src, len);
	}
	return res;
}

char *talloc_strdup(const void *parent, const char *s)
{
	return talloc_strndup(parent, s, TALLOC_MAXLEN);
}

char *talloc_strndup(const void *parent, const char *s, size_t maxlen)
{
	size_t len;
	char *res;

	if (!s)
		return NULL;

	len = strnlen(s, maxlen);
	res = talloc_named_const(parent, len + 1, NULL);
	if (!res)
		return NULL;
	memcpy(res, s, len);
	res[len] = 0;

	talloc_set_name_const(res, res);
	return res;
}

/*
 * string append
 */

static size_t buffer_strlen(const void *ptr)
{
	size_t len = talloc_get_size(ptr);
	return len ? len - 1 : 0;
}

static char *_concat(char *ptr, bool isbuf, const char *s, size_t maxlen)
{
	size_t plen;
	size_t slen;

	/* simple cases */
	if (!ptr)
		return talloc_strndup(ptr, s, maxlen);
	if (!s)
		return ptr;

	/* get lengths */
	if (isbuf) {
		plen = buffer_strlen(ptr);
	} else {
		plen = strnlen(ptr, talloc_get_size(ptr));
	}
	slen = strnlen(s, maxlen);

	/* resize and copy */
	ptr = talloc_realloc_fn(ptr, ptr, plen + slen + 1);
	if (!ptr)
		return NULL;
	memcpy(ptr + plen, s, slen + 1);

	talloc_set_name_const(ptr, ptr);
	return ptr;
}

char *talloc_strdup_append(char *ptr, const char *s)
{
	return _concat(ptr, false, s, TALLOC_MAXLEN);
}

char *talloc_strdup_append_buffer(char *ptr, const char *s)
{
	return _concat(ptr, true, s, TALLOC_MAXLEN);
}

char *talloc_strndup_append(char *ptr, const char *s, size_t maxlen)
{
	return _concat(ptr, false, s, maxlen);
}

char *talloc_strndup_append_buffer(char *ptr, const char *s, size_t maxlen)
{
	return _concat(ptr, true, s, maxlen);
}

/*
 * printfs
 */

_PRINTF(4,0)
static char *_tprintf(const void *parent, char *ptr, size_t plen, const char *fmt, va_list ap)
{
	char buf[128];
	ssize_t len;
	va_list ap2;
	char *res;

	/* print into temp buffer */
	va_copy(ap2, ap);
	len = vsnprintf(buf, sizeof(buf), fmt, ap2);
	va_end(ap2);
	if (len < 0)
		return NULL;

	/* reserve room */
	res = talloc_realloc_fn(parent, ptr, plen + len + 1);
	if (!res)
		return NULL;

	/* fill with string */
	if (len < (int)sizeof(buf)) {
		memcpy(res + plen, buf, len + 1);
	} else {
		va_copy(ap2, ap);
		vsnprintf(res + plen, len + 1, fmt, ap2);
		va_end(ap2);
	}

	talloc_set_name_const(res, res);
	return res;
}

char *talloc_vasprintf(const void *parent, const char *fmt, va_list ap)
{
	return _tprintf(parent, NULL, 0, fmt, ap);
}

char *talloc_vasprintf_append(char *ptr, const char *fmt, va_list ap)
{
	size_t plen = strnlen(ptr, talloc_get_size(ptr));
	return _tprintf(NULL, ptr, plen, fmt, ap);
}

char *talloc_vasprintf_append_buffer(char *ptr, const char *fmt, va_list ap)
{
	size_t plen = buffer_strlen(ptr);
	return _tprintf(NULL, ptr, plen, fmt, ap);
}

char *talloc_asprintf(const void *parent, const char *fmt, ...)
{
	char *res;
	va_list ap;

	va_start(ap, fmt);
	res = talloc_vasprintf(parent, fmt, ap);
	va_end(ap);

	return res;
}

char *talloc_asprintf_append(char *ptr, const char *fmt, ...)
{
	char *res;
	va_list ap;

	va_start(ap, fmt);
	res = talloc_vasprintf_append(ptr, fmt, ap);
	va_end(ap);

	return res;
}

char *talloc_asprintf_append_buffer(char *ptr, const char *fmt, ...)
{
	char *res;
	va_list ap;

	va_start(ap, fmt);
	res = talloc_vasprintf_append_buffer(ptr, fmt, ap);
	va_end(ap);

	return res;
}

/*
 * Autofree
 */

/* run on program exit */
static void autofree_handler(void)
{
	TALLOC_FREE(autofree_ctx);
}

static int autofree_destructor(void *ptr)
{
	autofree_ctx = NULL;
	return 0;
}

/* create context, register handler with atexit */
void *talloc_autofree_context(void)
{
	static int atexit_ok;

	/* register atexit handler */
	if (!atexit_ok) {
		if (atexit(autofree_handler) != 0)
			return NULL;
		atexit_ok = 1;
	}

	/* initialize autofree top-level context */
	if (!autofree_ctx) {
		autofree_ctx = talloc_named_const(NULL, 0, AUTOFREE_NAME);
		if (!autofree_ctx)
			return NULL;
		talloc_set_destructor(autofree_ctx, autofree_destructor);
	}

	return autofree_ctx;
}

/*
 * Logging
 */

static void log_to_stderr(const char *message)
{
	fprintf(stderr, "%s\n", message);
}

_PRINTF(1, 2)
static void do_log(const char *fmt, ...)
{
	char buf[128];
	va_list ap;

	if (!_log_cb)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	_log_cb(buf);
}

_PRINTF(1, 2)
static void do_dbg(const char *fmt, ...)
{
	char buf[128];
	va_list ap;

	if (!_log_cb || debug_level == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	_log_cb(buf);
}

_PRINTF(1, 0)
static void do_abort(const char *fmt, ...)
{
	char buf[128];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (_abort_cb)
		_abort_cb(buf);
	else if (_log_cb)
		_log_cb(buf);
	abort();
}

void talloc_set_log_fn(void (*log_fn)(const char *message))
{
	_log_cb = log_fn;
}

void talloc_set_log_stderr(void)
{
	_log_cb = log_to_stderr;
}

void talloc_set_abort_fn(void (*abort_fn)(const char *reason))
{
	_abort_cb = abort_fn;
}

/*
 * Tracking.
 */

static void atexit_leak_report(void)
{
	if (leak_report == 2)
		talloc_report_full(NULL, stderr);
	else
		talloc_report(NULL, stderr);
}

/* activate null context as child of autofree context */
void talloc_enable_null_tracking(void)
{
	void *ctx;
	if (!null_context) {
		ctx = talloc_named_const(NULL, 0, NULL_NAME);
		if (ctx && autofree_ctx)
			talloc_reparent(NULL, ctx, autofree_ctx);
		null_context = ctx;
	}
}

/* activate null context */
void talloc_enable_null_tracking_no_autofree(void)
{
	if (!null_context)
		null_context = talloc_named_const(NULL, 0, NULL_NAME);
}

/* move childs away from null context */
void talloc_disable_null_tracking(void)
{
	struct THeader *t, *tchild;
	struct List *el, *tmp;

	if (!null_context)
		return;

	t = ptr2hdr(null_context);
	list_for_each_safe(el, &t->child_list, tmp) {
		tchild = container_of(el, struct THeader, node);
		list_del(&tchild->node);
		tchild->parent = NULL;
	}
	TALLOC_FREE(null_context);
}

void talloc_enable_leak_report(void)
{
	if (!leak_report)
		atexit(atexit_leak_report);
	leak_report = 1;
}

void talloc_enable_leak_report_full(void)
{
	if (!leak_report)
		atexit(atexit_leak_report);
	leak_report = 2;
}

/*
 * Reporting
 */

static void *find_ptr_from_ref(const struct TRef *ref)
{
	struct List *el;
	struct TRef *ref2;
	struct THeader *tref2;
	struct THeader *t;

	list_for_each(el, &ref->ref_node) {
		/*
		 * Actual struct is not known here - THeader
		 * must have both ->destructor & ->ref_list
		 * accessible locations.
		 */
		ref2 = container_of(el, struct TRef, ref_node);

		/* this check must work it out */
		tref2 = ((struct THeader *)ref2) - 1;
		if (hdr_is_ref(tref2))
			continue;

		/* it is not TRef, so it must be parent's THeader */
		t = container_of(el, struct THeader, ref_list);
		return hdr2ptr(t);
	}
	return NULL;
}

void talloc_report_depth_cb(const void *ptr, int depth, int max_depth,
			    void (*cb_func)(const void *ptr, int depth, int max_depth, int is_ref, void *cb_arg),
			    void *cb_arg)
{
	struct List *el;
	struct THeader *tchild;
	struct THeader *t;

	t = ptr2hdr(ptr);
	if (!t)
		t = ptr2hdr(null_context);
	if (!t)
		return;
	if (has_flags(t, FLAG_PENDING))
		return;

	/* run callback */
	if (hdr_is_ref(t)) {
		void *ptr2 = find_ptr_from_ref(ptr);
		if (ptr2)
			cb_func(ptr2, depth, max_depth, true, cb_arg);
		return;
	}
	cb_func(ptr, depth, max_depth, false, cb_arg);

	/* check depth */
	depth++;
	if (depth > max_depth)
		return;

	/* loop over childs */
	set_flags(t, FLAG_PENDING);
	list_for_each(el, &t->child_list) {
		tchild = container_of(el, struct THeader, node);
		talloc_report_depth_cb(hdr2ptr(tchild), depth, max_depth, cb_func, cb_arg);
	}
	clear_flags(t, FLAG_PENDING);
}

static void report_cb(const void *ptr, int depth, int max_depth, int is_ref, void *cb_arg)
{
	FILE *f = cb_arg;
	struct BytesAndCount state;
	const char *name;
	int indent;
	char limitbuf[128];
	struct THeader *t;

	indent = depth * 2;
	t = ptr2hdr(ptr);
	name = talloc_get_name(ptr);

	limitbuf[0] = 0;
	if (name == MEMLIMIT_NAME) {
		struct TLimit *lim = hdr2ptr(t);
		snprintf(limitbuf, sizeof(limitbuf), "%s [cur=%zu max=%zu]",
			 name, lim->cur_size, lim->max_size);
		name = limitbuf;
	}

	memset(&state, 0, sizeof(state));
	talloc_report_depth_cb(ptr, 0, TALLOC_MAX_DEPTH, calc_bytes_and_count, &state);

	if (depth == 0) {
		fprintf(f, "talloc report on '%s' (total %zu bytes in %zu blocks)%s\n",
			name, state.bytes, state.count, limitbuf);
		return;
	}
	if (is_ref) {
		fprintf(f, "%*sreference to %s\n", indent, " ", name);
		return;
	}
	fprintf(f, "%*s%-*s contains %6zu bytes in %6zu blocks%s\n",
		indent, " ",
		indent < 40 ? 40 - indent : 0, name,
		state.bytes, state.count,
		limitbuf);
}

void talloc_report_depth_file(const void *ptr, int depth, int max_depth, FILE *f)
{
	talloc_report_depth_cb(ptr, depth, max_depth, report_cb, f);
}

void talloc_report(const void *ptr, FILE *f)
{
	talloc_report_depth_file(ptr, 0, 1, f);
}

void talloc_report_full(const void *ptr, FILE *f)
{
	talloc_report_depth_file(ptr, 0, TALLOC_MAX_DEPTH, f);
}

void talloc_show_parents(const void *ptr, FILE *file)
{
	struct THeader *t, *tref;
	struct TRef *ref;
	struct List *el;
	if (!ptr) {
		fprintf(file, "No parents for NULL\n");
		return;
	}
	fprintf(file, "Parents for '%s'\n", talloc_get_name(ptr));
	t = ptr2hdr(ptr);
	if (t->parent) {
		fprintf(file, "\t%s\n", talloc_get_name(hdr2ptr(t->parent)));
	} else {
		fprintf(file, "\tNULL context\n");
	}
	list_for_each(el, &t->ref_list) {
		ref = container_of(el, struct TRef, ref_node);
		tref = ptr2hdr(ref);
		fprintf(file, "\t%s\n", talloc_get_name(hdr2ptr(tref->parent)));
	}
}

/*
 * Talloc-backed CxMem.
 *
 * Makes CxMem modules work with talloc.
 */

static void *cxt_alloc(void *ctx, size_t size)
{
	return talloc_size(ctx, size);
}

static void cxt_free(void *ctx, void *ptr)
{
	if (talloc_unlink(ctx, ptr) != 0)
		do_log("cxt_free: talloc_unlink failed\n");
}

static void *cxt_realloc(void *ctx, void *ptr, size_t len)
{
	return talloc_realloc_size(ctx, ptr, len);
}

static void cxt_destroy(void *ctx)
{
	if (talloc_free(ctx) != 0)
		do_log("cxt_destroy: talloc_free failed\n");
}

static const struct CxOps cxt_ops = {
	cxt_alloc,
	cxt_realloc,
	cxt_free,
	cxt_destroy,
};

CxMem *talloc_as_cx(const void *parent, const char *name)
{
	struct CxMem *cx;

	if (!name)
		name = ".cxmem";
	cx = talloc_named_const(parent, sizeof(struct CxMem), name);
	if (!cx)
		return NULL;
	cx->ops = &cxt_ops;
	cx->ctx = cx;
	return cx;
}
