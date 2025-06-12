
/*
 * Extra allocators
 */

#include <usual/cxextra.h>
#include <usual/list.h>
#include <usual/bits.h>

#include <string.h>

/*
 * Tools for allocators.
 */

static inline void *p_move(const void *p, int ofs)
{
	return (char *)p + ofs;
}


/*
 * sample exit-on-failure wrapper
 */

static void *nofail_alloc(void *next, size_t len)
{
	void *p = cx_alloc(next, len);
	if (!p)
		exit(1);
	return p;
}

static void *nofail_realloc(void *next, void *ptr, size_t len)
{
	void *p = cx_realloc(next, ptr, len);
	if (!p)
		exit(1);
	return p;
}

static void nofail_free(void *next, void *ptr)
{
	cx_free(next, ptr);
}

static void nofail_destroy(void *next)
{
	cx_destroy(next);
}

const struct CxOps cx_nofail_ops = {
	nofail_alloc,
	nofail_realloc,
	nofail_free,
	nofail_destroy,
};

const struct CxMem cx_libc_nofail = {
	&cx_nofail_ops,
	(void*)&cx_libc_allocator,
};

/*
 * Append-only pool.
 */

struct CxPoolSeg {
	struct CxPoolSeg *prev;
	unsigned char *seg_start;
	unsigned char *seg_pos;
	unsigned char *seg_end;
};

struct CxPool {
	struct CxMem this;
	const struct CxMem *parent;
	struct CxPoolSeg *last;
	unsigned char *last_ptr;
	unsigned int align;
	bool allow_free_first;

	struct CxPoolSeg first_seg;
};
#define POOL_HDR  ALIGN(sizeof(struct CxPoolSeg))

static struct CxPoolSeg *new_seg(struct CxPool *pool, size_t nsize)
{
	struct CxPoolSeg *seg;
	unsigned char *ptr;
	size_t alloc = POOL_HDR + nsize;

	seg = cx_alloc(pool->parent, alloc);
	if (seg == NULL)
		return NULL;
	ptr = (unsigned char *)seg;
	seg->seg_start = (void *)CUSTOM_ALIGN(ptr + POOL_HDR, pool->align);
	seg->seg_pos = seg->seg_start;
	seg->seg_end = (unsigned char *)seg + alloc;
	seg->prev = pool->last;
	pool->last = seg;
	pool->last_ptr = NULL;
	return seg;
}

static void *pool_alloc(void *ctx, size_t size)
{
	struct CxPool *pool = ctx;
	struct CxPoolSeg *seg = pool->last;
	void *ptr;
	unsigned nsize;

	size = CUSTOM_ALIGN(size, pool->align);
	if (seg && seg->seg_pos + size <= seg->seg_end) {
		ptr = seg->seg_pos;
		seg->seg_pos += size;
		pool->last_ptr = ptr;
		return ptr;
	} else {
		nsize = seg ? (2 * (seg->seg_end - seg->seg_start)) : 512;
		while (nsize < size)
			nsize *= 2;
		seg = new_seg(pool, nsize);
		if (!seg)
			return NULL;
		ptr = seg->seg_pos;
		seg->seg_pos += size;
		pool->last_ptr = ptr;
		return ptr;
	}
}

/* free only last item */
static void pool_free(void *ctx, void *ptr)
{
	struct CxPool *pool = ctx;
	struct CxPoolSeg *cur = pool->last;

	if (pool->last_ptr != ptr)
		return;
	cur->seg_pos = (void *)ptr;
	pool->last_ptr = NULL;
}

static size_t pool_guess_old_len(struct CxPool *pool, unsigned char *ptr)
{
	struct CxPoolSeg *seg = pool->last;
	unsigned char *cstart;

	while (seg) {
		cstart = (void *)CUSTOM_ALIGN((seg + 1), pool->align);
		if (ptr >= cstart && ptr < seg->seg_pos)
			return seg->seg_pos - ptr;
		seg = seg->prev;
	}
	return 0;
}

/* realloc only last item properly, otherwise do new alloc */
static void *pool_realloc(void *ctx, void *ptr, size_t len)
{
	struct CxPool *pool = ctx;
	struct CxPoolSeg *seg = pool->last;
	unsigned char *p = ptr;
	size_t olen;

	if (pool->last_ptr != ptr) {
		olen = pool_guess_old_len(pool, ptr);
		p = pool_alloc(ctx, len);
		if (!p)
			return NULL;
		if (olen > len)
			olen = len;
		memcpy(p, ptr, olen);
		return p;
	}

	olen = seg->seg_pos - p;
	if (seg->seg_pos - olen + len <= seg->seg_end) {
		seg->seg_pos = p + len;
		return p;
	} else {
		p = pool_alloc(ctx, len);
		if (!p)
			return NULL;
		memcpy(p, ptr, olen);
		return p;
	}
}

static void pool_destroy(void *ctx)
{
	struct CxPool *pool = ctx;
	struct CxPoolSeg *cur, *prev;
	if (!pool)
		return;
	for (cur = pool->last; cur; ) {
		prev = cur->prev;
		if (!prev)
			break;
		cx_free(pool->parent, cur);
		cur = prev;
	}
	if (pool->allow_free_first)
		cx_free(pool->parent, pool);
}

static const struct CxOps pool_ops = {
	pool_alloc,
	pool_realloc,
	pool_free,
	pool_destroy,
};

/*
 * public functions
 */

CxMem *cx_new_pool_from_area(CxMem *parent, void *buf, size_t size, bool allow_free, unsigned int align)
{
	struct CxPool *head;

	if (size < sizeof(struct CxPool))
		return NULL;
	if (align == 0)
		align = 8;
	else if (!is_power_of_2(align))
		return NULL;

	head = buf;
	memset(head, 0, sizeof(struct CxPool));

	head->parent = parent;
	head->this.ops = &pool_ops;
	head->this.ctx = head;
	head->last = &head->first_seg;
	head->allow_free_first = allow_free;
	head->align = align;

	head->first_seg.seg_start = (void *)CUSTOM_ALIGN(head + 1, align);
	head->first_seg.seg_pos = head->first_seg.seg_start;
	head->first_seg.seg_end = (unsigned char *)head + size;

	return &head->this;
}

CxMem *cx_new_pool(CxMem *parent, size_t initial_size, unsigned int align)
{
	void *area;
	size_t size;

	if (initial_size < 1024)
		initial_size = 1024;

	size = sizeof(struct CxPool) + initial_size;

	area = cx_alloc(parent, size);
	if (!area)
		return NULL;

	return cx_new_pool_from_area(parent, area, size, true, align);
}

/*
 * tree alloc
 */

#define TREE_HDR (int)(sizeof(struct CxTreeItem))

struct CxTree {
	struct CxMem this;
	CxMem *real;
	struct List alloc_list;
	struct List subtree_node;
	struct List subtree_list;
};

/* header for each allocation */
struct CxTreeItem {
	struct List node;
};

static void *tree_alloc(void *ctx, size_t len)
{
	struct CxTree *tree = ctx;
	struct CxTreeItem *item;

	item = cx_alloc(tree->real, TREE_HDR + len);
	if (!item)
		return NULL;
	list_init(&item->node);
	list_append(&tree->alloc_list, &item->node);

	return p_move(item, TREE_HDR);
}

static void *tree_realloc(void *ctx, void *ptr, size_t len)
{
	struct CxTree *t = ctx;
	struct CxTreeItem *item, *item2;
	item = p_move(ptr, -TREE_HDR);

	list_del(&item->node);
	item2 = cx_realloc(t->real, item, TREE_HDR + len);
	if (item2) {
		list_append(&t->alloc_list, &item2->node);
		return p_move(item2, TREE_HDR);
	} else {
		list_append(&t->alloc_list, &item->node);
		return NULL;
	}
}

static void tree_free(void *ctx, void *ptr)
{
	struct CxTree *t = ctx;
	struct CxTreeItem *item;

	item = p_move(ptr, -TREE_HDR);
	list_del(&item->node);
	cx_free(t->real, item);
}

static void tree_destroy(void *ctx)
{
	struct CxTree *tree = ctx, *sub;
	struct CxTreeItem *item;
	struct List *el, *tmp;

	/* unregister from parent */
	list_del(&tree->subtree_node);

	/* free elements */
	list_for_each_safe(el, &tree->alloc_list, tmp) {
		list_del(el);
		item = container_of(el, struct CxTreeItem, node);
		cx_free(tree->real, item);
	}

	/* free subtrees */
	list_for_each_safe(el, &tree->subtree_list, tmp) {
		sub = container_of(el, struct CxTree, subtree_node);
		tree_destroy(sub);
	}

	/* free base struct */
	cx_free(tree->real, tree);
}

static const struct CxOps tree_ops = {
	tree_alloc,
	tree_realloc,
	tree_free,
	tree_destroy,
};


CxMem *cx_new_tree(CxMem *cx)
{
	struct CxTree *t, *parent = NULL;
	CxMem *real = cx;

	/*
	 * Try to allocate from real allocator.  Otherwise allocations
	 * will have double headers.
	 */
	if (cx->ops == &tree_ops) {
		parent = cx->ctx;
		real = parent->real;
	}

	/* initialize */
	t = cx_alloc(real, sizeof(*t));
	if (!t)
		return NULL;
	t->real = real;
	t->this.ops = &tree_ops;
	t->this.ctx = t;
	list_init(&t->alloc_list);
	list_init(&t->subtree_node);
	list_init(&t->subtree_list);

	/* register at parent */
	if (parent)
		list_append(&parent->subtree_list, &t->subtree_node);

	return &t->this;
}
