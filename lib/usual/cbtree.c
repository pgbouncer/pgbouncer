/*
 * Crit-bit tree / binary radix tree.
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

/*
 * Associates a C string with user pointer (called "obj").
 *
 * Requires it's own internal nodes, thus not embeddable
 * to user structs.
 */

#include <usual/cbtree.h>

#include <usual/bits.h>

/*
 * - Childs are either other nodes or user pointers.
 *   User pointers have lowest bit set.
 *
 * - All nodes have both childs.
 *
 * - Keys are handled as having infinite length,
 *   zero-filled after actual end.
 */

struct Node {
	struct Node *child[2];
	size_t bitpos;
};

struct CBTree {
	struct Node *root;
	cbtree_getkey_func obj_key_cb;
	cbtree_walker_func obj_free_cb;
	void *cb_ctx;

	CxMem *cx;
};

#define SAME_KEY SIZE_MAX

#define MAX_KEY (SIZE_MAX / 8)

/*
 * Low-level operations.
 */

/* does ptr point to user object or slot */
static inline bool is_node(void *ptr)
{
	return ((uintptr_t)(ptr) & 1) == 0;
}

/* flag pointer as pointing to user object */
static inline void *set_external(const void *obj)
{
	return (void*)((uintptr_t)(obj) | 1);
}

/* remove flag from user pointer */
static inline void *get_external(void *extval)
{
	return (void*)((uintptr_t)(extval) & (~1));
}

/* get specific bit from string */
static inline unsigned int get_bit(size_t bitpos, const unsigned char *key, size_t klen)
{
	size_t pos = bitpos / 8;
	unsigned int bit = 7 - (bitpos % 8);
	return (pos < klen) && (key[pos] & (1 << bit));
}

/* use callback to get key for a stored object */
static inline size_t get_key(struct CBTree *tree, void *obj, const void **key_p)
{
	return tree->obj_key_cb(tree->cb_ctx, obj, key_p);
}

/* check if object key matches argument */
static inline bool key_matches(struct CBTree *tree, void *obj, const void *key, size_t klen)
{
	const void *o_key;
	size_t o_klen;
	o_klen = get_key(tree, obj, &o_key);
	return (o_klen == klen) && (memcmp(key, o_key, klen) == 0);
}

/* Find first differing bit on 2 strings.  */
static size_t find_crit_bit(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen)
{
	unsigned char av, bv, c, pos;
	size_t i;
	size_t minlen = (alen > blen) ? blen : alen;
	size_t maxlen = (alen > blen) ? alen : blen;

	/* find differing byte in common data */
	for (i = 0; i < minlen; i++) {
		av = a[i];
		bv = b[i];
		if (av != bv)
			goto found;
	}

	/* find differing byte when one side is zero-filled */
	for (; i < maxlen; i++) {
		av = (i < alen) ? a[i] : 0;
		bv = (i < blen) ? b[i] : 0;
		if (av != bv)
			goto found;
	}
	return SAME_KEY;

found:
	/* calculate bits that differ */
	c = av ^ bv;

	/* find the first one */
	pos = 8 - fls(c);

	return i * 8 + pos;
}


/*
 * Lookup
 */

/* walk nodes until external pointer is found */
static void *raw_lookup(struct CBTree *tree, const void *key, size_t klen)
{
	struct Node *node = tree->root;
	unsigned int bit;
	while (is_node(node)) {
		bit = get_bit(node->bitpos, key, klen);
		node = node->child[bit];
	}
	return get_external(node);
}

/* actual lookup.  returns obj ptr or NULL of not found */
void *cbtree_lookup(struct CBTree *tree, const void *key, size_t klen)
{
	void *obj;

	if (!tree->root)
		return NULL;

	/* find match based on bits we know about */
	obj = raw_lookup(tree, key, klen);

	/* need to check if the object actually matches */
	if (key_matches(tree, obj, key, klen))
		return obj;

	return NULL;
}


/*
 * Insertion.
 */

/* node allocation */
static struct Node *new_node(struct CBTree *tree)
{
	struct Node *node = cx_alloc(tree->cx, sizeof(*node));
	if (!node)
		return NULL;
	memset(node, 0, sizeof(*node));
	return node;
}

/* insert into empty tree */
static bool insert_first(struct CBTree *tree, void *obj)
{
	tree->root = set_external(obj);
	return true;
}

/* insert into specific bit-position */
static bool insert_at(struct CBTree *tree, size_t newbit, const void *key, size_t klen, void *obj)
{
	/* location of current node/obj pointer under examination */
	struct Node **pos = &tree->root;
	struct Node *node;
	unsigned int bit;

	while (is_node(*pos) && ((*pos)->bitpos < newbit)) {
		bit = get_bit((*pos)->bitpos, key, klen);
		pos = &(*pos)->child[bit];
	}

	bit = get_bit(newbit, key, klen);
	node = new_node(tree);
	if (!node)
		return false;
	node->bitpos = newbit;
	node->child[bit] = set_external(obj);
	node->child[bit ^ 1] = *pos;
	*pos = node;
	return true;
}

/* actual insert: returns true -> insert ok or key found, false -> alloc failure */
bool cbtree_insert(struct CBTree *tree, void *obj)
{
	const void *key, *old_key;
	size_t newbit, klen, old_klen;
	void *old_obj;

	if (!tree->root)
		return insert_first(tree, obj);

	/* current key */
	klen = get_key(tree, obj, &key);
	if (klen > MAX_KEY)
		return false;

	/* nearest key in tree */
	old_obj = raw_lookup(tree, key, klen);
	old_klen = get_key(tree, old_obj, &old_key);

	/* first differing bit is the target position */
	newbit = find_crit_bit(key, klen, old_key, old_klen);
	if (newbit == SAME_KEY)
		return false;
	return insert_at(tree, newbit, key, klen, obj);
}


/*
 * Key deletion.
 */

/* true -> object was found and removed, false -> not found */
bool cbtree_delete(struct CBTree *tree, const void *key, size_t klen)
{
	void *obj, *tmp;
	unsigned bit = 0;
	/* location of current node/obj pointer under examination */
	struct Node **pos = &tree->root;
	/* if 'pos' has user obj, prev_pos has internal node pointing to it */
	struct Node **prev_pos = NULL;

	if (!tree->root)
		return false;

	/* match bits we know about */
	while (is_node(*pos)) {
		bit = get_bit((*pos)->bitpos, key, klen);
		prev_pos = pos;
		pos = &(*pos)->child[bit];
	}

	/* does the key actually matches */
	obj = get_external(*pos);
	if (!key_matches(tree, obj, key, klen))
		return false;

	if (tree->obj_free_cb)
		tree->obj_free_cb(tree->cb_ctx, obj);

	/* drop the internal node pointing to our key */
	if (prev_pos) {
		tmp = *prev_pos;
		*prev_pos = (*prev_pos)->child[bit ^ 1];
		cx_free(tree->cx, tmp);
	} else {
		tree->root = NULL;
	}
	return true;
}

/*
 * Management.
 */

struct CBTree *cbtree_create(cbtree_getkey_func obj_key_cb,
			     cbtree_walker_func obj_free_cb,
			     void *cb_ctx,
			     CxMem *cx)
{
	struct CBTree *tree = cx_alloc(cx, sizeof(*tree));
	if (!tree)
		return NULL;
	tree->root = NULL;
	tree->cb_ctx = cb_ctx;
	tree->obj_key_cb = obj_key_cb;
	tree->obj_free_cb = obj_free_cb;
	tree->cx = cx;
	return tree;
}

/* recursive freeing */
static void destroy_node(struct CBTree *tree, struct Node *node)
{
	if (is_node(node)) {
		destroy_node(tree, node->child[0]);
		destroy_node(tree, node->child[1]);
		cx_free(tree->cx, node);
	} else if (tree->obj_free_cb) {
		void *obj = get_external(node);
		tree->obj_free_cb(tree->cb_ctx, obj);
	}
}

/* Free tree and all it's internal nodes. */
void cbtree_destroy(struct CBTree *tree)
{
	if (tree->root)
		destroy_node(tree, tree->root);
	tree->root = NULL;
	cx_free(tree->cx, tree);
}

/*
 * walk over tree
 */

static bool walk(struct Node *node, cbtree_walker_func cb_func, void *cb_arg)
{
	if (!is_node(node))
		return cb_func(cb_arg, get_external(node));
	return walk(node->child[0], cb_func, cb_arg)
	    && walk(node->child[1], cb_func, cb_arg);
}

bool cbtree_walk(struct CBTree *tree, cbtree_walker_func cb_func, void *cb_arg)
{
	if (!tree->root)
		return true;
	return walk(tree->root, cb_func, cb_arg);
}
