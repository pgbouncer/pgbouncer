/*
 * AA-Tree - Binary tree with embeddable nodes.
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

/*
 * Self-balancing binary tree.
 *
 * Here is an implementation of AA-tree (Arne Andersson tree)
 * which is simplification of Red-Black tree.
 *
 * Red-black tree has following properties that must be kept:
 * 1. A node is either red or black.
 * 2. The root is black.
 * 3. All leaves (NIL nodes) are black.
 * 4. Both childen of red node are black.
 * 5. Every path from root to leaf contains same number of black nodes.
 *
 * AA-tree adds additional property:
 * 6. Red node can exist only as a right node.
 *
 * Red-black tree properties quarantee that the longest path is max 2x longer
 * than shortest path (B-R-B-R-B-R-B vs. B-B-B-B) thus the tree will be roughly
 * balanced.  Also it has good worst-case guarantees for insertion and deletion,
 * which makes it good tool for real-time applications.
 *
 * AA-tree removes most special cases from RB-tree, thus making resulting
 * code lot simpler.  It requires slightly more rotations when inserting
 * and deleting but also keeps the tree more balanced.
 */


#include <usual/aatree.h>

#include <stddef.h>   /* for NULL */

typedef struct AATree Tree;
typedef struct AANode Node;

/*
 * NIL node
 */
#define NIL ((struct AANode *)&_nil)
static const struct AANode _nil = { NIL, NIL, 0 };

/*
 * Rebalancing.  AA-tree needs only 2 operations
 * to keep the tree balanced.
 */

/*
 * Fix red on left.
 *
 *     X          Y
 *    /     -->    \
 *   Y              X
 *    \            /
 *     a          a
 */
static inline Node * skew(Node *x)
{
	Node *y = x->left;
	if (x->level == y->level && x != NIL) {
		x->left = y->right;
		y->right = x;
		return y;
	}
	return x;
}

/*
 * Fix 2 reds on right.
 *
 *    X                Y
 *     \              / \
 *      Y      -->   X   Z
 *     / \            \
 *    a   Z            a
 */
static inline Node * split(Node *x)
{
	Node *y = x->right;
	if (x->level == y->right->level && x != NIL) {
		x->right = y->left;
		y->left = x;
		y->level++;
		return y;
	}
	return x;
}

/* insert is easy */
static Node *rebalance_on_insert(Node *current)
{
	return split(skew(current));
}

/* remove is bit more tricky */
static Node *rebalance_on_remove(Node *current)
{
	/*
	 * Removal can create a gap in levels,
	 * fix it by lowering current->level.
	 */
	if (current->left->level < current->level - 1
	    || current->right->level < current->level - 1)
	{
		current->level--;

		/* if ->right is red, change it's level too */
		if (current->right->level > current->level)
			current->right->level = current->level;

		/* reshape, ask Arne about those */
		current = skew(current);
		current->right = skew(current->right);
		current->right->right = skew(current->right->right);
		current = split(current);
		current->right = split(current->right);
	}
	return current;
}

/*
 * Recursive insertion
 */

static Node * insert_sub(Tree *tree, Node *current, uintptr_t value, Node *node)
{
	int cmp;

	if (current == NIL) {
		/*
		 * Init node as late as possible, to avoid corrupting
		 * the tree in case it is already added.
		 */
		node->left = node->right = NIL;
		node->level = 1;

		tree->count++;
		return node;
	}

	/* recursive insert */
	cmp = tree->node_cmp(value, current);
	if (cmp > 0)
		current->right = insert_sub(tree, current->right, value, node);
	else if (cmp < 0)
		current->left = insert_sub(tree, current->left, value, node);
	else
		/* already exists? */
		return current;

	return rebalance_on_insert(current);
}

void aatree_insert(Tree *tree, uintptr_t value, Node *node)
{
	tree->root = insert_sub(tree, tree->root, value, node);
}

/*
 * Recursive removal
 */

/* remove_sub could be used for that, but want to avoid comparisions */
static Node *steal_leftmost(Tree *tree, Node *current, Node **save_p)
{
	if (current->left == NIL) {
		*save_p = current;
		return current->right;
	}

	current->left = steal_leftmost(tree, current->left, save_p);
	return rebalance_on_remove(current);
}

/* drop this node from tree */
static Node *drop_this_node(Tree *tree, Node *old)
{
	Node *new = NIL;

	if (old->left == NIL)
		new = old->right;
	else if (old->right == NIL)
		new = old->left;
	else {
		/*
		 * Picking nearest from right is better than from left,
		 * due to asymmetry of the AA-tree.  It will result in
		 * less tree operations in the long run,
		 */
		old->right = steal_leftmost(tree, old->right, &new);

		/* take old node's place */
		*new = *old;
	}

	/* cleanup for old node */
	if (tree->release_cb)
		tree->release_cb(old, tree);
	tree->count--;

	return new;
}

static Node *remove_sub(Tree *tree, Node *current, uintptr_t value)
{
	int cmp;

	/* not found? */
	if (current == NIL)
		return current;

	cmp = tree->node_cmp(value, current);
	if (cmp > 0)
		current->right = remove_sub(tree, current->right, value);
	else if (cmp < 0)
		current->left = remove_sub(tree, current->left, value);
	else
		current = drop_this_node(tree, current);

	return rebalance_on_remove(current);
}

void aatree_remove(Tree *tree, uintptr_t value)
{
	tree->root = remove_sub(tree, tree->root, value);
}

/*
 * Walking all nodes
 */

static void walk_sub(Node *current, enum AATreeWalkType wtype,
		     aatree_walker_f walker, void *arg)
{
	if (current == NIL)
		return;

	switch (wtype) {
	case AA_WALK_IN_ORDER:
		walk_sub(current->left, wtype, walker, arg);
		walker(current, arg);
		walk_sub(current->right, wtype, walker, arg);
		break;
	case AA_WALK_POST_ORDER:
		walk_sub(current->left, wtype, walker, arg);
		walk_sub(current->right, wtype, walker, arg);
		walker(current, arg);
		break;
	case AA_WALK_PRE_ORDER:
		walker(current, arg);
		walk_sub(current->left, wtype, walker, arg);
		walk_sub(current->right, wtype, walker, arg);
		break;
	}
}

/* walk tree in correct order */
void aatree_walk(Tree *tree, enum AATreeWalkType wtype, aatree_walker_f walker, void *arg)
{
	walk_sub(tree->root, wtype, walker, arg);
}

/* walk tree in bottom-up order, so that walker can destroy the nodes */
void aatree_destroy(Tree *tree)
{
	walk_sub(tree->root, AA_WALK_POST_ORDER, tree->release_cb, tree);

	/* reset tree */
	tree->root = NIL;
	tree->count = 0;
}

/* prepare tree */
void aatree_init(Tree *tree, aatree_cmp_f cmpfn, aatree_walker_f release_cb)
{
	tree->root = NIL;
	tree->count = 0;
	tree->node_cmp = cmpfn;
	tree->release_cb = release_cb;
}

/*
 * search function
 */
Node *aatree_search(Tree *tree, uintptr_t value)
{
	Node *current = tree->root;
	while (current != NIL) {
		int cmp = tree->node_cmp(value, current);
		if (cmp > 0)
			current = current->right;
		else if (cmp < 0)
			current = current->left;
		else
			return current;
	}
	return NULL;
}
