/*
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

/** @file
 *
 * AA-Tree - Binary tree with embeddable nodes.
 *
 * AA-Tree (Arne Andersson tree) is a simplified Red-Black tree.
 */

#ifndef _USUAL_AATREE_H_
#define _USUAL_AATREE_H_

#include <usual/base.h>

struct AATree;
struct AANode;

/** Callback for node comparision against value */
typedef int (*aatree_cmp_f)(uintptr_t, struct AANode *node);

/** Callback for walking the tree */
typedef void (*aatree_walker_f)(struct AANode *n, void *arg);

/**
 * Tree header, for storing helper functions.
 */
struct AATree {
	struct AANode *root;
	int count;
	aatree_cmp_f node_cmp;
	aatree_walker_f release_cb;
};

/**
 * Tree node.  Embeddable, parent structure should be taken
 * with container_of().
 *
 * Techinally, the full level is not needed and 2-lowest
 * bits of either ->left or ->right would be enough
 * to keep track of structure.  Currently this is not
 * done to keep code simple.
 */
struct AANode {
	struct AANode *left;	/**<  smaller values */
	struct AANode *right;	/**<  larger values */
	int level;		/**<  number of black nodes to leaf */
};

/**
 * Walk order types.
 */
enum AATreeWalkType {
	AA_WALK_IN_ORDER = 0,	/* left->self->right */
	AA_WALK_PRE_ORDER = 1,	/* self->left->right */
	AA_WALK_POST_ORDER = 2,	/* left->right->self */
};

/** Initialize structure */
void aatree_init(struct AATree *tree, aatree_cmp_f cmpfn, aatree_walker_f release_cb);

/** Search for node */
struct AANode *aatree_search(struct AATree *tree, uintptr_t value);

/** Insert new node */
void aatree_insert(struct AATree *tree, uintptr_t value, struct AANode *node);

/** Remote node */
void aatree_remove(struct AATree *tree, uintptr_t value);

/** Walk over all nodes */
void aatree_walk(struct AATree *tree, enum AATreeWalkType wtype, aatree_walker_f walker, void *arg);

/** Free */
void aatree_destroy(struct AATree *tree);

/** Check if terminal node. */
static inline int aatree_is_nil_node(const struct AANode *node)
{
	return (node->left == node);
}

#endif
