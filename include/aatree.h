/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
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

typedef struct Node Node;
typedef struct Tree Tree;

typedef int (*tree_cmp_f)(long, Node *node);
typedef void (*tree_walker_f)(Node *n, void *arg);

/*
 * Tree header, for storing helper functions.
 */
struct Tree {
	Node *root;
	int count;
	tree_cmp_f node_cmp;
	tree_walker_f release_cb;
};

/*
 * Tree node.
 */
struct Node {
	Node *left;	/* smaller values */
	Node *right;	/* larger values */
	int level;	/* number of black nodes to leaf */
};

/*
 * walk order
 */
enum TreeWalkType {
	WALK_IN_ORDER = 0, /* left->self->right */
	WALK_PRE_ORDER = 1, /* self->left->right */
	WALK_POST_ORDER = 2, /* left->right->self */
};

void tree_init(Tree *tree, tree_cmp_f cmpfn, tree_walker_f release_cb);
Node *tree_search(Tree *tree, long value);
void tree_insert(Tree *tree, long value, Node *node);
void tree_remove(Tree *tree, long value);
void tree_walk(Tree *tree, enum TreeWalkType wtype, tree_walker_f walker, void *arg);
void tree_destroy(Tree *tree);

