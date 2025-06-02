#include <usual/aatree.h>
#include <usual/psrandom.h>
#include <usual/time.h>

#include <string.h>

#include "test_common.h"


static char *OK = "OK";

typedef struct MyNode MyNode;
struct MyNode {
	struct AANode node;
	int value;
};

static int my_node_pair_cmp(const struct AANode *n1, const struct AANode *n2)
{
	const struct MyNode *m1 = container_of(n1, struct MyNode, node);
	const struct MyNode *m2 = container_of(n2, struct MyNode, node);
	return m1->value - m2->value;
}

static int my_node_cmp(uintptr_t value, struct AANode *node)
{
	MyNode *my = container_of(node, MyNode, node);
	return value - my->value;
}

static MyNode *make_node(int value)
{
	MyNode *node = malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));
	node->value = value;
	return node;
}

static void my_node_free(struct AANode *node, void *arg)
{
	MyNode *my = container_of(node, MyNode, node);
	free(my);
}

/*
 * Test tree sanity
 */

static const char *mkerr(const char *msg, int v, const struct AANode *node)
{
	static char buf[128];
	snprintf(buf, sizeof(buf), "%s: %d", msg, v);
	return buf;
}

static const char *check_sub(const struct AATree *tree, const struct AANode *node, int i)
{
	int cmp_left = 0, cmp_right = 0;
	const char *res;
	if (aatree_is_nil_node(node))
		return OK;
	if (node->level != node->left->level + 1)
		return mkerr("bad left level", i, node);
	if (!((node->level == node->right->level + 1)
	      || (node->level == node->right->level
		  && node->right->level != node->right->level + 1)))
		return mkerr("bad right level", i, node);
	if (!aatree_is_nil_node(node->left))
		cmp_left = my_node_pair_cmp(node, node->left);
	if (!aatree_is_nil_node(node->right))
		cmp_right = my_node_pair_cmp(node, node->right);
	if (cmp_left < 0)
		return mkerr("wrong left order", i, node);
	if (cmp_right > 0)
		return mkerr("wrong right order", i, node);
	res = check_sub(tree, node->left, i);
	if (!res)
		res = check_sub(tree, node->right, i);
	return res;
}

static const char *check(struct AATree *tree, int i)
{
	return check_sub(tree, tree->root, i);
}

/*
 * checking operations
 */

static const char * my_search(struct AATree *tree, int value)
{
	struct AANode *res;
	res = aatree_search(tree, value);
	return res ? OK : "not found";
}

static const char *my_insert(struct AATree *tree, int value)
{
	MyNode *my = make_node(value);
	aatree_insert(tree, value, &my->node);
	return check(tree, value);
}

static const char *my_remove(struct AATree *tree, int value)
{
	const char *res;
	res = my_search(tree, value);
	if (res != OK)
		return res;
	aatree_remove(tree, value);
	res = check(tree, value);
	if (res != OK)
		return res;
	if (aatree_search(tree, value) != NULL)
		return "still found";
	return OK;
}

/*
 * Simple opeartions.
 */

static void test_aatree_basic(void *p)
{
	struct AATree tree[1];
	int i;

	aatree_init(tree, my_node_cmp, my_node_free);

	str_check(my_search(tree, 1), "not found");

	for (i = 0; i < 15; i++) {
		str_check(my_insert(tree, i), "OK");
	}
	for (i = -1; i > -15; i--) {
		str_check(my_insert(tree, i), "OK");
	}
	for (i = 30; i < 45; i++) {
		str_check(my_insert(tree, i), "OK");
	}
	for (i = 15; i < 30; i++) {
		str_check(my_insert(tree, i), "OK");
	}

	for (i = -14; i < 45; i++) {
		str_check(my_remove(tree, i), "OK");
	}
end:
	aatree_destroy(tree);
}

/*
 * randomized test
 */

#define RSIZE 3000

static int get_next(bool with_stat, bool added[])
{
	int r = pseudo_random_range(RSIZE);
	int i = r;
	while (1) {
		if (added[i] == with_stat)
			return i;
		if (++i >= RSIZE)
			i = 0;
		if (i == r)
			return -1;
	}
}

static void test_aatree_random(void *p)
{
	bool is_added[RSIZE];
	int prefer_remove = 0; /* 0 - insert, 1 - delete */
	int n;
	int op; /* 0 - insert, 1 - delete */
	struct AATree tree[1];
	unsigned long long total = 0;

	memset(is_added, 0, sizeof(is_added));

	aatree_init(tree, my_node_cmp, my_node_free);
	while (total < 20000) {
		int r = pseudo_random_range(16);
		if (prefer_remove)
			op = r > 5;
		else
			op = r > 10;
		/* op = 0; */

		n = get_next(op, is_added);
		if (n < 0) {
			if (prefer_remove == op) {
				prefer_remove = !prefer_remove;
			}
			continue;
		}

		if (op == 0) {
			str_check(my_insert(tree, n), "OK");
			is_added[n] = 1;
		} else {
			str_check(my_remove(tree, n), "OK");
			is_added[n] = 0;
		}
		total++;
	}
end:
	aatree_destroy(tree);
}

struct testcase_t aatree_tests[] = {
	{ "basic", test_aatree_basic },
	{ "random", test_aatree_random },
	END_OF_TESTCASES
};
