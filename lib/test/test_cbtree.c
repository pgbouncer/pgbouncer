#include <usual/cbtree.h>

#include <usual/string.h>
#include <usual/psrandom.h>

#include "test_common.h"

static char *OK = "OK";

struct MyNode {
	char str[64];
	int len;
};

static size_t my_getkey(void *ctx, void *obj, const void **dst_p)
{
	struct MyNode *node = obj;
	*dst_p = node->str;
	return node->len;
}

static struct MyNode *make_node(int value)
{
	struct MyNode *node = malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));
	snprintf(node->str, sizeof(node->str), "%d", value);
	node->len = strlen(node->str);
	return node;
}

static bool my_node_free(void *ctx, void *obj)
{
	free(obj);
	return true;
}

/*
 * Test tree sanity
 */

/*
 * checking operations
 */

static const char *my_search(struct CBTree *tree, int value)
{
	struct AANode *res;
	char buf[64];
	snprintf(buf, sizeof(buf), "%d", value);
	res = cbtree_lookup(tree, buf, strlen(buf));
	return res ? OK : "not found";
}

static const char *my_insert(struct CBTree *tree, int value)
{
	struct MyNode *my = make_node(value);
	if (!cbtree_insert(tree, my))
		return "insert failed";
	return my_search(tree, value);
}

static const char *my_remove(struct CBTree *tree, int value)
{
	struct MyNode *my;
	char buf[64];
	snprintf(buf, sizeof(buf), "%d", value);

	my = cbtree_lookup(tree, buf, strlen(buf));
	if (!my)
		return "nonexsist element";
	cbtree_delete(tree, buf, strlen(buf));
	if (cbtree_lookup(tree, buf, strlen(buf)) != NULL)
		return "still found";
	return OK;
}

/*
 * Simple opeartions.
 */

static void test_cbtree_basic(void *p)
{
	struct CBTree *tree;
	int i;

	tree = cbtree_create(my_getkey, my_node_free, NULL, NULL);

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
	cbtree_destroy(tree);
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

static void test_cbtree_random(void *p)
{
	bool is_added[RSIZE];
	int prefer_remove = 0;	/* 0 - insert, 1 - delete */
	int n;
	int op;	/* 0 - insert, 1 - delete */
	struct CBTree *tree;
	unsigned long long total = 0;

	memset(is_added, 0, sizeof(is_added));

	tree = cbtree_create(my_getkey, my_node_free, NULL, NULL);

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
	cbtree_destroy(tree);
}

struct testcase_t cbtree_tests[] = {
	{ "basic", test_cbtree_basic },
	{ "random", test_cbtree_random },
	END_OF_TESTCASES
};
