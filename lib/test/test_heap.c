#include <usual/heap.h>

#include <string.h>

#include "test_common.h"

struct MyNode {
	int value;
	unsigned heap_idx;
};

/* min-heap */
static bool heap_is_better(const void *a, const void *b)
{
	const struct MyNode *aa = a, *bb = b;
	return (aa->value < bb->value);
}

static void my_save_pos(void *p, unsigned i)
{
	struct MyNode *node = p;
	node->heap_idx = i;
}

static char *OK = "OK";

static struct MyNode *make_node(int v)
{
	struct MyNode *n = malloc(sizeof(*n));
	n->value = v;
	n->heap_idx = -1;
	return n;
}

static unsigned _heap_get_child(unsigned i, unsigned child_nr)
{
	return 2*i + 1 + child_nr;
}

static bool _heap_is_better(struct Heap *h, unsigned i1, unsigned i2)
{
	return heap_is_better(heap_get_obj(h, i1), heap_get_obj(h, i2));
}


/*
 * Test tree sanity
 */

static const char *mkerr(const char *msg, unsigned idx, int val)
{
	static char buf[128];
	snprintf(buf, sizeof(buf), "%s: idx=%d curval=%d", msg, idx, val);
	return buf;
}

static const char *check_sub(struct Heap *heap, unsigned idx, int i)
{
	unsigned c0 = _heap_get_child(idx, 0);
	unsigned c1 = _heap_get_child(idx, 1);
	struct MyNode *n;
	const char *res;
	unsigned used = heap_size(heap);

	if (idx >= used)
		return OK;

	n = heap_get_obj(heap, idx);
	if (n->heap_idx != idx)
		return mkerr("wrong saved idx", idx, i);

	if (c0 < used && _heap_is_better(heap, c0, idx))
		return mkerr("c0 wrong order", idx, i);
	if (c1 < used && _heap_is_better(heap, c1, idx))
		return mkerr("c1 wrong order", idx, i);

	res = check_sub(heap, c0, i);
	if (res == OK)
		res = check_sub(heap, c1, i);
	return res;
}

static const char *check(struct Heap *heap, int i)
{
	return check_sub(heap, 0, i);
}

/*
 * checking operations
 */

static const char *my_insert(struct Heap *heap, int value)
{
	struct MyNode *my = make_node(value);
	if (!heap_push(heap, my))
		return "FAIL";
	return check(heap, value);
}

static const char *my_remove(struct Heap *h, unsigned idx)
{
	struct MyNode *n;
	if (idx >= heap_size(h))
		return "NEXIST";
	n = heap_get_obj(h, idx);
	heap_remove(h, idx);
	free(n);
	return check(h, 0);
}

static const char *my_clean(struct Heap *heap)
{
	const char *res;
	while (heap_size(heap) > 0) {
		res = my_remove(heap, 0);
		if (res != OK)
			return res;
	}
	return OK;
}

/*
 * Simple operations.
 */

static void test_heap_basic(void *p)
{
	struct Heap *heap;
	int i;

	heap = heap_create(heap_is_better, my_save_pos, NULL);

	str_check(my_remove(heap, 0), "NEXIST");
	str_check(my_insert(heap, 0), "OK");
	str_check(my_remove(heap, 0), "OK");

	for (i = 0; i < 15; i++) {
		str_check(my_insert(heap, i), "OK");
	}
	str_check(my_clean(heap), "OK");

	for (i = -1; i > -15; i--) {
		str_check(my_insert(heap, i), "OK");
	}
	str_check(my_clean(heap), "OK");
	for (i = 30; i < 45; i++) {
		str_check(my_insert(heap, i), "OK");
	}
	str_check(my_clean(heap), "OK");
	for (i = 15; i < 30; i++) {
		str_check(my_insert(heap, i), "OK");
	}
	str_check(my_clean(heap), "OK");
end:
	heap_destroy(heap);
}

#if 0
/*
 * randomized test
 */

#define RSIZE 3000

static int get_next(bool with_stat, bool added[])
{
	int r = random() % RSIZE;
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

	srandom(123123);
	memset(is_added, 0, sizeof(is_added));

	aatree_init(tree, my_node_cmp, my_node_free);
	while (total < 100000) {
		int r = random() & 15;
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
#endif

struct testcase_t heap_tests[] = {
	{ "basic", test_heap_basic },
	/* { "random", test_aatree_random }, */
	END_OF_TESTCASES
};
