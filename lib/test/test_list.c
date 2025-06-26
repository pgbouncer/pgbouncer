#include "test_common.h"

#include <usual/psrandom.h>
#include <usual/list.h>
#include <usual/mempool.h>

struct MyNode {
	struct List node;
	int val;
	int seq;
};

static int my_cmp(const struct List *a, const struct List *b)
{
	struct MyNode *aa, *bb;
	aa = container_of(a, struct MyNode, node);
	bb = container_of(b, struct MyNode, node);
	if (aa->val < bb->val) return -1;
	if (aa->val > bb->val) return 1;
	return 0;
}

static bool check_list(struct List *list, int n)
{
	struct List *old, *cur;
	int i;

	old = NULL;
	i = 0;
	for (cur = list->next; cur != list; cur = cur->next) {
		i++;
		if (old) {
			struct MyNode *mcur, *mold;
			mcur = container_of(cur, struct MyNode, node);
			mold = container_of(old, struct MyNode, node);
			if (mold->val > mcur->val) {
				printf("bad order(%d): old.val=%d new.val=%d", n, mold->val, mcur->val);
				return false;
			}
			if (mold->val == mcur->val && mold->seq > mcur->seq) {
				printf("unstable(%d): old.seq=%d new.seq=%d", n, mold->seq, mcur->seq);
				return false;
			}
			if (cur->prev != old) {
				printf("llist err 2 (n=%d)", n);
				return false;
			}
		} else {
			if (cur->prev != list) {
				printf("llist err (n=%d)", n);
				return false;
			}
		}
		old = cur;
	}
	if (list->prev != ((old) ? old : list)) {
		printf("llist err 3 (n=%d)", n);
		return false;
	}
	if (i != n) {
		printf("llist err 3 (n=%d)", n);
		return false;
	}
	return true;
}

static bool test_sort(void (*sort)(struct List *list, list_cmp_f cmp), int n)
{
	struct MemPool *pool = NULL;
	struct List list[1];
	bool ok;
	int i;

	/* random */
	list_init(list);
	for (i = 0; i < n; i++) {
		struct MyNode *e = mempool_alloc(&pool, sizeof(*e));
		list_init(&e->node);
		e->val = pseudo_random_range(100);
		e->seq = i;
		list_append(list, &e->node);
	}
	sort(list, my_cmp);
	ok = check_list(list, n);
	mempool_destroy(&pool);
	if (!ok)
		return false;

	/* seq */
	list_init(list);
	for (i = 0; i < n; i++) {
		struct MyNode *e = mempool_alloc(&pool, sizeof(*e));
		list_init(&e->node);
		e->val = i;
		e->seq = i;
		list_append(list, &e->node);
	}
	sort(list, my_cmp);
	ok = check_list(list, n);
	mempool_destroy(&pool);
	if (!ok)
		return false;

	/* reverse */
	list_init(list);
	for (i = 0; i < n; i++) {
		struct MyNode *e = mempool_alloc(&pool, sizeof(*e));
		list_init(&e->node);
		e->val = -i;
		e->seq = i;
		list_append(list, &e->node);
	}
	sort(list, my_cmp);
	ok = check_list(list, n);
	mempool_destroy(&pool);
	if (!ok)
		return false;

	return true;
}

static void test_list_sort(void *p)
{
	int i;
	for (i = 0; i < 259; i++)
		tt_assert(test_sort(list_sort, i));
end:    ;
}

#if 0
static void test_list_sort2(void *p)
{
	int i;
	for (i = 0; i < 259; i++)
		tt_assert(test_sort(list_sort2, i));
end:    ;
}

static void test_list_sort3(void *p)
{
	int i;
	for (i = 0; i < 259; i++)
		tt_assert(test_sort(list_sort3, i));
end:    ;
}
#endif

struct testcase_t list_tests[] = {
	{ "sort", test_list_sort },
#if 0
	{ "sort2", test_list_sort2 },
	{ "sort3", test_list_sort3 },
#endif
	END_OF_TESTCASES
};
