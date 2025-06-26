#include <usual/shlist.h>

#include "test_common.h"

#include <usual/string.h>

struct MyNode {
	struct SHList node;
	char val[16];
};

static const char *xval(const struct SHList *elem)
{
	const struct MyNode *n;
	if (!elem) return NULL;
	n = container_of(elem, struct MyNode, node);
	return n->val;
}

static struct MyNode *new_node(int v)
{
	struct MyNode *n = malloc(sizeof(*n));
	if (!n) return NULL;
	shlist_init(&n->node);
	snprintf(n->val, sizeof(n->val), "%d", v);
	return n;
}

static const char *check_list(struct SHList *list)
{
	struct SHList *old, *cur;

	old = NULL;
	for (cur = shlist_get_next(list); cur != list; cur = shlist_get_next(cur)) {
		if (old) {
			if (shlist_get_prev(cur) != old)
				return "FAIL 1";
		} else {
			if (shlist_get_prev(cur) != list)
				return "FAIL 2";
		}
		old = cur;
	}
	if (shlist_get_prev(list) != ((old) ? old : list))
		return "FAIL 3";
	return "OK";
}

static const char *xshow(struct SHList *list)
{
	static char res[1024];
	struct SHList *el;
	const char *ck = check_list(list);

	if (strcmp(ck, "OK") != 0)
		return ck;

	res[0] = 0;
	shlist_for_each(el, list) {
		if (res[0])
			strlcat(res, ",", sizeof(res));
		strlcat(res, xval(el), sizeof(res));
	}
	return res;
}

static const char *xadd(struct SHList *list, int v)
{
	struct MyNode *n = new_node(v);
	if (!n) return "FAIL";
	shlist_append(list, &n->node);
	return xshow(list);
}

static const char *xadd1(struct SHList *list, int v)
{
	struct MyNode *n = new_node(v);
	if (!n) return "FAIL";
	shlist_prepend(list, &n->node);
	return xshow(list);
}

static const char *xdel(struct SHList *list, int v)
{
	char buf[32];
	struct SHList *el, *tmp;
	struct MyNode *n;
	snprintf(buf, sizeof(buf), "%d", v);
	shlist_for_each_safe(el, list, tmp) {
		n = container_of(el, struct MyNode, node);
		if (strcmp(buf, n->val) == 0) {
			shlist_remove(el);
			free(n);
		}
	}
	if (!check_list(list))
		return "FAIL";
	return xshow(list);
}

#if (defined __GNUC__) && (__GNUC__ >= 12)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wstringop-overread"
#endif

static void test_shlist(void *p)
{
	struct SHList rlist, *list = &rlist;

	shlist_init(list);
	str_check(check_list(list), "OK");
	str_check(xadd(list, 2), "2");
	str_check(xadd1(list, 1), "1,2");
	str_check(xadd(list, 3), "1,2,3");
	str_check(xadd(list, 4), "1,2,3,4");
	str_check(check_list(list), "OK");

	{
		struct MyNode *n;
		struct SHList *el;
		str_check(xadd1(list, 0), "0,1,2,3,4");
		el = shlist_pop(list);
		n = container_of(el, struct MyNode, node);
		str_check(n->val, "0");
		free(n);
	}

	{
		struct MyNode *n;
		str_check(xadd1(list, 0), "0,1,2,3,4");
		n = shlist_pop_type(list, struct MyNode, node);
		str_check(n->val, "0");
		free(n);
	}


	str_check(xval(shlist_first(list)), "1");
	str_check(xval(shlist_last(list)), "4");
	int_check(shlist_empty(list), 0);

	str_check(xdel(list, 2), "1,3,4");
	str_check(xdel(list, 1), "3,4");
	str_check(xdel(list, 4), "3");
	str_check(xdel(list, 3), "");
	str_check(check_list(list), "OK");
	int_check(shlist_empty(list), 1);
end:    ;
}
#if (defined __GNUC__) && (__GNUC__ >= 12)
#pragma GCC diagnostic pop
#endif

static void test_shlist_remove(void *p)
{
	static struct SHList xlist, xnode;
	struct SHList *list = &xlist;
	struct SHList *node = &xnode;

	shlist_init(list);
	tt_assert(shlist_empty(list));
	shlist_append(list, node);
	tt_assert(!shlist_empty(list));
	tt_assert(!shlist_empty(list));
	shlist_remove(node);
	tt_assert(shlist_empty(node));
	tt_assert(shlist_empty(list));
end:    ;
}

struct testcase_t shlist_tests[] = {
	{ "remove", test_shlist_remove },
	{ "basic", test_shlist },
	END_OF_TESTCASES
};
