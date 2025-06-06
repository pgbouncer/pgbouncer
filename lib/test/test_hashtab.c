#include <usual/hashtab-impl.h>

#include <usual/list.h>

#include <string.h>

#include "test_common.h"

struct MyNode {
	int value;
};

static int cf_size = 64;
static int cf_ofs = 0;
static int cf_cnt = 3 * 64;
static int cf_mod = 13;

static bool mycmp(const htab_val_t curval, const void *arg)
{
	const struct MyNode *n1 = curval;
	const struct MyNode *n2 = arg;
	return n1->value == n2->value;
}


static struct MyNode *make_node(int v)
{
	struct MyNode *n = malloc(sizeof(*n));
	n->value = v;
	return n;
}

/*
 * checking operations
 */

static const char *my_insert(struct HashTab *htab, int value)
{
	struct MyNode *my = make_node(value);
	void **p;
	int key = value % cf_mod;
	p = hashtab_lookup(htab, key, true, my);
	if (!p)
		return "FAIL";
	if (*p)
		return "EXISTS?";
	*p = my;
	return "OK";
}

static const char *my_remove(struct HashTab *h, int value)
{
	struct MyNode tmp, *my;
	void **p;
	int key = value % cf_mod;

	tmp.value = value;

	p = hashtab_lookup(h, key, false, &tmp);
	if (!p)
		return "NEXIST";
	my = *p;
	if (my->value != value)
		return "WRONG";

	hashtab_delete(h, key, &tmp);
	free(my);

	p = hashtab_lookup(h, key, false, &tmp);
	if (p)
		return "EXISTS?";
	return "OK";
}

static const char *my_lookup(struct HashTab *htab, int value)
{
	void **p;
	struct MyNode tmp, *my;
	int key = value % cf_mod;

	tmp.value = value;
	p = hashtab_lookup(htab, key, false, &tmp);
	if (!p)
		return "NEXIST";
	my = *p;
	if (my->value != value)
		return "WRONG";
	return "OK";
}

/*
 * Simple operations.
 */

static void test_hash_basic(void *p)
{
	struct HashTab *htab;
	int i;

	htab = hashtab_create(cf_size, mycmp, NULL);

	for (i = 0; i < cf_cnt; i++) {
		int n = i + cf_ofs;
		str_check(my_lookup(htab, n), "NEXIST");
		str_check(my_insert(htab, n), "OK");
		str_check(my_lookup(htab, n), "OK");
	}

	for (i = 0; i < cf_cnt; i++) {
		int n = i + cf_ofs;
		str_check(my_lookup(htab, n), "OK");
		str_check(my_remove(htab, n), "OK");
		str_check(my_lookup(htab, n), "NEXIST");
	}

end:
	hashtab_destroy(htab);
}

struct testcase_t hashtab_tests[] = {
	{ "basic", test_hash_basic },
	END_OF_TESTCASES
};
