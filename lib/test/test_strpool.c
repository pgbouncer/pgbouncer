#include <usual/strpool.h>

#include "test_common.h"

#include <string.h>

static void test_strpool(void *p)
{
	struct StrPool *pool;
	struct PStr *s;

	pool = strpool_create(NULL);
	tt_assert(pool);
	strpool_free(pool);

	pool = strpool_create(NULL);
	tt_assert(pool);
	int_check(strpool_total(pool), 0);

	s = strpool_get(pool, "foo", -1);
	str_check(s->str, "foo");
	int_check(s->refcnt, 1);
	int_check(s->len, 3);
	int_check(strpool_total(pool), 1);

	tt_assert(s == strpool_get(pool, "fooTAIL", 3));
	int_check(s->refcnt, 2);
	int_check(strpool_total(pool), 1);

	strpool_incref(s);
	int_check(s->refcnt, 3);

	strpool_decref(s);
	int_check(s->refcnt, 2);
	strpool_decref(s);
	int_check(s->refcnt, 1);
	int_check(strpool_total(pool), 1);
	strpool_decref(s);
	int_check(strpool_total(pool), 0);

	strpool_free(pool);

	/* free strc with strings */
	pool = strpool_create(NULL);
	tt_assert(pool);
	s = strpool_get(pool, "foo", -1);
	s = strpool_get(pool, "bar", 3);
	int_check(strpool_total(pool), 2);
	strpool_free(pool);

end:    ;
}


/*
 * Describe
 */

struct testcase_t strpool_tests[] = {
	{ "strpool", test_strpool },
	END_OF_TESTCASES
};
