#include <usual/mdict.h>

#include <usual/string.h>

#include "test_common.h"

static const char *xget(struct MDict *d, const char *k)
{
	const char *val = mdict_get(d, k);
	return val ? val : "NULL";
}

static void test_mdict(void *p)
{
	struct MDict *d;
	struct MBuf buf;
	const char *s;

	d = mdict_new(NULL);
	str_check(xget(d, "key"), "NULL");
	int_check(mdict_put(d, "key", "val"), 1);
	int_check(mdict_put(d, "key2", "foo"), 1);
	int_check(mdict_put(d, "key2", ""), 1);
	int_check(mdict_put(d, "key3", NULL), 1);
	int_check(mdict_put(d, "key4", "v1"), 1);
	int_check(mdict_del(d, "key4"), 1);
	str_check(xget(d, "key"), "val");
	str_check(xget(d, "key2"), "");
	str_check(xget(d, "key3"), "NULL");
	str_check(xget(d, "key4"), "NULL");
	str_check(xget(d, "key5"), "NULL");
	int_check(mdict_del(d, "key5"), 0);

	mbuf_init_dynamic(&buf);
	int_check(mdict_urlencode(d, &buf), 1);
	int_check(mbuf_write_byte(&buf, 0), 1);
	str_check(mbuf_data(&buf), "key=val&key2=&key3");
	mbuf_free(&buf);

	mdict_free(d);

	d = mdict_new(NULL);
	s = "key=val&key2=&key3";
	int_check(mdict_urldecode(d, s, strlen(s)), 1);
	str_check(xget(d, "key"), "val");
	str_check(xget(d, "key2"), "");
	str_check(xget(d, "key3"), "NULL");
	mdict_free(d);
end:;
}


/*
 * Describe
 */

struct testcase_t mdict_tests[] = {
	{ "basic", test_mdict },
	END_OF_TESTCASES
};
