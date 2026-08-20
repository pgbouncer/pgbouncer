#include <usual/cfparser.h>
#include <usual/time.h>
#include <usual/string.h>
#include <usual/logging.h>
#include <usual/fileutil.h>

#include "test_common.h"

struct Config1 {
	char *str1;
	char *def1;
	int int1;
	int bool1;
};

struct Config2 {
	char *str2;
	char *def2;
	double time_double;
	usec_t time_usec;
	char *value2;
};

static struct Config1 cf1;
static struct Config2 cf2;

static void cleanup(void)
{
	free(cf1.str1);
	free(cf1.def1);
	free(cf2.str2);
	free(cf2.def2);
	memset(&cf1, 0, sizeof(cf1));
	memset(&cf2, 0, sizeof(cf2));
}

static const struct CfKey keys1 [] = {
	CF_ABS("str1", CF_STR, cf1.str1, 0, NULL),
	CF_ABS("def1", CF_STR, cf1.def1, 0, NULL),
	CF_ABS("int", CF_INT, cf1.int1, 0, NULL),
	CF_ABS("bool", CF_BOOL, cf1.bool1, 0, NULL),
	{ NULL },
};

static const struct CfKey keys2 [] = {
	CF_ABS("str2", CF_STR, cf2.str2, 0, NULL),
	CF_ABS("def2", CF_STR, cf2.def2, 0, "somedefault"),
	CF_ABS("time1", CF_TIME_USEC, cf2.time_usec, 0, NULL),
	CF_ABS("time2", CF_TIME_DOUBLE, cf2.time_double, 0, NULL),
	CF_ABS("test key", CF_STR, cf2.value2, 0, NULL),
	{ NULL },
};

static const struct CfSect sects [] = {
	{ "one", keys1 },
	{ "two", keys2 },
	{ NULL },
};

static struct CfContext cfdesc1 = { sects, NULL };

static void test_abs(void *ptr)
{
	char buf[128];
	enum LogLevel save_level;

	int_check(1, cf_load_file(&cfdesc1, tdata("test_cfparser.ini")));

	str_check(cf1.str1, "val1");
	tt_assert(cf1.def1 == NULL);
	str_check(cf2.str2, "val2");
	str_check(cf2.def2, "somedefault");

	tt_assert(cf2.time_usec == (3 * USEC / 2));
	tt_assert(cf2.time_double == 2.5);

	str_check("val1", cf_get(&cfdesc1, "one", "str1", buf, sizeof(buf)));
	int_check(1, cf_set(&cfdesc1, "one", "str1", "val2"));
	str_check("val2", cf_get(&cfdesc1, "one", "str1", buf, sizeof(buf)));

	save_level = cf_stderr_level;
	cf_stderr_level = LG_FATAL;
	int_check(0, cf_set(&cfdesc1, "one", "nonexistent", "foo"));
	cf_stderr_level = save_level;
end:
	cleanup();
}

/*
 * relative addressing.
 */

#define CF_REL_BASE struct Config1
static const struct CfKey rkeys1 [] = {
	CF_REL("str1", CF_STR, str1, 0, NULL),
	CF_REL("def1", CF_STR, def1, 0, NULL),
	CF_REL("int", CF_INT, int1, 0, NULL),
	CF_REL("bool", CF_BOOL, bool1, 0, NULL),
	{ NULL },
};
#undef CF_REL_BASE

#define CF_REL_BASE struct Config2
static const struct CfKey rkeys2 [] = {
	CF_REL("str2", CF_STR, str2, 0, NULL),
	CF_REL("def2", CF_STR, def2, 0, "somedefault"),
	CF_REL("time1", CF_TIME_USEC, time_usec, 0, NULL),
	CF_REL("time2", CF_TIME_DOUBLE, time_double, 0, NULL),
	CF_REL("test key", CF_STR, value2, 0, NULL),
	{ NULL },
};
#undef CF_REL_BASE

static void *get_two(void *top_arg, const char *sect_name)
{
	return &cf2;
}

static const struct CfSect rsects [] = {
	{ "one", rkeys1 },
	{ "two", rkeys2, get_two, },
	{ NULL },
};

static struct CfContext cfdesc2 = { rsects, &cf1 };

static void test_rel(void *ptr)
{
	char buf[128];
	const char *fn = tdata("test_cfparser.ini");

	cleanup();

	int_check(1, cf_load_file(&cfdesc2, fn));

	str_check(cf1.str1, "val1");
	tt_assert(cf1.def1 == NULL);
	str_check(cf2.str2, "val2");
	str_check(cf2.def2, "somedefault");

	tt_assert(cf2.time_usec == (3 * USEC / 2));
	tt_assert(cf2.time_double == 2.5);

	str_check("val1", cf_get(&cfdesc2, "one", "str1", buf, sizeof(buf)));
	int_check(1, cf_set(&cfdesc2, "one", "str1", "val2"));
	str_check("val2", cf_get(&cfdesc2, "one", "str1", buf, sizeof(buf)));
end:
	cleanup();
}
/*
 * Describe
 */

struct testcase_t cfparser_tests[] = {
	{ "abs", test_abs },
	{ "rel", test_rel },
	END_OF_TESTCASES
};
