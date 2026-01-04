#include <usual/hashing/crc32.h>
#include <usual/hashing/lookup3.h>

#include <usual/string.h>

#include "test_common.h"

static uint32_t xcrc32(const char *s)
{
	return calc_crc32(s, strlen(s), 0);
}

static uint32_t xlookup3(const char *s)
{
	return hash_lookup3(s, strlen(s));
}

static void test_crc32(void *p)
{
	int_check(xcrc32(""), 0);
	int_check(xcrc32("a"), 3904355907);
	int_check(xcrc32("abc"), 891568578);
	int_check(xcrc32("message digest"), 538287487);
	int_check(xcrc32("abcdefghijklmnopqrstuvwxyz"), 1277644989);
	int_check(xcrc32("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), 532866770);
	int_check(xcrc32("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), 2091469426);
end:    ;
}

static void test_lookup3(void *p)
{
#ifdef WORDS_BIGENDIAN
	int_check(xlookup3(""), 3735928559);
	int_check(xlookup3("a"), -454251968);
	int_check(xlookup3("abc"), -1186250080);
	int_check(xlookup3("message digest"), 670730672);
	int_check(xlookup3("abcdefghijklmnopqrstuvwxyz"), 251682059);
	int_check(xlookup3("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), 567386262);
	int_check(xlookup3("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), 312582506);
#else
	int_check(xlookup3(""), 3735928559);
	int_check(xlookup3("a"), 1490454280);
	int_check(xlookup3("abc"), 238646833);
	int_check(xlookup3("message digest"), 2512672053);
	int_check(xlookup3("abcdefghijklmnopqrstuvwxyz"), 1966650813);
	int_check(xlookup3("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), 3992286962);
	int_check(xlookup3("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), 2776963519);
#endif
end:    ;
}

struct testcase_t hashing_tests[] = {
	{ "crc32", test_crc32 },
	{ "lookup3", test_lookup3 },
	END_OF_TESTCASES
};
