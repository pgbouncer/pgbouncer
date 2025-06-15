#include <usual/psrandom.h>
#include <usual/string.h>
#include <usual/endian.h>

#include "test_common.h"

#define str_check(a, b) tt_str_op(a, ==, b)

#define tt_stri_op(a,op,b)						\
	tt_assert_test_type(a,b,#a" "#op" "#b,const char *,		\
			    (strcasecmp(_val1,_val2) op 0),"<%s>")

#define stri_check(a, b) tt_stri_op(a, ==, b)


static const char *mkhex(const uint8_t *src, int len)
{
	static char buf[1024 + 1];
	static const char hextbl[] = "0123456789abcdef";
	int i;
	for (i = 0; i < len; i++) {
		buf[i*2] = hextbl[src[i] >> 4];
		buf[i*2+1] = hextbl[src[i] & 15];
	}
	buf[i*2] = 0;
	return buf;
}

/*
 * Test if seeding works fine.
 */

static void test_seed(void *ptr)
{
	uint32_t val1;
	pseudo_random_seed(1, 1);
	val1 = pseudo_random();
	pseudo_random_seed(2, 2);
	pseudo_random();
	pseudo_random_seed(1, 1);
	int_check(pseudo_random(), val1);
end:
	pseudo_random_seed(test_seed1, test_seed2);
}

/*
 * Check bytes and algo stability.
 */

static const char *run_bytes(size_t count)
{
	uint8_t res[512];
	if (count >= sizeof res)
		return "NOMEM";
	memset(res, 0, sizeof res);
	pseudo_random_bytes(res, count);
	if (res[count])
		return "OVERFLOW";
	return mkhex(res, count);
}

static void test_bytes(void *ptr)
{
	pseudo_random_seed(1, 1);
	str_check(run_bytes(0), "");
	str_check(run_bytes(10), "604913fc779c86c8c2eb");
	str_check(run_bytes(5), "5d3e8b9dc2");
	str_check(run_bytes(4), "47e760b3");
	str_check(run_bytes(3), "a09744");
	str_check(run_bytes(2), "85d6");
	str_check(run_bytes(1), "93");
end:
	pseudo_random_seed(test_seed1, test_seed2);
}

/*
 * Test random value extraction
 */

static void test_random(void *z)
{
	uint8_t buf[8];
	uint32_t v1, v2;
	pseudo_random_seed(0, 0);
	pseudo_random_bytes(buf, 8);
	v1 = le32dec(buf);
	v2 = le32dec(buf+4);
	pseudo_random_seed(0, 0);
	int_check(v1, pseudo_random());
	int_check(v2, pseudo_random());
end:
	pseudo_random_seed(test_seed1, test_seed2);
}

/*
 * Check range limit.
 */

static bool run_range(uint32_t limit)
{
	bool res = false;
	int i;
	for (i = 0; i < 100; i++) {
		uint32_t v = pseudo_random_range(limit);
		if (limit == 0) {
			int_check(v, 0);
		} else {
			tt_assert(v < limit);
		}
	}
	res = true;
end:
	return res;
}

static void test_range(void *z)
{
	if (!run_range(1)) goto end;
	if (!run_range(0)) goto end;
	if (!run_range(255)) goto end;
end:
	pseudo_random_seed(test_seed1, test_seed2);
}

/*
 * Test if core algo is sane.
 */

// orig code by Sebastiano Vigna
static uint64_t xs128plus_orig(uint64_t s[2])
{
	uint64_t s1 = s[ 0 ];
	const uint64_t s0 = s[ 1 ];
	s[ 0 ] = s0;
	s1 ^= s1 << 23; // a
	return ( s[ 1 ] = ( s1 ^ s0 ^ ( s1 >> 17 ) ^ ( s0 >> 26 ) ) ) + s0; // b, c
}

static void test_core(void *z)
{
	uint64_t i, s_orig[2], s_cur[2], s_1024[16], s_bak[16];
	s_orig[0] = s_cur[0] = UINT64_C(0x123456789abcdef1);
	s_orig[1] = s_cur[1] = UINT64_C(0xfedcba9876543210);
	for (i = 0; i < 100; i++) {
		xs128plus_orig(s_orig);
		xorshift128plus(&s_cur[0], &s_cur[1]);
		tt_assert(s_orig[0] == s_cur[0]);
		tt_assert(s_orig[1] == s_cur[1]);
	}

	for (i = 0; i < 16; i++)
		s_1024[i] = xorshift128plus(&s_cur[0], &s_cur[1]);

	memcpy(s_bak, s_1024, sizeof s_bak);
	xorshift1024plus(s_1024, 0);
	tt_assert(s_1024[0] == s_bak[0]);
	tt_assert(s_1024[1] != s_bak[1]);
	tt_assert(s_1024[1] != s_bak[0]);
	tt_assert(s_1024[2] == s_bak[2]);
	tt_assert(s_1024[15] == s_bak[15]);

	memcpy(s_bak, s_1024, sizeof s_bak);
	xorshift1024plus(s_1024, 15);
	tt_assert(s_1024[15] == s_bak[15]);
	tt_assert(s_1024[0] != s_bak[0]);
	tt_assert(s_1024[0] != s_bak[1]);
	tt_assert(s_1024[0] != s_bak[15]);
end:
	pseudo_random_seed(test_seed1, test_seed2);
}


/*
 * Launcher.
 */

struct testcase_t psrandom_tests[] = {
	{ "core", test_core },
	{ "seed", test_seed },
	{ "bytes", test_bytes },
	{ "random", test_random },
	{ "range", test_range },
	END_OF_TESTCASES
};
