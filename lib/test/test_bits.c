#include <usual/bits.h>

#include "test_common.h"

/*
 * is_power_of_2
 */

static void test_pow2(void *p)
{
	int_check(is_power_of_2(0), 0);
	int_check(is_power_of_2(1), 1);
	int_check(is_power_of_2(2), 1);
	int_check(is_power_of_2(3), 0);
end:    ;
}

/*
 * rol
 */

static void test_rol(void *p)
{
	/* rol16 */
	int_check(rol16(1, 1), 2);
	int_check(rol16(1, 15), 32768);
	int_check(rol16(0x8000, 1), 1);

	/* rol32 */
	int_check(rol32(1, 1), 2);
	int_check(rol32(0x80000000, 1), 1);

	/* rol64 */
	ull_check(rol64(1, 1), 2);
	ull_check(rol64(1, 63), 0x8000000000000000ULL);
end:    ;
}

/*
 * ror
 */

static void test_ror(void *p)
{
	/* ror16 */
	int_check(ror16(1, 1), 0x8000);
	/* ror32 */
	int_check(ror32(1, 1), 0x80000000);
	/* ror64 */
	ull_check(ror64(1, 1), 0x8000000000000000ULL);
end:    ;
}

/*
 * fls
 */

static void test_fls(void *p)
{
	/* fls */
	int_check(fls(0), 0);
	int_check(fls(1), 1);
	int_check(fls(3), 2);
	int_check(fls((int)-1), 32);

	/* flsl */
	int_check(flsl(0), 0);
	int_check(flsl(1), 1);
	int_check(flsl(3), 2);
	if (sizeof(long) == 4)
		int_check(flsl((long)-1), 32);
	else
		int_check(flsl((long)-1), 64);

	/* flsll */
	int_check(flsll(0), 0);
	int_check(flsll(1), 1);
	int_check(flsll(3), 2);
	int_check(flsll((long long)-1), 64);
end:    ;
}

/*
 * ffs
 */

static void test_ffs(void *p)
{
	/* ffs */
	int_check(ffs(0), 0);
	int_check(ffs(1), 1);
	int_check(ffs(3), 1);
	int_check(ffs((int)-1), 1);
	int_check(ffs(ror32(1, 1)), 32);

	/* flsl */
	int_check(ffsl(0), 0);
	int_check(ffsl(1), 1);
	int_check(ffsl(3), 1);
	int_check(ffsl((long)-1), 1);
	if (sizeof(long) == 4)
		int_check(ffsl(ror32(1, 1)), 32);
	else
		int_check(ffsl(ror64(1, 1)), 64);

	/* ffsll */
	int_check(ffsll(0), 0);
	int_check(ffsll(1), 1);
	int_check(ffsll(3), 1);
	int_check(ffsll((long long)-1), 1);
	ull_check((1ULL << 63), ror64(1, 1));
	int_check(ffsll(1ULL << 63), 64);
	int_check(ffsll(ror64(1, 1)), 64);
end:    ;
}


/*
 * safe mul
 */

static void test_safe_mul(void *p)
{
	uint8_t v8;
	uint16_t v16;
	uint32_t v32;
	uint64_t v64;
	unsigned int i;
	unsigned long l;
	size_t s;

	tt_assert(safe_mul_uint8(&v8, 1, 1)); tt_assert(v8 == 1);
	tt_assert(safe_mul_uint8(&v8, 15, 15)); tt_assert(v8 == 15*15);
	tt_assert(!safe_mul_uint8(&v8, 16, 16)); tt_assert(v8 == 15 * 15);
	tt_assert(safe_mul_uint8(&v8, 255, 1)); tt_assert(v8 == 255); v8 = 0;
	tt_assert(safe_mul_uint8(&v8, 1, 255)); tt_assert(v8 == 255);
	tt_assert(safe_mul_uint8(&v8, 256/4, 3)); tt_assert(v8 == 3*256/4); v8 = 0;
	tt_assert(safe_mul_uint8(&v8, 3, 256/4)); tt_assert(v8 == 3*256/4);
	tt_assert(!safe_mul_uint8(&v8, 256/4, 5));
	tt_assert(!safe_mul_uint8(&v8, 5, 256/4));
	tt_assert(safe_mul_uint8(&v8, 0, 255)); tt_assert(v8 == 0);

	tt_assert(safe_mul_uint16(&v16, 1, 1)); tt_assert(v16 == 1);
	tt_assert(safe_mul_uint16(&v16, UINT8_MAX, UINT8_MAX)); tt_assert(v16 == (1U * UINT8_MAX * UINT8_MAX));
	tt_assert(!safe_mul_uint16(&v16, UINT8_MAX + 1, UINT8_MAX + 1)); tt_assert(v16 == (1U * UINT8_MAX * UINT8_MAX));
	tt_assert(safe_mul_uint16(&v16, UINT16_MAX, 1)); tt_assert(v16 == UINT16_MAX); v16 = 0;
	tt_assert(safe_mul_uint16(&v16, 1, UINT16_MAX)); tt_assert(v16 == UINT16_MAX);
	tt_assert(safe_mul_uint16(&v16, (1<<16)/4, 3)); tt_assert(v16 == 3U * (1<<16)/4); v16 = 0;
	tt_assert(safe_mul_uint16(&v16, 3, (1<<16)/4)); tt_assert(v16 == 3U * (1<<16)/4);
	tt_assert(!safe_mul_uint16(&v16, (1<<16)/4, 5));
	tt_assert(!safe_mul_uint16(&v16, 5, (1<<16)/4));
	tt_assert(safe_mul_uint16(&v16, UINT16_MAX, 0)); tt_assert(v16 == 0);

	tt_assert(safe_mul_uint32(&v32, 1, 1)); tt_assert(v32 == 1);
	tt_assert(safe_mul_uint32(&v32, UINT16_MAX, UINT16_MAX)); tt_assert(v32 == (1U * UINT16_MAX * UINT16_MAX));
	tt_assert(!safe_mul_uint32(&v32, UINT16_MAX + 1, UINT16_MAX + 1)); tt_assert(v32 == (1U * UINT16_MAX * UINT16_MAX));
	tt_assert(safe_mul_uint32(&v32, UINT32_MAX, 1)); tt_assert(v32 == UINT32_MAX); v32 = 0;
	tt_assert(safe_mul_uint32(&v32, 1, UINT32_MAX)); tt_assert(v32 == UINT32_MAX);
	tt_assert(safe_mul_uint32(&v32, (1ULL<<32)/4, 3)); tt_assert(v32 == 3 * (1ULL<<32)/4); v32 = 0;
	tt_assert(safe_mul_uint32(&v32, 3, (1ULL<<32)/4)); tt_assert(v32 == 3 * (1ULL<<32)/4);
	tt_assert(!safe_mul_uint32(&v32, (1ULL<<32)/4, 5));
	tt_assert(!safe_mul_uint32(&v32, 5, (1ULL<<32)/4));
	tt_assert(safe_mul_uint32(&v32, 0, UINT32_MAX)); tt_assert(v32 == 0);

	tt_assert(safe_mul_uint64(&v64, 1, 1)); tt_assert(v64 == 1);
	tt_assert(safe_mul_uint64(&v64, UINT32_MAX, UINT32_MAX)); tt_assert(v64 == (1ULL*UINT32_MAX*UINT32_MAX));
	tt_assert(!safe_mul_uint64(&v64, UINT32_MAX + 1ULL, UINT32_MAX + 1ULL)); tt_assert(v64 == (1ULL*UINT32_MAX*UINT32_MAX));
	tt_assert(safe_mul_uint64(&v64, UINT64_MAX, 1)); tt_assert(v64 == UINT64_MAX); v64 = 0;
	tt_assert(safe_mul_uint64(&v64, 1, UINT64_MAX)); tt_assert(v64 == UINT64_MAX);
	tt_assert(safe_mul_uint64(&v64, (1ULL<<(64 - 2)), 3)); tt_assert(v64 == (1ULL<<(64 - 2)) * 3); v64 = 0;
	tt_assert(safe_mul_uint64(&v64, 3, (1ULL<<(64 - 2)))); tt_assert(v64 == (1ULL<<(64 - 2)) * 3);
	tt_assert(!safe_mul_uint64(&v64, (1ULL<<(64 - 2)), 5));
	tt_assert(!safe_mul_uint64(&v64, 5, (1ULL<<(64 - 2))));
	tt_assert(safe_mul_uint64(&v64, UINT64_MAX, 0)); tt_assert(v64 == 0);

	tt_assert(safe_mul_uint(&i, UINT16_MAX, UINT16_MAX)); tt_assert(i == (1U * UINT16_MAX * UINT16_MAX));
	tt_assert(safe_mul_ulong(&l, ULONG_MAX, 1)); tt_assert(l == ULONG_MAX);
	tt_assert(safe_mul_size(&s, SIZE_MAX, 1)); tt_assert(s == SIZE_MAX);
	tt_assert(safe_mul_size(&s, 1, SIZE_MAX)); tt_assert(s == SIZE_MAX);
end:    ;
}

/*
 * Describe
 */

struct testcase_t bits_tests[] = {
	{ "is_power_of_2", test_pow2 },
	{ "rol", test_rol },
	{ "ror", test_ror },
	{ "ffs", test_ffs },
	{ "fls", test_fls },
	{ "safe_mul", test_safe_mul },
	END_OF_TESTCASES
};
