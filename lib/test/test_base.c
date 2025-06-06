#include <usual/base.h>

#include "test_common.h"

#include <string.h>

struct somestruct {
	char a, b, c;
};

static void test_ptr(void *p)
{
	/* offsetof */
	int_check(offsetof(struct somestruct, a), 0);
	int_check(offsetof(struct somestruct, b), 1);
	int_check(offsetof(struct somestruct, c), 2);

	/* container_of */
	{
		struct somestruct s = {'a', 'b', 'c'};
		char *pa = &s.a;
		char *pb = &s.b;
		char *pc = &s.c;
		struct somestruct *sa, *sb, *sc;
		sa = container_of(pa, struct somestruct, a);
		sb = container_of(pb, struct somestruct, b);
		sc = container_of(pc, struct somestruct, c);
		int_check(sa->a, 'a');
		int_check(sb->b, 'b');
		int_check(sc->c, 'c');
	}

	/* alignof */
	int_check(alignof(char), 1);
	int_check(alignof(short), 2);
	int_check(alignof(int), 4);

	/* CUSTOM_ALIGN */
	int_check(CUSTOM_ALIGN(1, 4), 4);
	int_check(CUSTOM_ALIGN(2, 4), 4);
	int_check(CUSTOM_ALIGN(3, 4), 4);
	int_check(CUSTOM_ALIGN(4, 4), 4);
	int_check(CUSTOM_ALIGN(5, 4), 8);
end:;
}

#ifdef _PACKED
struct packed {
	char a;
	int b;
	char c;
	short d;
} _PACKED;
#endif

static void test_misc(void *_p)
{
	int i_4[4];
	int i_2[2];
	short s_4[4];
	short s_2[2];

	int_check(ARRAY_NELEM(i_4), 4);
	int_check(ARRAY_NELEM(i_2), 2);
	int_check(ARRAY_NELEM(s_4), 4);
	int_check(ARRAY_NELEM(s_2), 2);

	int_check(strcmp(__func__, "test_misc"), 0);
#ifdef _PACKED
	int_check(sizeof(struct packed), 8);
#endif

end:;
}

#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9
#pragma GCC diagnostic ignored "-Walloc-size-larger-than="
#endif

static void test_reallocarray(void *_p)
{
	void *p;
	p = reallocarray(NULL, 1, 1); tt_assert(p); free(p);
	p = reallocarray(NULL, SIZE_MAX, SIZE_MAX); tt_assert(p == NULL);
end:;
}

#pragma GCC diagnostic pop

struct testcase_t base_tests[] = {
	{ "ptr", test_ptr },
	{ "misc", test_misc },
	{ "reallocarray", test_reallocarray },
	END_OF_TESTCASES
};
