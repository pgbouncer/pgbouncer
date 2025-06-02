#include "test_common.h"

#include <usual/string.h>
#include <usual/cxextra.h>

static int delta = 0;

static char logbuf[1024];

static void reset(void)
{
	logbuf[0] = 0;
}

_PRINTF(1,2)
static void m_log(const char *fmt, ...)
{
	size_t len = strlen(logbuf);
	va_list ap;

	if (len && len < sizeof(logbuf) - 1)
		logbuf[len++] = ' ';

	va_start(ap, fmt);
	vsnprintf(logbuf + len, sizeof(logbuf) - len, fmt, ap);
	va_end(ap);
}

static void *log_alloc(void *ctx, size_t len)
{
	void *p;
	m_log("A(%d)", (int)len);
	delta += len;
	p = cx_alloc(ctx, len + 8);
	*(int*)p = len;
	return (char *)p + 8;
}

static void *log_realloc(void *ctx, void *ptr, size_t len)
{
	char *p = (char *)ptr - 8;
	int olen = *(int*)p;
	m_log("R(%d)", (int)len);
	p = cx_realloc(ctx, p, len + 8);
	*(int*)p = len;
	delta += len - olen;
	return p + 8;
}

static void log_free(void *ctx, void *ptr)
{
	char *p = (char *)ptr - 8;
	int len = *(int*)p;
	delta -= len;
	m_log("F(%d)", len);
	cx_free(ctx, p);
}

static const struct CxOps log_ops = {
	log_alloc,
	log_realloc,
	log_free,
};

static const struct CxMem log_libc = {
	&log_ops,
	(void*)&cx_libc_allocator,
};

#define log_check(x) str_check(logbuf, x); reset();

static void test_cxalloc_basic(void *zzz)
{
	CxMem *cx = &log_libc;
	void *p;
	delta = 0;
	p = cx_alloc(cx, 16);
	log_check("A(16)")
	p = cx_realloc(cx, p, 500);
	log_check("R(500)")
	cx_free(cx, p);
	log_check("F(500)");
	int_check(delta, 0);
end:
	reset();
}

static void test_cxalloc_tree(void *zzz)
{
	CxMem *cx1, *cx2;
	void *p;
	delta = 0;
	cx1 = cx_new_tree(&log_libc);
	p = cx_alloc(cx1, 16);
	p = cx_realloc(cx1, p, 500);
	p = cx_realloc(cx1, p, 1500);
	p = cx_alloc(cx1, 55);
	cx_free(cx1, p);

	cx2 = cx_new_tree(cx1);
	p = cx_realloc(cx2, NULL, 2500);
	cx2 = cx_new_tree(cx2);
	p = cx_realloc(cx2, NULL, 3500);

	cx_destroy(cx1);

	/* str_check(logbuf, "A(16)R(500)F()"); */
	int_check(delta, 0);
end:
	reset();
}

static void test_cxalloc_util(void *zzz)
{
	CxMem *cx = &log_libc;
	void *p;
	delta = 0;
	p = cx_strdup(cx, "3333");
	log_check("A(5)");
	str_check(p, "3333");
	cx_free(cx, p);
	log_check("F(5)");

	p = cx_memdup(cx, "9876543", 8);
	log_check("A(8)");
	str_check(p, "9876543");
	cx_free(cx, p);
	log_check("F(8)");

	p = cx_sprintf(cx, "a=%s", "123");
	log_check("A(6)")
	cx_free(cx, p);
	log_check("F(6)");
	int_check(delta, 0);
end:;
}

struct testcase_t cxalloc_tests[] = {
	{ "basic", test_cxalloc_basic },
	{ "tree", test_cxalloc_tree },
	{ "util", test_cxalloc_util },
	END_OF_TESTCASES
};
