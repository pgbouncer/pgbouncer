#include <usual/base.h>
#include <string.h>
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

#undef basename
#undef dirname

#include <usual/string.h>
#include <usual/mbuf.h>

#include "test_common.h"

/*
 * strlcpy
 */

static char *run_strlcpy(char *dst, const char *src, int size, int expres)
{
	int res;
	memcpy(dst, "XXX", 4);
	res = strlcpy(dst, src, size);
	if (res != expres)
		return "FAIL";
	return dst;
}

static void test_strlcpy(void *ptr)
{
	char buf[128];
	str_check(run_strlcpy(buf, "", 16, 0), "");
	str_check(run_strlcpy(buf, "", 0, 0), "XXX");
	str_check(run_strlcpy(buf, "", 16, 0), "");
	str_check(run_strlcpy(buf, "abc", 16, 3), "abc");
	str_check(run_strlcpy(buf, "abc", 4, 3), "abc");
	str_check(run_strlcpy(buf, "abc", 3, 3), "ab");
	str_check(run_strlcpy(buf, "abc", 2, 3), "a");
	str_check(run_strlcpy(buf, "abc", 1, 3), "");
	str_check(run_strlcpy(buf, "abc", 0, 3), "XXX");
end:    ;
}

/*
 * strlcat
 */

static char *run_strlcat(char *dst, const char *src, int size, int expres)
{
	int res;
	memcpy(dst, "PFX", 4);
	res = strlcat(dst, src, size);
	if (res != expres)
		return "FAIL";
	return dst;
}

static void test_strlcat(void *ptr)
{
	char buf[128];
	str_check(run_strlcat(buf, "", 16, 3), "PFX");
	str_check(run_strlcat(buf, "abc", 16, 6), "PFXabc");
	str_check(run_strlcat(buf, "abc", 7, 6), "PFXabc");
	str_check(run_strlcat(buf, "abc", 6, 6), "PFXab");
	str_check(run_strlcat(buf, "abc", 5, 6), "PFXa");
	str_check(run_strlcat(buf, "abc", 4, 6), "PFX");
	str_check(run_strlcat(buf, "abc", 3, 6), "PFX");
	str_check(run_strlcat(buf, "abc", 2, 5), "PFX");
	str_check(run_strlcat(buf, "abc", 1, 4), "PFX");
	str_check(run_strlcat(buf, "abc", 0, 3), "PFX");
end:    ;
}


/*
 * strnlen()
 */
static void test_strnlen(void *p)
{
	tt_assert(strnlen("foobar", 0) == 0);
	tt_assert(strnlen("foobar", 1) == 1);
	tt_assert(strnlen("foobar", 2) == 2);
	tt_assert(strnlen("foobar", 3) == 3);
	tt_assert(strnlen("foobar", 4) == 4);
	tt_assert(strnlen("foobar", 5) == 5);
	tt_assert(strnlen("foobar", 6) == 6);
	tt_assert(strnlen("foobar", 7) == 6);
	tt_assert(strnlen("foobar", 8) == 6);
	tt_assert(strnlen("foobar", 9) == 6);
end:    ;
}


/*
 * strerror_r()
 */

static void test_strerror_r(void *p)
{
	char buf[128];
	/* "int" vs. "const char *" */
	tt_assert(strerror_r(EINTR, buf, sizeof(buf)) != 0);
	tt_assert(strlen(strerror_r(EINTR, buf, sizeof(buf))) != 0);
end:    ;
}
/*
 * strcmpeq
 */

static void test_strcmpeq(void *ptr)
{
	tt_assert(strcmpeq("foo", "foo") == true);
	tt_assert(strcmpeq(NULL, NULL) == true);

	tt_assert(strcmpeq("foo", "bar") == false);
	tt_assert(strcmpeq("foo", NULL) == false);
	tt_assert(strcmpeq(NULL, "foo") == false);
end:    ;
}


/*
 * memrchr
 */

static void test_memrchr(void *p)
{
	static const char data[] = "abcdabc";
	tt_assert(memrchr(data, 'a', 8) == data + 4);
	tt_assert(memrchr(data, 'a', 4) == data + 0);
	tt_assert(memrchr(data, 'd', 8) == data + 3);
	tt_assert(memrchr(data, 'x', 8) == NULL);
end:    ;
}

/*
 * memmem
 */

static int zmemm(const char *s, const char *q)
{
	char *r = memmem(s, strlen(s), q, strlen(q));
	return r ? (r - s) : -1;
}

static void test_memmem(void *p)
{
	int_check(zmemm("qwe", ""), 0);
	int_check(zmemm("qwe", "q"), 0);
	int_check(zmemm("qwe", "w"), 1);
	int_check(zmemm("qwe", "e"), 2);
	int_check(zmemm("qwe", "x"), -1);
	int_check(zmemm("qwe", "qw"), 0);
	int_check(zmemm("qwe", "we"), 1);
	int_check(zmemm("qwe", "qx"), -1);
	int_check(zmemm("qwe", "wx"), -1);
	int_check(zmemm("qwe", "ex"), -1);
	int_check(zmemm("qwe", "qwe"), 0);
	int_check(zmemm("qwe", "qwx"), -1);
	int_check(zmemm("qwe", "qxe"), -1);
	int_check(zmemm("qwe", "xwe"), -1);
	int_check(zmemm("qweqweza", "qweza"), 3);
	int_check(zmemm("qweqweza", "weza"), 4);
	int_check(zmemm("qweqweza", "eza"), 5);
	int_check(zmemm("qweqweza", "za"), 6);
	int_check(zmemm("qweqweza", "a"), 7);
	int_check(zmemm("qweqweza", "qwez"), 3);
	int_check(zmemm("qweqweza", "wez"), 4);
	int_check(zmemm("qweqweza", "ez"), 5);
	int_check(zmemm("qweqweza", "z"), 6);
	int_check(zmemm("qweqwez", "qweza"), -1);
	int_check(zmemm("qweqwez", "weza"), -1);
	int_check(zmemm("qweqwez", "eza"), -1);
	int_check(zmemm("qweqwez", "za"), -1);
	int_check(zmemm("qweqwez", "a"), -1);
end:    ;
}

/*
 * mempcpy
 */

static void test_mempcpy(void *p)
{
	char buf[128];
	memset(buf, 0, sizeof buf);
	tt_assert(mempcpy(buf, "xx", 0) == buf);  str_check(buf, "");
	tt_assert(mempcpy(buf, "xx", 1) == buf + 1);  str_check(buf, "x");
	tt_assert(mempcpy(buf, "yy", 2) == buf + 2);  str_check(buf, "yy");
end:    ;
}

/*
 * strpcpy
 */

static int run_strpcpy(char *dst, const char *src, int size)
{
	char *res;
	memcpy(dst, "XXX", 4);
	res = strpcpy(dst, src, size);
	if (res == NULL) {
		if (size == 0) {
			if (strcmp(dst, "XXX") != 0)
				return -10;
		} else {
			if (memcmp(dst, src, size - 1) != 0)
				return -11;
			if (dst[size - 1] != '\0')
				return -12;
		}
		return -1;
	}
	if (*res != '\0')
		return -13;
	if (memcmp(dst, src, res - dst) != 0)
		return -14;
	if (res < dst)
		return -15;
	return res - dst;
}

static void test_strpcpy(void *p)
{
	char buf[128];
	memset(buf, 0, sizeof buf);
	int_check(run_strpcpy(buf, "", 0), -1);
	int_check(run_strpcpy(buf, "", 1), 0);
	int_check(run_strpcpy(buf, "a", 0), -1);
	int_check(run_strpcpy(buf, "a", 1), -1);
	int_check(run_strpcpy(buf, "a", 2), 1);
	int_check(run_strpcpy(buf, "asd", 1), -1);
	int_check(run_strpcpy(buf, "asd", 2), -1);
	int_check(run_strpcpy(buf, "asd", 3), -1);
	int_check(run_strpcpy(buf, "asd", 4), 3);
	int_check(run_strpcpy(buf, "asd", 5), 3);
end:    ;
}

/*
 * strpcat
 */

static int run_strpcat(char *dst, const char *src, int size)
{
	char *res;
	char copydst[1024];
	char copy[1024];
	strlcpy(copydst, dst, sizeof copy);
	strlcpy(copy, dst, sizeof copy);
	strlcat(copy, src, sizeof copy);
	res = strpcat(dst, src, size);
	if (res == NULL) {
		if (size == 0) {
			if (strcmp(dst, copydst) != 0)
				return -10;
		} else {
			if (memcmp(dst, copy, size - 1) != 0)
				return -11;
			if (dst[size - 1] != '\0')
				return -12;
		}
		return -1;
	}
	if (*res != '\0')
		return -13;
	if (memcmp(dst, copy, res - dst) != 0)
		return -14;
	if (res < dst)
		return -15;
	return res - dst;
}

static void test_strpcat(void *p)
{
	char buf[128];
	memset(buf, 0, sizeof buf);
	int_check(run_strpcat(buf, "", 0), -1);
	int_check(run_strpcat(buf, "", 1), 0);
	int_check(run_strpcat(buf, "a", 1), -1);
	int_check(run_strpcat(buf, "a", 2), 1);
	str_check(buf, "a");

	int_check(run_strpcat(buf, "b", 0), -1);
	int_check(run_strpcat(buf, "b", 1), -12);
	int_check(run_strpcat(buf, "b", 2), -1);
	int_check(run_strpcat(buf, "b", 3), 2);
	str_check(buf, "ab");
end:    ;
}

/*
 * basename
 */

static const char *run_basename(const char *path)
{
	static char buf[128];
	const char *res;
	if (!path)
		return basename(NULL);
	strlcpy(buf, path, sizeof(buf));
	res = basename(buf);
	if (strcmp(buf, path) != 0)
		return "MODIFIES";
	return res;
}

static void test_basename(void *p)
{
	str_check(run_basename("/usr/lib"), "lib");
	str_check(run_basename("/usr/"), "usr");
	str_check(run_basename("/"), "/");
	str_check(run_basename("///"), "/");
	str_check(run_basename("//usr//lib//"), "lib");
	str_check(run_basename(""), ".");
	str_check(run_basename("a/"), "a");
	str_check(run_basename(NULL), ".");
end:    ;
}

/*
 * dirname
 */

static const char *run_dirname(const char *path)
{
	static char buf[128];
	const char *res;
	if (!path)
		return dirname(NULL);
	strlcpy(buf, path, sizeof(buf));
	res = dirname(buf);
	if (strcmp(buf, path) != 0)
		return "MODIFIES";
	return res;
}

static void test_dirname(void *p)
{
	str_check(run_dirname("/usr/lib"), "/usr");
	str_check(run_dirname("/usr/"), "/");
	str_check(run_dirname("usr"), ".");
	str_check(run_dirname("/usr/"), "/");
	str_check(run_dirname("/"), "/");
	str_check(run_dirname("/"), "/");
	str_check(run_dirname(".."), ".");
	str_check(run_dirname("."), ".");
	str_check(run_dirname(""), ".");
	str_check(run_dirname("a/"), ".");
	str_check(run_dirname("a//"), ".");
	str_check(run_dirname(NULL), ".");
end:    ;
}

/*
 * strlist
 */

static bool slshow(void *arg, const char *s)
{
	struct MBuf *mb = arg;
	if (mbuf_written(mb) > 0) {
		if (!mbuf_write_byte(mb, ','))
			return false;
	}
	if (!s) s = "NULL";
	return mbuf_write(mb, s, strlen(s));
}

static const char *lshow(const struct StrList *sl)
{
	static char buf[128];
	bool ok;
	struct MBuf mb;
	mbuf_init_fixed_writer(&mb, buf, sizeof(buf));
	ok = strlist_foreach(sl, slshow, &mb);
	if (!ok) return "FAIL";
	ok = mbuf_write_byte(&mb, 0);
	if (!ok) return "FAIL";
	return buf;
}

static void test_strlist(void *p)
{
	struct StrList *sl = NULL;
	char *s;
	sl = strlist_new(NULL);
	str_check(lshow(sl), "");
	strlist_append(sl, "1");
	str_check(lshow(sl), "1");
	strlist_append(sl, "2");
	str_check(lshow(sl), "1,2");
	strlist_append(sl, "3");
	str_check(lshow(sl), "1,2,3");
	s = strlist_pop(sl);
	str_check(s, "1");
	free(s);
	strlist_append(sl, NULL);
	str_check(lshow(sl), "2,3,NULL");
	strlist_free(sl);
end:    ;
}

static bool sl_add(void *arg, const char *s)
{
	return strlist_append(arg, s);
}

static const char *wlist(const char *s)
{
	const char *res = "FAIL";
	struct StrList *sl = strlist_new(NULL);
	bool ok = parse_word_list(s, sl_add, sl);
	if (ok) {
		if (strlist_empty(sl))
			res = "-";
		else
			res = lshow(sl);
	}
	strlist_free(sl);
	return res;
}

static void test_wlist(void *p)
{
	str_check(wlist("1,2,3"), "1,2,3");
	str_check(wlist(" 1 , \n 2 \t , \t3"), "1,2,3");
	str_check(wlist("  1 "), "1");
	str_check(wlist("  1 ,"), "1");
	str_check(wlist(",  1 "), "1");
	str_check(wlist("1  2"), "1  2");
	str_check(wlist("  "), "");
end:    ;
}

static void test_mempbrk(void *z)
{
	const char *p = "0123456789";
	tt_assert(mempbrk(p, 10, "", 0) == NULL);
	tt_assert(mempbrk(p, 10, "a", 0) == NULL);
	tt_assert(mempbrk(p, 10, "ab", 0) == NULL);
	tt_assert(mempbrk(p, 10, "abc", 0) == NULL);
	tt_assert(mempbrk(p, 10, "1", 1) == p + 1);
	tt_assert(mempbrk(p, 10, "12", 2) == p + 1);
	tt_assert(mempbrk(p, 10, "21", 2) == p + 1);
	tt_assert(mempbrk(p, 10, "123", 3) == p + 1);
	tt_assert(mempbrk(p, 10, "321", 3) == p + 1);
	tt_assert(mempbrk(p, 11, "abc\0", 4) == p + 10);
end:    ;
}

static void test_memcspn(void *z)
{
	int_check(memcspn("qwe", 3, "", 0), 3);
	int_check(memcspn("qwe", 3, "w", 1), 1);
	int_check(memcspn("qwe", 3, "z", 1), 3);
	int_check(memcspn("qwe", 3, "we", 2), 1);
	int_check(memcspn("qwe", 3, "eq", 2), 0);
	int_check(memcspn("qwe", 3, "zx", 2), 3);
	int_check(memcspn("qwe", 3, "wez", 3), 1);
	int_check(memcspn("qwe", 3, "ewz", 3), 1);
	int_check(memcspn("qwe", 3, "zxa", 3), 3);
	int_check(memcspn("qwe", 3, "weza", 4), 1);
	int_check(memcspn("qwe", 3, "azew", 4), 1);
	int_check(memcspn("qwe", 3, "zxab", 4), 3);
end:    ;
}

static void test_memspn(void *z)
{
	const char *d = "0123456789";
	int_check(memspn(d, 10, "", 0), 0);
	int_check(memspn(d, 10, "0", 1), 1);
	int_check(memspn(d, 10, "1", 1), 0);
	int_check(memspn(d, 10, "23", 2), 0);
	int_check(memspn(d, 10, "01", 2), 2);
	int_check(memspn(d, 10, "456", 3), 0);
	int_check(memspn(d, 10, "012", 3), 3);
	int_check(memspn(d, 10, "4567", 4), 0);
	int_check(memspn(d, 10, "0123", 4), 4);
	int_check(memspn(d, 10, d, 10), 10);
	int_check(memspn(d, 11, d, 11), 11);
end:    ;
}

static void test_s2d_dot(void *p)
{
	char buf[128];
	double val;
	char *end;

	memset(buf, 0, sizeof(buf));
	dtostr_dot(buf, sizeof(buf), 1.5);
	str_check(buf, "1.5");
	val = strtod_dot(buf, &end);
	tt_assert(val == 1.5);
	tt_assert(*end == 0);
end:    ;
}

static const char *wrap_strtonum(const char *s, long long minval, long long maxval)
{
	static char buf[256];
	long long res, res1;
	const char *err = "HUH";
	errno = EPERM;
	res1 = strtonum(s, minval, maxval, NULL);
	errno = EPERM;
	res = strtonum(s, minval, maxval, &err);
	if (err && (res != 0 || !errno || errno == ENOMEM))
		return "ERRBUG";
	if (!err && errno != EPERM)
		return "ERRBACKUP";
	if (res1 != res)
		return "EH";
	if (!err) {
		snprintf(buf, sizeof buf, "%" PRId64, (int64_t)res);
		return buf;
	}
	snprintf(buf, sizeof buf, "E:%s", err);
	return buf;
}

static void test_strtonum(void *p)
{
	str_check(wrap_strtonum("1", -10, 50), "1");
	str_check(wrap_strtonum("-11", -100, -1), "-11");
	str_check(wrap_strtonum("", 1, 9), "E:invalid");
	str_check(wrap_strtonum(" ", 1, 9), "E:invalid");
	str_check(wrap_strtonum(" x", 1, 9), "E:invalid");
	str_check(wrap_strtonum(" 5.5", 1, 9), "E:invalid");
	str_check(wrap_strtonum(" 5 ", 1, 9), "E:invalid");
	str_check(wrap_strtonum("0x05", 1, 9), "E:invalid");
	str_check(wrap_strtonum("0", 1, 9), "E:too small");
	str_check(wrap_strtonum("11", 1, 9), "E:too large");
	str_check(wrap_strtonum(" 5", 1, 9), "5");
	str_check(wrap_strtonum(" -5", -10, 10), "-5");

	str_check(wrap_strtonum("5", -5, 5), "5");
	str_check(wrap_strtonum("-5", -5, 5), "-5");
	str_check(wrap_strtonum("6", -5, 5), "E:too large");
	str_check(wrap_strtonum("-6", -5, 5), "E:too small");
	/* limits */
	str_check(wrap_strtonum(" 9223372036854775807", LLONG_MIN, LLONG_MAX), "9223372036854775807");
	str_check(wrap_strtonum(" 9223372036854775808", LLONG_MIN, LLONG_MAX), "E:too large");
	str_check(wrap_strtonum(" 9900000000000000000", LLONG_MIN, LLONG_MAX), "E:too large");
	str_check(wrap_strtonum("-9223372036854775808", LLONG_MIN, LLONG_MAX), "-9223372036854775808");
	str_check(wrap_strtonum("-9223372036854775809", LLONG_MIN, LLONG_MAX), "E:too small");
	str_check(wrap_strtonum("-9900000000000000000", LLONG_MIN, LLONG_MAX), "E:too small");
	str_check(wrap_strtonum("-10", LLONG_MIN, 0), "-10");
	str_check(wrap_strtonum("10", 0, LLONG_MAX), "10");
	str_check(wrap_strtonum(" 9223372036854775807", -10, 10), "E:too large");
	str_check(wrap_strtonum("-9223372036854775808", -10, 10), "E:too small");
end:    ;
}

static const char *run_strsep(const char *input, const char *delim)
{
	static char buf[1024];
	static char res[1024];
	char *ptr, *tok;

	strlcpy(buf, input, sizeof(buf));
	res[0] = 0;

	for (ptr = buf; ptr; ) {
		tok = strsep(&ptr, delim);
		if (!tok) tok = "NULL";
		strlcat(res, "(", sizeof(res));
		strlcat(res, tok, sizeof(res));
		strlcat(res, ")", sizeof(res));
	}
	return res;
}

static void test_strsep(void *p)
{
	char *ptr = NULL;

	tt_assert(strsep(&ptr, "x") == NULL);
	str_check(run_strsep("", ""), "()");
	str_check(run_strsep("qwe", ""), "(qwe)");
	str_check(run_strsep("", ","), "()");
	str_check(run_strsep("a,b,,c", ","), "(a)(b)()(c)");
	str_check(run_strsep(",,", ","), "()()()");
	str_check(run_strsep(",:,", ",:"), "()()()()");
	str_check(run_strsep(",:,", ":,"), "()()()()");
	str_check(run_strsep("", ",:"), "()");
	str_check(run_strsep(" a , b : c ", ",:"), "( a )( b )( c )");
end:    ;
}

#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 7
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

static void test_snprintf(void *p)
{
	char buf[32];
	char *longstr = "0123456789";
	int_check(snprintf(buf, 7, "%s", longstr), 10);
	int_check(snprintf(buf, 8, "%s", longstr), 10);
	int_check(snprintf(buf, 9, "%s", longstr), 10);
	int_check(snprintf(buf, 10, "%s", longstr), 10);
	int_check(snprintf(buf, 11, "%s", longstr), 10);
	int_check(snprintf(buf, 12, "%s", longstr), 10);
end:    ;
}

#pragma GCC diagnostic pop

static void test_asprintf(void *p)
{
	char *res = NULL;

	int_check(asprintf(&res, "%s", "1234"), 4);
	str_check(res, "1234");
	free(res);
end:    ;
}

_PRINTF(2, 3)
static int tmp_asprintf(char **dst, const char *fmt, ...)
{
	int res;
	va_list ap;
	va_start(ap, fmt);
	res = vasprintf(dst, fmt, ap);
	va_end(ap);
	return res;
}

static void test_vasprintf(void *p)
{
	char *res = NULL;
	int_check(tmp_asprintf(&res, "%s", "1234"), 4);
	str_check(res, "1234");
	free(res);
end:    ;
}

/*
 * Describe
 */

struct testcase_t string_tests[] = {
	{ "strlcpy", test_strlcpy },
	{ "strlcat", test_strlcat },
	{ "strnlen", test_strnlen },
	{ "strerror_r", test_strerror_r },
	{ "strcmpeq", test_strcmpeq },
	{ "memrchr", test_memrchr },
	{ "memmem", test_memmem },
	{ "mempbrk", test_mempbrk },
	{ "memcspn", test_memcspn },
	{ "memspn", test_memspn},
	{ "mempcpy", test_mempcpy },
	{ "strsep", test_strsep },
	{ "strpcpy", test_strpcpy },
	{ "strpcat", test_strpcat },
	{ "basename", test_basename },
	{ "dirname", test_dirname },
	{ "strlist", test_strlist },
	{ "parse_wordlist", test_wlist },
	{ "str2double_dot", test_s2d_dot },
	{ "strtonum", test_strtonum },
	{ "snprintf", test_snprintf },
	{ "asprintf", test_asprintf },
	{ "vasprintf", test_vasprintf },
	END_OF_TESTCASES
};
