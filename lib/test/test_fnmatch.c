#include <usual/fnmatch.h>

#include <usual/string.h>
#include <usual/wchar.h>
#include "test_common.h"

/*
 * POSIX syntax.
 */

static void test_fnmatch_posix(void *p)
{
	/* literal */
	int_check(0, fnmatch("", "", 0));
	int_check(0, fnmatch("a", "a", 0));
	int_check(0, fnmatch("abc", "abc", 0));
	int_check(1, fnmatch("", "b", 0));
	int_check(1, fnmatch("a", "", 0));
	int_check(1, fnmatch("a", "b", 0));

	/* single wildcard */
	int_check(0, fnmatch("a?", "ax", 0));
	int_check(0, fnmatch("??", "ax", 0));
	int_check(1, fnmatch("?", "ax", 0));
	int_check(1, fnmatch("???", "ax", 0));

	/* wildcard */
	int_check(0, fnmatch("a*", "ax", 0));
	int_check(0, fnmatch("*", "", 0));
	int_check(0, fnmatch("*", "qwe", 0));
	int_check(0, fnmatch("ab*ab", "abxxab", 0));
	int_check(1, fnmatch("ab*ab", "abxxabc", 0));

	/* wildcard+ */
	int_check(0, fnmatch("ab*ab*", "abxxabc", 0));
	int_check(0, fnmatch("ab*ab*c", "abxxabc", 0));
	int_check(0, fnmatch("ab*ab*c", "abxxabxc", 0));
	int_check(0, fnmatch("??*??", "abxxab", 0));
	int_check(0, fnmatch("*??", "abxxab", 0));
	int_check(0, fnmatch("??*", "abxxab", 0));
	int_check(0, fnmatch("a**c", "abc", 0));

	/* classes */
	int_check(0, fnmatch("[abc]", "b", 0));
	int_check(1, fnmatch("[abc]", "x", 0));
	int_check(0, fnmatch("[a-c]", "b", 0));
	int_check(1, fnmatch("[a-c]", "x", 0));
	int_check(0, fnmatch("[b-b]", "b", 0));
	int_check(1, fnmatch("[!abc]", "b", 0));
	int_check(1, fnmatch("[!a-c]", "b", 0));
	int_check(0, fnmatch("[!a-c]", "x", 0));
	int_check(0, fnmatch("[*?[][*?[][*?[]", "*?[", 0));
	int_check(0, fnmatch("[[:alpha:]][![:alpha:]]", "a9", 0));
	int_check(0, fnmatch("[[:alnum:]][![:alnum:]]", "9-", 0));
#ifdef iswblank
	int_check(0, fnmatch("[[:blank:]][![:blank:]]", " -", 0));
#endif
	int_check(0, fnmatch("[[:cntrl:]][![:cntrl:]]", "\tx", 0));
	int_check(0, fnmatch("[[:digit:]][![:digit:]]", "9a", 0));
	int_check(0, fnmatch("[[:graph:]][![:graph:]]", "a\t", 0));
	int_check(0, fnmatch("[[:lower:]][![:lower:]]", "aA", 0));
	int_check(0, fnmatch("[[:print:]][![:print:]]", "a\n", 0));
	int_check(0, fnmatch("[[:punct:]][![:punct:]]", ".x", 0));
	int_check(0, fnmatch("[[:space:]][![:space:]]", " x", 0));
	int_check(0, fnmatch("[[:upper:]][![:upper:]]", "Ff", 0));
	int_check(0, fnmatch("[[:xdigit:]][![:xdigit:]]", "Fx", 0));
	int_check(0, fnmatch("[", "[", 0));
	int_check(0, fnmatch("[f", "[f", 0));

	/* escaping */
	int_check(1, fnmatch("\\a\\?", "ax", 0));
	int_check(0, fnmatch("\\a\\?", "a?", 0));
	int_check(1, fnmatch("\\a\\*", "ax", 0));
	int_check(0, fnmatch("\\a\\*", "a*", 0));
	int_check(0, fnmatch("\\[a]", "[a]", 0));
	int_check(0, fnmatch("\\\\", "\\", 0));
	int_check(0, fnmatch("\\$\\'\\\"\\<\\>", "$'\"<>", 0));
	int_check(1, fnmatch("a\\", "a", 0));
	int_check(1, fnmatch("a\\", "a\\", 0));
	int_check(0, fnmatch("a\\", "a\\", FNM_NOESCAPE));
	int_check(0, fnmatch("\\[a]", "\\a", FNM_NOESCAPE));
	int_check(0, fnmatch("\\*b", "\\aab", FNM_NOESCAPE));

	/* FNM_PATHNAME */
	int_check(0, fnmatch("ab*c", "ab/c", 0));
	int_check(1, fnmatch("ab*c", "ab/c", FNM_PATHNAME));
	int_check(1, fnmatch("ab?c", "ab/c", FNM_PATHNAME));
	int_check(1, fnmatch("ab[/]c", "ab/c", FNM_PATHNAME));
	int_check(0, fnmatch("/*/", "//", FNM_PATHNAME));
	int_check(1, fnmatch("a[b/c]d", "a/d", FNM_PATHNAME));
	int_check(0, fnmatch("abd", "abd", FNM_PATHNAME));
	int_check(1, fnmatch("a[b/c]d", "a[b/c]d", FNM_PATHNAME));

	/* FNM_PERIOD */
	int_check(0, fnmatch(".foo", ".foo", 0));
	int_check(0, fnmatch("?foo", ".foo", 0));
	int_check(0, fnmatch("[.]foo", ".foo", 0));
	int_check(0, fnmatch("[!abc]foo", ".foo", 0));
	int_check(0, fnmatch("*foo", ".foo", 0));
	int_check(0, fnmatch(".foo", ".foo", FNM_PERIOD));
	int_check(1, fnmatch("*foo", ".foo", FNM_PERIOD));
	int_check(1, fnmatch("?foo", ".foo", FNM_PERIOD));
	int_check(0, fnmatch("*/?foo", "sub/.foo", FNM_PERIOD));
	int_check(1, fnmatch("*.foo", ".foo", FNM_PERIOD));
	int_check(1, fnmatch("[.]foo", ".foo", FNM_PERIOD));

	/* FNM_PATHNAME | FNM_PERIOD */
	int_check(1, fnmatch("*/?foo", "sub/.foo", FNM_PERIOD|FNM_PATHNAME));
	int_check(1, fnmatch("*/[.]foo", "sub/.foo", FNM_PERIOD|FNM_PATHNAME));
	int_check(1, fnmatch("*/*.c", "sub/.foo.c", FNM_PERIOD|FNM_PATHNAME));
	int_check(1, fnmatch("*/*", "sub/.foo.c", FNM_PERIOD|FNM_PATHNAME));
	int_check(0, fnmatch("*/*.c", "sub/foo..c", FNM_PERIOD|FNM_PATHNAME));
	int_check(1, fnmatch("*/*.foo", "sub/.foo", FNM_PERIOD|FNM_PATHNAME));

	/* escapes in brackets ~ posix */
	int_check(0, fnmatch("[A\\]]", "\\]", FNM_NOESCAPE));
#ifndef HAVE_FNMATCH
	int_check(0, fnmatch("[a\\-x]", "_", FNM_NOESCAPE));
#endif
end:    ;
}

/*
 * GNU syntax.
 */

static void test_fnmatch_gnu(void *p)
{
	/* FNM_CASEFOLD */
	int_check(1, fnmatch("aaAA", "AaAa", 0));
	int_check(1, fnmatch("[b][b][B][B][a-c][A-C][a-c][A-C]", "bBbBbbBB", 0));
	int_check(0, fnmatch("aaAA", "AaAa", FNM_CASEFOLD));
	int_check(0, fnmatch("[b][b][B][B][a-c][A-C][a-c][A-C]", "bBbBbbBB", FNM_CASEFOLD));

	/* FNM_LEADING_DIR */
	int_check(0, fnmatch("a", "a", FNM_LEADING_DIR|FNM_PATHNAME));
	int_check(0, fnmatch("a", "a/b", FNM_LEADING_DIR|FNM_PATHNAME));
	int_check(0, fnmatch("a/b", "a/b/c/d", FNM_LEADING_DIR|FNM_PATHNAME));
	int_check(0, fnmatch("a/*/*", "a/b/c/d", FNM_LEADING_DIR|FNM_PATHNAME));
	int_check(0, fnmatch("*", "/a", FNM_LEADING_DIR|FNM_PATHNAME));
	/* seems wrong to allow it */
	int_check(0, fnmatch("a", "a/b", FNM_LEADING_DIR));

	/* escapes in brackets ~ gnu */
	int_check(0, fnmatch("[A\\]][A\\]]", "]A", 0));
	int_check(1, fnmatch("[a\\-x]", "_", 0));
	int_check(0, fnmatch("[\\!x]", "!", 0));
	int_check(1, fnmatch("[\\!x]", "\\", 0));
	int_check(0, fnmatch("[\\[:alnum:]", ":", 0));
end:    ;
}

/*
 * DoS possibilities.
 */

static void test_fnmatch_weird(void *p)
{
	char pat[4096];
	char str[4096];
	int i;

	memset(pat, 0, sizeof(pat));
	memset(str, 0, sizeof(str));

	memset(pat, '*', 1500);
	memset(str, 'a', 1500);
	int_check(0, fnmatch(pat, str, 0));

	pat[10] = 'a';
	pat[1200] = 'b';
	int_check(0, fnmatch(pat, "ab", 0));

	for (i = 0; i < 1200; i++) {
		char c = 'a' + (i%26);
		pat[i*2] = c;
		pat[i*2 + 1] = '*';
		str[i*2] = c;
		str[i*2 + 1] = c;
	}
	pat[i*2] = 0;
	str[i*2] = 0;
	int_check(0, fnmatch(pat, str, 0));

	for (i = 0; i < 2000; i++) {
		pat[i*2] = '*';
		pat[i*2 + 1] = '?';
		str[i*2] = 'a';
		str[i*2 + 1] = 'b';
	}
	str[i*2] = 0;
	pat[i*2] = 0;
	int_check(0, fnmatch(pat, str, 0));
	pat[i*2] = 'a';
	pat[i*2 + 1] = 0;
	int_check(1, fnmatch(pat, str, 0));
	pat[i*2] = 'b';
	int_check(0, fnmatch(pat, str, 0));
	pat[i*2] = '*';
	pat[3] = 'x';
	str[2000] = 'x';
	int_check(0, fnmatch(pat, str, 0));

	memset(pat, '?', sizeof(pat));
	memset(str, 'x', sizeof(str));
	str[4000] = 0;
	pat[2000] = 0;
	pat[0] = '*';
	int_check(0, fnmatch(pat, str, 0));
end:    ;
}

struct testcase_t fnmatch_tests[] = {
	{ "posix", test_fnmatch_posix },
	{ "gnu", test_fnmatch_gnu },
	{ "weird", test_fnmatch_weird },
	END_OF_TESTCASES
};
