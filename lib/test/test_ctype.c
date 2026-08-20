#include <usual/ctype.h>

#include <string.h>
#include "test_common.h"

#include <stdio.h>

/*
 * if char works
 */

static void test_ctype_char(void *p)
{
	int c, cx;
	for (c = 0; c < 256; c++) {
		cx = (int)(char)c;
		int_check(isalnum(c), isalnum(cx));
		int_check(isalpha(c), isalpha(cx));
		int_check(isascii(c), isascii(cx));
		int_check(isblank(c), isblank(cx));
		int_check(iscntrl(c), iscntrl(cx));
		int_check(isdigit(c), isdigit(cx));
		int_check(islower(c), islower(cx));
		int_check(isgraph(c), isgraph(cx));
		int_check(isprint(c), isprint(cx));
		int_check(ispunct(c), ispunct(cx));
		int_check(isspace(c), isspace(cx));
		int_check(isupper(c), isupper(cx));
		int_check(isxdigit(c), isxdigit(cx));
		if (c == 255) {
			int_check(toupper(c), (unsigned char)toupper(cx));
			int_check(tolower(c), (unsigned char)tolower(cx));
		} else {
			int_check(toupper(c), toupper(cx));
			int_check(tolower(c), tolower(cx));
		}
	}
end:    ;
}


/*
 * Describe
 */

struct testcase_t ctype_tests[] = {
	{ "ctype_char", test_ctype_char },
	END_OF_TESTCASES
};
