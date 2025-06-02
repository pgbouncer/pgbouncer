#include <usual/fileutil.h>

#include <usual/string.h>
#include <usual/mbuf.h>

#include "test_common.h"

/*
 * LN1 = 4*8
 * LN2 = 8*4*8
 * LN3 = 8*8*4*8
 */

#define LN1 "11112222333344445555666677778888"
#define LN2 LN1 LN1 LN1 LN1   LN1 LN1 LN1 LN1
#define LN3 LN2 LN2 LN2 LN2   LN2 LN2 LN2 LN2

static const char fdata[] = "1\n"
"line 2\n"
"\n"
LN3
"noln";
static const char filename[] = "test_fileutil.tmp";

static bool createfile(void)
{
	FILE *f = fopen(filename, "wb+");
	if (!f) return false;
	fwrite(fdata, 1, strlen(fdata), f);
	fclose(f);
	return true;
}

static void test_fsize(void *p)
{
	int_check(createfile(), 1);

	tt_assert(file_size(filename) == (int)strlen(fdata));
	tt_assert(file_size(filename) == (int)sizeof(fdata) - 1);
	tt_assert(file_size("nonexist") == -1);
end:;
}

static bool addln(void *arg, const char *ln, ssize_t len)
{
	struct MBuf *buf = arg;
	int xlen = len;
	if (len < 0)
		return false;
	if (len > 0 && ln[len - 1] == '\n')
		xlen--;
	if (memchr(ln, '\n', xlen))
		return false;
	return mbuf_write(buf, ln, len);
}

static void test_getline(void *p)
{
	struct MBuf buf;

	mbuf_init_dynamic(&buf);

	tt_assert(foreach_line(filename, addln, &buf));
	tt_assert(mbuf_write_byte(&buf, 0));
end:
	unlink(filename);
	mbuf_free(&buf);
}

struct testcase_t fileutil_tests[] = {
	{ "file_size", test_fsize },
	{ "getline", test_getline },
	END_OF_TESTCASES
};
