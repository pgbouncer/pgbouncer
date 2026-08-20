#include <usual/utf8.h>

#include "test_common.h"

#include <string.h>

static int uget1(int a)
{
	char buf[2] = { a, 0 };
	const char *p = buf;
	return utf8_get_char(&p, buf + 1);
}

static int uget2(int a, int b)
{
	char buf[3] = { a, b, 0 };
	const char *p = buf;
	return utf8_get_char(&p, buf + 2);
}

static int uget3(int a, int b, int c)
{
	char buf[4] = { a, b, c, 0 };
	const char *p = buf;
	return utf8_get_char(&p, buf + 3);
}

static int uget4(int a, int b, int c, int d)
{
	char buf[5] = { a, b, c, d, 0 };
	const char *p = buf;
	return utf8_get_char(&p, buf + 4);
}

static const char *mkseq(uint32_t c, int n)
{
	static char buf[8];
	static const uint8_t prefix[] = { 0, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
	int i;
	for (i = n - 1; i > 0; i--) {
		buf[i] = (c & 0x3F) | 0x80;
		c >>= 6;
	}
	buf[0] = prefix[n - 1] | c;
	return buf;
}

static int readseq(uint32_t c, int n)
{
	const char *p = mkseq(c, n);
	return utf8_get_char(&p, p + n);
}

static void test_utf8_char_size(void *p)
{
	int_check(utf8_char_size(0), 1);
	int_check(utf8_char_size('a'), 1);
	int_check(utf8_char_size(0x7F), 1);
	int_check(utf8_char_size(0x80), 2);
	int_check(utf8_char_size(0x7FF), 2);
	int_check(utf8_char_size(0x800), 3);
	int_check(utf8_char_size(0xFFFF), 3);
	int_check(utf8_char_size(0x10000), 4);
	int_check(utf8_char_size(0x100000), 4);
	int_check(utf8_char_size(0x10FFFF), 4);
end:    ;
}

static void test_utf8_seq_size(void *p)
{
	int_check(utf8_seq_size(0), 1);
	int_check(utf8_seq_size(0x7F), 1);
	int_check(utf8_seq_size(0x80), 0);
	int_check(utf8_seq_size(0xBF), 0);
	int_check(utf8_seq_size(0xC0), 0);
	int_check(utf8_seq_size(0xC1), 0);
	int_check(utf8_seq_size(0xC2), 2);
	int_check(utf8_seq_size(0xDF), 2);
	int_check(utf8_seq_size(0xE0), 3);
	int_check(utf8_seq_size(0xEF), 3);
	int_check(utf8_seq_size(0xF0), 4);
	int_check(utf8_seq_size(0xF4), 4);
	int_check(utf8_seq_size(0xF5), 0);
	int_check(utf8_seq_size(0xFF), 0);
end:    ;
}

static void test_utf8_get_char(void *p)
{
	int_check(uget1(0), 0);
	int_check(uget1(0x7F), 0x7F);
	int_check(uget2(0xC2, 0xA2), 0xA2);
	int_check(uget2(0xC2, 0xA2), 0xA2);
	int_check(uget3(0xE2, 0x82, 0xAC), 0x20AC);
	int_check(uget4(0xF0, 0xA4, 0xAD, 0xA2), 0x024B62);

	/* invalid reads */
	int_check(uget1(0x80), -0x80);
	int_check(uget1(0xC1), -0xC1);
	int_check(uget3(0xE0, 0x82, 0xAC), -0xE0);

	/* short reads */
	int_check(uget1(0xC2), -0xC2);
	int_check(uget2(0xE2, 0x82), -0xE2);
	int_check(uget3(0xF0, 0xA4, 0xAD), -0xF0);

	/* good boundaries */
	int_check(readseq(0x7f, 1), 0x7f);
	int_check(readseq(0x80, 2), 0x80);
	int_check(readseq(0x7ff, 2), 0x7ff);
	int_check(readseq(0x800, 3), 0x800);
	int_check(readseq(0xffff, 3), 0xffff);
	int_check(readseq(0x10000, 4), 0x10000);
	int_check(readseq(0x10ffff, 4), 0x10ffff);
	int_check(readseq(0xd7ff, 3), 0xd7ff);
	int_check(readseq(0xe000, 3), 0xe000);

	/* bad boundaries */
	int_check(readseq(0x7f, 2), -193);
	int_check(readseq(0x7ff, 3), -224);
	int_check(readseq(0xffff, 4), -240);
	int_check(readseq(0x110000, 4), -244);
	int_check(readseq(0x10ffff, 5), -248);
	int_check(readseq(0xd800, 3), -237);
	int_check(readseq(0xdfff, 3), -237);
end:    ;
}

static const char *uput(unsigned c, int buflen)
{
	static char res[64];
	unsigned char buf[8];
	char *dst = (char *)buf;
	char *dstend = (char *)buf + buflen;
	unsigned len, i;
	bool ok;

	memset(buf, 11, sizeof(buf));
	ok = utf8_put_char(c, &dst, dstend);
	if (!ok)
		return "FAILED";
	len = dst - (char *)buf;
	for (i = len; i < 8; i++) {
		if (buf[i] != 11)
			return "OVER";
	}
	snprintf(res, sizeof(res), "%02X %02X %02X %02X %02X %02X",
		 buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	if (len)
		res[len*3 - 1] = 0;
	else
		res[0] = 0;
	return res;
}

static void test_utf8_put_char(void *p)
{
	str_check(uput(0, 1), "00");
	str_check(uput(0x7F, 1), "7F");
	str_check(uput(0xA2, 2), "C2 A2");
	str_check(uput(0x20AC, 3), "E2 82 AC");
	str_check(uput(0x024B62, 4), "F0 A4 AD A2");
	str_check(uput(0x80FFFFFF, 5), "");
	str_check(uput(0xD801, 5), "");
	str_check(uput(0xFEFF, 5), "EF BB BF");
	str_check(uput(0xFFFE, 5), "EF BF BE");

	str_check(uput(0, 0), "FAILED");
	str_check(uput(0xA2, 1), "FAILED");
	str_check(uput(0x20AC, 2), "FAILED");
	str_check(uput(0x20AC, 1), "FAILED");
	str_check(uput(0x024B62, 3), "FAILED");
	str_check(uput(0x024B62, 2), "FAILED");
	str_check(uput(0x024B62, 1), "FAILED");
	str_check(uput(0x024B62, 0), "FAILED");
end:    ;
}

static int validseq(uint32_t c, int n)
{
	const char *p = mkseq(c, n);
	return utf8_validate_seq(p, p + n);
}

static void test_utf8_validate_seq(void *p)
{
	/* good boundaries */
	int_check(validseq(0x7f, 1), 1);
	int_check(validseq(0x80, 2), 2);
	int_check(validseq(0x7ff, 2), 2);
	int_check(validseq(0x800, 3), 3);
	int_check(validseq(0xffff, 3), 3);
	int_check(validseq(0x10000, 4), 4);
	int_check(validseq(0x10ffff, 4), 4);
	int_check(validseq(0xd7ff, 3), 3);
	int_check(validseq(0xe000, 3), 3);

	/* bad boundaries */
	int_check(validseq(0x7f, 2), 0);
	int_check(validseq(0x7ff, 3), 0);
	int_check(validseq(0xffff, 4), 0);
	int_check(validseq(0x110000, 4), 0);
	int_check(validseq(0x10ffff, 5), 0);
	int_check(validseq(0xd800, 3), 0);
	int_check(validseq(0xdfff, 3), 0);
end:    ;
}

/*
 * Describe
 */

struct testcase_t utf8_tests[] = {
	{ "utf8_char_size", test_utf8_char_size },
	{ "utf8_seq_size", test_utf8_seq_size },
	{ "utf8_get_char", test_utf8_get_char },
	{ "utf8_put_char", test_utf8_put_char },
	{ "utf8_validate_seq", test_utf8_validate_seq },
	END_OF_TESTCASES
};
