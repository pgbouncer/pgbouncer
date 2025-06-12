#include <usual/wchar.h>
#include <string.h>

#include "test_common.h"


/*
 * mbstr_decode()
 */

static const char *decode(const char *s, int inbuf)
{
	static char out[128];
	wchar_t tmp[128];
	wchar_t *res;
	int reslen = 4;
	unsigned i;

	for (i = 0; i < 128; i++)
		tmp[i] = '~';

	res = mbstr_decode(s, inbuf, &reslen, tmp, sizeof(tmp), true);
	if (res == NULL) {
		if (errno == EILSEQ) return "EILSEQ";
		if (errno == ENOMEM) return "ENOMEM";
		return "NULL??";
	}
	if (res != tmp)
		return "EBUF";
	if (res[reslen] == 0)
		res[reslen] = 'Z';
	else
		return "reslen fail?";

	for (i = 0; i < 128; i++) {
		out[i] = tmp[i];
		if (out[i] == '~') {
			out[i+1] = 0;
			break;
		} else if (out[i] == 0) {
			out[i] = '#';
		} else if (tmp[i] > 127) {
			out[i] = 'A' + tmp[i] % 26;
		}
	}
	return out;
}

static void test_mbstr_decode(void *p)
{
	str_check(decode("", 0), "Z~");
	str_check(decode("", 1), "Z~");
	str_check(decode("a", 0), "Z~");

	str_check(decode("abc", 0), "Z~");
	str_check(decode("abc", 1), "aZ~");
	str_check(decode("abc", 2), "abZ~");
	str_check(decode("abc", 3), "abcZ~");
	str_check(decode("abc", 4), "abcZ~");
	str_check(decode("abc", 5), "abcZ~");

	if (MB_CUR_MAX > 1) {
		str_check(decode("aa\200cc", 5), "aaYccZ~");
		str_check(decode("a\200cc", 5), "aYccZ~");
		str_check(decode("aa\200c", 5), "aaYcZ~");
	}
end:;
}

/*
 * mbsnrtowcs()
 */


static const char *mbsnr(const char *str, int inbuf, int outbuf)
{
	static char out[128];
	wchar_t tmp[128];
	int res;
	unsigned i;
	const char *s = str;
	mbstate_t ps;

	for (i = 0; i < 128; i++)
		tmp[i] = '~';

	memset(&ps, 0, sizeof(ps));
	res = mbsnrtowcs(tmp, &s, inbuf, outbuf, &ps);
	if (res < 0) {
		if (errno == EILSEQ) {
			snprintf(out, sizeof(out), "EILSEQ(%d)", (int)(s - str));
			return out;
		}
		return "unknown error";
	}
	if (tmp[res] == 0)
		tmp[res] = s ? 'z' : 'Z';

	for (i = 0; i < 128; i++) {
		out[i] = tmp[i];
		if (out[i] == '~') {
			out[i+1] = 0;
			break;
		}
	}
	return out;
}

static void test_mbsnrtowcs(void *p)
{
	str_check(mbsnr("", 1, 1), "Z~");
	str_check(mbsnr("", 0, 0), "~");
	str_check(mbsnr("", 0, 1), "~"); /* XXX */
	str_check(mbsnr("", 1, 0), "~");

	str_check(mbsnr("x", 1, 1), "x~");
	str_check(mbsnr("x", 0, 0), "~");
	str_check(mbsnr("x", 0, 1), "~"); /* XXX */
	str_check(mbsnr("x", 1, 0), "~");

	str_check(mbsnr("abc", 3, 3), "abc~");
	str_check(mbsnr("abc", 3, 4), "abc~"); /* XXX */

	str_check(mbsnr("abc", 4, 3), "abc~");
	str_check(mbsnr("abc", 4, 4), "abcZ~");
end:;
}

/*
 * Describe
 */

struct testcase_t wchar_tests[] = {
	{ "mbsnrtowcs", test_mbsnrtowcs },
	{ "mbstr_decode", test_mbstr_decode },
	END_OF_TESTCASES
};
