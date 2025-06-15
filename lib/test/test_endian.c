#include <usual/endian.h>

#include "test_common.h"

#include <string.h>

/*
 * bswap*()
 */

static void test_bswap(void *p)
{
	int_check(bswap16(0xff01), 0x01ff);
	int_check(bswap32(0x01020304), 0x04030201);
	ull_check(bswap64(0x0102030405060708ULL), 0x0807060504030201ULL);
end:;
}

/*
 * *enc(), *dec()
 */

static uint64_t tdecode(int t, ...)
{
	uint8_t buf[16];
	bool be = t > 0;
	va_list ap;
	uint64_t val = 777;
	int i;

	if (t < 0) t = -t;

	va_start(ap, t);
	memset(buf, 0xC1, sizeof(buf));
	for (i = 0; i < t; i++)
		buf[i] = va_arg(ap, int);
	va_end(ap);

	if (be) {
		switch (t) {
		case 2: val = be16dec(buf); break;
		case 4: val = be32dec(buf); break;
		case 8: val = be64dec(buf); break;
		}
	} else {
		switch (t) {
		case 2: val = le16dec(buf); break;
		case 4: val = le32dec(buf); break;
		case 8: val = le64dec(buf); break;
		}
	}
	return val;
}

static const char *tencode(int t, uint64_t val)
{
	static char res[64];
	uint8_t buf[16];
	bool be = t > 0;
	int i;

	if (t < 0) t = -t;

	memset(buf, 0xFC, sizeof(buf));

	if (be) {
		switch (t) {
		case 2: be16enc(buf, val); break;
		case 4: be32enc(buf, val); break;
		case 8: be64enc(buf, val); break;
		}
	} else {
		switch (t) {
		case 2: le16enc(buf, val); break;
		case 4: le32enc(buf, val); break;
		case 8: le64enc(buf, val); break;
		}
	}

	for (i = t; i < (int)sizeof(buf); i++) {
		if (buf[i] != 0xFC)
			return "OVER";
	}

	snprintf(res, sizeof(res), "%02X %02X %02X %02X %02X %02X %02X %02X ",
		 buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
	res[t*3 - 1] = 0;
	return res;
}

static void test_encdec(void *p)
{
	ull_check(tdecode( 2, 1,2), 0x0102);
	ull_check(tdecode(-2, 1,2), 0x0201);
	ull_check(tdecode( 4, 1,2,3,4), 0x01020304);
	ull_check(tdecode(-4, 1,2,3,4), 0x04030201);
	ull_check(tdecode( 8, 1,2,3,4,5,6,7,8), 0x0102030405060708);
	ull_check(tdecode(-8, 1,2,3,4,5,6,7,8), 0x0807060504030201);

	str_check(tencode( 2, 0x0102), "01 02");
	str_check(tencode(-2, 0x0102), "02 01");
	str_check(tencode( 4, 0x01020304), "01 02 03 04");
	str_check(tencode(-4, 0x01020304), "04 03 02 01");
	str_check(tencode( 8, 0x0102030405060708ULL), "01 02 03 04 05 06 07 08");
	str_check(tencode(-8, 0x0102030405060708ULL), "08 07 06 05 04 03 02 01");
end:;
}


/*
 * Describe
 */

struct testcase_t endian_tests[] = {
	{ "bswap", test_bswap },
	{ "encdec", test_encdec },
	END_OF_TESTCASES
};
