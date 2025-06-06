#include <usual/socket.h>

#include <string.h>

#include "test_common.h"

static const char *ntop(int af, const void *src)
{
	static char buf[128];
	const char *res;
	res = inet_ntop(af, src, buf, sizeof(buf));
	return res ? res : "NULL";
}

static void test_ntop(void *z)
{
	static const uint8_t data[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	str_check(ntop(AF_INET, data), "1.2.3.4");
	str_check(ntop(AF_INET6, data), "102:304:506:708:90a:b0c:d0e:f10");
end:;
}

static const char *pton(int af, const char *s)
{
	static char str[128];
	unsigned char buf[128];
	int res;
	int len = (af == AF_INET) ?  4 : 16;

	memset(buf, 0xCC, sizeof(buf));

	res = inet_pton(af, s, buf);
	if (res < 0) return "EAFBAD";
	if (res == 0) return "FAIL";
	if (buf[len] != 0xCC || buf[len + 1] != 0xCC)
		return "EOVER";
	if (buf[len - 1] == 0xCC || buf[0] == 0xCC)
		return "EUNDER";

	s = inet_ntop(af, buf, str, sizeof(str));
	return s ? s : "NULL";
}

static void test_pton(void *z)
{
	str_check(pton(AF_INET, "127.0.0.255"), "127.0.0.255");
	str_check(pton(AF_INET, "127.0.0"), "FAIL");
	str_check(pton(AF_INET, "127.1.1.a"), "FAIL");
	str_check(pton(AF_INET, "127.1.1.300"), "FAIL");

	str_check(pton(AF_INET6, "0001:0002:ffff:4444:5555:6666:7777:8888"), "1:2:ffff:4444:5555:6666:7777:8888");
	str_check(pton(AF_INET6, "::"), "::");
	str_check(pton(AF_INET6, "F00F::5060"), "f00f::5060");
	str_check(pton(AF_INET6, "F00F::127.0.0.1"), "f00f::7f00:1");
	str_check(pton(AF_INET6, "::1:2:3:4:5:6:7:8"), "FAIL");
end:;
}

struct testcase_t socket_tests[] = {
	{ "inet_ntop", test_ntop },
	{ "inet_pton", test_pton },
	END_OF_TESTCASES
};
