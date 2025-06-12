#include <usual/time.h>

#include <string.h>

#include "test_common.h"


static void test_get_time(void *p)
{
	usec_t t, t2;
	usec_t ct, ct2;

	t = get_time_usec();
	ct = get_cached_time();

	usleep(USEC / 4);
	t2 = get_time_usec();
	tt_assert(t + USEC / 4 <= t2);

	ct2 = get_cached_time();
	tt_assert(ct2 == ct);
	reset_time_cache();
	ct2 = get_cached_time();
	tt_assert(ct2 != ct);
end:;
}

static void test_time_format(void *p)
{
	char buf[128];
	usec_t t;

#ifdef WIN32
	tt_assert(_putenv("TZ=GMT") >= 0);
	_tzset();
	printf( "_daylight = %d\n", _daylight );
	printf( "_timezone = %ld\n", _timezone );
	printf( "_tzname[0] = %s\n", _tzname[0] );

#else
	setenv("TZ", "GMT", 1);
	tzset();
#endif

	t = 1226059006841546;
	str_check(format_time_ms(t, buf, sizeof(buf)), "2008-11-07 11:56:46.841 GMT");
	str_check(format_time_s(t, buf, sizeof(buf)), "2008-11-07 11:56:46 GMT");
end:;
}

struct testcase_t time_tests[] = {
	{ "gettime", test_get_time },
	{ "format", test_time_format },
	END_OF_TESTCASES
};
