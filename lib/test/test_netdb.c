#include <usual/netdb.h>

#include <usual/string.h>
#include <usual/socket.h>
#include <usual/time.h>

#include "test_common.h"

static int gotres;

static void cb_func(union sigval v)
{
	gotres++;
}

static void test_gai(void *p)
{
	int res;
	struct sigevent sev;
	struct gaicb req;
	struct gaicb *rlist[] = { &req };

	memset(&req, 0, sizeof(req));
	req.ar_name = "localhost";

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = cb_func;

	res = getaddrinfo_a(GAI_NOWAIT, rlist, 1, &sev);
	if (res == EAI_SYSTEM && errno == ENOSYS) {
		/* ok - no impl */
		goto end;
	} else {
		int_check(res, 0);
	}

	while (gai_error(&req) == EAI_INPROGRESS || gotres == 0)
		usleep(10000);

	int_check(gai_error(&req), 0);

	freeaddrinfo(req.ar_result);

	int_check(gotres, 1);
end:;
}

struct testcase_t netdb_tests[] = {
	{ "getaddrinfo_a", test_gai },
	END_OF_TESTCASES
};
