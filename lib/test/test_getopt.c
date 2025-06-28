#include <usual/getopt.h>

#include "test_common.h"

#include <usual/string.h>
#include <usual/err.h>

static const char *xgetopt(const char *opts, const struct option *lopts, ...)
{
	static char resbuf[1024];

	int i, c, argc = 1;
	char *argv[100];
	va_list ap;
	char *p = resbuf, *bufend = resbuf + sizeof resbuf;

	resbuf[0] = 'X';
	resbuf[1] = 0;
	argv[0] = "prog";

	va_start(ap, lopts);
	while (1) {
		argv[argc] = va_arg(ap, char *);
		if (!argv[argc])
			break;
		argc++;
	}
	va_end(ap);

	opterr = 0;
	optind = 0;
	while (1) {
		if (lopts)
			c = getopt_long(argc, argv, opts, lopts, NULL);
		else
			c = getopt(argc, argv, opts);
		if (c == -1)
			break;

		switch (c) {
		case '?':
			return "ERR";
		case ':':
			return "EARG";
		case 0:
			break;
		default:
			if (p != resbuf)
				*p++ = ',';
			if (optarg)
				p += snprintf(p, bufend - p, "%c=%s", c, optarg);
			else
				p += snprintf(p, bufend - p, "%c", c);
		}
	}
	for (i = optind; i < argc; i++)
		p += snprintf(p, bufend - p, "|%s", argv[i]);
	if (p >= bufend)
		return "bufover";
	return resbuf;
}

static void test_getopt(void *_)
{
	str_check(xgetopt("ab:", NULL, "-abFOO", "zzz", NULL), "a,b=FOO|zzz");
	str_check(xgetopt("ab:", NULL, "-a", "zzz", "-bFOO", NULL), "a,b=FOO|zzz");
	str_check(xgetopt("ab:", NULL, "-b", "FOO", "-", "--", "-a", NULL), "b=FOO|-|-a");
	str_check(xgetopt("ab:", NULL, "--foo", NULL), "ERR");
end:    ;
}

static void test_getopt_long(void *_)
{
	static int longc;
	static const char sopts[] = "ab:";
	static const struct option lopts[] = {
		{ "longa", no_argument, NULL, 'a'},
		{ "longb", required_argument, NULL, 'b'},
		{ "longc", no_argument, &longc, 'C'},
		{ NULL },
	};

	str_check(xgetopt(sopts, lopts, "--longa", "--", "--longa", NULL), "a|--longa");
	str_check(xgetopt(sopts, lopts, "--longb", "FOO", "ARG", "--longa", NULL), "b=FOO,a|ARG");
	str_check(xgetopt(sopts, lopts, "--longb=BAZ", NULL), "b=BAZ");
	str_check(xgetopt(sopts, lopts, "--longb", NULL), "ERR");
	str_check(xgetopt(sopts, lopts, "--xx", NULL), "ERR");
	str_check(xgetopt(sopts, lopts, "-", "--longc", "ARG", NULL), "|-|ARG");
	tt_assert(longc == 'C');
end:    ;
}

struct testcase_t getopt_tests[] = {
	{ "getopt", test_getopt },
	{ "getopt_long", test_getopt_long },
	END_OF_TESTCASES
};
