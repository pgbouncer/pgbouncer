#include <usual/regex.h>
#include <usual/string.h>

#include "test_common.h"

#define NMATCH 20

/*
 * quick regex sanity check
 */

/* execute basic regex and return result as string */
static const char *b_rx(const char *regex, const char *str, int flags)
{
	static char buf[512];
	regex_t rx;
	regmatch_t matches[NMATCH];
	unsigned int nmatch, i;
	int err;
	char *dst = buf, *bufend = buf + sizeof buf;

	memset(&rx, 0, sizeof(rx));
	memset(matches, -1, sizeof(&matches));

	/* compile */
	err = regcomp(&rx, regex, flags);
	if (err)
		goto fail;
	nmatch = rx.re_nsub;

	/* match */
	err = regexec(&rx, str, NMATCH, matches, 0);
	if (err)
		goto fail;

	/* format result */
	for (i = 0; i < nmatch + 1; i++) {
		regmatch_t *m = &matches[i];
		*dst++ = '(';
		if (m->rm_so >= 0)
			dst += snprintf(dst, bufend - dst, "%d", (int)m->rm_so);
		else
			*dst++ = '?';
		*dst++ = ',';
		if (m->rm_eo >= 0)
			dst += snprintf(dst, bufend - dst, "%d", (int)m->rm_eo);
		else
			*dst++ = '?';
		if (dst >= bufend)
			return "bufover";
		*dst++ = ')';
	}
	regfree(&rx);
	return buf;

fail:
	/* format error */
	regfree(&rx);
	switch (err) {
	case REG_NOMATCH: return "NOMATCH";
	case REG_BADBR: return "BADBR";
	case REG_BADPAT: return "BADPAT";
	case REG_BADRPT: return "BADRPT";
	case REG_EBRACE: return "EBRACE";
	case REG_EBRACK: return "EBRACK";
	case REG_ECOLLATE: return "ECOLLATE";
	case REG_ECTYPE: return "ECTYPE";
#ifdef REG_EEND
	case REG_EEND: return "EEND";
#endif
	case REG_EESCAPE: return "EESCAPE";
	case REG_EPAREN: return "EPAREN";
	case REG_ERANGE: return "ERANGE";
#ifdef REG_ESIZE
	case REG_ESIZE: return "ESIZE";
#endif
	case REG_ESPACE: return "ESPACE";
	case REG_ESUBREG: return "ESUBREG";
#ifdef REG_ENOSYS
	case REG_ENOSYS: return "ENOSYS";
#endif
#ifdef REG_EMPTY
	case REG_EMPTY: return "EMPTY";
#endif
	default: return "UNKNOWN_ERROR";
	}
}

/* execute extended regex and return result as string */
static const char *e_rx(const char *regex, const char *str, int flags)
{
	return b_rx(regex, str, flags | REG_EXTENDED);
}

static void test_regex(void *ptr)
{
	str_check(e_rx("foo*", "foobar", 0), "(0,3)");
	str_check(e_rx("foo(x)?.*", "foobar", 0), "(0,6)(?,?)");
	str_check(e_rx("foo", "bar", 0), "NOMATCH");
	str_check(e_rx("foo{5,1}", "bar", 0), "BADBR");
	/* str_check(e_rx("(|)", "bar", 0), "BADPAT"); */
	str_check(e_rx("*", "bar", 0), "BADRPT");
	str_check(e_rx("foo{", "bar", 0), "EBRACE");
	str_check(e_rx("fo[o", "bar", 0), "EBRACK");
	str_check(e_rx("[[:foo:]]", "bar", 0), "ECTYPE");
	str_check(e_rx("foo\\", "foobar", 0), "EESCAPE");
	str_check(e_rx("fo(o", "bar", 0), "EPAREN");
	str_check(e_rx("[a-b-c]", "bar", 0), "ERANGE");
	str_check(b_rx("(\\1)", "bar", 0), "ESUBREG");
	str_check(e_rx("[[:random:]]", "bar", 0), "ECTYPE");
end:    ;
}

/*
 * Describe
 */

struct testcase_t regex_tests[] = {
	{ "minimal", test_regex },
	END_OF_TESTCASES
};
