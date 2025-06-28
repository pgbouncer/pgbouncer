/*
 * Some utility functions for Postgres.
 *
 * - Literal & ident quoting.
 * - Array parsing
 */

#include <usual/pgutil.h>

#include <usual/ctype.h>

/* str -> E'str' */
bool pg_quote_literal(char *_dst, const char *_src, int dstlen)
{
	char *dst = _dst;
	char *end = _dst + dstlen - 2;
	const char *src = _src;
	bool stdquote = true;

	if (dstlen < 3)
		return false;

	if (_src == NULL) {
		if (dstlen < 5)
			return false;
		memcpy(_dst, "NULL", 5);
		return true;
	}

retry:
	*dst++ = '\'';
	while (*src && dst < end) {
		if (*src == '\'') {
			*dst++ = '\'';
		} else if (*src == '\\') {
			if (stdquote)
				goto retry_ext;
			*dst++ = '\\';
		}
		*dst++ = *src++;
	}
	if (*src || dst > end)
		return false;

	*dst++ = '\'';
	*dst = 0;

	return true;
retry_ext:
	/* string contains '\\', retry as E'' string */
	dst = _dst;
	src = _src;
	*dst++ = 'E';
	stdquote = false;
	goto retry;
}

static inline bool id_start(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || c == '_';
}

static inline bool id_body(unsigned char c)
{
	return id_start(c) || (c >= '0' && c <= '9');
}

/* ident -> "ident" */
bool pg_quote_ident(char *_dst, const char *_src, int dstlen)
{
	char *dst = _dst;
	char *end = _dst + dstlen - 1;
	const char *src = _src;

	if (dstlen < 1)
		return false;

	if (!id_start(*src))
		goto needs_quoting;

	while (*src && dst < end) {
		if (!id_body(*src))
			goto needs_quoting;
		*dst++ = *src++;
	}
	if (*src)
		return false;
	*dst = 0;

	if (!pg_is_reserved_word(_dst))
		return true;

needs_quoting:
	dst = _dst;
	src = _src;
	end = _dst + dstlen - 2;
	if (dstlen < 3)
		return false;
	*dst++ = '"';
	while (*src && dst < end) {
		if (*src == '"')
			*dst++ = *src;
		*dst++ = *src++;
	}
	if (*src)
		return false;
	*dst++ = '"';
	*dst = 0;
	return true;
}

/* schema.name -> "schema"."name" */
bool pg_quote_fqident(char *_dst, const char *_src, int dstlen)
{
	const char *dot = strchr(_src, '.');
	char scmbuf[128];
	const char *scm;
	int scmlen;
	if (dot) {
		scmlen = dot - _src;
		if (scmlen >= (int)sizeof(scmbuf))
			return false;
		memcpy(scmbuf, _src, scmlen);
		scmbuf[scmlen] = 0;
		scm = scmbuf;
		_src = dot + 1;
	} else {
		scm = "public";
	}
	if (!pg_quote_ident(_dst, scm, dstlen))
		return false;

	scmlen = strlen(_dst);
	_dst[scmlen] = '.';
	_dst += scmlen + 1;
	dstlen -= scmlen + 1;
	if (!pg_quote_ident(_dst, _src, dstlen))
		return false;
	return true;
}

/*
 * pgarray parsing
 */

static bool parse_value(struct StrList *arr, const char *val, const char *vend,
			CxMem *cx)
{
	int len;
	const char *s;
	char *str, *p;
	unsigned c;

	while (val < vend && isspace(*val))
		val++;
	while (vend > val && isspace(vend[-1]))
		vend--;
	if (val == vend) return false;

	s = val;
	len = vend - val;
	if (len == 4 && !strncasecmp(val, "null", len)) {
		return strlist_append_ref(arr, NULL);
	}
	p = str = cx_alloc(cx, len + 1);
	if (!str)
		return false;

	/* unquote & copy */
	while (s < vend) {
		c = *s++;
		if (c == '"') {
			while (1) {
				c = *s++;
				if (c == '"')
					break;
				else if (c == '\\')
					*p++ = *s++;
				else
					*p++ = c;
			}
		} else if (c == '\\') {
			*p++ = *s++;
		} else {
			*p++ = c;
		}
	}
	*p++ = 0;
	if (!strlist_append_ref(arr, str)) {
		cx_free(cx, str);
		return false;
	}
	return true;
}

struct StrList *pg_parse_array(const char *pgarr, CxMem *cx)
{
	const char *s = pgarr;
	struct StrList *lst;
	const char *val = NULL;
	unsigned c;

	/* skip dimension def "[x,y]={..}" */
	if (*s == '[') {
		s = strchr(s, ']');
		if (!s || s[1] != '=')
			return NULL;
		s += 2;
	}
	if (*s++ != '{')
		return NULL;

	lst = strlist_new(cx);
	if (!lst)
		return NULL;

	while (*s) {
		/* array end */
		if (s[0] == '}') {
			if (s[1] != 0) {
				goto failed;
			}
			if (val) {
				if (!parse_value(lst, val, s, cx))
					goto failed;
			}
			return lst;
		}

		/* cannot init earlier to support empty arrays */
		if (!val)
			val = s;

		/* val done? */
		if (*s == ',') {
			if (!parse_value(lst, val, s, cx))
				goto failed;
			val = ++s;
			continue;
		}

		/* scan value */
		c = *s++;
		if (c == '"') {
			while (1) {
				c = *s++;
				if (c == '"') {
					break;
				} else if (c == '\\') {
					if (!*s) goto failed;
					s++;
				} else if (!*s) {
					goto failed;
				}
			}
		} else if (c == '\\') {
			if (!*s) goto failed;
			s++;
		}
	}
	if (s[-1] != '}')
		goto failed;
	return lst;
failed:
	strlist_free(lst);
	return NULL;
}

/*
 * Postgres keyword lookup.
 */

/* gperf tries ot inline a non-static function. */
#undef inline
#undef __inline
#undef __attribute__
#define inline
#define __inline
#define __attribute__(x)
#define long uintptr_t

/* include gperf code */
const char *pg_keyword_lookup_real(const char *str, size_t len);
#include <usual/pgutil_kwlookup.h>

bool pg_is_reserved_word(const char *str)
{
	const char *kw = pg_keyword_lookup_real(str, strlen(str));
	return kw != NULL;
}
