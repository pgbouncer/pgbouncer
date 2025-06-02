/*
 * fnmatch.c
 *
 * Copyright (c) 2012  Marko Kreen
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Differences from POSIX:
 * - ^ can be used in place of !
 * - \ is escape in bracket expression, unless FNM_NOESCAPE is given.
 * - FNM_CASEFOLD
 * - FNM_LEADING_DIR
 */

#include <usual/fnmatch.h>
#include <usual/wchar.h>

#include <string.h>

#ifdef NEED_USUAL_FNMATCH

/* compare chars with case folding */
static inline bool cmp_fold(wchar_t c1, wchar_t c2, int flags)
{
	if (c1 == c2)
		return true;
	if (flags & FNM_CASEFOLD) {
		if (iswupper(c1) && iswlower(c2))
			return c1 == (wchar_t)towupper(c2);
		else if (iswlower(c1) && iswupper(c2))
			return c1 == (wchar_t)towlower(c2);
	}
	return false;
}

/* compare char to range with case folding */
static inline bool range_fold(wchar_t c, wchar_t r1, wchar_t r2, int flags)
{
	if (c >= r1 && c <= r2)
		return true;
	if (flags & FNM_CASEFOLD) {
		/* convert only if it makes sense */
		if (iswupper(c) && iswlower(r1) && iswlower(r2)) {
			c = towlower(c);
			if (c >= r1 && c <= r2)
				return true;
		} else if (iswlower(c) && iswupper(r1) && iswupper(r2)) {
			c = towupper(c);
			if (c >= r1 && c <= r2)
				return true;
		}
	}
	return false;
}

/* match bracket expression */
static const wchar_t *match_class(const wchar_t *pat, wchar_t c, int flags)
{
	const wchar_t *p = pat;
	const wchar_t *start;
	bool neg = false;
	bool match = false;
	bool fallback_ok = true;
	const wchar_t *n1, *n2;
	wctype_t wct;

	/* negation */
	if (*p == '!' || *p == '^') {
		neg = true;
		p++;
	}
	start = p;
loop:
	/* named class, equivalence class or collating symbol */
	if (p[0] == '[' && (p[1] == ':' || p[1] == '.' || p[1] == '=')) {
		n1 = p + 2;
		n2 = wcschr(n1, p[1]);
		if (!n2 || n2[1] != ']')
			goto parse_fail;
		if (p[1] != ':')
			return NULL;
		p = n2 + 2;
		wct = wctype_wcsn(n1, n2-n1);
		if (wct == (wctype_t)0)
			return NULL;
		if (iswctype(c, wct))
			match = true;
		fallback_ok = false;
		/* skip rest */
		goto loop;
	}
parse_fail:

	/* unexpected pattern end */
	if (p[0] == '\0') {
		/* only open bracket exists, take it as literal */
		if (fallback_ok && c == '[')
			return pat - 1;
		return NULL;
	}

	/* closing bracket */
	if (p[0] == ']' && p != start)
		return (match ^ neg) ? p : NULL;

	/* escape next char */
	if (p[0] == '\\' && !(flags & FNM_NOESCAPE)) {
		if (p[1] == '\0')
			return NULL;
		p++;
	}

	/* its either simple range or char */
	if (p[1] == '-' && p[2] != ']' && p[2] != '\0') {
		wchar_t r1 = p[0];
		wchar_t r2 = p[2];
		if (r2 == '\\' && !(flags & FNM_NOESCAPE)) {
			p++;
			r2 = p[2];
			if (r2 == '\0')
				return NULL;
		}
		if (range_fold(c, r1, r2, flags))
			match = true;
		p += 3;
	} else {
		if (cmp_fold(c, p[0], flags))
			match = true;
		p++;
	}
	goto loop;
}

/*
 * FNM_PATHNAME disallows wildcard match for '/',
 * FNM_PERIOD disallows wildcard match for leading '.',
 * check for string end also.
 */
static bool disallow_wildcard(const wchar_t *s, const wchar_t *str, int flags)
{
	if (*s == '\0')
		return true;
	if (*s == '/')
		return (flags & FNM_PATHNAME);
	if (*s == '.' && (flags & FNM_PERIOD)) {
		if (s == str)
			return true;
		if (s[-1] == '/' && (flags & FNM_PATHNAME))
			return true;
	}
	return false;
}

/*
 * Non-recursive fnmatch(), based on globmatch() by <linux@horizon.com>
 */
static int wfnmatch(const wchar_t *pat, const wchar_t *str, int flags)
{
	const wchar_t *p = pat;
	const wchar_t *s = str;
	const wchar_t *retry_p = NULL;
	const wchar_t *skip_s = NULL;
loop:
	switch (*p) {
	case '*':
		/* match any number of chars from this position on */
		retry_p = p + 1;
		skip_s = s;
		/* dot after '*' must not match leading dot */
		if (p[1] == '.' && disallow_wildcard(s, str, flags))
			return FNM_NOMATCH;
		break;
	case '?':
		/* match any char */
		if (disallow_wildcard(s, str, flags))
			goto nomatch_retry;
		s++;
		break;
	case '[':
		/* match character class */
		if (disallow_wildcard(s, str, flags))
			goto nomatch_retry;
		p = match_class(p + 1, *s, flags);
		if (p == NULL)
			goto nomatch_retry;
		s++;
		break;
	case '\\':
		/* escape next char */
		if (!(flags & FNM_NOESCAPE)) {
			p++;
			if (*p == '\0')
				return FNM_NOMATCH;
		}
		/* fallthrough */
	default:
		/* match single char */
		if (*s == '/' && *p == '\0' && (flags & FNM_LEADING_DIR))
			return 0;
		if (!cmp_fold(*p, *s, flags))
			goto nomatch_retry;
		if (*s == '\0')
			return 0;
		s++;
	}
	p++;
	goto loop;

nomatch_retry:
	/* eat chars with '*', if possible */
	if (retry_p == NULL || *s == '\0')
		return FNM_NOMATCH;
	s = skip_s++;
	p = retry_p;
	if (*s == '\0')
		return (*p == '\0') ? 0 : FNM_NOMATCH;
	if (disallow_wildcard(s, str, flags))
		return FNM_NOMATCH;
	s++;
	goto loop;
}

/*
 * Convert locale-specific encoding to wchar_t string
 */
int fnmatch(const char *pat, const char *str, int flags)
{
	wchar_t *wpat, *wstr;
	wchar_t pbuf[128];
	wchar_t sbuf[128];
	int plen = strlen(pat);
	int slen = strlen(str);
	int res;

	/* convert encoding */
	wpat = mbstr_decode(pat, plen, NULL, pbuf, sizeof(pbuf) / sizeof(wchar_t), false);
	if (!wpat)
		return (errno == EILSEQ) ? FNM_NOMATCH : -1;
	wstr = mbstr_decode(str, slen, NULL, sbuf, sizeof(sbuf) / sizeof(wchar_t), true);
	if (!wstr)
		return -1;

	/* run actual fnmatch */
	res = wfnmatch(wpat, wstr, flags);

	/* free buffers */
	if (wstr != sbuf)
		free(wstr);
	if (wpat != pbuf)
		free(wpat);

	return res;
}

#endif
