/*
 * String utilities.
 *
 * Copyright (c) 2009  Marko Kreen
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

#include <usual/string.h>

#include <locale.h>
#ifdef HAVE_XLOCALE_H
#include <xlocale.h>
#endif
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif

#include <usual/mbuf.h>
#include <usual/statlist.h>
#include <usual/ctype.h>
#include <usual/bytemap.h>

/*
 * Dynamic list of strings.
 */

struct StrList {
	struct StatList list;
	CxMem *ca;
};

struct StrItem {
	struct List node;
	char *str;
};

bool strlist_empty(struct StrList *slist)
{
	return statlist_empty(&slist->list);
}

bool strlist_append(struct StrList *slist, const char *str)
{
	char *nstr = NULL;
	bool ok;
	if (str) {
		nstr = cx_strdup(slist->ca, str);
		if (!nstr)
			return false;
	}
	ok = strlist_append_ref(slist, nstr);
	if (!ok)
		cx_free(slist->ca, nstr);
	return ok;
}

bool strlist_append_ref(struct StrList *slist, char *str)
{
	struct StrItem *item = cx_alloc(slist->ca, sizeof(*item));
	if (!item)
		return false;
	list_init(&item->node);
	item->str = str;
	statlist_append(&slist->list, &item->node);
	return true;
}

char *strlist_pop(struct StrList *slist)
{
	struct StrItem *item;
	struct List *el;
	char *str;

	el = statlist_pop(&slist->list);
	if (!el)
		return NULL;

	item = container_of(el, struct StrItem, node);
	str = item->str;
	cx_free(slist->ca, item);
	return str;
}

struct StrList *strlist_new(CxMem *ca)
{
	struct StrList *slist = cx_alloc0(ca, sizeof(*slist));
	if (!slist)
		return NULL;
	statlist_init(&slist->list, "strlist");
	slist->ca = ca;
	return slist;
}

void strlist_free(struct StrList *slist)
{
	char *s;
	if (!slist)
		return;
	while (!strlist_empty(slist)) {
		s = strlist_pop(slist);
		if (s)
			cx_free(slist->ca, s);
	}
	cx_free(slist->ca, slist);
}

bool strlist_foreach(const struct StrList *slist, str_cb func, void *arg)
{
	struct List *el;
	struct StrItem *item;
	statlist_for_each(el, &slist->list) {
		item = container_of(el, struct StrItem, node);
		if (!func(arg, item->str))
			return false;
	}
	return true;
}

/*
 * Parse comma separated words.
 */

static inline const char *skip_ws(const char *p)
{
	while (*p && isspace(*p))
		p++;
	return p;
}


bool parse_word_list(const char *s, str_cb cb_func, void *cb_arg)
{
	struct MBuf buf;
	const char *p = s;
	const char *start, *end;

	mbuf_init_dynamic(&buf);
	while (*p) {
		/* parse word */
		p = skip_ws(p);
		start = p;
		while (*p && *p != ',')
			p++;
		end = p;
		while (end > start && isspace(*(end - 1)))
			end--;

		/* parse comma */
		if (*p) {
			if (*p == ',') {
				p++;
			} else {
				goto failed_syntax;
			}
		}

		/* extract string */
		if (!mbuf_write(&buf, start, end - start))
			goto failed;
		if (!mbuf_write_byte(&buf, 0))
			goto failed;

		/* launch callback */
		if (!cb_func(cb_arg, (const char *)buf.data))
			goto failed;

		/* reset */
		mbuf_rewind_writer(&buf);
	}
	mbuf_free(&buf);
	return true;

failed_syntax:
	errno = EINVAL;
failed:
	mbuf_free(&buf);
	return false;
}

/*
 * Minimal spec-conforming implementations of strlcpy(), strlcat().
 */

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t n)
{
	size_t len = strlen(src);
	if (len < n) {
		memcpy(dst, src, len + 1);
	} else if (n > 0) {
		memcpy(dst, src, n - 1);
		dst[n - 1] = 0;
	}
	return len;
}
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t n)
{
	size_t pos = 0;
	while (pos < n && dst[pos])
		pos++;
	return pos + strlcpy(dst + pos, src, n - pos);
}
#endif

char *strpcpy(char *dst, const char *src, size_t n)
{
	if (n == 0)
		return NULL;
	for (; n > 0; n--, dst++, src++) {
		if ((*dst = *src) == '\0')
			return dst;
	}
	dst[-1] = '\0';
	return NULL;
}

char *strpcat(char *dst, const char *src, size_t n)
{
	size_t dstlen = strnlen(dst, n);
	if (dstlen < n)
		return strpcpy(dst + dstlen, src, n - dstlen);
	return NULL;
}

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	return (char *)(dst) + n;
}
#endif

#ifndef HAVE_MEMRCHR
void *memrchr(const void *s, int c, size_t n)
{
	const uint8_t *p = s;
	while (n--) {
		if (p[n] == c)
			return (void *)(p + n);
	}
	return NULL;
}
#endif

#ifndef HAVE_MEMMEM
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
	const uint8_t *s = haystack;
	const uint8_t *q = needle;
	const uint8_t *s2;
	size_t i;

	if (nlen == 0)
		return (void *)haystack;
	if (nlen > hlen)
		return NULL;
	s2 = memchr(haystack, *q, hlen);
	if (!s2 || nlen == 1)
		return (void *)s2;
	for (i = s2 - s; i <= hlen - nlen; i++) {
		if (s[i] == q[0] && s[i + 1] == q[1]) {
			if (memcmp(s + i + 2, q + 2, nlen - 2) == 0)
				return (void *)(s + i);
		}
	}
	return NULL;
}
#endif

#ifndef HAVE_EXPLICIT_BZERO

#if defined(_WIN32) && defined(SecureZeroMemory)

void explicit_bzero(void *buf, size_t len)
{
	SecureZeroMemory(buf, len);
}

#elif defined(HAVE_MEMSET_S)

void explicit_bzero(void *buf, size_t len)
{
	memset_s(buf, len, 0, len);
}

#else /* non-win32 */

/* avoid link-time optimization */
#if defined(__GNUC__x) || __has_attribute(weak)
void __explicit_bzero_hack(void *, size_t);
__attribute__((weak)) void __explicit_bzero_hack(void *buf, size_t len)
{
}
#else
typedef void (*__explicit_bzero_cb_t)(void *, size_t);
static void __explicit_bzero_hack_cb(void *buf, size_t len)
{
}
static volatile __explicit_bzero_cb_t __explicit_bzero_hack = __explicit_bzero_hack_cb;
#endif

void explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
	__explicit_bzero_hack(buf, len);
}

#endif
#endif /* !_WIN32 */

#ifndef HAVE_BASENAME
const char *basename(const char *path)
{
	const char *p, *p2;
	static char buf[256];
	unsigned len;

	if (path == NULL || path[0] == 0)
		return memcpy(buf, ".", 2);
	if ((p = strrchr(path, '/')) == NULL)
		return path;
	if (p[1])
		return p + 1;

	/* last char is '/' */
	for (p2 = p; p2 > path; p2--) {
		if (p2[-1] != '/') {
			len = p2 - path;
			if (len > sizeof(buf) - 1)
				len = sizeof(buf) - 1;
			memcpy(buf, p2 - len, len);
			buf[len] = 0;
			return basename(buf);
		}
	}
	/* path contains only '/' chars */
	return p;
}
#endif

#ifndef HAVE_DIRNAME
const char *dirname(const char *path)
{
	const char *p;
	size_t len;
	static char buf[1024];

	if (path == NULL || path[0] == 0)
		return memcpy(buf, ".", 2);

	/* ignore tailing '/' */
	len = strlen(path);
	while (len && path[len - 1] == '/')
		len--;
	if (!len)
		return memcpy(buf, "/", 2);

	/* find end of dirname, strip '/' */
	if ((p = memrchr(path, '/', len)) == NULL)
		return memcpy(buf, ".", 2);
	len = p - path;
	while (len && path[len - 1] == '/')
		len--;
	if (!len)
		return memcpy(buf, "/", 2);

	/* return it */
	if (len > sizeof(buf) - 1) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	memcpy(buf, path, len);
	buf[len] = 0;
	return buf;
}
#endif

#ifdef WIN32
const char *win32_strerror(int e)
{
	static char buf[1024];
	return strerror_r(e, buf, sizeof(buf));
}
#endif

/* restore original strerror_r() */
#undef strerror_r

const char *usual_strerror_r(int e, char *dst, size_t dstlen)
{
#ifdef WIN32
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, e,
		      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		      dst, dstlen, NULL);
#else /* !WIN32 */

#ifdef STRERROR_R_CHAR_P
	dst = strerror_r(e, dst, dstlen);
#else
	if (strerror_r(e, dst, dstlen) != 0)
		strlcpy(dst, "ERR", dstlen);
#endif

#endif /* !WIN32 */

	return dst;
}

void *mempbrk(const void *data, size_t dlen, const void *find, size_t flen)
{
	const uint8_t *s = data;
	const uint8_t *fb = find;
	size_t i;
	struct Bitmap256 bmap;

	if (flen == 0)
		return NULL;
	if (flen == 1)
		return memchr(data, fb[0], dlen);

	bitmap256_init(&bmap);
	for (i = 0; i < flen; i++)
		bitmap256_set(&bmap, fb[i]);
	for (i = 0; i < dlen; i++) {
		if (bitmap256_is_set(&bmap, s[i]))
			return (void *)(s + i);
	}
	return NULL;
}

size_t memspn(const void *data, size_t dlen, const void *accept, size_t alen)
{
	const uint8_t *s = data;
	const uint8_t *fb = accept;
	size_t i;
	struct Bitmap256 bmap;

	if (alen == 0)
		return 0;
	if (alen == 1) {
		for (i = 0; i < dlen; i++)
			if (s[i] != fb[0])
				break;
		return i;
	}

	bitmap256_init(&bmap);
	for (i = 0; i < alen; i++)
		bitmap256_set(&bmap, fb[i]);
	for (i = 0; i < dlen; i++) {
		if (!bitmap256_is_set(&bmap, s[i]))
			break;
	}
	return i;
}

size_t memcspn(const void *data, size_t dlen, const void *reject, size_t rlen)
{
	const void *p;

	p = mempbrk(data, dlen, reject, rlen);
	if (p != NULL)
		return (char *)p - (char *)data;
	return dlen;
}

double strtod_dot(const char *s, char **tokend)
{
	const char *dp;
	char buf[128];
	char *dst, *tmp, *end, *dot = NULL;
	unsigned int i, dplen;
	double res;

	/* check if locale is sane */
#ifdef HAVE_NL_LANGINFO
	dp = nl_langinfo(RADIXCHAR);
#else
	dp = localeconv()->decimal_point;
#endif
	if (memcmp(dp, ".", 2) == 0)
		return strtod(s, tokend);

	/* try to use proper api */
#ifdef HAVE_STRTOD_L
	{
		static locale_t c_locale = NULL;
		if (!c_locale)
			c_locale = newlocale(LC_ALL_MASK, "C", NULL);
		if (c_locale)
			return strtod_l(s, tokend, c_locale);
	}
#endif

	while (*s && isspace(*s))
		s++;

	dot = NULL;
	dst = buf;
	end = buf + sizeof(buf) - 5;
	dplen = dp[1] ? strlen(dp) : 1;
	for (i = 0; s[i]; i++) {
		if (s[i] >= '0' && s[i] <= '9') {
			*dst++ = s[i];
		} else if (s[i] == '.') {
			dot = dst;
			memcpy(dst, dp, dplen);
			dst += dplen;
		} else if (s[i] == '-' || s[i] == '+' || s[i] == 'e' || s[i] == 'E') {
			*dst++ = s[i];
		} else {
			break;
		}

		if (dst >= end) {
			errno = ERANGE;
			return 0;
		}
	}
	*dst = '\0';

	if (!dot)
		return strtod(s, tokend);

	tmp = NULL;
	res = strtod(buf, &tmp);
	if (tmp && tokend) {
		*tokend = (char *)s + (tmp - buf);
		if (dot && tmp > dot && dplen > 1)
			*tokend -= (dplen - 1);
	}
	return res;
}


ssize_t dtostr_dot(char *buf, size_t buflen, double val)
{
	const char *dp;
	ssize_t len, dplen;
	char *p;

	/* render with max precision */
	len = snprintf(buf, buflen, "%.17g", val);
	if (len >= (ssize_t)buflen || len < 0)
		return len;

	/* check if locale is sane */
#ifdef HAVE_NL_LANGINFO
	dp = nl_langinfo(RADIXCHAR);
#else
	dp = localeconv()->decimal_point;
#endif
	if (memcmp(dp, ".", 2) == 0)
		return len;

	dplen = dp[1] ? strlen(dp) : 1;
	p = memchr(buf, dp[0], len);
	if (p) {
		*p = '.';
		if (dp[1]) {
			memmove(p + 1, p + dplen, strlen(p + dplen) + 1);
			len -= dplen - 1;
		}
	}
	return len;
}

#ifndef HAVE_STRTONUM

long long strtonum(const char *s, long long minval, long long maxval, const char **errstr_p)
{
	char *end = NULL;
	long long res;
	int old_errno = errno;

	if (minval > maxval)
		goto einval;

	errno = 0;
	res = strtoll(s, &end, 10);
	if (errno == ERANGE) {
		if (res < 0)
			goto esmall;
		else
			goto elarge;
	} else if (errno != 0) {
		goto einval;
	} else if (*end || end == s) {
		goto einval;
	} else if (res < minval) {
		goto esmall;
	} else if (res > maxval) {
		goto elarge;
	}

	/* success */
	if (errstr_p)
		*errstr_p = NULL;
	errno = old_errno;
	return res;

esmall:
	if (errstr_p)
		*errstr_p = "too small";
	errno = ERANGE;
	return 0;

elarge:
	if (errstr_p)
		*errstr_p = "too large";
	errno = ERANGE;
	return 0;

einval:
	if (errstr_p)
		*errstr_p = "invalid";
	errno = EINVAL;
	return 0;
}

#endif

#ifndef HAVE_STRSEP

char *strsep(char **stringp, const char *delim)
{
	char *end, *start = *stringp;
	if (start) {
		end = start + strcspn(start, delim);
		*stringp = *end ? end + 1 : NULL;
		*end = 0;
	}
	return start;
}

#endif

#ifndef HAVE_ASPRINTF

int asprintf(char **dst_p, const char *fmt, ...)
{
	int res;
	va_list ap;
	va_start(ap, fmt);
	res = vasprintf(dst_p, fmt, ap);
	va_end(ap);
	return res;
}

#endif

#ifndef HAVE_VASPRINTF

int vasprintf(char **dst_p, const char *fmt, va_list ap)
{
	return cx_vasprintf(NULL, dst_p, fmt, ap);
}

#endif

#ifndef HAVE_STRNLEN

size_t strnlen(const char *string, size_t maxlen)
{
	const char *end = memchr(string, '\0', maxlen);
	return end ? (size_t)(end - string) : maxlen;
}

#endif

/*
 * Same as strcmp, but handles NULLs. If both sides are NULL, returns "true".
 */
bool strcmpeq(const char *str_left, const char *str_right)
{
	if (str_left == NULL && str_right == NULL)
		return true;

	if (str_left == NULL || str_right == NULL)
		return false;

	return strcmp(str_left, str_right) == 0;
}
