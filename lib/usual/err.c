/*
 * Cmdline error reporting.
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

#include <usual/err.h>

#include <usual/string.h>

#ifndef HAVE_SETPROGNAME
static const char *progname;
#endif

#ifndef HAVE_ERR
void err(int e, const char *fmt, ...)
{
	char buf[1024], ebuf[256];
	va_list ap;
	int olderrno = errno;
	if (fmt) {
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);
		errx(e, "%s: %s", buf, strerror_r(olderrno, ebuf, sizeof(ebuf)));
	} else {
		errx(e, "%s", strerror_r(olderrno, ebuf, sizeof(ebuf)));
	}
}
#endif

#ifndef HAVE_ERRX
void errx(int e, const char *fmt, ...)
{
	va_list ap;
	if (progname)
		fprintf(stderr, "%s: ", progname);
	if (fmt) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
	fprintf(stderr, "\n");
	exit(e);
}
#endif

#ifndef HAVE_WARN
void warn(const char *fmt, ...)
{
	char buf[1024], ebuf[256];
	va_list ap;
	int olderrno = errno;
	if (fmt) {
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);
		warnx("%s: %s", buf, strerror_r(olderrno, ebuf, sizeof(ebuf)));
	} else {
		warnx("%s", strerror_r(olderrno, ebuf, sizeof(ebuf)));
	}
}
#endif

#ifndef HAVE_WARNX
void warnx(const char *fmt, ...)
{
	va_list ap;
	if (progname)
		fprintf(stderr, "%s: ", progname);
	if (fmt) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}
#endif

#ifndef HAVE_SETPROGNAME
void setprogname(const char *s)
{
	const char *ss = strrchr(s, '/');
	progname = ss ? (ss + 1) : s;
}
#endif

#ifndef HAVE_GETPROGNAME
const char *getprogname(void)
{
	return progname;
}
#endif

void *xmalloc(size_t len)
{
	void *p = malloc(len);
	if (!p)
		err(1, "no mem");
	return p;
}

void *xrealloc(void *p, size_t len)
{
	void *p2 = realloc(p, len);
	if (!p2)
		err(1, "no mem");
	return p2;
}

char *xstrdup(const char *s)
{
	void *s2 = strdup(s);
	if (!s2)
		err(1, "no mem");
	return s2;
}
