/*
 * libusual - Utility library for C
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
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

#include <usual/cxalloc.h>
#include <usual/statlist.h>

#include <string.h>

/*
 * Utility routines for cx_* API.
 */

void *cx_alloc(CxMem *cx, size_t len)
{
	if (!len)
		return NULL;
	if (!cx)
		cx = USUAL_ALLOC;
	return cx->ops->c_alloc(cx->ctx, len);
}

void *cx_realloc(CxMem *cx, void *ptr, size_t len)
{
	if (!cx)
		cx = USUAL_ALLOC;
	if (!ptr)
		return cx_alloc(cx, len);
	if (!len) {
		cx_free(cx, ptr);
		return NULL;
	}
	return cx->ops->c_realloc(cx->ctx, ptr, len);
}

void cx_free(CxMem *cx, void *ptr)
{
	if (!cx)
		cx = USUAL_ALLOC;
	if (ptr)
		cx->ops->c_free(cx->ctx, ptr);
}

void cx_destroy(CxMem *cx)
{
	if (!cx)
		return;
	if (!cx->ops->c_destroy)
		abort();
	cx->ops->c_destroy(cx->ctx);
}

void *cx_alloc0(CxMem *cx, size_t len)
{
	void *p = cx_alloc(cx, len);
	if (p)
		memset(p, 0, len);
	return p;
}

void *cx_memdup(CxMem *cx, const void *src, size_t len)
{
	void *p = cx_alloc(cx, len);
	if (p)
		memcpy(p, src, len);
	return p;
}

void *cx_strdup(CxMem *cx, const char *s)
{
	return cx_memdup(cx, s, strlen(s) + 1);
}

char *cx_sprintf(CxMem *cx, const char *fmt, ...)
{
	char *res;
	va_list ap;
	va_start(ap, fmt);
	res = cx_vsprintf(cx, fmt, ap);
	va_end(ap);
	return res;
}

char *cx_vsprintf(CxMem *cx, const char *fmt, va_list ap)
{
	char *res;
	cx_vasprintf(cx, &res, fmt, ap);
	return res;
}

int cx_asprintf(CxMem *cx, char **dst_p, const char *fmt, ...)
{
	int res;
	va_list ap;
	va_start(ap, fmt);
	res = cx_vasprintf(cx, dst_p, fmt, ap);
	va_end(ap);
	return res;
}

int cx_vasprintf(CxMem *cx, char **dst_p, const char *fmt, va_list ap)
{
	char buf[128], *dst;
	int res, res2;

	*dst_p = NULL;

	res = vsnprintf(buf, sizeof buf, fmt, ap);
	if (res < 0)
		return -1;
	dst = cx_alloc(cx, res + 1);
	if (!dst)
		return -1;

	if ((size_t)res < sizeof buf) {
		memcpy(dst, buf, res + 1);
	} else {
		res2 = vsnprintf(dst, res + 1, fmt, ap);
		if (res2 != res) {
			cx_free(cx, dst);
			return -1;
		}
	}
	*dst_p = dst;
	return res;
}

/*
 * Base allocator that uses libc routines.
 */

static void *libc_alloc(void *ctx, size_t len)
{
	return malloc(len);
}

static void *libc_realloc(void *ctx, void *ptr, size_t len)
{
	return realloc(ptr, len);
}

static void libc_free(void *ctx, void *ptr)
{
	free(ptr);
}

static const struct CxOps libc_alloc_ops = {
	libc_alloc,
	libc_realloc,
	libc_free,
};

const struct CxMem cx_libc_allocator = {
	&libc_alloc_ops,
	NULL,
};
