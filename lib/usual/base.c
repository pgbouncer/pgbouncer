/*
 * Basic C environment.
 *
 * Copyright (c) 2007-2009 Marko Kreen
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

#include <usual/base.h>
#include <usual/bits.h>

#if defined(HAVE_MALLOC_H) && defined(__darwin__)
#include <malloc.h>
#endif

/* define posix_memalign() only when possible to emulate */
#if !defined(HAVE_POSIX_MEMALIGN) \
    && (defined(HAVE_MEMALIGN) || defined(HAVE_VALLOC))

int posix_memalign(void **ptr_p, size_t align, size_t len)
{
	void *p;
	int ret, old_errno = errno;

#ifdef HAVE_MEMALIGN
	p = memalign(align, len);
#else /* !HAVE_MEMALIGN */
#ifdef HAVE_VALLOC
	/* assuming less than pagesize alignment */
	p = valloc(len);
#endif /* !VALLOC */
#endif /* !MEMALIGN */

	*ptr_p = p;
	if (p)
		return 0;

	/* on error restore old errno */
	ret = errno;
	errno = old_errno;
	return ret;
}
#endif

#ifndef HAVE_REALLOCARRAY

void *reallocarray(void *p, size_t count, size_t size)
{
	size_t total;
	if (!safe_mul_size(&total, count, size)) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(p, total);
}

#endif
