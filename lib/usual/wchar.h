/*
 * wchar.h - wchar_t utilities.
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

#ifndef _USUAL_WCHAR_H_
#define _USUAL_WCHAR_H_

#include <usual/base.h>

#include <wchar.h>
#include <wctype.h>

wchar_t *mbstr_decode(const char *str, int str_len, int *wlen_p, wchar_t *wbuf, int wbuf_len, bool allow_invalid);

wctype_t wctype_wcsn(const wchar_t *name, unsigned int namelen);

#ifndef HAVE_MBSNRTOWCS
#define mbsnrtowcs(a, b, c, d, e) usual_mbsnrtowcs(a, b, c, d, e)
size_t mbsnrtowcs(wchar_t *dst, const char **src_p, size_t srclen, size_t dstlen, mbstate_t *ps);
#endif

#endif
