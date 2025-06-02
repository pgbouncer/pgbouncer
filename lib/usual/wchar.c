/*
 * wchar utility functions.
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

#include <usual/wchar.h>

#include <string.h>

wchar_t *mbstr_decode(const char *str, int str_len, int *wlen_p,
		      wchar_t *wbuf, int wbuf_len, bool allow_invalid)
{
	mbstate_t ps;
	int clen;
	wchar_t *dst, *w, *wend;
	const char *s;
	const char *str_end;
	int wmax;

	if (str_len < 0)
		str_len = strlen(str);
	str_end = str + str_len;

	/* max number of wchar_t that the output can take plus zero-terminator */
	wmax = str_len + 1;
	if (wbuf != NULL && wmax < wbuf_len) {
		dst = wbuf;
	} else {
		dst = malloc(sizeof(wchar_t) * wmax);
		if (!dst)
			return NULL;
	}

	/* try full decode at once */
	s = str;
	memset(&ps, 0, sizeof(ps));
	clen = mbsnrtowcs(dst, &s, str_len, wmax, &ps);
	if (clen >= 0) {
		if (wlen_p)
			*wlen_p = clen;
		dst[clen] = 0;
		return dst;
	}
	if (!allow_invalid)
		goto fail;

	/* full decode failed, decode chars one-by-one */
	s = str;
	w = dst;
	wend = dst + wmax - 1;
	memset(&ps, 0, sizeof(ps));
	while (s < str_end && w < wend) {
		clen = mbrtowc(w, s, str_end - s, &ps);
		if (clen > 0) {
			/* single char */
			w++;
			s += clen;
		} else if (clen == 0) {
			/* string end */
			break;
		} else if (allow_invalid) {
			/* allow invalid encoding */
			memset(&ps, 0, sizeof(ps));
			*w++ = (unsigned char)*s++;
		} else {
			/* invalid encoding */
			goto fail;
		}
	}

	/* make sure we got string end */
	if (s < str_end && *s != '\0')
		goto fail;

	*w = 0;
	if (wlen_p)
		*wlen_p = w - dst;
	return dst;

fail:
	if (dst != wbuf)
		free(dst);
	return NULL;
}

wctype_t wctype_wcsn(const wchar_t *name, unsigned int namelen)
{
	char buf[10];
	unsigned int i;

	if (namelen >= sizeof(buf))
		return (wctype_t)0;
	for (i = 0; i < namelen; i++) {
		wchar_t c = name[i];
		if (c < 0x20 || c > 127)
			return (wctype_t)0;
		buf[i] = c;
	}
	buf[i] = 0;
	return wctype(buf);
}

#ifndef HAVE_MBSNRTOWCS

size_t mbsnrtowcs(wchar_t *dst, const char **src_p, size_t srclen, size_t dstlen, mbstate_t *ps)
{
	int clen;
	const char *s, *s_end;
	wchar_t *w;
	mbstate_t pstmp;
	size_t count = 0;

	if (!ps) {
		memset(&pstmp, 0, sizeof(pstmp));
		ps = &pstmp;
	}

	s = *src_p;
	s_end = s + srclen;
	w = dst;
	while (s < s_end) {
		if (w && count >= dstlen) {
			/* dst is full */
			break;
		}
		clen = mbrtowc(w, s, s_end - s, ps);
		if (clen > 0) {
			/* proper character */
			if (w)
				w++;
			count++;
			s += clen;
		} else if (clen < 0) {
			/* invalid encoding */
			*src_p = s;
			return (size_t)(-1);
		} else {
			/* end of string */
			if (w)
				*w = 0;
			*src_p = NULL;
			return count;
		}
	}
	/* end due to srclen */
	*src_p = s;
	return count;
}

#endif
