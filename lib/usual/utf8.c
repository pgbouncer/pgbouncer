/*
 * Low-level UTF8 handling.
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

#include <usual/utf8.h>
#include <usual/err.h>

#define u8head(c, mask) (((c) & (mask | (mask >> 1))) == mask)
#define u8tail(c)       u8head(c, 0x80)

/*
 * conservative utf8 decoder
 *
 * if invalid char, advance src pointer by one and return
 * negative byte value.  this can be ignored or replaced.
 */
int utf8_get_char(const char **src_p, const char *_srcend)
{
	uint32_t c;
	const uint8_t *srcend = (uint8_t *)_srcend;
	const uint8_t *p = (uint8_t *)(*src_p);
	/*
	 * 0xxx xxxx -> len=1
	 * 10xx xxxx -> tail byte
	 * 110x xxxx -> len=2
	 * 1110 xxxx -> len=3
	 * 1111 0xxx -> len=4
	 */
	if (p[0] < 0x80) {
		c = *p++;
	} else if (u8head(p[0], 0xC0)) {
		if (p + 2 > srcend)
			goto eos;
		if (!u8tail(p[1]))
			goto bad_enc;

		c = ((p[0] & 0x1F) << 6) | (p[1] & 0x3F);
		if (c < 0x80)
			goto bad_enc;
		p += 2;
	} else if (u8head(p[0], 0xE0)) {
		if (p + 3 > srcend)
			goto eos;
		if (!u8tail(p[1]) || !u8tail(p[2]))
			goto bad_enc;

		c = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
		if ((c < 0x800) || ((c & 0xF800) == 0xD800))
			goto bad_enc;
		p += 3;
	} else if (u8head(p[0], 0xF0)) {
		if (p + 4 > srcend)
			goto eos;
		if (!u8tail(p[1]) || !u8tail(p[2]) || !u8tail(p[3]))
			goto bad_enc;

		c = ((p[0] & 0x07) << 18) | ((p[1] & 0x3F) << 12)
		    | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
		if (c < 0x10000 || c > 0x10FFFF)
			goto bad_enc;
		p += 4;
	} else {
		goto bad_enc;
	}
	*src_p = (char *)p;
	return c;
bad_enc:
eos:
	c = p[0];
	*src_p = (char *)p + 1;
	return -(int)c;
}

/* encode one char - skip invalid ones */
bool utf8_put_char(unsigned int c, char **dst_p, const char *dstend)
{
	char *dst = *dst_p;
	if (c < 0x80) {
		if (dst + 1 > dstend)
			goto no_room;
		*dst++ = c;
	} else if (c < 0x800) {
		if (dst + 2 > dstend)
			goto no_room;
		*dst++ = 0xC0 | (c >> 6);
		*dst++ = 0x80 | (c & 0x3F);
	} else if (c < 0x10000) {
		if (dst + 3 > dstend)
			goto no_room;
		if (c < 0xD800 || c > 0xDFFF) {
			*dst++ = 0xE0 | (c >> 12);
			*dst++ = 0x80 | ((c >> 6) & 0x3F);
			*dst++ = 0x80 | (c & 0x3F);
		}
	} else if (c <= 0x10FFFF) {
		if (dst + 4 > dstend)
			goto no_room;
		*dst++ = 0xF0 | (c >> 18);
		*dst++ = 0x80 | ((c >> 12) & 0x3F);
		*dst++ = 0x80 | ((c >> 6) & 0x3F);
		*dst++ = 0x80 | (c & 0x3F);
	}
	*dst_p = dst;
	return true;

no_room:
	return false;
}

int utf8_char_size(unsigned int c)
{
	if (c < 0x80) return 1;
	if (c < 0x800) return 2;
	if (c < 0x10000) return 3;
	return 4;
}

int utf8_seq_size(unsigned char b)
{
	if (b < 0x80) return 1;
	if (b < 0xC2) return 0;
	if (b < 0xE0) return 2;
	if (b < 0xF0) return 3;
	if (b < 0xF5) return 4;
	return 0;
}

/*
 *     7f: c1bf (+1)
 *     80: c280
 *    7ff: dfbf
 *    7ff: e09fbf (+1)
 *    800: e0a080
 *   ffff: efbfbf
 *   ffff: f08fbfbf (+1)
 *  10000: f0908080
 * 10ffff: f48fbfbf
 */
int utf8_validate_seq(const char *src, const char *srcend)
{
	const unsigned char *u = (unsigned char *)src;
	const unsigned char *uend = (unsigned char *)srcend;

	if (u[0] < 0x80) {	/* ascii */
		if (u[0] == 0)
			goto invalid;
		return 1;
	} else if (u[0] < 0xC2) {	/* tail byte as first byte */
		goto invalid;
	} else if (u[0] < 0xE0) {	/* 1 tail byte */
		if (u + 2 > uend)
			goto invalid;

		if ((u[1] & 0xC0) != 0x80)
			goto invalid;
		return 2;
	} else if (u[0] < 0xF0) {	/* 2 tail bytes */
		if (u + 3 > uend)
			goto invalid;
		if (u[0] == 0xE0 && u[1] < 0xA0)
			goto invalid;
		if (u[0] == 0xED && u[1] >= 0xA0)
			goto invalid;
		if ((u[1] & 0xC0) != 0x80)
			goto invalid;
		if ((u[2] & 0xC0) != 0x80)
			goto invalid;
		return 3;
	} else if (u[0] < 0xF5) {	/* 3-tail bytes */
		if (u + 4 > uend)
			goto invalid;
		if (u[0] == 0xF0 && u[1] < 0x90)
			goto invalid;
		if (u[0] == 0xF4 && u[1] > 0x8F)
			goto invalid;

		if ((u[1] & 0xC0) != 0x80)
			goto invalid;
		if ((u[2] & 0xC0) != 0x80)
			goto invalid;
		if ((u[3] & 0xC0) != 0x80)
			goto invalid;
		return 4;
	}
invalid:
	return 0;
}

bool utf8_validate_string(const char *src, const char *end)
{
	unsigned int n;
	while (src < end) {
		if (*src & 0x80) {
			n = utf8_validate_seq(src, end);
			if (n == 0)
				return false;
			src += n;
		} else if (*src == '\0') {
			return false;
		} else {
			src++;
		}
	}
	return true;
}
