/** @file
 * Low-level UTF8 handling.
 */

/*
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

#ifndef _USUAL_UTF8_H_
#define _USUAL_UTF8_H_

#include <usual/base.h>

/**
 * Parse Unicode codepoint from UTF8 stream.
 *
 * On invalid UTF8 sequence returns negative byte value and
 * inreases src_p by one.
 *
 * @param src_p Location of data pointer.  Will be incremented in-place.
 * @param srcend  Pointer to end of data.
 * @return UNOCODE codepoint or negative byte value on error.
 */
int  utf8_get_char(const char **src_p, const char *srcend);

/**
 * Write Unicode codepoint as UTF8 sequence.
 *
 * Skips invalid Unicode values without error.
 *
 * @param c       Unicode codepoint.
 * @param dst_p   Location of dest pointer, will be increased in-place.
 * @param dstend  Pointer to end of buffer.
 * @return false if not room, true otherwise.
 */
bool utf8_put_char(unsigned int c, char **dst_p, const char *dstend);

/** Return UTF8 seq length based on unicode codepoint */
int utf8_char_size(unsigned int c);

/** Return UTF8 seq length based on first byte */
int utf8_seq_size(unsigned char c);

/** Return sequence length if all bytes are valid, 0 otherwise. */
int utf8_validate_seq(const char *src, const char *srcend);

bool utf8_validate_string(const char *src, const char *end);

#endif
