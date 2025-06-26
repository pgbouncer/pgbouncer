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

/**
 * @file
 *
 * Utility functions for PostgreSQL data formats.
 */
#ifndef _USUAL_PGUTIL_H_
#define _USUAL_PGUTIL_H_

#include <usual/string.h>

/** Check if string is reserver word for PostgreSQL. */
bool pg_is_reserved_word(const char *str);

/** Quote value as string for PostgreSQL */
bool pg_quote_literal(char *_dst, const char *_src, int dstlen);

/** Quote value as ident for PostgreSQL */
bool pg_quote_ident(char *_dst, const char *_src, int dstlen);

/** Quote fully-qualified ident for PostgreSQL */
bool pg_quote_fqident(char *_dst, const char *_src, int dstlen);

/** Parse PostgreSQL array. */
struct StrList *pg_parse_array(const char *pgarr, CxMem *cx);

#endif
