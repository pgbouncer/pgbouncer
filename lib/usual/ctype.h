/*
 * ctype wrappers
 *
 * Copyright (c) 2011  Marko Kreen
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
 * ctype compat.
 *
 * Provides wrappers that make sure the functions work on 'char' values.
 *
 * @note
 * POSIX requires that these functions accept EOF/-1 in addition
 * to ordinary byte values.  That means when working on 'char',
 * the functions cannot differetiate between 0xFF and EOF.
 * As no code should give EOF to <ctype.h> functions and no code
 * should depend whether 0xFF is labeled ispunct() or not,
 * it seems no worthwhile to fix it.
 */

#ifndef _USUAL_CTYPE_H_
#define _USUAL_CTYPE_H_

#include <usual/base.h>

#include <ctype.h>

#ifndef isblank
#define isblank usual_isblank
static inline int isblank(int c) { return (c == ' ') || (c == '\t'); }
#endif

/* keep right signature, cast to uchar internally */
#define _WRAP_CTYPE_FN(name) \
	static inline int safe_ ## name (int c) { \
		return name((unsigned char)(c)); \
	}

_WRAP_CTYPE_FN(isalnum)
#undef isalnum
/** Safe isalnum */
#define isalnum safe_isalnum

_WRAP_CTYPE_FN(isalpha)
#undef isalpha
/** Safe isalpha */
#define isalpha safe_isalpha

_WRAP_CTYPE_FN(isascii)
#undef isascii
/** Safe isascii */
#define isascii safe_isascii

_WRAP_CTYPE_FN(isblank)
#undef isblank
/** Safe isblank */
#define isblank safe_isblank

_WRAP_CTYPE_FN(iscntrl)
#undef iscntrl
/** Safe iscntrl */
#define iscntrl safe_iscntrl

_WRAP_CTYPE_FN(isdigit)
#undef isdigit
/** Safe isdigit */
#define isdigit safe_isdigit

_WRAP_CTYPE_FN(isgraph)
#undef isgraph
/** Safe isgraph */
#define isgraph safe_isgraph

_WRAP_CTYPE_FN(islower)
#undef islower
/** Safe islower */
#define islower safe_islower

_WRAP_CTYPE_FN(isprint)
#undef isprint
/** Safe isprint */
#define isprint safe_isprint

_WRAP_CTYPE_FN(ispunct)
#undef ispunct
/** Safe ispunct */
#define ispunct safe_ispunct

_WRAP_CTYPE_FN(isspace)
#undef isspace
/** Safe isspace */
#define isspace safe_isspace

_WRAP_CTYPE_FN(isupper)
#undef isupper
/** Safe isupper */
#define isupper safe_isupper

_WRAP_CTYPE_FN(isxdigit)
#undef isxdigit
/** Safe isxdigit */
#define isxdigit safe_isxdigit

_WRAP_CTYPE_FN(tolower)
#undef tolower
/** Safe tolower */
#define tolower safe_tolower

_WRAP_CTYPE_FN(toupper)
#undef toupper
/** Safe toupper */
#define toupper safe_toupper

#undef _WRAP_CTYPE_FN

#endif /* _USUAL_CTYPE_H_ */
