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

/** @file
 * Random stuff that does not fit elsewhere.
 */
#ifndef _USUAL_MISC_H_
#define _USUAL_MISC_H_

#include <usual/base.h>

#ifdef WORDS_BIGENDIAN
#define FOURCC(a, b, c, d) \
	(((unsigned int)(unsigned char)(a) << 24) \
	 | ((unsigned int)(unsigned char)(b) << 16) \
	 | ((unsigned int)(unsigned char)(c) << 8) \
	 | ((unsigned int)(unsigned char)(d)))
#else
/** Four-byte identifier as integer */
#define FOURCC(a, b, c, d) \
	(((unsigned int)(unsigned char)(a)) \
	 | ((unsigned int)(unsigned char)(b) << 8) \
	 | ((unsigned int)(unsigned char)(c) << 16) \
	 | ((unsigned int)(unsigned char)(d) << 24))
#endif

#if defined(__i386__) || defined(__x86_64__)
#define mb()  asm volatile ("mfence" ::: "memory")
#define rmb() asm volatile ("lfence" ::: "memory")
#define wmb() asm volatile ("sfence" ::: "memory")
#endif

#endif
