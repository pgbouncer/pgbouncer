/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007 Marko Kreen, Skype Technologies OÜ
 * 
 * Permission to use, copy, modify, and distribute this software for any
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

/*
 * Required system headers
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

/* how to specify array with unknown length */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
#define FLEX_ARRAY
#elif defined(__GNUC__)
#define FLEX_ARRAY
#else
#define FLEX_ARRAY 1
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4)

/* gcc has hew positive aspects too */
#define _MUSTCHECK		__attribute__((warn_unused_result))
#define _DEPRECATED		__attribute__((deprecated))
#define _PRINTF(fmtpos, argpos)	__attribute__((format(printf, fmtpos, argpos)))
#define _MALLOC			__attribute__((malloc))

/* those do not seem to work well */
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)

#else

#define _MUSTCHECK
#define _DEPRECATED
#define _PRINTF(x,y)
#define _MALLOC
#define unlikely(x) x
#define likely(x) x

#endif

/* cant use assert() as we want to log too */
#ifdef CASSERT
#define Assert(e) \
do { \
	if (unlikely(!(e))) { \
		fatal_noexit("Assert(%s) failed", #e); \
		abort(); \
	} \
} while (0)
#else
#define Assert(e)
#endif

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX  128 /* actual sizeof() will be applied later anyway */
#endif

/* how many microseconds in a second */
#define USEC (1000000LL)

typedef uint64_t usec_t;

/*
 * bool type.
 */

typedef unsigned char bool;
#define false	0
#define true	1

/*
 * PostgreSQL type OIDs for resultsets.
 */

#define INT8OID 20
#define INT4OID 23
#define TEXTOID 25

/*
 * Make sure __func__ works.
 */

#ifndef HAVE_FUNCNAME__FUNC
#define __func__ __FUNCTION__
#endif

/*
 * Some systems (Solaris) does not define INADDR_NONE
 */
#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

/*
 * libc compat functions.
 */

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t n) _MUSTCHECK;
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t n) _MUSTCHECK;
#endif
#ifndef HAVE_GETPEEREID
int getpeereid(int fd, uid_t *uid_p, gid_t *gid_p) _MUSTCHECK;
#endif
#ifndef HAVE_BASENAME
const char *basename(const char *path);
#endif

void change_user(const char *user);

/*
 * memcpy() optimization - improves hash.c.
 *
 * GCC can optimize fixed-length memcpys but not variable-length ones.
 * For short variable-length memcpys its faster to do dumb inlined copy
 * than call out to libc.
 */

#if defined(__GNUC__) && (__GNUC__ >= 3)

static inline void *_inline_memcpy(void *dst_, const void *src_, size_t len)
{
	const uint8_t *src = src_;
	uint8_t *dst = dst_;
	while (len--)
		*dst++ = *src++;
	return dst_;
}

static inline void *_own_memcpy(void *dst, const void *src, size_t len)
{
	if (!__builtin_constant_p(len)
	    && __builtin_constant_p(len < 16)
	    && len < 16)
		return _inline_memcpy(dst, src, len);
	else
		return memcpy(dst, src, len);
}

#undef memcpy
#define memcpy(d, s, n) _own_memcpy(d, s, n)

#endif

/*
 * strcmp() optimization - compare first char inline.
 */

static inline int _inline_strcmp(const char *a, const char *b)
{
	if ((*a - *b) != 0)
		return (*a - *b);
	return strcmp(a, b);
}

#undef strcmp
#define strcmp(a, b) _inline_strcmp(a, b)

