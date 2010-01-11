/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
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

/*
 * Required system headers
 */

#include <usual/base.h>

#ifdef WIN32
#include "win32support.h"
#endif

#include <sys/stat.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <sys/resource.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

/* how to specify array with unknown length */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
#define FLEX_ARRAY
#elif defined(__GNUC__)
#define FLEX_ARRAY
#else
#define FLEX_ARRAY 1
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

#ifndef HAVE_GETPEEREID
int getpeereid(int fd, uid_t *uid_p, gid_t *gid_p) _MUSTCHECK;
#endif
#ifndef HAVE_CRYPT
static inline char *crypt(const char *p, const char *s) { return NULL; }
#endif
#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
#endif
#ifndef HAVE_LSTAT
static inline int lstat(const char *path, struct stat *st) { return stat(path, st); }
#endif

/* libevent 1.3 does not have event_loopbreak() */
#ifndef HAVE_EVENT_LOOPBREAK
static inline void event_loopbreak(void) { }
#endif

void change_user(const char *user);

