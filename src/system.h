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
#include "../config.h"
#endif

#define _GNU_SOURCE

#include <sys/errno.h>
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

#ifdef CASSERT
#define Assert(e) do { if (!(e)) { \
	fatal_noexit("Assert(%s) failed", #e); abort(); } } while (0)
#else
#define Assert(e)
#endif

#ifndef UNIX_PATH_MAX
/* #define UNIX_PATH_MAX  (sizeof(((struct sockaddr_un *)0)->sun_path)) */
#define UNIX_PATH_MAX  128 /* actual sizeof() will be applied later anyway */
#endif

/* how many microseconds in a second */
#define USEC (1000000LL)


/*
 * PostgreSQL types.
 */

typedef enum { false=0, true=1 } bool;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

/*
 * PostgreSQL type OIDs for resultsets.
 */

#define INT8OID 20
#define INT4OID 23
#define TEXTOID 25

/*
 * libc compat functions.
 */

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t n);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t n);
#endif
#ifndef HAVE_GETPEEREID
int getpeereid(int fd, uid_t *uid_p, gid_t *gid_p);
#endif

