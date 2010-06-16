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
 * libc compat functions.
 */

#ifndef HAVE_CRYPT
static inline char *crypt(const char *p, const char *s) { return NULL; }
#endif
#ifndef HAVE_LSTAT
static inline int lstat(const char *path, struct stat *st) { return stat(path, st); }
#endif

void change_user(const char *user);

