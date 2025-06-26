/*
 * Cmdline error reporting.
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

/**
 * @file
 *
 * Error printing for command-line utilities.
 */
#ifndef _USUAL_ERR_H_
#define _USUAL_ERR_H_

#include <usual/base.h>

#ifdef HAVE_ERR_H
#include <err.h>
#endif

#ifndef HAVE_ERR
/** Print formatted message and strerror(errno) to stderr and exit with given error code */
void err(int e, const char *fmt, ...) _PRINTF(2, 3);
#endif
#ifndef HAVE_ERRX
/** Print formatted message to stderr and exit with given error code */
void errx(int e, const char *fmt, ...) _PRINTF(2, 3);
#endif
#ifndef HAVE_WARN
/** Print formatted message and strerror(errno) to stderr */
void warn(const char *fmt, ...)  _PRINTF(1, 2);
#endif
#ifndef HAVE_WARNX
/** Print formatted message to stderr */
void warnx(const char *fmt, ...)  _PRINTF(1, 2);
#endif
#ifndef HAVE_SETPROGNAME
/** Set program name to that will printed as prefix to error messages */
void setprogname(const char *s);
#endif
#ifndef HAVE_GETPROGNAME
/** Return program name set with @ref setprogname */
const char *getprogname(void);
#endif

/** Malloc that exits on failure */
void *xmalloc(size_t len);

/** Realloc that exits on failure */
void *xrealloc(void *p, size_t len);

/** strdup that exits on failure */
char *xstrdup(const char *s);

#endif
