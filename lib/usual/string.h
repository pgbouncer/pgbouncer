/*
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
 * \file
 * Theme include for strings.
 */

#ifndef _USUAL_STRING_H_
#define _USUAL_STRING_H_

#include <usual/cxalloc.h>

#include <string.h>

/**
 * @name  List of strings.
 * @{
 */

/** Callback signature */
typedef bool (*str_cb)(void *arg, const char *s);

struct StrList;
/** Allocate new string list */
struct StrList *strlist_new(CxMem *ca);
/** Free string string */
void strlist_free(struct StrList *slist);
/** Check if empty */
bool strlist_empty(struct StrList *slist);
/** Append copy of string. */
bool strlist_append(struct StrList *slist, const char *str);
/** Append reference, strlist now owns it. */
bool strlist_append_ref(struct StrList *slist, char *str);
/** Call function on each element */
bool strlist_foreach(const struct StrList *slist, str_cb cb_func, void *cb_arg);
/** Remove and return first element */
char *strlist_pop(struct StrList *slist);
/* @} */

/** Parse comma-separated elements from string and launch callback for each of them. */
bool parse_word_list(const char *s, str_cb cb_func, void *cb_arg);

#ifndef HAVE_STRLCPY
#undef strlcpy
#define strlcpy(a, b, c) usual_strlcpy(a, b, c)
/** Compat: Safely copy string to fixed-length buffer.  */
size_t strlcpy(char *dst, const char *src, size_t n);
#endif

#ifndef HAVE_STRLCAT
#undef strlcat
#define strlcat(a, b, c) usual_strlcat(a, b, c)
/** Compat: Safely append string to fixed-length buffer. */
size_t strlcat(char *dst, const char *src, size_t n);
#endif

#undef strpcpy
#define strpcpy(a, b, c) usual_strpcpy(a, b, c)

/**
 * Safe string copy.
 *
 * Returns pointer to end of string in dst or NULL
 * if truncation occured.  Destination will be
 * zero-terminated unless dstlen is 0.
 */
char *strpcpy(char *dst, const char *src, size_t dstlen);

#undef strpcat
#define strpcat(a, b, c) usual_strpcat(a, b, c)

/**
 * Safe string concat.
 *
 * Returns pointer to end of string in dst or NULL if truncation occured.
 * Destination will be zero-terminated, unless dstlen is 0 or existing
 * contents were not zero-terminated.
 */
char *strpcat(char *dst, const char *src, size_t dstlen);


#ifndef HAVE_MEMRCHR
#undef memrchr
#define memrchr(a, b, c) usual_memrchr(a, b, c)
/** Compat: find byte in reverse direction */
void *memrchr(const void *s, int c, size_t n);
#endif

#ifndef HAVE_MEMMEM
#undef memmem
#define memmem(a, b, c, d) usual_memmem(a, b, c, d)
/** Compat: find memory area */
void *memmem(const void *s, size_t slen, const void *q, size_t qlen);
#endif

#ifndef HAVE_MEMPCPY
#undef mempcpy
#define mempcpy(a, b, c) usual_mempcpy(a, b, c)
/** Copy memory, return pointer to end. */
void *mempcpy(void *dst, const void *src, size_t len);
#endif

/** Return position to first byte that is in 'find'. */
void *mempbrk(const void *data, size_t dlen, const void *find, size_t flen);

/** Return number of bytes where none are in reject. */
size_t memcspn(const void *data, size_t dlen, const void *reject, size_t rlen);

/** Return number of bytes where all are in accept. */
size_t memspn(const void *data, size_t dlen, const void *accept, size_t alen);

#ifndef HAVE_BASENAME
#undef basename
#define basename(a) usual_basename(a)
/** Compat: Return pointer to last non-path element.
    Never modifies path, returns either pointer inside path or static buffer.  */
const char *basename(const char *path);
#endif

#ifndef HAVE_DIRNAME
#undef dirname
#define dirname(a) usual_dirname(a)
/** Compat: Return directory part of pathname.
    Never modifies path, returns either pointer inside path or static buffer.  */
const char *dirname(const char *path);
#endif

#ifndef HAVE_EXPLICIT_BZERO
#undef explicit_bzero
#define explicit_bzero(a, b) usual_explicit_bzero(a, b)
/** Definitely clear memory */
void explicit_bzero(void *buf, size_t len);
#endif

/*
 * strerror, strerror_r
 */

#ifdef WIN32
const char *win32_strerror(int e);
/** Compat: strerror() for win32 */
#define strerror(x) win32_strerror(x)
#endif

const char *usual_strerror_r(int e, char *dst, size_t dstlen);
/** Compat: Provide GNU-style API: const char *strerror_r(int e, char *dst, size_t dstlen)  */
#define strerror_r(a, b, c) usual_strerror_r(a, b, c)

/** strtod() that uses '.' as decimal separator */
double strtod_dot(const char *s, char **tokend);

/** Convert double to string with '.' as decimal separator */
ssize_t dtostr_dot(char *buf, size_t buflen, double val);

#ifndef HAVE_STRTONUM
#undef strtonum
#define strtonum(a, b, c, d) usual_strtonum(a, b, c, d)
/**
 * Convert string to integer, check limits.
 *
 * Accepts only decimal numbers, no octal or hex.  Allows leading whitespace,
 * but not tailing.
 *
 * On success, returns value that is minval <= res <= maxval.  If errstr_p is given
 * it stores NULL there.  Keeps old errno value.
 *
 * On error, returns 0, sets errno, and if errstr_p is given, stores error reason there.
 */
long long strtonum(const char *s, long long minval, long long maxval, const char **errstr_p);
#endif

#ifndef HAVE_STRSEP
#undef strsep
#define strsep(a, b) usual_strsep(a, b)
/**
 * Return next token from string.
 *
 * Tokens are separated by delim chars
 * Modifies string in-place.
 */
char *strsep(char **stringp, const char *delim);
#endif

#ifndef HAVE_ASPRINTF
#undef asprintf
#define asprintf(dst_p, fmt, ...) usual_asprintf(dst_p, fmt, __VA_ARGS__)
int asprintf(char **dst_p, const char *fmt, ...) _PRINTF(2, 3);
#endif

#ifndef HAVE_VASPRINTF
#undef vasprintf
#define vasprintf(dst_p, fmt, ap) usual_vasprintf(dst_p, fmt, ap)
int vasprintf(char **dst_p, const char *fmt, va_list ap) _PRINTF(2, 0);
#endif

bool strcmpeq(const char *str_left, const char *str_right);

#endif
