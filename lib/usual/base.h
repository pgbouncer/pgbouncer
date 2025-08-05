/** @file
 * Basic C environment.
 */

/*
 * Copyright (c) 2007-2009 Marko Kreen
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

#ifndef _USUAL_BASE_H_
#define _USUAL_BASE_H_

#ifdef USUAL_TEST_CONFIG
#include "test_config.h"
#elif defined(_MSC_VER)
#include <usual/config_msvc.h>
#else
#include <usual/config.h>
#endif

/* solaris is broken otherwise */
#if defined(__sun)
#define _XPG4_2
#define __EXTENSIONS__
#endif

/* C11 */
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdbool.h>

#ifdef WIN32
#include <usual/base_win32.h>
#define DLLEXPORT __declspec(dllexport)
#define DLLIMPORT __declspec(dllimport)
#else
#define DLLEXPORT
#define DLLIMPORT
#endif

/** given pointer to field inside struct, return pointer to struct */
#ifndef container_of
#define container_of(ptr, type, field) ((type *)((char *)(ptr) - offsetof(type, field)))
#endif

/** get alignment requirement for a type */
#ifndef alignof
#define alignof(type) offsetof(struct { char c; type t; }, t)
#endif

/** power-of-2 alignment */
#ifndef CUSTOM_ALIGN
#define CUSTOM_ALIGN(x, a) (((uintptr_t)(x) + (uintptr_t)(a) - 1) & ~((uintptr_t)(a) - 1))
#endif

/** preferred alignment */
#ifndef ALIGN
#define ALIGN(x)  CUSTOM_ALIGN(x, sizeof(long))
#endif

/** number of elements in array */
#define ARRAY_NELEM(a)  (sizeof(a) / sizeof((a)[0]))

/**
 * Compat helper to specify array with unknown length.
 *
 * Usage:
 *
 * @code
 * char flex_string[FLEX_ARRAY];
 * @endcode
 */
#define FLEX_ARRAY

/** Make string token from C expression */
#define STR(x) _STR_(x)
#define _STR_(x) #x

/** Make single C token from 2 separate tokens */
#define CONCAT(a, b)    _CONCAT_(a, b)
#define _CONCAT_(a, b)  a ## b

/** Make single C token from 3 separate tokens */
#define CONCAT3(a, b, c)     _CONCAT3_(a, b, c)
#define _CONCAT3_(a, b, c)  a ## b ## c

/** Make single C token from 4 separate tokens */
#define CONCAT4(a, b, c, d)    _CONCAT4_(a, b, c, d)
#define _CONCAT4_(a, b, c, d)  a ## b ## c ## d

/**
 * @name Compiler checks, mainly for internal usage.
 *
 * @{
 */

/** Pre-processor macro to check if compiler is GCC with high enough version */
#if defined(__GNUC__)
#define _COMPILER_GNUC(maj, min) ((__GNUC__ > (maj)) || (__GNUC__ == (maj) && __GNUC_MINOR__ >= (min)))
#else
#define _COMPILER_GNUC(maj, min) (0)
#endif
/** Pre-processor macro to check if compiler is CLANG with high enough version */
#if defined(__clang__)
#define _COMPILER_CLANG(maj, min) ((__clang_major__ > (maj)) || (__clang_major__ == (maj) && __clang_minor__ >= (min)))
#else
#define _COMPILER_CLANG(maj, min) (0)
#endif
/** Pre-processor macro to check if compiler is Visual C with high enough version */
#if defined(_MSC_VER)
#define _COMPILER_MSC(ver) (_MSC_VER >= (ver))
#else
#define _COMPILER_MSC(ver) (0)
#endif
/** Pre-processor macro to check if compiler is Intel CC with high enough version */
#if defined(__INTEL_COMPILER)
#define _COMPILER_ICC(ver) (__INTEL_COMPILER >= (ver))
#else
#define _COMPILER_ICC(ver) (0)
#endif

/*
 * clang compat
 *
 * They work only if the compiler is clang,
 * return 0 otherwise.
 */

#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif
#ifndef __has_feature
#define __has_feature(x) (0)
#endif
#ifndef __has_extension
#define __has_extension(x) __has_feature(x)
#endif
#ifndef __has_attribute
#define __has_attribute(x) (0)
#endif

/*
 * clang macros that cannot be defined here:
 * __is_identifier
 * __has_include
 * __has_include_next
 * __has_warning
 */

/**
 * @}
 *
 * @name Function/struct attributes.
 *
 * @{
 */

/** Disable padding for structure */
#ifndef _MSC_VER
#define _PACKED                 __attribute__((packed))
#endif

/*
 * make compiler do something useful
 */

/** Show warning if function result is not used */
#if _COMPILER_GNUC(4, 0) || __has_attribute(warn_unused_result)
#define _MUSTCHECK __attribute__((warn_unused_result))
#else
#define _MUSTCHECK
#endif

/** Show warning if used */
#if _COMPILER_GNUC(4, 0) || __has_attribute(deprecated)
#define _DEPRECATED __attribute__((deprecated))
#else
#define _DEPRECATED
#endif

/** Check printf-style format and arg sanity */
#if _COMPILER_GNUC(4, 0) || __has_attribute(printf)
#ifdef __MINGW32__
#define _PRINTF(fmtpos, argpos) __attribute__((format(__MINGW_PRINTF_FORMAT, fmtpos, argpos)))
#else
#define _PRINTF(fmtpos, argpos) __attribute__((format(printf, fmtpos, argpos)))
#endif
#else
#define _PRINTF(fmtpos, argpos)
#endif

/** Function returns new pointer */
#if _COMPILER_GNUC(4, 0) || __has_attribute(malloc)
#define _MALLOC __attribute__((malloc))
#else
#define _MALLOC
#endif

/** Disable 'unused' warning for function/argument. */
#if _COMPILER_GNUC(4, 0) || __has_attribute(unused)
#define _UNUSED __attribute__((unused))
#else
#define _UNUSED
#endif

/** Do not inline function. */
#if _COMPILER_GNUC(4, 0) || __has_attribute(noinline)
#define _NOINLINE __attribute__((noinline))
#else
#define _NOINLINE
#endif

/** Indicates that function never returns */
#if _COMPILER_GNUC(4, 0) || __has_attribute(noreturn)
#define _NORETURN __attribute__((noreturn))
#else
#define _NORETURN
#endif

/** Hint for compiler that expression (x) is likely to be true */
#if _COMPILER_GNUC(4, 0) || __has_builtin(__builtin_expect)
#define likely(x) __builtin_expect(!!(x), 1)
#else
#define likely(x) (x)
#endif

/** Hint for compiler that expression (x) is likely to be false */
#if _COMPILER_GNUC(4, 0) || __has_builtin(__builtin_expect)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define unlikely(x) (x)
#endif

/* @} */


/**
 * Compile-time assert.
 *
 * Expression must be evaluatable at compile time.
 * If false, stop compilation with message.
 *
 * It can be used in either global or function scope.
 */
#ifndef static_assert
#if _COMPILER_GNUC(4, 6) || _COMPILER_MSC(1600) || __has_feature(c_static_assert)
/* Version for new compilers */
#define static_assert(expr, msg) _Static_assert(expr, msg)
#else
/* Version for old compilers */
#define static_assert(expr, msg) enum { CONCAT4(static_assert_failure_, __LINE__, _, __COUNTER__) = 1/(1 != (1 + (expr))) }
#endif
#endif /* !static_assert */


/** assert() that uses <usual/logging> module  */
#ifndef Assert
#ifdef CASSERT
void log_fatal(const char *file, int line, const char *func, bool show_perror, void *ctx, const char *s, ...) _PRINTF(6, 7);
#define Assert(e) \
	do { \
		if (unlikely(!(e))) { \
			log_fatal(__FILE__, __LINE__, __func__, false, NULL, \
				  "Assert(%s) failed", #e); \
			abort(); \
		} \
	} while (0)
#else
#define Assert(e)
#endif
#endif

/** Zeroing malloc */
_MUSTCHECK
static inline void *zmalloc(size_t len)
{
	return calloc(1, len);
}

#ifndef HAVE_POSIX_MEMALIGN
#define posix_memalign(a, b, c) usual_memalign(a, b, c)
/** Compat: posix_memalign() */
int posix_memalign(void **ptr_p, size_t align, size_t len);
#endif

#ifndef HAVE_REALLOCARRAY
#define reallocarray(a, b, c) usual_reallocarray(a, b, c)

/**
 * Same as realloc(), but safely calculates total size.
 */
void *reallocarray(void *p, size_t count, size_t size);

#endif

#endif
