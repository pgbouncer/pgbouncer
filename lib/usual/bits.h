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
 * Bit arithmetics.
 *
 * - is_power_of_2
 * - ffs, ffsl, ffsll
 * - fls, flsl, flsll
 * - rol16, rol32, rol64
 * - ror16, ror32, ror64
 */
#ifndef _USUAL_BITS_H_
#define _USUAL_BITS_H_

#include <usual/base.h>

#include <string.h>
#include <limits.h>

/** Checks if integer has only one bit set */
static inline bool is_power_of_2(unsigned int n)
{
	return (n > 0) && !(n & (n - 1));
}

/*
 * Single-eval and type-safe rol/ror
 */

/** Rotate 16-bit int to left */
static inline uint16_t rol16(uint16_t v, int s)
{
	return (v << s) | (v >> (16 - s));
}
/** Rotate 32-bit int to left */
static inline uint32_t rol32(uint32_t v, int s)
{
	return (v << s) | (v >> (32 - s));
}
/** Rotate 64-bit int to left */
static inline uint64_t rol64(uint64_t v, int s)
{
	return (v << s) | (v >> (64 - s));
}

/** Rotate 16-bit int to right */
static inline uint16_t ror16(uint16_t v, int s) { return rol16(v, 16 - s); }

/** Rotate 32-bit int to right */
static inline uint32_t ror32(uint32_t v, int s) { return rol32(v, 32 - s); }

/** Rotate 64-bit int to right */
static inline uint64_t ror64(uint64_t v, int s) { return rol64(v, 64 - s); }

/*
 * fls(int)
 * flsl(long)
 * flsll(long long)
 *
 *   find MSB bit set, 1-based ofs, 0 if arg == 0
 */

#undef fls
#undef flsl
#undef flsll
#define fls(x) usual_fls(x)
#define flsl(x) usual_flsl(x)
#define flsll(x) usual_flsll(x)

#if _COMPILER_GNUC(4,0) || __has_builtin(__builtin_clzll)
#define _USUAL_FLS_(sfx, type) \
	return (x == 0) ? 0 : ((8*sizeof(type)) - __builtin_clz ## sfx(x))
#else
#define _USUAL_FLS_(sfx, type) \
	unsigned type u = x; \
	unsigned int bit; \
	if (x == 0) return 0; \
	/* count from smallest bit, assuming small values */ \
	for (bit = 1; u > 1; bit++) u >>= 1; \
	return bit
#endif

/** Find last (highest) set bit, 1-based offset, 0 if arg == 0 */
static inline int fls(int x)
{
	_USUAL_FLS_(, int);
}

/** Find last (highest) set bit, 1-based offset, 0 if arg == 0 */
static inline int flsl(long x)
{
	_USUAL_FLS_(l, long);
}

/** Find last (highest) set bit, 1-based offset, 0 if arg == 0 */
static inline int flsll(long long x)
{
	_USUAL_FLS_(ll, long long);
}

#undef _USUAL_FLS_

/*
 * ffs(int)
 * ffsl(long)
 * ffsll(long long)
 *
 *   find LSB bit set, 1-based ofs, 0 if arg == 0
 */

#undef ffs
#undef ffsl
#undef ffsll
#define ffs(x) usual_ffs(x)
#define ffsl(x) usual_ffsl(x)
#define ffsll(x) usual_ffsll(x)

#if _COMPILER_GNUC(4,0) || __has_builtin(__builtin_ffsll)
#define _USUAL_FFS_(sfx, type) \
	return __builtin_ffs ## sfx((unsigned type)(x))
#else
#define _USUAL_FFS_(sfx, type) \
	unsigned int bit; \
	unsigned type u = x; \
	if (!x) return 0; \
	/* count from smallest bit, assuming small values */ \
	for (bit = 1; !(u & 1); bit++) u >>= 1; \
	return bit
#endif

/** Find first (lowest) set bit, 1-based ofs, 0 if arg == 0 */
static inline int ffs(int x)
{
	_USUAL_FFS_(, int);
}

/** Find first (lowest) set bit, 1-based ofs, 0 if arg == 0 */
static inline int ffsl(long x)
{
	_USUAL_FFS_(l, long);
}

/** Find first (lowest) set bit, 1-based ofs, 0 if arg == 0 */
static inline int ffsll(long long x)
{
	_USUAL_FFS_(ll, long long);
}

#undef _USUAL_FFS_

/*
 * Multiply and check overflow.
 */

#define _USUAL_MUL_SAFE_(type, max)	\
	type unsafe = (type)(1) << (sizeof(type) * 8/2); /* sqrt(max+1) */ \
	if (a < unsafe && b < unsafe)	\
		goto safe;		\
	if (!a || !b)			\
		goto safe;		\
	if ((max / a) >= b)		\
		goto safe;		\
	return false;			\
   safe:				\
	*res_p = a * b;			\
	return true;

/** Multiply with overflow check for 'unsigned int' */
static inline bool safe_mul_uint(unsigned int *res_p, unsigned int a, unsigned int b)
{
	_USUAL_MUL_SAFE_(unsigned int, UINT_MAX);
}

/** Multiply with overflow check for 'unsigned long' */
static inline bool safe_mul_ulong(unsigned long *res_p, unsigned long a, unsigned long b)
{
	_USUAL_MUL_SAFE_(unsigned long, ULONG_MAX);
}

/** Multiply with overflow check for 'uint8_t' */
static inline bool safe_mul_uint8(uint8_t *res_p, uint8_t a, uint8_t b)
{
	_USUAL_MUL_SAFE_(uint8_t, UINT8_MAX);
}

/** Multiply with overflow check for 'uint16_t' */
static inline bool safe_mul_uint16(uint16_t *res_p, uint16_t a, uint16_t b)
{
	_USUAL_MUL_SAFE_(uint16_t, UINT16_MAX);
}

/** Multiply with overflow check for 'uint32_t' */
static inline bool safe_mul_uint32(uint32_t *res_p, uint32_t a, uint32_t b)
{
	_USUAL_MUL_SAFE_(uint32_t, UINT32_MAX);
}

/** Multiply with overflow check for 'uint64_t' */
static inline bool safe_mul_uint64(uint64_t *res_p, uint64_t a, uint64_t b)
{
	_USUAL_MUL_SAFE_(uint64_t, UINT64_MAX);
}

/** Multiply with overflow check for 'size_t' */
static inline bool safe_mul_size(size_t *res_p, size_t a, size_t b)
{
	_USUAL_MUL_SAFE_(size_t, SIZE_MAX);
}

#undef _USUAL_MUL_SAFE_

#endif
