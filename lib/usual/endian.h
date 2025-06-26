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

/**
 * @file
 *
 * Endianess conversion, convert integers to bytes.
 */

#ifndef _USUAL_ENDIAN_H_
#define _USUAL_ENDIAN_H_

#include <usual/base.h>
#include <string.h>

/*
 * Need to include OS headers even if unused, so our
 * definitions stay in use.
 */

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#endif

/*
 * Is unaligned access to integers OK?  Does not apply to floats.
 *
 * OK: x86, amd64, arm >= v6, ppc
 */
#if defined(__amd64__) || defined(__i386__) || defined(__ppc__) || defined(__ppc64__) \
	|| defined(__ARM_FEATURE_UNALIGNED) \
	|| defined(_M_IX86) || defined(_M_X64) || defined(_M_PPC) \
	|| (defined(_M_ARM) && _M_ARM >= 6)
#define WORDS_UNALIGNED_ACCESS_OK
#endif

/*
 * Ignore OS defines, as they may define only some subset of functions.
 *
 * Instead try to use compiler builtins.
 */

#undef bswap16
#undef bswap32
#undef bswap64

#undef htobe16
#undef htobe32
#undef htobe64
#undef htole16
#undef htole32
#undef htole64
#undef be16toh
#undef be32toh
#undef be64toh
#undef le16toh
#undef le32toh
#undef le64toh

#undef be16dec
#undef be32dec
#undef be64dec
#undef le16dec
#undef le32dec
#undef le64dec
#undef h16dec
#undef h32dec
#undef h64dec

#undef be16enc
#undef be32enc
#undef be64enc
#undef le16enc
#undef le32enc
#undef le64enc
#undef h16enc
#undef h32enc
#undef h64enc

/*
 * Redefine to avoid conflicts.
 */

#define bswap16(x) usual_bswap16(x)
#define bswap32(x) usual_bswap32(x)
#define bswap64(x) usual_bswap64(x)

#define be16dec(p) usual_be16dec(p)
#define be32dec(p) usual_be32dec(p)
#define be64dec(p) usual_be64dec(p)
#define le16dec(p) usual_le16dec(p)
#define le32dec(p) usual_le32dec(p)
#define le64dec(p) usual_le64dec(p)
#define h16dec(p) usual_h16dec(p)
#define h32dec(p) usual_h32dec(p)
#define h64dec(p) usual_h64dec(p)

#define be16enc(p, x) usual_be16enc(p, x)
#define be32enc(p, x) usual_be32enc(p, x)
#define be64enc(p, x) usual_be64enc(p, x)
#define le16enc(p, x) usual_le16enc(p, x)
#define le32enc(p, x) usual_le32enc(p, x)
#define le64enc(p, x) usual_le64enc(p, x)
#define h16enc(p, x) usual_h16enc(p, x)
#define h32enc(p, x) usual_h32enc(p, x)
#define h64enc(p, x) usual_h64enc(p, x)

/**
 * @name  Always swap.
 *
 * @{
 */

/** Swap 16-bit int */
static inline uint16_t bswap16(uint16_t x)
{
#if _COMPILER_GNUC(4, 8) || __has_builtin(__builtin_bswap16)
	return __builtin_bswap16(x);
#else
	return (x << 8) | (x >> 8);
#endif
}

/** Swap 32-bit int */
static inline uint32_t bswap32(uint32_t x)
{
#if _COMPILER_GNUC(4, 3) || __has_builtin(__builtin_bswap32)
	return __builtin_bswap32(x);
#else
	x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF);
	return (x << 16) | (x >> 16);
#endif
}

/** Swap 64-bit int */
static inline uint64_t bswap64(uint64_t x)
{
#if _COMPILER_GNUC(4, 3) || __has_builtin(__builtin_bswap64)
	return __builtin_bswap64(x);
#else
	return ((uint64_t)bswap32(x) << 32) | bswap32(x >> 32);
#endif
}

/**
 * @}
 *
 * @name Convert host-endian int to BE/LE.
 *
 * @{
 */

#ifdef WORDS_BIGENDIAN

/** Convert native 16-bit int to big-endian */
#define htobe16(x)      ((uint16_t)(x))
/** Convert native 32-bit int to big-endian */
#define htobe32(x)      ((uint32_t)(x))
/** Convert native 64-bit int to big-endian */
#define htobe64(x)      ((uint64_t)(x))

/** Convert native 16-bit int to little-endian */
#define htole16(x)      bswap16(x)
/** Convert native 32-bit int to little-endian */
#define htole32(x)      bswap32(x)
/** Convert native 64-bit int to little-endian */
#define htole64(x)      bswap64(x)

/** Convert big-endian 16-bit int to host-endian */
#define be16toh(x)      ((uint16_t)(x))
/** Convert big-endian 32-bit int to host-endian */
#define be32toh(x)      ((uint32_t)(x))
/** Convert big-endian 64-bit int to host-endian */
#define be64toh(x)      ((uint64_t)(x))

/** Convert little-endian 16-bit int to host-endian */
#define le16toh(x)      bswap16(x)
/** Convert little-endian 32-bit int to host-endian */
#define le32toh(x)      bswap32(x)
/** Convert little-endian 64-bit int to host-endian */
#define le64toh(x)      bswap64(x)

#else /* !WORDS_BIGENDIAN */

/** Convert native 16-bit int to big-endian */
#define htobe16(x)      bswap16(x)
/** Convert native 32-bit int to big-endian */
#define htobe32(x)      bswap32(x)
/** Convert native 64-bit int to big-endian */
#define htobe64(x)      bswap64(x)
/** Convert native 16-bit int to little-endian */
#define htole16(x)      ((uint16_t)(x))
/** Convert native 32-bit int to little-endian */
#define htole32(x)      ((uint32_t)(x))
/** Convert native 64-bit int to little-endian */
#define htole64(x)      ((uint64_t)(x))

/** Convert big-endian 16-bit int to host-endian */
#define be16toh(x)      bswap16(x)
/** Convert big-endian 32-bit int to host-endian */
#define be32toh(x)      bswap32(x)
/** Convert big-endian 64-bit int to host-endian */
#define be64toh(x)      bswap64(x)

/** Convert little-endian 64-bit int to host-endian */
#define le16toh(x)      ((uint16_t)(x))
/** Convert little-endian 64-bit int to host-endian */
#define le32toh(x)      ((uint32_t)(x))
/** Convert little-endian 64-bit int to host-endian */
#define le64toh(x)      ((uint64_t)(x))

#endif

/**
 * @}
 *
 * @name Read integer values from memory and convert to host format.
 *
 * @{
 */

/** Read big-endian 16-bit int from memory */
static inline uint16_t be16dec(const void *p)
{
	uint16_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return htobe16(tmp);
}

/** Read big-endian 32-bit int from memory */
static inline uint32_t be32dec(const void *p)
{
	uint32_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return htobe32(tmp);
}

/** Read big-endian 64-bit int from memory */
static inline uint64_t be64dec(const void *p)
{
	uint64_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return htobe64(tmp);
}

/** Read little-endian 16-bit int from memory */
static inline uint16_t le16dec(const void *p)
{
	uint16_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return htole16(tmp);
}

/** Read little-endian 32-bit int from memory */
static inline uint32_t le32dec(const void *p)
{
	uint32_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return htole32(tmp);
}

/** Read little-endian 64-bit int from memory */
static inline uint64_t le64dec(const void *p)
{
	uint64_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return htole64(tmp);
}

/** Read host-endian 16-bit int from memory */
static inline uint16_t h16dec(const void *p)
{
	uint16_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return tmp;
}

/** Read host-endian 32-bit int from memory */
static inline uint32_t h32dec(const void *p)
{
	uint32_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return tmp;
}

/** Read host-endian 64-bit int from memory */
static inline uint64_t h64dec(const void *p)
{
	uint64_t tmp;
	memcpy(&tmp, p, sizeof(tmp));
	return tmp;
}

/**
 * @}
 *
 * @name Convert host value to LE/BE and write to memory
 *
 * @{
 */

/** Write big-endian 16-bit int to memory */
static inline void be16enc(void *p, uint16_t x)
{
	uint16_t tmp = htobe16(x);
	memcpy(p, &tmp, sizeof(tmp));
}

/** Write big-endian 32-bit int to memory */
static inline void be32enc(void *p, uint32_t x)
{
	uint32_t tmp = htobe32(x);
	memcpy(p, &tmp, sizeof(tmp));
}

/** Write big-endian 64-bit int to memory */
static inline void be64enc(void *p, uint64_t x)
{
	uint64_t tmp = htobe64(x);
	memcpy(p, &tmp, sizeof(tmp));
}

/** Write little-endian 16-bit int to memory */
static inline void le16enc(void *p, uint16_t x)
{
	uint16_t tmp = htole16(x);
	memcpy(p, &tmp, sizeof(tmp));
}

/** Write little-endian 32-bit int to memory */
static inline void le32enc(void *p, uint32_t x)
{
	uint32_t tmp = htole32(x);
	memcpy(p, &tmp, sizeof(tmp));
}

/** Write little-endian 64-bit int to memory */
static inline void le64enc(void *p, uint64_t x)
{
	uint64_t tmp = htole64(x);
	memcpy(p, &tmp, sizeof(tmp));
}

/** Write host-endian 16-bit int to memory */
static inline void h16enc(void *p, uint16_t x)
{
	memcpy(p, &x, sizeof(x));
}

/** Write host-endian 32-bit int to memory */
static inline void h32enc(void *p, uint32_t x)
{
	memcpy(p, &x, sizeof(x));
}

/** Write host-endian 64-bit int to memory */
static inline void h64enc(void *p, uint64_t x)
{
	memcpy(p, &x, sizeof(x));
}

/** @} */


#endif /* _USUAL_ENDIAN_H_ */
