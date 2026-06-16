/*
 * byte map
 *
 * Copyright (c) 2014  Marko Kreen
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
 * Map 256 byte values to bit or int.
 */
#ifndef _USUAL_BYTEMAP_H_
#define _USUAL_BYTEMAP_H_

#define BITMAP256_SHIFT 5
#define BITMAP256_MASK  ((1 << BITMAP256_SHIFT) - 1)

/**
 * Bitmap of 256 bits.
 */
struct Bitmap256 {
	uint32_t bmap[256 / 32];
};

/**
 * Clear bitmap.
 */
static inline void bitmap256_init(struct Bitmap256 *bmap)
{
	memset(bmap, 0, sizeof(*bmap));
}

/**
 * Set one bit.
 */
static inline void bitmap256_set(struct Bitmap256 *bmap, uint8_t byte)
{
	bmap->bmap[byte >> BITMAP256_SHIFT] |= 1 << (byte & BITMAP256_MASK);
}

/**
 * Check if bit is set.
 */
static inline bool bitmap256_is_set(const struct Bitmap256 *bmap, uint8_t byte)
{
	return bmap->bmap[byte >> BITMAP256_SHIFT] & (1 << (byte & BITMAP256_MASK));
}

/*
 * Declare const value of bytemap
 */

/**
 * Use C preprocessor to fill Bitmap256.
 *
 * Usage:
 * @code
 * #define check_isdigit(c) ((c) >= '0' && (c) <= '9')
 * static const struct Bitmap256 map_isdigit = BITMAP256_CONST(check_isdigit);
 * @endcode
 */
#define BITMAP256_CONST(check) {{ \
			_BMAP256_V32(check, 0), _BMAP256_V32(check, 32), _BMAP256_V32(check, 64), _BMAP256_V32(check, 96), \
			_BMAP256_V32(check, 128), _BMAP256_V32(check, 160), _BMAP256_V32(check, 192), _BMAP256_V32(check, 224) }}
#define _BMAP256_V32(ck, p) \
	_BMAP256_V8(ck, (p) + 0) | _BMAP256_V8(ck, (p) + 8) | _BMAP256_V8(ck, (p) + 16) | _BMAP256_V8(ck, (p) + 24)
#define _BMAP256_V8(ck, p) \
	_BMAP256_BIT(ck, (p) + 0) | _BMAP256_BIT(ck, (p) + 1) | _BMAP256_BIT(ck, (p) + 2) | _BMAP256_BIT(ck, (p) + 3) | \
	_BMAP256_BIT(ck, (p) + 4) | _BMAP256_BIT(ck, (p) + 5) | _BMAP256_BIT(ck, (p) + 6) | _BMAP256_BIT(ck, (p) + 7)
#define _BMAP256_BIT(ck, p) (ck(p) ? (1 << ((p)&BMAP256_MASK)) : 0)

/**
 * Use C preprocessor to generate array of 256 values.
 *
 * Usage:
 * @code
 * #define my_hexval(c) (((c) >= '0' && (c) <= '9') ? ((c) - '0') : ( \
 *                       ((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) : ( \
 *                       ((c) >= 'a' && (c) <= 'f') ? ((c) - 'a' + 10) : -1 )))
 * static const int map_hexval[] = INTMAP256_CONST(my_hexval);
 * @endcode
 */
#define INTMAP256_CONST(map_value) { _INTMAP_V128(map_value, 0), _INTMAP_V128(map_value, 128) }
#define _INTMAP_V128(mf, n) _INTMAP_V32(mf, (n) + 0*32), _INTMAP_V32(mf, (n) + 1*32), _INTMAP_V32(mf, (n) + 2*32), _INTMAP_V32(mf, (n) + 3*32)
#define _INTMAP_V32(mf, n) _INTMAP_V8(mf, (n) + 0*8), _INTMAP_V8(mf, (n) + 1*8), _INTMAP_V8(mf, (n) + 2*8), _INTMAP_V8(mf, (n) + 3*8)
#define _INTMAP_V8(mf, n) mf((n) + 0), mf((n) + 1), mf((n) + 2), mf((n) + 3), mf((n) + 4), mf((n) + 5), mf((n) + 6), mf((n) + 7)


#endif
