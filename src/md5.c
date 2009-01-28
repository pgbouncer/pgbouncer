/*
 * MD5 implementation based on RFC1321.
 * 
 * Copyright (c) 2008 Marko Kreen, Skype Technologies OÜ
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

#include "system.h"
#include "md5.h"

/*
 * Support functions.
 */

#define bufpos(ctx) ((ctx)->nbytes & (MD5_BLOCK_LENGTH - 1))

static inline uint32_t rol(uint32_t v, int s)
{
	return (v << s) | (v >> (32 - s));
}

static inline void swap_words(uint32_t *w, int n)
{
#ifdef WORDS_BIGENDIAN
	for (; n > 0; w++, n--) {
		uint32_t v = rol(*w, 16);
		*w = ((v >> 8) & 0x00FF00FF) | ((v << 8) & 0xFF00FF00);
	}
#endif
}

static inline void put_word(uint8_t *dst, uint32_t val)
{
#ifdef WORDS_BIGENDIAN
	dst[0] = val;
	dst[1] = val >> 8;
	dst[2] = val >> 16;
	dst[3] = val >> 24;
#else
	memcpy(dst, &val, 4);
#endif
}

/*
 * MD5 core.
 */

#define F(X,Y,Z) ((X & Y) | ((~X) & Z))
#define G(X,Y,Z) ((X & Z) | (Y & (~Z)))
#define H(X,Y,Z) (X ^ Y ^ Z)
#define I(X,Y,Z) (Y ^ (X | (~Z)))

#define OP(fn, a, b, c, d, k, s, T_i) \
	a = b + rol(a + fn(b, c, d) + X[k] + T_i, s)

static void md5_mix(struct md5_ctx *ctx, const uint32_t *X)
{
	uint32_t a, b, c, d;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;

	/* Round 1. */
	OP(F, a, b, c, d, 0, 7, 0xd76aa478);
	OP(F, d, a, b, c, 1, 12, 0xe8c7b756);
	OP(F, c, d, a, b, 2, 17, 0x242070db);
	OP(F, b, c, d, a, 3, 22, 0xc1bdceee);
	OP(F, a, b, c, d, 4, 7, 0xf57c0faf);
	OP(F, d, a, b, c, 5, 12, 0x4787c62a);
	OP(F, c, d, a, b, 6, 17, 0xa8304613);
	OP(F, b, c, d, a, 7, 22, 0xfd469501);
	OP(F, a, b, c, d, 8, 7, 0x698098d8);
	OP(F, d, a, b, c, 9, 12, 0x8b44f7af);
	OP(F, c, d, a, b, 10, 17, 0xffff5bb1);
	OP(F, b, c, d, a, 11, 22, 0x895cd7be);
	OP(F, a, b, c, d, 12, 7, 0x6b901122);
	OP(F, d, a, b, c, 13, 12, 0xfd987193);
	OP(F, c, d, a, b, 14, 17, 0xa679438e);
	OP(F, b, c, d, a, 15, 22, 0x49b40821);

	/* Round 2. */
	OP(G, a, b, c, d, 1, 5, 0xf61e2562);
	OP(G, d, a, b, c, 6, 9, 0xc040b340);
	OP(G, c, d, a, b, 11, 14, 0x265e5a51);
	OP(G, b, c, d, a, 0, 20, 0xe9b6c7aa);
	OP(G, a, b, c, d, 5, 5, 0xd62f105d);
	OP(G, d, a, b, c, 10, 9, 0x02441453);
	OP(G, c, d, a, b, 15, 14, 0xd8a1e681);
	OP(G, b, c, d, a, 4, 20, 0xe7d3fbc8);
	OP(G, a, b, c, d, 9, 5, 0x21e1cde6);
	OP(G, d, a, b, c, 14, 9, 0xc33707d6);
	OP(G, c, d, a, b, 3, 14, 0xf4d50d87);
	OP(G, b, c, d, a, 8, 20, 0x455a14ed);
	OP(G, a, b, c, d, 13, 5, 0xa9e3e905);
	OP(G, d, a, b, c, 2, 9, 0xfcefa3f8);
	OP(G, c, d, a, b, 7, 14, 0x676f02d9);
	OP(G, b, c, d, a, 12, 20, 0x8d2a4c8a);

	/* Round 3. */
	OP(H, a, b, c, d, 5, 4, 0xfffa3942);
	OP(H, d, a, b, c, 8, 11, 0x8771f681);
	OP(H, c, d, a, b, 11, 16, 0x6d9d6122);
	OP(H, b, c, d, a, 14, 23, 0xfde5380c);
	OP(H, a, b, c, d, 1, 4, 0xa4beea44);
	OP(H, d, a, b, c, 4, 11, 0x4bdecfa9);
	OP(H, c, d, a, b, 7, 16, 0xf6bb4b60);
	OP(H, b, c, d, a, 10, 23, 0xbebfbc70);
	OP(H, a, b, c, d, 13, 4, 0x289b7ec6);
	OP(H, d, a, b, c, 0, 11, 0xeaa127fa);
	OP(H, c, d, a, b, 3, 16, 0xd4ef3085);
	OP(H, b, c, d, a, 6, 23, 0x04881d05);
	OP(H, a, b, c, d, 9, 4, 0xd9d4d039);
	OP(H, d, a, b, c, 12, 11, 0xe6db99e5);
	OP(H, c, d, a, b, 15, 16, 0x1fa27cf8);
	OP(H, b, c, d, a, 2, 23, 0xc4ac5665);

	/* Round 4. */
	OP(I, a, b, c, d, 0, 6, 0xf4292244);
	OP(I, d, a, b, c, 7, 10, 0x432aff97);
	OP(I, c, d, a, b, 14, 15, 0xab9423a7);
	OP(I, b, c, d, a, 5, 21, 0xfc93a039);
	OP(I, a, b, c, d, 12, 6, 0x655b59c3);
	OP(I, d, a, b, c, 3, 10, 0x8f0ccc92);
	OP(I, c, d, a, b, 10, 15, 0xffeff47d);
	OP(I, b, c, d, a, 1, 21, 0x85845dd1);
	OP(I, a, b, c, d, 8, 6, 0x6fa87e4f);
	OP(I, d, a, b, c, 15, 10, 0xfe2ce6e0);
	OP(I, c, d, a, b, 6, 15, 0xa3014314);
	OP(I, b, c, d, a, 13, 21, 0x4e0811a1);
	OP(I, a, b, c, d, 4, 6, 0xf7537e82);
	OP(I, d, a, b, c, 11, 10, 0xbd3af235);
	OP(I, c, d, a, b, 2, 15, 0x2ad7d2bb);
	OP(I, b, c, d, a, 9, 21, 0xeb86d391);

	ctx->a += a;
	ctx->b += b;
	ctx->c += c;
	ctx->d += d;
}

/*
 * Public API.
 */

void md5_reset(struct md5_ctx *ctx)
{
	ctx->nbytes = 0;
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;
}

void md5_update(struct md5_ctx *ctx, const void *data, unsigned int len)
{
	unsigned int n;
	const uint8_t *ptr = data;
	uint8_t *buf = (uint8_t *)ctx->buf;

	while (len > 0) {
		n = MD5_BLOCK_LENGTH - bufpos(ctx);
		if (n > len)
			n = len;
		memcpy(buf + bufpos(ctx), ptr, n);
		ptr += n;
		len -= n;
		ctx->nbytes += n;
		if (bufpos(ctx) == 0) {
			swap_words(ctx->buf, 16);
			md5_mix(ctx, ctx->buf);
		}
	}
}

void md5_final(uint8_t *dst, struct md5_ctx *ctx)
{
	static const uint8_t padding[MD5_BLOCK_LENGTH] = { 0x80 };
	uint64_t final_len = ctx->nbytes * 8;
	int pad_len, pos = bufpos(ctx);

	/* add padding */
	pad_len = MD5_BLOCK_LENGTH - 8 - pos;
	if (pad_len <= 0)
		pad_len += MD5_BLOCK_LENGTH;
	md5_update(ctx, padding, pad_len);

	/* add length directly */
	swap_words(ctx->buf, 14);
	ctx->buf[14] = final_len;
	ctx->buf[15] = final_len >> 32;

	/* final result */
	md5_mix(ctx, ctx->buf);
	put_word(dst, ctx->a);
	put_word(dst + 4, ctx->b);
	put_word(dst + 8, ctx->c);
	put_word(dst + 12, ctx->d);
}

