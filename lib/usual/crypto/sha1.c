/*
 * SHA1 implementation based on RFC3174.
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

#include <usual/crypto/sha1.h>

#include <usual/crypto/digest.h>
#include <usual/endian.h>
#include <usual/bits.h>

#define bufpos(ctx) ((ctx)->nbytes & (SHA1_BLOCK_SIZE - 1))

/*
 * SHA1 core.
 */

#define W(n)		(buf[(n) & 15])
#define setW(n, val)	W(n) = val

/* base SHA1 operation */
#define SHA1OP(_t, fn, K) do { \
	uint32_t tmp, t = (_t); \
	if (t >= 16) { \
		tmp = W(t - 3) ^ W(t - 8) ^ W(t - 14) ^ W(t - 16); \
		setW(t, rol32(tmp, 1)); \
	} else { \
		/* convert endianess on first go */ \
		setW(t, be32toh(W(t))); \
	} \
	tmp = rol32(a, 5) + fn(b, c, d) + e + W(t) + K; \
	e = d; d = c; c = rol32(b, 30); b = a; a = tmp; \
} while (0)

/* mix functions */
#define F0(b, c, d) (d ^ (b & (c ^ d)))
#define F1(b, c, d) (b ^ c ^ d)
#define F2(b, c, d) ((b & c) | (b & d) | (c & d))
#define F3(b, c, d) (b ^ c ^ d)

/* operation details for each round */
#define SHA1R0(t) SHA1OP(t, F0, 0x5a827999)
#define SHA1R1(t) SHA1OP(t, F1, 0x6ed9eba1)
#define SHA1R2(t) SHA1OP(t, F2, 0x8f1bbcdc)
#define SHA1R3(t) SHA1OP(t, F3, 0xca62c1d6)

/* repeat with increasing offset */
#define R4(R, t) R(t+0); R(t+1); R(t+2); R(t+3)
#define R16(R, t) R4(R, t+0); R4(R, t+4); R4(R, t+8); R4(R, t+12)
#define R20(R, t) R16(R, t+0); R4(R, t+16)

static void sha1_core(struct sha1_ctx * ctx, uint32_t *buf)
{
	uint32_t a, b, c, d, e;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;
	e = ctx->e;

	R20(SHA1R0, 0);
	R20(SHA1R1, 20);
	R20(SHA1R2, 40);
	R20(SHA1R3, 60);

	ctx->a += a;
	ctx->b += b;
	ctx->c += c;
	ctx->d += d;
	ctx->e += e;
}

/*
 * Public API.
 */

void sha1_reset(struct sha1_ctx *ctx)
{
	ctx->nbytes = 0;
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;
	ctx->e = 0xc3d2e1f0;
}

void sha1_update(struct sha1_ctx *ctx, const void *data, unsigned int len)
{
	unsigned int n;
	const uint8_t *src = data;
	uint8_t *dst = (uint8_t *)ctx->buf;

	while (len > 0) {
		n = SHA1_BLOCK_SIZE - bufpos(ctx);
		if (n > len)
			n = len;

		memcpy(dst + bufpos(ctx), src, n);
		src += n;
		len -= n;
		ctx->nbytes += n;

		if (bufpos(ctx) == 0)
			sha1_core(ctx, ctx->buf);
	}
}

void sha1_final(struct sha1_ctx *ctx, uint8_t *dst)
{
	static const uint8_t padding[SHA1_BLOCK_SIZE] = { 0x80 };
	uint64_t nbits = ctx->nbytes * 8;
	int pad_len, pos = bufpos(ctx);

	/* add padding */
	pad_len = SHA1_BLOCK_SIZE - 8 - pos;
	if (pad_len <= 0)
		pad_len += SHA1_BLOCK_SIZE;
	sha1_update(ctx, padding, pad_len);

	/* add length */
	ctx->buf[14] = htobe32(nbits >> 32);
	ctx->buf[15] = htobe32(nbits);

	/* final result */
	sha1_core(ctx, ctx->buf);
	be32enc(dst + 0*4, ctx->a);
	be32enc(dst + 1*4, ctx->b);
	be32enc(dst + 2*4, ctx->c);
	be32enc(dst + 3*4, ctx->d);
	be32enc(dst + 4*4, ctx->e);
}

/*
 * DigestInfo
 */

static const struct DigestInfo sha1_info = {
	(DigestInitFunc *)sha1_reset,
	(DigestUpdateFunc *)sha1_update,
	(DigestFinalFunc *)sha1_final,
	sizeof(struct sha1_ctx),
	SHA1_DIGEST_LENGTH,
	SHA1_BLOCK_SIZE
};

const struct DigestInfo *digest_SHA1(void)
{
	return &sha1_info;
}
