/*
 * SHA2-512 implementation based on FIPS180-2.
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

#include <usual/crypto/sha512.h>
#include <usual/crypto/digest.h>

#include <usual/endian.h>
#include <usual/bits.h>

/* repeat with increasing offset */
#define R4(R, t) R(t+0); R(t+1); R(t+2); R(t+3)
#define R16(R, t) R4(R, t+0); R4(R, t+4); R4(R, t+8); R4(R, t+12)
#define R64(R, t) R16(R, t+0); R16(R, t+16); R16(R, t+32); R16(R, t+48);

#define bufpos(ctx) ((ctx)->nbytes & (SHA512_BLOCK_SIZE - 1))

/*
 * initial values
 */

static const uint64_t H384[8] = {
	UINT64_C(0xcbbb9d5dc1059ed8), UINT64_C(0x629a292a367cd507), UINT64_C(0x9159015a3070dd17),
	UINT64_C(0x152fecd8f70e5939), UINT64_C(0x67332667ffc00b31), UINT64_C(0x8eb44a8768581511),
	UINT64_C(0xdb0c2e0d64f98fa7), UINT64_C(0x47b5481dbefa4fa4),
};

static const uint64_t H512[8] = {
	UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b), UINT64_C(0x3c6ef372fe94f82b),
	UINT64_C(0xa54ff53a5f1d36f1), UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
	UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179),
};

/*
 * constants for mixing
 */

static const uint64_t K[80] = {
	UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd), UINT64_C(0xb5c0fbcfec4d3b2f),
	UINT64_C(0xe9b5dba58189dbbc), UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
	UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118), UINT64_C(0xd807aa98a3030242),
	UINT64_C(0x12835b0145706fbe), UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
	UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1), UINT64_C(0x9bdc06a725c71235),
	UINT64_C(0xc19bf174cf692694), UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
	UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65), UINT64_C(0x2de92c6f592b0275),
	UINT64_C(0x4a7484aa6ea6e483), UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
	UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210), UINT64_C(0xb00327c898fb213f),
	UINT64_C(0xbf597fc7beef0ee4), UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
	UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70), UINT64_C(0x27b70a8546d22ffc),
	UINT64_C(0x2e1b21385c26c926), UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
	UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8), UINT64_C(0x81c2c92e47edaee6),
	UINT64_C(0x92722c851482353b), UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
	UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30), UINT64_C(0xd192e819d6ef5218),
	UINT64_C(0xd69906245565a910), UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
	UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53), UINT64_C(0x2748774cdf8eeb99),
	UINT64_C(0x34b0bcb5e19b48a8), UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
	UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3), UINT64_C(0x748f82ee5defb2fc),
	UINT64_C(0x78a5636f43172f60), UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
	UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9), UINT64_C(0xbef9a3f7b2c67915),
	UINT64_C(0xc67178f2e372532b), UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
	UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178), UINT64_C(0x06f067aa72176fba),
	UINT64_C(0x0a637dc5a2c898a6), UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
	UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493), UINT64_C(0x3c9ebe0a15c9bebc),
	UINT64_C(0x431d67c49c100d4c), UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
	UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

/*
 * mixing
 */

#define CH(x,y,z)  ((x & y) ^ ((~x) & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

#define E0(x) (ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39))
#define E1(x) (ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41))
#define O0(x) (ror64(x,  1) ^ ror64(x,  8) ^ (x >> 7))
#define O1(x) (ror64(x, 19) ^ ror64(x, 61) ^ (x >> 6))

#define W(n)	(ctx->buf.words[(n) & 15])
#define setW(n,v) W(n) = (v)

#define SHA512_ROUND(_t) do { \
	uint64_t tmp1, tmp2, t = (_t); \
	if (t >= 16) { \
		setW(t, O1(W(t - 2)) + W(t - 7) + O0(W(t - 15)) + W(t - 16)); \
	} else { \
		/* convert endianess on first go */ \
		setW(t, be64toh(W(t))); \
	} \
	tmp1 = h + E1(e) + CH(e,f,g) + K[k_pos++] + W(t); \
	tmp2 = E0(a) + MAJ(a,b,c); \
	h = g; g = f; f = e; e = d + tmp1; d = c; c = b; b = a; a = tmp1 + tmp2; \
} while (0)

/*
 * actual core
 */

static void sha512_core(struct sha512_ctx *ctx)
{
	uint64_t *state = ctx->state;
	uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
	unsigned k_pos = 0;

	R16(SHA512_ROUND, 0);
	while (k_pos < 80) {
		R16(SHA512_ROUND, 16);
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

/*
 * Public API for SHA512.
 */

void sha512_reset(struct sha512_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->state, H512, sizeof(H512));
}

void sha512_update(struct sha512_ctx *ctx, const void *data, unsigned int len)
{
	unsigned int n;
	const uint8_t *src = data;
	uint8_t *dst = ctx->buf.raw;

	while (len > 0) {
		n = SHA512_BLOCK_SIZE - bufpos(ctx);
		if (n > len)
			n = len;

		memcpy(dst + bufpos(ctx), src, n);
		src += n;
		len -= n;
		ctx->nbytes += n;

		if (bufpos(ctx) == 0)
			sha512_core(ctx);
	}
}

void sha512_final(struct sha512_ctx *ctx, uint8_t *dst)
{
	static const uint8_t padding[SHA512_BLOCK_SIZE] = { 0x80 };
	uint64_t nbits = ctx->nbytes * 8;
	int i, pad_len;

	/* add padding */
	pad_len = SHA512_BLOCK_SIZE - 16 - bufpos(ctx);
	if (pad_len <= 0)
		pad_len += SHA512_BLOCK_SIZE;
	sha512_update(ctx, padding, pad_len);

	/* add length */
	ctx->buf.words[14] = 0;
	ctx->buf.words[15] = htobe64(nbits);

	/* final result */
	sha512_core(ctx);
	for (i = 0; i < SHA512_DIGEST_LENGTH / 8; i++)
		be64enc(dst + i*8, ctx->state[i]);
}

/*
 * Public API for SHA384.
 */

void sha384_reset(struct sha512_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->state, H384, sizeof(H384));
}

void sha384_update(struct sha512_ctx *ctx, const void *data, unsigned int len)
{
	sha512_update(ctx, data, len);
}

void sha384_final(struct sha512_ctx *ctx, uint8_t *dst)
{
	uint8_t buf[SHA512_DIGEST_LENGTH];
	sha512_final(ctx, buf);
	memcpy(dst, buf, SHA384_DIGEST_LENGTH);
	memset(buf, 0, sizeof(buf));
}

/*
 * DigestInfo
 */

const struct DigestInfo *digest_SHA384(void)
{
	static const struct DigestInfo info = {
		(DigestInitFunc *)sha384_reset,
		(DigestUpdateFunc *)sha384_update,
		(DigestFinalFunc *)sha384_final,
		sizeof(struct sha512_ctx),
		SHA384_DIGEST_LENGTH,
		SHA384_BLOCK_SIZE
	};
	return &info;
}

const struct DigestInfo *digest_SHA512(void)
{
	static const struct DigestInfo info = {
		(DigestInitFunc *)sha512_reset,
		(DigestUpdateFunc *)sha512_update,
		(DigestFinalFunc *)sha512_final,
		sizeof(struct sha512_ctx),
		SHA512_DIGEST_LENGTH,
		SHA512_BLOCK_SIZE
	};
	return &info;
}
