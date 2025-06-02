/*
 * SHA2-256 implementation based on FIPS180-2.
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

#include <usual/crypto/sha256.h>
#include <usual/crypto/digest.h>

#include <usual/endian.h>
#include <usual/bits.h>

/* repeat with increasing offset */
#define R4(R, t) R(t+0); R(t+1); R(t+2); R(t+3)
#define R16(R, t) R4(R, t+0); R4(R, t+4); R4(R, t+8); R4(R, t+12)
#define R64(R, t) R16(R, t+0); R16(R, t+16); R16(R, t+32); R16(R, t+48);

#define bufpos(ctx) ((ctx)->nbytes & (SHA256_BLOCK_SIZE - 1))

/*
 * initial values
 */

static const uint32_t H224[8] = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

static const uint32_t H256[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/*
 * constants for mixing
 */

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/*
 * mixing
 */

#define CH(x,y,z)  ((x & y) ^ ((~x) & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

#define E0(x) (ror32(x,  2) ^ ror32(x, 13) ^ ror32(x, 22))
#define E1(x) (ror32(x,  6) ^ ror32(x, 11) ^ ror32(x, 25))
#define O0(x) (ror32(x,  7) ^ ror32(x, 18) ^ (x >> 3))
#define O1(x) (ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10))

#define W(n)	(ctx->buf.words[(n) & 15])
#define setW(n,v) W(n) = (v)

#define SHA256_ROUND(_t) do { \
	uint32_t tmp1, tmp2, t = (_t); \
	if (t >= 16) { \
		setW(t, O1(W(t - 2)) + W(t - 7) + O0(W(t - 15)) + W(t - 16)); \
	} else { \
		/* convert endianess on first go */ \
		setW(t, be32toh(W(t))); \
	} \
	tmp1 = h + E1(e) + CH(e,f,g) + K[k_pos++] + W(t); \
	tmp2 = E0(a) + MAJ(a,b,c); \
	h = g; g = f; f = e; e = d + tmp1; d = c; c = b; b = a; a = tmp1 + tmp2; \
} while (0)

/*
 * actual core
 */

static void sha256_core(struct sha256_ctx *ctx)
{
	uint32_t *state = ctx->state;
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
	unsigned k_pos = 0;

	R16(SHA256_ROUND, 0);
	while (k_pos < 64) {
		R16(SHA256_ROUND, 16);
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
 * Public API for SHA256.
 */

void sha256_reset(struct sha256_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->state, H256, sizeof(H256));
}

void sha256_update(struct sha256_ctx *ctx, const void *data, unsigned int len)
{
	unsigned int n;
	const uint8_t *src = data;
	uint8_t *dst = ctx->buf.raw;

	while (len > 0) {
		n = SHA256_BLOCK_SIZE - bufpos(ctx);
		if (n > len)
			n = len;

		memcpy(dst + bufpos(ctx), src, n);
		src += n;
		len -= n;
		ctx->nbytes += n;

		if (bufpos(ctx) == 0)
			sha256_core(ctx);
	}
}

void sha256_final(struct sha256_ctx *ctx, uint8_t *dst)
{
	static const uint8_t padding[SHA256_BLOCK_SIZE] = { 0x80 };
	uint64_t nbits = ctx->nbytes * 8;
	int pad_len, pos = bufpos(ctx);
	int i;

	/* add padding */
	pad_len = SHA256_BLOCK_SIZE - 8 - pos;
	if (pad_len <= 0)
		pad_len += SHA256_BLOCK_SIZE;
	sha256_update(ctx, padding, pad_len);

	/* add length */
	ctx->buf.words[14] = htobe32(nbits >> 32);
	ctx->buf.words[15] = htobe32(nbits);

	/* final result */
	sha256_core(ctx);
	for (i = 0; i < SHA256_DIGEST_LENGTH / 4; i++)
		be32enc(dst + i*4, ctx->state[i]);
}

/*
 * Public API for SHA224.
 */

void sha224_reset(struct sha256_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->state, H224, sizeof(H224));
}

void sha224_update(struct sha256_ctx *ctx, const void *data, unsigned int len)
{
	sha256_update(ctx, data, len);
}

void sha224_final(struct sha256_ctx *ctx, uint8_t *dst)
{
	uint8_t buf[SHA256_DIGEST_LENGTH];
	sha256_final(ctx, buf);
	memcpy(dst, buf, SHA224_DIGEST_LENGTH);
	memset(buf, 0, sizeof(buf));
}

/*
 * DigestInfo
 */

const struct DigestInfo *digest_SHA224(void)
{
	static const struct DigestInfo info = {
		(DigestInitFunc *)sha224_reset,
		(DigestUpdateFunc *)sha224_update,
		(DigestFinalFunc *)sha224_final,
		sizeof(struct sha256_ctx),
		SHA224_DIGEST_LENGTH,
		SHA224_BLOCK_SIZE
	};
	return &info;
}

const struct DigestInfo *digest_SHA256(void)
{
	static const struct DigestInfo info = {
		(DigestInitFunc *)sha256_reset,
		(DigestUpdateFunc *)sha256_update,
		(DigestFinalFunc *)sha256_final,
		sizeof(struct sha256_ctx),
		SHA256_DIGEST_LENGTH,
		SHA256_BLOCK_SIZE
	};
	return &info;
}
