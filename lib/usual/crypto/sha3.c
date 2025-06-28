/*
 * SHA3 implementation.
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

#include <usual/crypto/sha3.h>
#include <usual/crypto/digest.h>

#define PAD_SHA3        0x06
#define PAD_SHAKE       0x1f

void sha3_224_reset(struct SHA3Context *ctx)
{
	keccak_init(&ctx->kctx, SHA3_224_CAPACITY);
	ctx->padded = 0;
	ctx->obytes = SHA3_224_DIGEST_LENGTH;
	ctx->pad = PAD_SHA3;
}

void sha3_256_reset(struct SHA3Context *ctx)
{
	keccak_init(&ctx->kctx, SHA3_256_CAPACITY);
	ctx->padded = 0;
	ctx->obytes = SHA3_256_DIGEST_LENGTH;
	ctx->pad = PAD_SHA3;
}

void sha3_384_reset(struct SHA3Context *ctx)
{
	keccak_init(&ctx->kctx, SHA3_384_CAPACITY);
	ctx->padded = 0;
	ctx->obytes = SHA3_384_DIGEST_LENGTH;
	ctx->pad = PAD_SHA3;
}

void sha3_512_reset(struct SHA3Context *ctx)
{
	keccak_init(&ctx->kctx, SHA3_512_CAPACITY);
	ctx->padded = 0;
	ctx->obytes = SHA3_512_DIGEST_LENGTH;
	ctx->pad = PAD_SHA3;
}

void shake128_reset(struct SHA3Context *ctx)
{
	keccak_init(&ctx->kctx, SHAKE128_CAPACITY);
	ctx->padded = 0;
	ctx->obytes = SHAKE128_DIGEST_LENGTH;
	ctx->pad = PAD_SHAKE;
}

void shake256_reset(struct SHA3Context *ctx)
{
	keccak_init(&ctx->kctx, SHAKE256_CAPACITY);
	ctx->padded = 0;
	ctx->obytes = SHAKE256_DIGEST_LENGTH;
	ctx->pad = PAD_SHAKE;
}

void sha3_update(struct SHA3Context *ctx, const void *ptr, unsigned len)
{
	keccak_absorb(&ctx->kctx, ptr, len);
}

void sha3_final(struct SHA3Context *ctx, void *dst)
{
	if (!ctx->padded) {
		keccak_pad(&ctx->kctx, &ctx->pad, 1);
		ctx->padded = 1;
	}
	keccak_squeeze(&ctx->kctx, dst, ctx->obytes);
}

void shake_update(struct SHA3Context *ctx, const void *ptr, unsigned len)
{
	keccak_absorb(&ctx->kctx, ptr, len);
}

void shake_extract(struct SHA3Context *ctx, void *dst, unsigned count)
{
	if (!ctx->padded) {
		keccak_pad(&ctx->kctx, &ctx->pad, 1);
		ctx->padded = 1;
	}
	keccak_squeeze(&ctx->kctx, dst, count);
}

/*
 * DigestInfo
 */

static const struct DigestInfo sha3_224_info = {
	(DigestInitFunc *)sha3_224_reset,
	(DigestUpdateFunc *)sha3_update,
	(DigestFinalFunc *)sha3_final,
	sizeof(struct SHA3Context),
	SHA3_224_DIGEST_LENGTH,
	SHA3_224_BLOCK_SIZE
};

static const struct DigestInfo sha3_256_info = {
	(DigestInitFunc *)sha3_256_reset,
	(DigestUpdateFunc *)sha3_update,
	(DigestFinalFunc *)sha3_final,
	sizeof(struct SHA3Context),
	SHA3_256_DIGEST_LENGTH,
	SHA3_256_BLOCK_SIZE
};

static const struct DigestInfo sha3_384_info = {
	(DigestInitFunc *)sha3_384_reset,
	(DigestUpdateFunc *)sha3_update,
	(DigestFinalFunc *)sha3_final,
	sizeof(struct SHA3Context),
	SHA3_384_DIGEST_LENGTH,
	SHA3_384_BLOCK_SIZE
};

static const struct DigestInfo sha3_512_info = {
	(DigestInitFunc *)sha3_512_reset,
	(DigestUpdateFunc *)sha3_update,
	(DigestFinalFunc *)sha3_final,
	sizeof(struct SHA3Context),
	SHA3_512_DIGEST_LENGTH,
	SHA3_512_BLOCK_SIZE
};

static const struct DigestInfo shake128_info = {
	(DigestInitFunc *)shake128_reset,
	(DigestUpdateFunc *)sha3_update,
	(DigestFinalFunc *)sha3_final,
	sizeof(struct SHA3Context),
	SHAKE128_DIGEST_LENGTH,
	SHAKE128_BLOCK_SIZE
};

static const struct DigestInfo shake256_info = {
	(DigestInitFunc *)shake256_reset,
	(DigestUpdateFunc *)sha3_update,
	(DigestFinalFunc *)sha3_final,
	sizeof(struct SHA3Context),
	SHAKE256_DIGEST_LENGTH,
	SHAKE256_BLOCK_SIZE
};

const struct DigestInfo *digest_SHA3_224(void)
{
	return &sha3_224_info;
}

const struct DigestInfo *digest_SHA3_256(void)
{
	return &sha3_256_info;
}

const struct DigestInfo *digest_SHA3_384(void)
{
	return &sha3_384_info;
}

const struct DigestInfo *digest_SHA3_512(void)
{
	return &sha3_512_info;
}

const struct DigestInfo *digest_SHAKE128(void)
{
	return &shake128_info;
}

const struct DigestInfo *digest_SHAKE256(void)
{
	return &shake256_info;
}
