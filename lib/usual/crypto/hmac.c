/*
 * HMAC implementation based on OpenBSD hmac.c
 *
 * Copyright (c) 2012 Daniel Farina
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

#include <usual/crypto/hmac.h>

#include <string.h>


struct HMAC {
	struct DigestContext *hash;
	CxMem *cx;
	uint8_t *ipad;
	uint8_t *opad;
};

struct HMAC *hmac_new(const struct DigestInfo *impl,
		      const void *key, unsigned int key_len,
		      CxMem *cx)
{
	struct DigestContext *hash;
	struct HMAC *hmac;
	unsigned bs = impl->block_len;
	unsigned i;

	/* load hash */
	hash = digest_new(impl, cx);
	if (!hash)
		return NULL;

	/* struct setup */
	hmac = cx_alloc0(cx, sizeof(struct HMAC) + 2*bs);
	if (!hmac) {
		digest_free(hash);
		return NULL;
	}
	hmac->hash = hash;
	hmac->cx = cx;
	hmac->ipad = (uint8_t *)(hmac + 1);
	hmac->opad = hmac->ipad + bs;

	/* copy key to pads */
	if (key_len > bs) {
		digest_update(hash, key, key_len);
		digest_final(hash, hmac->ipad);
		digest_reset(hash);
		memcpy(hmac->opad, hmac->ipad, digest_result_len(hash));
	} else {
		memcpy(hmac->ipad, key, key_len);
		memcpy(hmac->opad, key, key_len);
	}

	/* calculate pads */
	for (i = 0; i < bs; i++) {
		hmac->ipad[i] ^= 0x36;
		hmac->opad[i] ^= 0x5c;
	}

	/* prepare for user data */
	digest_update(hmac->hash, hmac->ipad, bs);
	return hmac;
}

/* Free context */
void hmac_free(struct HMAC *ctx)
{
	digest_free(ctx->hash);
	cx_free(ctx->cx, ctx);
}

/* Clean HMAC state */
void hmac_reset(struct HMAC *ctx)
{
	unsigned bs = digest_block_len(ctx->hash);

	digest_reset(ctx->hash);
	digest_update(ctx->hash, ctx->ipad, bs);
}


/* Update HMAC state with more data */
void hmac_update(struct HMAC *ctx, const void *data, unsigned int len)
{
	digest_update(ctx->hash, data, len);
}


/* Get final HMAC result */
void hmac_final(struct HMAC *ctx, uint8_t *dst)
{
	unsigned bs = digest_block_len(ctx->hash);
	unsigned rs = digest_result_len(ctx->hash);

	digest_final(ctx->hash, dst);

	digest_reset(ctx->hash);
	digest_update(ctx->hash, ctx->opad, bs);
	digest_update(ctx->hash, dst, rs);
	digest_final(ctx->hash, dst);
}

unsigned hmac_block_len(struct HMAC *ctx)
{
	return digest_block_len(ctx->hash);
}

unsigned hmac_result_len(struct HMAC *ctx)
{
	return digest_result_len(ctx->hash);
}
