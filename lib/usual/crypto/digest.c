/*
 * Common API for cryptographic digests.
 *
 * Copyright (c) 2012  Marko Kreen
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

#include <usual/crypto/digest.h>

#include <string.h>

struct DigestContext {
	const struct DigestInfo *impl;
	CxMem *cx;
	uint64_t state[1];
};

struct DigestContext *digest_new(const struct DigestInfo *impl, CxMem *cx)
{
	struct DigestContext *ctx;
	unsigned alloc;

	alloc = offsetof(struct DigestContext, state) + impl->state_len;
	ctx = cx_alloc(cx, alloc);
	if (!ctx)
		return NULL;

	ctx->impl = impl;
	ctx->cx = cx;
	impl->init(ctx->state);
	return ctx;
}

void digest_update(struct DigestContext *ctx, const void *data, size_t len)
{
	ctx->impl->update(ctx->state, data, len);
}

void digest_final(struct DigestContext *ctx, uint8_t *res)
{
	ctx->impl->final(ctx->state, res);
}

void digest_reset(struct DigestContext *ctx)
{
	ctx->impl->init(ctx->state);
}

void digest_free(struct DigestContext *ctx)
{
	CxMem *cx = ctx->cx;
	unsigned alloc = offsetof(struct DigestContext, state) + ctx->impl->state_len;

	memset(ctx, 0, alloc);
	cx_free(cx, ctx);
}

unsigned digest_block_len(struct DigestContext *ctx)
{
	return ctx->impl->block_len;
}

unsigned digest_result_len(struct DigestContext *ctx)
{
	return ctx->impl->result_len;
}
