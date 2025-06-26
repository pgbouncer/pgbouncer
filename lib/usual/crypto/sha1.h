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

/**
 * @file
 *
 * SHA1 implementation.
 */

#ifndef _USUAL_CRYPTO_SHA1_H_
#define _USUAL_CRYPTO_SHA1_H_

#include <usual/base.h>

/** Block length for SHA1 */
#define SHA1_BLOCK_SIZE         64

/** Result length for SHA1 */
#define SHA1_DIGEST_LENGTH      20


/** SHA1 state */
struct sha1_ctx {
	uint64_t nbytes;
	uint32_t a, b, c, d, e;
	uint32_t buf[SHA1_BLOCK_SIZE / 4];
};

/** Clean state */
void sha1_reset(struct sha1_ctx *ctx);

/** Update state with more data */
void sha1_update(struct sha1_ctx *ctx, const void *data, unsigned int len);

/** Get final result */
void sha1_final(struct sha1_ctx *ctx, uint8_t *dst);

#endif
