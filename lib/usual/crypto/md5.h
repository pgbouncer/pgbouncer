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

/**
 * @file
 *
 * MD5 cryptographic hash.
 */

#ifndef _USUAL_CRYPTO_MD5_H_
#define _USUAL_CRYPTO_MD5_H_

#include <usual/base.h>

/** Block length for MD5 */
#define MD5_BLOCK_LENGTH	64

/** Result length for MD5 */
#define MD5_DIGEST_LENGTH	16

/** MD5 state */
struct md5_ctx {
	uint64_t nbytes;
	uint32_t a, b, c, d;
	uint32_t buf[16];
};

/** Clean state */
void md5_reset(struct md5_ctx *ctx);

/** Update state with more data */
void md5_update(struct md5_ctx *ctx, const void *data, unsigned int len);

/** Get final result */
void md5_final(struct md5_ctx *ctx, uint8_t *dst);

#endif
