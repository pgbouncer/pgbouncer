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

/**
 * @file
 *
 * SHA256 and SHA224 cryptographic hashes.
 */

#ifndef _USUAL_CRYPTO_SHA256_H_
#define _USUAL_CRYPTO_SHA256_H_

#include <usual/base.h>

/** SHA224 block size in bytes */
#define SHA224_BLOCK_SIZE (16*4)

/** SHA256 block size in bytes */
#define SHA256_BLOCK_SIZE (16*4)

/** SHA224 result length in bytes */
#define SHA224_DIGEST_LENGTH (224/8)

/** SHA256 result length in bytes */
#define SHA256_DIGEST_LENGTH (256/8)

/**
 * State structure for both SHA256 and SHA224.
 */
struct sha256_ctx {
	union {
		uint32_t words[16];
		uint8_t raw[16 * 4];
	} buf;
	uint32_t state[8];
	uint64_t nbytes;
};

/** Initialize structure for SHA256 */
void sha256_reset(struct sha256_ctx *ctx);

/** Process more data */
void sha256_update(struct sha256_ctx *ctx, const void *data, unsigned int len);

/** Calculate final result */
void sha256_final(struct sha256_ctx *ctx, uint8_t *dst);

/** Initialize structure for SHA224 */
void sha224_reset(struct sha256_ctx *ctx);

/** Process more data */
void sha224_update(struct sha256_ctx *ctx, const void *data, unsigned int len);

/** Calculate final result */
void sha224_final(struct sha256_ctx *ctx, uint8_t *dst);

#endif
