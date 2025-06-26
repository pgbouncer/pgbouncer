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

/**
 * @file
 *
 * SHA3 variants of Keccak.
 *
 * SHA3-X are fixed-length hashes, SHAKE is variable-length.
 */

#ifndef _USUAL_CRYPTO_SHA3_H_
#define _USUAL_CRYPTO_SHA3_H_

#include <usual/crypto/keccak.h>

/** Keccak capacity area for SHA3-224, in bits */
#define SHA3_224_CAPACITY       448
/** Keccak capacity area for SHA3-256, in bits */
#define SHA3_256_CAPACITY       512
/** Keccak capacity area for SHA3-384, in bits */
#define SHA3_384_CAPACITY       768
/** Keccak capacity area for SHA3-512, in bits */
#define SHA3_512_CAPACITY       1024
/** Keccak capacity area for SHAKE128, in bits */
#define SHAKE128_CAPACITY       256
/** Keccak capacity area for SHAKE256, in bits */
#define SHAKE256_CAPACITY       512

/** Result length of SHA3-224, in bytes */
#define SHA3_224_DIGEST_LENGTH  (224/8)
/** Result length of SHA3-256, in bytes */
#define SHA3_256_DIGEST_LENGTH  (256/8)
/** Result length of SHA3-384, in bytes */
#define SHA3_384_DIGEST_LENGTH  (384/8)
/** Result length of SHA3-512, in bytes */
#define SHA3_512_DIGEST_LENGTH  (512/8)
/** Result length of SHAKE128, in bytes */
#define SHAKE128_DIGEST_LENGTH  (256/8)
/** Result length of SHAKE256, in bytes */
#define SHAKE256_DIGEST_LENGTH  (512/8)

/** Block size of SHA3-224, in bytes */
#define SHA3_224_BLOCK_SIZE     ((1600 - SHA3_224_CAPACITY) / 8)
/** Block size of SHA3-256, in bytes */
#define SHA3_256_BLOCK_SIZE     ((1600 - SHA3_256_CAPACITY) / 8)
/** Block size of SHA3-384, in bytes */
#define SHA3_384_BLOCK_SIZE     ((1600 - SHA3_384_CAPACITY) / 8)
/** Block size of SHA3-512, in bytes */
#define SHA3_512_BLOCK_SIZE     ((1600 - SHA3_512_CAPACITY) / 8)
/** Block size of SHAKE128, in bytes */
#define SHAKE128_BLOCK_SIZE     ((1600 - SHAKE128_CAPACITY) / 8)
/** Block size of SHAKE256, in bytes */
#define SHAKE256_BLOCK_SIZE     ((1600 - SHAKE256_CAPACITY) / 8)

/**
 * State structure.
 */
struct SHA3Context {
	struct KeccakContext kctx;
	bool padded;
	uint8_t pad;
	unsigned int obytes;
};

/** Initialize state for SHA3-224 */
void sha3_224_reset(struct SHA3Context *ctx);

/** Initialize state for SHA3-256 */
void sha3_256_reset(struct SHA3Context *ctx);

/** Initialize state for SHA3-384 */
void sha3_384_reset(struct SHA3Context *ctx);

/** Initialize state for SHA3-512 */
void sha3_512_reset(struct SHA3Context *ctx);

/** Process data, update state */
void sha3_update(struct SHA3Context *ctx, const void *ptr, unsigned len);

/** Calculate final result */
void sha3_final(struct SHA3Context *ctx, void *dst);

/** Initialize state for SHAKE128 */
void shake128_reset(struct SHA3Context *ctx);

/** Initialize state for SHAKE256 */
void shake256_reset(struct SHA3Context *ctx);

/** Process data, update state */
void shake_update(struct SHA3Context *ctx, const void *ptr, unsigned len);

/** Output variable amount of result data */
void shake_extract(struct SHA3Context *ctx, void *dst, unsigned count);

#endif
