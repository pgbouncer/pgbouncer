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

/**
 * @file
 *
 * Common API for cryptographic digests.
 */

#ifndef _USUAL_CRYPTO_DIGEST_H_
#define _USUAL_CRYPTO_DIGEST_H_

#include <usual/cxalloc.h>

typedef void (DigestInitFunc)(void *ctx);
typedef void (DigestUpdateFunc)(void *ctx, const void *, unsigned);
typedef void (DigestFinalFunc)(void *ctx, uint8_t *);

/**
 * Algoright info.
 */
struct DigestInfo {
	DigestInitFunc *init;
	DigestUpdateFunc *update;
	DigestFinalFunc *final;
	short state_len;
	short result_len;
	short block_len;
};

/**
 * Algoright instance.
 */
struct DigestContext;

/**
 * Allocate and initialize new algorithm instance.
 */
struct DigestContext *digest_new(const struct DigestInfo *impl, CxMem *cx);

/** Hash more data */
void digest_update(struct DigestContext *ctx, const void *data, size_t len);

/**
 * Get final result.
 *
 * To re-use same instance, digest_reset() must be called first.
 */
void digest_final(struct DigestContext *ctx, uint8_t *res);

/**
 * Prepares instance for new data.
 */
void digest_reset(struct DigestContext *ctx);

/**
 * Free instance.
 */
void digest_free(struct DigestContext *ctx);

/**
 * Hash function block length in bytes.
 */
unsigned digest_block_len(struct DigestContext *ctx);

/**
 * Hash function result length in bytes.
 */
unsigned digest_result_len(struct DigestContext *ctx);

/*
 * Declare algorithm info's here instead per-also headers
 * to avoid unnecessary dependencies.
 */

/** MD5 message digest */
const struct DigestInfo *digest_MD5(void);

/** SHA1 message digest */
const struct DigestInfo *digest_SHA1(void);

/** SHA224 message digest */
const struct DigestInfo *digest_SHA224(void);

/** SHA256 message digest */
const struct DigestInfo *digest_SHA256(void);

/** SHA384 message digest */
const struct DigestInfo *digest_SHA384(void);

/** SHA512 message digest */
const struct DigestInfo *digest_SHA512(void);

/** SHA3-224 message digest */
const struct DigestInfo *digest_SHA3_224(void);

/** SHA3-256 message digest */
const struct DigestInfo *digest_SHA3_256(void);

/** SHA3-384 message digest */
const struct DigestInfo *digest_SHA3_384(void);

/** SHA3-512 message digest */
const struct DigestInfo *digest_SHA3_512(void);

/** SHAKE128 in regular digest mode */
const struct DigestInfo *digest_SHAKE128(void);

/** SHAKE256 in regular digest mode */
const struct DigestInfo *digest_SHAKE256(void);

#endif
