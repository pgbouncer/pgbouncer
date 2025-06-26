/*
 * HMAC implementation based on OpenBSD
 *
 * Copyright (c) 2012  Daniel Farina
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
 * HMAC-SHA1 implementation (RFC2104).
 */

#ifndef _USUAL_CRYPTO_HMAC_H_
#define _USUAL_CRYPTO_HMAC_H_

#include <usual/crypto/digest.h>

/** HMAC Context */
struct HMAC;

/** Create context with key */
struct HMAC *hmac_new(const struct DigestInfo *impl,
		      const void *key, unsigned int key_len,
		      CxMem *cx);

/** Free context */
void hmac_free(struct HMAC *ctx);

/** Initialize context */
void hmac_reset(struct HMAC *ctx);

/** Hash more data */
void hmac_update(struct HMAC *ctx, const void *data, unsigned int len);

/** Get final result */
void hmac_final(struct HMAC *ctx, uint8_t *dst);

unsigned hmac_block_len(struct HMAC *ctx);
unsigned hmac_result_len(struct HMAC *ctx);

#endif /* _USUAL_HMAC_H_ */
