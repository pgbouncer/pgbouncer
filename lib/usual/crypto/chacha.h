/*
 * ChaCha cipher.
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
 * ChaCha cipher.
 */

#ifndef _CHACHA_CLEAN_H_
#define _CHACHA_CLEAN_H_

#include <usual/base.h>

#define CHACHA_KEY_SIZE		32
#define CHACHA_IV_SIZE		8
#define CHACHA_BLOCK_SIZE	64

/**
 * ChaCha state.
 */
struct ChaCha {
	uint32_t state[16];
	union {
		uint32_t output32[16];
		uint8_t output8[16*4];
	} u;
	unsigned int pos;
};

/**
 * Set 256-bit key.
 */
void chacha_set_key_256(struct ChaCha *ctx, const void *key);

/**
 * Set 128-bit key.
 */
void chacha_set_key_128(struct ChaCha *ctx, const void *key);

/**
 * Set 2x32-bit counter and 8-byte IV.
 */
void chacha_set_nonce(struct ChaCha *ctx, uint32_t counter_low, uint32_t counter_high, const void *iv);

/**
 * Extract plain keystream.
 */
void chacha_keystream(struct ChaCha *ctx, void *stream, size_t bytes);

/**
 * XOR data with keystream.
 */
void chacha_keystream_xor(struct ChaCha *ctx, const void *plain, void *encrypted, size_t bytes);

#endif
