/*
 * Keccak implementation.
 *
 * Copyright (c) 2012 Marko Kreen
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

/** @file
 * Simple API to Keccak1600 permutation + sponge.
 */

#ifndef _USUAL_CRYPTO_KECCAK_H_
#define _USUAL_CRYPTO_KECCAK_H_

#include <usual/base.h>

/**
 * Keccak state structure for all modes.
 */
struct KeccakContext {
	/* 5*5*64 bit state */
	union {
		uint64_t state64[25];
		uint32_t state32[2*25];
	} u;
	uint32_t pos;		/* current byte position in buffer */
	uint32_t rbytes;	/* rate (= block size) in bytes */
};

/**
 * Set up state with specified capacity.
 *
 * Returns 1 if successful, 0 if invalid capacity.
 */
int keccak_init(struct KeccakContext *ctx, unsigned int capacity);

/**
 * Hash additional data.
 */
void keccak_absorb(struct KeccakContext *ctx, const void *data, size_t len);

/**
 * Extract bytes from state.
 */
void keccak_squeeze(struct KeccakContext *ctx, uint8_t *dst, size_t len);

/**
 * Extract bytes from state, XOR into data.
 */
void keccak_squeeze_xor(struct KeccakContext *ctx, uint8_t *dst, const void *src, size_t len);

/**
 * XOR data into state and return it.
 */
void keccak_encrypt(struct KeccakContext *ctx, uint8_t *dst, const void *src, size_t len);

/**
 * XOR state with data and return it.
 */
void keccak_decrypt(struct KeccakContext *ctx, uint8_t *dst, const void *src, size_t len);

/**
 * Hash pad suffix.
 */
void keccak_pad(struct KeccakContext *ctx, const void *data, size_t len);

/**
 * Move internal position to start of buffer.
 *
 * Useful for PRNG/duplex modes.
 */
void keccak_rewind(struct KeccakContext *ctx);

/**
 * Clear rate bits.
 */
void keccak_forget(struct KeccakContext *ctx);


#endif
