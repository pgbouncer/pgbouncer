/*
 * PRNG based on Keccak.
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
 * Implements PRNG mode for Keccak sponge function.
 */

#ifndef _USUAL_CRYPTO_KECCAK_PRNG_H_
#define _USUAL_CRYPTO_KECCAK_PRNG_H_

#include <usual/crypto/keccak.h>

/**
 * State structure.
 */
struct KeccakPRNG {
	struct KeccakContext ctx;
	bool extracting;
	bool have_data;
};

/**
 * Setup Keccak with specified capacity.
 *
 * @param prng		State structure to be initialized.
 * @param capacity	Keccak capacity in bits.
 * @return		False if invalid capacity, true otherwise.
 */
bool keccak_prng_init(struct KeccakPRNG *prng, int capacity);

/**
 * Merge entropy data into state.
 */
void keccak_prng_add_data(struct KeccakPRNG *prng, const void *data, size_t len);

/**
 * Extract PRNG bytes from state.
 *
 * @return True, if extraction was successful.  False if state has not been initialzed with keccak_prng_add_data().
 */
bool keccak_prng_extract(struct KeccakPRNG *prng, void *data, size_t len);

#endif
