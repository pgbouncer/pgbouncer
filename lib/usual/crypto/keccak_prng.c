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

#include <usual/crypto/keccak_prng.h>

bool keccak_prng_init(struct KeccakPRNG *prng, int capacity)
{
	if (!keccak_init(&prng->ctx, capacity))
		return false;
	prng->extracting = false;
	prng->have_data = false;
	return true;
}

void keccak_prng_add_data(struct KeccakPRNG *prng, const void *data, size_t len)
{
	if (prng->extracting) {
		keccak_rewind(&prng->ctx);
		prng->extracting = false;
	}

	keccak_absorb(&prng->ctx, data, len);

	if (!prng->have_data && len > 0)
		prng->have_data = true;
}

bool keccak_prng_extract(struct KeccakPRNG *prng, void *data, size_t len)
{
	if (!prng->have_data)
		return false;
	if (!prng->extracting) {
		keccak_pad(&prng->ctx, "\x01", 1);
		prng->extracting = true;
	}
	keccak_squeeze(&prng->ctx, data, len);
	return true;
}
