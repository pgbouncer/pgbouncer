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

/*
 * Based on: chacha-ref.c version 20080118 / D. J. Bernstein / Public domain.
 */

#include <usual/crypto/chacha.h>

#include <usual/endian.h>
#include <usual/bits.h>

#define CHACHA_ROUNDS 20

#define QUARTERROUND(in, out, a, b, c, d) \
	do { \
		out[a] = in[a] + in[b];    out[d] = rol32(in[d] ^ out[a], 16); \
		out[c] = in[c] + out[d];   out[b] = rol32(in[b] ^ out[c], 12); \
		out[a] = out[a] + out[b];  out[d] = rol32(out[d] ^ out[a], 8); \
		out[c] = out[c] + out[d];  out[b] = rol32(out[b] ^ out[c], 7); \
	} while (0)

#define OUTPUT(a,b,c,d) \
	do { \
		output[a] = htole32(x[a] + input[a]); \
		output[b] = htole32(x[b] + input[b]); \
		output[c] = htole32(x[c] + input[c]); \
		output[d] = htole32(x[d] + input[d]); \
	} while (0)

/* mix full state.  needs 2 call sites to avoid inlining  */
static void chacha_mix(struct ChaCha *ctx)
{
	const uint32_t *input = ctx->state;
	uint32_t *output = ctx->u.output32;
	int i;
	uint32_t x[16];

	/* first "column" round */
	QUARTERROUND(input, x, 0, 4, 8, 12);
	QUARTERROUND(input, x, 1, 5, 9, 13);
	QUARTERROUND(input, x, 2, 6, 10, 14);
	QUARTERROUND(input, x, 3, 7, 11, 15);

	for (i = 0; i < CHACHA_ROUNDS/2 - 1; i++) {
		/* "diagonal" round */
		QUARTERROUND(x, x, 0, 5, 10, 15);
		QUARTERROUND(x, x, 1, 6, 11, 12);
		QUARTERROUND(x, x, 2, 7, 8, 13);
		QUARTERROUND(x, x, 3, 4, 9, 14);

		/* "column" round */
		QUARTERROUND(x, x, 0, 4, 8, 12);
		QUARTERROUND(x, x, 1, 5, 9, 13);
		QUARTERROUND(x, x, 2, 6, 10, 14);
		QUARTERROUND(x, x, 3, 7, 11, 15);
	}

	/* last "diagonal" round */
	QUARTERROUND(x, x, 0, 5, 10, 15); OUTPUT(0, 5, 10, 15);
	QUARTERROUND(x, x, 1, 6, 11, 12); OUTPUT(1, 6, 11, 12);
	QUARTERROUND(x, x, 2, 7, 8, 13);  OUTPUT(2, 7, 8, 13);
	QUARTERROUND(x, x, 3, 4, 9, 14);  OUTPUT(3, 4, 9, 14);

	ctx->pos = 0;

	ctx->state[12]++;
	if (!ctx->state[12])
		ctx->state[13]++;
}

void chacha_set_key_256(struct ChaCha *ctx, const void *key)
{
	unsigned int i;

	memcpy(&ctx->state[0], "expand 32-byte k", 16);
	memcpy(&ctx->state[4], key, 32);
	for (i = 0; i < 12; i++)
		ctx->state[i] = le32toh(ctx->state[i]);

	ctx->pos = CHACHA_BLOCK_SIZE;
}

void chacha_set_key_128(struct ChaCha *ctx, const void *key)
{
	unsigned int i;

	memcpy(&ctx->state[0], "expand 16-byte k", 16);
	memcpy(&ctx->state[4], key, 16);
	memcpy(&ctx->state[8], key, 16);
	for (i = 0; i < 12; i++)
		ctx->state[i] = le32toh(ctx->state[i]);

	ctx->pos = CHACHA_BLOCK_SIZE;
}

void chacha_set_nonce(struct ChaCha *ctx, uint32_t counter_low, uint32_t counter_high, const void *iv)
{
	const uint8_t *_iv = iv;

	ctx->state[12] = counter_low;
	ctx->state[13] = counter_high;
	if (_iv) {
		ctx->state[14] = le32dec(_iv);
		ctx->state[15] = le32dec(_iv + 4);
	}

	ctx->pos = CHACHA_BLOCK_SIZE;
}

void chacha_keystream(struct ChaCha *ctx, void *stream, size_t bytes)
{
	unsigned int n, avail;
	const uint8_t *ks = ctx->u.output8;
	uint8_t *dst = stream;

	while (bytes > 0) {
		if (ctx->pos >= CHACHA_BLOCK_SIZE)
			chacha_mix(ctx);

		avail = CHACHA_BLOCK_SIZE - ctx->pos;
		n = (bytes > avail) ? avail : bytes;

		memcpy(dst, ks + ctx->pos, n);

		bytes -= n;
		dst += n;
		ctx->pos += n;
	}
}

void chacha_keystream_xor(struct ChaCha *ctx, const void *plain, void *encrypted, size_t bytes)
{
	unsigned int i, n, avail;
	const uint8_t *ks = ctx->u.output8;
	const uint8_t *src = plain;
	uint8_t *dst = encrypted;

	while (bytes > 0) {
		if (ctx->pos >= CHACHA_BLOCK_SIZE)
			chacha_mix(ctx);

		avail = CHACHA_BLOCK_SIZE - ctx->pos;
		n = (bytes > avail) ? avail : bytes;

		for (i = 0; i < n; i++)
			dst[i] = src[i] ^ ks[i];

		bytes -= n;
		dst += n;
		src += n;
		ctx->pos += n;
	}
}
