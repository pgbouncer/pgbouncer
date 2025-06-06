/*
 * Pseudo-random bytes.
 *
 * Copyright (c) 2015  Marko Kreen
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

#include <usual/psrandom.h>

#include <usual/crypto/csrandom.h>
#include <usual/endian.h>

/*  Written in 2014 by Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

/* This is the fastest generator passing BigCrush without
   systematic failures, but due to the relatively short period it is
   acceptable only for applications with a mild amount of parallelism;
   otherwise, use a xorshift1024* generator.

   The state must be seeded so that it is not everywhere zero. If you have
   a nonzero 64-bit seed, we suggest to pass it twice through
   MurmurHash3's avalanching function. */

static inline uint64_t xorshift128plus_core(uint64_t a, uint64_t b, uint64_t *sb)
{
	b ^= b << 23;
	b ^= a ^ (b >> 17) ^ (a >> 26);
	*sb = b;
	return a + b;
}

/*
 * End-user APIs for 128-bit and 1024-bit states.
 */

/* 128-bit state.  Period: 2**128 - 1 */
uint64_t xorshift128plus(uint64_t *s0, uint64_t *s1)
{
	/* swap s0 and s1, calculate new s1 */
	uint64_t a = *s1, b = *s0;
	*s0 = a;
	return xorshift128plus_core(a, b, s1);
}

#define XS1K_STATE	16
#define XS1K_MASK	(XS1K_STATE - 1)

/* 1024-bit state.  Period: 2**1024 - 1 */
uint64_t xorshift1024plus(uint64_t state[XS1K_STATE], unsigned int counter)
{
	uint64_t *s0 = &state[counter & XS1K_MASK];
	uint64_t *s1 = &state[(counter + 1) & XS1K_MASK];
	return xorshift128plus_core(*s0, *s1, s1);
}

/*
 * csrandom()-style API on top that.
 */

static uint64_t ps_state[XS1K_STATE];
static uint32_t ps_init, ps_counter, ps_cache;

static void ps_initial_seed(void)
{
	csrandom_bytes(ps_state, sizeof ps_state);
	ps_init = 1;
}

void pseudo_random_seed(uint64_t a, uint64_t b)
{
	uint64_t X1 = 123456789, X2 = 987654321;
	int i;

	/* xorshift does not like all-zero value */
	if (a + X1)
		a += X1;
	if (b + X2)
		b += X2;

	/* fill all state */
	for (i = XS1K_STATE - 1; i >= 0; i--)
		ps_state[i] = xorshift128plus(&a, &b);

	ps_init = 1;
	ps_counter = 0;
}

uint32_t pseudo_random(void)
{
	uint64_t val;

	if (!ps_init)
		ps_initial_seed();

	if (ps_init == 2) {
		ps_init = 1;
		return ps_cache;
	}

	val = xorshift1024plus(ps_state, ps_counter++);
	ps_cache = val >> 32;
	ps_init = 2;
	return val;
}

void pseudo_random_bytes(void *dst, size_t count)
{
	uint32_t val;
	uint8_t *p = dst;

	while (count >= 4) {
		val = pseudo_random();
		le32enc(p, val);
		count -= 4;
		p += 4;
	}
	if (count > 0) {
		for (val = pseudo_random(); count > 0; count--) {
			*p++ = val;
			val >>= 8;
		}
	}
}

uint32_t pseudo_random_range(uint32_t upper_bound)
{
	uint32_t mod, lim, val;

	if (upper_bound <= 1)
		return 0;

	/* 2**32 % x == (2**32 - x) % x */
	mod = -upper_bound % upper_bound;

	/* wait for value in range [0 .. 2**32-mod) */
	lim = -mod;

	/* loop until good value appears */
	while (1) {
		val = pseudo_random();
		if (val < lim || lim == 0)
			return val % upper_bound;
	}
}
