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

/**
 * Pseudo-random number generator for non-cryptographic purposes.
 *
 * By default it's seeded with csrandom so returns unpredictable
 * values (but not cryptographically stong).  But when
 * pseudo_random_seed() is used, all following values
 * are determined completely by seed.
 */

#ifndef _USUAL_PSRANDOM_H_
#define _USUAL_PSRANDOM_H_

#include <usual/base.h>

/**
 * Return value with uniform probability over whole 32-bit range.
 */
uint32_t pseudo_random(void);

/**
 * Return with with uniform probability over specific range.
 */
uint32_t pseudo_random_range(uint32_t upper_bound);

/**
 * Fill buffer with random bytes.
 */
void pseudo_random_bytes(void *dst, size_t count);

/**
 * Set 128-bit seed.  Following values will be
 * fully deterministic based on seed.
 */
void pseudo_random_seed(uint64_t a, uint64_t b);

/* 128-bit state.  Period: 2**128 - 1 */
uint64_t xorshift128plus(uint64_t *s0, uint64_t *s1);

/* 1024-bit state.  Period: 2**1024 - 1 */
uint64_t xorshift1024plus(uint64_t state[16], unsigned int counter);

#endif
