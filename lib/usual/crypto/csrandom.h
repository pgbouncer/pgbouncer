/*
 * Cryptographically Secure Randomness.
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
 * Cryptographically Secure Randomness.
 */

#ifndef _USUAL_CRYPTO_CSRANDOM_H_
#define _USUAL_CRYPTO_CSRANDOM_H_

#include <usual/base.h>

/**
 * Return random uint32_t.
 */
uint32_t csrandom(void);

/**
 * Return unsigned integer in range.
 */
uint32_t csrandom_range(uint32_t upper_bound);

/**
 * Fill buffer with random bytes.
 */
void csrandom_bytes(void *buf, size_t nbytes);

#endif
