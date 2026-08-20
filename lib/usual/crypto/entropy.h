/*
 * Load entropy from kernel.
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
 * Load entropy from OS.
 */

#ifndef _USUAL_CRYPTO_ENTROPY_H_
#define _USUAL_CRYPTO_ENTROPY_H_

#include <usual/base.h>

#ifndef HAVE_GETENTROPY
#define getentropy(dst, len) usual_getentropy(dst, len)

/**
 * Fetch entropy from OS kernel.
 */
int getentropy(void *dst, size_t len);

#endif /* !HAVE_GETENTROPY */
#endif /* _USUAL_CRYPTO_ENTROPY_H_ */
