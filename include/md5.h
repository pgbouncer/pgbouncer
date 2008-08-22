/*
 * MD5 implementation based on RFC1321.
 * 
 * Copyright (c) 2008 Marko Kreen, Skype Technologies OÜ
 * 
 * Permission to use, copy, modify, and distribute this software for any
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

#ifndef __MD5_H__
#define __MD5_H__

#define MD5_BLOCK_LENGTH	64
#define MD5_DIGEST_LENGTH	16

struct md5_ctx {
	uint64_t nbytes;
	uint32_t a, b, c, d;
	uint32_t buf[16];
};

void md5_reset(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, const void *data, unsigned int len);
void md5_final(uint8_t *dst, struct md5_ctx *ctx);

#ifndef AVOID_MD5_COMPAT
typedef struct md5_ctx MD5_CTX;
#define MD5_Init(c) md5_reset(c)
#define MD5_Update(c, d, l) md5_update(c, d, l)
#define MD5_Final(d, c) md5_final(d, c)
#endif

#endif

