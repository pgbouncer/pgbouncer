/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007 Marko Kreen, Skype Technologies OÜ
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

/*
 * A simple version of Bob Jenkins' lookup3.c hash.
 *
 * It is supposed to give same results as hashlittle() on little-endian
 * and hashbig() on big-endian machines.
 *
 * Speed seems comparable to Jenkins' optimized version (~ -10%).
 * Actual difference varies as it depends on cpu/compiler/libc details.
 */

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"

/* rotate uint32 */
#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

/* mix 3 32-bit values reversibly */
#define mix(a, b, c) do { \
	a -= c;  a ^= rot(c, 4);  c += b; \
	b -= a;  b ^= rot(a, 6);  a += c; \
	c -= b;  c ^= rot(b, 8);  b += a; \
	a -= c;  a ^= rot(c,16);  c += b; \
	b -= a;  b ^= rot(a,19);  a += c; \
	c -= b;  c ^= rot(b, 4);  b += a; \
} while (0)

/* final mixing of 3 32-bit values (a,b,c) into c */
#define final(a, b, c) do { \
	c ^= b; c -= rot(b,14); \
	a ^= c; a -= rot(c,11); \
	b ^= a; b -= rot(a,25); \
	c ^= b; c -= rot(b,16); \
	a ^= c; a -= rot(c, 4); \
	b ^= a; b -= rot(a,14); \
	c ^= b; c -= rot(b,24); \
} while (0)

/* short version - let compiler worry about memory access */
uint32_t lookup3_hash(const void *data, size_t len)
{
	uint32_t a, b, c;
	uint32_t buf[3];
	const uint8_t *p = data;

	a = b = c = 0xdeadbeef + len;
	if (len == 0)
		goto done;

	while (len > 12) {
		memcpy(buf, p, 12);
		a += buf[0];
		b += buf[1];
		c += buf[2];
		mix(a, b, c);
		p += 12;
		len -= 12;
	}

	buf[0] = buf[1] = buf[2] = 0;
	memcpy(buf, p, len);
	a += buf[0];
	b += buf[1];
	c += buf[2];
	final(a, b, c);
done:
	return c;
}

