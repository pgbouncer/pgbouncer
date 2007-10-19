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
 * A version of Bob Jenkins' lookup3.c hash.
 *
 * It is supposed to give same results as hashlittle() on little-endian
 * and hashbig() on big-endian machines.
 */

#include <sys/types.h>

#include "hash.h"

/* rotate uint32 */
#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

/*
 * Disallow going over given data length.
 * It is safe, if word boundary is not crossed,
 * should be bit faster, although I have not noticed yet.
 */
#define STRICT_LENGTH 1

/*
 * Bob Jenkins hash mixing functions for 3 32bit integers.
 */

#define main_mix(a, b, c) do { \
	a -= c;  a ^= rot(c, 4);  c += b; \
	b -= a;  b ^= rot(a, 6);  a += c; \
	c -= b;  c ^= rot(b, 8);  b += a; \
	a -= c;  a ^= rot(c,16);  c += b; \
	b -= a;  b ^= rot(a,19);  a += c; \
	c -= b;  c ^= rot(b, 4);  b += a; \
} while (0)

#define final_mix(a, b, c) do { \
	c ^= b; c -= rot(b,14); \
	a ^= c; a -= rot(c,11); \
	b ^= a; b -= rot(a,25); \
	c ^= b; c -= rot(b,16); \
	a ^= c; a -= rot(c, 4); \
	b ^= a; b -= rot(a,14); \
	c ^= b; c -= rot(b,24); \
} while (0)

/*
 * Macros for fetching uint32_t from memory.
 *
 * Depending on alignment, it can be done with
 * uint32, uint16 or uint8.
 */

/* load uint from proper pointer and shift t oposition */
#define GET(ptr, pos, sft) (((uint32_t)((ptr)[pos])) << sft)

#ifdef WORDS_BIGENDIAN

#define LOAD_BYTES(v, p8, n) do { \
	switch (n) { \
	case 4: v += GET(p8, 0, 24) | GET(p8, 1, 16) | GET(p8, 2, 8) | GET(p8, 3, 0); break; \
	case 3: v += GET(p8, 0, 24) | GET(p8, 1, 16) | GET(p8, 2, 8); break; \
	case 2: v += GET(p8, 0, 24) | GET(p8, 1, 16); break; \
	case 1: v += GET(p8, 0, 24); break; \
	} \
} while (0)

#define LOAD_SHORTS(v, p16, n) do { \
	switch (n) { \
	case 4: v += GET(p16, 0, 16) | GET(p16, 1, 0); break; \
	case 3: v += GET(p16, 0, 16) |(GET(p16, 1, 0) & 0xFF00); break; \
	case 2: v += GET(p16, 0, 16); break; \
	case 1: v += GET(p16, 0, 16) & 0xFF00; break; \
	} \
} while (0)

#define LOAD_INTS(v, p32, n) do { \
	switch (n) { \
	case 4: v += GET(p32, 0, 0); break; \
	case 3: v += GET(p32, 0, 0) & 0xFFFFFF00; break; \
	case 2: v += GET(p32, 0, 0) & 0xFFFF0000; break; \
	case 1: v += GET(p32, 0, 0) & 0xFF000000; break; \
	} \
} while (0)

#else /* LITTLE-ENDIAN */

#define LOAD_BYTES(v, p8, n) do { \
	switch (n) { \
	case 4: v += GET(p8, 0, 0) | GET(p8, 1, 8) | GET(p8, 2, 16) | GET(p8, 3, 24); break; \
	case 3: v += GET(p8, 0, 0) | GET(p8, 1, 8) | GET(p8, 2, 16); break; \
	case 2: v += GET(p8, 0, 0) | GET(p8, 1, 8); break; \
	case 1: v += GET(p8, 0, 0); break; \
	} \
} while (0)

#define LOAD_SHORTS(v, p16, n) do { \
	switch (n) { \
	case 4: v += GET(p16, 0, 0) | GET(p16, 1, 16); break; \
	case 3: v += GET(p16, 0, 0) |(GET(p16, 1, 16) & 0x00FF); break; \
	case 2: v += GET(p16, 0, 0); break; \
	case 1: v += GET(p16, 0, 0) & 0x00FF; break; \
	} \
} while (0)

#define LOAD_INTS(v, p32, n) do { \
	switch (n) { \
	case 4: v += GET(p32, 0, 0); break; \
	case 3: v += GET(p32, 0, 0) & 0x00FFFFFF; break; \
	case 2: v += GET(p32, 0, 0) & 0x0000FFFF; break; \
	case 1: v += GET(p32, 0, 0) & 0x000000FF; break; \
	} \
} while (0)

#endif /* LITTLE ENDIAN */

/*
 * combined fetching, also increases data pointer.
 */
#define LOAD(v, data, n, unit) do { \
	if (n < 4 && unit > 1 && STRICT_LENGTH) { \
		LOAD_BYTES(v, ((uint8_t *)data), n); \
	} else { \
		switch (unit) { \
		case 4: LOAD_INTS(v, data, n); break; \
		case 2: LOAD_SHORTS(v, data, n); break; \
		case 1: LOAD_BYTES(v, data, n); break; \
		} \
	} \
	data += n/unit; \
} while (0)

/*
 * common main loop
 */
#define main_loop(data, len, a, b, c, unit) do { \
	while (len > 12) { \
		LOAD(a, data, 4, unit); \
		LOAD(b, data, 4, unit); \
		LOAD(c, data, 4, unit); \
		main_mix(a, b, c); \
		len -= 12; \
	} \
} while (0)

/*
 * fetch last 12 bytes into variables and mix them
 */
#define final_loop(data, len, a, b, c, unit) do { \
	switch (len) { \
	case 12: LOAD(a, data, 4, unit); LOAD(b, data, 4, unit); LOAD(c, data, 4, unit); break; \
	case 11: LOAD(a, data, 4, unit); LOAD(b, data, 4, unit); LOAD(c, data, 3, unit); break; \
	case 10: LOAD(a, data, 4, unit); LOAD(b, data, 4, unit); LOAD(c, data, 2, unit); break; \
	case  9: LOAD(a, data, 4, unit); LOAD(b, data, 4, unit); LOAD(c, data, 1, unit); break; \
	case  8: LOAD(a, data, 4, unit); LOAD(b, data, 4, unit); break; \
	case  7: LOAD(a, data, 4, unit); LOAD(b, data, 3, unit); break; \
	case  6: LOAD(a, data, 4, unit); LOAD(b, data, 2, unit); break; \
	case  5: LOAD(a, data, 4, unit); LOAD(b, data, 1, unit); break; \
	case  4: LOAD(a, data, 4, unit); break; \
	case  3: LOAD(a, data, 3, unit); break; \
	case  2: LOAD(a, data, 2, unit); break; \
	case  1: LOAD(a, data, 1, unit); break; \
	case  0: return c; \
	} \
	final_mix(a, b, c); \
} while (0)

/*
 * common function body
 */
#define body(data, len, unit_type, unit) do { \
	uint32_t a, b, c; \
	const unit_type *ptr = data; \
	a = b = c = 0xdeadbeef + len; \
	main_loop(ptr, len, a, b, c, unit); \
	final_loop(ptr, len, a, b, c, unit); \
	return c; \
} while (0)

/*
 * actual function
 */
unsigned lookup_hash(const void *data, unsigned len)
{
	if (((long)data & 3) == 0)
		body(data, len, uint32_t, 4);
	else if (((long)data & 1) == 0)
		body(data, len, uint16_t, 2);
	else
		body(data, len, uint8_t, 1);
}

