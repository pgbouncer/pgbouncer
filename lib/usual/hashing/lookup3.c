/*
 * The contents of this file are public domain.
 *
 * Based on: lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 */

/*
 * Compact version of Bob Jenkins' lookup3.c hash.
 */

#include <usual/hashing/lookup3.h>

#include <string.h>

#define rot(x, k) (((x)<<(k)) | ((x)>>(32-(k))))

#define mix(a, b, c) do { \
	a -= c;  a ^= rot(c, 4);  c += b; \
	b -= a;  b ^= rot(a, 6);  a += c; \
	c -= b;  c ^= rot(b, 8);  b += a; \
	a -= c;  a ^= rot(c,16);  c += b; \
	b -= a;  b ^= rot(a,19);  a += c; \
	c -= b;  c ^= rot(b, 4);  b += a; \
} while (0)

#define final(a, b, c) do { \
	c ^= b; c -= rot(b,14); \
	a ^= c; a -= rot(c,11); \
	b ^= a; b -= rot(a,25); \
	c ^= b; c -= rot(b,16); \
	a ^= c; a -= rot(c, 4); \
	b ^= a; b -= rot(a,14); \
	c ^= b; c -= rot(b,24); \
} while (0)

/* variable length copy of ~6 bytes, avoid call to libc */
static inline void simple_memcpy(void *dst_, const void *src_, size_t len)
{
	const uint8_t *src = src_;
	uint8_t *dst = dst_;
	while (len--)
		*dst++ = *src++;
}

uint64_t hash_lookup3(const void *data, size_t len)
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
	simple_memcpy(buf, p, len);
	a += buf[0];
	b += buf[1];
	c += buf[2];
	final(a, b, c);
done:
	return ((uint64_t)b << 32) | c;
}
