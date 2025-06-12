/*
 * Copyright (c) 2012  Marko Kreen
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

#include <usual/hashing/siphash.h>

#include <usual/crypto/csrandom.h>
#include <usual/endian.h>
#include <usual/bits.h>

#define SIP_ROUND1 \
    v0 += v1; v1 = rol64(v1, 13); v1 ^= v0; v0 = rol64(v0, 32);	\
    v2 += v3; v3 = rol64(v3, 16); v3 ^= v2;			\
    v0 += v3; v3 = rol64(v3, 21); v3 ^= v0;			\
    v2 += v1; v1 = rol64(v1, 17); v1 ^= v2; v2 = rol64(v2, 32)
#define SIP_ROUND2	SIP_ROUND1; SIP_ROUND1
#define SIP_ROUND4	SIP_ROUND2; SIP_ROUND2
#define SIP_ROUNDS(n)	SIP_ROUND ## n

#define sip_compress(n)		\
	do {			\
		v3 ^= m;	\
		SIP_ROUNDS(n);	\
		v0 ^= m;	\
	} while (0)

#define sip_finalize(n)		\
	do {			\
		v2 ^= 0xff;	\
		SIP_ROUNDS(n);	\
	} while (0)

uint64_t siphash24(const void *data, size_t len, uint64_t k0, uint64_t k1)
{
	const uint8_t *s = data;
	const uint8_t *end = s + len - (len % 8);
	uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
	uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
	uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
	uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);
	uint64_t m;

	for (; s < end; s += 8) {
		m = le64dec(s);
		sip_compress(2);
	}

	m = (uint64_t)len << 56;
	switch (len & 7) {
	case 7: m |= (uint64_t)s[6] << 48;
		/* fallthrough */
	case 6: m |= (uint64_t)s[5] << 40;
		/* fallthrough */
	case 5: m |= (uint64_t)s[4] << 32;
		/* fallthrough */
	case 4: m |= (uint64_t)s[3] << 24;
		/* fallthrough */
	case 3: m |= (uint64_t)s[2] << 16;
		/* fallthrough */
	case 2: m |= (uint64_t)s[1] <<  8;
		/* fallthrough */
	case 1: m |= (uint64_t)s[0];
		break;
	case 0: break;
	}
	sip_compress(2);

	sip_finalize(4);
	return (v0 ^ v1 ^ v2 ^ v3);
}

uint64_t siphash24_secure(const void *data, size_t len)
{
	static bool initialized;
	static uint64_t k0, k1;

	if (!initialized) {
		k0 = ((uint64_t)csrandom() << 32) | csrandom();
		k1 = ((uint64_t)csrandom() << 32) | csrandom();
		initialized = true;
	}

	return siphash24(data, len, k0, k1);
}
