/*
xxHash - Fast Hash algorithm
Copyright (C) 2012-2014, Yann Collet.
BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

You can contact the author at :
- xxHash source repository : http://code.google.com/p/xxhash/
*/

#include <usual/hashing/xxhash.h>

#include <usual/endian.h>
#include <usual/bits.h>

#define PRIME32_1	2654435761U
#define PRIME32_2	2246822519U
#define PRIME32_3	3266489917U
#define PRIME32_4	668265263U
#define PRIME32_5	374761393U

#define read32(p) h32dec(p)

uint32_t xxhash(const void *input, size_t len, uint32_t seed)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t * const bEnd = p + len;
	uint32_t h32;

	if (len >= 16) {
		const uint8_t * const limit = bEnd - 16;
		uint32_t v1, v2, v3, v4;

		v1 = seed + PRIME32_1 + PRIME32_2;
		v2 = seed + PRIME32_2;
		v3 = seed + 0;
		v4 = seed - PRIME32_1;

		do {
			v1 += read32(p) * PRIME32_2; v1 = rol32(v1, 13); v1 *= PRIME32_1; p += 4;
			v2 += read32(p) * PRIME32_2; v2 = rol32(v2, 13); v2 *= PRIME32_1; p += 4;
			v3 += read32(p) * PRIME32_2; v3 = rol32(v3, 13); v3 *= PRIME32_1; p += 4;
			v4 += read32(p) * PRIME32_2; v4 = rol32(v4, 13); v4 *= PRIME32_1; p += 4;
		} while (p <= limit);

		h32 = rol32(v1, 1) + rol32(v2, 7) + rol32(v3, 12) + rol32(v4, 18);
	} else {
		h32 = seed + PRIME32_5;
	}

	h32 += len;

	while (p <= bEnd - 4) {
		h32 += read32(p) * PRIME32_3;
		h32 = rol32(h32, 17) * PRIME32_4 ;
		p += 4;
	}

	while (p < bEnd) {
		h32 += (*p) * PRIME32_5;
		h32 = rol32(h32, 11) * PRIME32_1 ;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}
