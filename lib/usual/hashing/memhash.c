/*
 * memhash.h - Randomized in-memory hashing.
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


#include <usual/hashing/memhash.h>
#include <usual/hashing/xxhash.h>
#include <usual/hashing/spooky.h>
#include <usual/crypto/csrandom.h>

#include <string.h>

uint32_t memhash_seed(const void *data, size_t len, uint32_t seed)
{
	if (sizeof(void *) == 8 || sizeof(long) == 8) {
		uint64_t hash[2];
		hash[0] = seed;
		hash[1] = 0;
		spookyhash(data, len, &hash[0], &hash[1]);
		return hash[0];
	} else {
		return xxhash(data, len, seed);
	}
}

uint32_t memhash(const void *data, size_t len)
{
	static bool initialized;
	static uint32_t rand_seed;

	if (!initialized) {
		initialized = true;
		rand_seed = csrandom();
	}
	return memhash_seed(data, len, rand_seed);
}

uint32_t memhash_string(const char *s)
{
	return memhash(s, strlen(s));
}
