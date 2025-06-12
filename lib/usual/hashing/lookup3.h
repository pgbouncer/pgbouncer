/**
 * @file
 *
 * Jenkins' lookup3 non-cryptographic hash.
 */
#ifndef _USUAL_HASHING_LOOKUP3_H_
#define _USUAL_HASHING_LOOKUP3_H_

#include <usual/base.h>

/**
 * Calculate 64-bit hash over data
 */
uint64_t hash_lookup3(const void *data, size_t len);

#endif
