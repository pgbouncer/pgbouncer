/**
 * @file
 *
 * Jenkins SpookyHash V2 - fast hash for 64-bit CPUs.
 */
#ifndef _USUAL_HASHING_SPOOKY_H_
#define _USUAL_HASHING_SPOOKY_H_

#include <usual/base.h>

/**
 * Run SpookyHash on data.
 */
void spookyhash(const void *message, size_t length, uint64_t *hash1, uint64_t *hash2);

#endif
