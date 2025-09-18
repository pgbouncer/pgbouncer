/*
 * Various things to allow source files from postgresql code to be
 * used in pgbouncer.  pgbouncer's system.h needs to be included
 * before this.
 */

/* from c.h */

#include <usual/base.h>
#include <usual/ctype.h>
#include <usual/endian.h>
#include <usual/string.h>


#ifdef CASSERT
#define USE_ASSERT_CHECKING
#endif

#define int8 int8_t
#define uint8 uint8_t
#define uint16 uint16_t
#define uint32 uint32_t
#define uint64 uint64_t
#define Size size_t

#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define pg_hton32(x) htobe32(x)

#define HIGHBIT					(0x80)
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT)

#define UINT64CONST(x) (x##ULL)

/* ignore gettext */
#define _(x) (x)

typedef unsigned int Oid;

#define MaxAllocSize    ((Size) 0x3fffffff)

#define pg_nodiscard _MUSTCHECK
#define pg_noreturn _NORETURN
#define pg_restrict restrict

/* define this to use non-server code paths */
#define FRONTEND
