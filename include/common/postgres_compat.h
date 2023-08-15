/*
 * Various things to allow source files from postgresql code to be
 * used in pgbouncer.  pgbouncer's system.h needs to be included
 * before this.
 */

/* from c.h */

#include <string.h>

#define int8 int8_t
#define uint8 uint8_t
#define uint16 uint16_t
#define uint32 uint32_t
#define uint64 uint64_t

#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define pg_hton32(x) htobe32(x)

#define pg_attribute_noreturn() _NORETURN

#define HIGHBIT					(0x80)
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT)

#define UINT64CONST(x) (x##ULL)

/* ignore gettext */
#define _(x) (x)

typedef unsigned int Oid;


/* define this to use non-server code paths */
#define FRONTEND
