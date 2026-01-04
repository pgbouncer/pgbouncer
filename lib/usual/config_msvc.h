
/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://libusual.github.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libusual"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libusual 0.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libusual"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.1"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to request cleaner win32 headers. */
#define WIN32_LEAN_AND_MEAN 1

/* Define to max win32 API version (0x0501=XP). */
//#define WINVER 0x0501
#define WINVER 0x0600

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined(_M_IX86) || defined(_M_X64)
/* #  undef WORDS_BIGENDIAN */
#else
#error "Unsupported MSVC target CPU"
#endif

/* Define to `int' if <sys/types.h> doesn't define. */
#define gid_t int

/* Define to `int' if <sys/types.h> does not define. */
#define pid_t int

/* Define to the equivalent of the C99 'restrict' keyword, or to
   nothing if this is not supported.  Do not define if restrict is
   supported directly.  */
#ifndef restrict
#define restrict
#endif

/* Define to `int' if <sys/types.h> doesn't define. */
#define uid_t int

#define _CRT_SECURE_NO_WARNINGS 1

#ifndef WIN32
#define WIN32 1
#endif
