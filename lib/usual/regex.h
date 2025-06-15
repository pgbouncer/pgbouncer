/*
 * Copyright (c) 2009  Marko Kreen
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

/**
 * @file
 *
 * POSIX regular expession API, provided by either libc or internally.
 *
 * The internal regex engine is only activated if OS does not provide
 * @ref uregex_links "<regex.h>" (eg. Windows) or if
 * --with-internal-regex is used when configuring @ref libusual.
 *
 * @section uregex  Features of internal regex (uregex).
 *
 * Simple recursive matcher, only features are small size
 * and POSIX compatibility.  Supports both Extended Regular Expressions (ERE)
 * and Basic Regular Expressions (BRE).
 *
 * @section uregex_syntax  Supported syntax
 * @code
 *   Both: . * ^ $ [] [[:cname:]]
 *   ERE: () {} | + ?
 *   BRE: \(\) \{\} \1-9
 * @endcode
 *
 * With REG_RELAXED_SYNTAX, following common escapes will be available:
 * @code
 *    Both: \b\B\d\D\s\S\w\W
 *    BRE:  \|
 *    ERE:  \1-9
 * @endcode
 *
 * With REG_RELAXED_MATCHING it returns the first match found after applying
 * leftmost-longest to all elements.  It skips the combinatorics to turn it
 * into guaranteed-longest match.
 *
 * @section uregex_skip Skipped POSIX features
 * - collation classes: [[. .]]
 * - equivalence classes: [[= =]]
 * - char ranges by locale order: [a-z]  (byte order will be used)
 * - multi-byte chars: UTF-8
 *
 * @section uregex_globaldefs Global defines
 * - USUAL_RELAXED_REGEX
 * - USE_INTERNAL_REGEX
 *
 * @section uregex_links  Compatibility
 *
 * - <a href="http://www.opengroup.org/onlinepubs/9699919799/basedefs/regex.h.html">
 *   POSIX-2008 <regex.h> spec</a> - by default uRegex run in mode where only
 *   features specified by POSIX are available.
 *
 * - <a href="http://www2.research.att.com/~gsf/testregex/">
 *   AT\&T Research regex(3) regression tests</a> - uRegex follows the interpretation
 *   given there and fully passes the testsuite.
 */


#ifndef _USUAL_REGEX_H_
#define _USUAL_REGEX_H_

#include <usual/base.h>

#if !defined(USE_INTERNAL_REGEX) && defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
#define USE_SYSTEM_REGEX
#endif


#ifdef USE_SYSTEM_REGEX
#include <regex.h>
#else

/*
 * uRegex defines
 */

/**
 * @name Standard flags to regcomp()
 * @{
 */

/** Use POSIX Extended Regex Syntax instead of Basic Syntax */
#define REG_EXTENDED	(1 << 0)

/** Do case-insensitive matching */
#define REG_ICASE	(1 << 1)

/** Do case-insensitive matching */
#define REG_NOSUB	(1 << 2)

/** Do case-insensitive matching */
#define REG_NEWLINE	(1 << 3)

/* @} */

/**
 * @name Standard flags to regexec()
 * @{
 */

/** The start of string is not beginning of line, so ^ should not match */
#define REG_NOTBOL	(1 << 4)

/** The end of string is not end of line, so $ should not match */
#define REG_NOTEOL	(1 << 5)

/* @} */

/**
 * @name Standard error codes
 * @{
 */
/** Match not found */
#define REG_NOMATCH	1
/** Bad {} repeat specification */
#define REG_BADBR	2
/** General problem with regular expression */
#define REG_BADPAT	3
/** Repeat used without preceding non-repeat element */
#define REG_BADRPT	4
/** Syntax error with {} */
#define REG_EBRACE	5
/** Syntax error with [] */
#define REG_EBRACK	6
/** Bad collation reference */
#define REG_ECOLLATE	7
/** Bad character class reference  */
#define REG_ECTYPE	8
/** Trailing backslack */
#define REG_EESCAPE	9
/** Syntax error with () */
#define REG_EPAREN	10
/** Bad endpoint in range */
#define REG_ERANGE	11
/** No memory */
#define REG_ESPACE	12
/** Bad subgroup reference */
#define REG_ESUBREG	13

/* @} */

/**
 * @name Other defines
 * @{
 */
#undef RE_DUP_MAX
/** Max count user can enter via {} */
#define RE_DUP_MAX	0x7ffe
/* @} */

/**
 * @name Non-standard flags for regcomp()
 * @{
 */

/**
 * Allow few common non-standard escapes:
 * @code
 *   \b - word-change
 *   \B - not word change
 *   \d - digit
 *   \D - non-digit
 *   \s - space
 *   \S - non-space
 *   \w - word char
 *   \W - non-word char
 *   \/ - /
 * @endcode
 */
#define REG_RELAXED_SYNTAX	(1 << 14)

/**
 * Dont permute groups in attempt to get longest match.
 *
 * May give minor speed win at the expense of strict
 * POSIX compatibility.
 */
#define REG_RELAXED_MATCHING	(1 << 15)

/** Turn on both REG_RELAXED_SYNTAX and REG_RELAXED_MATCHING */
#define REG_RELAXED		(REG_RELAXED_SYNTAX | REG_RELAXED_MATCHING)

/* @} */

/* turn them permanently on */
#ifdef USUAL_RELAXED_REGEX
#undef REG_EXTENDED
#define REG_EXTENDED (1 | REG_RELAXED)
#endif


/**
 * Compiled regex.
 *
 * It has only one standard field - re_nsub,
 * rest are implementation-specific.
 */
typedef struct {
	/** Number of subgroups in expression */
	int re_nsub;
	void *internal;
} regex_t;

/** Type for offset in match */
typedef long regoff_t;

/** Match location */
typedef struct {
	regoff_t rm_so;		/**<  Start offset */
	regoff_t rm_eo;		/**<  End offset   */
} regmatch_t;

/* avoid name conflicts */
#define regcomp(a,b,c) usual_regcomp(a,b,c)
#define regexec(a,b,c,d,e) usual_regexec(a,b,c,d,e)
#define regerror(a,b,c,d) usual_regerror(a,b,c,d)
#define regfree(a) usual_regfree(a)

/**
 * Compile regex.
 *
 * @param rx    Pre-allocated @ref regex_t structure to fill.
 * @param re    Regex as zero-terminated string.
 * @param flags See above for regcomp() flags.
 */
int regcomp(regex_t *rx, const char *re, int flags);

/**
 * Execute regex on a string.
 *
 * @param rx      Regex previously initialized with regcomp()
 * @param str     Zero-terminated string to match
 * @param nmatch  Number of matches in pmatch
 * @param pmatch  Array of matches.
 * @param eflags  Execution flags.  Supported flags: @ref REG_NOTBOL, @ref REG_NOTEOL
 */
int regexec(const regex_t *rx, const char *str, size_t nmatch, regmatch_t pmatch[], int eflags);

/**
 * Give error description.
 *
 * @param err  Error code returned by regcomp() or regexec()
 * @param rx   Regex structure used in regcomp() or regexec()
 * @param dst  Destination buffer
 * @param dstlen Size of dst
 */
size_t regerror(int err, const regex_t *rx, char *dst, size_t dstlen);

/**
 * Free resources allocated by regcomp().
 * @param rx Regex previously filled by regcomp()
 */
void regfree(regex_t *rx);

#endif /* !USE_SYSTEM_REGEX */

#endif /* _USUAL_REGEX_H_ */
