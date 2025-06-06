/*
 * fnmatch.h
 *
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

/**
 * \file
 * Theme include for strings.
 */

#ifndef _USUAL_FNMATCH_H_
#define _USUAL_FNMATCH_H_

#include <usual/base.h>

#if defined(HAVE_FNMATCH_H) && defined(FNM_CASEFOLD)
#include <fnmatch.h>
#else
	/* fnmatch missing or incomplete */
#define NEED_USUAL_FNMATCH
#endif

#ifdef NEED_USUAL_FNMATCH
#define fnmatch(p,s,f) usual_fnmatch(p,s,f)

/** Do not allow wildcard to match '/' */
#define FNM_PATHNAME	1
/** Treat '\\' as literal value */
#define FNM_NOESCAPE	2
/** Do not allow wildcard to match leading '.' */
#define FNM_PERIOD	4
/** (GNU) Match case-insensitively */
#define FNM_CASEFOLD	8
/** (GNU) Match leading directory in path */
#define FNM_LEADING_DIR	16

/* (GNU) random alias */
#define FNM_FILE_NAME	FNM_PATHNAME

/** Returned on no match */
#define FNM_NOMATCH	1

/**
 * Compat: fnmatch()
 */
int fnmatch(const char *pat, const char *str, int flags);

#endif /* NEED_USUAL_FNMATCH */

#endif /* !_USUAL_FNMATCH_H_ */
