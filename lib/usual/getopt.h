/*
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * getopt compat.
 *
 * This module provides getopt() and getopt_long().
 */

#ifndef _USUAL_GETOPT_H_
#define _USUAL_GETOPT_H_

#include <usual/base.h>

#ifndef NEED_USUAL_GETOPT
#if !defined(HAVE_GETOPT_H) || !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_LONG)
#define NEED_USUAL_GETOPT
#endif
#endif

#ifndef NEED_USUAL_GETOPT

/* Use system getopt */
#include <getopt.h>

#else /* NEED_USUAL_GETOPT */

/* avoid name collision */
#define optarg usual_optarg
#define opterr usual_opterr
#define optind usual_optind
#define optopt usual_optopt
#define getopt(a, b, c) usual_getopt(a, b, c)
#define getopt_long(a, b, c, d, e) usual_getopt_long(a, b, c, d, e)


/** argument to current option, or NULL if it has none */
extern char *optarg;
/** Current position in arg string.  Starts from 1.  Setting to 0 resets state. */
extern int optind;
/** whether getopt() should print error messages on problems.  Default: 1. */
extern int opterr;
/** Option char which caused error */
extern int optopt;

/** long option takes no argument */
#define no_argument        0
/** long option requires argument */
#define required_argument  1
/** long option has optional argument */
#define optional_argument  2

/** Long option description */
struct option {
	/** name of long option */
	const char *name;

	/**
	 * whether option takes an argument.
	 * One of no_argument, required_argument, and optional_argument.
	 */
	int has_arg;

	/** if not NULL, set *flag to val when option found */
	int *flag;

	/** if flag not NULL, value to set *flag to; else return value */
	int val;
};

/** Compat: getopt */
int getopt(int argc, char *argv[], const char *options);

/** Compat: getopt_long */
int getopt_long(int argc, char *argv[], const char *options,
		const struct option *longopts, int *longindex);

/** Compat: getopt_long_only */
int getopt_long_only(int nargc, char *argv[], const char *options,
		     const struct option *long_options, int *idx);


#endif /* NEED_USUAL_GETOPT */

#endif /* !_USUAL_GETOPT_H_ */
