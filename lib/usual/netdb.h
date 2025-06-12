/*
 * libusual - Utility library for C
 *
 * Copyright (c) 2010  Marko Kreen, Skype Technologies
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

/** @file
 *
 * DNS lookup.
 */

#ifndef _USUAL_NETDB_H_
#define _USUAL_NETDB_H_

#include <usual/signal.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifndef HAVE_GETADDRINFO_A

/** Async execution */
#ifndef GAI_WAIT
#define GAI_WAIT	0
#endif

/** Synchronous execution */
#ifndef GAI_NOWAIT
#define GAI_NOWAIT	1
#endif

/* avoid name conflicts */
#define gaicb usual_gaicb
#define getaddrinfo_a(a,b,c,d) usual_getaddrinfo_a(a,b,c,d)

/**
 * Request data for getaddrinfo_a().
 *
 * Fields correspond to getaddrinfo() parameters.
 */
struct gaicb {
	/** node name */
	const char *ar_name;
	/** service name */
	const char *ar_service;
	/** hints */
	const struct addrinfo *ar_request;
	/** result */
	struct addrinfo *ar_result;
	/* internal state */
	int _state;
};

#ifndef EAI_INPROGRESS
#define EAI_INPROGRESS -100
#endif

#ifndef EAI_SYSTEM
#define EAI_SYSTEM -10
#endif

#define gai_error(gcb) ((gcb)->_state)

/**
 * Compat: Async DNS lookup.
 */
int getaddrinfo_a(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp);

#endif /* HAVE_GETADDRINFO_A */

#endif /* _USUAL_NETDB_H_ */
