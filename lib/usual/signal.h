/*
 * Copyright (c) 2009 Marko Kreen
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
 * Signals compat.
 *
 * general
 * - sigaction() -> signal()
 *
 * win32:
 * - SIGALRM, alarm(), signal(SIGALRM), sigaction(SIGALRM)
 * - kill(pid, 0)
 */
#ifndef _USUAL_SIGNAL_H_
#define _USUAL_SIGNAL_H_

#include <usual/base.h>

#include <signal.h>

/*
 * Compat sigval, detect based on siginfo_t.si_code.
 */

#if !defined(SI_QUEUE) && !defined(HAVE_SIGQUEUE)
union sigval {
	int sival_int;
	void *sival_ptr;
};
#endif

/*
 * Compat sigevent
 */

#ifndef SIGEV_NONE
#define SIGEV_NONE 0
#define SIGEV_SIGNAL 1
#define SIGEV_THREAD 2
struct sigevent {
	int sigev_notify;
	int sigev_signo;
	union sigval sigev_value;
	void (*sigev_notify_function)(union sigval);
};
#endif

/*
 * Compat sigaction()
 */

#ifndef HAVE_SIGACTION
#define SA_SIGINFO 1
#define SA_RESTART 2
typedef struct siginfo_t siginfo_t;
struct sigaction {
	union {
		void (*sa_handler)(int);
		void (*sa_sigaction)(int, siginfo_t *, void *);
	};
	int sa_flags;
	int sa_mask;
};
#define sigemptyset(s)
#define sigfillset(s)
#define sigaddset(s, sig)
#define sigdelset(s, sig)
#define sigaction(a, b, c) compat_sigaction(a, b, c)
int sigaction(int sig, const struct sigaction *sa, struct sigaction *old);
#endif

/*
 * win32 compat:
 * kill(), alarm, SIGALRM
 */

#ifdef WIN32

#define SIGALRM 1023
#define SIGBUS 1022
unsigned alarm(unsigned);

int kill(int pid, int sig);

typedef void (*_sighandler_t)(int);

static inline _sighandler_t wrap_signal(int sig, _sighandler_t func)
{
	/* sigaction has custom handling for SIGALRM */
	if (sig == SIGALRM) {
		struct sigaction sa, oldsa;
		sa.sa_handler = func;
		sa.sa_flags = sa.sa_mask = 0;
		sigaction(SIGALRM, &sa, &oldsa);
		return oldsa.sa_handler;
	} else if (sig == SIGBUS) {
		return NULL;
	}
	return signal(sig, func);
}
#define signal(a, b) wrap_signal(a, b)
#endif

#endif
