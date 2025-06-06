/*
 * Signal compat.
 *
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

#include <usual/signal.h>

/*
 * alarm() for win32
 */

#ifdef WIN32

struct AlarmCtx {
	struct sigaction sa;
	HANDLE event;
	HANDLE thread;
	int secs;

};
static volatile struct AlarmCtx actx;

static DWORD WINAPI w32_alarm_thread(LPVOID arg)
{
	DWORD wres;
	unsigned msecs;

loop:
	if (actx.secs > 0) {
		msecs = actx.secs * 1000;
	} else {
		msecs = INFINITE;
	}

	wres = WaitForSingleObject(actx.event, msecs);
	if (wres == WAIT_OBJECT_0) {
		goto loop;
	} else if (wres == WAIT_TIMEOUT) {
		actx.secs = 0;
		if (actx.sa.sa_handler)
			actx.sa.sa_handler(SIGALRM);
		goto loop;
	} else {
		Sleep(1000);
		goto loop;
	}
	return 0;
}

unsigned int alarm(unsigned int secs)
{
	actx.secs = secs;

	/* create event */
	if (!actx.event) {
		actx.event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!actx.event)
			return 0;
	}

	/* create or notify thread */
	if (!actx.thread) {
		actx.thread = CreateThread(NULL, 0, w32_alarm_thread, NULL, 0, NULL);
	} else {
		SetEvent(actx.event);
	}
	return 0;
}

#endif

#ifndef HAVE_SIGACTION
int sigaction(int sig, const struct sigaction *sa, struct sigaction *old)
{
#ifdef WIN32
	if (sig == SIGALRM) {
		if (old)
			*old = actx.sa;
		if (sa)
			actx.sa = *sa;
		else
			actx.sa.sa_handler = NULL;
		return 0;
	}
#endif
	old->sa_handler = signal(sig, sa->sa_handler);
	if (old->sa_handler == SIG_ERR)
		return -1;
	return 0;
}
#endif

#ifdef WIN32
/* Only sig=0 is supported, to detect if process is running (ESRCH->not) */
int kill(int pid, int sig)
{
	HANDLE hProcess;
	DWORD exitCode;
	int ret = 0;

	/* handle only sig == 0 */
	if (sig != 0) {
		errno = EINVAL;
		return -1;
	}

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProcess == NULL) {
		if (GetLastError() == ERROR_INVALID_PARAMETER)
			ret = ESRCH;
		else
			ret = EPERM;
	} else {
		/* OpenProcess may succed for exited processes */
		if (GetExitCodeProcess(hProcess, &exitCode)) {
			if (exitCode != STILL_ACTIVE)
				ret = ESRCH;
		}
		CloseHandle(hProcess);
	}

	if (ret) {
		errno = ret;
		return -1;
	} else
		return  0;
}
#endif
