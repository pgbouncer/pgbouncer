/*
 * Common time functions.
 *
 * Copyright (c) 2007-2009 Marko Kreen, Skype Technologies OÜ
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

#include <usual/time.h>

#include <usual/string.h>

#include <stdio.h>

char *format_time_ms(usec_t time, char *dest, unsigned destlen)
{
	struct tm *tm, tmbuf;
	struct timeval tv;
	time_t sec;
	char msbuf[13];

	if (!time) {
		gettimeofday(&tv, NULL);
	} else {
		tv.tv_sec = time / USEC;
		tv.tv_usec = time % USEC;
	}

	sec = tv.tv_sec;
	tm = localtime_r(&sec, &tmbuf);
	strftime(dest, destlen, "%Y-%m-%d %H:%M:%S     %Z", tm);

	/* 'paste' milliseconds into place... */
	sprintf(msbuf, ".%03d", (int) (tv.tv_usec / 1000));
	memcpy(dest + 19, msbuf, 4);

	return dest;
}

char *format_time_s(usec_t time, char *dest, unsigned destlen)
{
	time_t s;
	struct tm tbuf, *tm;
	if (!time) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		s = tv.tv_sec;
	} else {
		s = time / USEC;
	}
	tm = localtime_r(&s, &tbuf);
	strftime(dest, destlen, "%Y-%m-%d %H:%M:%S %Z", tm);
	return dest;
}


/* read current time */
usec_t get_time_usec(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (usec_t)tv.tv_sec * USEC + tv.tv_usec;
}

static usec_t _time_cache;

/* read cached time */
usec_t get_cached_time(void)
{
	if (!_time_cache)
		_time_cache = get_time_usec();
	return _time_cache;
}

/* forget cached time, let next read fill it */
void reset_time_cache(void)
{
	_time_cache = 0;
}

/*
 * win32 compat
 */

#ifdef WIN32

/* unix epoch (1970) in seconds from windows epoch (1601) */
#define UNIX_EPOCH 11644473600LL

/* 1 sec in 100 nsec units */
#define FT_SEC 10000000LL

static void ft2tv(FILETIME *src, struct timeval *dest, bool use_epoch)
{
	ULARGE_INTEGER tmp;
	tmp.LowPart = src->dwLowDateTime;
	tmp.HighPart = src->dwHighDateTime;
	dest->tv_sec = (tmp.QuadPart / FT_SEC) - (use_epoch ? UNIX_EPOCH : 0);
	dest->tv_usec = (tmp.QuadPart % FT_SEC) / 10;
}

#ifndef HAVE_GETTIMEOFDAY

int gettimeofday(struct timeval *tp, void *tzp)
{
	FILETIME file_time;
	SYSTEMTIME system_time;

	/* read UTC timestamp */
	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);

	/* convert to timeval */
	ft2tv(&file_time, tp, true);

	return 0;
}

#endif /* !HAVE_GETTIMEOFDAY */

#ifndef HAVE_GETRUSAGE

int getrusage(int who, struct rusage *r_usage)
{
	FILETIME tcreate, texit, tkern, tuser;
	if (who != RUSAGE_SELF) {
		errno = EINVAL;
		return -1;
	}
	if (!GetProcessTimes(GetCurrentProcess(), &tcreate, &texit, &tkern, &tuser))
		return -1;
	ft2tv(&tuser, &r_usage->ru_utime, false);
	ft2tv(&tkern, &r_usage->ru_stime, false);
	return 0;
}

#endif /* !HAVE_GETRUSAGE */


#endif /* WIN32 */

#ifndef HAVE_TIMEGM

time_t timegm(struct tm *tm)
{
#ifdef WIN32
	return _mkgmtime(tm);
#else
	char buf[128], *tz, *old = NULL;
	time_t secs;

	tz = getenv("TZ");
	if (tz) {
		old = strdup(tz);
		if (!old) {
			strlcpy(buf, tz, sizeof buf);
			old = buf;
		}
	}
	setenv("TZ", "", 1);
	tzset();

	secs = mktime(tm);

	if (old) {
		setenv("TZ", old, 1);
	} else {
		unsetenv("TZ");
	}
	tzset();
	if (old && old != buf)
		free(old);
	return secs;
#endif
}

#endif /* HAVE_TIMEGM */
