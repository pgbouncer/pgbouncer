/*
 * Logging for unix service.
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

#include <usual/logging.h>

#include <sys/stat.h>

#include <usual/ctype.h>
#include <usual/string.h>
#include <usual/time.h>
#include <usual/err.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef USE_SYSTEMD
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>
#endif

#ifdef WIN32
#define LOG_EMERG       0
#define LOG_ALERT       1
#define LOG_CRIT        2
#define LOG_ERR         3
#define LOG_WARNING     4
#define LOG_NOTICE      5
#define LOG_INFO        6
#define LOG_DEBUG       7

#define LOG_PID 0
#define LOG_DAEMON 0

static inline void openlog(const char *ident, int opt, int fac)
{
}
#define syslog win32_eventlog
#define closelog()
static void win32_eventlog(int level, const char *fmt, ...) _PRINTF(2, 3);
#endif

int cf_quiet = 0;
int cf_verbose = 0;
const char *cf_logfile = NULL;

int cf_syslog = 0;
const char *cf_syslog_ident = NULL;
const char *cf_syslog_facility = NULL;

enum LogLevel cf_syslog_level = LG_INFO;
enum LogLevel cf_logfile_level = LG_NOISE;
enum LogLevel cf_stderr_level = LG_NOISE;

/* optional function to fill prefix */
logging_prefix_fn_t logging_prefix_cb;

static FILE *log_file = NULL;
static bool syslog_started = false;

struct LevelInfo {
	const char *tag;
	int syslog_prio;
};

static const struct LevelInfo log_level_list[] = {
	{ "FATAL", LOG_CRIT },	/* LG_FATAL */
	{ "ERROR", LOG_ERR },	/* LG_ERROR */
	{ "WARNING", LOG_WARNING },	/* LG_WARNING */
	{ "LOG", LOG_INFO },	/* LG_STATS*/
	{ "LOG", LOG_INFO },	/* LG_INFO */
	{ "DEBUG", LOG_DEBUG },	/* LG_DEBUG */
	{ "NOISE", LOG_DEBUG },	/* LG_NOISE */
};

struct FacName { const char *name; int code; };
static const struct FacName facility_names [] = {
#ifndef WIN32
	{ "auth", LOG_AUTH },
#ifdef LOG_AUTHPRIV
	{ "authpriv", LOG_AUTHPRIV },
#endif
	{ "daemon", LOG_DAEMON },
	{ "user", LOG_USER },
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
#endif
	{ NULL },
};

void reset_logging(void)
{
	if (log_file) {
		fclose(log_file);
		log_file = NULL;
	}
	if (syslog_started) {
		closelog();
		syslog_started = 0;
	}
}


static void start_syslog(void)
{
	const struct FacName *f;
	int fac = LOG_DAEMON;
	const char *ident = cf_syslog_ident;

	if (!cf_syslog)
		return;

	if (cf_syslog_facility) {
		for (f = facility_names; f->name; f++) {
			if (strcmp(f->name, cf_syslog_facility) == 0) {
				fac = f->code;
				break;
			}
		}
	}

	if (!ident) {
		ident = getprogname();
		if (!ident)
			ident = "unnamed";
	}

	openlog(ident, LOG_PID, fac);
	syslog_started = 1;
}


void log_generic(enum LogLevel level, void *ctx, const char *fmt, ...)
{
	char buf[2048], buf2[2048];
	char ebuf[256];
	char timebuf[64];
	const struct LevelInfo *lev = &log_level_list[level];
	unsigned pid = getpid();
	va_list ap;
	int pfxlen = 0;
	int old_errno = errno;
	char *msg = buf;

	if (logging_prefix_cb) {
		pfxlen = logging_prefix_cb(level, ctx, buf, sizeof(buf));
		if (pfxlen < 0)
			goto done;
		if (pfxlen >= (int)sizeof(buf))
			pfxlen = sizeof(buf) - 1;
	}
	va_start(ap, fmt);
	vsnprintf(buf + pfxlen, sizeof(buf) - pfxlen, fmt, ap);
	va_end(ap);

	/* replace '\n' in message with '\n\t', strip trailing whitespace */
	if (strchr(msg, '\n')) {
		char *dst = buf2;
		for (; *msg && dst - buf2 < (int)sizeof(buf2) - 2; msg++) {
			*dst++ = *msg;
			if (*msg == '\n')
				*dst++ = '\t';
		}
		while (dst > buf2 && isspace(dst[-1]))
			dst--;
		*dst = 0;
		msg = buf2;
	}

	format_time_ms(0, timebuf, sizeof(timebuf));

	if (!log_file && cf_logfile && cf_logfile[0]) {
		log_file = fopen(cf_logfile, "a");
		if (log_file) {
			/* Got the file, disable buffering */
			setvbuf(log_file, NULL, _IONBF, 0);
		} else {
			/* Unable to open, complain and fail */
			fprintf(stderr, "%s %u %s Cannot open logfile: '%s': %s\n",
				timebuf, pid, log_level_list[0].tag,
				cf_logfile,
				strerror_r(errno, ebuf, sizeof(ebuf)));
			exit(1);
		}
	}

	if (!cf_quiet && level <= cf_stderr_level) {
#ifdef USE_SYSTEMD
		static bool journal_stream_checked = false;
		static bool use_systemd_journal = false;

		if (!journal_stream_checked) {
			if (getenv("JOURNAL_STREAM")) {
				long long unsigned int f1, f2;
				if (sscanf(getenv("JOURNAL_STREAM"), "%llu:%llu", &f1, &f2) == 2) {
					struct stat st;
					dev_t js_dev = f1;
					ino_t js_ino = f2;
					if (fstat(fileno(stderr), &st) >= 0) {
						if (js_dev == st.st_dev && js_ino == st.st_ino)
							use_systemd_journal = true;
					}
				}
			}
			journal_stream_checked = true;
		}
		if (use_systemd_journal)
			sd_journal_print(lev->syslog_prio, "%s", msg);
		else
#endif
		fprintf(stderr, "%s [%u] %s %s\n", timebuf, pid, lev->tag, msg);
	}

	if (log_file && level <= cf_logfile_level)
		fprintf(log_file, "%s [%u] %s %s\n", timebuf, pid, lev->tag, msg);

	if (cf_syslog && level <= cf_syslog_level) {
		if (!syslog_started)
			start_syslog();
		syslog(lev->syslog_prio, "%s", msg);
	}
done:
	if (old_errno != errno)
		errno = old_errno;
}


void log_fatal(const char *file, int line, const char *func, bool show_perror, void *ctx, const char *fmt, ...)
{
	char buf[2048], ebuf[256];
	const char *estr = NULL;
	int old_errno = 0;
	va_list ap;

	if (show_perror) {
		old_errno = errno;
		estr = strerror_r(errno, ebuf, sizeof(ebuf));
	}

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (show_perror) {
		log_generic(LG_FATAL, ctx, "@%s:%d in function %s(): %s: %s [%d]",
			    file, line, func, buf, estr, old_errno);
	} else {
		log_generic(LG_FATAL, ctx, "@%s:%d in function %s(): %s",
			    file, line, func, buf);
	}
}

#ifdef WIN32

static void win32_eventlog(int level, const char *fmt, ...)
{
	static HANDLE evtHandle = INVALID_HANDLE_VALUE;
	int elevel;
	char buf[1024];
	const char *strlist[1] = { buf };
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	switch (level) {
	case LOG_CRIT:
	case LOG_ERR:
		elevel = EVENTLOG_ERROR_TYPE;
		break;
	case LOG_WARNING:
		elevel = EVENTLOG_WARNING_TYPE;
		break;
	default:
		elevel = EVENTLOG_INFORMATION_TYPE;
	}

	if (evtHandle == INVALID_HANDLE_VALUE) {
		evtHandle = RegisterEventSource(NULL, cf_syslog_ident);
		if (evtHandle == NULL || evtHandle == INVALID_HANDLE_VALUE) {
			evtHandle = INVALID_HANDLE_VALUE;
			return;
		}
	}
	ReportEvent(evtHandle, elevel, 0, 0, NULL, 1, 0, strlist, NULL);
}

#endif
