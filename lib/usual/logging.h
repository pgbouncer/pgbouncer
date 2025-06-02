/*
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

/**
 * @file
 *
 * Logging framework for unix services.
 *
 *
 * Supported outputs:
 * - syslog
 * - log file
 * - stderr
 *
 * @section logging_prefix Logging context
 *
 * It is possible to pass context info to all logging calls
 * and later add details to log lines or to filter based on it.
 *
 * Each call references 2 macros:
 * - LOG_CONTEXT_DEF - which can define/call any variables
 * - LOG_CONTEXT - which should return a pointer variable.
 *
 * Later, global callback function \ref logging_prefix_cb
 * will get this pointer with destination buffer and can either
 * add more info for log line or tell to skip logging this message.
 */
#ifndef _USUAL_LOGGING_H_
#define _USUAL_LOGGING_H_

#include <usual/base.h>

/* internal log levels */
enum LogLevel {
	LG_FATAL = 0,
	LG_ERROR = 1,
	LG_WARNING = 2,
	LG_STATS = 3,
	LG_INFO = 4,
	LG_DEBUG = 5,
	LG_NOISE = 6,
};
#ifndef LOG_CONTEXT_DEF
/** Example: Prepare dummy context pointer */
#define LOG_CONTEXT_DEF	void *_log_ctx = NULL
#endif
#ifndef LOG_CONTEXT
/** Example: Reference dummy context pointer */
#define LOG_CONTEXT	_log_ctx
#endif

/**
 * Signature for logging_prefix_cb.  Return value is either added string length in dst
 * or negative value to skip logging.
 */
typedef int (*logging_prefix_fn_t)(enum LogLevel lev, void *ctx, char *dst, unsigned int dstlen);

/**
 * Optional global callback for each log line.
 *
 * It can either add info to log message or skip logging it.
 */
extern logging_prefix_fn_t logging_prefix_cb;

/**
 * Global verbosity level.
 *
 * 0 - show only info level msgs (default)
 * 1 - show debug msgs (log_debug)
 * 2 - show noise msgs (log_noise)
 */
extern int cf_verbose;

/**
 * Toggle logging to stderr.  Default: 1.
 * daemon.c turns this off if goes to background
 */
extern int cf_quiet;

/**
 * Logfile location, default NULL
 */
extern const char *cf_logfile;

/** Syslog on/off */
extern int cf_syslog;
/** ident for syslog, if NULL syslog is disabled (default) */
extern const char *cf_syslog_ident;
/** Facility name */
extern const char *cf_syslog_facility;

/** Max log level for syslog writer */
extern enum LogLevel cf_syslog_level;
/** Max log level for logfile writer */
extern enum LogLevel cf_logfile_level;
/** Max log level for stderr writer */
extern enum LogLevel cf_stderr_level;

/*
 * Internal API.
 */

/* non-fatal logging */
void log_generic(enum LogLevel level, void *ctx, const char *s, ...) _PRINTF(3, 4);

/* this is also defined in base.h for Assert() */
void log_fatal(const char *file, int line, const char *func, bool show_perror,
	       void *ctx, const char *s, ...) _PRINTF(6, 7);

/*
 * Public API
 */

/** Log error message */
#define log_error(...) do { LOG_CONTEXT_DEF; \
		log_generic(LG_ERROR, LOG_CONTEXT, __VA_ARGS__); \
	} while (0)

/** Log warning message */
#define log_warning(...) do { LOG_CONTEXT_DEF; \
		log_generic(LG_WARNING, LOG_CONTEXT, __VA_ARGS__); \
	} while (0)

/** Log stats (liveness) message */
#define log_stats(...) do { LOG_CONTEXT_DEF; \
		log_generic(LG_STATS, LOG_CONTEXT, __VA_ARGS__); \
	} while (0)

/** Log info message */
#define log_info(...) do { LOG_CONTEXT_DEF; \
		log_generic(LG_INFO, LOG_CONTEXT, __VA_ARGS__); \
	} while (0)

/** Log debug message */
#define log_debug(...) do { LOG_CONTEXT_DEF; \
		if (unlikely(cf_verbose > 0)) \
			log_generic(LG_DEBUG, LOG_CONTEXT, __VA_ARGS__); \
	} while (0)

/** Log debug noise */
#define log_noise(...) do { LOG_CONTEXT_DEF; \
		if (unlikely(cf_verbose > 1)) \
			log_generic(LG_NOISE, LOG_CONTEXT, __VA_ARGS__); \
	} while (0)

/** Log and die.  It also logs source location */
#define fatal(...) do { LOG_CONTEXT_DEF; \
	log_fatal(__FILE__, __LINE__, __func__, false, LOG_CONTEXT, __VA_ARGS__); \
	exit(1); } while (0)

/** Log strerror and die.  Error message also includes strerror(errno) */
#define fatal_perror(...) do { LOG_CONTEXT_DEF; \
	log_fatal(__FILE__, __LINE__, __func__, true, LOG_CONTEXT, __VA_ARGS__); \
	exit(1); } while (0)

/** Less verbose fatal() */
#define die(...) do { LOG_CONTEXT_DEF; \
	log_generic(LG_FATAL, LOG_CONTEXT, __VA_ARGS__); \
	exit(1); } while (0)

/**
 * Close open logfiles and syslog.
 *
 * Useful when rotating log files.
 */
void reset_logging(void);

#endif
