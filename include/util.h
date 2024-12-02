/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
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
#include <usual/string.h>
#include <usual/cfparser.h>

/*
 * logging about specific socket
 */
int log_socket_prefix(enum LogLevel lev, void *ctx, char *dst, unsigned int dstlen);

#define slog_error(sk, args...) log_generic(LG_ERROR, sk, ## args)
#define slog_warning(sk, args...) log_generic(LG_WARNING, sk, ## args)
#define slog_info(sk, args...) log_generic(LG_INFO, sk, ## args)
#define slog_debug(sk, args...) do { \
		if (unlikely(cf_verbose > 0)) \
		log_generic(LG_DEBUG, sk, ## args); \
} while (0)
#define slog_noise(sk, args...) do { \
		if (unlikely(cf_verbose > 1)) \
		log_generic(LG_NOISE, sk, ## args); \
} while (0)

/*
 * password tools
 */
#define MD5_PASSWD_LEN  35
bool pg_md5_encrypt(const char *part1, const char *part2, size_t p2len, char *dest) _MUSTCHECK;
void get_random_bytes(uint8_t *dest, int len);

const char *bin2hex(const uint8_t *src, unsigned srclen, char *dst, unsigned dstlen);

bool tune_socket(int sock, bool is_unix) _MUSTCHECK;

bool strlist_contains(const char *liststr, const char *str);

void fill_remote_addr(PgSocket *sk, int fd, bool is_unix);
void fill_local_addr(PgSocket *sk, int fd, bool is_unix);


void rescue_timers(void);
void safe_evtimer_add(struct event *ev, struct timeval *tv);

/* log truncated strings */
#define safe_strcpy(dst, src, dstlen) do { \
		size_t needed = strlcpy(dst, src, dstlen); \
		if (unlikely(needed >= (dstlen))) \
		log_warning("bug in %s:%d - string truncated", __FILE__, __LINE__); \
} while (0)

/* parser setter and getter for parsing auth_dbname parameters using "cfparser" */
#define CF_AUTHDB       { cf_set_authdb, cf_get_str }
bool cf_set_authdb(struct CfValue *cv, const char *value);

/* reserved database name checking */
bool check_reserved_database(const char *value);
