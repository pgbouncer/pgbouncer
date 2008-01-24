/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007 Marko Kreen, Skype Technologies OÜ
 * 
 * Permission to use, copy, modify, and distribute this software for any
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

/*
 * time tools
 */
usec_t get_cached_time(void);
void reset_time_cache(void);

/*
 * load file into malloced buffer
 */
char *load_file(const char *fn) _MUSTCHECK;

void *zmalloc(size_t len) _MUSTCHECK _MALLOC;

/*
 * generic logging
 */
void log_level(const char *level, const char *s, ...)  _PRINTF(2, 3);
#define log_error(args...) log_level("ERROR", ## args)
#define log_warning(args...) log_level("WARNING", ## args)
#define log_info(args...) log_level("LOG", ## args)
#define log_debug(args...) do { \
		if (unlikely(cf_verbose > 0)) \
			log_level("DEBUG", ## args); \
	} while (0)
#define log_noise(args...) do { \
		if (unlikely(cf_verbose > 1)) \
			log_level("NOISE", ## args); \
	} while (0)

void close_logfile(void);

/*
 * logging about specific socket
 */
void slog_level(const char *level, const PgSocket *sock, const char *fmt, ...)  _PRINTF(3, 4);
#define slog_error(sk, args...) slog_level("ERROR", sk, ## args)
#define slog_warning(sk, args...) slog_level("WARNING", sk, ## args)
#define slog_info(sk, args...) slog_level("LOG", sk, ## args)
#define slog_debug(sk, args...) do { \
		if (unlikely(cf_verbose > 0)) \
			slog_level("DEBUG", sk, ## args); \
	} while (0)
#define slog_noise(sk, args...) do { \
		if (unlikely(cf_verbose > 1)) \
			slog_level("NOISE", sk, ## args); \
	} while (0)

/*
 * log and exit
 */
void _fatal(const char *file, int line, const char *func, bool do_exit, const char *s, ...) _PRINTF(5, 6);
void _fatal_perror(const char *file, int line, const char *func, const char *s, ...)  _PRINTF(4, 5);
#define fatal(args...) \
	_fatal(__FILE__, __LINE__, __FUNCTION__, true, ## args)
#define fatal_noexit(args...) \
	_fatal(__FILE__, __LINE__, __FUNCTION__, false, ## args)
#define fatal_perror(args...) \
	_fatal_perror(__FILE__, __LINE__, __FUNCTION__, ## args)

/*
 * non-interruptible operations
 */
int safe_read(int fd, void *buf, int len)			_MUSTCHECK;
int safe_write(int fd, const void *buf, int len)		_MUSTCHECK;
int safe_recv(int fd, void *buf, int len, int flags)		_MUSTCHECK;
int safe_send(int fd, const void *buf, int len, int flags) 	_MUSTCHECK;
int safe_close(int fd);
int safe_recvmsg(int fd, struct msghdr *msg, int flags)		_MUSTCHECK;
int safe_sendmsg(int fd, const struct msghdr *msg, int flags)	_MUSTCHECK;
int safe_connect(int fd, const struct sockaddr *sa, socklen_t sa_len)	_MUSTCHECK;
int safe_accept(int fd, struct sockaddr *sa, socklen_t *sa_len)	_MUSTCHECK;

/*
 * password tools
 */
#define MD5_PASSWD_LEN  35
#define isMD5(passwd) (memcmp(passwd, "md5", 3) == 0 \
		&& strlen(passwd) == MD5_PASSWD_LEN)
void pg_md5_encrypt(const char *part1, const char *part2, size_t p2len, char *dest);
void get_random_bytes(uint8_t *dest, int len);

void socket_set_nonblocking(int fd, int val);
void tune_socket(int sock, bool is_unix);

bool strlist_contains(const char *liststr, const char *str);

const char *format_date(usec_t uval);

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

