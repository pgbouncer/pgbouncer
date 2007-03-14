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
typedef uint64_t usec_t;
usec_t get_cached_time(void);
void reset_time_cache(void);

/*
 * load file into malloced buffer
 */
char *load_file(const char *fn);

void *zmalloc(size_t len);

/*
 * generic logging
 */
void log_level(const char *level, const char *s, ...);
#define log_error(args...) log_level("ERROR", ## args)
#define log_warning(args...) log_level("WARNING", ## args)
#define log_info(args...) log_level("LOG", ## args)
#define log_debug(args...) do { \
		if (cf_verbose > 0) log_level("DEBUG", ## args); \
	} while (0)
#define log_noise(args...) do { \
		if (cf_verbose > 1) log_level("NOISE", ## args); \
	} while (0)


/*
 * logging about specific socket
 */
void slog_level(const char *level, const PgSocket *sock, const char *fmt, ...);
#define slog_error(sk, args...) slog_level("ERROR", sk, ## args)
#define slog_warning(sk, args...) slog_level("WARNING", sk, ## args)
#define slog_info(sk, args...) slog_level("LOG", sk, ## args)
#define slog_debug(sk, args...) do { \
		if (cf_verbose > 0) slog_level("DEBUG", sk, ## args); \
	} while (0)
#define slog_noise(sk, args...) do { \
		if (cf_verbose > 1) slog_level("NOISE", sk, ## args); \
	} while (0)

/*
 * log and exit
 */
void _fatal(const char *file, int line, const char *func, const char *s, ...);
void _fatal_perror(const char *file, int line, const char *func, const char *s, ...);
#define fatal(args...) \
	_fatal(__FILE__, __LINE__, __FUNCTION__, ## args)
#define fatal_perror(args...) \
	_fatal_perror(__FILE__, __LINE__, __FUNCTION__, ## args)

/*
 * non-interruptible operations
 */
int safe_read(int fd, void *buf, int len);
int safe_write(int fd, const void *buf, int len);
int safe_recv(int fd, void *buf, int len, int flags);
int safe_send(int fd, const void *buf, int len, int flags);
int safe_close(int fd);
int safe_recvmsg(int fd, struct msghdr *msg, int flags);
int safe_sendmsg(int fd, const struct msghdr *msg, int flags);

/*
 * password tools
 */
#define MD5_PASSWD_LEN  35
#define isMD5(passwd) (memcmp(passwd, "md5", 3) == 0 \
		&& strlen(passwd) == MD5_PASSWD_LEN)
bool pg_md5_encrypt(const char *part1, const char *part2, size_t p2len, char *dest);
const char *pg_crypt(const char *passwd, const char *salt);
bool get_random_bytes(uint8 *dest, int len);

/*
 * safe string copy
 */
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t n);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t n);
#endif

/*
 * socket option handling
 */
bool get_unix_peer_uid(int fd, uid_t *uid_p);
void socket_set_nonblocking(int fd, int val);
void tune_socket(int sock, bool is_unix);

bool strlist_contains(const char *liststr, const char *str);

const char *format_date(usec_t uval);

