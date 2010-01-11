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

/*
 * Random small utility functions
 */

#include "bouncer.h"

#define MD5_COMPAT
#include <usual/md5.h>

int log_socket_prefix(enum LogLevel lev, void *ctx, char *dst, unsigned int dstlen)
{
	const struct PgSocket *sock = ctx;
	char *user, *db, *host;
	int port;

	/* no prefix */
	if (!sock)
		return 0;

	/* format prefix */
	db = sock->pool ? sock->pool->db->name : "(nodb)";
	user = sock->auth_user ? sock->auth_user->name : "(nouser)";
	if (sock->remote_addr.is_unix) {
		host = "unix";
	} else {
		host = inet_ntoa(sock->remote_addr.ip_addr);
	}
	port = sock->remote_addr.port;

	return snprintf(dst, dstlen, "%c-%p: %s/%s@%s:%d ",
			is_server_socket(sock) ? 'S' : 'C',
			sock, db, user, host, port);
}


/*
 * Load a file into malloc()-ed C string.
 */

char *load_file(const char *fn)
{
	struct stat st;
	char *buf = NULL;
	int res, fd;

	res = stat(fn, &st);
	if (res < 0) {
		log_error("%s: %s", fn, strerror(errno));
		goto load_error;
	}

	buf = malloc(st.st_size + 1);
	if (!buf) {
		log_error("%s: no mem", fn);
		goto load_error;
	}

	if ((fd = open(fn, O_RDONLY)) < 0) {
		log_error("%s: %s", fn, strerror(errno));
		goto load_error;
	}

	if ((res = safe_read(fd, buf, st.st_size)) < 0) {
		log_error("%s: %s", fn, strerror(errno));
		goto load_error;
	}

	close(fd);
	buf[st.st_size] = 0;

	return buf;

load_error:
	if (buf != NULL)
		free(buf);
	return NULL;
}

/*
 * PostgreSQL MD5 hashing.
 */

static void hash2hex(const uint8_t *hash, char *dst)
{
	int i;
	static const char hextbl [] = "0123456789abcdef";
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		*dst++ = hextbl[hash[i] >> 4];
		*dst++ = hextbl[hash[i] & 15];
	}
	*dst = 0;
}

void pg_md5_encrypt(const char *part1,
		    const char *part2, size_t part2len,
		    char *dest)
{
	MD5_CTX ctx;
	uint8_t hash[MD5_DIGEST_LENGTH];

	MD5_Init(&ctx);
	MD5_Update(&ctx, part1, strlen(part1));
	MD5_Update(&ctx, part2, part2len);
	MD5_Final(hash, &ctx);

	memcpy(dest, "md5", 3);
	hash2hex(hash, dest + 3);
}

/* wrapped for getting random bytes */
void get_random_bytes(uint8_t *dest, int len)
{
	int i;
	for (i = 0; i < len; i++)
		dest[i] = random() & 255;
}

/* set needed socket options */
void tune_socket(int sock, bool is_unix)
{
	int res;
	int val;

	/* close fd on exec */
	res = fcntl(sock, F_SETFD, FD_CLOEXEC);
	if (res < 0)
		fatal_perror("fcntl FD_CLOEXEC");

	/* when no data available, return EAGAIN instead blocking */
	socket_set_nonblocking(sock, 1);

#ifdef SO_NOSIGPIPE
	/* disallow SIGPIPE, if possible */
	val = 1;
	res = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof(val));
	if (res < 0)
		fatal_perror("setsockopt SO_NOSIGPIPE");
#endif

	/*
	 * Following options are for network sockets
	 */
	if (is_unix)
		return;

	/* the keepalive stuff needs some poking before enbling */
	if (cf_tcp_keepalive) {
		/* turn on socket keepalive */
		val = 1;
		res = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
		if (res < 0)
			fatal_perror("setsockopt SO_KEEPALIVE");
#ifdef __linux__
		/* set count of keepalive packets */
		if (cf_tcp_keepcnt > 0) {
			val = cf_tcp_keepcnt;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));
			if (res < 0)
				fatal_perror("setsockopt TCP_KEEPCNT");
		}
		/* how long the connection can stay idle before sending keepalive pkts */
		if (cf_tcp_keepidle) {
			val = cf_tcp_keepidle;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
			if (res < 0)
				fatal_perror("setsockopt TCP_KEEPIDLE");
		}
		/* time between packets */
		if (cf_tcp_keepintvl) {
			val = cf_tcp_keepintvl;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));
			if (res < 0)
				fatal_perror("setsockopt TCP_KEEPINTVL");
		}
#else
#ifdef TCP_KEEPALIVE
		if (cf_tcp_keepidle) {
			val = cf_tcp_keepidle;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &val, sizeof(val));
			if (res < 0)
				fatal_perror("setsockopt TCP_KEEPALIVE");
		}
#endif
#endif
	}

	/* set in-kernel socket buffer size */
	if (cf_tcp_socket_buffer) {
		val = cf_tcp_socket_buffer;
		res = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
		if (res < 0)
			fatal_perror("setsockopt SO_SNDBUF");
		val = cf_tcp_socket_buffer;
		res = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
		if (res < 0)
			fatal_perror("setsockopt SO_RCVBUF");
	}

	/*
	 * Turn off kernel buffering, each send() will be one packet.
	 */
	val = 1;
	res = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (res < 0)
		fatal_perror("setsockopt TCP_NODELAY");
}

/*
 * Find a string in comma-separated list.
 *
 * It does not support space inside tokens.
 */
bool strlist_contains(const char *liststr, const char *str)
{
	int c, len = strlen(str);
	const char *p, *listpos = liststr;
	
loop:
	/* find string fragment, later check if actual token */
	p = strstr(listpos, str);
	if (p == NULL)
		return false;

	/* move listpos further */
	listpos = p + len;
	/* survive len=0 and avoid unneccesary compare */
	if (*listpos)
		listpos++;

	/* check previous symbol */
	if (p > liststr) {
		c = *(p - 1);
		if (!isspace(c) && c != ',')
			goto loop;
	}

	/* check following symbol */
	c = p[len];
	if (c != 0 && !isspace(c) && c != ',')
		goto loop;

	return true;
}

void fill_remote_addr(PgSocket *sk, int fd, bool is_unix)
{
	PgAddr *dst = &sk->remote_addr;
	struct sockaddr_in adr;
	socklen_t len = sizeof(adr);
	int err;

	dst->ip_addr.s_addr = INADDR_ANY;
	dst->port = 0;
	dst->is_unix = is_unix;
	if (is_unix) {
		dst->port = cf_listen_port;
	} else {
		err = getpeername(fd, (struct sockaddr *)&adr, &len);
		if (err < 0) {
			log_error("fill_remote_addr: getpeername(%d) = %s",
				  fd, strerror(errno));
		} else {
			dst->ip_addr = adr.sin_addr;
			dst->port = ntohs(adr.sin_port);
		}
	}
}

void fill_local_addr(PgSocket *sk, int fd, bool is_unix)
{
	PgAddr *dst = &sk->local_addr;
	struct sockaddr_in adr;
	socklen_t len = sizeof(adr);
	int err;

	dst->ip_addr.s_addr = INADDR_ANY;
	dst->port = 0;
	dst->is_unix = is_unix;
	if (is_unix) {
		dst->port = cf_listen_port;
	} else {
		err = getsockname(fd, (struct sockaddr *)&adr, &len);
		if (err < 0) {
			log_error("fill_local_addr: getsockname(%d) = %s",
				  fd, strerror(errno));
		} else {
			dst->ip_addr = adr.sin_addr;
			dst->port = ntohs(adr.sin_port);
		}
	}
}

/*
 * Error handling around evtimer_add() is nasty as the code
 * may not be called again.  As there is fixed number of timers
 * in pgbouncer, provider safe_evtimer_add() that stores args of
 * failed calls in static array and retries later.
 */
#define TIMER_BACKUP_SLOTS  10

struct timer_slot {
	struct event *ev;
	struct timeval tv;
};
static struct timer_slot timer_backup_list[TIMER_BACKUP_SLOTS];
static int timer_backup_used = 0;

void safe_evtimer_add(struct event *ev, struct timeval *tv)
{
	int res;
	struct timer_slot *ts;
	
	res = evtimer_add(ev, tv);
	if (res >= 0)
		return;

	if (timer_backup_used >= TIMER_BACKUP_SLOTS)
		fatal_perror("TIMER_BACKUP_SLOTS full");

	ts = &timer_backup_list[timer_backup_used++];
	ts->ev = ev;
	ts->tv = *tv;
}

void rescue_timers(void)
{
	struct timer_slot *ts;
	while (timer_backup_used) {
		ts = &timer_backup_list[timer_backup_used - 1];
		if (evtimer_add(ts->ev, &ts->tv) < 0)
			break;
		timer_backup_used--;
	}
}

