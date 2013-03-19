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

#include <usual/crypto/md5.h>

int log_socket_prefix(enum LogLevel lev, void *ctx, char *dst, unsigned int dstlen)
{
	const struct PgSocket *sock = ctx;
	const char *user, *db, *host;
	char host6[PGADDR_BUF];
	int port;

	/* no prefix */
	if (!sock)
		return 0;

	/* format prefix */
	db = sock->pool ? sock->pool->db->name : "(nodb)";
	user = sock->auth_user ? sock->auth_user->name : "(nouser)";
	if (pga_is_unix(&sock->remote_addr)) {
		host = "unix";
	} else {
		host = pga_ntop(&sock->remote_addr, host6, sizeof(host6));
	}
	port = pga_port(&sock->remote_addr);

	return snprintf(dst, dstlen, "%c-%p: %s/%s@%s:%d ",
			is_server_socket(sock) ? 'S' : 'C',
			sock, db, user, host, port);
}

const char *bin2hex(const uint8_t *src, unsigned srclen, char *dst, unsigned dstlen)
{
	unsigned int i, j;
	static const char hextbl [] = "0123456789abcdef";
	if (!dstlen)
		return "";
	if (srclen*2+1 > dstlen)
		srclen = (dstlen - 1) / 2;
	for (i = j = 0; i < srclen; i++) {
		dst[j++] = hextbl[src[i] >> 4];
		dst[j++] = hextbl[src[i] & 15];
	}
	dst[j] = 0;
	return dst;
}

/*
 * PostgreSQL MD5 hashing.
 */

static void hash2hex(const uint8_t *hash, char *dst)
{
	bin2hex(hash, MD5_DIGEST_LENGTH, dst, 16*2+1);
}

void pg_md5_encrypt(const char *part1,
		    const char *part2, size_t part2len,
		    char *dest)
{
	struct md5_ctx ctx;
	uint8_t hash[MD5_DIGEST_LENGTH];

	md5_reset(&ctx);
	md5_update(&ctx, part1, strlen(part1));
	md5_update(&ctx, part2, part2len);
	md5_final(&ctx, hash);

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
bool tune_socket(int sock, bool is_unix)
{
	int res;
	int val;

	/* close fd on exec */
	res = fcntl(sock, F_SETFD, FD_CLOEXEC);
	if (res < 0)
		goto fail;

	/* when no data available, return EAGAIN instead blocking */
	socket_set_nonblocking(sock, 1);

#ifdef SO_NOSIGPIPE
	/* disallow SIGPIPE, if possible */
	val = 1;
	res = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof(val));
	if (res < 0)
		goto fail;
#endif

	/*
	 * Following options are for network sockets
	 */
	if (is_unix)
		return true;

	/* the keepalive stuff needs some poking before enbling */
	if (cf_tcp_keepalive) {
		/* turn on socket keepalive */
		val = 1;
		res = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
		if (res < 0)
			goto fail;
#ifdef __linux__
		/* set count of keepalive packets */
		if (cf_tcp_keepcnt > 0) {
			val = cf_tcp_keepcnt;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));
			if (res < 0)
				goto fail;
		}
		/* how long the connection can stay idle before sending keepalive pkts */
		if (cf_tcp_keepidle) {
			val = cf_tcp_keepidle;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
			if (res < 0)
				goto fail;
		}
		/* time between packets */
		if (cf_tcp_keepintvl) {
			val = cf_tcp_keepintvl;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));
			if (res < 0)
				goto fail;
		}
#else
#ifdef TCP_KEEPALIVE
		if (cf_tcp_keepidle) {
			val = cf_tcp_keepidle;
			res = setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &val, sizeof(val));
			if (res < 0)
				goto fail;
		}
#endif
#endif
	}

	/* set in-kernel socket buffer size */
	if (cf_tcp_socket_buffer) {
		val = cf_tcp_socket_buffer;
		res = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
		if (res < 0)
			goto fail;
		val = cf_tcp_socket_buffer;
		res = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
		if (res < 0)
			goto fail;
	}

	/*
	 * Turn off kernel buffering, each send() will be one packet.
	 */
	val = 1;
	res = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (res < 0)
		goto fail;
	return true;
fail:
	log_warning("tune_socket(%d) failed: %s", sock, strerror(errno));
	return false;
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
	socklen_t len = sizeof(PgAddr);
	int err;

	if (is_unix) {
		pga_set(dst, AF_UNIX, cf_listen_port);
	} else {
		err = getpeername(fd, (struct sockaddr *)dst, &len);
		if (err < 0) {
			log_error("fill_remote_addr: getpeername(%d) = %s",
				  fd, strerror(errno));
		}
	}
}

void fill_local_addr(PgSocket *sk, int fd, bool is_unix)
{
	PgAddr *dst = &sk->local_addr;
	socklen_t len = sizeof(PgAddr);
	int err;

	if (is_unix) {
		pga_set(dst, AF_UNIX, cf_listen_port);
	} else {
		err = getsockname(fd, (struct sockaddr *)dst, &len);
		if (err < 0) {
			log_error("fill_local_addr: getsockname(%d) = %s",
				  fd, strerror(errno));
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


/*
 * PgAddr operations
 */

int pga_port(const PgAddr *a)
{
	if (a->sa.sa_family == AF_INET6) {
		return ntohs(a->sin6.sin6_port);
	} else {
		return ntohs(a->sin.sin_port);
	}
}

/* set family and port */
void pga_set(PgAddr *a, int af, int port)
{
	memset(a, 0, sizeof(*a));
	if (af == AF_INET6) {
		a->sin6.sin6_family = af;
		a->sin6.sin6_port = htons(port);
	} else {
		a->sin.sin_family = af;
		a->sin.sin_port = htons(port);
	}
}

/* copy sockaddr_in/in6 to PgAddr */
void pga_copy(PgAddr *a, const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		memcpy(&a->sin, sa, sizeof(a->sin));
		break;
	case AF_INET6:
		memcpy(&a->sin6, sa, sizeof(a->sin6));
		break;
	case AF_UNIX:
		log_error("pga_copy: AF_UNIX copy not supported");
	}
}

static inline unsigned pga_family(const PgAddr *a)
{
	return a->sa.sa_family;
}

int pga_cmp_addr(const PgAddr *a, const PgAddr *b)
{
    if (pga_family(a) != pga_family(b))
		return pga_family(a) - pga_family(b);

	switch (pga_family(a)) {
	case AF_INET:
		return memcmp(&a->sin.sin_addr, &b->sin.sin_addr, sizeof(a->sin.sin_addr));
		break;
	case AF_INET6:
		return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, sizeof(a->sin6.sin6_addr));
		break;
	default:
		log_error("pga_cmp_addr: unsupported family");
		return 0;
	}
}

/* convert pgaddr to string */
const char *pga_ntop(const PgAddr *a, char *dst, int dstlen)
{
	const char *res = NULL;
	char buf[PGADDR_BUF];

	memset(buf, 0, sizeof(buf));

	switch (pga_family(a)) {
	case AF_UNIX:
		res = "unix";
		break;
	case AF_INET:
		res = inet_ntop(AF_INET, &a->sin.sin_addr, buf, sizeof(buf));
		break;
	case AF_INET6:
		res = inet_ntop(AF_INET6, &a->sin6.sin6_addr, buf, sizeof(buf));
		break;
	default:
		res = "(bad-af)";
	}
	if (res == NULL)
		res = "(err-ntop)";

	strlcpy(dst, res, dstlen);
	return dst;
}

/* parse address from string */
bool pga_pton(PgAddr *a, const char *s, int port)
{
	int res = 1;
	if (strcmp(s, "unix") == 0) {
		pga_set(a, AF_UNIX, port);
	} else if (strcmp(s, "*") == 0) {
		pga_set(a, AF_INET, port);
		a->sin.sin_addr.s_addr = htonl(INADDR_ANY);
	} else if (strchr(s, ':')) {
		pga_set(a, AF_INET6, port);
		res = inet_pton(AF_INET6, s, &a->sin6.sin6_addr);
	} else {
		pga_set(a, AF_INET, port);
		res = inet_pton(AF_INET, s, &a->sin.sin_addr);
	}
	if (res == 0)
		errno = EINVAL;
	return res > 0;
}

const char *pga_str(const PgAddr *a, char *dst, int dstlen)
{
	char buf[PGADDR_BUF];
	pga_ntop(a, buf, sizeof(buf));
	snprintf(dst, dstlen, "%s@%d", buf, pga_port(a));
	return dst;
}
