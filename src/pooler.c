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
 * Handling of pooler listening sockets
 */

#include "bouncer.h"

#include <usual/netdb.h>

struct ListenSocket {
	struct List node;
	int fd;
	bool active;
	struct event ev;
	PgAddr addr;
};

static STATLIST(sock_list);

/* hints for getaddrinfo(listen_addr) */
static const struct addrinfo hints = {
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = IPPROTO_TCP,
	.ai_flags = AI_PASSIVE,
};

/* should listening sockets be active or suspended? */
static bool need_active = false;
/* is it actually active or suspended? */
static bool pooler_active = false;

/* on accept() failure sleep 5 seconds */
static struct event ev_err;
static struct timeval err_timeout = {5, 0};

static void tune_accept(int sock, bool on);

/* atexit() cleanup func */
static void cleanup_sockets(void)
{
	struct ListenSocket *ls;
	struct List *el;

	/* avoid cleanup if exit() while suspended */
	if (cf_pause_mode == P_SUSPEND)
		return;

	while ((el = statlist_pop(&sock_list)) != NULL) {
		ls = container_of(el, struct ListenSocket, node);
		if (ls->fd > 0) {
			safe_close(ls->fd);
			ls->fd = 0;
		}
		if (pga_is_unix(&ls->addr)) {
			char buf[sizeof(struct sockaddr_un) + 20];
			snprintf(buf, sizeof(buf), "%s/.s.PGSQL.%d", cf_unix_socket_dir, cf_listen_port);
			unlink(buf);
		}
		statlist_remove(&sock_list, &ls->node);
		free(ls);
	}
}

/*
 * initialize another listening socket.
 */
static bool add_listen(int af, const struct sockaddr *sa, int salen)
{
	struct ListenSocket *ls;
	int sock, res;
	char buf[128];
	const char *errpos;

	log_debug("add_listen: %s", sa2str(sa, buf, sizeof(buf)));

	/* create socket */
	errpos = "socket";
	sock = socket(af, SOCK_STREAM, 0);
	if (sock < 0)
		goto failed;

	/* SO_REUSEADDR behaviour it default in WIN32.  */
#ifndef WIN32
	/* relaxed binding */
	if (af != AF_UNIX) {
		int val = 1;
		errpos = "setsockopt";
		res = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
		if (res < 0)
			goto failed;
	}
#endif

#ifdef IPV6_V6ONLY
	/* avoid ipv6 socket's attempt to takeover ipv4 port */
	if (af == AF_INET6) {
		int val = 1;
		errpos = "setsockopt/IPV6_V6ONLY";
		res = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
		if (res < 0)
			goto failed;
	}
#endif

	/* bind it */
	errpos = "bind";
	res = bind(sock, sa, salen);
	if (res < 0)
		goto failed;

	/* set common options */
	errpos = "tune_socket";
	if (!tune_socket(sock, (af == AF_UNIX)))
		goto failed;

	/* finally, accept connections */
	errpos = "listen";
	res = listen(sock, cf_listen_backlog);
	if (res < 0)
		goto failed;

	errpos = "calloc";
	ls = calloc(1, sizeof(*ls));
	if (!ls)
		goto failed;

	list_init(&ls->node);
	ls->fd = sock;
	if (sa->sa_family == AF_UNIX) {
		pga_set(&ls->addr, AF_UNIX, cf_listen_port);
	} else {
		pga_copy(&ls->addr, sa);
	}

	if (af == AF_UNIX) {
		struct sockaddr_un *un = (struct sockaddr_un *)sa;
		change_file_mode(un->sun_path, cf_unix_socket_mode, NULL, cf_unix_socket_group);
	} else {
		tune_accept(sock, cf_tcp_defer_accept);
	}

	log_info("listening on %s", sa2str(sa, buf, sizeof(buf)));
	statlist_append(&sock_list, &ls->node);
	return true;

failed:
	log_warning("cannot listen on %s: %s(): %s",
		    sa2str(sa, buf, sizeof(buf)),
		    errpos, strerror(errno));
	if (sock >= 0)
		safe_close(sock);
	return false;
}

static void create_unix_socket(const char *socket_dir, int listen_port)
{
	struct sockaddr_un un;
	int res;
	char lockfile[sizeof(struct sockaddr_un) + 10];
	struct stat st;

	/* fill sockaddr struct */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	snprintf(un.sun_path, sizeof(un.sun_path),
		"%s/.s.PGSQL.%d", socket_dir, listen_port);

	/* check for lockfile */
	snprintf(lockfile, sizeof(lockfile), "%s.lock", un.sun_path);
	res = lstat(lockfile, &st);
	if (res == 0)
		fatal("unix port %d is in use", listen_port);

	/* expect old bouncer gone */
	unlink(un.sun_path);

	add_listen(AF_UNIX, (const struct sockaddr *)&un, sizeof(un));
}

/*
 * Notify pooler only when also data is arrived.
 *
 * optval specifies how long after connection attempt to wait for data.
 *
 * Related to tcp_synack_retries sysctl, default 5 (corresponds 180 secs).
 *
 * SO_ACCEPTFILTER needs to be set after listen(), maybe TCP_DEFER_ACCEPT too.
 */
static void tune_accept(int sock, bool on)
{
	const char *act = on ? "install" : "uninstall";
	int res = 0;
#ifdef TCP_DEFER_ACCEPT
	int val = 45; /* FIXME: proper value */
	socklen_t vlen = sizeof(val);
	res = getsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, &vlen);
	log_noise("old TCP_DEFER_ACCEPT on %d = %d", sock, val);
	val = on ? 1 : 0;
	log_noise("%s TCP_DEFER_ACCEPT on %d", act, sock);
	res = setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, sizeof(val));
#else
#if 0
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg af, *afp = on ? &af : NULL;
	socklen_t af_len = on ? sizeof(af) : 0;
	memset(&af, 0, sizeof(af));
	strcpy(af.af_name, "dataready");
	log_noise("%s SO_ACCEPTFILTER on %d", act, sock);
	res = setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, afp, af_len);
#endif
#endif
#endif
	if (res < 0)
		log_warning("tune_accept: %s TCP_DEFER_ACCEPT/SO_ACCEPTFILTER: %s",
			    act, strerror(errno));
}

void pooler_tune_accept(bool on)
{
	struct List *el;
	struct ListenSocket *ls;
	statlist_for_each(el, &sock_list) {
		ls = container_of(el, struct ListenSocket, node);
		if (!pga_is_unix(&ls->addr))
			tune_accept(ls->fd, on);
	}
}

static void err_wait_func(evutil_socket_t sock, short flags, void *arg)
{
	if (cf_pause_mode != P_SUSPEND)
		resume_pooler();
}

static const char *addrpair(const PgAddr *src, const PgAddr *dst)
{
	static char ip1buf[PGADDR_BUF], ip2buf[PGADDR_BUF],
	            buf[2*PGADDR_BUF + 16];
	const char *ip1, *ip2;
	if (pga_is_unix(src))
		return "unix->unix";

	ip1 = pga_ntop(src, ip1buf, sizeof(ip1buf));
	ip2 = pga_ntop(src, ip2buf, sizeof(ip2buf));
	snprintf(buf, sizeof(buf), "%s:%d -> %s:%d",
		 ip1, pga_port(src), ip2, pga_port(dst));
	return buf;
}

static const char *conninfo(const PgSocket *sk)
{
	if (is_server_socket(sk)) {
		return addrpair(&sk->local_addr, &sk->remote_addr);
	} else {
		return addrpair(&sk->remote_addr, &sk->local_addr);
	}
}

/* got new connection, associate it with client struct */
static void pool_accept(evutil_socket_t sock, short flags, void *arg)
{
	struct ListenSocket *ls = arg;
	int fd;
	PgSocket *client;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr_un un;
		struct sockaddr sa;
	} raddr;
	socklen_t len = sizeof(raddr);
	bool is_unix = pga_is_unix(&ls->addr);

	if(!(flags & EV_READ)) {
		log_warning("no EV_READ in pool_accept");
		return;
	}
loop:
	/* get fd */
	fd = safe_accept(sock, &raddr.sa, &len);
	if (fd < 0) {
		if (errno == EAGAIN)
			return;
		else if (errno == ECONNABORTED)
			return;

		/*
		 * probably fd limit, pointless to try often
		 * wait a bit, hope that admin resolves somehow
		 */
		log_error("accept() failed: %s", strerror(errno));
		evtimer_set(&ev_err, err_wait_func, NULL);
		safe_evtimer_add(&ev_err, &err_timeout);
		suspend_pooler();
		return;
	}

	log_noise("new fd from accept=%d", fd);
	if (is_unix) {
		client = accept_client(fd, true);
	} else {
		client = accept_client(fd, false);
	}

	if (client)
		slog_debug(client, "P: got connection: %s", conninfo(client));

	/*
	 * there may be several clients waiting,
	 * avoid context switch by looping
	 */
	goto loop;
}

bool use_pooler_socket(int sock, bool is_unix)
{
	struct ListenSocket *ls;
	int res;
	char buf[PGADDR_BUF];

	if (!tune_socket(sock, is_unix))
		return false;

	ls = calloc(1, sizeof(*ls));
	if (!ls)
		return false;
	ls->fd = sock;
	if (is_unix) {
		pga_set(&ls->addr, AF_UNIX, cf_listen_port);
	} else {
		struct sockaddr_storage ss;
		socklen_t len = sizeof(ss);
		res = getsockname(sock, (struct sockaddr *)&ss, &len);
		if (res < 0) {
			log_error("getsockname failed");
			free(ls);
			return false;
		}
		pga_copy(&ls->addr, (struct sockaddr *)&ss);
	}
	log_info("got pooler socket: %s", pga_str(&ls->addr, buf, sizeof(buf)));
	statlist_append(&sock_list, &ls->node);
	return true;
}

void suspend_pooler(void)
{
	struct List *el;
	struct ListenSocket *ls;

	need_active = false;
	statlist_for_each(el, &sock_list) {
		ls = container_of(el, struct ListenSocket, node);
		if (!ls->active)
			continue;
		if (event_del(&ls->ev) < 0) {
			log_warning("suspend_pooler, event_del: %s", strerror(errno));
			return;
		}
		ls->active = false;
	}
	pooler_active = false;
}

void resume_pooler(void)
{
	struct List *el;
	struct ListenSocket *ls;

	need_active = true;
	statlist_for_each(el, &sock_list) {
		ls = container_of(el, struct ListenSocket, node);
		if (ls->active)
			continue;
		event_set(&ls->ev, ls->fd, EV_READ | EV_PERSIST, pool_accept, ls);
		if (event_add(&ls->ev, NULL) < 0) {
			log_warning("event_add failed: %s", strerror(errno));
			return;
		}
		ls->active = true;
	}
	pooler_active = true;
}

/* retry previously failed suspend_pooler() / resume_pooler() */
void per_loop_pooler_maint(void)
{
	if (need_active && !pooler_active)
		resume_pooler();
	else if (!need_active && pooler_active)
		suspend_pooler();
}

static bool parse_addr(void *arg, const char *addr)
{
	int res;
	char service[64];
	struct addrinfo *ai, *gaires = NULL;
	bool ok;

	if (!*addr)
		return true;
	if (strcmp(addr, "*") == 0)
		addr = NULL;
	snprintf(service, sizeof(service), "%d", cf_listen_port);

	res = getaddrinfo(addr, service, &hints, &gaires);
	if (res != 0) {
		fatal("getaddrinfo('%s', '%d') = %s [%d]", addr ? addr : "*",
		      cf_listen_port, gai_strerror(res), res);
	}

	for (ai = gaires; ai; ai = ai->ai_next) {
		ok = add_listen(ai->ai_family, ai->ai_addr, ai->ai_addrlen);
		/* it's unclear whether all or only first result should be used */
		if (0 && ok)
			break;
	}

	freeaddrinfo(gaires);
	return true;
}

/* listen on socket - should happen after all other initializations */
void pooler_setup(void)
{
	bool ok;
	static int init_done = 0;

	if (!init_done) {
		/* remove socket on shutdown */
		atexit(cleanup_sockets);
		init_done = 1;
	}

	ok = parse_word_list(cf_listen_addr, parse_addr, NULL);
	if (!ok)
		fatal("failed to parse listen_addr list: %s", cf_listen_addr);

	if (cf_unix_socket_dir && *cf_unix_socket_dir)
		create_unix_socket(cf_unix_socket_dir, cf_listen_port);

	if (!statlist_count(&sock_list))
		fatal("nowhere to listen on");

	resume_pooler();
}

bool for_each_pooler_fd(pooler_cb cbfunc, void *arg)
{
	struct List *el;
	struct ListenSocket *ls;
	bool ok;

	statlist_for_each(el, &sock_list) {
		ls = container_of(el, struct ListenSocket, node);
		ok = cbfunc(arg, ls->fd, &ls->addr);
		if (!ok)
			return false;
	}
	return true;
}
