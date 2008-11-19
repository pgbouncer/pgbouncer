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
 * Handling of pooler listening sockets
 */

#include "bouncer.h"

static int fd_net = 0;
static int fd_unix = 0;

static struct event ev_net;
static struct event ev_unix;

/* if sockets are registered in libevent */
static bool reg_net = false;
static bool reg_unix = false;

/* should listening sockets be active or suspended? */
static bool pooler_active = false;

/* on accept() failure sleep 5 seconds */
static struct event ev_err;
static struct timeval err_timeout = {5, 0};

/* atexit() cleanup func */
static void cleanup_unix_socket(void)
{
	char fn[256];

	/* avoid cleanup if exit() while suspended */
	if (!reg_unix)
		return;

	snprintf(fn, sizeof(fn), "%s/.s.PGSQL.%d",
			cf_unix_socket_dir, cf_listen_port);
	unlink(fn);
}

void get_pooler_fds(int *p_net, int *p_unix)
{
	*p_net = fd_net;
	*p_unix = fd_unix;
}

static int create_unix_socket(const char *socket_dir, int listen_port)
{
	struct sockaddr_un un;
	int res, sock;
	char lockfile[256];
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

	/* create socket */
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		fatal_perror("socket");

	/* bind it */
	res = bind(sock, (const struct sockaddr *)&un, sizeof(un));
	if (res < 0)
		fatal_perror("bind");

	/* remove socket on shutdown */
	atexit(cleanup_unix_socket);

	/* set common options */
	tune_socket(sock, true);

	/* finally, accept connections */
	res = listen(sock, 100);
	if (res < 0)
		fatal_perror("listen");

	res = chmod(un.sun_path, 0777);
	if (res < 0)
		fatal_perror("chmod");

	log_info("listening on unix:%s", un.sun_path);

	return sock;
}

/*
 * Notify pooler only when also data is arrived.
 *
 * optval specifies how long after connection attempt to wait for data.
 *
 * Related to tcp_synack_retries sysctl, default 5 (corresponds 180 secs).
 *
 * SO_ACCEPTFILTER needs to be set after listern(), maybe TCP_DEFER_ACCEPT too.
 */
static void tune_accept(int sock, bool on)
{
	const char *act = on ? "install" : "uninstall";
	int res = 0;
#ifdef TCP_DEFER_ACCEPT
	int val = 45; /* fixme: proper value */
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
	if (fd_net > 0)
		tune_accept(fd_net, on);
}

static int create_net_socket(const char *listen_addr, int listen_port)
{
	int sock;
	struct sockaddr_in sa;
	int res;
	int val;

	/* create socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		fatal_perror("socket");

	/* parse address */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(cf_listen_port);
	if (strcmp(listen_addr, "*") == 0) {
		sa.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		sa.sin_addr.s_addr = inet_addr(listen_addr);
		if (sa.sin_addr.s_addr == INADDR_NONE)
			fatal("cannot parse addr: '%s'", listen_addr);
	}

	/* relaxed binding */
	val = 1;
	res = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if (res < 0)
		fatal_perror("setsockopt");

	/* bind to address */
	res = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
	if (res < 0)
		fatal_perror("bind");

	/* set common options */
	tune_socket(sock, false);

	/* make it accept connections */
	res = listen(sock, 100);
	if (res < 0)
		fatal_perror("listen");

	tune_accept(sock, cf_tcp_defer_accept);

	log_info("listening on %s:%d", cf_listen_addr, cf_listen_port);

	return sock;
}

static void err_wait_func(int sock, short flags, void *arg)
{
	if (cf_pause_mode != P_SUSPEND)
		resume_pooler();
}

static const char *addrpair(const PgAddr *src, const PgAddr *dst)
{
	static char ip1buf[64], ip2buf[64], buf[256];
	const char *ip1, *ip2;
	if (src->is_unix)
		return "unix->unix";

	ip1 = inet_ntop(AF_INET, &src->ip_addr, ip1buf, sizeof(ip1buf));
	if (!ip1)
		ip1 = strerror(errno);
	ip2 = inet_ntop(AF_INET, &dst->ip_addr, ip2buf, sizeof(ip2buf));
	if (!ip2)
		ip2 = strerror(errno);
	snprintf(buf, sizeof(buf), "%s:%d -> %s:%d",
		 ip1, src->port, ip2, dst->port);
	return buf;
}

static const char *conninfo(const PgSocket *sk)
{
	if (is_server_socket(sk))
		return addrpair(&sk->local_addr, &sk->remote_addr);
	else
		return addrpair(&sk->remote_addr, &sk->local_addr);
}

/* got new connection, associate it with client struct */
static void pool_accept(int sock, short flags, void *is_unix)
{
	int fd;
	PgSocket *client;
	union {
		struct sockaddr_in in;
		struct sockaddr_un un;
		struct sockaddr sa;
	} addr;
	socklen_t len = sizeof(addr);

loop:
	/* get fd */
	fd = safe_accept(sock, &addr.sa, &len);
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
		{
			uid_t uid;
			gid_t gid;
			log_noise("getuid(): %d", (int)getuid());
			if (getpeereid(fd, &uid, &gid) >= 0)
				log_noise("unix peer uid: %d", (int)uid);
			else
				log_warning("unix peer uid failed: %s", strerror(errno));
		}
		client = accept_client(fd, NULL, true);
	} else {
		client = accept_client(fd, &addr.in, false);
	}

	slog_debug(client, "P: got connection: %s", conninfo(client));

	/*
	 * there may be several clients waiting,
	 * avoid context switch by looping
	 */
	goto loop;
}

bool use_pooler_socket(int sock, bool is_unix)
{
	tune_socket(sock, is_unix);

	if (is_unix)
		fd_unix = sock;
	else
		fd_net = sock;
	return true;
}

void suspend_pooler(void)
{
	pooler_active = false;

	if (fd_net && reg_net) {
		if (event_del(&ev_net) < 0) {
			log_warning("suspend_pooler, event_del: %s", strerror(errno));
			return;
		}
		reg_net = false;
	}
	if (fd_unix && reg_unix) {
		if (event_del(&ev_unix) < 0) {
			log_warning("suspend_pooler, event_del: %s", strerror(errno));
			return;
		}
		reg_unix = false;
	}
}

void resume_pooler(void)
{
	pooler_active = true;

	if (fd_unix && !reg_unix) {
		event_set(&ev_unix, fd_unix, EV_READ | EV_PERSIST, pool_accept, "1");
		if (event_add(&ev_unix, NULL) < 0) {
			log_warning("event_add failed: %s", strerror(errno));
			return;
		}
		reg_unix = true;
	}

	if (fd_net && !reg_net) {
		event_set(&ev_net, fd_net, EV_READ | EV_PERSIST, pool_accept, NULL);
		if (event_add(&ev_net, NULL) < 0) {
			log_warning("event_add failed: %s", strerror(errno));
		}
		reg_net = true;
	}
}

/* listen on socket - should happen after all other initializations */
void pooler_setup(void)
{
	if (cf_listen_addr && !fd_net)
		fd_net = create_net_socket(cf_listen_addr, cf_listen_port);

	if (cf_unix_socket_dir && !fd_unix)
		fd_unix = create_unix_socket(cf_unix_socket_dir, cf_listen_port);

	if (!fd_net && !fd_unix)
		fatal("nowhere to listen on");

	resume_pooler();
}

/* retry previously failed suspend_pooler() / resume_pooler() */
void per_loop_pooler_maint(void)
{
	if (pooler_active) {
		if ((fd_unix && !reg_unix) || (fd_net && !reg_net))
			resume_pooler();
	} else {
		if ((fd_unix && reg_unix) || (fd_net && reg_net))
			suspend_pooler();
	}
}

