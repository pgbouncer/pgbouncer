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
static int suspended = 0;

/* on accept() failure sleep 5 seconds */
static struct event ev_err;
static struct timeval err_timeout = {5, 0};

static void cleanup_unix_socket(void)
{
	char fn[256];
	if (!cf_unix_socket_dir || suspended)
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

#ifdef TCP_DEFER_ACCEPT
	/*
	 * Notify pooler only when also data is arrived.
	 *
	 * optval specifies how long after connection attempt to wait for data.
	 *
	 * Related to tcp_synack_retries sysctl, default 5 (corresponds 180 secs).
	 */
	if (cf_tcp_defer_accept > 0) {
		val = cf_tcp_defer_accept;
		res = setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, sizeof(val));
		if (res < 0)
			fatal_perror("setsockopt TCP_DEFER_ACCEPT");
	}
#endif

	/* finally, accept connections */
	res = listen(sock, 100);
	if (res < 0)
		fatal_perror("listen");

	log_info("listening on %s:%d", cf_listen_addr, cf_listen_port);

	return sock;
}

static void err_wait_func(int sock, short flags, void *arg)
{
	resume_pooler();
}

/* got new connection, associate it with client struct */
static void pool_accept(int sock, short flags, void *is_unix)
{
	int fd, err;
	PgSocket *client;
	union {
		struct sockaddr_in in;
		struct sockaddr_un un;
		struct sockaddr sa;
	} addr;
	socklen_t len = sizeof(addr);

loop:
	/* get fd */
	fd = accept(sock, &addr.sa, &len);
	if (fd < 0) {
		/* no more */
		if (errno == EWOULDBLOCK)
			return;

		/*
		 * probably fd limit, pointless to try often
		 * wait a bit, hope that admin resolves somehow
		 */
		log_error("accept() failed: %s", strerror(errno));
		evtimer_set(&ev_err, err_wait_func, NULL);
		err = evtimer_add(&ev_err, &err_timeout);
		if (err < 0)
			log_error("pool_accept: evtimer_add: %s", strerror(errno));
		else
			suspend_pooler();
		return;
	}

	log_noise("new fd from accept=%d", fd);
	if (is_unix) {
		log_debug("P: new unix client");
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
		log_debug("P: new tcp client");
		client = accept_client(fd, &addr.in, false);
	}

	if (!client) {
		log_warning("P: no mem for client struct");
		return;
	}

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
	suspended = 1;

	if (fd_net) {
		if (event_del(&ev_net) < 0)
			/* fixme */
			fatal_perror("event_del(ev_net)");
	}
	if (fd_unix) {
		if (event_del(&ev_unix) < 0)
			/* fixme */
			fatal_perror("event_del(ev_unix)");
	}
}

void resume_pooler(void)
{
	suspended = 0;

	if (fd_unix) {
		event_set(&ev_unix, fd_unix, EV_READ | EV_PERSIST, pool_accept, "1");
		if (event_add(&ev_unix, NULL) < 0)
			/* fixme: less serious approach? */
			fatal_perror("event_add(ev_unix)");
	}

	if (fd_net) {
		event_set(&ev_net, fd_net, EV_READ | EV_PERSIST, pool_accept, NULL);
		if (event_add(&ev_net, NULL) < 0)
			/* fixme: less serious approach? */
			fatal_perror("event_add(ev_net)");
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

