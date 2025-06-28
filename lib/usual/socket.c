/*
 * Socket helpers and compat.
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

#include <usual/socket.h>

#include <string.h>
#include <stdio.h>

#ifdef HAVE_UCRED_H
#include <ucred.h>
#endif
#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif

/* toggle non-blocking flag */
bool socket_set_nonblocking(int fd, bool non_block)
{
	int flags;

	/* get old flags */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return false;

	/* flip O_NONBLOCK */
	if (non_block)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	/* set new flags */
	if (fcntl(fd, F_SETFL, flags) < 0)
		return false;
	return true;
}

/* initial socket setup */
bool socket_setup(int sock, bool non_block)
{
	int res;

#ifdef SO_NOSIGPIPE
	/* disallow SIGPIPE, if possible */
	int val = 1;
	res = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof(val));
	if (res < 0)
		return false;
#endif

	/* close fd on exec */
	res = fcntl(sock, F_SETFD, FD_CLOEXEC);
	if (res < 0)
		return false;

	/* when no data available, return EAGAIN instead blocking */
	if (!socket_set_nonblocking(sock, non_block))
		return false;

	return true;
}

bool socket_set_keepalive(int fd, int onoff, int keepidle, int keepintvl, int keepcnt)
{
	int val, res;

	if (!onoff) {
		/* turn keepalive off */
		val = 0;
		res = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
		return (res == 0);
	}

	/* turn keepalive on */
	val = 1;
	res = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
	if (res < 0)
		return false;

	/* Darwin */
#ifdef TCP_KEEPALIVE
	if (keepidle) {
		val = keepidle;
		res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &val, sizeof(val));
		if (res < 0 && errno != ENOPROTOOPT)
			return false;
	}
#endif

	/* Linux, NetBSD */
#ifdef TCP_KEEPIDLE
	if (keepidle) {
		val = keepidle;
		res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
		if (res < 0 && errno != ENOPROTOOPT)
			return false;
	}
#endif
#ifdef TCP_KEEPINTVL
	if (keepintvl) {
		val = keepintvl;
		res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));
		if (res < 0 && errno != ENOPROTOOPT)
			return false;
	}
#endif
#ifdef TCP_KEEPCNT
	if (keepcnt > 0) {
		val = keepcnt;
		res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));
		if (res < 0 && errno != ENOPROTOOPT)
			return false;
	}
#endif

	/* Windows */
#ifdef SIO_KEEPALIVE_VALS
	if (keepidle || keepintvl) {
		struct tcp_keepalive vals;
		DWORD outlen = 0;
		if (!keepidle) keepidle = 5 * 60;
		if (!keepintvl) keepintvl = 15;
		vals.onoff = 1;
		vals.keepalivetime = keepidle * 1000;
		vals.keepaliveinterval = keepintvl * 1000;
		res = WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals), NULL, 0, &outlen, NULL, NULL);
		if (res != 0)
			return false;
	}
#endif
	return true;
}

/*
 * Convert sockaddr to string.  Supports ipv4, ipv6 and unix sockets.
 */
const char *sa2str(const struct sockaddr *sa, char *dst, size_t dstlen)
{
	const struct sockaddr_in *in;
	const struct sockaddr_in6 *in6;
	const struct sockaddr_un *un;
	const char *tmp;
	char buf[128];
	switch (sa->sa_family) {
	case AF_INET:
		in = (struct sockaddr_in *)sa;
		tmp = inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf));
		if (!tmp)
			return NULL;
		snprintf(dst, dstlen, "%s:%d", tmp, ntohs(in->sin_port));
		break;
	case AF_INET6:
		in6 = (struct sockaddr_in6 *)sa;
		tmp = inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf));
		if (!tmp)
			return NULL;
		snprintf(dst, dstlen, "[%s]:%d", tmp, ntohs(in6->sin6_port));
		break;
	case AF_UNIX:
		un = (struct sockaddr_un *)sa;
		if (un->sun_path[0] == '\0' && un->sun_path[1] != '\0')
			snprintf(dst, dstlen, "unix:@%s", un->sun_path + 1);
		else
			snprintf(dst, dstlen, "unix:%s", un->sun_path);
		break;
	default:
		snprintf(dst, dstlen, "sa2str(%d): unknown proto", sa->sa_family);
		break;
	}
	return dst;
}

#ifndef HAVE_GETPEEREID

/*
 * Get other side's uid and gid for UNIX socket.
 */
int getpeereid(int fd, uid_t *uid_p, gid_t *gid_p)
{
	pid_t pid;
	return getpeercreds(fd, uid_p, gid_p, &pid);
}

#endif

/*
 * Get uid, gid and pid of unix socket peer.
 *
 * Pid may not be availalbe on some OSes.
 * It's set to 0 then.
 */
int getpeercreds(int fd, uid_t *uid_p, gid_t *gid_p, pid_t *pid_p)
{
	/* What a mess */

#if defined(SO_PEERCRED)
	/* linux and others */
#if defined(HAVE_SYS_UCRED_H)
	struct sockpeercred cred;	/* openbsd */
#else
	struct ucred cred;		/* linux */
#endif
	socklen_t len = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
		*uid_p = cred.uid;
		*gid_p = cred.gid;
		*pid_p = cred.pid;
		return 0;
	}
	return -1;
#elif defined(HAVE_GETPEERUCRED)
	/* solaris */
	ucred_t *cred = NULL;
	if (getpeerucred(fd, &cred) == 0) {
		*uid_p = ucred_geteuid(cred);
		*gid_p = ucred_getegid(cred);
		*pid_p = ucred_getpid(cred);
		ucred_free(cred);
		if ((int)*uid_p == -1 || (int)*gid_p == -1)
			return -1;
		return 0;
	}
	return -1;
#elif defined(LOCAL_PEEREID)
	/* netbsd */
	struct unpcbid cred;
	socklen_t len = sizeof(cred);
	if (getsockopt(fd, 0, LOCAL_PEEREID, &cred, &len) != 0)
		return -1;
	*uid_p = cred.unp_euid;
	*gid_p = cred.unp_egid;
	*pid_p = cred.unp_pid;
	return 0;
#elif defined(HAVE_GETPEEREID)
	/* generic bsd; no pid */
	*pid_p = 0;
	return getpeereid(fd, uid_p, gid_p) == 0 ? 0 : -1;
#elif defined(LOCAL_PEERCRED)
	/* freebsd, osx, dfly; no pid */
	struct xucred cred;
	socklen_t len = sizeof(cred);
	if (getsockopt(fd, 0, LOCAL_PEERCRED, &cred, &len) != 0)
		return -1;
	if (cred.cr_version != XUCRED_VERSION) {
		errno = EINVAL;
		return -1;
	}
	*uid_p = cred.cr_uid;
	*gid_p = cred.cr_gid;
	*pid_p = 0;
	return 0;
#else
	/* no implementation */
	errno = ENOSYS;
	return -1;
#endif
}


#ifndef HAVE_POLL
/*
 * Emulate poll() with select()
 */

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

/*
 * dynamic buffer for fd_set to avoid depending on FD_SETSIZE
 */

struct fd_buf {
	fd_set *set;
	int alloc_bytes;
};

static void fdbuf_zero(struct fd_buf *buf)
{
	if (buf->set)
		memset(buf->set, 0, buf->alloc_bytes);
}

static bool fdbuf_resize(struct fd_buf *buf, int fd)
{
	int need_bytes;
	unsigned char *ptr;
	/* default allocation */
	int alloc = sizeof(fd_set);

#ifdef WIN32
	int cnt = buf->set ? buf->set->fd_count : 0;
	/* win32 fd_set is array of handles, +8 for count&padding */
	need_bytes = (cnt + 1) * sizeof(buf->set->fd_array[0]) + 8;
#else
	/* otherwise, fd_set is bitmap, +8 for int/long alignment */
	need_bytes = fd / 8 + 8;
#endif

	if (buf->alloc_bytes < need_bytes) {
		while (alloc < need_bytes)
			alloc *= 2;

		if (!buf->set)
			ptr = malloc(alloc);
		else
			ptr = realloc(buf->set, alloc);

		if (!ptr)
			return false;

		/* clean new area */
		memset(ptr + buf->alloc_bytes, 0, alloc - buf->alloc_bytes);

		buf->set = (fd_set *)ptr;
		buf->alloc_bytes = alloc;
	}
	return true;
}

/* win32: make macros ignore FD_SETSIZE */
#undef FD_SETSIZE
#define FD_SETSIZE (1 << 30)

int poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	static struct fd_buf readfds = { NULL, 0 };
	static struct fd_buf writefds = { NULL, 0 };

	struct pollfd *pf;
	int res, fd_max = 0;
	struct timeval *tv = NULL;
	struct timeval tvreal;
	unsigned i;

	/* convert timeout_ms to timeval */
	if (timeout_ms >= 0) {
		tvreal.tv_sec = timeout_ms / 1000;
		tvreal.tv_usec = (timeout_ms % 1000) * 1000;
		tv = &tvreal;
	} else if (timeout_ms < -1) {
		goto err_inval;
	}

	/*
	 * Convert pollfds to fd sets.
	 */
	fdbuf_zero(&readfds);
	fdbuf_zero(&writefds);
	for (i = 0; i < nfds; i++) {
		pf = fds + i;
		if (pf->fd < 0)
			goto err_badf;

		/* sets must be equal size */
		if (!fdbuf_resize(&readfds, pf->fd))
			goto err_nomem;
		if (!fdbuf_resize(&writefds, pf->fd))
			goto err_nomem;

		if (pf->events & POLLIN)
			FD_SET((unsigned)pf->fd, readfds.set);
		if (pf->events & POLLOUT)
			FD_SET((unsigned)pf->fd, writefds.set);
		if (pf->fd > fd_max)
			fd_max = pf->fd;
	}

	res = select(fd_max + 1, readfds.set, writefds.set, NULL, tv);
	if (res <= 0)
		return res;

	/*
	 * select() and poll() count fd-s differently,
	 * need to recount them here.
	 */
	res = 0;

	for (i = 0; i < nfds; i++) {
		pf = fds + i;
		pf->revents = 0;
		if ((pf->events & POLLIN) && FD_ISSET(pf->fd, readfds.set))
			pf->revents |= POLLIN;
		if ((pf->events & POLLOUT) && FD_ISSET(pf->fd, writefds.set))
			pf->revents |= POLLOUT;
		if (pf->revents)
			res += 1;
	}
	return res;

err_nomem:
	errno = ENOMEM;
	return -1;

err_badf:
	errno = EBADF;
	return -1;
err_inval:
	errno = EINVAL;
	return -1;
}

#endif /* PLPROXY_POLL_COMPAT */

#ifdef WIN32
/* create local TCP socket, idea from libevent/Tor */
int win32_socketpair(int d, int typ, int proto, int sv[2])
{
	int list = -1, s1 = -1, s2 = -1;
	struct sockaddr_in sa1, sa2;
	socklen_t slen = sizeof(sa1);
	int res;

	if (d != AF_INET && d != AF_UNIX)
		goto err_inval;
	if (proto || !sv)
		goto err_inval;

	/* prepare sockaddr for bind */
	memset(&sa1, 0, sizeof(sa1));
	sa1.sin_family = AF_INET;
	sa1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa1.sin_port = htons(0);

	/* create listen socket */
	list = socket(AF_INET, typ, 0);
	if (list == -1)
		return -1;
	res = bind(list, (struct sockaddr *)&sa1, sizeof(sa1));
	if (res == -1)
		goto failed;
	res = listen(list, 1);
	if (res == -1)
		goto failed;

	/* read listen port */
	res = getsockname(list, (struct sockaddr *)&sa1, &slen);
	if (res == -1 || slen != sizeof(sa1))
		goto failed;

	/* connect to it */
	s1 = socket(AF_INET, typ, 0);
	if (s1 == -1)
		goto failed;
	res = connect(s1, (struct sockaddr *)&sa1, sizeof(sa1));
	if (res == -1)
		goto failed;

	/* and accept from other end */
	s2 = accept(list, (struct sockaddr *)&sa2, &slen);
	if (s2 == -1 || slen != sizeof(sa2))
		goto failed;

	/* sanity check */
	res = getsockname(s1, (struct sockaddr *)&sa1, &slen);
	if (res == -1 || slen != sizeof(sa1))
		goto failed;
	if (sa1.sin_port != sa2.sin_port)
		goto failed;

	closesocket(list);
	sv[0] = s1;
	sv[1] = s2;
	return 0;

failed:
	errno = (res == -1) ? WSAGetLastError() : EFAULT;
	if (list != -1) closesocket(list);
	if (s1 != -1) closesocket(s1);
	if (s2 != -1) closesocket(s2);
	return -1;

err_inval:
	errno = EINVAL;
	return -1;
}
#endif
