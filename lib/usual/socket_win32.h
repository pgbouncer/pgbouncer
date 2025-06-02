/*
 * Socket compat code for win32.
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

#ifndef _USUAL_SOCKET_WIN32_H_
#define _USUAL_SOCKET_WIN32_H_

/* if found, likely a mistake */
#undef HAVE_INET_NTOP
#undef HAVE_INET_PTON

typedef int socklen_t;

#define in_addr_t   uint32_t

/*
 * make recvmsg/sendmsg and fd related code compile
 */

struct iovec {
	void	*iov_base;	/* Base address. */
	size_t	 iov_len;	/* Length. */
};

struct msghdr {
	void         *msg_name;
	int	     msg_namelen;
	struct iovec *msg_iov;
	int           msg_iovlen;
	void         *msg_control;
	int           msg_controllen;
	int           msg_flags;
};

#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif

#ifndef CMSG_FIRSTHDR

struct cmsghdr {
	int		cmsg_len;
	int		cmsg_level;
	int		cmsg_type;
};

#define CMSG_DATA(cmsg) ((unsigned char *) ((struct cmsghdr *) (cmsg) + 1))
#define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
	& ~(sizeof (size_t) - 1))
#define CMSG_LEN(len) ((int)(CMSG_ALIGN(sizeof(struct cmsghdr))+(len)))
#define CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= (int)sizeof(struct cmsghdr) ? \
	(struct cmsghdr *)(mhdr)->msg_control : \
	(struct cmsghdr *)NULL)
#define CMSG_NXTHDR(mhdr, cmsg) \
	(((cmsg) == NULL) ? CMSG_FIRSTHDR(mhdr) : \
	(((u_char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len) \
	+ CMSG_ALIGN(sizeof(struct cmsghdr)) > \
	(u_char *)((mhdr)->msg_control) + (mhdr)->msg_controllen) ? \
	(struct cmsghdr *)NULL : \
	(struct cmsghdr *)((u_char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len))))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr))+CMSG_ALIGN(len))

#endif

/*
 * unify WSAGetLastError() with errno.
 *
 * and convert int <-> SOCKET.
 */

/* int <-> socket */
#define FD2S(fd) ((intptr_t)(fd))
#define S2FD(fd) ((int)(fd))

/* socket <-> HANDLE, plain casts */
#define FD2H(fd) ((HANDLE)FD2S(fd))
#define H2FD(h) S2FD((SOCKET)(h))

static inline int ewrap(int res) {
	if (res < 0)
		errno = WSAGetLastError();
	return res;
}

/* proper signature for setsockopt */
static inline int w_setsockopt(int fd, int level, int optname, const void *optval, int optlen)
{
	return ewrap(setsockopt(FD2S(fd), level, optname, optval, optlen));
}
#define setsockopt(a,b,c,d,e) w_setsockopt(a,b,c,d,e)

/* proper signature for send */
static inline ssize_t w_send(int fd, const void *buf, size_t len, int flags) {
	return ewrap(send(FD2S(fd), buf, len, flags));
}
#define send(a,b,c,d) w_send(a,b,c,d)

/* proper signature for recv */
static inline ssize_t w_recv(int fd, void *buf, size_t len, int flags) {
	return ewrap(recv(FD2S(fd), buf, len, flags));
}
#define recv(a,b,c,d) w_recv(a,b,c,d)

#define getsockopt(a,b,c,d,e) ewrap(getsockopt(FD2S(a),b,c,d,e))
#define connect(a,b,c) ewrap(connect(FD2S(a),b,c))
#define socket(a,b,c) ewrap(S2FD(socket(a,b,c)))
#define bind(a,b,c) ewrap(bind(FD2S(a),b,c))
#define listen(a,b) ewrap(listen(FD2S(a),b))
#define accept(a,b,c) ewrap(accept(FD2S(a),b,c))
#define getpeername(a,b,c) ewrap(getpeername(FD2S(a),b,c))
#define getsockname(a,b,c) ewrap(getsockname(FD2S(a),b,c))
#define select(a,b,c,d,e) ewrap(select(a,b,c,d,e))

static inline struct hostent *w_gethostbyname(const char *n) {
	struct hostent *res = gethostbyname(n);
	if (!res) errno = WSAGetLastError();
	return res;
}
#define gethostbyname(a) w_gethostbyname(a)


/* make unix socket related code compile */
struct sockaddr_un {
	short sun_family;
	char sun_path[128];
};

/* sendmsg is not used */
static inline int sendmsg(int s, const struct msghdr *m, int flags)
{
	if (m->msg_iovlen != 1) {
		errno = EINVAL;
		return -1;
	}
	return send(s, m->msg_iov[0].iov_base,
		    m->msg_iov[0].iov_len, flags);
}

/* recvmsg() is, but only with one iov */
static inline int recvmsg(int s, struct msghdr *m, int flags)
{
	if (m->msg_iovlen != 1) {
		errno = EINVAL;
		return -1;
	}
	if (m->msg_controllen)
		m->msg_controllen = 0;
	return recv(s, m->msg_iov[0].iov_base,
		    m->msg_iov[0].iov_len, flags);
}

/*
 * fcntl
 */

#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 1
#define FD_CLOEXEC HANDLE_FLAG_INHERIT

static inline int fcntl(int fd, int cmd, long arg)
{
	ULONG lval;
	DWORD dval;
	switch (cmd) {
	case F_GETFD:
		if (GetHandleInformation(FD2H(fd), &dval))
			return dval;
		errno = EINVAL;
		return -1;
	case F_SETFD:
		/* set FD_CLOEXEC */
		if (SetHandleInformation(FD2H(fd), FD_CLOEXEC, arg))
			return 0;
		errno = EINVAL;
		return -1;
	case F_GETFL:
		/* O_NONBLOCK? */
		return 0;
	case F_SETFL:
		/* set O_NONBLOCK */
		lval = (arg & O_NONBLOCK) ? 1 : 0;
		if (ioctlsocket(FD2S(fd), FIONBIO, &lval) == SOCKET_ERROR) {
			errno = WSAGetLastError();
			return -1;
		}
		return 0;
	default:
		errno = EINVAL;
		return -1;
	}
}

/*
 * SIO_KEEPALIVE_VALS for mingw32
 */

#if !defined(SIO_KEEPALIVE_VALS)
#define SIO_KEEPALIVE_VALS	_WSAIOW(IOC_VENDOR,4)
struct tcp_keepalive {
	u_long onoff;
	u_long keepalivetime;
	u_long keepaliveinterval;
};
#endif

/*
 * Use native poll() if available
 */

#if !defined(HAVE_POLL) && defined(POLLIN)

#define HAVE_POLL
#define poll(a,b,c) usual_poll(a,b,c)

static inline int poll(struct pollfd *fds, int nfds, int timeout)
{
	return WSAPoll(fds, nfds, timeout);
}

#endif

#endif
