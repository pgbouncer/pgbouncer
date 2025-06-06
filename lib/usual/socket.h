/*
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

/** @file
 *
 * Socket compat, few utils.
 *
 * Socket headers included:
 * - win32: <winsock2.h>
 * - win32: <ws2tcpip.h>
 * - <sys/socket.h>
 * - <sys/un.h>
 * - <netinet/in.h>
 * - <netinet/tcp.h>
 * - <arpa/inet.h>
 * - <fcntl.h>
 * - <poll.h>
 */
#ifndef _USUAL_SOCKET_H_
#define _USUAL_SOCKET_H_

#include <usual/base.h>


#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <usual/socket_win32.h>
#endif

#include <fcntl.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef INADDR_NONE
/** Compat: Some systems (Solaris) does not define INADDR_NONE */
#define INADDR_NONE ((unsigned long) -1)
#endif

/**
 * Usual socket setup.
 *
 * - Disallow SIGPIPE
 * - Set close-on-exec flag
 * - Call \ref socket_set_nonblocking() with given flag
 */
bool socket_setup(int sock, bool non_block);

/**
 * Flip sockets non-blocking flag
 */
bool socket_set_nonblocking(int sock, bool non_block);

/**
 * Set sockets keepalive flags.
 *
 * @param fd		TCP socket
 * @param onoff		Whether to set keepalive on or off.
 * @param keepidle	How long the socket must be idle before keepalive packets are sent
 * @param keepintvl	How big period between consecutive keepalive packets.
 * @param keepcnt	How many keepalive packets to send before considering socket dead.
 */
bool socket_set_keepalive(int fd, int onoff, int keepidle, int keepintvl, int keepcnt);

/**
 * Convert struct sockaddr to stirng.
 *
 * Supports: ipv4, ipv5, unix sockets.
 */
const char *sa2str(const struct sockaddr *sa, char *buf, size_t buflen);

#ifndef HAVE_INET_NTOP
#undef inet_ntop
#define inet_ntop(a,b,c,d) usual_inet_ntop(a,b,c,d)
/** Compat: inet_ntop() */
const char *inet_ntop(int af, const void *src, char *dst, int cnt);
#endif

#ifndef HAVE_INET_PTON
#undef inet_pton
#define inet_pton(a,b,c) usual_inet_pton(a,b,c)
/** Compat: inet_pton() */
int inet_pton(int af, const char *src, void *dst);
#endif

#ifndef HAVE_GETPEEREID
#define getpeereid(a,b,c) compat_getpeereid(a,b,c)
/** Get user id of UNIX socket peer */
int getpeereid(int fd, uid_t *uid_p, gid_t *gid_p);
#endif

#define getpeercreds(a,b,c,d) usual_getpeercreds(a,b,c,d)
/** Get info of UNIX socket peer */
int getpeercreds(int fd, uid_t *uid_p, gid_t *gid_p, pid_t *pid_p);

#if !defined(HAVE_POLL)
#define POLLIN		(1 << 0)
#define POLLOUT		(1 << 1)
#define POLLHUP		(1 << 2)
#define POLLPRI		(1 << 3)
#define POLLNVAL	(1 << 4)
#define POLLERR		(1 << 5)
#define poll(a,b,c)	compat_poll(a,b,c)
struct pollfd {
	int fd;
	short events;
	short revents;
};
typedef unsigned long nfds_t;
/** Compat: select-based poll() */
int poll(struct pollfd *fds, nfds_t nfds, int timeout_ms);
#endif

#ifdef WIN32
#define socketpair(a,b,c,d) win32_socketpair(a,b,c,d)
/** Compat: socketpair() for win32 */
int socketpair(int d, int typ, int proto, int sv[2]);
#endif

#endif
