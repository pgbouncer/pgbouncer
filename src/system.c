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
 * Compat functions for OSes where libc does not provide them.
 */

#include "bouncer.h"

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_UCRED_H
#include <ucred.h>
#endif
#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

/*
 * Minimal spec-conforming implementations of strlcpy(), strlcat().
 */

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t n)
{
	size_t len = strlen(src);
	if (len < n) {
		memcpy(dst, src, len + 1);
	} else if (n > 0) {
		memcpy(dst, src, n - 1);
		dst[n - 1] = 0;
	}
	return len;
}
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t n)
{
	size_t pos = 0;
	while (pos < n && dst[pos])
		pos++;
	return pos + strlcpy(dst + pos, src, n - pos);
}
#endif

/*
 * Get other side's uid for UNIX socket.
 *
 * Standardise on getpeereid() from BSDs.
 */
#ifndef HAVE_GETPEEREID
int getpeereid(int fd, uid_t *uid_p, gid_t *gid_p)
{
#ifdef SO_PEERCRED
	struct ucred cred;
	socklen_t len = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) >= 0) {
		*uid_p = cred.uid;
		*gid_p = cred.gid;
		return 0;
	}
#else /* !SO_PEERCRED */
#ifdef HAVE_GETPEERUCRED
	ucred_t *cred = NULL;
	if (getpeerucred(fd, &cred) >= 0) {
		*uid_p = ucred_geteuid(cred);
		*gid_p = ucred_getegid(cred);
		ucred_free(cred);
		if (*uid_p >= 0 && *gid_p >= 0)
			return 0;
	}
#endif /* HAVE_GETPEERUCRED */
#endif /* !SO_PEERCRED */
	return -1;
}
#endif /* !HAVE_GETPEEREID */

#ifndef HAVE_BASENAME
const char *basename(const char *path)
{
	const char *p;
	if (path == NULL || path[0] == 0)
		return ".";
	if ((p = strrchr(path, '/')) != NULL)
		return p[1] ? p + 1 : p;
	return path;
}
#endif

void change_user(const char *user)
{
	const struct passwd *pw;
	gid_t gset[1];

	/* check for a valid username */
	pw = getpwnam(user);
	if (pw == NULL)
		fatal("could not find user '%s' to switch to", user);
	
	gset[0] = pw->pw_gid;
	if (getuid() == 0) {
		if (setgroups(1, gset) < 0)
			fatal_perror("failed to reset groups");
	}

	if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0)
		fatal_perror("failed to assume identity of user '%s'", user);

	if (getuid() != pw->pw_uid || geteuid() != pw->pw_uid)
		fatal("setuid() failed to work");
}

#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
	const unsigned char *p = src;
	if (af != AF_INET)
		return NULL;
	snprintf(dst, cnt, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return dst;
}
#endif


