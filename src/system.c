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

/* set permissions & mode for file */
void change_file_mode(const char *fn, mode_t mode,
		      const char *user_name,
		      const char *group_name)
{
	int res;
	uid_t uid = -1;
	gid_t gid = -1;
	unsigned long val;
	char *end;

	/* user lookup */
	if (user_name && user_name[0]) {
		const struct passwd *pw;

		val = strtoul(user_name, &end, 0);
		if (*end == 0) {
			uid = val;
		} else {
			/* check for a valid username */
			pw = getpwnam(user_name);
			if (!pw)
				fatal("could not find user '%s': %s",
				      user_name, strerror(errno));
			uid = pw->pw_uid;
		}
	}

	/* group lookup */
	if (group_name && group_name[0]) {
		struct group *gr;

		val = strtoul(group_name, &end, 0);
		if (*end == 0) {
			gid = val;
		} else {
			gr = getgrnam(group_name);
			if (!gr)
				fatal("could not find group '%s': %s",
				      group_name, strerror(errno));
			gid = gr->gr_gid;
		}
	}

	/* change user/group */
	if (uid != (uid_t)-1 || gid != (gid_t)-1) {
		res = chown(fn, uid, gid);
		if (res != 0) {
			fatal("chown(%s, %d, %d) failed: %s",
			      fn, uid, gid, strerror(errno));
		}
	}

	/* change mode */
	res = chmod(fn, mode);
	if (res != 0) {
		fatal("Failure to chmod(%s, 0%o): %s",
		      fn, mode, strerror(errno));
	}
}

/*
 * UNIX socket helper.
 */

bool check_unix_peer_name(int fd, const char *username)
{
	int res;
	uid_t peer_uid = -1;
	gid_t peer_gid = -1;
	struct passwd *pw;

	res = getpeereid(fd, &peer_uid, &peer_gid);
	if (res < 0)
		return false;
	pw = getpwuid(peer_uid);
	if (!pw)
		return false;
	return strcmp(pw->pw_name, username) == 0;
}

