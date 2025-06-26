/*
 * Daemonization & pidfile handling.
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


#include <usual/daemon.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include <usual/logging.h>
#include <usual/signal.h>

/*
 * pidfile management.
 */

static char *g_pidfile;

static void remove_pidfile(void)
{
	if (!g_pidfile)
		return;
	unlink(g_pidfile);
	free(g_pidfile);
	g_pidfile = NULL;
}

/*
 * Reads pid from pidfile and sends a signal to it.
 *
 * true - signaling was successful.
 * false - ENOENT / ESRCH
 *
 * fatal() otherwise.
 */
bool signal_pidfile(const char *pidfile, int sig)
{
	char buf[128 + 1];
	struct stat st;
	pid_t pid = 0;
	int fd, res;

	if (!pidfile || !pidfile[0])
		return false;

intr_loop:
	/* check if pidfile exists */
	if (stat(pidfile, &st) < 0)
		goto fail;

	/* read old pid */
	fd = open(pidfile, O_RDONLY);
	if (fd < 0)
		goto fail;
	res = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (res <= 0)
		goto fail;

	/* parse pid */
	buf[res] = 0;
	errno = 0;
	pid = strtoul(buf, NULL, 10);
	if (errno) {
		/* should we panic, or say no such process exists? */
		if (0)
			errno = ESRCH;
		goto fail;
	}

	/* send the signal */
	res = kill(pid, sig);
	if (res == 0)
		return true;
fail:
	/* decide error seriousness */
	if (errno == EINTR)
		goto intr_loop;
	if (errno == ENOENT || errno == ESRCH)
		return false;
	fatal_perror("signal_pidfile: unexpected error");
}

static void check_pidfile(const char *pidfile)
{
	if (signal_pidfile(pidfile, 0))
		die("pidfile exists, another instance running?");
	if (errno == ESRCH) {
		log_info("stale pidfile, removing");
		unlink(pidfile);
	}
}

static void write_pidfile(const char *pidfile, bool first_write)
{
	char buf[64];
	pid_t pid;
	int res, fd, len;
	static int atexit_hook = 0;
	int flags = O_WRONLY | O_CREAT;

	if (!pidfile || !pidfile[0])
		return;

	free(g_pidfile);
	g_pidfile = strdup(pidfile);
	if (!g_pidfile)
		die("out of memory");

	pid = getpid();
	snprintf(buf, sizeof(buf), "%u\n", (unsigned)pid);

	/* don't allow overwrite on first write */
	if (first_write)
		flags |= O_EXCL;

	fd = open(pidfile, flags, 0644);
	if (fd < 0)
		die("could not open pidfile '%s': %s", pidfile, strerror(errno));
	len = strlen(buf);
loop:
	res = write(fd, buf, len);
	if (res < 0) {
		if (errno == EINTR)
			goto loop;
		die("write to pidfile '%s' failed: %s", pidfile, strerror(errno));
	} else if (res < len) {
		len -= res;
		goto loop;
	}
	close(fd);

	if (!atexit_hook) {
		/* only remove when we have it actually written */
		atexit(remove_pidfile);
		atexit_hook = 1;
	}
}

/*
 * Function: daemonize
 *
 * Handle pidfile and daemonization.
 *
 * If pidfile is given, check if old process is running.
 *
 * If going background is required, require non-empty pidfile
 * and logfile.  Then fork to background and write pidfile.
 */
void daemonize(const char *pidfile, bool go_background)
{
	int pid, fd;

	if (pidfile && pidfile[0]) {
		check_pidfile(pidfile);
		/* write pidfile twice, to be able to show problems to user */
		write_pidfile(pidfile, true);
	} else if (go_background) {
		fatal("daemon needs pidfile configured");
	}

	if (!go_background)
		return;

	if ((!cf_logfile || !cf_logfile[0]) && !cf_syslog)
		fatal("daemon needs logging configured");

	/* send stdin, stdout, stderr to /dev/null */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		die("could not open /dev/null: %s", strerror(errno));
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2)
		close(fd);

	/* fork new process */
	pid = fork();
	if (pid < 0)
		die("fork failed: %s", strerror(errno));
	if (pid > 0)
		_exit(0);

	/* create new session */
	pid = setsid();
	if (pid < 0)
		die("setsid: %s", strerror(errno));

	/* fork again to avoid being session leader */
	pid = fork();
	if (pid < 0)
		die("fork failed; %s", strerror(errno));
	if (pid > 0)
		_exit(0);

	write_pidfile(pidfile, false);
}
