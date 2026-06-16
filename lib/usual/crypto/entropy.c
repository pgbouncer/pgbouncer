/*
 * Load entropy.
 *
 * Copyright (c) 2014  Marko Kreen
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

#include <usual/crypto/entropy.h>
#include <usual/err.h>
#include <usual/string.h>

#if defined(HAVE_GETRANDOM)
#include <sys/random.h>
#elif defined(HAVE_LINUX_RANDOM_H)
#include <sys/syscall.h>
#include <linux/random.h>
#endif

/*
 * Load system entropy.
 */

#ifndef HAVE_GETENTROPY

/*
 * win32
 */

#if defined(_WIN32) || defined(_WIN64)

#define HAVE_getentropy_win32

/*
 * Windows
 *
 * It's possible to get entropy via:
 * - CryptGenRandom.  Uses RtlGenRandom, requires CryptoAPI.
 * - rand_s().  Uses RtlGenRandom,  Requires VS2005 CRT, WindowsXP+.
 *   Missing in mingw32, exists in mingw64.
 * - RtlGenRandom().  Internal func, no proper public definition.
 *   There is broken def in <ntsecapi.h> that does not have NTAPI.
 *   Need to link or load from advapi32.dll.
 */

typedef BOOLEAN APIENTRY (*rtlgenrandom_t)(void *, ULONG);

static int getentropy_win32(void *dst, size_t len)
{
	HMODULE lib;
	rtlgenrandom_t fn;
	int res = -1;

	lib = LoadLibrary("advapi32.dll");
	if (lib) {
		fn = (rtlgenrandom_t)(void (*)(void))GetProcAddress(lib, "SystemFunction036");
		if (fn && fn(dst, len))
			res = 0;
		FreeLibrary(lib);
	}
	if (res < 0)
		errno = EIO;
	return res;
}

#endif /* WIN32 */

/*
 * Linux getrandom()
 */

#if defined(HAVE_GETRANDOM) || (defined(GRND_RANDOM) && defined(SYS_getrandom))

#define HAVE_getentropy_getrandom

#ifndef HAVE_GETRANDOM
static int getrandom(void *dst, size_t len, unsigned int flags)
{
	return syscall(SYS_getrandom, dst, len, flags);
}
#endif

static int getentropy_getrandom(void *dst, size_t len)
{
	int res;
retry:
	res = getrandom(dst, len, 0);
	if (res < 0) {
		if (errno == EINTR)
			goto retry;
		return -1;
	}
	if ((size_t)res == len)
		return 0;
	errno = EIO;
	return -1;
}

#endif /* getrandom */


/*
 * Generic /dev/urandom
 */

#ifndef HAVE_getentropy_win32

#define HAVE_getentropy_devrandom

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

/* open and check device node */
static int open_devrandom(const char *dev)
{
	int fd;
	int oflags = O_RDONLY;
#ifdef O_CLOEXEC
	oflags |= O_CLOEXEC;
#endif

open_loop:
	fd = open(dev, oflags);
	if (fd == -1) {
		if (errno == EINTR)
			goto open_loop;
		return -1;
	}

#ifndef O_CLOEXEC
	{
		int res;
		res = fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
		if (res != 0)
			goto fail;
	}
#endif

	/*
	 * Lightly verify that the device node looks sane
	 */

	{
		struct stat st;
		if (fstat(fd, &st) == -1 || !S_ISCHR(st.st_mode))
			goto fail;
	}
#ifdef RNDGETENTCNT
	{
		int cnt;
		if (ioctl(fd, RNDGETENTCNT, &cnt) == -1)
			goto fail;
	}
#endif

	/* seems fine */
	return fd;

fail:
	close(fd);
	return -1;
}

/*
 * Read normal random devices under /dev.
 */

static const char *devlist[] = {
	"/dev/urandom",
	"/dev/random",
	NULL,
};

static int getentropy_devrandom(void *dst, size_t bytes)
{
	uint8_t *d = dst;
	size_t need = bytes;
	int fd, res;
	unsigned int i;

	for (i = 0; devlist[i]; i++) {
reopen:
		fd = open_devrandom(devlist[i]);
		if (fd == -1)
			continue;

		while (need > 0) {
			res = read(fd, d, need);
			if (res > 0) {
				/* successful read */
				need -= res;
				d += res;
			} else if (res == 0) {
				/* eof - open again */
				close(fd);
				goto reopen;
			} else if (errno == EINTR) {
				/* signal - retry read */
			} else {
				close(fd);
				/* random error, fail */
				return -1;
			}
		}
		close(fd);
		return 0;
	}

	errno = EIO;
	return -1;
}

#endif /* devrandom */

/*
 * Export BSD-style getentropy().
 */

int getentropy(void *dst, size_t bytes)
{
	int res = -1;
	int old_errno = errno;
	if (bytes > 256) {
		errno = EIO;
		return res;
	}
#ifdef HAVE_getentropy_win32
	if (res != 0) {
		res = getentropy_win32(dst, bytes);
	}
#endif
#ifdef HAVE_getentropy_getrandom
	if (res != 0) {
		res = getentropy_getrandom(dst, bytes);
	}
#endif
#ifdef HAVE_getentropy_devrandom
	if (res != 0) {
		res = getentropy_devrandom(dst, bytes);
	}
#endif
	if (res == 0)
		errno = old_errno;
	return res;
}

#endif /* !HAVE_GETENTROPY */
