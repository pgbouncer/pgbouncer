/*
 * File access utils.
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

#include <usual/fileutil.h>

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

/*
 * Load text file into C string.
 */

void *load_file(const char *fn, size_t *len_p)
{
	struct stat st;
	char *buf = NULL;
	int res;
	FILE *f;
	int save_errno;

	f = fopen(fn, "r");
	if (!f)
		return NULL;

	res = fstat(fileno(f), &st);
	if (res < 0) {
		save_errno = errno;
		fclose(f);
		errno = save_errno;
		return NULL;
	}

	buf = malloc(st.st_size + 1);
	if (!buf) {
		save_errno = errno;
		fclose(f);
		errno = save_errno;
		return NULL;
	}

	if ((res = fread(buf, 1, st.st_size, f)) < 0) {
		save_errno = errno;
		free(buf);
		fclose(f);
		errno = save_errno;
		return NULL;
	}

	fclose(f);

	buf[res] = 0;
	if (len_p)
		*len_p = res;
	return buf;
}

/*
 * Read file line-by-line, call user func on each.
 */

bool foreach_line(const char *fn, procline_cb proc_line, void *arg)
{
	char *ln = NULL;
	size_t len = 0;
	ssize_t res;
	FILE *f = fopen(fn, "rb");
	bool ok = false;
	if (!f)
		return false;
	while (1) {
		res = getline(&ln, &len, f);
		if (res < 0) {
			if (feof(f))
				ok = true;
			break;
		}
		if (!proc_line(arg, ln, res))
			break;
	}
	fclose(f);
	free(ln);
	return ok;
}

/*
 * Find file size.
 */

ssize_t file_size(const char *fn)
{
	struct stat st;
	if (stat(fn, &st) < 0)
		return -1;
	return st.st_size;
}

/*
 * Map a file into mem.
 */

#ifdef HAVE_MMAP

int map_file(struct MappedFile *m, const char *fname, int rw)
{
	struct stat st;
	m->fd = open(fname, rw ? O_RDWR : O_RDONLY);
	if (m->fd < 0)
		return -1;
	if (fstat(m->fd, &st) < 0) {
		close(m->fd);
		return -1;
	}
	m->len = st.st_size;
	m->ptr = mmap(NULL, m->len, PROT_READ | (rw ? PROT_WRITE : 0),
		      MAP_SHARED, m->fd, 0);
	if (m->ptr == MAP_FAILED) {
		close(m->fd);
		return -1;
	}
	return 0;
}

void unmap_file(struct MappedFile *m)
{
	munmap(m->ptr, m->len);
	close(m->fd);
	m->ptr = NULL;
	m->fd = 0;
}

#endif


#ifndef HAVE_GETLINE
/*
 * Read line from FILE with dynamic allocation.
 */
int getline(char **line_p, size_t *size_p, void *_f)
{
	FILE *f = _f;
	char *p;
	int len = 0;

	if (!*line_p || *size_p < 128) {
		p = realloc(*line_p, 512);
		if (!p) return -1;
		*line_p = p;
		*size_p = 512;
	}

	while (1) {
		p = fgets(*line_p + len, *size_p - len, f);
		if (!p)
			return len ? len : -1;
		len += strlen(p);
		if ((*line_p)[len - 1] == '\n')
			return len;
		p = realloc(*line_p, *size_p * 2);
		if (!p)
			return -1;
		*line_p = p;
		*size_p *= 2;
	}
}
#endif
