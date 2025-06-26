/*
 * Dynamic library loading.
 *
 * Copyright (c) 2007-2009  Marko Kreen
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

#ifdef _WIN32

#include <usual/string.h>

/*
 * win32: Minimal dlopen, dlsym, dlclose, dlerror compat.
 */

void *dlopen(const char *fn, int flag)
{
	HMODULE h = LoadLibraryEx(fn, NULL, 0);
	return h;
}

void *dlsym(void *hptr, const char *fname)
{
	HMODULE h = hptr;
	FARPROC f = GetProcAddress(h, fname);
	return f;
}

int dlclose(void *hptr)
{
	HMODULE h = hptr;
	return FreeLibrary(h) ? 0 : -1;
}

const char *dlerror(void)
{
	return strerror(GetLastError());
}

#endif
