/*
 * Pthreads compat.
 *
 * Copyright (c) 2007-2009 Marko Kreen
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


#include <usual/pthread.h>

#ifndef HAVE_PTHREAD_H
#ifdef WIN32
/*
 * basic pthreads for win32.
 */

struct _w32thread {
	void *(*fn)(void *);
	void *arg;
};

static DWORD WINAPI w32launcher(LPVOID arg)
{
	struct _w32thread *info = arg;
	info->fn(info->arg);
	free(info);
	return 0;
}

int pthread_create(pthread_t *t, pthread_attr_t *attr, void *(*fn)(void *), void *arg)
{
	struct _w32thread *info = calloc(1, sizeof(*info));
	if (!info)
		return -1;
	info->fn = fn;
	info->arg = arg;
	*t = CreateThread(NULL, 0, w32launcher, info, 0, NULL);
	if (*t == NULL)
		return -1;
	return 0;
}

int pthread_join(pthread_t t, void **ret)
{
	(void)ret;
	if (WaitForSingleObject(t, INFINITE) != WAIT_OBJECT_0)
		return -1;
	CloseHandle(t);
	return 0;
}

int pthread_mutex_init(pthread_mutex_t *lock, void *unused)
{
	*lock = CreateMutex(NULL, FALSE, NULL);
	if (*lock == NULL)
		return -1;
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *lock)
{
	if (*lock) {
		CloseHandle(*lock);
		*lock = NULL;
	}
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *lock)
{
	if (WaitForSingleObject(*lock, INFINITE) != WAIT_OBJECT_0)
		return -1;
	return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *lock)
{
	if (!ReleaseMutex(*lock))
		return -1;
	return 0;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *))
{
	(void)destructor;
	*key = TlsAlloc();
	return *key == TLS_OUT_OF_INDEXES ? -1 : 0;
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
	return TlsSetValue(key, (LPVOID)value) ? 0 : -1;
}

void *pthread_getspecific(pthread_key_t key)
{
	return TlsGetValue(key);
}

#ifdef INIT_ONCE_STATIC_INIT

typedef void (*once_posix_cb_t)(void);

static BOOL once_wrapper(PINIT_ONCE once, void *arg, void **ctx)
{
	once_posix_cb_t cb = arg;
	arg();
	return TRUE;
}

int pthread_once(pthread_once_t *once, void (*once_func)(void))
{
	return InitOnceExecuteOnce(once, once_wrapper, once_func, NULL) ? 0 : -1;
}

#endif

void pthread_exit(void *retval)
{
	/* On Windows, ExitThread terminates the calling thread */
	ExitThread(retval ? (DWORD)(uintptr_t)retval : 0);
}


#endif /* win32 */
#endif /* !HAVE_PTHREAD_H */

int mutex_init(Mutex *lock, bool recursive)
{
#ifdef HAVE_PTHREAD_H
	int res;
	pthread_mutexattr_t attr;

	if (!recursive)
		return pthread_mutex_init(&lock->mutex, NULL);

	res = pthread_mutexattr_init(&attr);
	if (res != 0)
		return res;

#ifdef PTHREAD_MUTEX_RECURSIVE
	res = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#elif defined(PTHREAD_MUTEX_RECURSIVE_NP)
	res = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#else
	pthread_mutexattr_destroy(&attr);
	return -1;
#endif
	if (res != 0) {
		pthread_mutexattr_destroy(&attr);
		return res;
	}

	res = pthread_mutex_init(&lock->mutex, &attr);
	pthread_mutexattr_destroy(&attr);
	return res;
#else
	return pthread_mutex_init(&lock->mutex, NULL);
#endif /* HAVE_PTHREAD_H */
}

int mutex_lock(Mutex *lock)
{
	return pthread_mutex_lock(&lock->mutex);
}

int mutex_unlock(Mutex *lock)
{
	return pthread_mutex_unlock(&lock->mutex);
}
