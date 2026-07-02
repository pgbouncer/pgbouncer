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
 * This header provides the core multithreading infrastructure for pgbouncer,
 * enabling it to handle multiple client connections concurrently across multiple
 * worker threads. It includes thread-local storage and caching mechanisms, along
 * with operations for managing threads and thread-safe data structures.
 */

/*
 * Cross-platform pipe helpers.
 *
 * On Windows, libevent's win32 backend can only monitor Winsock sockets, not
 * anonymous pipe handles.  Use evutil_socketpair() to create a socket-based
 * pair and send()/recv() for I/O so the FDs are compatible with libevent
 * event monitoring on all platforms.
 */
#ifdef WIN32
#  define make_pipe(fds)          evutil_socketpair(AF_INET, SOCK_STREAM, 0, (fds))
#  define pipe_read(fd, buf, len) recv((SOCKET)(fd), (char *)(buf), (int)(len), 0)
#  define pipe_write(fd, buf, len) send((SOCKET)(fd), (const char *)(buf), (int)(len), 0)
#else
#  define make_pipe(fds)          pipe(fds)
#  define pipe_read(fd, buf, len) read((fd), (buf), (len))
#  define pipe_write(fd, buf, len) write((fd), (buf), (len))
#endif

/* Iterate over all worker threads (no-op when num_threads == 0) */
#define FOR_EACH_WORKER_THREAD(id) \
	for (int id = 0; (id) < num_threads; (id)++)

/*
 * Return a pointer to a per-worker field in workers[thread_id].
 * In single-thread mode thread_id is always 0.
 */
#define WORKER_THREAD_PTR(name, thread_id) \
	(&(workers[(thread_id)].name))

/*
 * Return the value of a per-worker field in workers[thread_id].
 * In single-thread mode thread_id is always 0.
 */
#define WORKER_THREAD_VAR(name, thread_id) \
	((workers[(thread_id)].name))

/* Execute func under lock in multithread mode; no locking in single-thread mode. */
#define WITH_LOCK(lock, func) \
	do { \
		if (multithread_mode) { \
			spin_lock_acquire(lock); \
			func; \
			spin_lock_release(lock); \
		} else { \
			func; \
		} \
	} while (0)

/* Iterate over a ThreadSafeStatList looked up by field name and thread_id. */
#define THREAD_SAFE_STATLIST_EACH_BY_NAME(list_name, thread_id, item, BODY) \
	THREAD_SAFE_STATLIST_EACH(WORKER_THREAD_PTR(list_name, thread_id), item, BODY)

extern int next_worker_thread_idx;

void start_worker_threads(void);
void init_worker_threads(void);
int join_worker_threads(void);
void lock_worker_thread(int thread_id);
void unlock_worker_thread(int thread_id);
int get_current_worker_thread_id(void);
usec_t get_worker_thread_time(int thread_id);
void reset_worker_thread_time_cache(void);
void worker_thread_event_wrapper(evutil_socket_t sock, short flags, void *arg);
void wakeup_worker_thread(int thread_id);

/* Helper function to set up multithread event arguments */
void init_worker_event_args(WorkerEventArgs *args, void *arg, event_callback_fn func, bool persistent, SpinLock *lock);
