#include "bouncer.h"

#include <usual/slab.h>

static void * worker_func(void *arg);
static void init_thread(int thread_id);

int next_worker_thread_idx = 0;
pthread_key_t worker_key;
int client_count = 0;
SpinLock client_count_lock;

/*
 * WORKER THREAD MAIN FUNCTION:
 * Each worker thread runs this function, which:
 * 1. Sets up its own event loop and thread-local storage
 * 2. Initializes thread-specific events (e.g. signals, janitor)
 * 3. Performs periodic maintenance tasks
 */
void * worker_func(void *arg)
{
	int err;
	Worker *this_thread = (Worker *) arg;
	struct event_base *base = event_base_new();
	pthread_setspecific(worker_key, this_thread);

	if (!base)
		die("event_base_new() failed");

	this_thread->base = base;

	/* Initialize thread-specific events */
	thread_pooler_setup();		/* Set up connection handling for this thread */
	signal_setup_worker(base, this_thread->thread_id);	/* Set up signal handling */
	janitor_setup();		/* Set up maintenance tasks */

	/* Signal that this thread is ready to handle connections */
	this_thread->ready = true;

	/* Main event loop: process events until shutdown */
	while (this_thread->cf_shutdown != SHUTDOWN_IMMEDIATE) {
		reset_worker_thread_time_cache();
		err = event_base_loop(base, EVLOOP_ONCE);
		if (err < 0) {
			if (errno != EINTR)
				log_warning("event_loop failed: %s", strerror(errno));
		}
		/* Perform periodic maintenance tasks */
		per_loop_maint();
		reuse_just_freed_objects();
		rescue_timers();
		per_loop_pooler_maint();
	}
	return NULL;
}

void init_thread(int thread_id)
{
	char name[MAX_SLAB_NAME];

	workers[thread_id].thread_id = thread_id;
	/* Pipes are only needed in multithread mode for cross-thread connection dispatch */
	if (multithread_mode) {
		if (make_pipe(workers[thread_id].pipefd) < 0)
			die("Thread %d init failed", thread_id);
		evutil_make_socket_nonblocking(workers[thread_id].pipefd[0]);
		evutil_make_socket_nonblocking(workers[thread_id].pipefd[1]);
	}
	thread_safe_statlist_init(&(workers[thread_id].pool_list), NULL, true);
	thread_safe_statlist_init(&(workers[thread_id].peer_pool_list), NULL, true);
	statlist_init(&(workers[thread_id].login_client_list), NULL);
	statlist_init(&(workers[thread_id].justfree_client_list), NULL);
	statlist_init(&(workers[thread_id].justfree_server_list), NULL);
	workers[thread_id].vpool = NULL;
	workers[thread_id].cf_shutdown = SHUTDOWN_NONE;
	workers[thread_id].cf_pause_mode = P_NONE;
	spin_lock_init(&(workers[thread_id].thread_lock), true);

	snprintf(name, sizeof(name), "pool_cache_t%d", thread_id);
	workers[thread_id].pool_cache = slab_create(name, sizeof(PgPool), 0, NULL, USUAL_ALLOC);

	snprintf(name, sizeof(name), "peer_pool_cache_t%d", thread_id);
	workers[thread_id].peer_pool_cache = slab_create(name, sizeof(PgPool), 0, NULL, USUAL_ALLOC);

	snprintf(name, sizeof(name), "outstanding_request_cache_t%d", thread_id);
	workers[thread_id].outstanding_request_cache = slab_create(name, sizeof(OutstandingRequest), 0, NULL, USUAL_ALLOC);

	if (!workers[thread_id].pool_cache ||
	    !workers[thread_id].peer_pool_cache || !workers[thread_id].outstanding_request_cache)
		fatal("cannot create per-thread caches for thread %d", thread_id);
}

void start_worker_threads(void)
{
	bool all_ready = false;
	pthread_key_create(&worker_key, NULL);

	FOR_EACH_WORKER_THREAD(thread_id){
		workers[thread_id].ready = false;
		pthread_create(&workers[thread_id].worker, NULL, worker_func, &workers[thread_id]);
	}

	/* Wait for all threads to finish initialization before accepting connections */
	while (!all_ready) {
		all_ready = true;
		FOR_EACH_WORKER_THREAD(thread_id){
			if (!workers[thread_id].ready) {
				all_ready = false;
				break;
			}
		}
		if (!all_ready) {
			usleep(1000);	/* Sleep for 1ms before checking again */
		}
	}
}

void init_worker_threads(void)
{
	workers = calloc(num_threads, sizeof(Worker));
	spin_lock_init(&prepared_statements_lock, true);
	spin_lock_init(&client_count_lock, true);
	FOR_EACH_WORKER_THREAD(thread_id) {
		init_thread(thread_id);
	}
}

int join_worker_threads(void)
{
	void *retval = NULL;
	FOR_EACH_WORKER_THREAD(tmp_thread_id){
		int ret = pthread_join(workers[tmp_thread_id].worker, &retval);
		if (ret != 0) {
			log_error("pthread_join failed, err=%d", ret);
			return 1;
		}

		if (retval) {
			long result = *((long *)retval);
			log_error("[%d] Thread returned %ld", tmp_thread_id, result);
		}
	}

	if (retval) {
		free(retval);
	}
	return 0;
}

void worker_thread_event_wrapper(evutil_socket_t sock, short flags, void *arg)
{
	WorkerEventArgs *event_args = (WorkerEventArgs *) arg;

	if (multithread_mode && event_args->lock != NULL) {
		spin_lock_acquire(event_args->lock);
	}

	event_args->func(sock, flags, event_args->arg);

	if (multithread_mode && event_args->lock != NULL) {
		spin_lock_release(event_args->lock);
	}

	if (!event_args->persistent)
		free(event_args);
}

void lock_worker_thread(int thread_id)
{
	if (thread_id < 0 || !multithread_mode) {
		return;
	}
	spin_lock_acquire(&(workers[thread_id].thread_lock));
}

void unlock_worker_thread(int thread_id)
{
	if (thread_id < 0 || !multithread_mode) {
		return;
	}
	spin_lock_release(&(workers[thread_id].thread_lock));
}

inline int get_current_worker_thread_id(void)
{
	Worker *this_thread;
	if (!multithread_mode)
		return 0;
	this_thread = (Worker *) pthread_getspecific(worker_key);
	return this_thread ? this_thread->thread_id : 0;
}

usec_t get_worker_thread_time(int thread_id)
{
	if (!multithread_mode || thread_id < 0) {
		return get_cached_time();
	}
	return get_cached_time_from_ptr(&workers[thread_id].time_cache);
}

void reset_worker_thread_time_cache(void)
{
	int thread_id;
	if (!multithread_mode)
		return;
	thread_id = get_current_worker_thread_id();
	if (thread_id < 0) {
		return;
	}
	workers[thread_id].time_cache = 0;
}

/*
 * Wake up a worker thread by writing a dummy ClientRequest (fd=-1) to its
 * pipe. handle_request() recognizes fd<0 and returns immediately without
 * accepting a connection, but the event loop unblocks and per_loop_maint()
 * runs, allowing waiting clients to retry launching server connections.
 */
void wakeup_worker_thread(int thread_id)
{
	ClientRequest wake;
	memset(&wake, 0, sizeof(wake));
	wake.fd = -1;
	wake.is_unix = false;
	if (pipe_write(workers[thread_id].pipefd[1], &wake, sizeof(wake)) <= 0) {
		log_warning("[Thread %d] wakeup_worker_thread: write failed: %s",
			    thread_id, strerror(errno));
	}
}

/* Helper function to set up multithread event arguments */
void init_worker_event_args(WorkerEventArgs *args, void *arg, event_callback_fn func, bool persistent, SpinLock *lock)
{
	args->arg = arg;
	args->func = func;
	args->persistent = persistent;
	args->lock = lock;
}
