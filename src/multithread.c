#include <multithread.h>
#include <bouncer.h>
#include <pooler.h>
#include <signal.h>

static void handle_sigterm_main(evutil_socket_t sock, short flags, void *arg);
static void handle_sigterm(evutil_socket_t sock, short flags, void *arg);
static void * worker_func(void *arg);
static void init_thread(int thread_id);

int next_thread = 0;
bool multithread_mode = false;
pthread_key_t event_base_key;
pthread_key_t thread_pointer;
Thread *threads;
int client_count = 0;
SpinLock client_count_lock;
int total_active_count = 0;	/* Total active count across all threads */
SpinLock total_active_count_lock;

ConnectionLimit *db_connection_limits;
SpinLock db_connection_limits_lock;

ConnectionLimit *db_client_connection_limits;
SpinLock db_client_connection_limits_lock;

static void signal_threads(int signal_pipe[2])
{
	if (!multithread_mode) {
		return;
	}
	if (write(signal_pipe[1], "x", 1) == -1) {
		log_error("Failed to write to pipe");
		return;
	}
}

void handle_sigterm_main(evutil_socket_t sock, short flags, void *arg)
{
	if (cf_shutdown) {
		log_info("got SIGTERM while shutting down, fast exit");
		/* pidfile cleanup happens via atexit() */
		exit(0);
	}
	log_info("got SIGTERM, shutting down, waiting for all clients disconnect");
	sd_notify(0, "STOPPING=1");
	if (cf_reboot)
		die("takeover was in progress, going down immediately");
	if (cf_pause_mode == P_SUSPEND)
		die("suspend was in progress, going down immediately");
	cf_shutdown = SHUTDOWN_WAIT_FOR_CLIENTS;
	cleanup_tcp_sockets();
	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id){
			signal_threads(threads[thread_id].worker_signal_events.pipe_sigterm);
		}
	}
}

void handle_sigterm(evutil_socket_t sock, short flags, void *arg)
{
	Thread *this_thread = (Thread *) pthread_getspecific(thread_pointer);
	char buf[1];
	if (read(threads[this_thread->thread_id].worker_signal_events.pipe_sigterm[0], buf, sizeof(buf)) == -1) {
		log_error("[Thread %d] read SIGTERM pipe failure.", this_thread->thread_id);
		return;
	}
	if (this_thread->cf_shutdown) {
		log_info("[Thread %d] got SIGTERM while shutting down, fast exit", this_thread->thread_id);
		/* pidfile cleanup happens via atexit() */
		exit(0);
	}
	log_info("[Thread %d] got SIGTERM, shutting down, waiting for all clients disconnect", this_thread->thread_id);
	this_thread->cf_shutdown = SHUTDOWN_WAIT_FOR_CLIENTS;
}

static void handle_sigint_main(evutil_socket_t sock, short flags, void *arg)
{
	if (cf_shutdown) {
		log_info("got SIGINT while shutting down, fast exit");
		/* pidfile cleanup happens via atexit() */
		exit(0);
	}
	log_info("got SIGINT, shutting down, waiting for all servers connections to be released");
	sd_notify(0, "STOPPING=1");
	if (cf_reboot)
		die("takeover was in progress, going down immediately");
	if (cf_pause_mode == P_SUSPEND)
		die("suspend was in progress, going down immediately");
	cf_pause_mode = P_PAUSE;
	cf_shutdown = SHUTDOWN_WAIT_FOR_SERVERS;
	cleanup_tcp_sockets();
	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id){
			signal_threads(threads[thread_id].worker_signal_events.pipe_sigint);
		}
	}
}


static void handle_sigint(evutil_socket_t sock, short flags, void *arg)
{
	Thread *this_thread = (Thread *) pthread_getspecific(thread_pointer);
	char buf[1];
	if (read(threads[this_thread->thread_id].worker_signal_events.pipe_sigint[0], buf, sizeof(buf)) == -1) {
		log_error("[Thread %d] read SIGINT pipe failure.", this_thread->thread_id);
		return;
	}
	if (this_thread->cf_shutdown) {
		log_info("[Thread %d] got SIGINT while shutting down, fast exit", this_thread->thread_id);
		/* pidfile cleanup happens via atexit() */
		exit(0);
	}
	log_info("[Thread %d] got SIGINT, shutting down, waiting for all servers connections to be released", this_thread->thread_id);
	this_thread->cf_shutdown = SHUTDOWN_WAIT_FOR_SERVERS;
}

#ifndef WIN32

static void handle_sigquit_main(evutil_socket_t sock, short flags, void *arg)
{
	log_info("got SIGQUIT, fast exit");
	/* pidfile cleanup happens via atexit() */
	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id){
			signal_threads(threads[thread_id].worker_signal_events.pipe_sigquit);
		}
		wait_threads();
	}
	exit(0);
}

static void handle_sigquit_worker(evutil_socket_t sock, short flags, void *arg)
{
	Thread *this_thread = (Thread *) pthread_getspecific(thread_pointer);
	char buf[1];
	if (read(threads[this_thread->thread_id].worker_signal_events.pipe_sigquit[0], buf, sizeof(buf)) == -1) {
		log_error("[Thread %d] read SIGQUIT pipe failure.", this_thread->thread_id);
		return;
	}
	log_info("[Thread %d] got SIGQUIT, fast exit", this_thread->thread_id);

	pthread_exit(NULL);
}

static void handle_sigusr1(int sock, short flags, void *arg)
{
	if (cf_pause_mode == P_NONE) {
		log_info("got SIGUSR1, pausing all activity");
		if (multithread_mode) {
			/* Set pause mode on all threads */
			FOR_EACH_THREAD(thread_id) {
				lock_thread(thread_id);
				threads[thread_id].cf_pause_mode = P_PAUSE;
				unlock_thread(thread_id);
			}
			MULTITHREAD_VISIT(&total_active_count_lock, {
				total_active_count = 0;
			});
		}
		cf_pause_mode = P_PAUSE;
	} else {
		log_info("got SIGUSR1, but already paused/suspended");
	}
}

static void handle_sigusr2(int sock, short flags, void *arg)
{
	if (cf_shutdown) {
		log_info("got SIGUSR2 while shutting down, ignoring");
		return;
	}
	switch (cf_pause_mode) {
	case P_SUSPEND:
		log_info("got SIGUSR2, continuing from SUSPEND");
		resume_all();
		cf_pause_mode = P_NONE;
		break;
	case P_PAUSE:
		log_info("got SIGUSR2, continuing from PAUSE");
		cf_pause_mode = P_NONE;
		break;
	case P_NONE:
		log_info("got SIGUSR2, but not paused/suspended");
	}
}


/*
 * Notify systemd that we are reloading, including a CLOCK_MONOTONIC timestamp
 * in usec so that the program is compatible with a Type=notify-reload service.
 *
 * See https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 */
static void notify_reloading(void)
{
#ifdef USE_SYSTEMD
	struct timespec ts;
	usec_t usec;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	usec = (usec_t)ts.tv_sec * USEC + (usec_t)ts.tv_nsec / (usec_t)1000;
	sd_notifyf(0, "RELOADING=1\nMONOTONIC_USEC=%" PRIu64, usec);
#endif
}

static void handle_sighup(int sock, short flags, void *arg)
{
	log_info("got SIGHUP, re-reading config");

	MULTITHREAD_ONLY_ITERATE(thread_id, {
		lock_thread(thread_id);
	});
	notify_reloading();
	load_config();
	if (!sbuf_tls_setup())
		log_error("TLS configuration could not be reloaded, keeping old configuration");
	sd_notify(0, "READY=1");
	MULTITHREAD_ONLY_ITERATE(thread_id, {
		unlock_thread(thread_id);
	});
}
#endif


void signal_setup(struct event_base *base, struct SignalEvent *signal_event)
{
	int err;

#ifndef WIN32
	sigset_t set;

	/* block SIGPIPE */
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	err = sigprocmask(SIG_BLOCK, &set, NULL);
	if (err < 0)
		fatal_perror("sigprocmask");

	/* install handlers */

	evsignal_assign(&(signal_event->ev_sigusr1), base, SIGUSR1, handle_sigusr1, NULL);
	err = evsignal_add(&(signal_event->ev_sigusr1), NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	evsignal_assign(&(signal_event->ev_sigusr2), base, SIGUSR2, handle_sigusr2, NULL);
	err = evsignal_add(&(signal_event->ev_sigusr2), NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	evsignal_assign(&(signal_event->ev_sighup), base, SIGHUP, handle_sighup, NULL);
	err = evsignal_add(&(signal_event->ev_sighup), NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	evsignal_assign(&(signal_event->ev_sigquit), base, SIGQUIT, handle_sigquit_main, NULL);
	err = evsignal_add(&(signal_event->ev_sigquit), NULL);
	if (err < 0)
		fatal_perror("evsignal_add");
#endif

	evsignal_assign(&(signal_event->ev_sigterm), base, SIGTERM, handle_sigterm_main, NULL);
	err = evsignal_add(&(signal_event->ev_sigterm), NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	evsignal_assign(&(signal_event->ev_sigint), base, SIGINT, handle_sigint_main, NULL);
	err = evsignal_add(&(signal_event->ev_sigint), NULL);
	if (err < 0)
		fatal_perror("evsignal_add");

	if (multithread_mode) {
		FOR_EACH_THREAD(thread_id){
			err = pipe(threads[thread_id].worker_signal_events.pipe_sigint);
			if (err < 0)
				fatal_perror("multithread signal pipe");
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigint[0]);
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigint[1]);

			err = pipe(threads[thread_id].worker_signal_events.pipe_sigterm);
			if (err < 0)
				fatal_perror("multithread signal pipe");
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigterm[0]);
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigterm[1]);

#ifndef WIN32
			err = pipe(threads[thread_id].worker_signal_events.pipe_sigusr1);
			if (err < 0)
				fatal_perror("multithread signal pipe");
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigusr1[0]);
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigusr1[1]);


			err = pipe(threads[thread_id].worker_signal_events.pipe_sigusr2);
			if (err < 0)
				fatal_perror("multithread signal pipe");
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigusr2[0]);
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigusr2[1]);

			err = pipe(threads[thread_id].worker_signal_events.pipe_sigquit);
			if (err < 0)
				fatal_perror("multithread signal pipe");
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigquit[0]);
			evutil_make_socket_nonblocking(threads[thread_id].worker_signal_events.pipe_sigquit[1]);
#endif
		}
	}
}


static void worker_signal_setup(struct event_base *base, int thread_id)
{
	int err;
#ifndef WIN32

	threads[thread_id].worker_signal_events.ev_sigusr1 = event_new(base, threads[thread_id].worker_signal_events.pipe_sigusr1[0], EV_READ | EV_PERSIST, handle_sigusr1, base);
	err = event_add(threads[thread_id].worker_signal_events.ev_sigusr1, NULL);
	if (err < 0)
		fatal_perror("multithread signal event add");

	threads[thread_id].worker_signal_events.ev_sigusr2 = event_new(base, threads[thread_id].worker_signal_events.pipe_sigusr2[0], EV_READ | EV_PERSIST, handle_sigusr2, base);
	err = event_add(threads[thread_id].worker_signal_events.ev_sigusr2, NULL);
	if (err < 0)
		fatal_perror("multithread signal event add");

	threads[thread_id].worker_signal_events.ev_sigquit = event_new(base, threads[thread_id].worker_signal_events.pipe_sigquit[0], EV_READ | EV_PERSIST, handle_sigquit_worker, base);
	err = event_add(threads[thread_id].worker_signal_events.ev_sigquit, NULL);
	if (err < 0)
		fatal_perror("multithread signal event add");
#endif

	threads[thread_id].worker_signal_events.ev_sigterm = event_new(base, threads[thread_id].worker_signal_events.pipe_sigterm[0], EV_READ | EV_PERSIST, handle_sigterm, base);
	err = event_add(threads[thread_id].worker_signal_events.ev_sigterm, NULL);
	if (err < 0)
		fatal_perror("multithread signal event add");


	threads[thread_id].worker_signal_events.ev_sigint = event_new(base, threads[thread_id].worker_signal_events.pipe_sigint[0], EV_READ | EV_PERSIST, handle_sigint, base);
	err = event_add(threads[thread_id].worker_signal_events.ev_sigint, NULL);
	if (err < 0)
		fatal_perror("multithread signal event add");
}

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
	Thread *this_thread = (Thread *) arg;
	struct event_base *base = event_base_new();
	pthread_setspecific(thread_pointer, this_thread);

	if (!base) {
		fprintf(stderr, "[Thread %d] Failed to create event_base.\n", this_thread->thread_id);
		die("event_base_new() failed");
	}

	pthread_setspecific(event_base_key, base);
	this_thread->base = base;

	/* Initialize thread-specific events */
	thread_pooler_setup();		/* Set up connection handling for this thread */
	worker_signal_setup(base, this_thread->thread_id);	/* Set up signal handling */
	janitor_setup();		/* Set up maintenance tasks */

	/* Signal that this thread is ready to handle connections */
	this_thread->ready = true;

	/* Main event loop: process events until shutdown */
	while (this_thread->cf_shutdown != SHUTDOWN_IMMEDIATE) {
		multithread_reset_time_cache();
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

static void event_base_destructor(void *base_ptr)
{
	if (base_ptr) {
		event_base_free((struct event_base *)base_ptr);
	}
}

void init_thread(int thread_id)
{
	threads[thread_id].thread_id = thread_id;
	if (pipe(threads[thread_id].pipefd) < 0) {
		die("Thread %d init failed", thread_id);
	}
	evutil_make_socket_nonblocking(threads[thread_id].pipefd[0]);
	evutil_make_socket_nonblocking(threads[thread_id].pipefd[1]);
	thread_safe_statlist_init(&(threads[thread_id].pool_list), NULL, true);
	thread_safe_statlist_init(&(threads[thread_id].peer_pool_list), NULL, true);
	statlist_init(&(threads[thread_id].login_client_list), NULL);
	statlist_init(&(threads[thread_id].justfree_client_list), NULL);
	statlist_init(&(threads[thread_id].justfree_server_list), NULL);
	threads[thread_id].vpool = NULL;
	threads[thread_id].cf_shutdown = SHUTDOWN_NONE;
	threads[thread_id].cf_pause_mode = P_NONE;
	spin_lock_init(&(threads[thread_id].thread_lock), true);
}

void start_threads(void)
{
	bool all_ready = false;
	pthread_key_create(&event_base_key, event_base_destructor);
	pthread_key_create(&thread_pointer, NULL);

	FOR_EACH_THREAD(thread_id){
		threads[thread_id].ready = false;
		pthread_create(&threads[thread_id].worker, NULL, worker_func, &threads[thread_id]);
	}

	/* Wait for all threads to finish initialization before accepting connections */
	while (!all_ready) {
		all_ready = true;
		FOR_EACH_THREAD(thread_id){
			if (!threads[thread_id].ready) {
				all_ready = false;
				break;
			}
		}
		if (!all_ready) {
			usleep(1000);	/* Sleep for 1ms before checking again */
		}
	}
	log_info("All %d worker threads are ready", arg_thread_number);
}

void init_threads(void)
{
	if (arg_thread_number < 1)
		return;
	log_info("allocating %d threads.", arg_thread_number);
	threads = calloc(arg_thread_number, sizeof(Thread));
	spin_lock_init(&prepared_statements_lock, true);
	multithread_limits_init(&db_connection_limits, &db_connection_limits_lock);
	multithread_limits_init(&db_client_connection_limits, &db_client_connection_limits_lock);

	FOR_EACH_THREAD(thread_id){
		init_thread(thread_id);
	}
}

int wait_threads(void)
{
	void *retval = NULL;
	FOR_EACH_THREAD(tmp_thread_id){
		int ret = pthread_join(threads[tmp_thread_id].worker, &retval);
		if (ret != 0) {
			log_error("pthread_join failed, err=%d\n", ret);
			return 1;
		}

		if (retval) {
			long result = *((long *)retval);
			log_error("[%d] Thread returned %ld\n", tmp_thread_id, result);
		}
	}

	if (retval) {
		free(retval);
	}
	return 0;
}


void multithread_event_wrapper(evutil_socket_t sock, short flags, void *arg)
{
	MultithreadEventArgs *event_args = (MultithreadEventArgs *) arg;

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

void lock_thread(int thread_id)
{
	if (thread_id < 0 || !multithread_mode) {
		return;
	}
	spin_lock_acquire(&(threads[thread_id].thread_lock));
}

void unlock_thread(int thread_id)
{
	if (thread_id < 0 || !multithread_mode) {
		return;
	}
	spin_lock_release(&(threads[thread_id].thread_lock));
}

inline int get_current_thread_id(void)
{
	Thread *this_thread;
	if (!multithread_mode) {
		return -1;
	}
	this_thread = (Thread *) pthread_getspecific(thread_pointer);
	return this_thread->thread_id;
}

usec_t get_multithread_time_with_id(int thread_id)
{
	if (!multithread_mode || thread_id < 0) {
		return get_cached_time();
	}
	return get_cached_time_from_ptr(&threads[thread_id].multithread_time_cache);
}

void multithread_reset_time_cache(void)
{
	int thread_id;
	if (!multithread_mode)
		return;
	thread_id = get_current_thread_id();
	if (thread_id < 0) {
		return;
	}
	threads[thread_id].multithread_time_cache = 0;
}


bool multithread_limits_init(ConnectionLimit **limit, SpinLock *lock)
{
	if (!multithread_mode) {
		return true;
	}
	*limit = NULL;
	spin_lock_init(lock, true);
	return true;
}


int multithread_get_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock)
{
	ConnectionLimit *limit_entry = NULL;
	if (!multithread_mode) {
		return -1;
	}
	spin_lock_acquire(lock);
	HASH_FIND_STR(*limits, name, limit_entry);
	if (limit_entry) {
		int count = limit_entry->current_count;
		spin_lock_release(lock);
		return count;
	}
	spin_lock_release(lock);
	return -1;
}

int multithread_get_limit(const char *name, ConnectionLimit **limits, SpinLock *lock)
{
	ConnectionLimit *limit_entry = NULL;
	if (!multithread_mode) {
		return -1;
	}
	spin_lock_acquire(lock);
	HASH_FIND_STR(*limits, name, limit_entry);
	// release lock early becuase limit is not expected to change
	spin_lock_release(lock);

	if (limit_entry) {
		int limit = limit_entry->limit;
		return limit;
	}
	return -1;
}

void multithread_set_limit(const char *name, ConnectionLimit **limits, SpinLock *lock, int limit)
{
	ConnectionLimit *limit_entry = NULL;
	if (!multithread_mode) {
		return;
	}
	spin_lock_acquire(lock);
	HASH_FIND_STR(*limits, name, limit_entry);
	if (limit_entry) {
		limit_entry->limit = limit;
	} else {
		limit_entry = (ConnectionLimit *)malloc(sizeof(ConnectionLimit));
		if (!limit_entry) {
			spin_lock_release(lock);
			return;
		}
		memset(limit_entry, 0, sizeof(ConnectionLimit));
		limit_entry->name = strdup(name);
		limit_entry->limit = limit;
		limit_entry->current_count = 0;
		HASH_ADD_KEYPTR(hh, *limits, name, strlen(name), limit_entry);
	}
	spin_lock_release(lock);
}

void multithread_increase_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock)
{
	ConnectionLimit *limit_entry = NULL;
	if (!multithread_mode) {
		return;
	}
	spin_lock_acquire(lock);
	HASH_FIND_STR(*limits, name, limit_entry);
	if (!limit_entry) {
		multithread_set_limit(name, limits, lock, -1);
		HASH_FIND_STR(*limits, name, limit_entry);
	}
	limit_entry->current_count++;
	spin_lock_release(lock);
}


void multithread_decrease_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock)
{
	ConnectionLimit *limit_entry = NULL;
	if (!multithread_mode) {
		return;
	}
	spin_lock_acquire(lock);
	HASH_FIND_STR(*limits, name, limit_entry);
	if (limit_entry) {
		limit_entry->current_count--;
		spin_lock_release(lock);
		return;
	} else {
		fatal("Limit entry not found for %s", name);
	}
	spin_lock_release(lock);
	return;
}

bool multithread_check_limit_count(const char *name, ConnectionLimit **limits, SpinLock *lock)
{
	ConnectionLimit *limit_entry = NULL;
	if (!multithread_mode) {
		return true;
	}
	spin_lock_acquire(lock);
	HASH_FIND_STR(*limits, name, limit_entry);
	if (limit_entry) {
		if (limit_entry->current_count >= limit_entry->limit) {
			spin_lock_release(lock);
			return false;
		}
		spin_lock_release(lock);
		return true;
	} else {
		fatal("Limit entry not found for %s", name);
	}
	spin_lock_release(lock);
	return true;
}


void multithread_remove_limit(const char *name, ConnectionLimit **limits, SpinLock *lock)
{
	ConnectionLimit *limit_entry = NULL;
	if (!multithread_mode) {
		return;
	}
	spin_lock_acquire(lock);
	HASH_FIND_STR(*limits, name, limit_entry);
	if (limit_entry) {
		HASH_DEL(*limits, limit_entry);
		free(limit_entry->name);
		free(limit_entry);
	}
	spin_lock_release(lock);
}

void multithread_free_limits(ConnectionLimit **limits)
{
	ConnectionLimit *entry, *tmp;
	if (!multithread_mode) {
		return;
	}
	HASH_ITER(hh, *limits, entry, tmp) {
		HASH_DEL(*limits, entry);
		free(entry->name);
		free(entry);
	}
	*limits = NULL;
}

/* Helper function to set up multithread event arguments */
void setup_multithread_event_args(MultithreadEventArgs *args, void *arg, event_callback_fn func, bool persistent, SpinLock *lock)
{
	args->arg = arg;
	args->func = func;
	args->persistent = persistent;
	args->lock = lock;
}
